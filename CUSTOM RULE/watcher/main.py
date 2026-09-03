"""
Watcher agent — `watcher/main.py`

Entry point for the runtime detection agent.

Run with:
    python -m watcher.main

Startup sequence (execute.txt §"How to start watching"):
  1. Load config — log all settings including dry-run status
  2. Build rule index from data/rules.jsonl — log clearly if empty
  3. Start tray icon thread
  4. Subscribe to each configured Windows Event Log channel
     (fail with a clear PermissionError if access denied)
  5. Main event loop:
       drain queue → normalize → index lookup → condition match
       → state advance → investigate on match → act → alert

Background tasks (same main loop, time-based):
  - Rule index hot-reload (every 1s mtime check)
  - Aggregation store cleanup (every 30s)
  - State manager GC (every 60s)
  - Evidence file retention cleanup (every 1h)
"""
from __future__ import annotations

import ctypes
import json
import logging
import os
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Path setup so "python -m watcher.main" works from project root ─────
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from watcher.config import get_watcher_settings
from watcher.event_bus import EventBus, DedupGuard
from watcher.collector_manager import CollectorManager
from watcher.collectors import COLLECTOR_REGISTRY
from watcher.rule_index import initial_load, maybe_reload, lookup
from watcher.aggregation_store import AggregationStore
from watcher.state_manager import StateManager, InstanceState
from watcher.correlation import CorrelationStore
from watcher.sustain_store import SustainStore
from watcher.investigation import write_evidence, update_evidence_actions, cleanup_old_evidence
from watcher.action_engine import ActionEngine
from watcher.notifier import fire_alert
from watcher.activity import ActivityLog, SavedActivityLog, write_runtime_status
from watcher.tray import TrayController
from shared.event_fields import IR_FIELD_PATHS, PLUGIN_FIELD_BLOCKS
from shared.windows_aliases import canonical_executable


def _unordered_processes_still_running(
    correlation: dict[str, Any],
    correlated_events: list[dict[str, Any]],
    process_iter=None,
) -> bool:
    """Verify that an unordered process co-occurrence is truly simultaneous."""
    if correlation.get("ordered", True) is not False:
        return True
    stages = correlation.get("stages", [])
    if len(stages) < 2 or any(stage.get("event") != "process.start" for stage in stages):
        return True

    expected: set[str] = set()
    for stage in stages:
        name_conditions = [
            condition for condition in stage.get("conditions", [])
            if str(condition.get("field", "")) in {"name", "process.name"}
            and condition.get("operator") == "=="
        ]
        if len(name_conditions) != 1:
            return True
        expected.add(canonical_executable(str(name_conditions[0].get("value", ""))))
    if len(expected) < 2:
        return True

    try:
        if process_iter is None:
            import psutil
            process_iter = psutil.process_iter
        running = {
            canonical_executable(str(info.get("name", "")))
            for process in process_iter(["name"])
            for info in [getattr(process, "info", {})]
            if info.get("name")
        }
    except Exception as exc:
        # A denied process-table snapshot must not invalidate real event
        # telemetry; retain the normal event-window behavior in that case.
        logger.warning("Could not re-check co-occurrence liveness: %s", exc)
        return True
    return expected.issubset(running)


# ═══════════════════════════════════════════════════════════════════════
# Logging
# ═══════════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("watcher")

def _acquire_pid_lock(path: Path) -> bool:
    try:
        import psutil
        if path.exists() and psutil.pid_exists(int(path.read_text(encoding="ascii").strip())):
            return False
    except (OSError, ValueError): pass
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(os.getpid()), encoding="ascii")
    return True


# ═══════════════════════════════════════════════════════════════════════
# Condition evaluator
# ═══════════════════════════════════════════════════════════════════════


# ── IR field name → normalized event path mapping ────────────────────
# The LLM generates IR using the field names from context_builder.py
# (e.g., "name", "command_line", "dest_ip"). Our normalized event stores
# these under nested keys ("process.name", "network.dest_ip"). This map
# bridges the two so that approved rules actually match events.
_IR_FIELD_MAP: dict[str, str] = IR_FIELD_PATHS
"""Compatibility alias; canonical mappings live in shared.event_fields."""


def _extract_field_value(event: dict, field_name: str) -> str:
    """
    Extract a field value from the normalized event dict.

    Handles three cases:
    1. IR flat names ("name", "command_line") → mapped to nested paths via _IR_FIELD_MAP
    2. Already-dotted paths ("process.name", "network.dest_ip") → navigated directly
    3. Flat top-level fields ("host", "user") → looked up directly
    """
    # Remap IR field names to their normalized event paths
    resolved = _IR_FIELD_MAP.get(field_name, field_name)
    parts = resolved.split(".", 1)
    if len(parts) == 1:
        val = event.get(resolved)  # use resolved, not original field_name
        if val is None:
            # New collector plugins keep their domain fields in a named block.
            # Resolve unambiguous IR names without requiring a central mapping
            # change every time a plugin is added.
            for block_name in PLUGIN_FIELD_BLOCKS:
                block = event.get(block_name)
                if isinstance(block, dict) and resolved in block:
                    val = block.get(resolved)
                    break
    else:
        sub = event.get(parts[0])
        if sub is None or not isinstance(sub, dict):
            return ""
        val = sub.get(parts[1])
    return str(val).lower() if val is not None else ""


def _evaluate_condition(event: dict, cond: dict) -> bool:
    """
    Evaluate a single IR condition against a normalized event.
    Operators supported (matching context_builder.py supported_operators):
        ==, !=, contains, not_contains, starts_with, ends_with, regex
    """
    field = cond.get("field", "")
    operator = cond.get("operator", "==")
    value = str(cond.get("value", "")).lower()
    actual = _extract_field_value(event, field)
    if field in {"name", "process.name"} and operator in {"==", "!="}:
        actual = canonical_executable(actual)
        value = canonical_executable(value)

    if operator == "==":
        return actual == value
    elif operator == "!=":
        return actual != value
    elif operator == "contains":
        return value in actual
    elif operator == "not_contains":
        return value not in actual
    elif operator == "starts_with":
        return actual.startswith(value)
    elif operator == "ends_with":
        return actual.endswith(value)
    elif operator == "regex":
        import re
        try:
            return bool(re.search(value, actual))
        except re.error:
            logger.warning("Invalid regex in condition: %s", value)
            return False
    elif operator == "is_public_ip":
        import ipaddress
        try:
            return ipaddress.ip_address(actual).is_global
        except ValueError:
            return False
    elif operator in (">", ">=", "<", "<="):
        # Numeric comparison
        try:
            a_num = float(actual)
            v_num = float(value)
            if operator == ">":
                return a_num > v_num
            elif operator == ">=":
                return a_num >= v_num
            elif operator == "<":
                return a_num < v_num
            elif operator == "<=":
                return a_num <= v_num
        except ValueError:
            return False
    else:
        logger.warning("Unknown operator '%s' — treating as False", operator)
        return False


def _all_conditions_match(event: dict, conditions: list[dict]) -> bool:
    """All conditions must pass (AND semantics)."""
    return all(_evaluate_condition(event, c) for c in conditions)


def _is_internal_notification_process(event: dict) -> bool:
    """Identify the PowerShell helper created by the winotify dependency."""
    process = event.get("process") if isinstance(event.get("process"), dict) else {}
    if str(process.get("name", "")).lower() not in {"powershell.exe", "pwsh.exe"}:
        return False
    command_line = str(process.get("command_line", "")).lower()
    return "toastnotificationmanager" in command_line and "watcher agent" in command_line


# ═══════════════════════════════════════════════════════════════════════
# Rule processing
# ═══════════════════════════════════════════════════════════════════════


def _process_event(
    event: dict[str, Any],
    rules: list[dict[str, Any]],
    agg_store: AggregationStore,
    state_mgr: StateManager,
    correlation_store: CorrelationStore,
    action_engine: ActionEngine,
    cfg,
    data_dir: Path,
    alerts_file: Path,
    evidence_dir: Path,
    activity: ActivityLog | None = None,
    sustain_store: SustainStore | None = None,
) -> None:
    """
    Match an event against all rules indexed for its event_type.
    Advance state, investigate, and act when a rule fires.

    Evidence capture is UNCONDITIONAL (Backend_Action_Evidence_Upgrade_Plan §B.1):
    If evidence write fails, actions are SKIPPED and the failure is logged CRITICAL.
    No action without a corresponding evidence record, ever.
    """
    # Notification helpers are generated by this application, not by the
    # monitored user/workload. Ignoring them prevents recursive alert storms.
    if _is_internal_notification_process(event):
        logger.debug("Ignoring GEKKO notification helper process pid=%s", event.get("process", {}).get("pid"))
        return

    for record in rules:
        rule_id = record.get("id", "")
        rule_text = record.get("rule_text", "")
        ir_wrap = record.get("ir", {})
        ir = ir_wrap.get("ir", {}) if ir_wrap else {}
        severity = ir.get("severity", "medium")
        conditions = ir.get("conditions", [])
        aggregation = ir.get("aggregation")
        response_actions = ir.get("response_actions", [])
        correlation = ir.get("correlation")
        sustain_for = ir.get("sustain_for")

        # Launcher shims are useful diagnostics but ordinarily should not fire
        # the same application rule as the persistent packaged process. A rule
        # can explicitly target the shim field when that behavior is wanted.
        proc = event.get("process", {}) if isinstance(event.get("process"), dict) else {}
        all_rule_conditions = list(conditions)
        if correlation:
            all_rule_conditions.extend(c for stage in correlation.get("stages", []) for c in stage.get("conditions", []))
        explicitly_targets_shim = any(str(c.get("field", "")) in {"is_launcher_shim", "process.is_launcher_shim"} for c in all_rule_conditions)
        # Ordered parent/child correlations must still see the launcher because
        # it is the real child carrying the ancestry edge. Single-event app
        # rules ignore it by default and match the persistent packaged process.
        if proc.get("is_launcher_shim") and not explicitly_targets_shim and not correlation:
            continue

        # Extract design-time explanation for audit trail
        explanation = ir_wrap.get("explanation", {}) if ir_wrap else {}
        design_time_explanation = {
            "suggested_action": ir.get("suggested_action", []),
            "suggested_action_reason": ir.get("suggested_action_reason", ""),
            "llm_explanation": explanation,
        }

        # Extract source collector from event metadata
        source_collector = event.get("source_collector", event.get("source", "unknown"))

        # ── Condition check ──────────────────────────────────────
        correlated_events = None
        if correlation:
            correlated_events = correlation_store.process(
                rule_id, correlation, event, _extract_field_value, _all_conditions_match
            )
            if correlated_events is None:
                continue
            if not _unordered_processes_still_running(correlation, correlated_events):
                # Completion consumed the prior entry. Seed a new window with
                # the newest event so a later real overlap is not missed.
                correlation_store.process(
                    rule_id, correlation, event, _extract_field_value, _all_conditions_match
                )
                if activity:
                    activity.write(
                        "correlation_not_concurrent", event, rule_id=rule_id,
                        reason="required processes were not all running",
                    )
                continue
            event = dict(event)
            event["correlated_events"] = correlated_events
            conditions = [c for stage in correlation.get("stages", []) for c in stage.get("conditions", [])]
        elif not _all_conditions_match(event, conditions):
            continue  # Fast discard — nothing written, nothing kept

        if sustain_for and event.get("_sustain_verified_rule_id") != rule_id:
            if sustain_store is None:
                logger.warning("Sustained rule %s cannot schedule because no SustainStore is available", rule_id[:8])
                continue
            if sustain_store.schedule(record, event, sustain_for):
                logger.info("Sustained condition pending: rule=%s duration=%s pid=%s",
                            rule_id[:8], sustain_for, event.get("process", {}).get("pid"))
                if activity:
                    activity.write("sustain_pending", event, rule_id=rule_id, duration=sustain_for)
            continue

        logger.info(
            "Rule MATCHED: rule=%s event_type=%s host=%s",
            rule_id[:8], event.get("event_type"), event.get("host"),
        )
        if activity: activity.write("rule_matched", event, rule_id=rule_id, severity=severity)

        # ── Entity + aggregation ─────────────────────────────────
        if aggregation:
            # Aggregated rule — check threshold
            key_fields = aggregation.get("key", [])
            agg_key = AggregationStore.build_key(rule_id, event, key_fields)
            window_str = aggregation.get("window", "5m")
            window_s = _parse_window_to_seconds(window_str)
            threshold = _safe_int(aggregation.get("threshold", "5"))

            count = agg_store.increment(agg_key, window_s)
            entity = tuple(f"{f}:{_extract_field_value(event, f)}" for f in key_fields) or ("*",)
            inst = state_mgr.get_or_create(rule_id, rule_text, entity)
            state_mgr.add_event(inst, event)

            if count < threshold:
                logger.debug(
                    "Aggregation: %d/%d for key=%s (rule=%s)",
                    count, threshold, agg_key, rule_id[:8],
                )
                state_mgr.advance(inst, InstanceState.TRIGGERED)
                continue  # Not yet at threshold

            # Threshold reached
            logger.warning(
                "Aggregation threshold REACHED: %d/%d key=%s rule=%s",
                count, threshold, agg_key, rule_id[:8],
            )
            agg_store.reset_counter(agg_key)
        else:
            # Single-event rule — matches immediately
            entity = ("*",)
            inst = state_mgr.get_or_create(rule_id, rule_text, entity)
            state_mgr.add_event(inst, event)

        # ── Advance to collecting → gather evidence (UNCONDITIONAL) ──
        state_mgr.advance(inst, InstanceState.COLLECTING)
        pid = event.get("process", {}).get("pid") if event.get("process") else None
        actions_requested = [a.get("type", "") for a in response_actions if a.get("type")]

        try:
            evidence_path = write_evidence(
                instance_id=inst.instance_id,
                rule_id=rule_id,
                rule_name=rule_text[:80],
                rule_text=rule_text,
                severity=severity,
                entity=entity,
                event=event,
                conditions=conditions,
                pid=pid,
                evidence_dir=evidence_dir,
                actions_requested=actions_requested,
                source_collector=source_collector,
                design_time_explanation=design_time_explanation,
                correlation=correlation,
            )
        except OSError as exc:
            # CRITICAL: No action without a corresponding evidence record.
            # Plan §B.1: "If evidence writing fails, do NOT proceed to execute actions"
            logger.critical(
                "EVIDENCE WRITE FAILED for instance=%s rule=%s: %s — "
                "SKIPPING ALL ACTIONS for this match. Disk full or permissions issue?",
                inst.instance_id[:8], rule_id[:8], exc,
            )
            state_mgr.close(inst)
            continue

        # ── Advance to responding → execute actions ───────────────
        state_mgr.advance(inst, InstanceState.RESPONDING)
        action_results = action_engine.execute_ordered(
            actions=response_actions,
            event=event,
            instance_id=inst.instance_id,
            evidence_path=evidence_path,
        )

        # ── Update evidence with action results ───────────────────
        # Flaw fix #4: partial failures visible in evidence record, not swallowed
        update_evidence_actions(evidence_path, action_results)

        # ── Fire alert (always — even in dry-run) ─────────────────
        fire_alert(
            rule_id=rule_id,
            rule_text=rule_text,
            severity=severity,
            event=event,
            action_results=action_results,
            instance_id=inst.instance_id,
            evidence_path=evidence_path,
            alerts_file=alerts_file,
            dry_run=cfg.watcher_dry_run,
        )
        if activity: activity.write("alert_saved", event, rule_id=rule_id, severity=severity, instance_id=inst.instance_id, evidence_path=str(evidence_path))

        # ── Close instance ────────────────────────────────────────
        state_mgr.close(inst)



def _ensure_admin_privileges(allow_non_admin: bool) -> None:
    """
    Check if running as Admin. If not, prompt UAC runas relaunch.
    """
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        is_admin = False

    if is_admin:
        return

    if allow_non_admin:
        logger.warning(
            "RUNNING IN NON-ADMIN MODE. "
            "Some telemetry collectors (e.g. security) and actions (e.g. isolate_host) "
            "will fail or be skipped. Enforce administrative privilege for full protection."
        )
        return

    logger.info("Administrative privileges required. Launching UAC prompt...")
    script = sys.executable
    params = f"-m watcher.main"
    try:
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", script, params, None, 1
        )
        if int(ret) > 32:
            logger.info("Successfully launched elevated agent process. Exiting loader.")
            sys.exit(0)
    except Exception as exc:
        logger.debug("UAC prompt failed: %s", exc)

    logger.critical(
        "CRITICAL ERROR: Administrator privileges are required to run the Watcher Agent.\n"
        "Please restart the agent as Administrator, or set WATCHER_ALLOW_NON_ADMIN=true "
        "in your .env file to allow running in non-admin mode."
    )
    sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════
# Main loop
# ═══════════════════════════════════════════════════════════════════════


def run() -> bool:
    """
    Full startup sequence + main event loop.
    Blocks until a SIGINT/SIGTERM or a tray Quit.
    """

    # ── 1. Load config ─────────────────────────────────────────────
    cfg = get_watcher_settings()
    log_level = getattr(logging, cfg.watcher_log_level.upper(), logging.INFO)
    logging.getLogger().setLevel(log_level)
    
    _ensure_admin_privileges(cfg.watcher_allow_non_admin)

    logger.info("=" * 60)
    logger.info("Watcher Agent starting up")
    logger.info("Dry-run mode: %s", cfg.watcher_dry_run)
    logger.info("Collectors: %s", cfg.collectors_list)
    logger.info("Max destructive/min: %d", cfg.watcher_max_destructive_per_minute)
    logger.info("Evidence retention: %d days", cfg.watcher_evidence_retention_days)
    logger.info(
        "Evidence quota: %d files / %d MB",
        cfg.watcher_evidence_max_files, cfg.watcher_evidence_max_total_mb,
    )
    logger.info("=" * 60)

    data_dir = _PROJECT_ROOT / cfg.watcher_data_dir
    rules_file = data_dir / "rules.jsonl"
    alerts_file = data_dir / "alerts.jsonl"
    evidence_dir = data_dir / "evidence"
    activity = ActivityLog(data_dir / "watcher_activity.jsonl")
    # Santosh, 2026-08-06: opt-in "Save Logs" archive, off by default, one consolidated
    # compressed file, toggled live via a small control file the GUI writes and this
    # process polls -- see SavedActivityLog's own doc comment for the full rationale.
    saved_activity = SavedActivityLog(data_dir / "watcher_saved_activity.jsonl")
    control_file = data_dir / "watcher_control.json"
    runtime_file = data_dir / "watcher_runtime.json"
    pid_file = data_dir / "watcher.pid"
    if not _acquire_pid_lock(pid_file):
        logger.info("Watcher already running; duplicate startup cancelled.")
        return True

    # ── 2. Build rule index ────────────────────────────────────────
    rule_state = initial_load(rules_file)

    # ── 3. Initialize sub-systems ──────────────────────────────────
    agg_store = AggregationStore()
    state_mgr = StateManager()
    correlation_store = CorrelationStore()
    sustain_store = SustainStore()
    action_engine = ActionEngine(
        dry_run=cfg.watcher_dry_run,
        max_destructive_per_minute=cfg.watcher_max_destructive_per_minute,
    )

    # ── 3b. Status dict (shared with tray) ────────────────────────
    _status: dict[str, Any] = {
        "state": "watching",
        "rules_loaded": rule_state.rule_count,
    }
    _stop_event = [False]  # list so it's mutable from closure

    def _stop_callback():
        _stop_event[0] = True

    tray = TrayController(
        status=_status,
        dashboard_url="http://localhost:3000",
        stop_callback=_stop_callback,
    )
    tray.start()
    crashed = False

    # ── 4. Initialize collectors & event bus ──────────────────────
    bus = EventBus()
    dedup = DedupGuard(ttl_s=2.0)
    manager = CollectorManager(cfg.collectors_list, bus)
    try:
        manager.start_all()
    except Exception as exc:
        logger.critical("Failed to start collector manager: %s", exc)
        tray.update_status("error")
        sys.exit(1)

    tray.update_status("watching", rule_state.rule_count)
    write_runtime_status(runtime_file, state="watching", pid=os.getpid(), rules_loaded=rule_state.rule_count,
                         dry_run=cfg.watcher_dry_run, dropped_events=0, deduplicated_events=0,
                         rule_load_errors=rule_state.load_errors, rule_index_degraded=rule_state.degraded)

    # ── Signal handling (Ctrl+C / service stop) ────────────────────
    def _signal_handler(sig, frame):
        logger.info("Received signal %d — shutting down...", sig)
        _stop_event[0] = True

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    # ── 5. Main loop ───────────────────────────────────────────────
    logger.info("Main loop started. Watcher is active.")
    _last_runtime_write = 0.0
    _last_correlation_cleanup = 0.0
    _last_control_poll = 0.0
    _last_saved_activity_flush = 0.0
    maintenance_stop = threading.Event()

    def _maintenance_worker() -> None:
        while not maintenance_stop.is_set():
            try:
                cleanup_old_evidence(
                    evidence_dir,
                    cfg.watcher_evidence_retention_days,
                    max_files=cfg.watcher_evidence_max_files,
                    max_total_bytes=cfg.watcher_evidence_max_total_mb * 1024 * 1024,
                )
            except Exception as exc: logger.warning("Evidence maintenance failed: %s", exc)
            if maintenance_stop.wait(3600.0):
                break

    threading.Thread(target=_maintenance_worker, name="watcher-maintenance", daemon=True).start()

    try:
        while not _stop_event[0]:
            # ── Drain event queue ────────────────────────────────
            processed = 0
            while not bus._q.empty():
                try:
                    item = bus._q.get_nowait()
                except Exception:
                    break

                # Check for pause
                if _status.get("state") == "paused":
                    continue  # discard events while paused

                source_name = item.get("source", "")
                raw_event = item.get("raw", {})

                collector_inst = manager.active_collectors.get(source_name)
                if not collector_inst:
                    continue

                event = collector_inst.decode(raw_event)
                if event is None:
                    continue  # not rule-relevant, drop
                activity.write("event_observed", event)
                saved_activity.write("event_observed", event)

                # ── Fix 9: Dedup guard — skip if overlapping collectors
                # (e.g. security + wmi) both fired for the same event ──
                if dedup.is_duplicate(event):
                    activity.write("event_deduplicated", event)
                    continue

                event_type = event.get("event_type", "")
                matching_rules = lookup(rule_state, event_type)

                if matching_rules:
                    _process_event(
                        event=event,
                        rules=matching_rules,
                        agg_store=agg_store,
                        state_mgr=state_mgr,
                        correlation_store=correlation_store,
                        action_engine=action_engine,
                        cfg=cfg,
                        data_dir=data_dir,
                        alerts_file=alerts_file,
                        evidence_dir=evidence_dir,
                        activity=activity,
                        sustain_store=sustain_store,
                    )
                    processed += 1

                # Do not let a continuously busy queue starve the health
                # heartbeat and make the desktop report a false OFFLINE state.
                if time.monotonic() - _last_runtime_write >= 1.0:
                    write_runtime_status(runtime_file, state=_status.get("state", "watching"), pid=os.getpid(),
                                         rules_loaded=rule_state.rule_count, dry_run=cfg.watcher_dry_run,
                                         dropped_events=bus.dropped, deduplicated_events=dedup.deduped_count,
                                         rule_load_errors=rule_state.load_errors,
                                         rule_index_degraded=rule_state.degraded)
                    _last_runtime_write = time.monotonic()

            # ── Periodic background tasks ────────────────────────

            # Hot-reload rules (every 1s mtime check — very cheap)
            # Verify due sustained-state rules without blocking event intake.
            for pending in sustain_store.pop_due():
                rule_id = str(pending.rule.get("id", ""))
                active = next((record for record in lookup(rule_state, pending.event.get("event_type", ""))
                               if str(record.get("id", "")) == rule_id), None)
                if active is None:
                    continue
                if not sustain_store.still_true(pending):
                    logger.info("Sustained condition not met: rule=%s process exited or identity changed", rule_id[:8])
                    activity.write("sustain_not_met", pending.event, rule_id=rule_id, duration=pending.duration)
                    continue
                verified = dict(pending.event)
                verified["_sustain_verified_rule_id"] = rule_id
                verified["sustained_condition"] = {
                    "duration": pending.duration,
                    "verified_at": datetime.now(timezone.utc).isoformat(),
                    "result": "still_running",
                }
                activity.write("sustain_verified", verified, rule_id=rule_id, duration=pending.duration)
                _process_event(
                    event=verified, rules=[active], agg_store=agg_store, state_mgr=state_mgr,
                    correlation_store=correlation_store, action_engine=action_engine, cfg=cfg,
                    data_dir=data_dir, alerts_file=alerts_file, evidence_dir=evidence_dir,
                    activity=activity, sustain_store=sustain_store,
                )

            old_count = rule_state.rule_count
            old_errors = rule_state.load_errors
            rule_state = maybe_reload(rule_state, rules_file)
            if rule_state.rule_count != old_count:
                tray.update_status(_status.get("state", "watching"), rule_state.rule_count)
                activity.write("rules_reloaded", rules_loaded=rule_state.rule_count)
            if rule_state.load_errors and rule_state.load_errors != old_errors:
                activity.write(
                    "rule_reload_degraded", rules_loaded=rule_state.rule_count,
                    errors=rule_state.load_errors,
                )

            if time.monotonic() - _last_runtime_write >= 1.0:
                write_runtime_status(runtime_file, state=_status.get("state", "watching"), pid=os.getpid(),
                                     rules_loaded=rule_state.rule_count, dry_run=cfg.watcher_dry_run,
                                     dropped_events=bus.dropped, deduplicated_events=dedup.deduped_count,
                                     rule_load_errors=rule_state.load_errors,
                                     rule_index_degraded=rule_state.degraded)
                _last_runtime_write = time.monotonic()

            # Aggregation store cleanup (every 30s)
            agg_store.maybe_cleanup()

            # State manager GC (every 60s)
            state_mgr.maybe_gc()
            if time.monotonic() - _last_correlation_cleanup >= 30.0:
                correlation_store.cleanup()
                _last_correlation_cleanup = time.monotonic()

            # Save-logs toggle: cheap poll of a small control file the GUI writes,
            # same "check every couple seconds" cost profile as the rule hot-reload
            # above (Santosh, 2026-08-06 -- live-toggleable without a watcher restart).
            if time.monotonic() - _last_control_poll >= 2.0:
                try:
                    desired = bool(json.loads(control_file.read_text(encoding="utf-8")).get("save_activity_log", False))
                except (OSError, ValueError, json.JSONDecodeError):
                    desired = False
                if desired != saved_activity.enabled:
                    saved_activity.set_enabled(desired)
                    activity.write("save_logs_toggled", enabled=desired)
                _last_control_poll = time.monotonic()

            # Flush any pending compacted repeat row so a long-running burst of the
            # same repeated event doesn't sit unwritten indefinitely.
            if time.monotonic() - _last_saved_activity_flush >= 10.0:
                saved_activity.flush()
                _last_saved_activity_flush = time.monotonic()

            # ── Yield to OS ──────────────────────────────────────
            # Sleep briefly so we don't spin at 100% CPU when idle.
            time.sleep(0.05)

    except Exception as exc:
        crashed = True
        logger.critical("Unhandled exception in main loop: %s", exc, exc_info=True)
        tray.update_status("error")
    finally:
        logger.info("Shutting down collector manager...")
        maintenance_stop.set()
        saved_activity.flush()
        manager.stop_all()
        tray.stop()
        write_runtime_status(runtime_file, state="stopped", pid=os.getpid(), rules_loaded=rule_state.rule_count)
        try:
            if pid_file.read_text(encoding="ascii").strip() == str(os.getpid()): pid_file.unlink()
        except OSError: pass
        logger.info("Watcher Agent stopped.")
    return not crashed


def supervised_run(run_once=None, sleep_fn=time.sleep) -> None:
    """Restart an unexpectedly crashed watcher with bounded backoff.

    A tray Exit, SIGINT, or SIGTERM is a clean stop and is never restarted.
    """
    run_once = run_once or run
    consecutive_failures = 0
    while True:
        if run_once():
            return
        consecutive_failures += 1
        delay = min(30, 2 ** (consecutive_failures - 1))
        logger.critical(
            "Watcher crashed; automatic recovery attempt %d in %ds",
            consecutive_failures, delay,
        )
        sleep_fn(delay)


# ═══════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════


def _parse_window_to_seconds(window_str: str) -> int:
    """Convert "5m", "1h", "30s" etc. to seconds."""
    if not window_str:
        return 300
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    try:
        unit = window_str[-1].lower()
        value = int(window_str[:-1])
        return value * units.get(unit, 1)
    except (ValueError, IndexError):
        return 300


def _safe_int(val: Any, default: int = 5) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


# ═══════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    supervised_run()
