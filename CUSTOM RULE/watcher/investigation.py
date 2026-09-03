"""
Investigation engine — `watcher/investigation.py`

Called ONLY when a rule's instance reaches the 'collecting' state —
never speculatively, never for events that didn't match.

Uses psutil (execute.txt §6 — justified addition, not scope creep):
  - Walk process tree: parent, children, command line, connections
  - The Windows-native ctypes approach used in main.py's health endpoint
    is fine for a single number; a full process tree is a different job
    that psutil already solves well.

Flaw-fix from execute.txt §7:
  - Each alert record carries evidence_path so an audit trail links
    back to the full evidence JSON, not just a summary string.

Upgrade (Backend_Action_Evidence_Upgrade_Plan §B.1, §B.2):
  - Evidence capture is UNCONDITIONAL — no code path where a rule matches
    and evidence isn't written. Evidence is not a response_action option.
  - Full evidence schema including: rule_name, severity, entity, event_type,
    source_collector, matched_conditions, actions_requested, actions_executed,
    design_time_explanation.
  - Evidence write failure blocks action execution (flaw fix #3 from plan):
    no action without a corresponding evidence record, ever.

Evidence storage:
  - data/evidence/{instance_id}.json — one small JSON file per match
  - Not a growing single file → each can be deleted independently
    when the retention period expires (handled by main.py's cleanup loop)
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from shared.integrity import write_signed_json

logger = logging.getLogger(__name__)

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False
    logger.warning(
        "psutil not available — process investigation will be skipped. "
        "Install with: pip install psutil"
    )


# ═══════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════


def _proc_summary(proc: "psutil.Process") -> dict[str, Any]:
    """Return a safe summary dict for one process."""
    try:
        return {
            "pid": proc.pid,
            "name": proc.name(),
            "cmdline": proc.cmdline(),
            "status": proc.status(),
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return {"pid": proc.pid, "name": "?", "cmdline": [], "status": "unknown"}


def _connections_summary(proc: "psutil.Process") -> list[dict[str, Any]]:
    """Return network connections for a process, safe on access errors."""
    try:
        conns = proc.connections(kind="all")
        result = []
        for c in conns:
            result.append({
                "fd": c.fd,
                "family": str(c.family),
                "type": str(c.type),
                "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                "status": c.status,
            })
        return result
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return []


# ═══════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════


def capture(pid: int | None) -> dict[str, Any]:
    """
    Capture process-tree evidence for a given PID.

    Returns a dict with process info (even if psutil is unavailable
    or the process has already exited — in those cases returns an
    informative stub so the evidence file is still created).
    """
    if not _PSUTIL_AVAILABLE:
        return {"error": "psutil_not_available", "pid": pid}

    if pid is None:
        return {"error": "no_pid", "pid": None}

    try:
        proc = psutil.Process(pid)
        evidence = {
            "pid": pid,
            "name": proc.name(),
            "exe": proc.exe() if hasattr(proc, "exe") else None,
            "cmdline": proc.cmdline(),
            "cwd": proc.cwd() if hasattr(proc, "cwd") else None,
            "status": proc.status(),
            "create_time": proc.create_time(),
            "username": proc.username() if hasattr(proc, "username") else None,
            "parent": _proc_summary(proc.parent()) if proc.parent() else None,
            "children": [_proc_summary(c) for c in proc.children(recursive=True)],
            "connections": _connections_summary(proc),
        }
    except psutil.NoSuchProcess:
        # Process already exited — record what we know
        evidence = {
            "pid": pid,
            "error": "process_exited",
            "note": "Process exited before investigation could capture details.",
        }
    except psutil.AccessDenied:
        evidence = {
            "pid": pid,
            "error": "access_denied",
            "note": "Access denied to process details — run watcher as Administrator.",
        }
    except Exception as exc:
        evidence = {
            "pid": pid,
            "error": "investigation_failed",
            "detail": str(exc),
        }

    return evidence


def write_evidence(
    instance_id: str,
    rule_id: str,
    rule_name: str,
    rule_text: str,
    severity: str,
    entity: tuple,
    event: dict[str, Any],
    conditions: list[dict[str, Any]],
    pid: int | None,
    evidence_dir: Path,
    actions_requested: list[str] | None = None,
    source_collector: str = "unknown",
    design_time_explanation: dict[str, Any] | None = None,
    correlation: dict[str, Any] | None = None,
) -> Path:
    """
    Write evidence to data/evidence/{instance_id}.json.

    UNCONDITIONAL — this is called before any action decision. There is no
    code path where a rule matches and evidence isn't written.

    Returns the path to the written file.

    Raises OSError if the write fails — callers MUST catch this and skip
    action execution (no action without a corresponding evidence record).

    Full evidence schema (Backend_Action_Evidence_Upgrade_Plan §B.2):
    {
      "instance_id": ...,
      "rule_id": ...,
      "rule_name": ...,
      "matched_at": iso8601,
      "severity": "high",
      "entity": {...},
      "event_type": ...,
      "source_collector": ...,
      "matched_conditions": [...],
      "process_tree": {...},
      "raw_event": {...},
      "actions_requested": [...],
      "actions_executed": [],      ← filled in by update_evidence_actions()
      "design_time_explanation": {...}
    }
    """
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = evidence_dir / f"{instance_id}.json"

    # Capture process tree evidence
    process_tree = capture(pid)

    # Build entity dict from tuple (e.g. ("user:admin", "host:server1"))
    entity_dict: dict[str, str] = {}
    for item in entity:
        if ":" in str(item):
            k, v = str(item).split(":", 1)
            entity_dict[k] = v
        else:
            entity_dict["entity"] = str(item)

    # Build matched_conditions with actual vs expected for audit trail
    matched_conditions = []
    for cond in conditions:
        matched_conditions.append({
            "field": cond.get("field", ""),
            "operator": cond.get("operator", "=="),
            "expected": cond.get("value", ""),
        })

    # Preserve the ordered meaning of a correlated rule. The previous flat
    # list remains for compatibility, while this structure lets an operator
    # prove exactly which event satisfied each stage.
    correlation_stages: list[dict[str, Any]] = []
    correlated_events = event.get("correlated_events", [])
    if correlation and isinstance(correlated_events, list):
        for index, stage in enumerate(correlation.get("stages", [])):
            contributing = correlated_events[index] if index < len(correlated_events) else {}
            proc = contributing.get("process", {}) if isinstance(contributing, dict) else {}
            stage_conditions = []
            for condition in stage.get("conditions", []):
                field = str(condition.get("field", ""))
                actual: Any = contributing
                for part in ({"name": "process.name", "pid": "process.pid", "ppid": "process.ppid", "command_line": "process.command_line"}.get(field, field)).split("."):
                    actual = actual.get(part) if isinstance(actual, dict) else None
                stage_conditions.append({
                    "field": field,
                    "operator": condition.get("operator", "=="),
                    "expected": condition.get("value", ""),
                    "actual": actual,
                })
            correlation_stages.append({
                "stage": index + 1,
                "event_type": stage.get("event", "unknown"),
                "conditions": stage_conditions,
                "contributing_event": contributing,
                "process_identity": {
                    "pid": proc.get("pid"), "ppid": proc.get("ppid"),
                    "guid": proc.get("guid"), "parent_guid": proc.get("parent_guid"),
                },
                "process_tree": capture(proc.get("pid")) if proc else {"error": "no_process"},
            })

    record = {
        "instance_id": instance_id,
        "rule_id": rule_id,
        "rule_name": rule_name,
        "rule_text": rule_text,
        "matched_at": datetime.now(timezone.utc).isoformat(),
        "severity": severity,
        "entity": entity_dict,
        "event_type": event.get("event_type", "unknown"),
        "source_collector": source_collector,
        "matched_conditions": matched_conditions,
        "correlation_stages": correlation_stages,
        "process_tree": process_tree,
        "raw_event": event,
        "actions_requested": actions_requested or [],
        "actions_executed": [],  # filled in by update_evidence_actions()
        "design_time_explanation": design_time_explanation or {},
    }

    # This raises OSError on failure — callers catch it and skip actions.
    # "No action without a corresponding evidence record, ever." (Plan §B.1)
    write_signed_json(evidence_path, record, "evidence")

    logger.info("Evidence written: %s", evidence_path)
    return evidence_path


def update_evidence_actions(
    evidence_path: Path,
    action_results: list[dict[str, Any]],
) -> None:
    """
    Update the evidence file with the actual actions executed and their results.

    Called AFTER execute_ordered() returns — updates actions_executed in-place.
    Partial failures (e.g. alert sent, isolate failed) are visible here —
    not swallowed, not lost.

    Never raises — if this fails, the evidence file still exists with the
    actions_requested recorded; we just don't have the individual results.
    """
    if not evidence_path.exists():
        logger.warning(
            "Cannot update evidence actions — file not found: %s", evidence_path
        )
        return

    try:
        with open(evidence_path, "r", encoding="utf-8") as f:
            record = json.load(f)

        record["actions_executed"] = action_results

        write_signed_json(evidence_path, record, "evidence")

        logger.debug("Evidence updated with action results: %s", evidence_path)
    except Exception as exc:
        logger.error(
            "Failed to update evidence actions for %s: %s — "
            "actions_executed will be empty in the evidence record",
            evidence_path, exc,
        )


def cleanup_old_evidence(
    evidence_dir: Path,
    retention_days: int,
    severity_retention: dict[str, int] | None = None,
    max_files: int | None = None,
    max_total_bytes: int | None = None,
) -> int:
    """
    Delete evidence files older than their severity-based retention period.

    Parameters:
        evidence_dir: Path to data/evidence/
        retention_days: Default retention days (used when severity can't be read)
        severity_retention: Optional mapping of severity → max age in days.
            Defaults to: {"low": 14, "medium": 30, "high": 90, "critical": 180}

    Returns the count of deleted files.

    Called by the main loop's background cleanup task (master.md Fix #7).
    Never crashes the main loop — errors are logged and skipped.
    """
    if not evidence_dir.exists():
        return 0

    import time

    # Severity-based retention: low-severity evidence expires faster,
    # critical evidence is kept much longer for audit/compliance.
    default_severity_retention = {
        "low": 14,
        "medium": 30,
        "high": 90,
        "critical": 180,
    }
    retention_map = severity_retention or default_severity_retention

    now = time.time()
    deleted = 0
    youngest_possible_expiry = min([retention_days, *retention_map.values()])

    for f in evidence_dir.glob("*.json"):
        try:
            mtime = os.path.getmtime(f)
            # A file younger than every configured retention threshold cannot
            # expire, so avoid opening/parsing it. This is important for large
            # evidence sets on synced or slower storage.
            if mtime >= now - (youngest_possible_expiry * 86400):
                continue
            # Read the severity from the evidence file to determine retention
            max_age_days = retention_days  # fallback
            try:
                with open(f, "r", encoding="utf-8") as fh:
                    record = json.load(fh)
                severity = record.get("severity", "")
                max_age_days = retention_map.get(severity, retention_days)
            except (json.JSONDecodeError, OSError):
                pass  # use default retention if file can't be read

            cutoff = now - (max_age_days * 86400)
            if mtime < cutoff:
                f.unlink()
                deleted += 1
                logger.debug("Deleted old evidence: %s (severity=%s, max_age=%dd)",
                             f.name, severity if 'severity' in dir() else 'unknown', max_age_days)
        except OSError as exc:
            logger.warning("Failed to delete evidence file %s: %s", f, exc)

    # Age retention alone is not a hard bound during an alert storm. Apply
    # oldest-first quotas after age cleanup so disk use remains predictable.
    try:
        remaining = sorted(
            (
                (path.stat().st_mtime, path.stat().st_size, path)
                for path in evidence_dir.glob("*.json")
            ),
            key=lambda item: item[0],
        )
        total_bytes = sum(item[1] for item in remaining)
        while remaining and (
            (max_files is not None and len(remaining) > max_files)
            or (max_total_bytes is not None and total_bytes > max_total_bytes)
        ):
            _, size, path = remaining.pop(0)
            try:
                path.unlink()
                total_bytes -= size
                deleted += 1
            except OSError as exc:
                logger.warning("Failed quota cleanup for evidence %s: %s", path, exc)
    except OSError as exc:
        logger.warning("Could not calculate evidence storage quota: %s", exc)

    if deleted:
        logger.info(
            "Evidence cleanup: deleted %d file(s) using severity-based retention %s",
            deleted, retention_map,
        )
    return deleted
