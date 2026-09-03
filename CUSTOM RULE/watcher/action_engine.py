"""
Action engine — `watcher/action_engine.py`

Executes the response_actions from an approved rule when it fires.

Three action types for v1 (execute.txt §7):
  - alert        — log + toast notification (always safe)
  - kill_process — terminate the matched process via psutil
  - isolate_host — add outbound-block firewall rule via netsh

Guardrails — all four from execute.txt §7, none skipped:

1. DRY-RUN MODE (default: ON)
   WATCHER_DRY_RUN=true logs "would have killed PID X" without acting.
   Destructive actions only run when DRY_RUN=false.

2. AGENT-WIDE RATE LIMIT
   A deque-based circuit breaker: if kill/isolate actions fired more
   than MAX_DESTRUCTIVE_PER_MINUTE times in the last 60s, further
   destructive actions are blocked and logged. Prevents a miscalibrated
   rule matching in a tight loop from damaging the host.

3. ISOLATE_HOST SELF-EXPIRY (flaw fix #1)
   Every isolation schedules its own removal via threading.Timer.
   Expiry failure is logged loudly. An isolation that never lifts
   would turn this tool into a self-inflicted outage.

4. SELF-ISOLATION PREVENTION (flaw fix implied)
   isolate_host checks the target isn't the host running the watcher.
   (Caller provides the target host; if it matches socket.gethostname()
   and no break-glass env var is set, the action is blocked.)

Upgrade (Backend_Action_Evidence_Upgrade_Plan):
  - ActionType enum imported from shared.action_types — no hardcoded strings.
  - EXECUTION_ORDER guarantees: ALERT → ISOLATE_HOST → KILL_PROCESS.
  - execute_ordered() uses fixed order regardless of list order in rule.
  - Per-action results include timestamps for the evidence record.
"""
from __future__ import annotations

import logging
import json
import os
import socket
import subprocess
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shared.action_types import ActionType, EXECUTION_ORDER, DESTRUCTIVE_ACTIONS
from shared.windows_aliases import canonical_executable

logger = logging.getLogger(__name__)

# FIX (safe process termination): Windows recycles PIDs once a process
# exits. If a rule fires on a stale PID -- correlation delay, aggregation
# window, sustain_for wait -- the OS may have already reassigned that PID to
# an unrelated process by the time kill_process actually runs. Revalidate
# identity immediately before killing rather than trusting the PID alone.
#
# Never kill TITAN's own components or core Windows processes regardless of
# what a rule says -- a rule that matched on name/PID confusion should never
# be able to take down the monitoring stack itself or destabilize the OS.
_PROTECTED_PROCESS_NAMES: frozenset[str] = frozenset({
    # TITAN's own 6 components -- killing any of these blinds coverage.
    "titan_process.exe", "titan.exe", "usb_test.exe", "file_test.exe",
    "application_endpoint.exe", "correlator.exe",
    # Core Windows processes -- killing these can crash or lock out the user.
    "system", "system idle process", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "lsass.exe", "explorer.exe",
})

# Wall-clock tolerance for create-time comparison. psutil's create_time()
# and the value an event carried through decode/queue/match latency can
# differ by a small amount even for the genuinely same process; this is not
# a precision requirement, just enough slack to not false-positive on that
# latency while still catching "a different process now owns this PID"
# (which differs by seconds to hours, not milliseconds).
_CREATE_TIME_TOLERANCE_S = 5.0


def _revalidate_kill_target(pid: int, event: dict[str, Any]) -> tuple[bool, str]:
    """
    Confirm the live process at `pid` right now is still the one the rule
    actually matched, immediately before killing it. Returns (ok, reason).
    """
    if not _PSUTIL_AVAILABLE:
        return False, "psutil_unavailable"

    proc_info = event.get("process") if isinstance(event.get("process"), dict) else {}
    expected_name = str(proc_info.get("name", "")).strip()

    try:
        live = psutil.Process(pid)
        live_name = canonical_executable(live.name())
    except psutil.NoSuchProcess:
        return False, "already_exited"
    except psutil.AccessDenied:
        return False, "access_denied"

    if live_name in _PROTECTED_PROCESS_NAMES:
        return False, f"protected_process:{live_name}"

    if expected_name:
        expected_canonical = canonical_executable(expected_name)
        if expected_canonical in _PROTECTED_PROCESS_NAMES:
            return False, f"protected_process:{expected_canonical}"
        if live_name != expected_canonical:
            # The name at this PID no longer matches what the rule matched
            # on -- exactly the PID-reuse case this revalidation exists for.
            return False, f"pid_reuse_suspected:expected={expected_canonical}:live={live_name}"

    expected_create_time = proc_info.get("create_time")
    if expected_create_time is not None:
        try:
            live_create_time = live.create_time()
            if abs(live_create_time - float(expected_create_time)) > _CREATE_TIME_TOLERANCE_S:
                return False, "pid_reuse_suspected:create_time_mismatch"
        except (psutil.NoSuchProcess, psutil.AccessDenied, TypeError, ValueError):
            pass  # can't compare -- name match above is still a real signal

    return True, "revalidated"

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════════════
# Circuit breaker (rate limit on destructive actions)
# ═══════════════════════════════════════════════════════════════════════


class DestructiveRateLimiter:
    """
    Agent-wide rate limiter for kill/isolate actions.
    Uses a sliding-window deque of action timestamps.
    """

    def __init__(self, max_per_minute: int) -> None:
        self._max = max_per_minute
        self._timestamps: deque[float] = deque()
        self._lock = threading.Lock()  # this one IS accessed from timer threads

    def check_and_record(self) -> bool:
        """
        Returns True if the action is allowed (and records it).
        Returns False if the circuit breaker is tripped.
        """
        with self._lock:
            now = time.time()
            # Drop timestamps older than 60s
            while self._timestamps and (now - self._timestamps[0]) > 60.0:
                self._timestamps.popleft()
            if len(self._timestamps) >= self._max:
                return False
            self._timestamps.append(now)
            return True

    @property
    def recent_count(self) -> int:
        with self._lock:
            now = time.time()
            return sum(1 for t in self._timestamps if (now - t) <= 60.0)


# ═══════════════════════════════════════════════════════════════════════
# Action engine
# ═══════════════════════════════════════════════════════════════════════


class ActionEngine:
    """Executes rule response actions with all guardrails applied."""

    ISOLATE_RULE_NAME = "WatcherAgent_Isolate"

    # Ports a remote analyst is plausibly managing this box through right
    # now. isolate_host refuses to proceed if one of these has an ESTABLISHED
    # connection, to avoid a rule stranding the operator mid-session -- see
    # _has_active_management_session for the "why" (Windows Firewall block
    # rules always win over allow rules, so there is no safe way to punch a
    # narrow exception through a block-all rule; refusing to isolate is the
    # honest alternative to a rule that silently doesn't actually protect it).
    _MANAGEMENT_PORTS = frozenset({3389, 22, 5985, 5986})

    def __init__(
        self,
        dry_run: bool,
        max_destructive_per_minute: int,
    ) -> None:
        self.dry_run = dry_run
        self._rate_limiter = DestructiveRateLimiter(max_destructive_per_minute)
        self._local_hostname = socket.gethostname().lower()
        self._verified_local_identities = self._build_local_identities()
        self._active_isolations: dict[str, threading.Timer] = {}
        # FIX (thread-safe isolation state): _lift_isolation runs on
        # independent threading.Timer threads, one per active isolation --
        # two expiring around the same time previously raced on a
        # read-modify-write of active_isolations.json with no lock,
        # silently losing whichever wrote last.
        self._isolation_state_lock = threading.Lock()
        data_dir = Path(os.environ.get("WATCHER_DATA_DIR", "data"))
        if not data_dir.is_absolute(): data_dir = Path(__file__).resolve().parents[1] / data_dir
        self._isolation_file = data_dir / "active_isolations.json"
        if not dry_run:
            self._recover_isolations()

        if dry_run:
            logger.warning(
                "ActionEngine: DRY-RUN MODE is ON. "
                "Destructive actions will be LOGGED but NOT executed. "
                "Set WATCHER_DRY_RUN=false to enable real actions."
            )
        else:
            logger.warning(
                "ActionEngine: DRY-RUN MODE is OFF. "
                "Destructive actions (kill_process, isolate_host) WILL execute."
            )

    def execute(
        self,
        actions: list[dict[str, Any]],
        event: dict[str, Any],
        instance_id: str,
        evidence_path: Path | None = None,
    ) -> list[dict[str, Any]]:
        """
        Execute all response actions for a fired rule (original order preserved).
        Returns a list of result dicts (one per action).

        Prefer execute_ordered() for new callers — it enforces the canonical
        ALERT → ISOLATE_HOST → KILL_PROCESS order regardless of list order.
        """
        results = []
        for action_spec in actions:
            action_type = action_spec.get("type", "alert")
            result = self._dispatch(action_type, action_spec, event, instance_id, evidence_path)
            results.append(result)
        return results

    def execute_ordered(
        self,
        actions: list[dict[str, Any]],
        event: dict[str, Any],
        instance_id: str,
        evidence_path: Path | None = None,
    ) -> list[dict[str, Any]]:
        """
        Execute response actions in canonical order: ALERT → ISOLATE_HOST → KILL_PROCESS.

        This guarantees:
          1. Alert fires first (non-destructive, never delayed)
          2. Isolate before Kill (reversible containment before irreversible termination)

        If both are selected and the second fails (e.g. netsh error), the first
        has already landed. Partial success is recorded per-action in the results.
        """
        # Build a lookup from action type string → action spec
        action_map: dict[str, dict[str, Any]] = {}
        for spec in actions:
            action_type_str = spec.get("type", "")
            action_map[action_type_str] = spec

        results = []
        for ordered_action in EXECUTION_ORDER:
            if ordered_action.value in action_map:
                spec = action_map[ordered_action.value]
                result = self._dispatch(
                    ordered_action.value, spec, event, instance_id, evidence_path
                )
                results.append(result)

        return results

    # ── Dispatch ──────────────────────────────────────────────────

    def _dispatch(
        self,
        action_type: str,
        action_spec: dict[str, Any],
        event: dict[str, Any],
        instance_id: str,
        evidence_path: Path | None,
    ) -> dict[str, Any]:
        now_iso = datetime.now(timezone.utc).isoformat()
        if action_type == ActionType.ALERT.value:
            result = self._do_alert(action_spec, event, instance_id, evidence_path)
        elif action_type == ActionType.KILL_PROCESS.value:
            result = self._do_kill_process(event, instance_id)
        elif action_type == ActionType.ISOLATE_HOST.value:
            result = self._do_isolate_host(action_spec, event, instance_id)
        else:
            logger.warning("Unknown action type: '%s' (no-op)", action_type)
            result = {"action": action_type, "result": "unknown_action_type"}
        # Always stamp with execution time for the evidence record
        result["at"] = now_iso
        return result

    # ── Alert (always safe, no guardrail needed) ───────────────────

    def _do_alert(
        self,
        action_spec: dict[str, Any],
        event: dict[str, Any],
        instance_id: str,
        evidence_path: Path | None,
    ) -> dict[str, Any]:
        logger.info(
            "ALERT fired — instance=%s event_type=%s host=%s",
            instance_id[:8], event.get("event_type"), event.get("host"),
        )
        return {
            "action": "alert",
            "instance_id": instance_id,
            "evidence_path": str(evidence_path) if evidence_path else None,
            "result": "alerted",
        }

    # ── Kill process ───────────────────────────────────────────────

    def _do_kill_process(
        self,
        event: dict[str, Any],
        instance_id: str,
    ) -> dict[str, Any]:
        pid = None
        if event.get("process"):
            pid = event["process"].get("pid")

        if pid is None:
            logger.warning("kill_process: no PID in event (instance=%s)", instance_id[:8])
            return {"action": "kill_process", "result": "no_pid"}

        # ── Guardrail 2: rate limit ─────────────────────────────
        if not self._rate_limiter.check_and_record():
            logger.error(
                "CIRCUIT BREAKER TRIPPED: kill_process blocked for PID %d — "
                "too many destructive actions in the last 60s (count=%d). "
                "Check your rules for miscalibration.",
                pid, self._rate_limiter.recent_count,
            )
            return {"action": "kill_process", "pid": pid, "result": "circuit_breaker_tripped"}

        # ── Guardrail 1: dry-run ────────────────────────────────
        # Dry-run reports intent without requiring a live target -- rule
        # logic can be exercised against synthetic PIDs. Revalidation below
        # only matters once an action can actually do something.
        if self.dry_run:
            logger.warning("[DRY-RUN] Would have killed PID %d", pid)
            return {"action": "kill_process", "pid": pid, "result": "dry_run"}

        # ── Guardrail 5: revalidate identity immediately before acting ──
        # Windows can reuse a PID after the original process exits; a
        # correlation/aggregation/sustain delay is enough time for that to
        # happen. Confirm the live process at this PID right now is still
        # the one the rule matched (name, and create_time when available)
        # and that it isn't TITAN's own component or a core OS process.
        revalidated, reason = _revalidate_kill_target(pid, event)
        if not revalidated:
            logger.error("kill_process: BLOCKED for PID %d — %s", pid, reason)
            return {"action": "kill_process", "pid": pid, "result": f"blocked:{reason}"}

        # ── Real execution ─────────────────────────────────────
        try:
            proc = psutil.Process(pid)
            proc.kill()
            logger.warning("kill_process: KILLED PID %d (%s)", pid, proc.name())
            return {"action": "kill_process", "pid": pid, "result": "killed"}
        except psutil.NoSuchProcess:
            return {"action": "kill_process", "pid": pid, "result": "already_exited"}
        except psutil.AccessDenied:
            logger.error("kill_process: access denied for PID %d", pid)
            return {"action": "kill_process", "pid": pid, "result": "access_denied"}
        except Exception as exc:
            logger.error("kill_process: unexpected error for PID %d: %s", pid, exc)
            return {"action": "kill_process", "pid": pid, "result": f"error: {exc}"}

    # ── Isolate host ───────────────────────────────────────────────

    def _do_isolate_host(
        self,
        action_spec: dict[str, Any],
        event: dict[str, Any],
        instance_id: str,
    ) -> dict[str, Any]:
        target_host = event.get("host", "").lower()

        # ── Guardrail 4a: verified local host identity ───────────
        # FIX: this action only ever has one real enforcement mechanism --
        # a local Windows Firewall rule on THIS machine. The previous check
        # only blocked when target_host exactly equaled the local hostname,
        # meaning any OTHER host string (a typo, a differently-cased name, a
        # host from a future multi-host deployment this single-host firewall
        # rule cannot actually reach) fell through and isolated this machine
        # anyway while believing it had isolated something else. Only
        # proceed when target_host is empty (most collectors don't always
        # set it) or verifiably identifies this machine; otherwise refuse
        # rather than silently isolate the wrong entity.
        if target_host and target_host not in self._verified_local_identities:
            logger.error(
                "isolate_host: REFUSED — event names host '%s', which this "
                "watcher cannot verify as itself, and no remote isolation "
                "capability exists. Isolating THIS machine would be wrong.",
                target_host,
            )
            return {"action": "isolate_host", "host": target_host, "result": "unverified_host_refused"}

        # ── Guardrail 4b: self-isolation break-glass ──────────────
        allow_self = os.environ.get("WATCHER_ALLOW_SELF_ISOLATE", "").lower() == "true"
        if not allow_self:
            logger.error(
                "SELF-ISOLATION BLOCKED for host '%s' (isolate_host always "
                "targets this machine — see above). Set "
                "WATCHER_ALLOW_SELF_ISOLATE=true (break-glass) to override.",
                target_host,
            )
            return {"action": "isolate_host", "host": target_host, "result": "self_isolation_blocked"}

        # ── Guardrail 4c: protect management access ───────────────
        # Windows Firewall block rules always win over allow rules
        # regardless of specificity or creation order, so there is no way
        # to punch a narrow "except my own RDP/SSH/WinRM session" exception
        # through a block-all outbound rule. Refusing to isolate when one of
        # those is actively established is the honest alternative to a rule
        # that can't actually keep the promise of protecting it.
        ignore_mgmt = os.environ.get("WATCHER_ISOLATE_IGNORE_MANAGEMENT_CHECK", "").lower() == "true"
        if not ignore_mgmt and self._has_active_management_session():
            logger.error(
                "isolate_host: REFUSED — an active RDP/SSH/WinRM session was "
                "detected; a block-all outbound rule could strand the "
                "operator. Set WATCHER_ISOLATE_IGNORE_MANAGEMENT_CHECK=true "
                "to override."
            )
            return {"action": "isolate_host", "host": target_host, "result": "management_session_active_refused"}

        # ── Guardrail 2: rate limit ─────────────────────────────
        if not self._rate_limiter.check_and_record():
            logger.error(
                "CIRCUIT BREAKER TRIPPED: isolate_host blocked — "
                "too many destructive actions in the last 60s."
            )
            return {"action": "isolate_host", "host": target_host, "result": "circuit_breaker_tripped"}

        # ── Parse duration ─────────────────────────────────────
        duration_str = action_spec.get("duration") or "30m"
        duration_s = _parse_duration_to_seconds(duration_str)

        # ── Guardrail 1: dry-run ────────────────────────────────
        if self.dry_run:
            logger.warning(
                "[DRY-RUN] Would have isolated host '%s' for %ds (%s)",
                target_host, duration_s, duration_str,
            )
            return {
                "action": "isolate_host",
                "host": target_host,
                "duration_s": duration_s,
                "result": "dry_run",
            }

        # ── Real execution ─────────────────────────────────────
        try:
            # FIX: remoteip=0.0.0.0/0 only scopes to IPv4 -- IPv6 outbound
            # traffic was completely unaffected by "isolation". remoteip=any
            # matches any remote address regardless of family, giving real
            # IPv4+IPv6 coverage in one rule.
            subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={self.ISOLATE_RULE_NAME}_{instance_id[:8]}",
                    "dir=out", "action=block", "enable=yes",
                    "remoteip=any",
                    "description=WatcherAgent isolation rule — auto-expires",
                ],
                check=True, capture_output=True,
            )
            logger.warning(
                "isolate_host: ISOLATED host for %ds — rule %s",
                duration_s, instance_id[:8],
            )

            # ── Guardrail 3: schedule self-expiry (flaw fix #1) ──
            rule_name = f"{self.ISOLATE_RULE_NAME}_{instance_id[:8]}"
            self._persist_isolation(instance_id, rule_name, time.time() + duration_s)
            timer = threading.Timer(
                duration_s,
                self._lift_isolation,
                args=[rule_name, instance_id],
            )
            timer.daemon = True
            timer.start()
            self._active_isolations[instance_id] = timer
            logger.info(
                "isolate_host: self-expiry timer set for %ds (instance=%s)",
                duration_s, instance_id[:8],
            )

            return {
                "action": "isolate_host",
                "host": target_host,
                "duration_s": duration_s,
                "result": "isolated",
            }
        except subprocess.CalledProcessError as exc:
            logger.error("isolate_host: netsh failed: %s", exc)
            return {"action": "isolate_host", "host": target_host, "result": f"netsh_error: {exc}"}
        except Exception as exc:
            logger.error("isolate_host: unexpected error: %s", exc)
            return {"action": "isolate_host", "host": target_host, "result": f"error: {exc}"}

    def _lift_isolation(self, rule_name: str, instance_id: str) -> None:
        """
        Remove the firewall isolation rule after the duration expires.
        Called by threading.Timer — logs loudly if removal fails (flaw fix #1).
        """
        removed = False
        try:
            subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_name}",
                ],
                check=True, capture_output=True,
            )
            logger.info(
                "isolate_host: isolation LIFTED for rule '%s' (instance=%s)",
                rule_name, instance_id[:8],
            )
            removed = True
        except subprocess.CalledProcessError as exc:
            logger.error(
                "CRITICAL: Failed to lift isolation rule '%s' — "
                "HOST MAY STILL BE ISOLATED. Manual removal required: "
                "netsh advfirewall firewall delete rule name=\"%s\". "
                "Error: %s",
                rule_name, rule_name, exc,
            )
        except Exception as exc:
            logger.error(
                "CRITICAL: Unexpected error lifting isolation '%s': %s",
                rule_name, exc,
            )
        finally:
            self._active_isolations.pop(instance_id, None)
            if removed: self._forget_isolation(instance_id)

    def _load_isolations(self) -> dict[str, dict[str, Any]]:
        try: return json.loads(self._isolation_file.read_text(encoding="utf-8"))
        except (OSError, ValueError): return {}

    def _write_isolations(self, entries: dict[str, dict[str, Any]]) -> None:
        self._isolation_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._isolation_file.with_name(f"{self._isolation_file.name}.{os.getpid()}.tmp")
        tmp.write_text(json.dumps(entries, indent=2), encoding="utf-8")
        os.replace(tmp, self._isolation_file)

    def _persist_isolation(self, instance_id: str, rule_name: str, expires_at: float) -> None:
        # FIX (thread safety): read-modify-write must be atomic as a whole,
        # not just the final os.replace -- _lift_isolation runs on
        # independent Timer threads and can call _forget_isolation
        # concurrently with this.
        with self._isolation_state_lock:
            entries = self._load_isolations()
            entries[instance_id] = {"rule_name": rule_name, "expires_at": expires_at}
            self._write_isolations(entries)

    def _forget_isolation(self, instance_id: str) -> None:
        with self._isolation_state_lock:
            entries = self._load_isolations(); entries.pop(instance_id, None)
            try: self._write_isolations(entries)
            except OSError as exc: logger.error("Could not update isolation recovery state: %s", exc)

    # ── Guardrail helpers ────────────────────────────────────────

    def _build_local_identities(self) -> frozenset[str]:
        """Every name/address this machine can legitimately be called."""
        identities = {self._local_hostname, "localhost", "127.0.0.1", "::1"}
        try:
            fqdn = socket.getfqdn().lower()
            if fqdn:
                identities.add(fqdn)
        except OSError:
            pass
        try:
            _, _, ip_list = socket.gethostbyname_ex(socket.gethostname())
            identities.update(ip.lower() for ip in ip_list)
        except OSError:
            pass
        return frozenset(identities)

    def _has_active_management_session(self) -> bool:
        """True if an RDP/SSH/WinRM connection is currently established."""
        if not _PSUTIL_AVAILABLE:
            return False
        try:
            for conn in psutil.net_connections(kind="tcp"):
                if (
                    conn.status == psutil.CONN_ESTABLISHED
                    and conn.laddr
                    and conn.laddr.port in self._MANAGEMENT_PORTS
                ):
                    return True
        except (psutil.AccessDenied, OSError):
            pass
        return False

    def _recover_isolations(self) -> None:
        """Resume or immediately lift firewall rules left by an earlier crash."""
        now = time.time()
        for instance_id, entry in self._load_isolations().items():
            rule_name = str(entry.get("rule_name", ""))
            remaining = float(entry.get("expires_at", 0)) - now
            if not rule_name: continue
            if remaining <= 0:
                logger.warning("Removing expired isolation left by a previous watcher run: %s", rule_name)
                self._lift_isolation(rule_name, instance_id)
            else:
                timer = threading.Timer(remaining, self._lift_isolation, args=[rule_name, instance_id])
                timer.daemon = True; timer.start(); self._active_isolations[instance_id] = timer
                logger.warning("Recovered active isolation %s; removal scheduled in %.0fs", rule_name, remaining)


# ═══════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════


def _parse_duration_to_seconds(duration_str: str) -> int:
    """
    Convert a duration string like "30m", "1h", "2d" to seconds.
    Defaults to 1800s (30 minutes) if parsing fails.
    """
    if not duration_str:
        return 1800
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    try:
        unit = duration_str[-1].lower()
        value = int(duration_str[:-1])
        return value * units.get(unit, 1)
    except (ValueError, IndexError):
        logger.warning("Invalid duration '%s' — defaulting to 30m", duration_str)
        return 1800
