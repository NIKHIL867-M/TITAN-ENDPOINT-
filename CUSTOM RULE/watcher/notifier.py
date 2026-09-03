"""
Notifier — `watcher/notifier.py`

Handles all output for a fired rule:
  1. Appends one line to data/alerts.jsonl (O(1), same JSONL pattern as rules.jsonl)
  2. Fires a Windows toast notification via winotify

Design from execute.txt §8:
  - This fires regardless of whether the dashboard is open — it's the
    thing that actually answers "alert me" since a browser tab you're
    not looking at doesn't count as an alert.
  - JSONL format: one line per alert, append-only, no file read needed.

Flaw-fix from execute.txt §7 (audit trail):
  - Each alert record carries: instance_id, evidence_path, rule_id,
    matched_event_type, action_results — enough to reconstruct why
    a kill/isolate happened from the record alone.
"""
from __future__ import annotations

import json
import logging
import os
import queue
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from shared.integrity import sign_record

logger = logging.getLogger(__name__)
_TOAST_QUEUE: queue.Queue[tuple[str, str, str]] = queue.Queue(maxsize=100)
_toast_worker_started = False
_toast_worker_lock = threading.Lock()
ALWAYS_NOTIFY_IN_DRY_RUN = True

try:
    from winotify import Notification, audio
    _WINOTIFY_AVAILABLE = True
except ImportError:
    _WINOTIFY_AVAILABLE = False
    logger.warning(
        "winotify not available — toast notifications will be skipped. "
        "Install with: pip install winotify"
    )


# ═══════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════


def fire_alert(
    rule_id: str,
    rule_text: str,
    severity: str,
    event: dict[str, Any],
    action_results: list[dict[str, Any]],
    instance_id: str,
    evidence_path: Path | None,
    alerts_file: Path,
    dry_run: bool = False,
) -> dict[str, Any]:
    """
    Record an alert and fire a Windows toast. Dry-run only suppresses
    destructive actions; notifications remain real.

    Returns the alert record dict so callers can log it too.
    """
    alert_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    # Build a human-readable summary for the toast
    event_type = event.get("event_type", "unknown")
    host = event.get("host", "?")
    process_name = ""
    if event.get("process"):
        process_name = event["process"].get("name", "")
    summary = _build_summary(event_type, host, process_name, action_results, dry_run)

    # ── Write to alerts.jsonl ─────────────────────────────────────
    record = {
        "id": alert_id,
        "instance_id": instance_id,
        "rule_id": rule_id,
        "rule_text": rule_text,
        "severity": severity,
        "fired_at": now,
        "event_type": event_type,
        "host": host,
        "summary": summary,
        "action_results": action_results,
        "evidence_path": str(evidence_path) if evidence_path else None,
        "dry_run": dry_run,
    }
    _append_alert(record, alerts_file)

    # ── Toast notification ────────────────────────────────────────
    if ALWAYS_NOTIFY_IN_DRY_RUN or not dry_run:
        _send_toast(
            rule_text=rule_text or "Detection Rule",
            severity=severity,
            summary=summary,
        )
    else:
        logger.info("[DRY-RUN] Toast skipped — would have shown: [%s] %s", severity.upper(), summary)

    logger.info(
        "Alert fired: id=%s rule=%s severity=%s host=%s dry_run=%s",
        alert_id[:8], rule_id[:8], severity, host, dry_run,
    )
    return record


# ═══════════════════════════════════════════════════════════════════════
# Internals
# ═══════════════════════════════════════════════════════════════════════


def _append_alert(record: dict[str, Any], alerts_file: Path) -> None:
    """Append one alert record to alerts.jsonl. O(1) — no file read."""
    alerts_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        record = sign_record(record, alerts_file.parent, "alert")
        max_bytes = max(1_000_000, int(os.environ.get("WATCHER_ALERT_MAX_BYTES", "5000000")))
        archive_count = min(20, max(1, int(os.environ.get("WATCHER_ALERT_ARCHIVES", "4"))))
        encoded = json.dumps(record, ensure_ascii=False, default=str) + "\n"
        if alerts_file.exists() and alerts_file.stat().st_size + len(encoded.encode("utf-8")) > max_bytes:
            oldest = alerts_file.with_name(f"alerts.{archive_count}.jsonl")
            oldest.unlink(missing_ok=True)
            for index in range(archive_count - 1, 0, -1):
                source = alerts_file.with_name(f"alerts.{index}.jsonl")
                if source.exists():
                    os.replace(source, alerts_file.with_name(f"alerts.{index + 1}.jsonl"))
            os.replace(alerts_file, alerts_file.with_name("alerts.1.jsonl"))
        with open(alerts_file, "a", encoding="utf-8") as f:
            f.write(encoded)
    except OSError as exc:
        # Never crash the main loop for a write failure — log and continue.
        logger.error("Failed to write alert to %s: %s", alerts_file, exc)


def _send_toast(rule_text: str, severity: str, summary: str) -> None:
    """Queue a toast without ever blocking the watcher event loop."""
    if not _WINOTIFY_AVAILABLE:
        logger.warning("Toast skipped (winotify not available): [%s] %s", severity.upper(), summary)
        return
    global _toast_worker_started
    with _toast_worker_lock:
        if not _toast_worker_started:
            threading.Thread(target=_toast_worker, name="watcher-toast", daemon=True).start()
            _toast_worker_started = True
    try:
        _TOAST_QUEUE.put_nowait((rule_text, severity, summary))
    except queue.Full:
        logger.warning("Toast queue full; notification dropped while alert/evidence remain saved")


def _toast_worker() -> None:
    while True:
        rule_text, severity, summary = _TOAST_QUEUE.get()
        _show_toast(rule_text, severity, summary)


def _show_toast(rule_text: str, severity: str, summary: str) -> None:
    """Perform the potentially slow Windows notification call off-loop."""

    # Keep user-authored rule text out of winotify's helper-process command
    # line. Otherwise a PowerShell command-line rule can match its own toast
    # helper and recursively generate alerts.
    title = f"[{severity.upper()}] GEKKO detection alert"
    try:
        n = Notification(
            app_id="Watcher Agent",
            title=title,
            msg=summary[:200],
            duration="long",
        )
        # Use a warning audio for high/critical, default for others
        if severity.lower() in ("high", "critical"):
            n.set_audio(audio.LoopingAlarm, loop=False)
        n.show()
    except Exception as exc:
        # Never crash the main loop for a toast failure.
        logger.warning("Toast notification failed: %s", exc)


def _build_summary(
    event_type: str,
    host: str,
    process_name: str,
    action_results: list[dict[str, Any]],
    dry_run: bool,
) -> str:
    """Build a concise human-readable alert summary."""
    parts = []
    if process_name:
        parts.append(f"Process: {process_name}")
    parts.append(f"Host: {host}")
    parts.append(f"Event: {event_type}")

    action_types = [r.get("action") for r in action_results if r.get("action")]
    if action_types:
        parts.append(f"Actions: {', '.join(action_types)}")

    if dry_run:
        parts.append("[DRY-RUN]")

    return " | ".join(parts)
