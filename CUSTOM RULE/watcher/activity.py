"""Bounded, sanitized runtime activity feed shared with the desktop API."""
from __future__ import annotations
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def activity_subject(event: dict[str, Any]) -> str:
    """Return a sanitized operator label without retaining raw event content."""
    proc = event.get("process") if isinstance(event.get("process"), dict) else {}
    if proc.get("name"):
        pid = f" [{proc.get('pid')}]" if proc.get("pid") is not None else ""
        return f"{proc['name']}{pid}"
    event_type = str(event.get("event_type") or "")
    if event_type == "powershell.script_block":
        path = event.get("path")
        block = str(event.get("script_block_id") or "")[:12]
        return str(path) if path else f"PowerShell script block {block or '(unidentified)'}"
    for field in (
        "task_name", "service_name", "threat_name", "device_name", "rule_name",
        "path", "username", "query_name", "pipe_name", "driver_name",
    ):
        if event.get(field):
            return str(event[field])[:160]
    collector = event.get("source_collector") or "unknown collector"
    return f"{event_type or 'event'} via {collector}"


class ActivityLog:
    def __init__(self, path: Path, max_bytes: int = 2_000_000) -> None:
        self.path, self.max_bytes, self._lock = path, max_bytes, threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, kind: str, event: dict[str, Any] | None = None, **details: Any) -> None:
        event = event or {}
        proc = event.get("process") if isinstance(event.get("process"), dict) else {}
        row = {"at": datetime.now(timezone.utc).isoformat(), "kind": kind,
               "event_type": event.get("event_type"), "collector": event.get("source_collector"),
               "host": event.get("host"), "process_name": proc.get("name"), "pid": proc.get("pid"),
               "subject": activity_subject(event), **details}
        line = json.dumps(row, ensure_ascii=False, default=str) + "\n"
        with self._lock:
            if self.path.exists() and self.path.stat().st_size + len(line.encode("utf-8")) > self.max_bytes:
                with self.path.open("rb") as source:
                    size = source.seek(0, os.SEEK_END)
                    source.seek(-min(size, self.max_bytes // 2), os.SEEK_END)
                    old = source.read(self.max_bytes // 2)
                first_newline = old.find(b"\n")
                self.path.write_bytes(old[first_newline + 1:] if first_newline >= 0 else b"")
            with self.path.open("a", encoding="utf-8") as handle: handle.write(line)

class SavedActivityLog:
    """Opt-in, space/RAM-conscious consolidated log of everything the watcher observes across
    every collector (registry_fim included) -- Santosh, 2026-08-06: "add option to save the logs
    ... keep it off until the user turns it on ... write all logs in one file itself ... try
    compress them a bit". Deliberately separate from the always-on ActivityLog above, which
    already powers the existing live "Watcher Activity" GUI tab and is left untouched here --
    this is purely an additional, larger, OFF-by-default archival file, same "Monitoring vs Save
    Logs" split every native TITAN endpoint already uses. Controlled live by a small control file
    the watcher process polls (see main.py) rather than an env var, so the GUI can flip it without
    restarting the watcher. Consecutive repeats of the same (kind, event_type, subject) within
    repeat_window_s are folded into one line with a repeat_count instead of one line each --
    the same "write once, count the rest" principle used across every other TITAN log this
    session, applied here too rather than dumping raw duplicates into the one big file.
    """

    def __init__(self, path: Path, max_bytes: int = 20_000_000, repeat_window_s: float = 5.0) -> None:
        self.path, self.max_bytes, self.repeat_window_s = path, max_bytes, repeat_window_s
        self._lock = threading.Lock()
        self.enabled = False
        self._last_key: str | None = None
        self._last_row: dict[str, Any] | None = None
        self._last_at: float = 0.0
        path.parent.mkdir(parents=True, exist_ok=True)

    def set_enabled(self, enabled: bool) -> None:
        with self._lock:
            if self.enabled and not enabled:
                self._flush_pending_locked()
            self.enabled = enabled

    def write(self, kind: str, event: dict[str, Any] | None = None, **details: Any) -> None:
        if not self.enabled:
            return
        event = event or {}
        proc = event.get("process") if isinstance(event.get("process"), dict) else {}
        subject = activity_subject(event)
        row = {"at": datetime.now(timezone.utc).isoformat(), "kind": kind,
               "event_type": event.get("event_type"), "collector": event.get("source_collector"),
               "host": event.get("host"), "process_name": proc.get("name"), "pid": proc.get("pid"),
               "subject": subject, **details}
        key = f"{kind}|{event.get('event_type')}|{subject}"
        now = time.monotonic()
        with self._lock:
            if key == self._last_key and self._last_row is not None and (now - self._last_at) <= self.repeat_window_s:
                self._last_row["repeat_count"] = self._last_row.get("repeat_count", 1) + 1
                self._last_row["last_seen"] = row["at"]
                self._last_at = now
                return
            self._flush_pending_locked()
            self._last_key, self._last_row, self._last_at = key, row, now

    def flush(self) -> None:
        with self._lock:
            self._flush_pending_locked()

    def _flush_pending_locked(self) -> None:
        if self._last_row is None:
            return
        line = json.dumps(self._last_row, ensure_ascii=False, default=str) + "\n"
        if self.path.exists() and self.path.stat().st_size + len(line.encode("utf-8")) > self.max_bytes:
            with self.path.open("rb") as source:
                size = source.seek(0, os.SEEK_END)
                source.seek(-min(size, self.max_bytes // 2), os.SEEK_END)
                old = source.read(self.max_bytes // 2)
            first_newline = old.find(b"\n")
            self.path.write_bytes(old[first_newline + 1:] if first_newline >= 0 else b"")
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line)
        self._last_row = None
        self._last_key = None


def write_runtime_status(path: Path, **fields: Any) -> None:
    current = {}
    try: current = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError): pass
    current.update(fields)
    current["heartbeat_at"] = datetime.now(timezone.utc).isoformat()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    try:
        tmp.write_text(json.dumps(current, indent=2, default=str), encoding="utf-8")
        for attempt in range(3):
            try:
                os.replace(tmp, path)
                return
            except PermissionError:
                time.sleep(0.03 * (attempt + 1))
    except OSError:
        pass
    finally:
        try: tmp.unlink(missing_ok=True)
        except OSError: pass
