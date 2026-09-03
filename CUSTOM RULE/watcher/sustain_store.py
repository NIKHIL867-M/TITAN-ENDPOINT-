"""Bounded delayed verification for rules whose condition must remain true."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable


def duration_seconds(value: str) -> int:
    try:
        return int(value[:-1]) * {"s": 1, "m": 60, "h": 3600}[value[-1].lower()]
    except (ValueError, KeyError, IndexError, AttributeError):
        return 60


@dataclass
class SustainEntry:
    key: tuple[str, str]
    due_at: float
    rule: dict[str, Any]
    event: dict[str, Any]
    expected_create_time: float | None
    duration: str


class SustainStore:
    """Keep only identity-bound timers; unmatched raw telemetry is not retained."""

    def __init__(self, max_entries: int = 10_000) -> None:
        self.max_entries = max_entries
        self._entries: dict[tuple[str, str], SustainEntry] = {}

    def schedule(self, rule: dict[str, Any], event: dict[str, Any], duration: str, now: float | None = None) -> bool:
        process = event.get("process") if isinstance(event.get("process"), dict) else {}
        pid = int(process.get("pid") or 0)
        if not pid:
            return False
        expected = process.get("create_time")
        if expected is None:
            try:
                import psutil
                expected = psutil.Process(pid).create_time()
            except Exception:
                expected = None
        identity = str(process.get("guid") or f"{pid}:{expected if expected is not None else 'unknown'}")
        key = (str(rule.get("id", "")), identity)
        if key in self._entries:
            return False
        if len(self._entries) >= self.max_entries and self._entries:
            oldest = min(self._entries, key=lambda item: self._entries[item].due_at)
            self._entries.pop(oldest, None)
        current = time.monotonic() if now is None else now
        self._entries[key] = SustainEntry(
            key=key, due_at=current + duration_seconds(duration), rule=rule,
            event=dict(event), expected_create_time=float(expected) if expected is not None else None,
            duration=duration,
        )
        return True

    def pop_due(self, now: float | None = None) -> list[SustainEntry]:
        current = time.monotonic() if now is None else now
        due = [entry for entry in self._entries.values() if entry.due_at <= current]
        for entry in due:
            self._entries.pop(entry.key, None)
        return due

    @staticmethod
    def still_true(entry: SustainEntry, process_lookup: Callable[[int], Any] | None = None) -> bool:
        process = entry.event.get("process", {})
        try:
            pid = int(process.get("pid") or 0)
            if process_lookup is None:
                import psutil
                process_lookup = psutil.Process
            live = process_lookup(pid)
            if not live.is_running():
                return False
            status = str(live.status()).lower()
            if status in {"zombie", "dead"}:
                return False
            if entry.expected_create_time is not None:
                return abs(float(live.create_time()) - entry.expected_create_time) < 0.01
            return True
        except Exception:
            return False

    @property
    def active_count(self) -> int:
        return len(self._entries)
