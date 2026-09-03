"""Bounded, in-memory ordered event correlation for approved rules."""
from __future__ import annotations
import time
from dataclasses import dataclass
from typing import Any, Callable

@dataclass
class CorrelationEntry:
    next_stage: int
    expires_at: float
    events: list[dict[str, Any]]
    stage_events: dict[int, dict[str, Any]] | None = None

class CorrelationStore:
    def __init__(self, max_entries: int = 10_000) -> None:
        self.max_entries = max_entries
        self._entries: dict[tuple[str, str], CorrelationEntry] = {}

    def process(self, rule_id: str, correlation: dict[str, Any], event: dict[str, Any],
                extract: Callable[[dict[str, Any], str], str],
                matches: Callable[[dict[str, Any], list[dict[str, Any]]], bool]) -> list[dict[str, Any]] | None:
        stages = correlation.get("stages", [])
        if len(stages) < 2:
            return None
        join_on = correlation.get("join_on", "")
        proc = event.get("process") if isinstance(event.get("process"), dict) else {}
        if correlation.get("ordered", True) is False:
            return self._process_unordered(rule_id, correlation, event, extract, matches)
        if join_on == "parent_process":
            return self._process_parent_chain(rule_id, correlation, event, proc, matches)
        join_value = proc.get("guid") if join_on in {"pid", "process.pid"} and proc.get("guid") else extract(event, join_on)
        if not join_value:
            return None
        key, now = (rule_id, join_value), time.monotonic()
        entry = self._entries.get(key)
        if entry and entry.expires_at <= now:
            self._entries.pop(key, None)
            entry = None
        if entry and entry.next_stage < len(stages):
            stage = stages[entry.next_stage]
            if event.get("event_type") == stage.get("event") and matches(event, stage.get("conditions", [])):
                entry.events.append(event)
                entry.next_stage += 1
                if entry.next_stage == len(stages):
                    self._entries.pop(key, None)
                    return entry.events
                return None
        first = stages[0]
        if event.get("event_type") == first.get("event") and matches(event, first.get("conditions", [])):
            if len(self._entries) >= self.max_entries and self._entries:
                oldest = min(self._entries, key=lambda k: self._entries[k].expires_at)
                self._entries.pop(oldest, None)
            self._entries[key] = CorrelationEntry(1, now + _duration_seconds(correlation.get("within", "2m")), [event])
        return None

    def _process_unordered(
        self, rule_id: str, correlation: dict[str, Any], event: dict[str, Any],
        extract: Callable[[dict[str, Any], str], str],
        matches: Callable[[dict[str, Any], list[dict[str, Any]]], bool],
    ) -> list[dict[str, Any]] | None:
        """Match every distinct stage in any order within one joined window."""
        stages = correlation.get("stages", [])
        join_on = correlation.get("join_on", "host")
        join_value = extract(event, join_on)
        if not join_value:
            return None
        key, now = (rule_id, join_value), time.monotonic()
        entry = self._entries.get(key)
        if entry and entry.expires_at <= now:
            self._entries.pop(key, None)
            entry = None
        stage_events = entry.stage_events if entry and entry.stage_events is not None else {}
        matched_index = next((
            index for index, stage in enumerate(stages)
            if index not in stage_events
            and event.get("event_type") == stage.get("event")
            and matches(event, stage.get("conditions", []))
        ), None)
        if matched_index is None:
            return None
        if entry is None:
            if len(self._entries) >= self.max_entries and self._entries:
                oldest = min(self._entries, key=lambda item: self._entries[item].expires_at)
                self._entries.pop(oldest, None)
            entry = CorrelationEntry(
                next_stage=0,
                expires_at=now + _duration_seconds(correlation.get("within", "2m")),
                events=[],
                stage_events={},
            )
            self._entries[key] = entry
        assert entry.stage_events is not None
        entry.stage_events[matched_index] = event
        if len(entry.stage_events) == len(stages):
            completed = [entry.stage_events[index] for index in range(len(stages))]
            self._entries.pop(key, None)
            return completed
        return None

    def _process_parent_chain(
        self, rule_id: str, correlation: dict[str, Any], event: dict[str, Any],
        proc: dict[str, Any], matches: Callable[[dict[str, Any], list[dict[str, Any]]], bool],
    ) -> list[dict[str, Any]] | None:
        """Correlate an ordered process ancestry using child PPID -> parent PID.

        Each process in a real launch chain has a different PID, so a generic
        same-field join cannot represent ancestry. Entries remain bounded by
        the normal expiry and capacity controls.
        """
        stages = correlation.get("stages", [])
        now = time.monotonic()
        try:
            pid = int(proc.get("pid") or 0)
            ppid = int(proc.get("ppid") or 0)
        except (TypeError, ValueError):
            return None
        if not pid:
            return None

        for key, entry in list(self._entries.items()):
            if key[0] != rule_id:
                continue
            if entry.expires_at <= now:
                self._entries.pop(key, None)
                continue
            if entry.next_stage >= len(stages):
                continue
            previous_proc = entry.events[-1].get("process", {})
            try:
                previous_pid = int(previous_proc.get("pid") or 0)
            except (TypeError, ValueError):
                previous_pid = 0
            stage = stages[entry.next_stage]
            previous_guid = str(previous_proc.get("guid") or "")
            parent_guid = str(proc.get("parent_guid") or "")
            identity_matches = ppid == previous_pid and (
                not previous_guid or not parent_guid or parent_guid == previous_guid
            )
            if identity_matches and event.get("event_type") == stage.get("event") and matches(event, stage.get("conditions", [])):
                entry.events.append(event)
                entry.next_stage += 1
                if entry.next_stage == len(stages):
                    self._entries.pop(key, None)
                    return entry.events
                return None

        first = stages[0]
        if event.get("event_type") == first.get("event") and matches(event, first.get("conditions", [])):
            if len(self._entries) >= self.max_entries and self._entries:
                oldest = min(self._entries, key=lambda item: self._entries[item].expires_at)
                self._entries.pop(oldest, None)
            self._entries[(rule_id, str(pid))] = CorrelationEntry(
                1, now + _duration_seconds(correlation.get("within", "2m")), [event]
            )
        return None

    def cleanup(self) -> int:
        now = time.monotonic()
        stale = [k for k, v in self._entries.items() if v.expires_at <= now]
        for key in stale:
            self._entries.pop(key, None)
        return len(stale)

    @property
    def active_count(self) -> int:
        return len(self._entries)

def _duration_seconds(value: str) -> int:
    try:
        return int(value[:-1]) * {"s": 1, "m": 60, "h": 3600}[value[-1]]
    except (ValueError, KeyError, IndexError):
        return 120
