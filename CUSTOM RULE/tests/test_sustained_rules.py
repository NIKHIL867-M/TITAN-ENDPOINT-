from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from app.context_builder import build_context
from app.rule_simulator import simulate
from app.semantic_validator import validate_against_context, validate_structure
from watcher.action_engine import ActionEngine
from watcher.aggregation_store import AggregationStore
from watcher.correlation import CorrelationStore
from watcher.main import _process_event
from watcher.state_manager import StateManager
from watcher.sustain_store import SustainStore


def sustained_ir(duration: str = "1m") -> dict:
    return {
        "trigger_event": "process.start", "aggregation": None, "correlation": None,
        "sustain_for": duration,
        "conditions": [{"field": "name", "operator": "==", "value": "notepad.exe"}],
        "investigation_steps": ["collect_process_tree"],
        "suggested_action": ["alert"], "suggested_action_reason": "Process remained open",
        "response_actions": [{"type": "alert", "duration": None}],
        "severity": "medium", "priority": 5, "tags": ["duration"],
    }


def test_sustained_ir_validates_and_simulates_both_outcomes():
    wrapped = {"status": "ok", "clarification": None, "ir": sustained_ir(), "explanation": None}
    structural = validate_structure(wrapped)
    assert structural.valid, structural.errors
    contextual = validate_against_context(structural.parsed, build_context())
    assert contextual.valid, contextual.errors
    result = simulate(structural.parsed)
    assert "sustained-state" in result.summary
    assert [event.did_trigger for event in result.events] == [True, False]


class _FakeProcess:
    def __init__(self, running: bool, created: float = 100.0) -> None:
        self.running, self.created = running, created
    def is_running(self): return self.running
    def status(self): return "running" if self.running else "dead"
    def create_time(self): return self.created


def test_sustain_store_waits_and_checks_same_process_identity():
    event = {"process": {"pid": 42, "guid": "g", "create_time": 100.0}}
    record = {"id": "r"}
    store = SustainStore()
    assert store.schedule(record, event, "1m", now=10.0)
    assert store.pop_due(now=69.9) == []
    entry = store.pop_due(now=70.0)[0]
    assert store.still_true(entry, lambda _pid: _FakeProcess(True, 100.0))
    assert not store.still_true(entry, lambda _pid: _FakeProcess(False, 100.0))
    assert not store.still_true(entry, lambda _pid: _FakeProcess(True, 999.0))


def test_sustained_runtime_does_not_alert_early_then_saves_after_verification(tmp_path: Path):
    inner = sustained_ir("1s")
    record = {"id": "sustain-rule", "rule_text": "Notepad stays open", "ir": {"status": "ok", "ir": inner}}
    event = {"event_type": "process.start", "host": "test", "source_collector": "wmi",
             "process": {"pid": 42, "ppid": 1, "guid": "g", "create_time": 100.0,
                         "name": "notepad.exe", "command_line": "notepad.exe"}, "network": None}
    alerts, evidence = tmp_path / "alerts.jsonl", tmp_path / "evidence"
    store = SustainStore()
    args = [AggregationStore(), StateManager(), CorrelationStore(), ActionEngine(True, 5),
            SimpleNamespace(watcher_dry_run=True), tmp_path, alerts, evidence]
    _process_event(event, [record], *args, sustain_store=store)
    assert store.active_count == 1
    assert not alerts.exists()

    verified = dict(event)
    verified["_sustain_verified_rule_id"] = "sustain-rule"
    verified["sustained_condition"] = {"duration": "1s", "result": "still_running"}
    _process_event(verified, [record], *args, sustain_store=store)
    saved = [json.loads(line) for line in alerts.read_text(encoding="utf-8").splitlines()]
    assert len(saved) == 1
    payload = json.loads(next(evidence.glob("*.json")).read_text(encoding="utf-8"))
    assert payload["raw_event"]["sustained_condition"]["result"] == "still_running"
