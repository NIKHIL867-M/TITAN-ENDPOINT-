from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app import main, rule_store
from app.context_builder import EVENT_FIELD_TYPES, _DEFAULT_CONTEXT
from app.rule_normalizer import normalize_rule_ir
from native_gui import _error_text
from watcher.correlation import CorrelationStore
from watcher.main import (
    _all_conditions_match, _extract_field_value, _process_event,
    _evaluate_condition, _unordered_processes_still_running,
)
from watcher.action_engine import ActionEngine
from watcher.aggregation_store import AggregationStore
from watcher.state_manager import StateManager


def _rule(event: str, conditions: list[dict], *, correlation: dict | None = None) -> dict:
    return {
        "trigger_event": event, "aggregation": None, "correlation": correlation,
        "conditions": conditions, "investigation_steps": ["collect_event_context"],
        "suggested_action": ["alert"], "suggested_action_reason": "test",
        "response_actions": [], "severity": "medium", "priority": 5, "tags": ["general-test"],
    }


def test_none_join_is_generalized_to_unordered_same_host():
    draft = _rule("process.start", [], correlation={
        "within": "1m", "join_on": "none",
        "stages": [
            {"event": "process.start", "conditions": [{"field": "name", "operator": "==", "value": "notepad.exe"}]},
            {"event": "process.start", "conditions": [{"field": "name", "operator": "==", "value": "calc.exe"}]},
        ],
    })
    normalized, notes = normalize_rule_ir(draft)
    assert normalized["correlation"]["join_on"] == "host"
    assert normalized["correlation"]["ordered"] is False
    assert normalized["correlation"]["stages"][1]["conditions"][0]["value"] == "CalculatorApp.exe"
    assert len(notes) == 2


def test_paint_alias_normalizes_to_real_runtime_executable():
    draft = _rule(
        "process.start",
        [{"field": "name", "operator": "==", "value": "Paint.exe"}],
    )
    normalized, notes = normalize_rule_ir(draft)
    assert normalized["conditions"][0]["value"] == "mspaint.exe"
    assert notes
    # Existing approved rules containing the former Paint.exe canonical name
    # must also match current Windows telemetry without rewriting persistence.
    event = {"event_type": "process.start", "process": {"name": "mspaint.exe"}}
    assert _evaluate_condition(
        event, {"field": "name", "operator": "==", "value": "Paint.exe"}
    )


def test_unordered_correlation_matches_either_arrival_order():
    correlation = {
        "within": "1m", "join_on": "host", "ordered": False,
        "stages": [
            {"event": "process.start", "conditions": [{"field": "name", "operator": "==", "value": "notepad.exe"}]},
            {"event": "process.start", "conditions": [{"field": "name", "operator": "==", "value": "CalculatorApp.exe"}]},
        ],
    }
    calculator = {"event_type": "process.start", "host": "pc", "process": {"name": "CalculatorApp.exe"}}
    notepad = {"event_type": "process.start", "host": "pc", "process": {"name": "notepad.exe"}}
    store = CorrelationStore()
    assert store.process("r", correlation, calculator, _extract_field_value, _all_conditions_match) is None
    assert store.process("r", correlation, notepad, _extract_field_value, _all_conditions_match) == [notepad, calculator]


class _NamedProcess:
    def __init__(self, name: str) -> None:
        self.info = {"name": name}


def test_process_cooccurrence_requires_both_apps_to_still_be_running():
    correlation = {
        "within": "1m", "join_on": "host", "ordered": False,
        "stages": [
            {"event": "process.start", "conditions": [{"field": "name", "operator": "==", "value": "calc.exe"}]},
            {"event": "process.start", "conditions": [{"field": "name", "operator": "==", "value": "Paint.exe"}]},
        ],
    }
    events = [
        {"event_type": "process.start", "process": {"name": "calc.exe"}},
        {"event_type": "process.start", "process": {"name": "mspaint.exe"}},
    ]
    only_paint = lambda _attrs: iter([_NamedProcess("mspaint.exe")])
    both = lambda _attrs: iter([_NamedProcess("CalculatorApp.exe"), _NamedProcess("mspaint.exe")])
    assert not _unordered_processes_still_running(correlation, events, only_paint)
    assert _unordered_processes_still_running(correlation, events, both)


def test_non_process_unordered_correlation_keeps_event_window_semantics():
    correlation = {
        "within": "1m", "join_on": "host", "ordered": False,
        "stages": [
            {"event": "dns.query", "conditions": []},
            {"event": "network.connect", "conditions": []},
        ],
    }
    assert _unordered_processes_still_running(correlation, [], lambda _: iter(()))


def test_nonconcurrent_process_candidate_does_not_alert_and_reseeds(monkeypatch, tmp_path):
    correlation = {
        "within": "1m", "join_on": "host", "ordered": False,
        "stages": [
            {"event": "process.start", "conditions": [{"field": "name", "operator": "==", "value": "notepad.exe"}]},
            {"event": "process.start", "conditions": [{"field": "name", "operator": "==", "value": "mspaint.exe"}]},
        ],
    }
    ir = _rule("process.start", [], correlation=correlation)
    ir["response_actions"] = [{"type": "alert", "duration": None}]
    record = {"id": "co-rule", "rule_text": "both running", "ir": {"status": "ok", "ir": ir}}
    store = CorrelationStore()
    alerts, evidence = tmp_path / "alerts.jsonl", tmp_path / "evidence"
    args = [
        AggregationStore(), StateManager(), store, ActionEngine(True, 5),
        SimpleNamespace(watcher_dry_run=True), tmp_path, alerts, evidence,
    ]
    notepad = {"event_type": "process.start", "host": "pc", "source_collector": "test",
               "process": {"pid": 1, "name": "notepad.exe"}}
    paint = {"event_type": "process.start", "host": "pc", "source_collector": "test",
             "process": {"pid": 2, "name": "mspaint.exe"}}

    monkeypatch.setattr("watcher.main._unordered_processes_still_running", lambda *_: False)
    _process_event(notepad, [record], *args)
    _process_event(paint, [record], *args)
    assert not alerts.exists()
    assert store.active_count == 1

    monkeypatch.setattr("watcher.main._unordered_processes_still_running", lambda *_: True)
    _process_event(notepad, [record], *args)
    assert len(alerts.read_text(encoding="utf-8").splitlines()) == 1


def test_approval_errors_show_root_messages():
    payload = {"detail": {"error": "draft_check_failed", "messages": ["join field 'none' is unavailable"]}}
    text = _error_text(payload)
    assert "draft check failed" in text
    assert "join field 'none'" in text


def test_structurally_different_available_rules_pass_final_approval(monkeypatch, tmp_path):
    monkeypatch.setattr(rule_store, "_RULES_FILE", tmp_path / "rules.jsonl")
    context = _DEFAULT_CONTEXT.model_copy(deep=True)
    context.agent_status = {
        "active_collectors": context.installed_collectors,
        "supported_events": list(EVENT_FIELD_TYPES),
        "failed_collectors": {},
    }
    monkeypatch.setattr(main, "build_context", lambda: context)
    client = TestClient(main.app)

    drafts = [
        _rule("service.install", [{"field": "service_name", "operator": "contains", "value": "Updater"}]),
        _rule("registry.change", [{"field": "path", "operator": "contains", "value": "Software\\Run"}]),
        _rule("defender.detection", [{"field": "threat_name", "operator": "contains", "value": "Trojan"}]),
        _rule("task.create", [{"field": "task_name", "operator": "contains", "value": "Maintenance"}]),
    ]
    co_occurrence, _ = normalize_rule_ir(_rule("process.start", [], correlation={
        "within": "1m", "join_on": "none",
        "stages": [
            {"event": "process.start", "conditions": [{"field": "name", "operator": "==", "value": "notepad.exe"}]},
            {"event": "process.start", "conditions": [{"field": "name", "operator": "==", "value": "calc.exe"}]},
        ],
    }))
    drafts.append(co_occurrence)

    for index, draft in enumerate(drafts):
        checked = client.post("/api/rules/draft-check", json={"draft": draft})
        assert checked.status_code == 200 and checked.json()["valid"], checked.text
        approved = client.post("/api/rules/approve", json={
            "rule_text": f"general rule {index}",
            "ir": {"status": "ok", "clarification": None, "ir": draft, "explanation": None},
            "response_actions": ["alert"],
        })
        assert approved.status_code == 200, approved.text
        assert approved.json()["status"] == "approved"

    assert rule_store.count_rules() == len(drafts)


@pytest.mark.parametrize(("event_type", "condition", "event"), [
    ("defender.detection", {"field": "threat_name", "operator": "contains", "value": "Trojan"},
     {"threat_name": "Trojan:Win32/Example", "severity": "High"}),
    ("service.install", {"field": "service_name", "operator": "contains", "value": "Updater"},
     {"service_name": "ContosoUpdater", "image_path": "C:\\Tools\\updater.exe"}),
    ("registry.change", {"field": "path", "operator": "contains", "value": "CurrentVersion\\Run"},
     {"registry": {"path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "change_type": "added"}}),
])
def test_non_process_runtime_events_save_alert_and_evidence(tmp_path, event_type, condition, event):
    ir = _rule(event_type, [condition])
    ir["response_actions"] = [{"type": "alert", "duration": None}]
    record = {"id": f"rule-{event_type}", "rule_text": f"test {event_type}", "ir": {"status": "ok", "ir": ir}}
    normalized_event = {"event_type": event_type, "host": "test-host", "source_collector": "test", "process": None, "network": None, **event}
    alerts, evidence = tmp_path / "alerts.jsonl", tmp_path / "evidence"
    _process_event(
        normalized_event, [record], AggregationStore(), StateManager(), CorrelationStore(),
        ActionEngine(True, 5), SimpleNamespace(watcher_dry_run=True), tmp_path, alerts, evidence,
    )
    saved = [json.loads(line) for line in alerts.read_text(encoding="utf-8").splitlines()]
    assert len(saved) == 1 and saved[0]["event_type"] == event_type
    assert len(list(evidence.glob("*.json"))) == 1
