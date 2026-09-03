"""End-to-end-safe tests for Calculator response and PowerShell correlation."""
import json
from pathlib import Path
from types import SimpleNamespace

from app.rule_normalizer import normalize_rule_ir
from app.semantic_validator import validate_against_context, validate_structure
from app.context_builder import build_context
from watcher.action_engine import ActionEngine
from watcher.aggregation_store import AggregationStore
from watcher.correlation import CorrelationStore
from watcher.main import _all_conditions_match, _evaluate_condition, _extract_field_value, _is_internal_notification_process, _process_event
from watcher.rule_index import initial_load, lookup
from watcher.state_manager import StateManager


def boss_ir():
    return {
        "trigger_event": "process.start", "aggregation": None,
        "correlation": {"within": "2m", "join_on": "pid", "stages": [
            {"event": "process.start", "conditions": [
                {"field": "name", "operator": "==", "value": "powershell.exe"},
                {"field": "command_line", "operator": "contains", "value": "-EncodedCommand"},
            ]},
            {"event": "network.connect", "conditions": [
                {"field": "dest_ip", "operator": "is_public_ip", "value": "true"},
            ]},
        ]},
        "conditions": [],
        "investigation_steps": ["collect_process_tree", "collect_parent_process", "collect_command_line", "collect_network_connection"],
        "response_actions": [{"type": "alert", "duration": None}],
        "severity": "high", "priority": 2, "tags": ["powershell", "correlation"],
        "suggested_action": ["alert"], "suggested_action_reason": "Notify without termination",
    }


def test_calculator_alias_normalizes_and_kill_is_guarded():
    ir = boss_ir()
    ir["correlation"] = None
    ir["conditions"] = [{"field": "name", "operator": "==", "value": "calc.exe"}]
    normalized, notes = normalize_rule_ir(ir)
    assert normalized["conditions"][0]["value"] == "CalculatorApp.exe"
    assert notes
    result = ActionEngine(dry_run=True, max_destructive_per_minute=5).execute_ordered(
        [{"type": "alert"}, {"type": "kill_process"}],
        {"event_type": "process.start", "host": "test", "process": {"pid": 424242}},
        "calculator-test",
    )
    assert [item["action"] for item in result] == ["alert", "kill_process"]
    assert result[1]["result"] == "dry_run"


def test_boss_ir_validates_and_public_ip_operator_is_correct():
    wrapped = {"status": "ok", "clarification": None, "ir": boss_ir(), "explanation": None}
    structural = validate_structure(wrapped)
    assert structural.valid, structural.errors
    contextual = validate_against_context(structural.parsed, build_context())
    assert contextual.valid, contextual.errors
    assert _evaluate_condition({"network": {"dest_ip": "8.8.8.8"}}, {"field": "dest_ip", "operator": "is_public_ip", "value": "true"})
    assert not _evaluate_condition({"network": {"dest_ip": "192.168.1.2"}}, {"field": "dest_ip", "operator": "is_public_ip", "value": "true"})


def test_rule_index_registers_every_correlation_stage(tmp_path: Path):
    record = {"id": "boss", "rule_text": "boss", "ir": {"status": "ok", "ir": boss_ir(), "explanation": None}}
    rules = tmp_path / "rules.jsonl"
    rules.write_text(json.dumps(record) + "\n", encoding="utf-8")
    state = initial_load(rules)
    assert lookup(state, "process.start") == [record]
    assert lookup(state, "network.connect") == [record]


def test_boss_sequence_writes_evidence_and_alert(tmp_path: Path):
    record = {"id": "boss-rule", "rule_text": "encoded PowerShell then public network", "ir": {"status": "ok", "ir": boss_ir(), "explanation": None}}
    alerts, evidence = tmp_path / "alerts.jsonl", tmp_path / "evidence"
    kwargs = dict(rules=[record], agg_store=AggregationStore(), state_mgr=StateManager(),
                  correlation_store=CorrelationStore(), action_engine=ActionEngine(True, 5),
                  cfg=SimpleNamespace(watcher_dry_run=True), data_dir=tmp_path, alerts_file=alerts, evidence_dir=evidence)
    start = {"event_type":"process.start", "host":"test", "source_collector":"sysmon",
             "process":{"pid":4242,"ppid":100,"name":"powershell.exe","command_line":"powershell.exe -EncodedCommand AAA"}, "network":None}
    network = {"event_type":"network.connect", "host":"test", "source_collector":"sysmon",
               "process":{"pid":4242,"name":"powershell.exe"},
               "network":{"dest_ip":"8.8.8.8","dest_port":443,"src_ip":"10.0.0.2","src_port":50000,"protocol":"tcp"}}
    _process_event(event=start, **kwargs)
    assert not alerts.exists()
    _process_event(event=network, **kwargs)
    alert_rows = [json.loads(line) for line in alerts.read_text(encoding="utf-8").splitlines()]
    assert len(alert_rows) == 1 and alert_rows[0]["severity"] == "high"
    evidence_files = list(evidence.glob("*.json"))
    assert len(evidence_files) == 1
    payload = json.loads(evidence_files[0].read_text(encoding="utf-8"))
    assert len(payload["raw_event"]["correlated_events"]) == 2
    assert payload["actions_executed"][0]["result"] == "alerted"


def test_private_ip_does_not_complete_boss_sequence(tmp_path: Path):
    store = CorrelationStore()
    ir = boss_ir()["correlation"]
    start = {"event_type":"process.start", "process":{"pid":9,"name":"powershell.exe","command_line":"-encodedcommand x"}}
    private = {"event_type":"network.connect", "process":{"pid":9}, "network":{"dest_ip":"10.0.0.1"}}
    from watcher.main import _extract_field_value, _all_conditions_match
    assert store.process("r", ir, start, _extract_field_value, _all_conditions_match) is None
    assert store.process("r", ir, private, _extract_field_value, _all_conditions_match) is None
    assert store.active_count == 1


def test_parent_process_chain_requires_exact_pid_ancestry():
    store = CorrelationStore()
    correlation = {"within": "30s", "join_on": "parent_process", "stages": [
        {"event": "process.start", "conditions": [{"field": "name", "operator": "==", "value": "cmd.exe"}]},
        {"event": "process.start", "conditions": [{"field": "name", "operator": "==", "value": "powershell.exe"}]},
        {"event": "process.start", "conditions": [{"field": "name", "operator": "==", "value": "notepad.exe"}]},
    ]}
    cmd = {"event_type":"process.start", "process":{"pid":100, "ppid":10, "name":"cmd.exe"}}
    unrelated_ps = {"event_type":"process.start", "process":{"pid":200, "ppid":99, "name":"powershell.exe"}}
    child_ps = {"event_type":"process.start", "process":{"pid":201, "ppid":100, "name":"powershell.exe"}}
    wrong_notepad = {"event_type":"process.start", "process":{"pid":300, "ppid":100, "name":"notepad.exe"}}
    child_notepad = {"event_type":"process.start", "process":{"pid":301, "ppid":201, "name":"notepad.exe"}}

    assert store.process("chain", correlation, cmd, _extract_field_value, _all_conditions_match) is None
    assert store.process("chain", correlation, unrelated_ps, _extract_field_value, _all_conditions_match) is None
    assert store.process("chain", correlation, child_ps, _extract_field_value, _all_conditions_match) is None
    assert store.process("chain", correlation, wrong_notepad, _extract_field_value, _all_conditions_match) is None
    matched = store.process("chain", correlation, child_notepad, _extract_field_value, _all_conditions_match)
    assert matched == [cmd, child_ps, child_notepad]


def test_internal_toast_powershell_is_identified_without_hiding_normal_powershell():
    toast = {"process": {"name": "powershell.exe", "command_line": "[Windows.UI.Notifications.ToastNotificationManager] app_id Watcher Agent"}}
    normal = {"process": {"name": "powershell.exe", "command_line": "powershell.exe -EncodedCommand AAA"}}
    assert _is_internal_notification_process(toast)
    assert not _is_internal_notification_process(normal)
