from __future__ import annotations

import json

from app import rule_store
from watcher.collectors.wmi import WmiCollector
from watcher.correlation import CorrelationStore
from watcher.investigation import write_evidence
from watcher.notifier import _append_alert


def _matches(event, conditions):
    return all(event.get("process", {}).get(c["field"]) == c["value"] for c in conditions)


def test_parent_chain_rejects_reused_pid_when_guids_disagree():
    store = CorrelationStore()
    correlation = {"join_on": "parent_process", "within": "2m", "stages": [
        {"event": "process.start", "conditions": [{"field": "name", "value": "cmd.exe"}]},
        {"event": "process.start", "conditions": [{"field": "name", "value": "powershell.exe"}]},
    ]}
    first = {"event_type": "process.start", "process": {"name": "cmd.exe", "pid": 10, "guid": "A"}}
    reused = {"event_type": "process.start", "process": {"name": "powershell.exe", "pid": 20, "ppid": 10, "parent_guid": "OTHER"}}
    store.process("r", correlation, first, lambda e, f: "", _matches)
    assert store.process("r", correlation, reused, lambda e, f: "", _matches) is None
    assert store.active_count == 1


def test_wmi_launcher_shim_is_tagged_not_dropped(monkeypatch):
    monkeypatch.setattr("watcher.collectors.wmi.identify_launcher_shim", lambda *_: {"target": "Notepad.exe"})
    monkeypatch.setattr("watcher.collectors.wmi._process_details", lambda *_: (10.5, 9.5, "C:\\Windows\\System32\\notepad.exe"))
    event = WmiCollector().decode({"name": "notepad.exe", "pid": 20, "ppid": 10, "command_line": "notepad.exe"})
    assert event is not None
    assert event["process"]["is_launcher_shim"] is True
    assert event["process"]["guid"] == "wmi:20:10.500000"
    assert event["process"]["parent_guid"] == "wmi:10:9.500000"


def test_packaged_notepad_image_is_not_misclassified_as_launcher(monkeypatch):
    monkeypatch.setattr("watcher.collectors.wmi.identify_launcher_shim", lambda *_: {"target": "Notepad.exe"})
    monkeypatch.setattr("watcher.collectors.wmi._process_details", lambda *_: (10.5, 9.5, r"C:\\Program Files\\WindowsApps\\Notepad\\Notepad.exe"))
    event = WmiCollector().decode({"name": "notepad.exe", "pid": 20, "ppid": 10,
                                   "command_line": r"C:\\Windows\\System32\\notepad.exe"})
    assert event["process"]["is_launcher_shim"] is False
    assert "WindowsApps" in event["process"]["executable_path"]


def test_correlated_evidence_labels_each_stage(tmp_path, monkeypatch):
    monkeypatch.setattr("watcher.investigation.capture", lambda pid: {"pid": pid})
    events = [
        {"event_type": "process.start", "process": {"name": "cmd.exe", "pid": 1}},
        {"event_type": "process.start", "process": {"name": "powershell.exe", "pid": 2, "ppid": 1}},
    ]
    correlation = {"stages": [
        {"event": "process.start", "conditions": [{"field": "name", "operator": "==", "value": "cmd.exe"}]},
        {"event": "process.start", "conditions": [{"field": "name", "operator": "==", "value": "powershell.exe"}]},
    ]}
    event = dict(events[-1], correlated_events=events)
    path = write_evidence("i", "r", "rule", "rule", "high", ("*",), event, [], 2, tmp_path, correlation=correlation)
    record = json.loads(path.read_text(encoding="utf-8"))
    assert [s["stage"] for s in record["correlation_stages"]] == [1, 2]
    assert record["correlation_stages"][0]["conditions"][0]["actual"] == "cmd.exe"
    assert record["correlation_stages"][1]["process_tree"] == {"pid": 2}


def test_duplicate_cleanup_preserves_oldest_rule_id(tmp_path, monkeypatch):
    rules = tmp_path / "rules.jsonl"
    inner = {"event": "process.start", "conditions": []}
    records = [{"id": "old", "ir": {"ir": inner}}, {"id": "new", "ir": {"ir": inner}}]
    rules.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    monkeypatch.setattr(rule_store, "_RULES_FILE", rules)
    result = rule_store.delete_semantic_duplicates()
    assert result["deleted_ids"] == ["new"]
    assert json.loads(rules.read_text(encoding="utf-8"))["id"] == "old"


def test_alert_rotation_keeps_configured_archive_depth(tmp_path, monkeypatch):
    path = tmp_path / "alerts.jsonl"
    monkeypatch.setenv("WATCHER_ALERT_MAX_BYTES", "1000000")
    monkeypatch.setenv("WATCHER_ALERT_ARCHIVES", "3")
    for generation in range(4):
        path.write_text(str(generation) * 1_000_000, encoding="utf-8")
        _append_alert({"generation": generation}, path)
    assert all((tmp_path / f"alerts.{index}.jsonl").exists() for index in (1, 2, 3))
    assert not (tmp_path / "alerts.4.jsonl").exists()
