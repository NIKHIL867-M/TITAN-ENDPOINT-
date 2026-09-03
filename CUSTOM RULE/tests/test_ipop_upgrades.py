"""Tests for independently reimplemented IPOP-inspired monitoring features."""
from pathlib import Path
import json
from types import SimpleNamespace

from watcher.bookmarks import EventBookmark
from watcher.collectors.inventory import InventoryCollector
from watcher.collectors.registry_fim import RegistryIntegrityCollector
from watcher.collectors.security import SecurityCollector
from watcher.collectors.wmi import _is_packaged_notepad_launcher
from watcher.main import _extract_field_value
from watcher.main import _process_event
from watcher.action_engine import ActionEngine
from watcher.aggregation_store import AggregationStore
from watcher.correlation import CorrelationStore
from watcher.state_manager import StateManager


class FakeEventApi:
    EvtSubscribeToFutureEvents = 1
    EvtSubscribeStartAfterBookmark = 3
    EvtRenderBookmark = 2

    def __init__(self, reject_saved=False):
        self.reject_saved = reject_saved
        self.calls = []
    def EvtCreateBookmark(self, xml): return {"xml": xml}
    def EvtUpdateBookmark(self, bookmark, event): bookmark["event"] = event
    def EvtRender(self, bookmark, flag): return f"<Bookmark Event='{bookmark['event']}'/>"
    def EvtSubscribe(self, channel, flags, **kwargs):
        self.calls.append((channel, flags, kwargs.get("Bookmark")))
        if self.reject_saved and flags == self.EvtSubscribeStartAfterBookmark:
            raise OSError("stale")
        return "subscription"


def test_bookmark_persists_and_resumes_atomically(tmp_path: Path):
    api = FakeEventApi()
    bookmark = EventBookmark("System", api)
    bookmark.path = tmp_path / "System.xml"
    bookmark.advance("event-42")
    assert "event-42" in bookmark.path.read_text(encoding="utf-8")
    second = EventBookmark("System", api); second.path = bookmark.path
    assert second.subscribe(lambda *args: None) == "subscription"
    assert api.calls[-1][1] == api.EvtSubscribeStartAfterBookmark


def test_stale_bookmark_falls_back_to_future_events(tmp_path: Path):
    api = FakeEventApi(reject_saved=True)
    bookmark = EventBookmark("Security", api); bookmark.path = tmp_path / "Security.xml"
    bookmark.path.write_text("<Bookmark/>", encoding="utf-8")
    assert bookmark.subscribe(lambda *args: None) == "subscription"
    assert [call[1] for call in api.calls] == [3, 1]
    assert not bookmark.path.exists()


def test_registry_baseline_roundtrip_and_normalized_fields(tmp_path: Path):
    collector = RegistryIntegrityCollector(); collector.baseline_file = tmp_path / "registry.json"
    baseline = {r"HKCU\Software\Example|Value": "abc"}
    collector._save(baseline)
    assert collector._load() == baseline
    event = collector.decode({"path": r"HKCU\Software\Example", "value_name": "Value", "change_type": "modified", "old_hash": "a", "new_hash": "b"})
    assert event["event_type"] == "registry.change"
    assert _extract_field_value(event, "change_type") == "modified"
    assert _extract_field_value(event, "value_name") == "value"


def test_inventory_snapshot_is_bounded_and_normalized(tmp_path: Path):
    collector = InventoryCollector(); collector.baseline_file = tmp_path / "inventory.json"
    snapshot = collector._snapshot()
    assert isinstance(snapshot, dict)
    assert len(snapshot) <= 10_000
    assert any(key.startswith("network|") for key in snapshot)
    event = collector.decode({"category": "network", "item": "Ethernet", "change_type": "modified"})
    assert _extract_field_value(event, "category") == "network"


def test_windows_11_notepad_launcher_is_not_double_counted():
    assert _is_packaged_notepad_launcher("notepad.exe", '"C:\\Windows\\System32\\notepad.exe"', 26100)
    assert not _is_packaged_notepad_launcher("notepad.exe", '"C:\\Program Files\\WindowsApps\\Notepad.exe" /session:x', 26100)
    assert not _is_packaged_notepad_launcher("notepad.exe", '"C:\\Windows\\System32\\notepad.exe"', 19045)


def test_security_4663_passively_decodes_actor_process_and_path():
    xml = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
      <System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4663</EventID>
      <TimeCreated SystemTime='2026-07-16T10:00:00Z'/><Computer>HOST1</Computer></System>
      <EventData>
       <Data Name='SubjectUserName'>analyst</Data><Data Name='SubjectUserSid'>S-1-5-21-1</Data>
       <Data Name='ObjectName'>C:\\Temp\\watched.txt</Data>
       <Data Name='ProcessName'>C:\\Windows\\System32\\notepad.exe</Data>
       <Data Name='ProcessId'>1234</Data><Data Name='AccessMask'>0x2</Data>
      </EventData></Event>"""
    event = SecurityCollector().decode({"xml": xml})
    assert event["event_type"] == "file.audit"
    assert event["file_audit"]["username"] == "analyst"
    assert event["file_audit"]["path"].endswith("watched.txt")
    assert event["process"]["name"] == "notepad.exe"
    assert event["process"]["pid"] == 1234


def test_registry_change_match_persists_evidence_and_alert(tmp_path: Path):
    ir = {
        "trigger_event": "registry.change", "aggregation": None, "correlation": None,
        "conditions": [{"field": "change_type", "operator": "==", "value": "modified"}],
        "investigation_steps": ["review_registry_path"],
        "response_actions": [{"type": "alert", "duration": None}],
        "severity": "medium", "priority": 4, "tags": ["registry", "integrity"],
        "suggested_action": ["alert"], "suggested_action_reason": "Integrity change",
    }
    record = {"id": "registry-rule", "rule_text": "Alert on registry modification",
              "ir": {"status": "ok", "ir": ir, "explanation": None}}
    event = RegistryIntegrityCollector().decode({"path": r"HKCU\Software\Example", "value_name": "Probe",
                                                  "change_type": "modified", "old_hash": "a", "new_hash": "b"})
    alerts, evidence = tmp_path / "alerts.jsonl", tmp_path / "evidence"
    _process_event(event, [record], AggregationStore(), StateManager(), CorrelationStore(),
                   ActionEngine(True, 5), SimpleNamespace(watcher_dry_run=True),
                   tmp_path, alerts, evidence)
    rows = [json.loads(line) for line in alerts.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 1 and rows[0]["rule_id"] == "registry-rule"
    files = list(evidence.glob("*.json")); assert len(files) == 1
    payload = json.loads(files[0].read_text(encoding="utf-8"))
    assert payload["raw_event"]["registry"]["value_name"] == "Probe"
    assert payload["actions_executed"][0]["result"] == "alerted"
