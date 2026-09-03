"""Native desktop and watcher-capability regression tests."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from fastapi.testclient import TestClient
from PySide6.QtWidgets import QApplication

from app.main import app
from native_gui import MainWindow, _local_time


def test_watcher_capability_catalog_is_complete():
    response = TestClient(app).get("/api/watcher-capabilities")
    assert response.status_code == 200
    body = response.json()
    events = {item["event"]: item for item in body["events"]}
    assert events["process.start"]["collectors"] == ["wmi", "security", "sysmon", "titan_sensors"]
    assert events["network.connect"]["collectors"] == ["sysmon", "titan_sensors"]
    assert events["network.connect"]["fields"]
    assert events["registry.change"]["collectors"] == ["registry_fim"]
    assert events["inventory.change"]["collectors"] == ["inventory"]
    assert events["file.audit"]["collectors"] == ["security"]
    assert body["storage_policy"]["unmatched_events"] == "transient_only"
    assert body["storage_policy"]["matched_events"] == "evidence_json_plus_alert_summary"


def test_native_window_has_required_workflows(monkeypatch):
    qt_app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(MainWindow, "_load_initial_data", lambda self: None)
    window = MainWindow("http://127.0.0.1:8765")
    assert window.windowTitle() == "GEKKO // Windows Rule Monitor"
    assert window.pool.maxThreadCount() == 4
    assert window.main_tabs.count() == 6
    assert window.review_tabs.count() == 3
    assert window.main_tabs.tabText(1) == "WATCHER COVERAGE"
    assert window.main_tabs.tabText(3) == "MATCHED EVIDENCE"
    assert window.main_tabs.tabText(4) == "WATCHER ACTIVITY"
    assert window.main_tabs.tabText(5) == "RESPONSE OUTCOMES"
    assert not window.approve_button.isEnabled()
    assert window.delete_rule_button.text() == "DELETE SELECTED RULE"
    assert window.delete_all_rules_button.text() == "DELETE ALL RULES"
    window.close()
    qt_app.processEvents()


def test_utc_timestamp_is_converted_to_local_timezone():
    rendered = _local_time("2026-07-18T06:25:01+00:00", include_date=True)
    assert rendered != "2026-07-18T06:25:01+00:00"
    assert "2026-07-18" in rendered


def test_refresh_preserves_rule_and_alert_selection(monkeypatch):
    qt_app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(MainWindow, "_load_initial_data", lambda self: None)
    monkeypatch.setattr(MainWindow, "_load_selected_evidence", lambda self, row: None)
    window = MainWindow("http://127.0.0.1:8765")
    rules = {"total": 2, "rules": [
        {"id": "new", "created_at": "2026-07-18T06:00:00+00:00", "rule_text": "new"},
        {"id": "old", "created_at": "2026-07-17T06:00:00+00:00", "rule_text": "old"},
    ]}
    window._history_loaded(rules); window.history_list.setCurrentRow(1); window._history_loaded(rules)
    assert window.history_list.currentItem().data(256) == "old"

    alerts = {"alerts": [
        {"id": "a", "instance_id": "ia", "severity": "high", "fired_at": "2026-07-18T06:00:00+00:00"},
        {"id": "b", "instance_id": "ib", "severity": "low", "fired_at": "2026-07-17T06:00:00+00:00"},
    ]}
    window._alerts_loaded(alerts); window.alert_list.setCurrentRow(1); window._alerts_loaded(alerts)
    assert window.alert_list.currentItem().data(256) == "b"
    window.close(); qt_app.processEvents()


def test_status_updates_do_not_unlock_inflight_parse(monkeypatch):
    qt_app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(MainWindow, "_load_initial_data", lambda self: None)
    window = MainWindow("http://127.0.0.1:8765")
    window.parse_button.setEnabled(False)
    window._set_status("Background refresh failed", "error")
    assert not window.parse_button.isEnabled()
    assert window.global_status.text() == "Background refresh failed"
    assert window.coverage_table.columnCount() == 7
    window.close(); qt_app.processEvents()
