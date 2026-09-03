"""Approved-rule deletion regression tests."""
from fastapi.testclient import TestClient

from app.main import app
from app import rule_store


def _use_temp_store(monkeypatch, tmp_path):
    monkeypatch.setattr(rule_store, "_DATA_DIR", tmp_path)
    monkeypatch.setattr(rule_store, "_RULES_FILE", tmp_path / "rules.jsonl")


def test_delete_one_rule_is_atomic_and_preserves_other_records(monkeypatch, tmp_path):
    _use_temp_store(monkeypatch, tmp_path)
    rule_store.append_rule({"id": "keep", "rule_text": "keep me"})
    rule_store.append_rule({"id": "remove", "rule_text": "remove me"})

    assert rule_store.delete_rule("remove") is True
    assert rule_store.delete_rule("missing") is False
    assert rule_store.count_rules() == 1
    assert rule_store.get_rule_by_id("keep")["rule_text"] == "keep me"


def test_delete_all_rules_returns_count(monkeypatch, tmp_path):
    _use_temp_store(monkeypatch, tmp_path)
    for number in range(3):
        rule_store.append_rule({"id": str(number)})

    assert rule_store.delete_all_rules() == 3
    assert rule_store.list_rules() == []
    assert rule_store.count_rules() == 0


def test_delete_rule_api(monkeypatch, tmp_path):
    _use_temp_store(monkeypatch, tmp_path)
    rule_store.append_rule({"id": "api-rule", "rule_text": "API deletion"})
    client = TestClient(app)

    response = client.delete("/api/rules/api-rule")
    assert response.status_code == 200
    assert response.json() == {"status": "deleted", "rule_id": "api-rule"}
    assert client.delete("/api/rules/api-rule").status_code == 404


def test_delete_all_rules_api(monkeypatch, tmp_path):
    _use_temp_store(monkeypatch, tmp_path)
    rule_store.append_rule({"id": "one"})
    rule_store.append_rule({"id": "two"})

    response = TestClient(app).delete("/api/rules")
    assert response.status_code == 200
    assert response.json() == {"status": "deleted", "deleted": 2}


def test_recent_rules_are_newest_first_and_bounded(monkeypatch, tmp_path):
    _use_temp_store(monkeypatch, tmp_path)
    for number in range(5):
        rule_store.append_rule({"id": str(number)})
    assert [item["id"] for item in rule_store.list_recent_rules(3)] == ["4", "3", "2"]


def test_semantic_duplicate_ignores_record_metadata(monkeypatch, tmp_path):
    _use_temp_store(monkeypatch, tmp_path)
    inner = {"trigger_event": "process.start", "conditions": [{"field": "name", "operator": "==", "value": "notepad.exe"}]}
    rule_store.append_rule({"id": "existing", "created_at": "old", "ir": {"status": "ok", "ir": inner}})
    found = rule_store.find_semantic_duplicate({"status": "ok", "ir": dict(inner)})
    assert found and found["id"] == "existing"
