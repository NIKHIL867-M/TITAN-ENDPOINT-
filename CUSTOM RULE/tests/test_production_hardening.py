from __future__ import annotations

import json
import os
import time
from pathlib import Path

from fastapi.testclient import TestClient

from app import main, rule_store
from shared.integrity import sign_record, verify_record
from watcher.investigation import cleanup_old_evidence, update_evidence_actions, write_evidence
from watcher.main import supervised_run
from watcher.rule_index import initial_load, maybe_reload
from watcher.correlation import CorrelationStore


def test_signed_record_detects_mutation(tmp_path: Path):
    signed = sign_record({"id": "r1", "value": 1}, tmp_path, "approved_rule")
    assert verify_record(signed, tmp_path, "approved_rule") == "verified"
    signed["value"] = 2
    assert verify_record(signed, tmp_path, "approved_rule") == "invalid"


def test_rule_index_suppresses_tampered_signed_rule(tmp_path: Path):
    inner = {
        "trigger_event": "process.start", "aggregation": None, "correlation": None,
        "conditions": [{"field": "name", "operator": "==", "value": "notepad.exe"}],
    }
    record = sign_record(
        {"id": "r1", "status": "approved", "ir": {"status": "ok", "ir": inner}},
        tmp_path, "approved_rule",
    )
    record["ir"]["ir"]["conditions"][0]["value"] = "powershell.exe"
    rules = tmp_path / "rules.jsonl"
    rules.write_text(json.dumps(record) + "\n", encoding="utf-8")
    assert initial_load(rules).rule_count == 0


def test_reload_retains_last_known_good_rules_on_total_corruption(tmp_path: Path):
    inner = {
        "trigger_event": "process.start", "aggregation": None, "correlation": None,
        "conditions": [{"field": "name", "operator": "==", "value": "notepad.exe"}],
    }
    record = sign_record(
        {"id": "r1", "status": "approved", "ir": {"status": "ok", "ir": inner}},
        tmp_path, "approved_rule",
    )
    rules = tmp_path / "rules.jsonl"
    rules.write_text(json.dumps(record) + "\n", encoding="utf-8")
    state = initial_load(rules)
    assert state.rule_count == 1
    rules.write_text("{broken json\n", encoding="utf-8")
    state.last_check_at = 0
    reloaded = maybe_reload(state, rules)
    assert reloaded.rule_count == 1
    assert reloaded.degraded is True
    assert reloaded.load_errors == 1


def test_rule_migration_signs_legacy_without_changing_identity(monkeypatch, tmp_path: Path):
    rules = tmp_path / "rules.jsonl"
    rules.write_text(json.dumps({"id": "original", "rule_text": "legacy"}) + "\n", encoding="utf-8")
    monkeypatch.setattr(rule_store, "_RULES_FILE", rules)
    assert rule_store.migrate_rule_integrity() == 1
    migrated = json.loads(rules.read_text(encoding="utf-8"))
    assert migrated["id"] == "original"
    assert verify_record(migrated, tmp_path, "approved_rule") == "verified"
    assert rule_store.migrate_rule_integrity() == 0


def test_evidence_is_verified_before_and_after_action_update(tmp_path: Path):
    path = write_evidence(
        "instance", "rule", "name", "text", "high", ("host:test",),
        {"event_type": "process.start", "host": "test", "process": {"pid": None}},
        [], None, tmp_path / "evidence",
    )
    first = json.loads(path.read_text(encoding="utf-8"))
    assert verify_record(first, tmp_path, "evidence") == "verified"
    update_evidence_actions(path, [{"action": "alert", "result": "alerted"}])
    final = json.loads(path.read_text(encoding="utf-8"))
    assert verify_record(final, tmp_path, "evidence") == "verified"
    assert final["actions_executed"][0]["result"] == "alerted"


def test_local_api_token_protects_non_health_routes(monkeypatch):
    monkeypatch.setenv("GEKKO_API_TOKEN", "test-secret")
    client = TestClient(main.app)
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/action-options").status_code == 401
    assert client.get(
        "/api/action-options", headers={"X-GEKKO-Token": "wrong"}
    ).status_code == 401
    assert client.get(
        "/api/action-options", headers={"X-GEKKO-Token": "test-secret"}
    ).status_code == 200


def test_cors_allows_only_declared_loopback_origins():
    client = TestClient(main.app)
    allowed = client.options(
        "/api/action-options",
        headers={
            "Origin": "http://127.0.0.1:8765",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert allowed.headers.get("access-control-allow-origin") == "http://127.0.0.1:8765"
    blocked = client.options(
        "/api/action-options",
        headers={
            "Origin": "https://attacker.example",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert "access-control-allow-origin" not in blocked.headers


def test_evidence_cleanup_enforces_count_and_byte_quotas(tmp_path: Path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    for index in range(6):
        path = evidence / f"{index}.json"
        path.write_text(json.dumps({"severity": "high", "data": "x" * 100}), encoding="utf-8")
        timestamp = time.time() - (100 - index)
        os.utime(path, (timestamp, timestamp))
    deleted = cleanup_old_evidence(
        evidence, retention_days=365, max_files=3, max_total_bytes=10_000,
    )
    assert deleted == 3
    assert sorted(path.stem for path in evidence.glob("*.json")) == ["3", "4", "5"]

    deleted = cleanup_old_evidence(
        evidence, retention_days=365, max_files=10, max_total_bytes=200,
    )
    assert deleted >= 2
    assert sum(path.stat().st_size for path in evidence.glob("*.json")) <= 200


def test_young_evidence_cleanup_does_not_parse_every_json(monkeypatch, tmp_path: Path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    for index in range(50):
        (evidence / f"{index}.json").write_text("not-json-but-young", encoding="utf-8")
    real_load = json.load
    calls = 0

    def counted_load(handle):
        nonlocal calls
        calls += 1
        return real_load(handle)

    monkeypatch.setattr(json, "load", counted_load)
    assert cleanup_old_evidence(evidence, retention_days=30, max_files=100) == 0
    assert calls == 0


def test_watcher_supervisor_restarts_crashes_but_stops_after_clean_exit():
    outcomes = iter([False, False, True])
    delays: list[int] = []
    supervised_run(lambda: next(outcomes), delays.append)
    assert delays == [1, 2]


def test_correlation_state_stays_bounded_under_large_unmatched_burst():
    store = CorrelationStore(max_entries=128)
    correlation = {
        "within": "1h", "join_on": "host", "ordered": True,
        "stages": [
            {"event": "process.start", "conditions": []},
            {"event": "network.connect", "conditions": []},
        ],
    }
    for index in range(20_000):
        event = {"event_type": "process.start", "host": f"host-{index}"}
        store.process("rule", correlation, event, lambda e, field: str(e.get(field, "")), lambda *_: True)
    assert store.active_count == 128
