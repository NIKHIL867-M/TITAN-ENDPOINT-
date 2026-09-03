"""
Tests for the YAML rule-authoring fallback (app/yaml_rules.py + the
POST /api/rules/from-yaml endpoint) — for when the Groq API limit/quota is
hit. Covers the parser directly and the full endpoint-level pipeline,
proving it shares the exact same validation as an LLM-produced draft.
"""
from fastapi.testclient import TestClient

from app.yaml_rules import parse_yaml_rule, MAX_YAML_BYTES
from app.main import app


VALID_YAML = """
trigger_event: process.start
conditions:
  - field: name
    operator: "=="
    value: calc.exe
response_actions:
  - type: alert
severity: low
priority: 5
tags: [example]
"""


# ═══════════════════════════════════════════════════════════════════════
# parse_yaml_rule — unit tests
# ═══════════════════════════════════════════════════════════════════════


def test_parses_valid_yaml_into_dict():
    draft, errors = parse_yaml_rule(VALID_YAML)
    assert errors == []
    assert draft["trigger_event"] == "process.start"
    assert draft["conditions"][0]["value"] == "calc.exe"
    assert draft["severity"] == "low"
    assert draft["priority"] == 5


def test_missing_trigger_event_is_a_clear_error():
    draft, errors = parse_yaml_rule("severity: low\npriority: 5\n")
    assert draft is None
    assert any("trigger_event" in e for e in errors)


def test_missing_severity_and_priority_both_reported():
    draft, errors = parse_yaml_rule("trigger_event: process.start\n")
    assert draft is None
    assert any("severity" in e for e in errors)
    assert any("priority" in e for e in errors)


def test_invalid_yaml_syntax_reports_a_clear_error():
    draft, errors = parse_yaml_rule("trigger_event: [unclosed")
    assert draft is None
    assert any("YAML syntax error" in e for e in errors)


def test_empty_input_reports_a_clear_error():
    draft, errors = parse_yaml_rule("")
    assert draft is None
    assert any("empty" in e.lower() for e in errors)


def test_yaml_list_at_top_level_is_rejected():
    draft, errors = parse_yaml_rule("- a\n- b\n")
    assert draft is None
    assert any("mapping" in e for e in errors)


def test_yaml_scalar_at_top_level_is_rejected():
    draft, errors = parse_yaml_rule("just a string")
    assert draft is None
    assert any("mapping" in e for e in errors)


def test_oversized_yaml_is_rejected():
    huge = "trigger_event: process.start\n# " + ("x" * (MAX_YAML_BYTES + 1))
    draft, errors = parse_yaml_rule(huge)
    assert draft is None
    assert any("too large" in e for e in errors)


def test_omitted_list_fields_default_to_empty_list():
    draft, errors = parse_yaml_rule("trigger_event: process.start\nseverity: low\npriority: 5\n")
    assert errors == []
    assert draft["conditions"] == []
    assert draft["investigation_steps"] == []
    assert draft["response_actions"] == []
    assert draft["tags"] == []


def test_provided_list_fields_are_not_overwritten():
    draft, errors = parse_yaml_rule(VALID_YAML)
    assert errors == []
    assert draft["tags"] == ["example"]
    assert len(draft["conditions"]) == 1


# ═══════════════════════════════════════════════════════════════════════
# /api/rules/from-yaml — endpoint tests (auth: see conftest.py's autouse
# GEKKO_ALLOW_UNAUTHENTICATED_LOCAL opt-in)
# ═══════════════════════════════════════════════════════════════════════


def test_endpoint_valid_yaml_returns_same_shape_as_draft_check(monkeypatch, tmp_path):
    monkeypatch.setattr("app.main._COLLECTOR_STATUS_FILE", tmp_path / "does_not_exist.json")
    with TestClient(app) as client:
        response = client.post("/api/rules/from-yaml", json={"yaml_text": VALID_YAML})
    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is True
    assert body["errors"] == []
    assert body["simulation"] is not None
    assert body["normalized_draft"]["trigger_event"] == "process.start"


def test_endpoint_invalid_yaml_syntax_returns_valid_false():
    with TestClient(app) as client:
        response = client.post("/api/rules/from-yaml", json={"yaml_text": "trigger_event: [unclosed"})
    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is False
    assert any("YAML syntax error" in e for e in body["errors"])


def test_endpoint_rejects_unknown_event_type_same_as_llm_draft_would():
    """A YAML rule referencing a made-up event must fail the SAME contextual
    validation an LLM draft would fail — proving the shared pipeline, not a
    separate/weaker YAML-only validator."""
    bad_yaml = (
        "trigger_event: totally.made.up.event\n"
        "conditions: []\n"
        "response_actions:\n  - type: alert\n"
        "severity: low\npriority: 5\n"
    )
    with TestClient(app) as client:
        response = client.post("/api/rules/from-yaml", json={"yaml_text": bad_yaml})
    body = response.json()
    assert body["valid"] is False
    assert body["errors"]


def test_endpoint_approve_flow_matches_llm_draft_flow(monkeypatch, tmp_path):
    """The output of from-yaml can be approved through the EXISTING
    /api/rules/approve endpoint unmodified -- no separate persistence path."""
    from app import rule_store
    monkeypatch.setattr(rule_store, "_DATA_DIR", tmp_path)
    monkeypatch.setattr(rule_store, "_RULES_FILE", tmp_path / "rules.jsonl")
    monkeypatch.setattr("app.main._COLLECTOR_STATUS_FILE", tmp_path / "does_not_exist.json")

    with TestClient(app) as client:
        check = client.post("/api/rules/from-yaml", json={"yaml_text": VALID_YAML})
        assert check.status_code == 200
        body = check.json()
        assert body["valid"] is True

        # /api/rules/approve expects the full ParseResult-shaped wrapper
        # ({"status": "ok", "ir": <flat IR>, ...}) -- the same wrapping the
        # pre-existing /api/rules/draft-check's normalized_draft output also
        # needs before being approved. Not specific to the YAML path.
        approve = client.post("/api/rules/approve", json={
            "rule_text": "[YAML] calc.exe alert test",
            "ir": {"status": "ok", "clarification": None, "ir": body["normalized_draft"], "explanation": None},
            "response_actions": ["alert"],
        })
        assert approve.status_code == 200, approve.text

    assert rule_store.count_rules() == 1
