"""Regression tests for editable IR validation and audit persistence."""

from app.context_builder import build_context, EVENT_FIELD_TYPES
from app.semantic_validator import validate_against_context, validate_structure
from app.rule_store import create_rule_record


def valid_draft():
    return {
        "trigger_event": "process.start",
        "aggregation": None,
        "conditions": [{"field": "name", "operator": "==", "value": "notepad.exe"}],
        "investigation_steps": [],
        "response_actions": [{"type": "alert", "duration": None}],
        "severity": "low",
        "priority": 3,
        "tags": ["test"],
        "suggested_action": ["alert"],
        "suggested_action_reason": "safe default",
    }


def wrap(draft):
    return {"status": "ok", "clarification": None, "ir": draft, "explanation": None}


def test_pathological_regex_is_rejected():
    draft = valid_draft()
    draft["conditions"][0] = {"field": "name", "operator": "regex", "value": "(a+)+b"}
    structural = validate_structure(wrap(draft))
    assert structural.valid
    result = validate_against_context(structural.parsed, build_context())
    assert not result.valid
    assert any("catastrophic backtracking" in error for error in result.errors)


def test_field_must_belong_to_selected_event():
    draft = valid_draft()
    draft["conditions"][0] = {"field": "source_ip", "operator": "==", "value": "127.0.0.1"}
    structural = validate_structure(wrap(draft))
    result = validate_against_context(structural.parsed, build_context())
    assert not result.valid
    assert any("not available for event" in error for error in result.errors)


def test_unknown_expert_fields_are_not_silently_discarded():
    draft = valid_draft()
    draft["correlation_stages"] = [{"event": "process.start"}]
    result = validate_structure(wrap(draft))
    assert not result.valid


def test_schema_covers_supported_event_families():
    assert "process.start" in EVENT_FIELD_TYPES
    assert "network.connect" in EVENT_FIELD_TYPES
    assert "registry.set" in EVENT_FIELD_TYPES


def test_edited_record_preserves_original_and_final_ir():
    original = wrap(valid_draft())
    final = wrap(valid_draft())
    final["ir"]["priority"] = 8
    record = create_rule_record(final, "test", original_ir=original, edit_mode="expert")
    assert record["edited"] is True
    assert record["original_ir"] == original
    assert record["final_ir"] == final
    assert record["edit_mode"] == "expert"
