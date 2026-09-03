"""
Test action validation — strict vs permissive (master.md Fix #1).

These tests directly encode the strict-vs-permissive distinction:
  - Approval (strict=True)  → empty actions list is REJECTED
  - Parse-time (strict=False) → empty actions list is ALLOWED

This is cheap insurance against the exact class of bug that Fix #1 addresses:
a human approving a rule with zero actions selected and nothing rejecting it.
"""
import pytest
from shared.action_types import validate_actions


# ═══════════════════════════════════════════════════════════════════════
# Unit tests for validate_actions() — the single source of truth
# ═══════════════════════════════════════════════════════════════════════


class TestValidateActionsStrict:
    """strict=True — used at approval time."""

    def test_empty_actions_rejected(self):
        """Fix #1: empty response_actions at approval → error."""
        errors = validate_actions([], strict=True)
        assert len(errors) > 0
        assert "at least one" in errors[0].lower()

    def test_valid_single_action(self):
        errors = validate_actions(["alert"], strict=True)
        assert errors == []

    def test_valid_multiple_actions(self):
        errors = validate_actions(["alert", "kill_process"], strict=True)
        assert errors == []

    def test_all_valid_actions(self):
        errors = validate_actions(["alert", "kill_process", "isolate_host"], strict=True)
        assert errors == []

    def test_invalid_action_rejected(self):
        errors = validate_actions(["alert", "explode_server"], strict=True)
        assert len(errors) == 1
        assert "explode_server" in errors[0]

    def test_all_invalid_actions(self):
        errors = validate_actions(["nuke", "orbital_strike"], strict=True)
        assert len(errors) == 2


class TestValidateActionsPermissive:
    """strict=False — used at parse-time."""

    def test_empty_actions_allowed(self):
        """Fix #1: empty response_actions at parse-time → no error."""
        errors = validate_actions([], strict=False)
        assert errors == []

    def test_valid_actions_still_validated(self):
        errors = validate_actions(["alert"], strict=False)
        assert errors == []

    def test_invalid_actions_still_rejected(self):
        """Even in permissive mode, nonsense action strings are rejected."""
        errors = validate_actions(["not_a_real_action"], strict=False)
        assert len(errors) == 1

    def test_default_is_strict(self):
        """The default behavior (no strict kwarg) should be strict."""
        errors = validate_actions([])
        assert len(errors) > 0


# ═══════════════════════════════════════════════════════════════════════
# Integration tests via FastAPI test client
# ═══════════════════════════════════════════════════════════════════════


class TestApproveEndpoint:
    """Test the /api/rules/approve endpoint enforces strict validation."""

    def test_approve_rejects_empty_actions(self, client):
        """Fix #1 regression test: approving with no actions → 400."""
        resp = client.post("/api/rules/approve", json={
            "rule_text": "alert on notepad.exe",
            "ir": {
                "status": "ok",
                "ir": {
                    "trigger_event": "process.start",
                    "conditions": [{"field": "name", "operator": "==", "value": "notepad.exe"}],
                    "investigation_steps": ["check parent"],
                    "response_actions": [],
                    "severity": "low",
                    "priority": 3,
                    "tags": ["test"],
                    "suggested_action": ["alert"],
                },
            },
            "response_actions": [],
        })
        assert resp.status_code == 400

    def test_approve_accepts_valid_actions(self, client):
        """Approving with valid actions → 200."""
        resp = client.post("/api/rules/approve", json={
            "rule_text": "alert on notepad.exe",
            "ir": {
                "status": "ok",
                "ir": {
                    "trigger_event": "process.start",
                    "conditions": [{"field": "name", "operator": "==", "value": "notepad.exe"}],
                    "investigation_steps": ["check parent"],
                    "response_actions": [],
                    "severity": "low",
                    "priority": 3,
                    "tags": ["test"],
                    "suggested_action": ["alert"],
                },
            },
            "response_actions": ["alert"],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "approved"
        duplicate = client.post("/api/rules/approve", json={
            "rule_text": "same executable rule, different wording",
            "ir": {
                "status": "ok",
                "ir": {
                    "trigger_event": "process.start",
                    "conditions": [{"field": "name", "operator": "==", "value": "notepad.exe"}],
                    "investigation_steps": ["check parent"],
                    "response_actions": [],
                    "severity": "low", "priority": 3, "tags": ["test"], "suggested_action": ["alert"],
                },
            },
            "response_actions": ["alert"],
        })
        assert duplicate.status_code == 200
        assert duplicate.json() == {"status": "already_approved", "rule_id": data["rule_id"]}

    def test_approve_rejects_invalid_action_strings(self, client):
        """Approving with garbage action strings → 400."""
        resp = client.post("/api/rules/approve", json={
            "rule_text": "alert on notepad.exe",
            "ir": {
                "status": "ok",
                "ir": {
                    "trigger_event": "process.start",
                    "conditions": [{"field": "name", "operator": "==", "value": "notepad.exe"}],
                    "investigation_steps": ["check parent"],
                    "response_actions": [],
                    "severity": "low",
                    "priority": 3,
                    "tags": ["test"],
                    "suggested_action": ["alert"],
                },
            },
            "response_actions": ["alert", "self_destruct"],
        })
        assert resp.status_code == 400
