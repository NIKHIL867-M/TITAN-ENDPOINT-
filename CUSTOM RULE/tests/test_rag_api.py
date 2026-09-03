"""API integration checks for RAG provenance and expanded rule input."""

from __future__ import annotations

from app.groq_client import ParseRuleResult
from app.knowledge.service import KnowledgeService


def _valid_result() -> ParseRuleResult:
    return ParseRuleResult(
        success=True,
        data={
            "status": "ok",
            "clarification": None,
            "ir": {
                "trigger_event": "process.start",
                "aggregation": None,
                "correlation": None,
                "sustain_for": None,
                "conditions": [
                    {"field": "name", "operator": "==", "value": "notepad.exe"}
                ],
                "investigation_steps": ["check_process_command_line"],
                "suggested_action": ["alert"],
                "suggested_action_reason": "Operator notification requested",
                "response_actions": [],
                "severity": "low",
                "priority": 8,
                "tags": ["test"],
            },
            "explanation": {
                "matched_event": "process.start",
                "inferred_threshold": "single event",
                "assumptions_made": [],
            },
        },
        budget_used=1,
        response_time_ms=1.0,
        model_used="test-model",
    )


def test_knowledge_status_and_search_endpoints(client, monkeypatch, tmp_path):
    from app import main

    monkeypatch.setattr(main, "_KNOWLEDGE", KnowledgeService(tmp_path / "rag"))
    status = client.get("/api/knowledge/status")
    assert status.status_code == 200
    assert status.json()["ready"] is True
    assert status.json()["watcher_loaded"] is False

    search = client.post(
        "/api/knowledge/search",
        json={"query": "Notepad remains open for more than one minute"},
    )
    assert search.status_code == 200
    ids = {item["id"] for item in search.json()["trace"]["documents"]}
    assert "pattern.sustained_process.v1" in ids


def test_parse_accepts_more_than_500_chars_and_returns_retrieval_trace(
    client, monkeypatch, tmp_path
):
    from app import main

    monkeypatch.setattr(main, "_KNOWLEDGE", KnowledgeService(tmp_path / "rag"))
    captured = {}

    async def fake_parse(rule_text, context, injection_flags=None, retrieval_context=None):
        captured["length"] = len(rule_text)
        captured["retrieval_context"] = retrieval_context
        return _valid_result()

    monkeypatch.setattr(main, "parse_rule", fake_parse)
    detailed_rule = (
        "Alert when Notepad starts and collect its process details. "
        + "Include this analyst context for investigation only. " * 11
    )
    assert len(detailed_rule) > 500
    response = client.post("/api/parse-rule", json={"rule_text": detailed_rule})
    assert response.status_code == 200
    payload = response.json()
    assert captured["length"] == len(detailed_rule.strip())
    assert captured["retrieval_context"]
    assert payload["retrieval"]["documents"]
    assert payload["meta"]["model_used"] == "test-model"


def test_rule_input_remains_bounded(client):
    response = client.post("/api/parse-rule", json={"rule_text": "x" * 4001})
    assert response.status_code == 400
    assert "exceeds 4000" in response.json()["detail"]
