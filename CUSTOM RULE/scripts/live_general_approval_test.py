"""Live API verification for general draft-check and approval consistency."""
from __future__ import annotations

import json
import urllib.request

BASE = "http://127.0.0.1:8765"


def call(method: str, path: str, payload: dict | None = None, timeout: int = 70) -> dict:
    body = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(BASE + path, data=body, method=method, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def rule(event: str, field: str, value: str) -> dict:
    return {
        "trigger_event": event, "aggregation": None, "correlation": None,
        "conditions": [{"field": field, "operator": "contains", "value": value}],
        "investigation_steps": ["collect_event_context"], "suggested_action": ["alert"],
        "suggested_action_reason": "live validation", "response_actions": [],
        "severity": "medium", "priority": 5, "tags": ["live-approval-test"],
    }


def approve_then_remove(label: str, draft: dict) -> dict:
    checked = call("POST", "/api/rules/draft-check", {"draft": draft})
    assert checked["valid"], f"{label} draft failed: {checked['errors']}"
    wrapper = {"status": "ok", "clarification": None, "ir": checked.get("normalized_draft", draft), "explanation": None}
    approved = call("POST", "/api/rules/approve", {
        "rule_text": f"LIVE GENERAL TEST: {label}", "ir": wrapper, "response_actions": ["alert"],
    })
    assert approved["status"] == "approved", f"{label} approval returned {approved}"
    call("DELETE", f"/api/rules/{approved['rule_id']}")
    return {"draft_check": "passed", "final_approval": "passed", "test_record_removed": True}


def main() -> None:
    text = "Generate an alert if Notepad and Calculator are both running at the same time."
    parsed = call("POST", "/api/parse-rule", {"rule_text": text})
    assert parsed["success"], parsed
    co_occurrence = parsed["ir"]["ir"]
    assert co_occurrence["correlation"]["join_on"] == "host"
    assert co_occurrence["correlation"]["ordered"] is False

    results = {"process_co_occurrence": approve_then_remove("process co-occurrence", co_occurrence)}
    for label, draft in {
        "service_install": rule("service.install", "service_name", "GEKKO_TEST_SERVICE"),
        "registry_change": rule("registry.change", "path", "GEKKO_TEST_RUN_KEY"),
        "defender_detection": rule("defender.detection", "threat_name", "GEKKO_TEST_THREAT"),
        "scheduled_task": rule("task.create", "task_name", "GEKKO_TEST_TASK"),
    }.items():
        results[label] = approve_then_remove(label.replace("_", " "), draft)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
