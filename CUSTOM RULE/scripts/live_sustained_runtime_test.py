"""Live end-to-end verification of sustained process liveness rules."""
from __future__ import annotations

import json
import subprocess
import time
import urllib.request

BASE = "http://127.0.0.1:8765"


def call(method: str, path: str, payload: dict | None = None) -> dict:
    body = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(BASE + path, data=body, method=method, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def alerts_for(rule_id: str) -> list[dict]:
    return [item for item in call("GET", "/api/alerts?limit=100").get("alerts", []) if item.get("rule_id") == rule_id]


def main() -> None:
    draft = {
        "trigger_event": "process.start", "aggregation": None, "correlation": None,
        "sustain_for": "2s",
        "conditions": [{"field": "name", "operator": "==", "value": "ping.exe"}],
        "investigation_steps": ["collect_process_tree"],
        "suggested_action": ["alert"], "suggested_action_reason": "live temporal verification",
        "response_actions": [], "severity": "medium", "priority": 5, "tags": ["live-sustain-test"],
    }
    checked = call("POST", "/api/rules/draft-check", {"draft": draft})
    assert checked["valid"], checked
    approved = call("POST", "/api/rules/approve", {
        "rule_text": "LIVE TEST: ping.exe remains alive for more than 2 seconds",
        "ir": {"status": "ok", "clarification": None, "ir": checked["normalized_draft"], "explanation": None},
        "response_actions": ["alert"],
    })
    assert approved["status"] == "approved", approved
    rule_id = approved["rule_id"]
    try:
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if call("GET", "/api/watcher-runtime").get("rules_loaded", 0) >= 4:
                break
            time.sleep(0.25)

        # Exits in about one second: must not satisfy a two-second rule.
        subprocess.run(["ping.exe", "-n", "2", "127.0.0.1"], stdout=subprocess.DEVNULL, check=True, timeout=5)
        time.sleep(3.0)
        early_count = len(alerts_for(rule_id))
        assert early_count == 0, "An early-exiting process incorrectly produced an alert"

        # Lives for about five seconds: must satisfy the same rule.
        long_process = subprocess.Popen(["ping.exe", "-n", "6", "127.0.0.1"], stdout=subprocess.DEVNULL)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and not alerts_for(rule_id):
            time.sleep(0.25)
        long_process.wait(timeout=8)
        saved = alerts_for(rule_id)
        assert len(saved) == 1, f"Expected one sustained alert, got {len(saved)}"
        evidence = call("GET", f"/api/evidence/{saved[0]['instance_id']}")
        assert evidence["raw_event"]["sustained_condition"]["result"] == "still_running"
        print(json.dumps({
            "status": "passed", "early_exit_alerts": early_count,
            "long_running_alerts": len(saved), "instance_id": saved[0]["instance_id"],
            "verified_duration": evidence["raw_event"]["sustained_condition"]["duration"],
        }, indent=2))
    finally:
        call("DELETE", f"/api/rules/{rule_id}")


if __name__ == "__main__":
    main()
