"""Delete all approved rules and approve only the exact one-minute Notepad rule."""
from __future__ import annotations

import json
import time
import urllib.request

BASE = "http://127.0.0.1:8765"
RULE_TEXT = "Alert if Notepad remains open for more than one minute"


def call(method: str, path: str, payload: dict | None = None, timeout: int = 70) -> dict:
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(BASE + path, data=data, method=method, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def wait_for_rules(expected: int) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if int(call("GET", "/api/watcher-runtime").get("rules_loaded", -1)) == expected:
            return
        time.sleep(0.25)
    raise RuntimeError(f"Watcher did not hot-reload to {expected} rule(s)")


def main() -> None:
    deleted = call("DELETE", "/api/rules")
    wait_for_rules(0)
    parsed = call("POST", "/api/parse-rule", {"rule_text": RULE_TEXT})
    assert parsed.get("success"), parsed
    draft = parsed["ir"]["ir"]
    assert draft.get("trigger_event") == "process.start", draft
    assert draft.get("sustain_for") == "1m", draft
    assert any(c.get("field") == "name" and str(c.get("value", "")).lower() == "notepad.exe" for c in draft.get("conditions", [])), draft
    checked = call("POST", "/api/rules/draft-check", {"draft": draft})
    assert checked.get("valid"), checked
    approved = call("POST", "/api/rules/approve", {
        "rule_text": RULE_TEXT,
        "ir": {"status": "ok", "clarification": None, "ir": checked["normalized_draft"], "explanation": parsed["ir"].get("explanation")},
        "response_actions": ["alert"],
    })
    assert approved.get("status") == "approved", approved
    wait_for_rules(1)
    print(json.dumps({
        "deleted_rule_count": deleted.get("deleted"), "approved_rule_id": approved["rule_id"],
        "rule_text": RULE_TEXT, "trigger_event": draft["trigger_event"],
        "condition": draft["conditions"], "sustain_for": draft["sustain_for"],
        "response_action": "alert", "watcher_rules_loaded": 1,
    }, indent=2))


if __name__ == "__main__":
    main()
