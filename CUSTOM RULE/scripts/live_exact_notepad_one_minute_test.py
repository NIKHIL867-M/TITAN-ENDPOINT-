"""Real early-exit and full-minute test for the sole approved Notepad rule."""
from __future__ import annotations

import json
import subprocess
import time
import urllib.request
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:8765"
ACTIVITY = ROOT / "data" / "watcher_activity.jsonl"
TEST_FILE = ROOT / "data" / "duration_notepad_test.txt"


def call(path: str) -> dict:
    with urllib.request.urlopen(BASE + path, timeout=10) as response:
        return json.load(response)


def activities(rule_id: str, pid: int, kind: str) -> list[dict]:
    rows = []
    for line in ACTIVITY.read_text(encoding="utf-8").splitlines():
        try:
            row = json.loads(line)
            if row.get("rule_id") == rule_id and int(row.get("pid") or 0) == pid and row.get("kind") == kind:
                rows.append(row)
        except (ValueError, TypeError):
            continue
    return rows


def wait_for_activity(rule_id: str, pid: int, kind: str, timeout: float) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        found = activities(rule_id, pid, kind)
        if found:
            return found[-1]
        time.sleep(0.25)
    raise RuntimeError(f"No {kind} activity for PID {pid} within {timeout}s")


def rule_alerts(rule_id: str) -> list[dict]:
    return [row for row in call("/api/alerts?limit=100").get("alerts", []) if row.get("rule_id") == rule_id]


def stop_test_process(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.terminate()
        try: process.wait(timeout=5)
        except subprocess.TimeoutExpired: process.kill()


def main() -> None:
    rules = call("/api/rules?limit=100&newest=true").get("rules", [])
    assert len(rules) == 1, f"Expected exactly one approved rule, found {len(rules)}"
    record = rules[0]
    rule_id = record["id"]
    inner = record["ir"]["ir"]
    assert inner.get("sustain_for") == "1m"
    assert len(rule_alerts(rule_id)) == 0, "The freshly approved rule already has alerts"

    # Case 1: start the exact target, then close it well before one minute.
    early = subprocess.Popen(["notepad.exe", str(TEST_FILE)])
    early_pending = wait_for_activity(rule_id, early.pid, "sustain_pending", 10)
    time.sleep(7)
    stop_test_process(early)
    early_failed = wait_for_activity(rule_id, early.pid, "sustain_not_met", 65)
    assert len(rule_alerts(rule_id)) == 0, "Early exit incorrectly generated an alert"

    # Case 2: start another exact target and keep it open beyond one minute.
    long_running = subprocess.Popen(["notepad.exe", str(TEST_FILE)])
    try:
        long_pending = wait_for_activity(rule_id, long_running.pid, "sustain_pending", 10)
        deadline = time.monotonic() + 70
        saved = []
        while time.monotonic() < deadline:
            saved = [a for a in rule_alerts(rule_id) if a.get("instance_id")]
            if saved:
                break
            time.sleep(0.5)
        assert len(saved) == 1, f"Expected exactly one one-minute alert, got {len(saved)}"
        evidence = call(f"/api/evidence/{saved[0]['instance_id']}")
        sustained = evidence["raw_event"]["sustained_condition"]
        assert sustained["duration"] == "1m" and sustained["result"] == "still_running"
        pending_at = datetime.fromisoformat(long_pending["at"])
        fired_at = datetime.fromisoformat(saved[0]["fired_at"])
        elapsed = (fired_at - pending_at).total_seconds()
        assert elapsed >= 60.0, f"Alert fired too early at {elapsed:.3f}s"
        print(json.dumps({
            "status": "passed", "rule_id": rule_id,
            "early_exit": {"pid": early.pid, "timer_started": early_pending["at"],
                           "not_met_recorded": early_failed["at"], "alerts": 0},
            "full_minute": {"pid": long_running.pid, "timer_started": long_pending["at"],
                            "alert_fired": saved[0]["fired_at"], "elapsed_seconds": round(elapsed, 3),
                            "alerts": 1, "evidence_instance": saved[0]["instance_id"]},
        }, indent=2))
    finally:
        stop_test_process(long_running)


if __name__ == "__main__":
    main()
