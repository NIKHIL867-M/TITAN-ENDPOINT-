"""Safe manual/live verification for cmd -> PowerShell -> Notepad correlation."""
from __future__ import annotations

import json
import subprocess
import time
import urllib.request

BASE = "http://127.0.0.1:8765"


def get_json(path: str) -> dict:
    with urllib.request.urlopen(BASE + path, timeout=5) as response:
        return json.load(response)


def main() -> None:
    initial = get_json("/api/alerts?limit=100")
    before = int(initial.get("total", 0))
    existing_instances = {a.get("instance_id") for a in initial.get("alerts", [])}
    subprocess.run([
        "cmd.exe", "/c",
        r"ping -n 3 127.0.0.1 >nul & powershell.exe -NoProfile -File scripts\chain_child.ps1",
    ], check=True, timeout=20)
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        alerts = get_json("/api/alerts?limit=10")
        candidates = [a for a in alerts.get("alerts", []) if a.get("instance_id") not in existing_instances and a.get("rule_text", "").startswith("Alert if Command Prompt")]
        if int(alerts.get("total", 0)) > before and candidates:
            alert = candidates[0]
            evidence = get_json(f"/api/evidence/{alert['instance_id']}")
            print(json.dumps({
                "status": "passed",
                "instance_id": alert["instance_id"],
                "severity": alert["severity"],
                "stages": evidence.get("correlation_stages", []),
            }, indent=2))
            return
        time.sleep(0.25)
    raise RuntimeError("No cmd -> PowerShell -> Notepad correlated alert arrived within 10 seconds")


if __name__ == "__main__":
    main()
