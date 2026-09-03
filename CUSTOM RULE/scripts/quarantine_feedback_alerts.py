"""Quarantine alerts created by GEKKO's historical toast feedback loop."""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    source = root / "data" / "alerts.jsonl"
    if not source.exists():
        print({"kept": 0, "quarantined": 0})
        return

    kept: list[str] = []
    quarantined: list[str] = []
    for line in source.read_text(encoding="utf-8").splitlines(keepends=True):
        try:
            alert = json.loads(line)
            evidence_path = Path(alert.get("evidence_path", ""))
            evidence = evidence_path.read_text(encoding="utf-8").lower() if evidence_path.is_file() else ""
        except (json.JSONDecodeError, OSError):
            kept.append(line)
            continue
        if "toastnotificationmanager" in evidence and "watcher agent" in evidence:
            quarantined.append(line)
        else:
            kept.append(line)

    if quarantined:
        stamp = datetime.now().strftime("%Y%m%d")
        archive = source.with_name(f"alerts_feedback_loop_{stamp}.jsonl")
        with open(archive, "a", encoding="utf-8") as target:
            target.writelines(quarantined)
        temporary = source.with_suffix(".jsonl.tmp")
        with open(temporary, "w", encoding="utf-8") as target:
            target.writelines(kept)
        os.replace(temporary, source)
    print({"kept": len(kept), "quarantined": len(quarantined)})


if __name__ == "__main__":
    main()
