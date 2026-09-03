"""Atomically move selected alert rows to a reversible audit archive."""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from pathlib import Path


def main(ids: set[str]) -> None:
    source = Path(__file__).resolve().parent.parent / "data" / "alerts.jsonl"
    kept: list[str] = []; moved: list[str] = []
    for line in source.read_text(encoding="utf-8").splitlines(keepends=True):
        try: alert_id = json.loads(line).get("id")
        except json.JSONDecodeError: alert_id = None
        (moved if alert_id in ids else kept).append(line)
    if moved:
        archive = source.with_name(f"alerts_gui_audit_{datetime.now():%Y%m%d}.jsonl")
        with open(archive, "a", encoding="utf-8") as target: target.writelines(moved)
        temporary = source.with_suffix(".jsonl.tmp")
        with open(temporary, "w", encoding="utf-8") as target: target.writelines(kept)
        os.replace(temporary, source)
    print({"kept": len(kept), "quarantined": len(moved)})


if __name__ == "__main__":
    main(set(sys.argv[1:]))
