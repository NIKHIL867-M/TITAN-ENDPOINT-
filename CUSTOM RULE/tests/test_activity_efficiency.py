"""Bounded activity-feed memory and operator-display regressions."""

from __future__ import annotations

import json

from app.main import _compact_activity_rows, _tail_jsonl
from watcher.activity import ActivityLog


def test_tail_jsonl_reads_only_recent_valid_rows(tmp_path):
    path = tmp_path / "activity.jsonl"
    lines = [json.dumps({"index": index}) for index in range(100)]
    path.write_text("\n".join(lines) + "\nmalformed\n", encoding="utf-8")
    rows = _tail_jsonl(path, 5)
    assert [row["index"] for row in rows] == [95, 96, 97, 98, 99]


def test_compaction_collapses_only_display_telemetry_not_matches():
    rows = [
        {
            "at": f"2026-07-23T10:00:0{index}+00:00",
            "kind": "event_observed",
            "event_type": "powershell.script_block",
            "collector": "powershell",
            "subject": f"PowerShell script block {index}",
        }
        for index in range(4)
    ]
    rows.extend(
        [
            {"kind": "rule_matched", "event_type": "powershell.script_block", "rule_id": "r1"},
            {"kind": "rule_matched", "event_type": "powershell.script_block", "rule_id": "r1"},
        ]
    )
    compacted = _compact_activity_rows(rows)
    assert len(compacted) == 3
    assert compacted[0]["repeat_count"] == 4
    assert [row["kind"] for row in compacted[1:]] == ["rule_matched", "rule_matched"]


def test_activity_log_adds_entity_for_non_process_event(tmp_path):
    path = tmp_path / "activity.jsonl"
    log = ActivityLog(path)
    log.write(
        "event_observed",
        {
            "event_type": "powershell.script_block",
            "source_collector": "powershell",
            "script_block_id": "abcdef1234567890",
            "process": None,
        },
    )
    row = json.loads(path.read_text(encoding="utf-8"))
    assert row["process_name"] is None
    assert row["subject"] == "PowerShell script block abcdef123456"
