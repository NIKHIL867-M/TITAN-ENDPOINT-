"""Regression coverage for findings in the July deep reviews."""
from __future__ import annotations

import ast
import json
from pathlib import Path

from watcher.event_bus import DedupGuard
from watcher.notifier import _append_alert


def test_failed_logins_from_same_security_collector_are_not_deduplicated():
    guard = DedupGuard(ttl_s=2)
    first = {"event_type": "auth.login_failure", "host": "h", "logon_id": "0x0", "source_collector": "security"}
    second = dict(first)
    assert guard.is_duplicate(first) is False
    assert guard.is_duplicate(second) is False


def test_overlapping_collectors_still_deduplicate_same_process():
    guard = DedupGuard(ttl_s=2)
    first = {"event_type": "process.start", "host": "h", "process": {"pid": 42}, "source_collector": "wmi"}
    second = {**first, "source_collector": "security"}
    assert guard.is_duplicate(first) is False
    assert guard.is_duplicate(second) is True


def test_capability_mapping_literal_has_no_duplicate_keys():
    path = Path(__file__).parents[1] / "app" / "capability_checker.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    assignment = next(node for node in tree.body if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", "") == "_SOURCE_TO_COLLECTORS")
    keys = [key.value for key in assignment.value.keys]
    assert len(keys) == len(set(keys))


def test_alert_log_rotates_at_configured_bound(tmp_path, monkeypatch):
    path = tmp_path / "alerts.jsonl"
    path.write_text("x" * 1_000_000, encoding="utf-8")
    monkeypatch.setenv("WATCHER_ALERT_MAX_BYTES", "1000000")
    _append_alert({"id": "new"}, path)
    assert (tmp_path / "alerts.1.jsonl").exists()
    assert json.loads(path.read_text(encoding="utf-8"))["id"] == "new"
