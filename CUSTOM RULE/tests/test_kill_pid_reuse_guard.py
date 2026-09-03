"""
Regression tests for the kill_process PID-reuse revalidation guard.

Windows recycles PIDs once a process exits. Previously action_engine.py
killed strictly by PID with no re-check; a rule firing after a correlation/
aggregation/sustain delay could terminate a completely different process
that happened to reuse that PID. _revalidate_kill_target() (action_engine.py)
now confirms name (and create_time when available) immediately before the
real kill, and refuses to touch TITAN's own components or core OS processes
regardless of what a rule says.
"""
import subprocess
import sys
import time

import psutil
import pytest

from watcher.action_engine import ActionEngine, _revalidate_kill_target


def _spawn_dummy(name_hint: str = "sleeper"):
    """A real, short-lived child process this test owns and can safely kill."""
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(0.2)  # let it fully start so psutil sees a stable create_time
    return proc


def test_kill_succeeds_when_identity_matches_real_process():
    child = _spawn_dummy()
    try:
        live = psutil.Process(child.pid)
        event = {
            "process": {
                "pid": child.pid,
                "name": live.name(),
                "create_time": live.create_time(),
            }
        }
        engine = ActionEngine(dry_run=False, max_destructive_per_minute=5)
        result = engine._do_kill_process(event, "test-instance")
        assert result["result"] == "killed"
        child.wait(timeout=5)  # confirm the OS actually terminated it
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)


def test_kill_blocked_when_name_no_longer_matches_pid():
    """Simulates PID reuse: the event's expected name no longer matches what's live at that PID."""
    child = _spawn_dummy()
    try:
        event = {
            "process": {
                "pid": child.pid,
                "name": "totally_different_process.exe",  # PID reuse: not what's actually running
            }
        }
        ok, reason = _revalidate_kill_target(child.pid, event)
        assert ok is False
        assert reason.startswith("pid_reuse_suspected")
    finally:
        child.kill()
        child.wait(timeout=5)


def test_kill_blocked_when_create_time_mismatches():
    child = _spawn_dummy()
    try:
        live = psutil.Process(child.pid)
        event = {
            "process": {
                "pid": child.pid,
                "name": live.name(),
                "create_time": live.create_time() - 3600,  # an hour off => different process
            }
        }
        ok, reason = _revalidate_kill_target(child.pid, event)
        assert ok is False
        assert "create_time_mismatch" in reason
    finally:
        child.kill()
        child.wait(timeout=5)


def test_kill_blocked_for_already_exited_pid():
    child = _spawn_dummy()
    child.kill()
    child.wait(timeout=5)
    time.sleep(0.2)

    event = {"process": {"pid": child.pid, "name": "python.exe"}}
    ok, reason = _revalidate_kill_target(child.pid, event)
    assert ok is False
    assert reason == "already_exited"


@pytest.mark.parametrize("protected_name", [
    "titan_process.exe", "correlator.exe", "explorer.exe", "lsass.exe",
])
def test_kill_blocked_for_protected_process_names(protected_name):
    """A rule can never cause TITAN's own components or core OS processes to be killed."""
    child = _spawn_dummy()
    try:
        # Event claims the target IS a protected name -- regardless of what's
        # actually live at that PID, this must be refused.
        event = {"process": {"pid": child.pid, "name": protected_name}}
        ok, reason = _revalidate_kill_target(child.pid, event)
        assert ok is False
        assert reason.startswith("protected_process") or reason.startswith("pid_reuse_suspected")
    finally:
        child.kill()
        child.wait(timeout=5)


def test_dry_run_reports_intent_without_requiring_a_real_pid():
    """Dry-run must keep working against synthetic PIDs (existing rule-logic tests rely on this)."""
    engine = ActionEngine(dry_run=True, max_destructive_per_minute=5)
    result = engine._do_kill_process({"process": {"pid": 999999999}}, "test-instance")
    assert result["result"] == "dry_run"
