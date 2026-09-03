"""
Regression tests for the safe-host-isolation fixes:
  - isolate_host previously proceeded (isolating THIS machine) for ANY
    target_host string that wasn't an exact match of the local hostname --
    including a genuinely different/typo'd host it has no way to actually
    reach. Now it only proceeds for a verified-local or empty target_host.
  - The netsh rule only covered IPv4 (remoteip=0.0.0.0/0); now remoteip=any
    covers IPv4+IPv6.
  - Active RDP/SSH/WinRM sessions are checked before isolating so a rule
    can't strand the operator (Windows Firewall block rules always win over
    allow rules, so there's no safe narrow exception to punch through one).
  - active_isolations.json read-modify-write is now lock-protected.
"""
import threading

from watcher.action_engine import ActionEngine


def _engine(dry_run=True):
    return ActionEngine(dry_run=dry_run, max_destructive_per_minute=5)


def test_unverified_host_is_refused_not_silently_isolated():
    engine = _engine()
    result = engine._do_isolate_host(
        {}, {"host": "some-other-machine-entirely"}, "test-instance",
    )
    assert result["result"] == "unverified_host_refused"


def test_empty_host_is_treated_as_local_and_hits_self_isolation_gate():
    engine = _engine()
    result = engine._do_isolate_host({}, {"host": ""}, "test-instance")
    # Passes the verified-host check (empty => local), then hits the
    # self-isolation break-glass gate (WATCHER_ALLOW_SELF_ISOLATE unset).
    assert result["result"] == "self_isolation_blocked"


def test_verified_local_hostname_hits_self_isolation_gate_not_unverified():
    engine = _engine()
    result = engine._do_isolate_host(
        {}, {"host": engine._local_hostname}, "test-instance",
    )
    assert result["result"] == "self_isolation_blocked"


def test_self_isolation_override_reaches_management_session_check(monkeypatch):
    monkeypatch.setenv("WATCHER_ALLOW_SELF_ISOLATE", "true")
    engine = _engine()
    monkeypatch.setattr(engine, "_has_active_management_session", lambda: True)
    result = engine._do_isolate_host({}, {"host": ""}, "test-instance")
    assert result["result"] == "management_session_active_refused"


def test_management_check_bypassed_with_explicit_override(monkeypatch):
    monkeypatch.setenv("WATCHER_ALLOW_SELF_ISOLATE", "true")
    monkeypatch.setenv("WATCHER_ISOLATE_IGNORE_MANAGEMENT_CHECK", "true")
    engine = _engine(dry_run=True)
    monkeypatch.setattr(engine, "_has_active_management_session", lambda: True)
    result = engine._do_isolate_host({}, {"host": ""}, "test-instance")
    # Dry-run, so it reaches the "would have isolated" branch rather than a refusal.
    assert result["result"] == "dry_run"


def test_isolation_state_is_thread_safe_under_concurrent_writes(tmp_path):
    """Regression for the unlocked read-modify-write race on active_isolations.json."""
    # dry_run=True avoids _recover_isolations() reading the real prod data
    # dir at construction time; the persist/forget helpers under test don't
    # consult self.dry_run at all, so this doesn't weaken the assertion.
    engine = _engine(dry_run=True)
    engine._isolation_file = tmp_path / "active_isolations.json"

    def persist(i: int):
        engine._persist_isolation(f"instance-{i}", f"rule-{i}", 9999999999.0)

    threads = [threading.Thread(target=persist, args=(i,)) for i in range(20)]
    for t in threads: t.start()
    for t in threads: t.join()

    entries = engine._load_isolations()
    assert len(entries) == 20, "concurrent writes must not clobber each other"

    def forget(i: int):
        engine._forget_isolation(f"instance-{i}")

    threads = [threading.Thread(target=forget, args=(i,)) for i in range(20)]
    for t in threads: t.start()
    for t in threads: t.join()

    assert engine._load_isolations() == {}
