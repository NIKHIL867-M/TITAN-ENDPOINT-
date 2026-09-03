"""
Regression tests for watcher/bookmarks.py's EventBookmark.advance() fix.

Observed live: on this OneDrive-synced project, os.replace() for the
bookmark file transiently fails with WinError 5 (Access Denied) on nearly
every event for a high-volume channel -- thousands of warnings per minute,
each logged, which is itself a real storage-growth problem. advance() now
retries briefly (absorbs a transient lock) and throttles the failure log to
every 100th occurrence per channel when it's still failing after retries.
"""
import os

import pytest

from watcher.bookmarks import EventBookmark


class _FakeApi:
    """Minimal stand-in for win32evtlog — advance() only touches these three."""
    def EvtCreateBookmark(self, xml):
        return object()

    def EvtUpdateBookmark(self, handle, event_handle):
        pass

    def EvtRender(self, handle, render_type):
        return "<Bookmark/>"

    EvtRenderBookmark = 1


@pytest.fixture(autouse=True)
def _reset_fail_counts():
    EventBookmark._fail_counts.clear()
    yield
    EventBookmark._fail_counts.clear()


def test_advance_succeeds_after_transient_replace_failure(tmp_path, monkeypatch):
    monkeypatch.setenv("WATCHER_DATA_DIR", str(tmp_path))
    bookmark = EventBookmark("TestChannel", _FakeApi())

    real_replace = os.replace
    calls = {"n": 0}

    def flaky_replace(src, dst):
        calls["n"] += 1
        if calls["n"] < 2:
            raise PermissionError("simulated WinError 5")
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", flaky_replace)
    bookmark.advance(object())  # must not raise -- retry absorbs the transient failure

    assert bookmark.path.exists()
    assert calls["n"] == 2


def test_advance_throttles_logging_when_permanently_failing(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("WATCHER_DATA_DIR", str(tmp_path))
    bookmark = EventBookmark("TestChannel", _FakeApi())

    def always_fails(src, dst):
        raise PermissionError("simulated permanent WinError 5")

    monkeypatch.setattr(os, "replace", always_fails)
    monkeypatch.setattr("watcher.bookmarks.time.sleep", lambda s: None)  # don't actually wait in the test

    import logging
    caplog.set_level(logging.WARNING, logger="watcher.bookmarks")

    for _ in range(150):
        bookmark.advance(object())

    warnings = [r for r in caplog.records if "Bookmark update failed" in r.message]
    # Only the 1st and 100th (of 150) should have logged -- not all 150.
    assert len(warnings) == 2
    assert EventBookmark._fail_counts["TestChannel"] == 150
