"""
Test DedupGuard — overlapping collector deduplication (master.md Fix #9).

Verifies that the DedupGuard correctly:
  - Flags duplicate events within the TTL window
  - Allows different events through
  - Cleans up expired entries
  - Handles edge cases (no PID, different hosts)
"""
import time
import pytest

from watcher.event_bus import DedupGuard


class TestDedupGuard:
    """Unit tests for the DedupGuard class."""

    def test_first_event_is_not_duplicate(self):
        """First occurrence of any event should pass through."""
        guard = DedupGuard(ttl_s=2.0)
        event = {
            "event_type": "process.start",
            "process": {"pid": 1234},
            "host": "testhost",
        }
        assert guard.is_duplicate(event) is False

    def test_same_event_within_ttl_is_duplicate(self):
        """Same (event_type, pid, host) within TTL → duplicate."""
        guard = DedupGuard(ttl_s=2.0)
        event = {
            "event_type": "process.start",
            "process": {"pid": 1234},
            "host": "testhost",
        }
        assert guard.is_duplicate(event) is False  # first
        assert guard.is_duplicate(event) is True   # duplicate

    def test_different_event_type_is_not_duplicate(self):
        """Different event_type → not a duplicate."""
        guard = DedupGuard(ttl_s=2.0)
        event1 = {
            "event_type": "process.start",
            "process": {"pid": 1234},
            "host": "testhost",
        }
        event2 = {
            "event_type": "process.stop",
            "process": {"pid": 1234},
            "host": "testhost",
        }
        assert guard.is_duplicate(event1) is False
        assert guard.is_duplicate(event2) is False

    def test_different_pid_is_not_duplicate(self):
        """Different PID → not a duplicate."""
        guard = DedupGuard(ttl_s=2.0)
        event1 = {
            "event_type": "process.start",
            "process": {"pid": 1234},
            "host": "testhost",
        }
        event2 = {
            "event_type": "process.start",
            "process": {"pid": 5678},
            "host": "testhost",
        }
        assert guard.is_duplicate(event1) is False
        assert guard.is_duplicate(event2) is False

    def test_different_host_is_not_duplicate(self):
        """Different host → not a duplicate."""
        guard = DedupGuard(ttl_s=2.0)
        event1 = {
            "event_type": "process.start",
            "process": {"pid": 1234},
            "host": "host-a",
        }
        event2 = {
            "event_type": "process.start",
            "process": {"pid": 1234},
            "host": "host-b",
        }
        assert guard.is_duplicate(event1) is False
        assert guard.is_duplicate(event2) is False

    def test_expired_entries_are_cleaned_up(self):
        """After TTL expires, the same event should pass through again."""
        guard = DedupGuard(ttl_s=0.1)  # 100ms TTL for fast test
        event = {
            "event_type": "process.start",
            "process": {"pid": 1234},
            "host": "testhost",
        }
        assert guard.is_duplicate(event) is False
        assert guard.is_duplicate(event) is True   # within TTL
        time.sleep(0.15)  # wait for TTL to expire
        assert guard.is_duplicate(event) is False   # expired, should pass

    def test_no_pid_handled_gracefully(self):
        """Events without a process/pid field should still dedup correctly."""
        guard = DedupGuard(ttl_s=2.0)
        event = {
            "event_type": "auth.login_failure",
            "host": "testhost",
        }
        assert guard.is_duplicate(event) is False
        assert guard.is_duplicate(event) is True

    def test_none_process_handled(self):
        """Events with process=None should not crash."""
        guard = DedupGuard(ttl_s=2.0)
        event = {
            "event_type": "process.start",
            "process": None,
            "host": "testhost",
        }
        assert guard.is_duplicate(event) is False
        assert guard.is_duplicate(event) is True

    def test_deduped_count_tracks(self):
        """The deduped_count metric should increase with each duplicate."""
        guard = DedupGuard(ttl_s=2.0)
        event = {
            "event_type": "process.start",
            "process": {"pid": 1},
            "host": "h",
        }
        guard.is_duplicate(event)  # first
        assert guard.deduped_count == 0
        guard.is_duplicate(event)  # dup
        assert guard.deduped_count == 1
        guard.is_duplicate(event)  # dup again
        assert guard.deduped_count == 2
