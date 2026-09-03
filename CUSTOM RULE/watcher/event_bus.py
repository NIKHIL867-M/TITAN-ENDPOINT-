"""
Event bus — `watcher/event_bus.py`

Thread-safe bounded queue that receives raw events from multiple collector
threads and allows the main loop consumer thread to drain them sequentially.

Design from execute.txt Collector Platform Redesign §3:
  - Bounded queue (default: 10,000) prevents runaway memory under storms.
  - Non-blocking put_nowait avoids blocking collector threads if queue is full.
  - Dropped events are tracked in self.dropped.

Includes DedupGuard (master.md Fix #9):
  - Prevents double-counting when overlapping collectors (e.g. security + wmi)
    both fire for the same real event within a short time window.
"""
from __future__ import annotations

import logging
import queue
import time
from typing import Any, Iterator

logger = logging.getLogger(__name__)


class DedupGuard:
    """
    Deduplication guard for overlapping collectors (master.md Fix #9).

    If both 'security' and 'wmi' collectors are enabled, both can emit
    'process.start' for the same real process launch. This guard ensures
    only the first event within a 2-second window is matched — no double
    alerts, no double evidence records, no double actions.

    Applied right after normalization, before rule matching. The key is
    (event_type, pid, host) — if the same triple appears within ttl_s
    seconds, the second is dropped.
    """

    def __init__(self, ttl_s: float = 2.0) -> None:
        self._seen: dict[tuple, tuple[float, str]] = {}  # key -> (expiry, collector)
        self.ttl_s = ttl_s
        self.deduped_count = 0

    def is_duplicate(self, event: dict[str, Any]) -> bool:
        """
        Check if this normalized event is a duplicate of a recently seen one.

        Returns True if the event should be dropped (duplicate),
        False if it should be processed (first occurrence).
        """
        key = dedup_key(event)

        now = time.time()

        # Cheap sweep: remove expired entries
        expired = [k for k, (expiry, _) in self._seen.items() if expiry <= now]
        for k in expired:
            del self._seen[k]

        source = str(event.get("source_collector", ""))
        previous = self._seen.get(key)
        # Dedup exists only to collapse the same real event reported by two
        # overlapping collectors. Repeated events from one collector (notably
        # Security 4625 with LogonId 0x0) must remain countable.
        if previous and (not source or previous[1] != source):
            self.deduped_count += 1
            if self.deduped_count % 100 == 1:
                logger.info(
                    "DedupGuard: %d duplicate event(s) suppressed so far "
                    "(overlapping collectors producing same event_type)",
                    self.deduped_count,
                )
            return True

        self._seen[key] = (now + self.ttl_s, source)
        return False


def dedup_key(event: dict[str, Any]) -> tuple:
    """Build a sufficiently specific key; unknown schemas fail open."""
    et, host = event.get("event_type", ""), event.get("host", "")
    proc = event.get("process") if isinstance(event.get("process"), dict) else {}
    if et.startswith("process.") or et in {"image.load", "file.create", "file.delete"}:
        identity = proc.get("guid") or proc.get("pid")
        return (et, identity, host) if identity is not None else (et, host, id(event))
    if et.startswith("auth."):
        identity = event.get("event_record_id")
        if not identity and str(event.get("logon_id", "")).lower() not in {"", "0", "0x0"}:
            identity = event.get("logon_id")
        return (et, identity, host) if identity else (et, host, id(event))
    if et == "network.connect":
        net = event.get("network") if isinstance(event.get("network"), dict) else {}
        return et, proc.get("guid") or proc.get("pid"), net.get("dest_ip"), net.get("dest_port"), host
    if et == "dns.query":
        return et, proc.get("guid") or proc.get("pid"), event.get("query_name"), host
    # A unique object identity deliberately means no accidental suppression.
    return et, host, id(event)


class EventBus:
    """Thread-safe queue with drop metrics for collector decoupling."""

    def __init__(self, maxsize: int = 10_000) -> None:
        self._q: queue.Queue[dict] = queue.Queue(maxsize=maxsize)
        self.dropped = 0

    def publish(self, source: str, raw: dict) -> None:
        """
        Publish a raw event from a collector.
        Never blocks the publisher thread; drops event if full.
        """
        try:
            self._q.put_nowait({"source": source, "raw": raw})
        except queue.QueueFull:
            self.dropped += 1
            if self.dropped % 100 == 1:
                logger.warning(
                    "EventBus queue is FULL! Dropped %d event(s) so far. "
                    "Rule matching performance may be too slow.",
                    self.dropped
                )

    def consume(self) -> Iterator[dict]:
        """Drains the queue continuously (blocks when empty)."""
        while True:
            yield self._q.get()
