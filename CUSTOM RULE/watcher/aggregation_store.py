"""
Aggregation store — `watcher/aggregation_store.py`

In-memory sliding-window counters and cooldowns.

Design from execute.txt §4:
  - Plain dict + dataclasses — no Redis, no external service.
  - Single-host tool: plain dict with TTL cleanup is the right amount
    of infrastructure.
  - Background cleanup every 30s drops expired entries: this is the
    bounded-memory guarantee. Nothing here grows without limit.

Key structure:
  - Counter key: (rule_id, entity_id, "count")
  - Cooldown key: (rule_id, entity_id, "cooldown")

Entity ID is typically a string like "user:CORP\\jsmith" or "host:ws01"
— whatever the rule's aggregation.key fields resolve to from the event.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
# Data types
# ═══════════════════════════════════════════════════════════════════════


@dataclass
class Counter:
    """Sliding-window counter — resets when window_start is older than window_s."""
    count: int
    window_start: float  # time.time() when the window opened


@dataclass
class Cooldown:
    """Cooldown record — active until expires_at."""
    expires_at: float


# ═══════════════════════════════════════════════════════════════════════
# Store class
# ═══════════════════════════════════════════════════════════════════════


class AggregationStore:
    """
    Per-watcher-instance aggregation store.

    Thread-safety note: in our architecture the main loop is single-
    threaded (draining a queue), so no lock is needed here. If ever
    moved to a multi-threaded model, add a threading.Lock.
    """

    CLEANUP_INTERVAL_S = 30.0

    def __init__(self) -> None:
        self._counters: dict[tuple, Counter] = {}
        self._cooldowns: dict[tuple, Cooldown] = {}
        self._last_cleanup = time.monotonic()

    # ── Counter API ───────────────────────────────────────────────

    def increment(self, key: tuple, window_s: int) -> int:
        """
        Increment the counter for `key` within a sliding window of `window_s` seconds.
        Returns the new count for the current window.

        If the window has expired, resets to 1 (starts a new window).
        """
        now = time.time()
        c = self._counters.get(key)
        if c is None or (now - c.window_start) > window_s:
            self._counters[key] = Counter(count=1, window_start=now)
            return 1
        c.count += 1
        return c.count

    def get_count(self, key: tuple, window_s: int) -> int:
        """Return current count without incrementing. Returns 0 if expired."""
        now = time.time()
        c = self._counters.get(key)
        if c is None or (now - c.window_start) > window_s:
            return 0
        return c.count

    def reset_counter(self, key: tuple) -> None:
        """Explicitly reset a counter (e.g., after a rule fires)."""
        self._counters.pop(key, None)

    # ── Cooldown API ──────────────────────────────────────────────

    def set_cooldown(self, key: tuple, duration_s: float) -> None:
        """Set a cooldown for `key` that expires after `duration_s` seconds."""
        self._cooldowns[key] = Cooldown(expires_at=time.time() + duration_s)
        logger.debug("Cooldown set: key=%s duration=%ss", key, duration_s)

    def in_cooldown(self, key: tuple) -> bool:
        """True if a non-expired cooldown exists for this key."""
        cd = self._cooldowns.get(key)
        if cd is None:
            return False
        if time.time() >= cd.expires_at:
            del self._cooldowns[key]
            return False
        return True

    # ── Cleanup ───────────────────────────────────────────────────

    def maybe_cleanup(self) -> None:
        """
        Drop expired counters and cooldowns.
        Call this from the main loop — it only runs every CLEANUP_INTERVAL_S.
        """
        now_mono = time.monotonic()
        if now_mono - self._last_cleanup < self.CLEANUP_INTERVAL_S:
            return

        now_wall = time.time()
        before_c = len(self._counters)
        before_cd = len(self._cooldowns)

        # We can't identify "expired" counters without knowing their window_s,
        # so we use a generous max-window heuristic: drop counters older than
        # 24h (no rule should have a window longer than a day for v1).
        MAX_COUNTER_AGE = 86400.0
        self._counters = {
            k: v for k, v in self._counters.items()
            if (now_wall - v.window_start) <= MAX_COUNTER_AGE
        }

        self._cooldowns = {
            k: v for k, v in self._cooldowns.items()
            if now_wall < v.expires_at
        }

        self._last_cleanup = now_mono
        dropped_c = before_c - len(self._counters)
        dropped_cd = before_cd - len(self._cooldowns)

        if dropped_c or dropped_cd:
            logger.debug(
                "AggregationStore cleanup: dropped %d counters, %d cooldowns",
                dropped_c, dropped_cd,
            )

    # ── Aggregation key builder ───────────────────────────────────

    @staticmethod
    def build_key(rule_id: str, event: dict, key_fields: list[str]) -> tuple:
        """
        Build the aggregation key tuple from the event's fields.

        e.g. key_fields=["user"] → key=("rule-uuid", "user:jsmith")
        """
        parts = [rule_id]
        for field in key_fields:
            val = _extract_field(event, field)
            parts.append(f"{field}:{val}")
        return tuple(parts)


# ═══════════════════════════════════════════════════════════════════════
# Field extractor (shared with condition evaluator)
# ═══════════════════════════════════════════════════════════════════════


def _extract_field(event: dict, field_name: str) -> str:
    """
    Extract a field value from a normalized event dict.
    Handles nested paths: "process.name", "network.dest_ip", etc.
    Returns empty string if the field is not present.
    """
    parts = field_name.split(".")
    if len(parts) == 1:
        val = event.get(field_name)
    else:
        # Navigate nested: "process.name" → event["process"]["name"]
        obj = event.get(parts[0])
        if obj is None or not isinstance(obj, dict):
            return ""
        val = obj.get(parts[1])

    if val is None:
        return ""
    return str(val)
