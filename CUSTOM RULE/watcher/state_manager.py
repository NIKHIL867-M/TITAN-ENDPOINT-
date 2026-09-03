"""
Rule state manager — `watcher/state_manager.py`

Tracks the lifecycle of a rule instance — one instance per
(rule_id, entity_tuple) pair that has started matching.

State machine (execute.txt §5):
    waiting → triggered → collecting → monitoring → responding → closed

For a simple threshold rule (e.g., brute-force login):
    triggered → responding  (in one step if threshold is exceeded)

For a single-event rule (e.g., powershell with -enc):
    triggered → responding  (immediately on first match)

The full machine visibly matters for multi-stage / chained rules —
built generally now so it doesn't need retrofitting later.

Instance key: (rule_id: str, entity: tuple[str, ...])
  where entity is built from the rule's aggregation.key fields,
  e.g. ("user:CORP\\jsmith",) for a rule aggregated by user.
  For single-event rules with no aggregation, entity = ("*",).
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
# State enum
# ═══════════════════════════════════════════════════════════════════════


class InstanceState(str, Enum):
    WAITING = "waiting"
    TRIGGERED = "triggered"
    COLLECTING = "collecting"
    MONITORING = "monitoring"
    RESPONDING = "responding"
    CLOSED = "closed"


# ═══════════════════════════════════════════════════════════════════════
# Rule instance
# ═══════════════════════════════════════════════════════════════════════


@dataclass
class RuleInstance:
    """
    One active instance of a rule being evaluated against an entity.
    """
    instance_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str = ""
    rule_text: str = ""
    entity: tuple = ()
    state: InstanceState = InstanceState.WAITING
    created_at: float = field(default_factory=time.time)
    triggered_at: float | None = None
    responded_at: float | None = None
    # The events that contributed to this instance (first few, for evidence)
    matched_events: list[dict[str, Any]] = field(default_factory=list)
    # Match count (for aggregation rules)
    match_count: int = 0


# ═══════════════════════════════════════════════════════════════════════
# State manager
# ═══════════════════════════════════════════════════════════════════════


class StateManager:
    """
    Manages all active RuleInstance objects.

    Single-threaded (runs in the main event loop) — no lock needed.
    """

    # Instances older than this (with no response) are auto-closed
    # to prevent unbounded memory growth on rules that never fire.
    _MAX_INSTANCE_AGE_S = 3600.0  # 1 hour

    def __init__(self) -> None:
        self._instances: dict[tuple, RuleInstance] = {}
        self._last_gc = time.monotonic()

    # ── Public API ────────────────────────────────────────────────

    def get_or_create(
        self,
        rule_id: str,
        rule_text: str,
        entity: tuple,
    ) -> RuleInstance:
        """
        Return the existing instance for (rule_id, entity), or create one
        in WAITING state if none exists.
        """
        key = (rule_id, *entity)
        inst = self._instances.get(key)
        if inst is None:
            inst = RuleInstance(
                rule_id=rule_id,
                rule_text=rule_text,
                entity=entity,
            )
            self._instances[key] = inst
        return inst

    def advance(self, inst: RuleInstance, new_state: InstanceState) -> None:
        """Advance an instance to a new state, logging the transition."""
        old = inst.state
        inst.state = new_state
        now = time.time()

        if new_state == InstanceState.TRIGGERED:
            inst.triggered_at = now
        elif new_state == InstanceState.RESPONDING:
            inst.responded_at = now

        logger.debug(
            "Instance %s (%s): %s → %s",
            inst.instance_id[:8], inst.rule_id[:8], old.value, new_state.value,
        )

    def close(self, inst: RuleInstance) -> None:
        """Mark instance as closed and remove it from the active set."""
        self.advance(inst, InstanceState.CLOSED)
        key = (inst.rule_id, *inst.entity)
        self._instances.pop(key, None)
        logger.debug("Instance %s closed.", inst.instance_id[:8])

    def add_event(self, inst: RuleInstance, event: dict[str, Any]) -> None:
        """Record a matching event in the instance (up to 10 kept)."""
        if len(inst.matched_events) < 10:
            inst.matched_events.append(event)
        inst.match_count += 1

    # ── Garbage collection ─────────────────────────────────────────

    def maybe_gc(self) -> None:
        """
        Remove stale instances that have been open longer than MAX_INSTANCE_AGE_S
        without completing. Call from the main loop.
        """
        now_mono = time.monotonic()
        if now_mono - self._last_gc < 60.0:  # check every minute
            return

        now_wall = time.time()
        stale_keys = [
            key for key, inst in self._instances.items()
            if (now_wall - inst.created_at) > self._MAX_INSTANCE_AGE_S
            and inst.state not in (InstanceState.RESPONDING, InstanceState.CLOSED)
        ]
        for key in stale_keys:
            inst = self._instances.pop(key)
            logger.debug(
                "GC: closed stale instance %s (rule=%s, age=%.0fs)",
                inst.instance_id[:8], inst.rule_id[:8],
                now_wall - inst.created_at,
            )
        if stale_keys:
            logger.info("StateManager GC: removed %d stale instance(s).", len(stale_keys))

        self._last_gc = now_mono
