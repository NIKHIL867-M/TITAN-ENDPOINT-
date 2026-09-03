"""
Rule index — `watcher/rule_index.py`

Loads data/rules.jsonl at startup and builds:
    dict[event_type, list[rule_dict]]

This is the "indexed dispatch" from the architecture:
  - An incoming process.start event ONLY gets checked against rules whose
    trigger_event == "process.start" — not the whole rule set.
  - O(1) lookup by event_type, not a linear scan of all rules.

Hot-reload (execute.txt §3):
  - Check mtime once per second (cheap, no inotify needed on Windows).
  - When mtime changes, rebuild the index from scratch.
  - Old index object is just GC'd — no locks needed because we replace
    the whole state object atomically in one assignment.

Flaw-fix from execute.txt §4:
  - Skip lines that fail json.loads — don't crash the loop.
  - A half-written line from a concurrent write (theoretically possible
    even with the lock in rule_store.py) is safely skipped.
"""
from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from shared.integrity import verify_record

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
# State container
# ═══════════════════════════════════════════════════════════════════════


@dataclass
class RuleIndexState:
    """
    Immutable snapshot of the rule index at a given file mtime.
    Replace the whole object to update; never mutate in place.
    """
    index: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    rule_count: int = 0
    last_mtime: float = 0.0
    last_check_at: float = 0.0
    load_errors: int = 0
    degraded: bool = False


# ═══════════════════════════════════════════════════════════════════════
# Build helpers
# ═══════════════════════════════════════════════════════════════════════


def _build_index(rules_file: Path) -> RuleIndexState:
    """
    Read rules.jsonl and build the event-type index.
    Skips corrupt/malformed lines gracefully — flaw fix #4.
    """
    index: dict[str, list[dict[str, Any]]] = {}
    rule_count = 0
    load_errors = 0
    seen_semantics: set[str] = set()

    if not rules_file.exists():
        logger.info("rules.jsonl not found — no approved rules yet. Watching but nothing will match.")
        return RuleIndexState(
            index={},
            rule_count=0,
            last_mtime=0.0,
            last_check_at=time.monotonic(),
        )

    mtime = os.path.getmtime(rules_file)

    with open(rules_file, encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                load_errors += 1
                logger.warning(
                    "rules.jsonl line %d: JSON parse error (skipping): %s",
                    lineno, exc,
                )
                continue

            integrity = verify_record(record, rules_file.parent, "approved_rule")
            if integrity in {"invalid", "unsupported"}:
                load_errors += 1
                logger.critical(
                    "rules.jsonl line %d failed integrity verification; execution suppressed",
                    lineno,
                )
                continue
            if integrity == "legacy_unsigned":
                logger.warning(
                    "rules.jsonl line %d is a legacy unsigned record; accepted for compatibility",
                    lineno,
                )

            # The record structure is:
            # { "id": ..., "ir": { "ir": { "trigger_event": ..., ... } } }
            try:
                trigger_event = record["ir"]["ir"]["trigger_event"]
            except (KeyError, TypeError):
                load_errors += 1
                logger.warning(
                    "rules.jsonl line %d: missing trigger_event (skipping)", lineno
                )
                continue

            inner = record["ir"]["ir"]
            if not inner.get("conditions") and not inner.get("correlation") and not inner.get("aggregation"):
                load_errors += 1
                logger.error(
                    "rules.jsonl line %d is an unsafe conditionless single-event rule; execution suppressed",
                    lineno,
                )
                continue

            # Approval history may contain repeated saves of the same executable
            # rule. Keep history intact, but execute each semantic rule once.
            semantic = json.dumps(inner, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            if semantic in seen_semantics:
                logger.warning("rules.jsonl line %d duplicates an active rule; execution copy suppressed", lineno)
                continue
            seen_semantics.add(semantic)

            event_types = [trigger_event]
            try:
                correlation = record["ir"]["ir"].get("correlation")
                if correlation:
                    event_types = [stage["event"] for stage in correlation.get("stages", [])]
            except (KeyError, TypeError):
                pass
            for event_type in dict.fromkeys(event_types):
                index.setdefault(event_type, []).append(record)
            rule_count += 1

    if rule_count == 0:
        logger.warning(
            "rules.jsonl exists but contains no valid approved rules. "
            "Watching but nothing will match."
        )
    else:
        logger.info(
            "Rule index built: %d rules across %d event type(s): %s",
            rule_count,
            len(index),
            list(index.keys()),
        )

    return RuleIndexState(
        index=index,
        rule_count=rule_count,
        last_mtime=mtime,
        last_check_at=time.monotonic(),
        load_errors=load_errors,
    )


# ═══════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════

# Check mtime at most once per second — cheap enough not to worry about
_RELOAD_INTERVAL_S = 1.0


def maybe_reload(state: RuleIndexState, rules_file: Path) -> RuleIndexState:
    """
    Return the current state unchanged, or a freshly built state if
    rules.jsonl has been modified since the last check.

    This is called on every event loop iteration — it's O(1) when
    nothing has changed (just a float comparison after the first check).
    """
    now = time.monotonic()
    if now - state.last_check_at < _RELOAD_INTERVAL_S:
        return state  # not time to check yet

    # Time to check mtime
    try:
        current_mtime = os.path.getmtime(rules_file) if rules_file.exists() else 0.0
    except OSError:
        current_mtime = 0.0

    if current_mtime == state.last_mtime:
        # File unchanged — just update the check timestamp
        state.last_check_at = now
        return state

    logger.info("rules.jsonl changed — reloading rule index...")
    new_state = _build_index(rules_file)
    new_state.last_check_at = now
    if new_state.rule_count == 0 and new_state.load_errors and state.rule_count:
        logger.critical(
            "Rule reload produced no valid rules after %d error(s); retaining %d last-known-good rule(s)",
            new_state.load_errors, state.rule_count,
        )
        state.last_mtime = new_state.last_mtime
        state.last_check_at = now
        state.load_errors = new_state.load_errors
        state.degraded = True
        return state
    return new_state


def initial_load(rules_file: Path) -> RuleIndexState:
    """
    Build the index on startup. Always call this before the main loop.
    """
    return _build_index(rules_file)


def lookup(state: RuleIndexState, event_type: str) -> list[dict[str, Any]]:
    """
    Return the list of rules matching this event_type.
    Returns an empty list if no rules match — never raises.
    """
    return state.index.get(event_type, [])
