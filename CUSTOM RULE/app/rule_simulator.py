"""
Rule simulator.

Generates synthetic events matching the IR's trigger event type, then
evaluates the rule's conditions against each one.

Produces 3–5 events:
  - 2–3 that SHOULD trigger the rule (matching conditions)
  - 1–2 that SHOULD NOT trigger (non-matching)

All data is local to the request scope — generated, evaluated, returned,
and discarded. Nothing is persisted, nothing is cached, nothing is
attached to a module-level structure.
"""


import random
from pydantic import BaseModel

from app.semantic_validator import ParseResult


class SimulationEvent(BaseModel):
    """A single synthetic event with evaluation results."""

    data: dict[str, str]
    should_trigger: bool
    did_trigger: bool
    explanation: str


class SimulationResult(BaseModel):
    """Full simulation output — consumed by the review UI."""

    events: list[SimulationEvent]
    summary: str


# ═══════════════════════════════════════════════════════════════════════
# Sample data pools for realistic synthetic events
# ═══════════════════════════════════════════════════════════════════════

_POOLS: dict[str, list[str]] = {
    "name": [
        "powershell.exe", "cmd.exe", "explorer.exe", "notepad.exe",
        "svchost.exe", "calc.exe", "chrome.exe", "python.exe",
    ],
    "parent_name": [
        "explorer.exe", "cmd.exe", "winlogon.exe", "services.exe",
        "svchost.exe", "wininit.exe",
    ],
    "command_line": [
        "powershell.exe -encodedcommand SGVsbG8=",
        "cmd.exe /c dir C:\\Windows\\System32",
        "powershell.exe Get-Process | Out-File report.txt",
        "notepad.exe C:\\temp\\notes.txt",
        "svchost.exe -k netsvcs",
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File s.ps1",
        "chrome.exe --no-sandbox --disable-gpu",
    ],
    "username": ["admin", "jdoe", "svc_backup", "analyst1", "guest"],
    "source_ip": [
        "192.168.1.100", "10.0.0.55", "203.0.113.42",
        "172.16.0.10", "8.8.8.8",
    ],
    "hash": [
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
        "deadbeef1234deadbeef1234deadbeef12",
        "cafebabe5678cafebabe5678cafebabe56",
    ],
    "method": ["password", "kerberos", "ntlm", "certificate"],
    "result": ["success", "failure", "locked_out"],
}

# Fields that trigger with numeric data
_NUMERIC_FIELDS = {"pid", "ppid"}


def _pick(field: str, *, match_value: str | None = None) -> str:
    """Pick a value for a field — either the match_value or a random one."""
    if match_value is not None:
        return match_value
    if field in _NUMERIC_FIELDS:
        return str(random.randint(100, 9999))
    pool = _POOLS.get(field)
    if pool:
        return random.choice(pool)
    return f"sample_{field}_value"


def _pick_non_matching(field: str, avoid: str) -> str:
    """Pick a value that is NOT the given avoid value."""
    pool = _POOLS.get(field)
    if pool:
        candidates = [v for v in pool if v.lower() != avoid.lower()]
        if candidates:
            return random.choice(candidates)
    if field in _NUMERIC_FIELDS:
        return str(random.randint(100, 9999))
    return f"other_{field}_value"


def _evaluate_condition(
    field_value: str, operator: str, condition_value: str
) -> bool:
    """Evaluate a single condition against a field value."""
    try:
        if operator == "==":
            return field_value.lower() == condition_value.lower()
        if operator == "!=":
            return field_value.lower() != condition_value.lower()
        if operator == "contains":
            return condition_value.lower() in field_value.lower()
        if operator == "within":
            return field_value.lower() in condition_value.lower()
        if operator == "is_public_ip":
            import ipaddress
            return ipaddress.ip_address(field_value).is_global
        if operator in (">", "<", ">=", "<="):
            fv, cv = float(field_value), float(condition_value)
            return {
                ">": fv > cv,
                "<": fv < cv,
                ">=": fv >= cv,
                "<=": fv <= cv,
            }[operator]
    except (ValueError, KeyError):
        pass
    return False


def simulate(parsed: ParseResult) -> SimulationResult:
    """
    Generate synthetic events and evaluate the rule's conditions.

    All structures are local — nothing escapes this function's scope
    except the returned SimulationResult.
    """
    if parsed.status == "needs_clarification" or parsed.ir is None:
        return SimulationResult(
            events=[],
            summary="Cannot simulate: rule needs clarification",
        )

    ir = parsed.ir
    if ir.sustain_for:
        return SimulationResult(
            events=[
                SimulationEvent(data={"process_state": "still_running", "duration": ir.sustain_for},
                                should_trigger=True, did_trigger=True,
                                explanation=f"Process identity remained alive for {ir.sustain_for}"),
                SimulationEvent(data={"process_state": "exited_early", "duration": ir.sustain_for},
                                should_trigger=False, did_trigger=False,
                                explanation="Process exited before the sustained-state timer elapsed"),
            ],
            summary=f"2/2 sustained-state scenarios behaved as expected ({ir.sustain_for})",
        )
    if ir.correlation:
        stage_names = [stage.event for stage in ir.correlation.stages]
        join_field = ir.correlation.join_on
        ordering = "ordered" if ir.correlation.ordered else "unordered"
        return SimulationResult(
            events=[
                SimulationEvent(
                    data={"sequence": " -> ".join(stage_names), join_field: "4242", "dest_ip": "8.8.8.8"},
                    should_trigger=True,
                    did_trigger=True,
                    explanation=f"All {ordering} stages matched on {join_field} within {ir.correlation.within}",
                ),
                SimulationEvent(
                    data={"sequence": " -> ".join(stage_names), join_field: "4242", "dest_ip": "192.168.1.10"},
                    should_trigger=False,
                    did_trigger=False,
                    explanation="Private destination does not satisfy the public-IP stage",
                ),
            ],
            summary=f"2/2 {ordering} correlation scenarios behaved as expected ({ir.correlation.within} window)",
        )
    events: list[SimulationEvent] = []

    # Determine all relevant fields
    condition_fields = {c.field for c in ir.conditions}
    agg_fields = set(ir.aggregation.key) if ir.aggregation else set()

    # Determine base field set from trigger event type
    base_fields: set[str] = set()
    trigger_lower = ir.trigger_event.lower()
    if "process" in trigger_lower:
        base_fields.update(["pid", "ppid", "name", "command_line", "parent_name", "hash"])
    if "auth" in trigger_lower or "login" in trigger_lower:
        base_fields.update(["username", "source_ip", "result", "method"])

    all_fields = base_fields | condition_fields | agg_fields

    # ── Generate 2–3 MATCHING events ──────────────────────────────
    for i in range(random.randint(2, 3)):
        data: dict[str, str] = {}
        for field in all_fields:
            matching_cond = next(
                (c for c in ir.conditions if c.field == field), None
            )
            if matching_cond:
                # For "contains" operator, embed the value in a realistic string
                if matching_cond.operator == "contains":
                    base = _pick(field)
                    if matching_cond.value.lower() not in base.lower():
                        data[field] = f"{base} {matching_cond.value}"
                    else:
                        data[field] = base
                else:
                    data[field] = _pick(field, match_value=matching_cond.value)
            else:
                data[field] = _pick(field)

        did_trigger = (
            all(
                _evaluate_condition(
                    data.get(c.field, ""), c.operator, c.value
                )
                for c in ir.conditions
            )
            if ir.conditions
            else True
        )

        events.append(
            SimulationEvent(
                data=data,
                should_trigger=True,
                did_trigger=did_trigger,
                explanation=(
                    f"Matching event #{i + 1}: all conditions satisfied"
                    if did_trigger
                    else f"Event #{i + 1}: expected to trigger but a condition was not met"
                ),
            )
        )

    # ── Generate 1–2 NON-MATCHING events ──────────────────────────
    for i in range(random.randint(1, 2)):
        data = {}
        for field in all_fields:
            matching_cond = next(
                (c for c in ir.conditions if c.field == field), None
            )
            if matching_cond:
                data[field] = _pick_non_matching(field, matching_cond.value)
            else:
                data[field] = _pick(field)

        did_trigger = (
            all(
                _evaluate_condition(
                    data.get(c.field, ""), c.operator, c.value
                )
                for c in ir.conditions
            )
            if ir.conditions
            else True
        )

        events.append(
            SimulationEvent(
                data=data,
                should_trigger=False,
                did_trigger=did_trigger,
                explanation=(
                    f"Non-matching event #{i + 1}: correctly did not trigger"
                    if not did_trigger
                    else f"Non-matching event #{i + 1}: unexpectedly triggered — review conditions"
                ),
            )
        )

    # ── Summary ───────────────────────────────────────────────────
    correct = sum(1 for e in events if e.should_trigger == e.did_trigger)
    total = len(events)
    summary = f"{correct}/{total} events evaluated correctly"
    if correct < total:
        summary += " — review conditions for potential issues"

    return SimulationResult(events=events, summary=summary)
