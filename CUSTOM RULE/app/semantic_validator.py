"""
Semantic validator (execute.txt §8c).

Two-layer validation:
  1. STRUCTURAL — Pydantic models enforce types, enums, ranges, and
     patterns. This is where Python does less manual work than the Node
     version: type checking, the severity enum, the priority range, and
     the time-window regex are declarations, not hand-written checks.
  2. CONTEXTUAL — hand-written logic verifies that fields, operators,
     and actions referenced in the IR actually exist in the current
     deployment context (runtime data, not static schema).

Pydantic's structured ValidationError (listing exactly which field
failed and why) is what gets fed back to the LLM on retry (§8c).

Upgrade (Backend_Action_Evidence_Upgrade_Plan):
  - Response actions are now validated against shared.action_types.ActionType
    at the validator level — no free-text actions can ever reach the watcher.
  - RuleIR and ParseResult now carry suggested_action / suggested_action_reason
    fields for the human-in-the-loop review flow.
"""


import re
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.context_builder import DeploymentContext, EVENT_FIELD_TYPES, OPERATORS_BY_FIELD_TYPE
from shared.action_types import ActionType, validate_actions


# ═══════════════════════════════════════════════════════════════════════
# IR Pydantic models
# ═══════════════════════════════════════════════════════════════════════


class Condition(BaseModel):
    """A single condition in the rule's condition list."""

    field: str
    operator: str
    value: str


class Aggregation(BaseModel):
    """Aggregation / windowing specification."""

    key: list[str]
    window: str = Field(pattern=r"^\d+[smhd]$")
    threshold: str


class ResponseAction(BaseModel):
    """A single response action to take when the rule fires."""

    type: str
    duration: Optional[str] = None


class Explanation(BaseModel):
    """LLM's self-documentation of what it inferred and assumed."""

    matched_event: str
    inferred_threshold: str
    assumptions_made: list[str]


class CorrelationStage(BaseModel):
    event: str
    conditions: list[Condition] = Field(default_factory=list)


class Correlation(BaseModel):
    stages: list[CorrelationStage] = Field(min_length=2, max_length=5)
    within: str = Field(pattern=r"^\d+[smh]$")
    join_on: str
    ordered: bool = True


class RuleIR(BaseModel):
    """The full intermediate representation of a parsed rule."""

    model_config = ConfigDict(extra="forbid")

    trigger_event: str
    aggregation: Optional[Aggregation] = None
    correlation: Optional[Correlation] = None
    sustain_for: Optional[str] = Field(default=None, pattern=r"^\d+[smh]$")
    conditions: list[Condition]
    investigation_steps: list[str]
    response_actions: list[ResponseAction]
    severity: Literal["low", "medium", "high", "critical"]
    priority: int = Field(ge=1, le=10)
    tags: list[str]
    # LLM-suggested actions (pre-filled in review UI — human finalises response_actions)
    suggested_action: list[str] = Field(default_factory=list)
    suggested_action_reason: Optional[str] = None


class ParseResult(BaseModel):
    """Top-level model matching the LLM's output schema."""

    status: Literal["ok", "needs_clarification"]
    clarification: Optional[str] = None
    ir: Optional[RuleIR] = None
    explanation: Optional[Explanation] = None


# ═══════════════════════════════════════════════════════════════════════
# Validation result
# ═══════════════════════════════════════════════════════════════════════


class ValidationResult(BaseModel):
    """Outcome of validation — consumed by retry logic and UI."""

    valid: bool
    errors: list[str]
    parsed: Optional[ParseResult] = None


def validate_regex_pattern(pattern: str) -> list[str]:
    """Reject invalid or high-risk regular expressions before runtime."""
    errors: list[str] = []
    if len(pattern) > 200:
        errors.append("regex pattern too long (max 200 characters)")
    # Nested/repeated quantifiers are the most common catastrophic
    # backtracking shape, e.g. (a+)+, (.*)* and (a|aa)+.
    if re.search(r"\([^)]*(?:[+*]|\{\d+(?:,\d*)?\})[^)]*\)\s*(?:[+*]|\{\d+(?:,\d*)?\})", pattern):
        errors.append("regex pattern risks catastrophic backtracking; simplify nested repetition")
    if re.search(r"\([^)]*\|[^)]*\)\s*[+*]", pattern):
        errors.append("regex pattern uses a repeated alternation that may backtrack excessively")
    try:
        re.compile(pattern)
    except re.error as exc:
        errors.append(f"invalid regex: {exc}")
    return errors


# ═══════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════


def validate_structure(raw_dict: dict) -> ValidationResult:
    """
    Validate the raw JSON dict against the IR Pydantic schema.
    Returns structured errors if validation fails — these are what
    get fed back to the LLM on retry.
    """
    try:
        parsed = ParseResult(**raw_dict)
        return ValidationResult(valid=True, errors=[], parsed=parsed)
    except ValidationError as e:
        errors: list[str] = []
        for err in e.errors():
            loc = " → ".join(str(x) for x in err["loc"])
            errors.append(f"Field '{loc}': {err['msg']}")
        return ValidationResult(valid=False, errors=errors)


def validate_against_context(
    parsed: ParseResult,
    context: DeploymentContext,
) -> ValidationResult:
    """
    Check that all fields, operators, and actions referenced in the IR
    actually exist in the deployment context. This is the layer Pydantic
    can't handle — it's runtime data, not a static schema.
    """
    errors: list[str] = []

    # If the model said it needs clarification, that's a valid response
    if parsed.status == "needs_clarification":
        return ValidationResult(valid=True, errors=[], parsed=parsed)

    ir = parsed.ir
    if ir is None:
        errors.append(
            "Status is 'ok' but no IR object was provided — "
            "either provide an IR or set status to 'needs_clarification'"
        )
        return ValidationResult(valid=False, errors=errors, parsed=parsed)

    if ir.sustain_for:
        if ir.trigger_event != "process.start":
            errors.append("sustain_for currently requires process.start telemetry so liveness can be re-verified")
        if ir.aggregation or ir.correlation:
            errors.append("sustain_for cannot be combined with aggregation or correlation in one rule")

    # Event schemas are the authoritative field inventory. The older broad
    # log-source grouping in DeploymentContext is intentionally smaller and
    # must not reject valid fields from newer collectors (Defender, tasks,
    # services, named pipes, and so on).
    all_fields: set[str] = {
        field for event_fields in EVENT_FIELD_TYPES.values() for field in event_fields
    }

    # ── Validate conditions ────────────────────────────────────────
    conditions_to_validate = [(ir.trigger_event, i, cond) for i, cond in enumerate(ir.conditions)]
    if ir.correlation:
        for stage_index, stage in enumerate(ir.correlation.stages):
            if stage.event not in EVENT_FIELD_TYPES:
                errors.append(f"Correlation stage [{stage_index}]: unknown event '{stage.event}'")
            conditions_to_validate.extend((stage.event, i, cond) for i, cond in enumerate(stage.conditions))
        if ir.trigger_event != ir.correlation.stages[0].event:
            errors.append("trigger_event must equal the first correlation stage event")
        for stage_index, stage in enumerate(ir.correlation.stages):
            parent_chain = ir.correlation.join_on == "parent_process" and stage.event == "process.start"
            if not parent_chain and ir.correlation.join_on not in EVENT_FIELD_TYPES.get(stage.event, {}):
                errors.append(
                    f"Correlation stage [{stage_index}]: join field '{ir.correlation.join_on}' "
                    f"is unavailable for event '{stage.event}'"
                )

    for event_name, i, cond in conditions_to_validate:
        if cond.field not in all_fields:
            valid_list = ", ".join(sorted(all_fields))
            errors.append(
                f"Condition [{i}]: field '{cond.field}' does not exist. "
                f"Valid fields are: {valid_list}"
            )
        if cond.operator not in context.supported_operators:
            valid_list = ", ".join(context.supported_operators)
            errors.append(
                f"Condition [{i}]: operator '{cond.operator}' is not supported. "
                f"Valid operators are: {valid_list}"
            )
        event_fields = EVENT_FIELD_TYPES.get(event_name, {})
        if event_fields and cond.field not in event_fields:
            errors.append(
                f"Condition [{i}]: field '{cond.field}' is not available for "
                f"event '{event_name}'"
            )
        field_type = event_fields.get(cond.field)
        if field_type and cond.operator not in OPERATORS_BY_FIELD_TYPE[field_type]:
            errors.append(
                f"Condition [{i}]: operator '{cond.operator}' is invalid for "
                f"{field_type} field '{cond.field}'"
            )
        if cond.operator == "regex":
            errors.extend(f"Condition [{i}]: {msg}" for msg in validate_regex_pattern(cond.value))
        if cond.operator == "is_public_ip" and cond.field not in {"dest_ip", "src_ip", "source_ip"}:
            errors.append(f"Condition [{i}]: is_public_ip requires an IP address field")

    # ── Validate response actions against shared ActionType enum ─────
    # This is the validator-level guarantee: no free-text action strings
    # ever reach the watcher. The UI enforcing checkboxes is nice-to-have;
    # this rejection is what actually makes it safe.
    action_type_strings = [a.type for a in ir.response_actions]
    if action_type_strings:
        action_errors = validate_actions(action_type_strings, strict=False)
        if action_errors:
            errors.extend(action_errors)

    # Also cross-check against deployment context's supported_actions list
    for i, action in enumerate(ir.response_actions):
        if action.type not in context.supported_actions:
            valid_list = ", ".join(context.supported_actions)
            errors.append(
                f"Response action [{i}]: type '{action.type}' is not in the "
                f"deployment context. Valid context actions are: {valid_list}"
            )
        if action.duration is not None:
            if not re.match(r"^\d+[smhd]$", action.duration):
                errors.append(
                    f"Response action [{i}]: duration '{action.duration}' is malformed. "
                    f"Expected format: number + unit (s/m/h/d), e.g. '3m', '1h'"
                )

    # ── Validate suggested_action values (best-effort, not hard error) ─
    if ir.suggested_action:
        valid_values = {e.value for e in ActionType}
        for sa in ir.suggested_action:
            if sa not in valid_values:
                errors.append(
                    f"suggested_action '{sa}' is not a known action type — "
                    f"expected one of: {sorted(valid_values)}"
                )

    # ── Validate aggregation keys ──────────────────────────────────
    if ir.aggregation is not None:
        for key_field in ir.aggregation.key:
            if key_field not in all_fields:
                valid_list = ", ".join(sorted(all_fields))
                errors.append(
                    f"Aggregation key '{key_field}' does not exist. "
                    f"Valid fields are: {valid_list}"
                )

    return ValidationResult(
        valid=len(errors) == 0,
        errors=errors,
        parsed=parsed,
    )
