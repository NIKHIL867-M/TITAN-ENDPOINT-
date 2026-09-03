"""
shared/action_types.py — THE single definition of valid response actions.

Both app/ (validates rules at approval time) and watcher/ (executes actions
at match time) import ActionType from here — neither one hardcodes action
strings anywhere else in the codebase.

Design principle: if you ever add a fourth action (e.g. block_network), it's
one addition here and both sides pick it up automatically.
"""


from enum import Enum


class ActionType(str, Enum):
    """Enumeration of all supported response actions.

    Using str as the base class means enum values serialize naturally
    to JSON as strings ("alert", "kill_process", "isolate_host") —
    no custom serializer needed.
    """
    ALERT = "alert"
    KILL_PROCESS = "kill_process"
    ISOLATE_HOST = "isolate_host"


# Human-facing labels kept next to the enum so UI and validator never disagree.
ACTION_LABELS: dict[ActionType, str] = {
    ActionType.ALERT: "Send an alert",
    ActionType.KILL_PROCESS: "Kill the process",
    ActionType.ISOLATE_HOST: "Isolate the host",
}

# Additional human-readable descriptions for the review UI.
ACTION_DESCRIPTIONS: dict[ActionType, str] = {
    ActionType.ALERT: "Always recommended — low risk, non-destructive",
    ActionType.KILL_PROCESS: "Immediate and irreversible — terminates the matched process",
    ActionType.ISOLATE_HOST: "Blocks all outbound network — auto-lifts after configured duration",
}

# Severity → suggested default actions. Used ONLY as a starting suggestion
# pre-filled in the review UI — the human always makes the final choice.
SEVERITY_SUGGESTED_ACTION: dict[str, list[ActionType]] = {
    "low":      [ActionType.ALERT],
    "medium":   [ActionType.ALERT],
    "high":     [ActionType.ALERT, ActionType.ISOLATE_HOST],
    "critical": [ActionType.ALERT, ActionType.KILL_PROCESS],
}

# Fixed execution order for multi-action rules (non-destructive → reversible → irreversible).
# Alert first: never delayed by anything. Isolate before Kill: containment before termination.
EXECUTION_ORDER: list[ActionType] = [
    ActionType.ALERT,
    ActionType.ISOLATE_HOST,
    ActionType.KILL_PROCESS,
]

# Actions that require dry-run guardrail (destructive operations).
DESTRUCTIVE_ACTIONS: set[ActionType] = {
    ActionType.KILL_PROCESS,
    ActionType.ISOLATE_HOST,
}


def validate_actions(actions: list[str], *, strict: bool = True) -> list[str]:
    """
    Validate a list of action type strings against the ActionType enum.

    Returns a list of error strings (empty if all valid).

    Parameters:
        strict: When True (default), requires at least one action — used at
                approval time where the human must have selected something.
                When False, an empty list is allowed — used at parse-time
                where the LLM hasn't produced actions yet.

    Two call sites, one function, one named parameter — never two copies
    of the same logic that can drift apart.
    """
    errors: list[str] = []
    valid_values = {e.value for e in ActionType}

    if strict and not actions:
        errors.append(
            "At least one response action is required "
            "(Alert is always a safe default — add 'alert' to response_actions)"
        )
        return errors

    for action_str in actions:
        if action_str not in valid_values:
            errors.append(
                f"'{action_str}' is not a supported action — "
                f"must be one of: {sorted(valid_values)}"
            )

    return errors
