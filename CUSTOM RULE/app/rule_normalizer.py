"""Deterministic Windows-specific IR corrections applied before validation."""
from __future__ import annotations
from copy import deepcopy
from shared.windows_aliases import executable_aliases

def normalize_rule_ir(ir: dict) -> tuple[dict, list[str]]:
    normalized, notes = deepcopy(ir), []
    condition_groups = [normalized.get("conditions", [])]
    correlation = normalized.get("correlation")
    if correlation:
        join_on = str(correlation.get("join_on", "")).strip().lower()
        # A model may use "none" for two independent events that merely need
        # to coexist in one time window. Represent that deterministically as
        # an unordered, same-host correlation supported by the runtime.
        if join_on in {"none", "no_join", "global", "same_host"}:
            correlation["join_on"] = "host"
            correlation["ordered"] = False
            notes.append("Normalized independent-event correlation to unordered same-host co-occurrence")
        else:
            correlation.setdefault("ordered", True)
        condition_groups.extend(stage.get("conditions", []) for stage in correlation.get("stages", []))
    for conditions in condition_groups:
        for condition in conditions:
            if condition.get("field") not in ("name", "process.name") or condition.get("operator") != "==":
                continue
            value = str(condition.get("value", "")).lower()
            actual = executable_aliases().get(value)
            if actual:
                condition["value"] = actual
                notes.append(f"Normalized Windows execution alias '{value}' to persistent process '{actual}'")
    return normalized, notes
