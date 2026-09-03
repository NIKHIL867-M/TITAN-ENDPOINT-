"""
YAML rule authoring — `app/yaml_rules.py`

Fallback rule-authoring path for when the Groq API limit/quota is hit (or
for offline/scripted authoring): write the rule IR directly in YAML,
bypassing the LLM entirely. Runs through the EXACT SAME structural +
contextual + capability + simulation pipeline as an LLM-produced draft
(app.main._parse_draft) — this module only turns YAML text into the same
plain `dict` shape `_parse_draft` already accepts from
`POST /api/rules/draft-check`. No separate, potentially-drifting
validation path; no new persistence path either (the caller still uses the
existing `POST /api/rules/approve`, same as a reviewed LLM draft).

Not screened by injection_screener.screen() — that module exists
specifically to catch prompt-injection attempts against the LLM prompt this
rule text would otherwise be embedded into. A YAML rule never reaches an
LLM, so there is no prompt to inject into; the existing structural +
contextual + capability validation is what actually gates what a YAML rule
can do, exactly as it gates an LLM draft.

Example (mirrors the flat IR shape used everywhere else in this codebase):

    trigger_event: process.start
    conditions:
      - field: name
        operator: "=="
        value: calc.exe
    response_actions:
      - type: alert
    severity: low
    priority: 5
    tags: [example]

Required fields: trigger_event, severity, priority (this module intentionally
does NOT default severity — silently defaulting a safety-relevant field
could mask what a rule actually does). Aggregation, correlation, sustain_for,
suggested_action, and suggested_action_reason may be omitted (RuleIR's own
Pydantic defaults apply, same as an LLM draft that leaves them out).
conditions, investigation_steps, response_actions, and tags default to an
empty list here if omitted, so a minimal rule doesn't need to know every
field RuleIR technically requires — the SAME structural validation
(app.semantic_validator.validate_structure) still runs afterward and will
reject an empty response_actions/conditions combination that doesn't make
sense, exactly as it would for an LLM draft.
"""
from __future__ import annotations

import yaml

# Bounded input, matching MAX_RULE_LENGTH's spirit (a hand-written IR is
# more verbose per-byte than a one-line English sentence, so a somewhat
# higher ceiling than MAX_RULE_LENGTH is reasonable) and body_size_gate's
# 64KB hard ceiling upstream in main.py.
MAX_YAML_BYTES = 8_000

# RuleIR fields (app/semantic_validator.py) with no Pydantic default -- must
# either be present in the YAML or filled in here with an empty-list default
# so a minimal rule doesn't fail on fields it never needed to think about.
_LIST_FIELDS_DEFAULTING_EMPTY = ("conditions", "investigation_steps", "response_actions", "tags")

# RuleIR fields with no Pydantic default and no safe default here -- a
# missing one is a clear, actionable error rather than a silent guess.
_REQUIRED_FIELDS = ("trigger_event", "severity", "priority")


def parse_yaml_rule(yaml_text: str) -> tuple[dict | None, list[str]]:
    """
    Parse YAML rule text into the plain-dict IR shape _parse_draft expects.

    Returns (draft_dict, []) on success, or (None, [error, ...]) with
    human-readable errors (YAML syntax errors, wrong top-level shape,
    missing required fields) that the caller can surface directly — the
    SAME error-list contract _parse_draft's own callers already use.
    """
    if len(yaml_text.encode("utf-8")) > MAX_YAML_BYTES:
        return None, [f"YAML input too large (max {MAX_YAML_BYTES} bytes)"]

    try:
        loaded = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        return None, [f"YAML syntax error: {exc}"]

    if loaded is None:
        return None, ["YAML input is empty"]
    if not isinstance(loaded, dict):
        return None, [
            "YAML must describe a single rule as a mapping (key: value pairs) "
            "at the top level, not a list or a scalar"
        ]

    missing = [field for field in _REQUIRED_FIELDS if field not in loaded]
    if missing:
        return None, [f"Missing required field '{field}'" for field in missing]

    for field in _LIST_FIELDS_DEFAULTING_EMPTY:
        loaded.setdefault(field, [])

    return loaded, []
