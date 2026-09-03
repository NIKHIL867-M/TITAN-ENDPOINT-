"""
JSON extractor — robust extraction of JSON from raw LLM output.

Three-step fallback:
  1. json.loads(raw) directly
  2. Strip markdown fences (```json ... ```) and retry
  3. Bracket-depth scan: find first '{' to its matching '}' and parse

Returns the parsed dict or None if all steps fail.

If Groq's structured-output mode is available for the chosen model
(response_format={"type": "json_object"}), that should be preferred
at the call site so this module acts as a fallback, not the primary path.
"""


import json
import re


def extract_json(raw: str) -> dict | None:
    """
    Attempt to extract a valid JSON object from raw LLM output.
    Returns the parsed dict, or None if extraction fails at all steps.
    """
    if not raw or not raw.strip():
        return None

    text = raw.strip()

    # Step 1: Direct parse
    result = _try_parse(text)
    if result is not None:
        return result

    # Step 2: Strip markdown fences
    stripped = _strip_fences(text)
    if stripped != text:
        result = _try_parse(stripped.strip())
        if result is not None:
            return result

    # Step 3: Bracket-depth scan
    extracted = _bracket_extract(text)
    if extracted is not None:
        result = _try_parse(extracted)
        if result is not None:
            return result

    return None


def _try_parse(text: str) -> dict | None:
    """Try to parse text as JSON. Returns dict or None."""
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except (json.JSONDecodeError, ValueError):
        pass
    return None


# Matches ```json ... ``` or ``` ... ``` (with optional language tag)
_FENCE_RE = re.compile(r"```(?:json)?\s*\n?(.*?)\n?\s*```", re.DOTALL)


def _strip_fences(text: str) -> str:
    """Remove markdown code fences wrapping JSON."""
    match = _FENCE_RE.search(text)
    if match:
        return match.group(1)
    return text


def _bracket_extract(text: str) -> str | None:
    """
    Find the first '{' and scan to its matching '}' using a depth counter.
    Handles cases where the model added prose before/after the JSON.

    Correctly skips braces inside JSON string literals (accounting for
    escaped quotes).
    """
    start = text.find("{")
    if start == -1:
        return None

    depth = 0
    in_string = False
    escape_next = False

    for i in range(start, len(text)):
        ch = text[i]

        if escape_next:
            escape_next = False
            continue

        if ch == "\\" and in_string:
            escape_next = True
            continue

        if ch == '"' and not escape_next:
            in_string = not in_string
            continue

        if in_string:
            continue

        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]

    return None
