"""
Injection screener (execute.txt §4).

Scans rule text for prompt-injection patterns BEFORE it reaches the LLM.

Contract (fixed per flaw #4):
  - HIGH-confidence match → safe=False → pipeline STOPS, LLM never called
  - LOW-confidence match  → safe=True, pass_with_warnings=True → pipeline
    continues with warning badges in the human review UI
  - No match              → safe=True, pass_with_warnings=False

The screener NEVER silently strips or modifies the input. The original
text is always returned unchanged as `flagged_input` (not `sanitizedInput`
— the old name was self-contradictory).

Implementation: plain `re` patterns. No heavy NLP library — this is a
lightweight pattern scan, not a classifier.
"""


import re
import base64

from pydantic import BaseModel


class ScreenResult(BaseModel):
    """Result of injection screening."""

    safe: bool                    # False = HIGH-confidence injection → BLOCK
    pass_with_warnings: bool      # True = LOW-confidence → proceed flagged
    flags: list[str]              # human-readable descriptions
    flagged_input: str            # original input, unchanged — name matches behavior


# ═══════════════════════════════════════════════════════════════════════
# HIGH-confidence patterns — these BLOCK the LLM call
# ═══════════════════════════════════════════════════════════════════════

_HIGH_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # ── Prompt override phrases ────────────────────────────────────
    (
        re.compile(
            r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+"
            r"(instructions?|prompts?|rules?|directions?)",
            re.I,
        ),
        "Prompt override: attempt to ignore previous instructions",
    ),
    (
        re.compile(
            r"disregard\s+(the\s+)?(system\s+)?"
            r"(prompt|instructions?|message|rules?)",
            re.I,
        ),
        "Prompt override: attempt to disregard system prompt",
    ),
    (
        re.compile(
            r"forget\s+(all\s+|everything\s+)?"
            r"(you\s+)?(know|were\s+told|learned)",
            re.I,
        ),
        "Prompt override: attempt to reset model context",
    ),
    (
        re.compile(r"new\s+instructions?\s*:", re.I),
        "Prompt override: attempt to inject new instructions",
    ),
    (
        re.compile(r"\bdo\s+not\s+follow\b", re.I),
        "Prompt override: direct instruction to not follow rules",
    ),
    (
        re.compile(r"override\s+(all\s+)?(system|safety|security)\s+", re.I),
        "Prompt override: attempt to override system constraints",
    ),
    # ── Role-play injection ────────────────────────────────────────
    (
        re.compile(r"you\s+are\s+now\s+", re.I),
        "Role-play injection: attempt to reassign model identity",
    ),
    (
        re.compile(r"act\s+as\s+(a|an|if)\s+", re.I),
        "Role-play injection: 'act as' attempt",
    ),
    (
        re.compile(r"pretend\s+(you\s+are|to\s+be)\s+", re.I),
        "Role-play injection: 'pretend to be' attempt",
    ),
    (
        re.compile(r"from\s+now\s+on\s+(you|your)\s+", re.I),
        "Role-play injection: 'from now on' identity shift",
    ),
    # ── System prompt references ───────────────────────────────────
    (
        re.compile(
            r"(system\s+prompt|system\s+message|hidden\s+prompt"
            r"|initial\s+instructions?)",
            re.I,
        ),
        "System prompt reference: attempt to access or reference system prompt",
    ),
    (
        re.compile(
            r"(reveal|show|print|output|display|repeat|echo)\s+"
            r"(your|the)\s+(system|initial|hidden|secret)\s+",
            re.I,
        ),
        "System prompt extraction: attempt to extract system prompt content",
    ),
]


# ═══════════════════════════════════════════════════════════════════════
# LOW-confidence patterns — these WARN but don't block
# ═══════════════════════════════════════════════════════════════════════

_LOW_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"(modify|delete|update|change|edit)\s+rule\s*(id|#|\d)", re.I
        ),
        "Cross-rule reference: attempt to modify another rule",
    ),
    (
        re.compile(r"rule\s*(id|#)\s*\d+", re.I),
        "Cross-rule reference: references a specific rule ID",
    ),
    (
        re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]"),
        "Control characters detected in input",
    ),
    (
        re.compile(r"[{}<>]{5,}"),
        "Excessive special characters — possible encoding or injection attempt",
    ),
    (
        re.compile(r"\\u[0-9a-fA-F]{4}", re.I),
        "Unicode escape sequences detected — possible obfuscation",
    ),
]


# ═══════════════════════════════════════════════════════════════════════
# Specialised detectors
# ═══════════════════════════════════════════════════════════════════════

_SUSPICIOUS_DECODED_KEYWORDS = frozenset(
    ["ignore", "system", "prompt", "instruction", "disregard", "override"]
)


def _check_base64(text: str) -> str | None:
    """Detect likely base64-encoded injection payloads (HIGH confidence)."""
    b64_pattern = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
    for match in b64_pattern.findall(text):
        try:
            decoded = base64.b64decode(match).decode("utf-8", errors="ignore")
            if any(kw in decoded.lower() for kw in _SUSPICIOUS_DECODED_KEYWORDS):
                return "Base64-encoded injection detected: decoded content contains suspicious phrases"
        except Exception:
            pass
    return None


def _check_hex(text: str) -> str | None:
    """Detect hex-encoded content (LOW confidence)."""
    hex_pattern = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
    if hex_pattern.search(text):
        return "Hex-encoded content detected — possible obfuscation attempt"
    return None


def _check_homoglyphs(text: str) -> str | None:
    """
    Detect Unicode homoglyphs commonly used to bypass keyword filters.
    E.g., Cyrillic 'а' (U+0430) looks identical to Latin 'a' but
    bypasses an ASCII regex for "ignore".
    """
    homoglyph_ranges = [
        (0x0400, 0x04FF),   # Cyrillic
        (0x2000, 0x206F),   # General Punctuation (zero-width chars etc.)
        (0xFF00, 0xFFEF),   # Fullwidth Latin / Halfwidth Katakana
    ]
    count = 0
    for ch in text:
        cp = ord(ch)
        for lo, hi in homoglyph_ranges:
            if lo <= cp <= hi:
                count += 1
                break
    if count > 2:
        return (
            f"Unicode homoglyphs detected ({count} characters) "
            "— possible keyword-filter bypass attempt"
        )
    return None


# ═══════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════


def screen(text: str) -> ScreenResult:
    """
    Screen rule text for injection patterns.

    Returns ScreenResult with:
      - safe=False if any HIGH-confidence pattern found → BLOCK
      - pass_with_warnings=True if only LOW-confidence patterns found → WARN
      - flagged_input always contains the original, unmodified text
    """
    flags: list[str] = []
    has_high = False
    has_low = False

    # ── HIGH-confidence pattern scan ───────────────────────────────
    for pattern, description in _HIGH_PATTERNS:
        if pattern.search(text):
            flags.append(f"[HIGH] {description}")
            has_high = True

    # Base64 check (HIGH)
    b64_flag = _check_base64(text)
    if b64_flag:
        flags.append(f"[HIGH] {b64_flag}")
        has_high = True

    # ── LOW-confidence pattern scan (always run for full reporting) ─
    for pattern, description in _LOW_PATTERNS:
        if pattern.search(text):
            flags.append(f"[LOW] {description}")
            has_low = True

    # Hex check (LOW)
    hex_flag = _check_hex(text)
    if hex_flag:
        flags.append(f"[LOW] {hex_flag}")
        has_low = True

    # Homoglyph check (LOW)
    homoglyph_flag = _check_homoglyphs(text)
    if homoglyph_flag:
        flags.append(f"[LOW] {homoglyph_flag}")
        has_low = True

    return ScreenResult(
        safe=not has_high,
        pass_with_warnings=(has_low and not has_high),
        flags=flags,
        flagged_input=text,  # never modified
    )
