"""
Rule store — JSON Lines (JSONL) based persistence.

Deliberate upgrade over a single JSON array file:
  - append_rule() is O(1): open("a"), write one line, done.
    No read → deserialize → append → reserialize → rewrite cycle.
  - list_rules() paginates with itertools.islice — only materialises
    `limit` rules in memory, never the whole file.
  - get_rule_by_id() is a linear scan — fine at the expected scale
    (dozens to low hundreds of rules).

Files:
  - data/rules.jsonl     — approved rules
  - data/rejections.jsonl — rejected rules with reasons

data/ is created on first write, gitignored.
"""


import json
import os
import itertools
from collections import deque
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from shared.integrity import sign_record, verify_record


_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_RULES_FILE = _DATA_DIR / "rules.jsonl"
_REJECTIONS_FILE = _DATA_DIR / "rejections.jsonl"

# Thread-safe append lock — prevents two simultaneous /api/rules/approve
# calls from interleaving partial lines in the JSONL file.
# (execute.txt flaw fix #4 — watcher is reader-only but the API is not)
_RULES_LOCK = threading.Lock()
_REJECTIONS_LOCK = threading.Lock()


def _ensure_data_dir() -> None:
    """Create data/ if it doesn't exist."""
    _DATA_DIR.mkdir(parents=True, exist_ok=True)


# ═══════════════════════════════════════════════════════════════════════
# Record factories
# ═══════════════════════════════════════════════════════════════════════


def create_rule_record(
    ir_dict: dict,
    rule_text: str,
    injection_flags: list[str] | None = None,
    capability_gaps: list[str] | None = None,
    original_ir: dict | None = None,
    edit_mode: str | None = None,
    retrieval_trace: dict | None = None,
) -> dict:
    """Create a full rule record with metadata, ready for storage."""
    original = original_ir if original_ir is not None else ir_dict
    edited = original != ir_dict
    return {
        "id": str(uuid.uuid4()),
        "status": "approved",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "rule_text": rule_text,
        "ir": ir_dict,
        "original_ir": original,
        "final_ir": ir_dict,
        "edited": edited,
        "edit_mode": edit_mode if edited else None,
        "approved_at": datetime.now(timezone.utc).isoformat(),
        "injection_flags": injection_flags or [],
        "capability_gaps": capability_gaps or [],
        "retrieval_trace": retrieval_trace or None,
    }


def create_rejection_record(
    ir_dict: dict | None,
    rule_text: str,
    reason: str,
    injection_flags: list[str] | None = None,
) -> dict:
    """Create a rejection record with metadata."""
    return {
        "id": str(uuid.uuid4()),
        "status": "rejected",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "rule_text": rule_text,
        "ir": ir_dict,
        "reason": reason,
        "injection_flags": injection_flags or [],
    }


# ═══════════════════════════════════════════════════════════════════════
# Storage operations
# ═══════════════════════════════════════════════════════════════════════


def append_rule(rule: dict) -> None:
    """
    Append an approved rule to rules.jsonl.
    True O(1) append: one open("a"), one write, fsync, done — no
    read-modify-rewrite of the whole file (that defeated the point of
    JSONL and doesn't scale past a few thousand rules).
    Thread-safe: locked so concurrent approve requests can't interleave.
    """
    _ensure_data_dir()
    with _RULES_LOCK:
        rule = sign_record(rule, _RULES_FILE.parent, "approved_rule")
        try:
            with open(_RULES_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(rule, ensure_ascii=False) + "\n")
                f.flush()
                os.fsync(f.fileno())
        except Exception as exc:
            raise RuntimeError(f"Failed to append to rules.jsonl: {exc}") from exc


def append_rejection(rejection: dict) -> None:
    """
    Append a rejection record atomically.
    Reads current file, appends record, writes to tmp, then replaces target.
    Thread-safe: locked so concurrent reject requests can't interleave.
    """
    _ensure_data_dir()
    with _REJECTIONS_LOCK:
        lines = []
        if _REJECTIONS_FILE.exists():
            try:
                with open(_REJECTIONS_FILE, "r", encoding="utf-8") as f:
                    lines = f.readlines()
            except Exception:
                pass

        lines.append(json.dumps(rejection, ensure_ascii=False) + "\n")

        tmp_file = _REJECTIONS_FILE.with_suffix(".jsonl.tmp")
        try:
            with open(tmp_file, "w", encoding="utf-8") as f:
                f.writelines(lines)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_file, _REJECTIONS_FILE)
        except Exception as exc:
            raise RuntimeError(f"Failed atomic write to rejections.jsonl: {exc}") from exc


def migrate_rule_integrity() -> int:
    """Sign legacy approved rules without blessing invalid signed records."""
    if not _RULES_FILE.exists():
        return 0
    migrated = 0
    with _RULES_LOCK:
        output: list[str] = []
        with _RULES_FILE.open("r", encoding="utf-8") as source:
            for line in source:
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    output.append(line)
                    continue
                if verify_record(record, _RULES_FILE.parent, "approved_rule") == "legacy_unsigned":
                    record = sign_record(record, _RULES_FILE.parent, "approved_rule")
                    migrated += 1
                output.append(json.dumps(record, ensure_ascii=False) + "\n")
        if migrated:
            _replace_rules(output)
    return migrated


def list_rules(page: int = 0, limit: int = 20) -> list[dict]:
    """
    Paginated rule listing.

    Only materialises `limit` rules in memory via itertools.islice,
    never the entire file.
    """
    if not _RULES_FILE.exists():
        return []

    start = page * limit
    rules: list[dict] = []
    with open(_RULES_FILE, encoding="utf-8") as f:
        for line in itertools.islice(f, start, start + limit):
            line = line.strip()
            if line:
                try:
                    rules.append(json.loads(line))
                except json.JSONDecodeError:
                    continue  # skip corrupted lines
    return rules


def list_recent_rules(limit: int = 100) -> list[dict]:
    """Return the newest valid rules first without retaining unbounded data."""
    if not _RULES_FILE.exists() or limit <= 0:
        return []
    recent: deque[dict] = deque(maxlen=limit)
    with open(_RULES_FILE, encoding="utf-8") as source:
        for line in source:
            try:
                if line.strip(): recent.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return list(reversed(recent))


def find_semantic_duplicate(ir_dict: dict) -> dict | None:
    """Find an approved record with the same executable inner IR."""
    target = ir_dict.get("ir") if isinstance(ir_dict, dict) else None
    if not isinstance(target, dict) or not _RULES_FILE.exists():
        return None
    target_json = json.dumps(target, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    with open(_RULES_FILE, encoding="utf-8") as source:
        for line in source:
            try:
                record = json.loads(line)
                inner = record.get("ir", {}).get("ir")
                if isinstance(inner, dict) and json.dumps(inner, sort_keys=True, separators=(",", ":"), ensure_ascii=False) == target_json:
                    return record
            except (json.JSONDecodeError, AttributeError):
                continue
    return None


def count_rules() -> int:
    """Count total rules without loading them into memory."""
    if not _RULES_FILE.exists():
        return 0
    count = 0
    with open(_RULES_FILE, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                count += 1
    return count


def get_rule_by_id(rule_id: str) -> dict | None:
    """
    Find a rule by ID. Linear scan — fine at the expected scale
    (dozens to low hundreds of rules). Easy to add an index file later
    if it ever becomes a bottleneck.
    """
    if not _RULES_FILE.exists():
        return None

    with open(_RULES_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rule = json.loads(line)
                if rule.get("id") == rule_id:
                    return rule
            except json.JSONDecodeError:
                continue
    return None


def delete_rule(rule_id: str) -> bool:
    """Atomically delete one approved rule by ID.

    Returns ``True`` only when a matching record was removed. Malformed lines
    are preserved so a UI operation never silently discards recoverable data.
    """
    if not rule_id or not _RULES_FILE.exists():
        return False

    _ensure_data_dir()
    with _RULES_LOCK:
        kept: list[str] = []
        deleted = False
        with open(_RULES_FILE, "r", encoding="utf-8") as source:
            for line in source:
                try:
                    record = json.loads(line) if line.strip() else None
                except json.JSONDecodeError:
                    record = None
                if isinstance(record, dict) and record.get("id") == rule_id:
                    deleted = True
                    continue
                kept.append(line)

        if not deleted:
            return False
        _replace_rules(kept)
        return True


def delete_all_rules() -> int:
    """Atomically remove every approved rule and return the previous count."""
    _ensure_data_dir()
    with _RULES_LOCK:
        previous = count_rules()
        _replace_rules([])
        return previous


def delete_semantic_duplicates() -> dict:
    """Atomically remove duplicate executable IR records, preserving the oldest.

    Preserving the earliest record also preserves the rule IDs referenced by
    existing evidence and alert history.
    """
    if not _RULES_FILE.exists():
        return {"deleted": 0, "deleted_ids": [], "kept": 0}
    with _RULES_LOCK:
        seen: set[str] = set()
        kept_lines: list[str] = []
        deleted_ids: list[str] = []
        kept_count = 0
        with open(_RULES_FILE, "r", encoding="utf-8") as source:
            for line in source:
                try:
                    record = json.loads(line) if line.strip() else None
                    inner = record.get("ir", {}).get("ir") if isinstance(record, dict) else None
                except (json.JSONDecodeError, AttributeError):
                    record, inner = None, None
                if isinstance(inner, dict):
                    semantic = json.dumps(inner, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                    if semantic in seen:
                        deleted_ids.append(str(record.get("id", "")))
                        continue
                    seen.add(semantic)
                    kept_count += 1
                kept_lines.append(line)
        if deleted_ids:
            _replace_rules(kept_lines)
        return {"deleted": len(deleted_ids), "deleted_ids": deleted_ids, "kept": kept_count}


def _replace_rules(lines: list[str]) -> None:
    """Replace the rules file while the caller holds ``_RULES_LOCK``."""
    tmp_file = _RULES_FILE.with_suffix(".jsonl.tmp")
    try:
        with open(tmp_file, "w", encoding="utf-8") as target:
            target.writelines(lines)
            target.flush()
            os.fsync(target.fileno())
        os.replace(tmp_file, _RULES_FILE)
    except Exception as exc:
        raise RuntimeError(f"Failed atomic rewrite of rules.jsonl: {exc}") from exc


def list_rejections(page: int = 0, limit: int = 20) -> list[dict]:
    """Paginated rejection listing."""
    if not _REJECTIONS_FILE.exists():
        return []

    start = page * limit
    rejections: list[dict] = []
    with open(_REJECTIONS_FILE, encoding="utf-8") as f:
        for line in itertools.islice(f, start, start + limit):
            line = line.strip()
            if line:
                try:
                    rejections.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return rejections
