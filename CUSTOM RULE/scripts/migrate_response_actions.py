"""
scripts/migrate_response_actions.py

One-time migration: scan data/rules.jsonl and map old response_action type
strings to the canonical ActionType enum values.

Run with:
    python scripts/migrate_response_actions.py [--dry-run]

Flags anything that can't be mapped cleanly — those rules are preserved
but flagged with a 'migration_warning' field so you know to review them.

Maps:
    "block_auth"      → "alert"  (old action, closest safe equivalent)
    "alert"           → "alert"  (unchanged)
    "kill_process"    → "kill_process" (unchanged)
    "isolate_host"    → "isolate_host" (unchanged)
    anything else     → flagged, defaults to "alert"
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow running from project root
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from shared.action_types import ActionType

_RULES_FILE = _PROJECT_ROOT / "data" / "rules.jsonl"
_BACKUP_FILE = _PROJECT_ROOT / "data" / "rules.jsonl.pre_migration_backup"

# Old → new action type mapping
_ACTION_MAP: dict[str, str] = {
    "alert": ActionType.ALERT.value,
    "kill_process": ActionType.KILL_PROCESS.value,
    "isolate_host": ActionType.ISOLATE_HOST.value,
    # Legacy action types from before the enum was enforced
    "block_auth": ActionType.ALERT.value,  # old brute-force action → safe equivalent
    "block": ActionType.ISOLATE_HOST.value,
    "kill": ActionType.KILL_PROCESS.value,
    "quarantine": ActionType.ISOLATE_HOST.value,
    "terminate": ActionType.KILL_PROCESS.value,
}

_VALID_VALUES = {e.value for e in ActionType}


def migrate(dry_run: bool = True) -> None:
    if not _RULES_FILE.exists():
        print(f"No rules file found at {_RULES_FILE} — nothing to migrate.")
        return

    lines = _RULES_FILE.read_text(encoding="utf-8").splitlines()
    total = 0
    changed = 0
    flagged = 0
    migrated_lines: list[str] = []

    for i, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            migrated_lines.append("")
            continue

        try:
            rule = json.loads(line)
        except json.JSONDecodeError as exc:
            print(f"  [WARN] Line {i}: JSON decode error — skipping: {exc}")
            migrated_lines.append(line)
            continue

        total += 1
        ir_wrap = rule.get("ir", {})
        ir = ir_wrap.get("ir", {}) if isinstance(ir_wrap, dict) else {}
        response_actions = ir.get("response_actions", [])

        if not isinstance(response_actions, list):
            migrated_lines.append(line)
            continue

        new_actions = []
        rule_changed = False
        rule_flagged = False
        warnings: list[str] = []

        for action_spec in response_actions:
            if not isinstance(action_spec, dict):
                # Old format might be just a string
                action_type = str(action_spec)
            else:
                action_type = action_spec.get("type", "")

            if action_type in _VALID_VALUES:
                # Already valid — keep as-is
                new_actions.append({"type": action_type, "duration": action_spec.get("duration") if isinstance(action_spec, dict) else None})
            elif action_type in _ACTION_MAP:
                mapped = _ACTION_MAP[action_type]
                new_actions.append({"type": mapped, "duration": action_spec.get("duration") if isinstance(action_spec, dict) else None})
                warnings.append(f"'{action_type}' → '{mapped}'")
                rule_changed = True
            else:
                # Unknown — default to alert, flag for review
                new_actions.append({"type": ActionType.ALERT.value, "duration": None})
                warnings.append(f"'{action_type}' is UNKNOWN → defaulted to 'alert' — REVIEW REQUIRED")
                rule_changed = True
                rule_flagged = True

        if not new_actions:
            # No actions at all — add alert as default
            new_actions = [{"type": ActionType.ALERT.value, "duration": None}]
            warnings.append("response_actions was empty → defaulted to ['alert']")
            rule_changed = True

        if rule_changed:
            changed += 1
            ir["response_actions"] = new_actions
            ir_wrap["ir"] = ir
            rule["ir"] = ir_wrap
            if warnings:
                rule.setdefault("migration_warnings", []).extend(warnings)
            print(f"  [{'FLAG' if rule_flagged else 'FIX '}] Rule {rule.get('id', '?')[:8]}: {'; '.join(warnings)}")

        if rule_flagged:
            flagged += 1

        migrated_lines.append(json.dumps(rule, ensure_ascii=False))

    print(f"\nSummary: {total} rules | {changed} changed | {flagged} flagged for review")

    if dry_run:
        print("\n[DRY-RUN] No changes written. Re-run without --dry-run to apply.")
        return

    # Backup first
    if not dry_run:
        _BACKUP_FILE.write_text("\n".join(lines), encoding="utf-8")
        print(f"Backup written to: {_BACKUP_FILE}")

    _RULES_FILE.write_text("\n".join(migrated_lines) + "\n", encoding="utf-8")
    print(f"Migration complete. Rules written to: {_RULES_FILE}")
    if flagged:
        print(f"\n⚠  {flagged} rule(s) were flagged — search for 'migration_warnings' in rules.jsonl and review.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Migrate response_actions in rules.jsonl to the canonical ActionType enum."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Show what would change without writing (default: True)",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually write the changes (disables --dry-run)",
    )
    args = parser.parse_args()

    dry_run = not args.apply
    print(f"Migration {'[DRY-RUN]' if dry_run else '[APPLYING]'}\n")
    migrate(dry_run=dry_run)
