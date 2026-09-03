"""Shared, reloadable Windows execution-alias and launcher-shim configuration."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

_CONFIG_FILE = Path(__file__).resolve().parents[1] / "data" / "uwp_aliases.json"
_DEFAULT_ALIASES = {
    "calc.exe": "CalculatorApp.exe",
    "calculator.exe": "CalculatorApp.exe",
    "paint.exe": "mspaint.exe",
    "mspaint.exe": "mspaint.exe",
}
_cache: tuple[int, dict[str, Any]] | None = None


def load_windows_alias_config() -> dict[str, Any]:
    """Load configuration and remain compatible with the old flat mapping."""
    global _cache
    try:
        mtime = _CONFIG_FILE.stat().st_mtime_ns
        if _cache and _cache[0] == mtime:
            return _cache[1]
        raw = json.loads(_CONFIG_FILE.read_text(encoding="utf-8"))
        if "aliases" not in raw:  # legacy {alias: executable} shape
            raw = {"aliases": raw, "launcher_shims": []}
        config = {
            "aliases": {str(k).lower(): str(v) for k, v in raw.get("aliases", {}).items()},
            "launcher_shims": list(raw.get("launcher_shims", [])),
        }
        _cache = (mtime, config)
        return config
    except (OSError, ValueError, TypeError, AttributeError):
        return {"aliases": _DEFAULT_ALIASES, "launcher_shims": []}


def executable_aliases() -> dict[str, str]:
    return load_windows_alias_config()["aliases"]


def canonical_executable(name: str) -> str:
    """Return the persistent executable name used by runtime telemetry."""
    lowered = str(name).strip().lower()
    return executable_aliases().get(lowered, lowered).lower()


def identify_launcher_shim(name: str, command_line: str, windows_build: int | None = None) -> dict[str, Any] | None:
    """Return shim metadata when a process matches a configured launcher shim."""
    if windows_build is None:
        try:
            windows_build = sys.getwindowsversion().build
        except AttributeError:
            windows_build = 0
    executable = command_line.strip().lower().lstrip('"')
    for shim in load_windows_alias_config()["launcher_shims"]:
        try:
            if int(windows_build) < int(shim.get("min_windows_build", 0)):
                continue
            if name.lower() != str(shim.get("name", "")).lower():
                continue
            if not executable.startswith(str(shim.get("path_prefix", "")).lower()):
                continue
            return {"target": str(shim.get("target", name)), "kind": str(shim.get("kind", "launcher"))}
        except (TypeError, ValueError):
            continue
    return None
