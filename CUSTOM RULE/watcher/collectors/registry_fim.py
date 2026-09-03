"""Selected-path Windows Registry integrity monitoring with persistent baseline."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .base import Collector

logger = logging.getLogger(__name__)
try:
    import winreg
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False

_ROOT = Path(__file__).resolve().parents[2]
_HIVES = {"HKCU": getattr(winreg, "HKEY_CURRENT_USER", None), "HKLM": getattr(winreg, "HKEY_LOCAL_MACHINE", None)} if _AVAILABLE else {}
_DEFAULT_PATHS = (
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run;"
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
)


class RegistryIntegrityCollector(Collector):
    name = "registry_fim"
    produces = ["registry.change"]
    collection_mode = "periodic"

    def __init__(self) -> None:
        self._stop_event = threading.Event()
        self.interval = max(2, int(os.environ.get("WATCHER_REGISTRY_INTERVAL_S", "10")))
        self.poll_interval_s = self.interval
        self.paths = [value.strip() for value in os.environ.get("WATCHER_REGISTRY_PATHS", _DEFAULT_PATHS).split(";") if value.strip()]
        data = Path(os.environ.get("WATCHER_DATA_DIR", "data"))
        if not data.is_absolute(): data = _ROOT / data
        self.baseline_file = data / "baselines" / "registry.json"

    def check_prerequisites(self) -> list[str]:
        if not _AVAILABLE: return ["winreg is unavailable; registry integrity requires Windows"]
        return [] if self.paths else ["WATCHER_REGISTRY_PATHS contains no paths"]

    def start(self, emit: Callable[[dict], None]) -> None:
        previous = self._load() or self._snapshot()
        if not self.baseline_file.exists(): self._save(previous)
        while not self._stop_event.wait(self.interval):
            current = self._snapshot()
            for identity in sorted(set(previous) | set(current)):
                old, new = previous.get(identity), current.get(identity)
                if old == new: continue
                change_type = "added" if old is None else "deleted" if new is None else "modified"
                path, value_name = identity.split("|", 1)
                emit({"path": path, "value_name": value_name, "change_type": change_type,
                      "old_hash": old, "new_hash": new})
            self._save(current); previous = current

    def stop(self) -> None:
        self._stop_event.set()

    def decode(self, raw_event: dict) -> dict[str, Any] | None:
        return {"event_type": "registry.change", "timestamp": datetime.now(timezone.utc).isoformat(),
                "host": os.environ.get("COMPUTERNAME", "localhost"), "user": os.environ.get("USERNAME"),
                "process": None, "network": None, "registry": dict(raw_event),
                "source_collector": self.name, "raw": dict(raw_event)}

    def _snapshot(self) -> dict[str, str]:
        snapshot: dict[str, str] = {}
        for configured in self.paths:
            hive_name, _, subkey = configured.partition("\\")
            hive = _HIVES.get(hive_name.upper())
            if hive is None or not subkey: continue
            try:
                with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                    index = 0
                    path_count = 0
                    while path_count < 5000:
                        try: name, value, value_type = winreg.EnumValue(key, index)
                        except OSError: break
                        payload = json.dumps([value_type, value], default=str, ensure_ascii=False).encode("utf-8")
                        snapshot[f"{hive_name.upper()}\\{subkey}|{name or '(Default)'}"] = hashlib.sha256(payload).hexdigest()
                        index += 1; path_count += 1
                    if path_count >= 5000:
                        logger.warning("Registry monitoring cap reached for %s: only the first 5,000 values are watched", configured)
            except (PermissionError, FileNotFoundError, OSError) as exc:
                logger.debug("Registry path unavailable %s: %s", configured, exc)
        return snapshot

    def _load(self) -> dict[str, str]:
        try: return json.loads(self.baseline_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError): return {}

    def _save(self, value: dict[str, str]) -> None:
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.baseline_file.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(value, indent=2), encoding="utf-8"); os.replace(tmp, self.baseline_file)
