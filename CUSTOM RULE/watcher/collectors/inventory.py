"""Low-frequency network and installed-software inventory change collector."""
from __future__ import annotations
import hashlib, json, logging, os, threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from .base import Collector

logger = logging.getLogger(__name__)
try:
    import psutil, winreg
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False
_ROOT = Path(__file__).resolve().parents[2]

class InventoryCollector(Collector):
    name = "inventory"
    produces = ["inventory.change"]
    collection_mode = "periodic"

    def __init__(self) -> None:
        self._stop_event = threading.Event()
        self.interval = max(30, int(os.environ.get("WATCHER_INVENTORY_INTERVAL_S", "300")))
        self.poll_interval_s = self.interval
        data = Path(os.environ.get("WATCHER_DATA_DIR", "data"))
        if not data.is_absolute(): data = _ROOT / data
        self.baseline_file = data / "baselines" / "inventory.json"

    def check_prerequisites(self) -> list[str]:
        return [] if _AVAILABLE else ["inventory collector requires Windows winreg and psutil"]

    def start(self, emit: Callable[[dict], None]) -> None:
        previous = self._load() or self._snapshot()
        if not self.baseline_file.exists(): self._save(previous)
        while not self._stop_event.wait(self.interval):
            current = self._snapshot()
            for identity in sorted(set(previous) | set(current)):
                old, new = previous.get(identity), current.get(identity)
                if old == new: continue
                category, item = identity.split("|", 1)
                change_type = "added" if old is None else "deleted" if new is None else "modified"
                emit({"category": category, "item": item, "change_type": change_type, "old_hash": old, "new_hash": new})
            self._save(current); previous = current

    def stop(self) -> None: self._stop_event.set()

    def decode(self, raw_event: dict) -> dict[str, Any] | None:
        return {"event_type":"inventory.change", "timestamp":datetime.now(timezone.utc).isoformat(),
                "host":os.environ.get("COMPUTERNAME","localhost"), "user":None, "process":None,
                "network":None, "inventory":dict(raw_event), "source_collector":self.name, "raw":dict(raw_event)}

    def _snapshot(self) -> dict[str, str]:
        items: dict[str, Any] = {}
        stats = psutil.net_if_stats(); addresses = psutil.net_if_addrs()
        for name in sorted(set(stats) | set(addresses)):
            items[f"network|{name}"] = {"up": getattr(stats.get(name), "isup", None),
                "mtu": getattr(stats.get(name), "mtu", None),
                "addresses": sorted(f"{a.family}:{a.address}:{a.netmask or ''}" for a in addresses.get(name, []))}
        uninstall_paths = (
            ("native", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            ("wow32", r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        )
        for hive_name, hive in (("HKLM", winreg.HKEY_LOCAL_MACHINE), ("HKCU", winreg.HKEY_CURRENT_USER)):
          for view_name, uninstall in uninstall_paths:
            try:
                with winreg.OpenKey(hive, uninstall) as root:
                    for index in range(min(winreg.QueryInfoKey(root)[0], 5000)):
                        try:
                            subname = winreg.EnumKey(root, index)
                            with winreg.OpenKey(root, subname) as sub:
                                name = _reg_value(sub, "DisplayName")
                                if name: items[f"software|{hive_name}:{view_name}:{subname}"] = {"name":name, "version":_reg_value(sub,"DisplayVersion"), "publisher":_reg_value(sub,"Publisher")}
                        except OSError: continue
            except OSError: pass
        return {key: hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest() for key, value in items.items()}

    def _load(self) -> dict[str, str]:
        try: return json.loads(self.baseline_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError): return {}
    def _save(self, value: dict[str, str]) -> None:
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True); tmp=self.baseline_file.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(value, indent=2), encoding="utf-8"); os.replace(tmp,self.baseline_file)

def _reg_value(key, name: str) -> str | None:
    try: return str(winreg.QueryValueEx(key, name)[0])
    except OSError: return None
