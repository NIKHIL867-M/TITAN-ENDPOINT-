"""
Collectors package initialization — `watcher/collectors/__init__.py`

Exposes the COLLECTOR_REGISTRY mapping name → collector class.
Allows new collectors to be registered here dynamically.
"""
from __future__ import annotations

from .base import Collector
from .security import SecurityCollector
from .system import SystemCollector
from .sysmon import SysmonCollector
from .wmi import WmiCollector
from .registry_fim import RegistryIntegrityCollector
from .inventory import InventoryCollector
from .windows_channels import ScheduledTasksCollector, UsbCollector, FirewallCollector, PowerShellCollector, DefenderCollector
from .titan_sensors import TitanSensorCollector

COLLECTOR_REGISTRY: dict[str, type[Collector]] = {
    "security": SecurityCollector,
    "system": SystemCollector,
    "sysmon": SysmonCollector,
    "wmi": WmiCollector,
    "registry_fim": RegistryIntegrityCollector,
    "inventory": InventoryCollector,
    "scheduled_tasks": ScheduledTasksCollector,
    "usb": UsbCollector,
    "firewall": FirewallCollector,
    "powershell": PowerShellCollector,
    "defender": DefenderCollector,
    "titan_sensors": TitanSensorCollector,
}

__all__ = ["Collector", "COLLECTOR_REGISTRY"]
