"""Focused Windows event-channel collectors with bounded decoding."""
from __future__ import annotations
import logging
import threading
import time
from typing import Any, Callable
from xml.etree import ElementTree as ET

from .base import Collector, extract_raw_fields, parse_system_block, safe_int, xml_find, xml_find_data
from watcher.bookmarks import EventBookmark

logger = logging.getLogger(__name__)
try:
    import win32api
    import win32evtlog
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False


class ChannelCollector(Collector):
    channel = ""
    event_map: dict[int, str] = {}
    collection_mode = "realtime"

    def __init__(self) -> None:
        self._stop_event = threading.Event()
        self._subscription = None

    def check_prerequisites(self) -> list[str]:
        if not _AVAILABLE:
            return ["pywin32 is not installed — pip install pywin32"]
        try:
            handle = win32evtlog.EvtQuery(self.channel, win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection, "*")
            win32api.CloseHandle(handle)
            return []
        except Exception as exc:
            return [f"cannot read '{self.channel}': {exc}"]

    def start(self, emit: Callable[[dict], None]) -> None:
        bookmark = EventBookmark(self.channel, win32evtlog)
        def callback(action, context, handle):
            if action == win32evtlog.EvtSubscribeActionDeliver:
                try:
                    emit({"xml": win32evtlog.EvtRender(handle, win32evtlog.EvtRenderEventXml)})
                    bookmark.advance(handle)
                except Exception as exc:
                    logger.warning("[%s] callback error: %s", self.name, exc)
        self._subscription = bookmark.subscribe(callback)
        self._stop_event.wait()

    def stop(self) -> None:
        self._stop_event.set()
        self._subscription = None

    def _parts(self, raw_event: dict) -> tuple[ET.Element, dict, Any, dict] | None:
        try:
            root = ET.fromstring(raw_event.get("xml", ""))
        except (ET.ParseError, TypeError):
            return None
        system = parse_system_block(root)
        if not system or system["event_id"] not in self.event_map:
            return None
        data = xml_find(root, "EventData")
        return root, system, data, extract_raw_fields(data)


class ScheduledTasksCollector(ChannelCollector):
    name, channel = "scheduled_tasks", "Microsoft-Windows-TaskScheduler/Operational"
    event_map = {106: "task.create", 140: "task.update", 141: "task.delete", 200: "task.run"}
    produces = list(event_map.values())
    def decode(self, raw_event: dict) -> dict[str, Any] | None:
        parts = self._parts(raw_event)
        if not parts: return None
        _, system, data, raw = parts
        return {"event_type": self.event_map[system["event_id"]], "timestamp": system["timestamp"], "host": system["host"],
                "task_name": xml_find_data(data, "TaskName") or xml_find_data(data, "Task") or "",
                "task_path": xml_find_data(data, "TaskName") or "", "command": xml_find_data(data, "ActionName") or "",
                "user": xml_find_data(data, "UserName"), "process": None, "network": None, "source_collector": self.name, "raw": raw}


class UsbCollector(ChannelCollector):
    name, channel = "usb", "Microsoft-Windows-DriverFrameworks-UserMode/Operational"
    event_map = {2003: "usb.device_connect", 2100: "usb.device_query"}
    produces = list(event_map.values())
    def decode(self, raw_event: dict) -> dict[str, Any] | None:
        parts = self._parts(raw_event)
        if not parts: return None
        _, system, data, raw = parts
        device_id = xml_find_data(data, "InstanceId") or xml_find_data(data, "DeviceInstanceId") or ""
        upper = device_id.upper()
        def token(prefix: str) -> str:
            return next((p.split("_")[-1] for p in upper.replace("\\", "&").split("&") if p.startswith(prefix)), "")
        return {"event_type": self.event_map[system["event_id"]], "timestamp": system["timestamp"], "host": system["host"],
                "device_name": xml_find_data(data, "DeviceName") or "", "device_id": device_id,
                "vendor_id": token("VID_"), "product_id": token("PID_"), "user": None, "process": None, "network": None,
                "source_collector": self.name, "raw": raw}


class FirewallCollector(ChannelCollector):
    name, channel = "firewall", "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
    event_map = {2004: "firewall.rule_change", 2005: "firewall.rule_change", 2006: "firewall.rule_change"}
    produces = ["firewall.rule_change"]
    def decode(self, raw_event: dict) -> dict[str, Any] | None:
        parts = self._parts(raw_event)
        if not parts: return None
        _, system, data, raw = parts
        rule_name = xml_find_data(data, "RuleName") or ""
        if rule_name.lower().startswith("watcher_isolate"): return None
        return {"event_type": "firewall.rule_change", "timestamp": system["timestamp"], "host": system["host"],
                "rule_name": rule_name, "operation": str(system["event_id"]), "user": None, "process": None, "network": None,
                "source_collector": self.name, "raw": raw}


class ScriptBlockReassembler:
    def __init__(self, ttl_s: float = 30, max_blocks: int = 500) -> None:
        self.ttl_s, self.max_blocks, self._buffers = ttl_s, max_blocks, {}
    def add(self, block_id: str, number: int, total: int, value: str) -> str | None:
        now = time.monotonic()
        self._buffers = {k: v for k, v in self._buffers.items() if now - v["seen"] <= self.ttl_s}
        if block_id not in self._buffers and len(self._buffers) >= self.max_blocks:
            self._buffers.pop(next(iter(self._buffers)))
        buf = self._buffers.setdefault(block_id, {"parts": {}, "total": total, "seen": now})
        buf["parts"][number] = value
        if len(buf["parts"]) < buf["total"]: return None
        result = "".join(buf["parts"].get(i, "") for i in range(1, buf["total"] + 1))
        self._buffers.pop(block_id, None)
        return result


class PowerShellCollector(ChannelCollector):
    name, channel = "powershell", "Microsoft-Windows-PowerShell/Operational"
    event_map, produces = {4104: "powershell.script_block"}, ["powershell.script_block"]
    def __init__(self) -> None:
        super().__init__(); self.reassembler = ScriptBlockReassembler()
    def check_prerequisites(self) -> list[str]:
        problems = super().check_prerequisites()
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging") as key:
                if int(winreg.QueryValueEx(key, "EnableScriptBlockLogging")[0]) != 1: raise OSError()
        except OSError:
            problems.append("PowerShell Script Block Logging is disabled; enable the policy before saving 4104 rules")
        return problems
    def decode(self, raw_event: dict) -> dict[str, Any] | None:
        parts = self._parts(raw_event)
        if not parts: return None
        _, system, data, raw = parts
        block_id = xml_find_data(data, "ScriptBlockId") or "unknown"
        script = self.reassembler.add(block_id, safe_int(xml_find_data(data, "MessageNumber"), 1), safe_int(xml_find_data(data, "MessageTotal"), 1), xml_find_data(data, "ScriptBlockText") or "")
        if script is None: return None
        return {"event_type": "powershell.script_block", "timestamp": system["timestamp"], "host": system["host"],
                "script_text": script[:4096], "script_block_id": block_id, "path": xml_find_data(data, "Path"),
                "user": None, "process": None, "network": None, "source_collector": self.name, "raw": raw}


class DefenderCollector(ChannelCollector):
    """Windows Defender detections and remediation results (1116/1117)."""
    name, channel = "defender", "Microsoft-Windows-Windows Defender/Operational"
    event_map = {1116: "defender.detection", 1117: "defender.remediation"}
    produces = list(event_map.values())

    def decode(self, raw_event: dict) -> dict[str, Any] | None:
        parts = self._parts(raw_event)
        if not parts: return None
        _, system, data, raw = parts
        return {
            "event_type": self.event_map[system["event_id"]],
            "timestamp": system["timestamp"], "host": system["host"],
            "threat_name": xml_find_data(data, "Threat Name") or xml_find_data(data, "ThreatName") or "",
            "severity": xml_find_data(data, "Severity Name") or xml_find_data(data, "SeverityName") or "",
            "category": xml_find_data(data, "Category Name") or xml_find_data(data, "CategoryName") or "",
            "path": xml_find_data(data, "Path") or "",
            "action": xml_find_data(data, "Action Name") or xml_find_data(data, "ActionName") or "",
            "status": xml_find_data(data, "Status Description") or xml_find_data(data, "StatusDescription") or "",
            "user": None, "process": None, "network": None,
            "source_collector": self.name, "raw": raw,
        }
