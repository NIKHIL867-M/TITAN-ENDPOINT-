"""
Sysmon collector — `watcher/collectors/sysmon.py`

Wraps win32evtlog.EvtSubscribe for Microsoft-Windows-Sysmon/Operational.
Decodes:
  - EID 1  → process.start (with full command line and parent info)
  - EID 3  → network.connect
  - EID 7  → image.load
  - EID 11 → file.create
  - EID 13 → registry.set

Optional collector — check_prerequisites() checks if the channel exists
and is readable. If Sysmon is not installed, it returns a clear problem
so that the collector manager logs it as skipped instead of crashing the agent.
"""
from __future__ import annotations

import logging
import threading
from typing import Any, Callable
from xml.etree import ElementTree as ET

from .base import (
    Collector, xml_find, xml_find_data,
    safe_int, parse_system_block, extract_raw_fields, extract_user,
)
from watcher.bookmarks import EventBookmark

logger = logging.getLogger(__name__)

try:
    import win32evtlog
    import win32api
    _WIN32_AVAILABLE = True
except ImportError:
    _WIN32_AVAILABLE = False


_EVENT_MAP = {
    1: "process.start",
    3: "network.connect",
    7: "image.load",
    11: "file.create",
    13: "registry.set",
    10: "credential.access_attempt",
    19: "wmi.persistence", 20: "wmi.persistence", 21: "wmi.persistence",
    22: "dns.query", 23: "file.delete", 26: "file.delete",
    17: "named_pipe.create", 18: "named_pipe.connect",
    6: "driver.load", 25: "process.tamper",
}


class SysmonCollector(Collector):
    name = "sysmon"
    produces = ["process.start", "network.connect", "image.load", "file.create", "registry.set",
                "dns.query", "credential.access_attempt", "process.access", "wmi.persistence", "file.delete",
                "named_pipe.create", "named_pipe.connect", "driver.load", "process.tamper"]

    def __init__(self) -> None:
        self._channel = "Microsoft-Windows-Sysmon/Operational"
        self._subscription = None
        self._stop_event = threading.Event()

    def check_prerequisites(self) -> list[str]:
        """
        Verify Sysmon Operational channel is present and accessible.
        """
        problems = []

        if not _WIN32_AVAILABLE:
            problems.append("pywin32 is not installed — pip install pywin32")
            return problems

        try:
            test_handle = win32evtlog.EvtQuery(
                self._channel,
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
                "*",
            )
            win32api.CloseHandle(test_handle)
        except Exception as exc:
            error_code = exc.args[0] if exc.args and isinstance(exc.args[0], int) else 0
            if error_code == 15007:
                problems.append(
                    f"Sysmon event log channel '{self._channel}' could not be found. "
                    f"Make sure Sysmon is installed on this system."
                )
            elif error_code == 5:
                problems.append(
                    f"access denied to Sysmon channel '{self._channel}'. "
                    f"Run as Administrator or add user to Event Log Readers."
                )
            else:
                problems.append(f"cannot open Sysmon channel: {exc}")

        return problems

    def start(self, emit: Callable[[dict], None]) -> None:
        """Subscribe to the Sysmon channel."""
        if not _WIN32_AVAILABLE:
            raise RuntimeError("win32evtlog not available")

        bookmark = EventBookmark(self._channel, win32evtlog)

        def _callback(action, context, event_handle):
            try:
                if action == win32evtlog.EvtSubscribeActionDeliver:
                    xml = win32evtlog.EvtRender(
                        event_handle, win32evtlog.EvtRenderEventXml
                    )
                    emit({"xml": xml})
                    bookmark.advance(event_handle)
            except Exception as exc:
                logger.warning("Sysmon callback error: %s", exc)

        self._subscription = bookmark.subscribe(_callback)
        logger.info("[sysmon] Subscribed to channel: %s", self._channel)
        self._stop_event.wait()

    def stop(self) -> None:
        self._stop_event.set()
        self._subscription = None
        logger.info("[sysmon] Stopped.")

    def decode(self, raw_event: dict) -> dict[str, Any] | None:
        """Decode Sysmon XML into the common schema."""
        xml_str = raw_event.get("xml")
        if not xml_str:
            return None

        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            return None

        sys_block = parse_system_block(root)
        if sys_block is None:
            return None

        event_id = sys_block["event_id"]
        event_type = _EVENT_MAP.get(event_id)
        if event_type is None:
            return None

        event_data = xml_find(root, "EventData")
        user = extract_user(root, event_data)

        # ── Process block (EID 1 — process creation) ─────────────────
        process = None
        if event_type == "process.start":
            name = xml_find_data(event_data, "Image") or ""
            name = name.split("\\")[-1] if "\\" in name else name
            pid = safe_int(xml_find_data(event_data, "ProcessId"))
            ppid = safe_int(xml_find_data(event_data, "ParentProcessId"))
            cmdline = xml_find_data(event_data, "CommandLine") or ""
            process = {
                "name": name.lower(),
                "pid": pid,
                "ppid": ppid,
                "command_line": cmdline.lower(),
                "guid": xml_find_data(event_data, "ProcessGuid") or "",
                "parent_guid": xml_find_data(event_data, "ParentProcessGuid") or "",
            }

        # ── Network block (EID 3 — network connection) ───────────────
        network = None
        if event_type == "network.connect":
            network = {
                "dest_ip": xml_find_data(event_data, "DestinationIp") or "",
                "dest_port": safe_int(xml_find_data(event_data, "DestinationPort")),
                "src_ip": xml_find_data(event_data, "SourceIp") or "",
                "src_port": safe_int(xml_find_data(event_data, "SourcePort")),
                "protocol": xml_find_data(event_data, "Protocol") or "",
            }
            image = xml_find_data(event_data, "Image") or ""
            process = {
                "name": image.split("\\")[-1].lower() if image else "",
                "pid": safe_int(xml_find_data(event_data, "ProcessId")),
                "ppid": None,
                "command_line": "",
                "guid": xml_find_data(event_data, "ProcessGuid") or "",
            }

        extra: dict[str, Any] = {}
        if event_type == "dns.query":
            image = xml_find_data(event_data, "Image") or ""
            process = {"name": image.split("\\")[-1].lower(), "pid": safe_int(xml_find_data(event_data, "ProcessId")),
                       "guid": xml_find_data(event_data, "ProcessGuid") or "", "ppid": None, "command_line": ""}
            extra = {"query_name": xml_find_data(event_data, "QueryName") or "",
                     "query_status": xml_find_data(event_data, "QueryStatus") or "",
                     "query_results": xml_find_data(event_data, "QueryResults") or ""}
        elif event_type == "credential.access_attempt":
            target = xml_find_data(event_data, "TargetImage") or ""
            if not target.lower().endswith("lsass.exe"):
                event_type = "process.access"
            extra = {
                "source_process": {"pid": safe_int(xml_find_data(event_data, "SourceProcessId")), "name": xml_find_data(event_data, "SourceImage") or "", "guid": xml_find_data(event_data, "SourceProcessGUID") or ""},
                "target_process": {"pid": safe_int(xml_find_data(event_data, "TargetProcessId")), "name": target, "guid": xml_find_data(event_data, "TargetProcessGUID") or ""},
                "granted_access": xml_find_data(event_data, "GrantedAccess") or "",
            }
        elif event_type == "wmi.persistence":
            operation = {19: "filter", 20: "consumer", 21: "binding"}[event_id]
            extra = {"operation": operation, "name": xml_find_data(event_data, "Name") or "",
                     "query": xml_find_data(event_data, "Query") or "",
                     "destination": xml_find_data(event_data, "Destination") or "",
                     "consumer": xml_find_data(event_data, "Consumer") or "",
                     "filter": xml_find_data(event_data, "Filter") or ""}
        elif event_type in {"file.create", "file.delete", "image.load", "registry.set"}:
            image = xml_find_data(event_data, "Image") or ""
            process = {"name": image.split("\\")[-1].lower(), "pid": safe_int(xml_find_data(event_data, "ProcessId")),
                       "guid": xml_find_data(event_data, "ProcessGuid") or "", "ppid": None, "command_line": ""}
            if event_type.startswith("file."):
                extra["path"] = xml_find_data(event_data, "TargetFilename") or ""
        elif event_type.startswith("named_pipe."):
            image = xml_find_data(event_data, "Image") or ""
            process = {"name": image.split("\\")[-1].lower(), "pid": safe_int(xml_find_data(event_data, "ProcessId")),
                       "guid": xml_find_data(event_data, "ProcessGuid") or "", "ppid": None, "command_line": ""}
            extra = {"pipe_name": xml_find_data(event_data, "PipeName") or ""}
        elif event_type == "driver.load":
            extra = {"path": xml_find_data(event_data, "ImageLoaded") or "",
                     "hash": xml_find_data(event_data, "Hashes") or "",
                     "signed": xml_find_data(event_data, "Signed") or "",
                     "signature": xml_find_data(event_data, "Signature") or "",
                     "signature_status": xml_find_data(event_data, "SignatureStatus") or ""}
        elif event_type == "process.tamper":
            image = xml_find_data(event_data, "Image") or ""
            process = {"name": image.split("\\")[-1].lower(), "pid": safe_int(xml_find_data(event_data, "ProcessId")),
                       "guid": xml_find_data(event_data, "ProcessGuid") or "", "ppid": None, "command_line": ""}
            extra = {"tamper_type": xml_find_data(event_data, "Type") or ""}

        raw = extract_raw_fields(event_data)

        return {
            "event_type": event_type,
            "timestamp": sys_block["timestamp"],
            "host": sys_block["host"],
            "user": user,
            "process": process,
            "network": network,
            "source_collector": self.name,
            "raw": raw,
            **extra,
        }
