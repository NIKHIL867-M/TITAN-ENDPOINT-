"""
Security log collector — `watcher/collectors/security.py`

Wraps win32evtlog.EvtSubscribe for the Windows Security channel.
Decodes Security EID 4688 (process.start), 4624 (auth.login_success),
4625 (auth.login_failure).

check_prerequisites() programmatically verifies:
  1. Running as Administrator (ctypes.windll.shell32.IsUserAnAdmin)
  2. auditpol Process Creation success auditing is enabled
     (subprocess.run auditpol /get /subcategory:"Process Creation")

This is the fix for the "notepad rule didn't fire" debugging session:
the collector tells you EXACTLY what's wrong at startup, not after
you've been running for 30 minutes wondering why nothing matches.
"""
from __future__ import annotations

import ctypes
import logging
import subprocess
import threading
from typing import Any, Callable
from xml.etree import ElementTree as ET

from .base import (
    Collector, xml_find, xml_find_data, xml_text,
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


# Event IDs this collector understands
_EVENT_MAP = {
    4624: "auth.login_success",
    4625: "auth.login_failure",
    4648: "auth.runas",
    4688: "process.start",
    4663: "file.audit",
    7045: "service.install",
}


class SecurityCollector(Collector):
    name = "security"
    produces = ["auth.login_success", "auth.login_failure", "auth.runas", "process.start", "service.install", "file.audit"]

    def __init__(self) -> None:
        self._channel = "Security"
        self._subscription = None
        self._stop_event = threading.Event()

    def check_prerequisites(self) -> list[str]:
        """
        Check:
          1. win32evtlog is available (pywin32 installed)
          2. Running as Administrator
          3. auditpol Process Creation success auditing is enabled
        """
        problems = []

        if not _WIN32_AVAILABLE:
            problems.append("pywin32 is not installed — pip install pywin32")
            return problems  # can't check further without pywin32

        # Check admin
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                problems.append(
                    "requires Administrator privileges to read the Security log. "
                    "Run the watcher as Administrator, or add your account to "
                    "the 'Event Log Readers' group."
                )
        except Exception:
            problems.append("could not determine admin status")

        # Check auditpol Process Creation
        try:
            result = subprocess.run(
                ["auditpol", "/get", "/subcategory:Process Creation"],
                capture_output=True, text=True, timeout=5,
            )
            output = result.stdout.lower()
            if "success" not in output:
                problems.append(
                    "Process Creation auditing is not enabled. "
                    "Enable it with: auditpol /set /subcategory:\"Process Creation\" /success:enable "
                    "(requires Administrator). Without this, process start events "
                    "(EID 4688) will not appear in the Security log."
                )
        except FileNotFoundError:
            problems.append("auditpol command not found — cannot verify process auditing")
        except subprocess.TimeoutExpired:
            problems.append("auditpol timed out — cannot verify process auditing")
        except Exception as exc:
            logger.debug("auditpol check failed: %s", exc)
            # Non-fatal — don't block startup for an auditpol check failure

        # Check channel access
        try:
            test_handle = win32evtlog.EvtQuery(
                self._channel,
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
                "*",
            )
            win32api.CloseHandle(test_handle)
        except Exception as exc:
            error_code = exc.args[0] if exc.args and isinstance(exc.args[0], int) else 0
            if error_code == 5:
                problems.append(
                    f"access denied to '{self._channel}' channel. "
                    f"Run as Administrator or join 'Event Log Readers' group."
                )
            else:
                problems.append(f"cannot open '{self._channel}' channel: {exc}")

        return problems

    def prerequisite_warnings(self) -> list[str]:
        try:
            result = subprocess.run(
                ["auditpol", "/get", "/subcategory:File System"],
                capture_output=True, text=True, timeout=5,
            )
            if "success" not in result.stdout.lower():
                return [
                    'File who-data (Security 4663) is unavailable. Enable Object Access/File System auditing with: '
                    'auditpol /set /subcategory:"File System" /success:enable, then configure a SACL on each monitored path.'
                ]
        except Exception as exc:
            return [f"Could not verify File System auditing for Security 4663: {exc}"]
        return []

    def start(self, emit: Callable[[dict], None]) -> None:
        """Subscribe to the Security channel and push raw XML via emit()."""
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
                logger.warning("Security callback error: %s", exc)

        self._subscription = bookmark.subscribe(_callback)
        logger.info("[security] Subscribed to channel: %s", self._channel)

        # Block until stop is requested (collector_manager runs us on a thread)
        self._stop_event.wait()

    def stop(self) -> None:
        self._stop_event.set()
        self._subscription = None
        logger.info("[security] Stopped.")

    def decode(self, raw_event: dict) -> dict[str, Any] | None:
        """Decode a Security log event into the common schema."""
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
            return None  # Not an event we decode — drop silently

        event_data = xml_find(root, "EventData")
        user = extract_user(root, event_data)

        # Process block (EID 4688 — process creation)
        process = None
        if event_type == "process.start":
            name = xml_find_data(event_data, "NewProcessName") or ""
            name = name.split("\\")[-1] if "\\" in name else name
            pid = safe_int(xml_find_data(event_data, "NewProcessId"))
            ppid = safe_int(xml_find_data(event_data, "ProcessId"))
            cmdline = xml_find_data(event_data, "CommandLine") or ""
            process = {
                "name": name.lower(),
                "pid": pid,
                "ppid": ppid,
                "command_line": cmdline.lower(),
            }

        file_audit = None
        if event_type == "file.audit":
            process_path = xml_find_data(event_data, "ProcessName") or ""
            process = {
                "name": process_path.split("\\")[-1].lower() if process_path else "",
                "pid": safe_int(xml_find_data(event_data, "ProcessId")),
                "ppid": None,
                "command_line": "",
            }
            file_audit = {
                "path": xml_find_data(event_data, "ObjectName") or "",
                "access_mask": xml_find_data(event_data, "AccessMask") or "",
                "user_sid": xml_find_data(event_data, "SubjectUserSid") or "",
                "username": xml_find_data(event_data, "SubjectUserName") or "",
                "process_name": process_path,
            }

        raw = extract_raw_fields(event_data)

        return {
            "event_type": event_type,
            "timestamp": sys_block["timestamp"],
            "host": sys_block["host"],
            "user": user,
            "process": process,
            "network": None,
            "file_audit": file_audit,
            "source_collector": self.name,
            "raw": raw,
        }
