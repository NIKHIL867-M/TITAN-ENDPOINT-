"""
WMI Process Collector — `watcher/collectors/wmi.py`

Subscribes to WMI process creation events using win32com.client.
Allows standard (non-admin) users to receive process.start events in real time.

Prerequisites:
  - None (accessible by standard users for processes running in their session).
"""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable

from .base import Collector
from shared.windows_aliases import identify_launcher_shim

logger = logging.getLogger(__name__)


def _is_packaged_notepad_launcher(name: str, command_line: str, windows_build: int) -> bool:
    """Compatibility wrapper; recognition is now driven by shared JSON config."""
    return identify_launcher_shim(name, command_line, windows_build) is not None


def _process_details(pid: int, ppid: int) -> tuple[float | None, float | None, str]:
    try:
        import psutil
        process = psutil.Process(pid)
        created = process.create_time()
        executable = process.exe()
        parent_created = psutil.Process(ppid).create_time() if ppid else None
        return created, parent_created, executable
    except Exception:
        return None, None, ""


try:
    import win32com.client
    import pythoncom
    import pywintypes
    _WIN32COM_AVAILABLE = True
except ImportError:
    _WIN32COM_AVAILABLE = False


class WmiCollector(Collector):
    name = "wmi"
    produces = ["process.start"]

    def __init__(self) -> None:
        self._stop_event = threading.Event()

    def check_prerequisites(self) -> list[str]:
        problems = []
        if not _WIN32COM_AVAILABLE:
            problems.append("pywin32 is not installed or win32com is missing.")
        return problems

    def start(self, emit: Callable[[dict], None]) -> None:
        """Subscribe to WMI process creation events."""
        if not _WIN32COM_AVAILABLE:
            raise RuntimeError("win32com is not available")

        # win32com calls on a background thread require CoInitialize
        pythoncom.CoInitialize()
        try:
            wmi = win32com.client.GetObject("winmgmts:")
            # Query process creation events every 1 second
            query = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"
            watcher = wmi.ExecNotificationQuery(query)
            logger.info("[wmi] Listening for WMI process creation events...")

            while not self._stop_event.is_set():
                try:
                    # Wait up to 1000ms for an event
                    event = watcher.NextEvent(1000)
                    proc = event.Properties_("TargetInstance").Value
                    
                    raw_event = {
                        "name": str(proc.Name or ""),
                        "pid": int(proc.ProcessID or 0),
                        "ppid": int(proc.ParentProcessID or 0),
                        "command_line": str(proc.CommandLine or ""),
                        "executable_path": str(proc.ExecutablePath or ""),
                    }
                    emit(raw_event)
                except pywintypes.com_error as exc:
                    # Typically timeout (HRESULT -2147217389 / WBEM_S_TIMEDOUT)
                    pass
                except Exception as exc:
                    logger.debug("[wmi] Loop exception: %s", exc)
                    time.sleep(0.5)
        finally:
            pythoncom.CoUninitialize()

    def stop(self) -> None:
        self._stop_event.set()
        logger.info("[wmi] Stopped.")

    def decode(self, raw_event: dict) -> dict[str, Any] | None:
        """Decode WMI raw event into common process.start schema."""
        name = raw_event.get("name", "")
        pid = raw_event.get("pid", 0)
        ppid = raw_event.get("ppid", 0)
        command_line = raw_event.get("command_line", "")

        create_time, parent_create_time, observed_executable = _process_details(int(pid), int(ppid))
        executable_path = str(raw_event.get("executable_path") or observed_executable or "")
        shim = identify_launcher_shim(str(name), str(command_line))
        # The Windows 11 packaged process can retain a System32-origin command
        # line. Its actual WindowsApps image proves it is persistent, not the
        # short-lived launcher shim.
        if "\\windowsapps\\" in executable_path.lower():
            shim = None

        return {
            "event_type": "process.start",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host": "localhost",
            "user": None,
            "process": {
                "name": name.lower(),
                "pid": pid,
                "ppid": ppid,
                "command_line": command_line.lower(),
                "guid": f"wmi:{pid}:{create_time:.6f}" if create_time is not None else "",
                "parent_guid": f"wmi:{ppid}:{parent_create_time:.6f}" if parent_create_time is not None else "",
                "create_time": create_time,
                "is_launcher_shim": bool(shim),
                "shim_target": shim.get("target", "") if shim else "",
                "executable_path": executable_path,
            },
            "network": None,
            "source_collector": self.name,
            "raw": raw_event,
        }
