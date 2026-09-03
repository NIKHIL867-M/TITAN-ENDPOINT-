"""
System log collector — `watcher/collectors/system.py`

Wraps win32evtlog.EvtSubscribe for the Windows System channel.
Decodes System EID 7036 (service.state_change), 7045 (service.install).

Typically does NOT require Administrator privileges — the System log
is readable by standard users on most Windows configurations.
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
    7036: "service.state_change",
    7045: "service.install",
}


class SystemCollector(Collector):
    name = "system"
    produces = ["service.state_change", "service.install"]

    def __init__(self) -> None:
        self._channel = "System"
        self._subscription = None
        self._stop_event = threading.Event()

    def check_prerequisites(self) -> list[str]:
        """
        System log is typically readable without elevation.
        Still verify the channel exists and is accessible.
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
            if error_code == 5:
                problems.append(f"access denied to '{self._channel}' channel")
            elif error_code == 15007:
                problems.append(f"'{self._channel}' channel not found")
            else:
                problems.append(f"cannot open '{self._channel}' channel: {exc}")

        return problems

    def start(self, emit: Callable[[dict], None]) -> None:
        """Subscribe to the System channel."""
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
                logger.warning("System callback error: %s", exc)

        self._subscription = bookmark.subscribe(_callback)
        logger.info("[system] Subscribed to channel: %s", self._channel)
        self._stop_event.wait()

    def stop(self) -> None:
        self._stop_event.set()
        self._subscription = None
        logger.info("[system] Stopped.")

    def decode(self, raw_event: dict) -> dict[str, Any] | None:
        """Decode a System log event into the common schema."""
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
        raw = extract_raw_fields(event_data)

        return {
            "event_type": event_type,
            "timestamp": sys_block["timestamp"],
            "host": sys_block["host"],
            "user": user,
            "process": None,
            "network": None,
            "source_collector": self.name,
            "raw": raw,
        }
