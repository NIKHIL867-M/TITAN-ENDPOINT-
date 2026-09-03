"""
Collector base class — `watcher/collectors/base.py`

Every collector, regardless of telemetry source, implements this shape.
This is the actual plugin boundary: a new collector is one new file that
knows how to subscribe to its source AND how to decode its raw events
into the common normalized schema. Nothing else needs to know that
format exists.

Design from execute.txt Collector Platform Redesign §1:
  - check_prerequisites() is abstract — forgetting to implement it makes
    the collector fail to instantiate, not fail silently at runtime.
  - decode() lives INSIDE each collector, not in a separate central
    normalizer with a branch per source.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, Callable
from xml.etree import ElementTree as ET

logger = logging.getLogger(__name__)

# XML namespace used by Windows Event Log
NS = "http://schemas.microsoft.com/win/2004/08/events/event"
NS_MAP = {"e": NS}


class Collector(ABC):
    """
    Abstract base class for all telemetry collectors.

    Every collector:
    - Has a name (e.g. "security", "sysmon")
    - Lists the event_types it can produce
    - Can self-check its own prerequisites before starting
    - Subscribes to its source and pushes raw events via emit()
    - Decodes raw events into the common normalized schema
    """

    name: str = ""
    produces: list[str] = []
    collection_mode: str = "realtime"
    poll_interval_s: int | None = None

    def prerequisite_warnings(self) -> list[str]:
        """Non-fatal coverage limitations exposed to the operator."""
        return []

    @abstractmethod
    def check_prerequisites(self) -> list[str]:
        """
        Return a list of human-readable problems (empty list = OK).

        Called before start(). This is where requirements like
        "requires Administrator privileges" or "requires auditpol
        Process Creation success auditing" live — checked and reported
        clearly instead of failing silently.

        Examples:
            []                                          # all good
            ["requires Administrator privileges"]       # access denied
            ["Sysmon is not installed on this host"]    # missing provider
        """
        ...

    @abstractmethod
    def start(self, emit: Callable[[dict], None]) -> None:
        """
        Begin producing events, calling emit(raw_event_dict) for each one.

        Runs on its own thread (the collector_manager starts each collector
        on a daemon thread). Must not block the caller — it should set up
        the subscription and return, or loop internally.

        The emit callback is:
            emit({"xml": raw_xml_string, ...})
        """
        ...

    @abstractmethod
    def stop(self) -> None:
        """Clean shutdown — stop the subscription."""
        ...

    @abstractmethod
    def decode(self, raw_event: dict) -> dict[str, Any] | None:
        """
        Turn this collector's raw event into the common normalized schema.

        Return None to drop an event this collector saw but has no
        rule-relevant meaning (most log lines aren't interesting —
        decode is also the filter).

        The common schema:
        {
            "event_type":        "process.start" | "auth.login_failure" | ...,
            "timestamp":         iso8601 string,
            "host":              str,
            "user":              str | None,
            "process":           {...} | None,
            "network":           {...} | None,
            "source_collector":  str,   # kept for evidence/debugging only
            "raw":               dict,
        }
        """
        ...


# ═══════════════════════════════════════════════════════════════════════
# Shared XML helpers — used by all collectors that read Windows Event XML
# ═══════════════════════════════════════════════════════════════════════


def xml_text(elem: ET.Element | None) -> str | None:
    """Return stripped text of an XML element, or None."""
    if elem is None:
        return None
    t = elem.text
    return t.strip() if t else None


def xml_find(root: ET.Element, *path_parts: str) -> ET.Element | None:
    """Find a descendant element using the namespaced path parts."""
    query = "/".join(f"e:{p}" for p in path_parts)
    return root.find(query, NS_MAP)


def xml_find_data(event_data: ET.Element | None, name: str) -> str | None:
    """Find a named Data element inside EventData."""
    if event_data is None:
        return None
    for child in event_data:
        if child.get("Name") == name:
            return xml_text(child)
    return None


def safe_int(value: str | None, default: int = 0) -> int:
    """Convert to int safely."""
    try:
        return int(value or default)
    except (ValueError, TypeError):
        return default


def parse_system_block(root: ET.Element) -> dict[str, Any] | None:
    """
    Extract common System block fields from a Windows Event XML root.
    Returns None if the System block is missing.
    """
    system = xml_find(root, "System")
    if system is None:
        return None

    provider_elem = xml_find(root, "System", "Provider")
    provider_name = (provider_elem.get("Name") or "") if provider_elem is not None else ""

    event_id_elem = xml_find(root, "System", "EventID")
    try:
        event_id = int(xml_text(event_id_elem) or "0")
    except ValueError:
        event_id = 0

    time_created = xml_find(root, "System", "TimeCreated")
    timestamp = (time_created.get("SystemTime") if time_created is not None else None) or ""

    computer_elem = xml_find(root, "System", "Computer")
    host = xml_text(computer_elem) or "unknown"

    return {
        "provider_name": provider_name,
        "event_id": event_id,
        "timestamp": timestamp,
        "host": host,
    }


def extract_raw_fields(event_data: ET.Element | None) -> dict:
    """Extract all Data fields from EventData into a flat dict (for evidence)."""
    raw: dict = {}
    if event_data is not None:
        for child in event_data:
            raw[child.get("Name", child.tag)] = xml_text(child)
    return raw


def extract_user(root: ET.Element, event_data: ET.Element | None) -> str | None:
    """Extract user from either EventData fields or System/Security block."""
    user = xml_find_data(event_data, "SubjectUserName")
    if not user:
        user = xml_find_data(event_data, "TargetUserName")
    if not user:
        security_elem = xml_find(root, "System", "Security")
        user = (security_elem.get("UserID") if security_elem is not None else None)
    return user
