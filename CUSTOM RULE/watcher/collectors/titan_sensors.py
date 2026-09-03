"""
TITAN sensor collector — `watcher/collectors/titan_sensors.py`

Bridges CUSTOM RULE (GEKKO) to the 5 independent native TITAN ENDPOINT
sensors (Port/Process/File Integrity/Network/Application) plus the
Correlator's own session_timeline output. Those 6 programs are pure,
read-only JSONL evidence writers with zero IPC and zero knowledge of this
watcher — this collector closes that gap from the read side only, the same
way the C++ Correlator does it: poll-tail already-written log files, never
write into any of them, never touch the sensors' own processes.

Source of truth for 5 of the 6 log directories is the Correlator's own
`CORRELATOR/correlator_config.txt` ("name=directory" lines) — reusing it
means Santosh only ever edits paths in one place after an elevated
"start", instead of keeping two configs in sync. This module only reads
that file; it never writes to it, so the C++ Correlator's own behavior is
untouched. The Correlator's own output directory isn't listed in that
file (it writes relative to wherever it's launched from), so it has its
own optional TITAN_CORRELATOR_LOG_DIR env var instead — see
watcher/config.py.

Tailing design mirrors CORRELATOR/log_tailer.h/.cpp: poll a directory,
match files by filename hint, read bytes appended since a persisted
offset, hold back a not-yet-newline-terminated partial line, and drop
tracking for files that disappear (pruned by the source endpoint's own
retention logic — never an error). Offsets are persisted the same
atomic tmp+os.replace way watcher/bookmarks.py persists Windows Event Log
bookmarks, just keyed by filename + byte offset instead of an EVT
bookmark blob.

Field-name strategy: event types that already exist in the watcher's
vocabulary (process.start, file.create, file.delete, dns.query,
network.connect) are reused whenever a TITAN record's semantics genuinely
match — this gets existing rules "for free" across sources and lets the
main loop's DedupGuard collapse duplicates if e.g. both `sysmon` and
`titan_sensors` are enabled. Signals TITAN alone carries (USB HID-injection
timing, process persistence touchpoints, file-integrity hash mismatches,
the Correlator's own cross-endpoint joins) get new `titan.`-namespaced
event types instead of overloading an existing one with the wrong shape.
"""
from __future__ import annotations

import json
import logging
import time
import os
import threading
from pathlib import Path
from typing import Any, Callable

from .base import Collector

logger = logging.getLogger(__name__)


# Matches CORRELATOR/main.cpp's FilenameHintFor() exactly — keeps the
# tailer from picking up unrelated files if a directory is ever shared.
_FILENAME_HINTS: dict[str, str] = {
    "port": "usb",
    "process": "titan_",
    "file_integrity": "fim_events",
    "network": "titan_",
    "application": "application_events",
    "correlator": "",  # its own exclusive directory — no filter needed
}

_KNOWN_SOURCES = frozenset(_FILENAME_HINTS)


def _default_correlator_config_path() -> Path:
    # This file lives at CUSTOM RULE/watcher/collectors/titan_sensors.py
    custom_rule_root = Path(__file__).resolve().parents[2]
    titan_root = custom_rule_root.parent
    return titan_root / "CORRELATOR" / "correlator_config.txt"


def load_source_directories(config_path: Path, correlator_log_dir: str = "") -> dict[str, Path]:
    """
    Parse "name=directory" lines from the Correlator's own config file —
    same format, same file, so log paths only ever need updating in one
    place after Santosh runs the real elevated binaries. Unknown source
    names are ignored (forward-compatible with future config additions
    this collector doesn't understand yet). Read-only: never writes back.
    """
    sources: dict[str, Path] = {}
    try:
        text = config_path.read_text(encoding="utf-8-sig")  # tolerate a BOM, same as main.cpp
    except OSError as exc:
        logger.warning("[titan_sensors] Cannot read Correlator config %s: %s", config_path, exc)
        text = ""

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        name, _, directory = line.partition("=")
        name, directory = name.strip(), directory.strip()
        if name in _KNOWN_SOURCES and directory:
            sources[name] = Path(directory)

    if correlator_log_dir:
        sources["correlator"] = Path(correlator_log_dir)

    return sources


# Bounds a single accumulating partial (not-yet-newline-terminated) line.
# Every real record from all 6 TITAN programs is a single-line, bounded-size
# JSON object -- a "line" that keeps growing past this without a newline
# means something is wrong upstream (truncated write mid-line, corrupt
# file), not a legitimately huge record. Drop and log rather than let it
# accumulate without bound across polls.
_MAX_PARTIAL_BYTES = 8 * 1024 * 1024  # 8 MiB

# Debounce interval for bookmark persistence -- see save()'s docstring for
# the real feedback loop this fixes (measured live: ~48% of File Integrity's
# entire log volume was this collector's own bookmark writes). A crash
# within this window re-reads (not loses) up to this many seconds of
# already-emitted events on restart -- an acceptable trade-off already
# consistent with this collector's documented at-least-once delivery.
_MIN_SAVE_INTERVAL_S = 5.0


class _FileBookmark:
    """
    Persists one tailed file's byte offset atomically, across restarts.

    FIX (filename reuse): stores the file's identity (Windows file index,
    the NTFS equivalent of an inode) alongside the offset. If a rotated log
    directory ever reuses a filename (unlikely given the 5 sensors' own
    timestamped pack names, but not impossible after a clock change or a
    naming collision), the stored offset would otherwise be silently
    replayed against unrelated bytes in the new file. A file-identity
    mismatch is treated the same as "file shrank" -- start over from 0.
    """

    def __init__(self, bookmark_dir: Path, source_name: str, file_name: str) -> None:
        safe = f"{source_name}__{file_name}".replace(" ", "_")
        self._path = bookmark_dir / f"{safe}.json"
        self._last_saved_at = 0.0
        self._pending_offset: int | None = None
        self._pending_file_id: int | None = None

    def load(self) -> tuple[int, int | None]:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            offset = int(data.get("offset", 0))
            file_id = data.get("file_id")
            return offset, (int(file_id) if file_id is not None else None)
        except (OSError, ValueError, TypeError):
            return 0, None

    def save(self, offset: int, file_id: int | None, force: bool = False) -> None:
        # FIX (observed live -- feedback loop): saving on every single poll
        # cycle means this write is itself a file-system event that
        # FILEEE's File Integrity endpoint sees and logs -- and one of the
        # 5 things titan_sensors tails IS file_integrity's own output log,
        # so its growth (partly caused by these very bookmark writes) drove
        # MORE frequent saves, which drove more FIM activity. Measured live:
        # this was ~48% of FIM's entire log volume, pure noise, roughly
        # doubling its write rate and shrinking its effective retention
        # window for real evidence. Debounced to at most once per
        # kMinSaveIntervalS per file; `force=True` (used on collector stop)
        # bypasses the debounce for a final durable save.
        now = time.monotonic()
        if not force and (now - self._last_saved_at) < _MIN_SAVE_INTERVAL_S:
            self._pending_offset = offset
            self._pending_file_id = file_id
            return
        self._last_saved_at = now
        self._pending_offset = None
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps({"offset": offset, "file_id": file_id}), encoding="utf-8")
            os.replace(tmp, self._path)
        except OSError as exc:
            logger.warning("[titan_sensors] Bookmark save failed for %s: %s", self._path, exc)

    def flush(self) -> None:
        """Force-persist any debounced offset. Call on collector stop."""
        if self._pending_offset is not None:
            self.save(self._pending_offset, self._pending_file_id, force=True)


def _file_identity(path: Path) -> int | None:
    """Windows file index (st_ino) -- stable across renames, changes if the filename is reused by a new file."""
    try:
        return os.stat(path).st_ino
    except OSError:
        return None


class _SourceTailer:
    """Poll-tails one source directory for files matching its filename hint."""

    def __init__(self, source_name: str, directory: Path, bookmark_dir: Path) -> None:
        self.source_name = source_name
        self.directory = directory
        self.hint = _FILENAME_HINTS.get(source_name, "")
        self._bookmark_dir = bookmark_dir
        self._offsets: dict[str, int] = {}
        self._file_ids: dict[str, int | None] = {}
        self._bookmarks: dict[str, _FileBookmark] = {}
        self._partial: dict[str, str] = {}
        self._partial_dropped = 0

    def read_new_lines(self) -> list[str]:
        if not self.directory.is_dir():
            return []
        try:
            candidates = sorted(
                p for p in self.directory.iterdir()
                if p.is_file() and (not self.hint or self.hint in p.name)
            )
        except OSError as exc:
            logger.debug("[titan_sensors:%s] Cannot list %s: %s", self.source_name, self.directory, exc)
            return []

        lines: list[str] = []
        seen_names = set()
        for path in candidates:
            key = path.name
            seen_names.add(key)
            current_id = _file_identity(path)

            if key not in self._bookmarks:
                self._bookmarks[key] = _FileBookmark(self._bookmark_dir, self.source_name, key)
                loaded_offset, loaded_id = self._bookmarks[key].load()
                if loaded_id is not None and current_id is not None and loaded_id != current_id:
                    # Filename reused by a different file since the last
                    # persisted bookmark -- the old offset means nothing here.
                    logger.info(
                        "[titan_sensors:%s] File identity changed for %s -- filename reused, restarting from 0",
                        self.source_name, key,
                    )
                    loaded_offset = 0
                self._offsets[key] = loaded_offset
                self._file_ids[key] = current_id
                self._partial[key] = ""
            elif current_id is not None and self._file_ids.get(key) is not None and current_id != self._file_ids[key]:
                # Reused mid-session (this run tailed the old file, then it
                # was replaced by a new one with the same name before we
                # noticed via size shrinking).
                self._offsets[key] = 0
                self._partial[key] = ""
                self._file_ids[key] = current_id

            try:
                size = path.stat().st_size
            except OSError:
                continue
            offset = self._offsets.get(key, 0)
            if size < offset:
                # File was rotated/truncated out from under us — start over,
                # exactly how log_tailer.h treats a shrunk file.
                offset = 0
                self._partial[key] = ""
            if size <= offset:
                continue

            try:
                with open(path, "rb") as f:
                    f.seek(offset)
                    chunk = f.read(size - offset)
            except OSError as exc:
                logger.debug("[titan_sensors:%s] Read failed for %s: %s", self.source_name, path, exc)
                continue

            text = self._partial.get(key, "") + chunk.decode("utf-8", errors="replace")
            parts = text.split("\n")
            remainder = parts.pop()
            if len(remainder) > _MAX_PARTIAL_BYTES:
                self._partial_dropped += 1
                logger.warning(
                    "[titan_sensors:%s] Partial line for %s exceeded %d bytes with no newline "
                    "(dropped, total drops so far: %d) -- upstream write likely truncated mid-line",
                    self.source_name, key, _MAX_PARTIAL_BYTES, self._partial_dropped,
                )
                remainder = ""
            # Tolerate CRLF line endings — Windows text-mode ofstream writers
            # (some of the 5 sensors' loggers) emit "\r\n", not just "\n".
            lines.extend(p.rstrip("\r") for p in parts if p.strip())
            self._partial[key] = remainder
            self._offsets[key] = offset + len(chunk)
            self._bookmarks[key].save(self._offsets[key], current_id)

        # Drop tracking for files that disappeared (pruned by the source
        # endpoint's own retention logic) — never an error, matches
        # log_tailer.h's documented behavior exactly.
        for stale in set(self._bookmarks) - seen_names:
            self._bookmarks.pop(stale, None)
            self._file_ids.pop(stale, None)
            self._offsets.pop(stale, None)
            self._partial.pop(stale, None)

        return lines

    def flush_bookmarks(self) -> None:
        """Force-persist every tracked file's debounced offset. Call on stop()."""
        for bookmark in self._bookmarks.values():
            bookmark.flush()


# ═══════════════════════════════════════════════════════════════════════
# Common-schema helpers
# ═══════════════════════════════════════════════════════════════════════


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _process_block(
    pid: Any = None, ppid: Any = None, name: str = "", command_line: str = "",
    parent_name: str = "", hash_: str = "", tid: Any = None, guid: str = "",
) -> dict[str, Any]:
    block: dict[str, Any] = {
        "name": str(name or "").lower(),
        "pid": _safe_int(pid),
        "ppid": _safe_int(ppid) if ppid is not None else None,
        "command_line": str(command_line or "").lower(),
        "guid": guid,
    }
    if parent_name:
        block["parent_name"] = str(parent_name).lower()
    if hash_:
        block["hash"] = hash_
    if tid is not None:
        block["tid"] = _safe_int(tid)
    return block


# ═══════════════════════════════════════════════════════════════════════
# Per-source decoders — one raw JSONL line -> common normalized schema
# ═══════════════════════════════════════════════════════════════════════


def _decode_process(rec: dict) -> dict[str, Any] | None:
    """PROCESS ENDPOINT (titan_process.exe) — event.cpp ForwardJson shape."""
    subtype = rec.get("event_subtype", "")
    pid = rec.get("pid")

    if subtype in ("process_start", "process_snapshot"):
        return {
            "event_type": "process.start",
            "timestamp": rec.get("log_time") or rec.get("ts") or "",
            "host": "localhost",
            "user": rec.get("user_name") or None,
            "process": _process_block(
                pid=pid, ppid=rec.get("parent_pid"),
                name=rec.get("process_name", ""), command_line=rec.get("command_line_raw", ""),
                parent_name=rec.get("parent_name", ""), hash_=rec.get("fingerprint", ""),
                guid=f"titan_process:{pid}:{rec.get('t_unix_ms', 0)}",
            ),
            "network": None,
            "source_collector": "titan_sensors",
            "raw": rec,
            # TITAN-only extras — not in IR_FIELD_PATHS, resolved as flat
            # top-level fields (same convention as sysmon.py's **extra).
            "executable_path": rec.get("canonical_path", ""),
            "signature_valid": rec.get("signature_valid"),
            "integrity": rec.get("integrity"),
            "elevation": rec.get("elevation"),
            "persistence_touched": bool(rec.get("persistence_touched", False)),
        }

    if subtype == "process_stop":
        return {
            "event_type": "titan.process.stop",
            "timestamp": rec.get("log_time") or rec.get("ts") or "",
            "host": "localhost",
            "user": rec.get("user_name") or None,
            "process": _process_block(pid=pid, name=rec.get("process_name", "")),
            "network": None,
            "source_collector": "titan_sensors",
            "raw": rec,
            "exit_time": rec.get("exit_time"),
        }

    return None


_FILE_ACTION_EVENT_TYPE = {"create": "file.create", "delete": "file.delete"}


def _decode_file_integrity(rec: dict) -> dict[str, Any] | None:
    """FILEEE (file_test.exe) — file_processor.cpp BuildJson shape."""
    action = rec.get("action")
    if action is None:
        return None  # temp_* / other sub-records not mapped in this pass
    event_type = _FILE_ACTION_EVENT_TYPE.get(action, "titan.file.modify")
    return {
        "event_type": event_type,
        "timestamp": rec.get("timestamp") or "",
        "host": "localhost",
        "user": None,
        "process": _process_block(pid=rec.get("pid"), tid=rec.get("tid"), name=rec.get("process", "")),
        "network": None,
        "source_collector": "titan_sensors",
        "raw": rec,
        "path": rec.get("path", ""),
        "old_path": rec.get("old_path"),
        "action": action,
        "protected": bool(rec.get("protected", False)),
        "executable": bool(rec.get("executable", False)),
        "document": bool(rec.get("document", False)),
        "sha256": rec.get("sha256"),
        "hash_status": rec.get("hash_status"),
    }


def _decode_network(rec: dict) -> dict[str, Any] | None:
    """NETOWRK ENDPOINT (titan.exe) — event.cpp ToJson shape."""
    if rec.get("record_type") != "network_packet":
        return None

    base: dict[str, Any] = {
        "timestamp": rec.get("ts") or "",
        "host": "localhost",
        "user": None,
        "process": _process_block(pid=rec.get("pid"), name=rec.get("process_name", "")),
        "source_collector": "titan_sensors",
        "raw": rec,
    }

    if rec.get("dns_query"):
        base["event_type"] = "dns.query"
        base["network"] = None
        base["query_name"] = rec.get("dns_query", "")
        base["query_status"] = "success" if rec.get("dns_answers") else "unknown"
        base["query_results"] = rec.get("dns_answers", "")
        return base

    if rec.get("http_method") or rec.get("http_status_code"):
        base["event_type"] = "titan.network.http"
        base["network"] = {
            "dest_ip": rec.get("remote_ip", ""), "dest_port": _safe_int(rec.get("remote_port")),
            "src_ip": rec.get("local_ip", ""), "src_port": _safe_int(rec.get("local_port")),
        }
        base["http_method"] = rec.get("http_method")
        base["http_target"] = rec.get("http_target")
        base["http_host"] = rec.get("http_host")
        base["http_status_code"] = rec.get("http_status_code")
        base["http_reason"] = rec.get("http_reason")
        return base

    base["event_type"] = "network.connect"
    base["network"] = {
        "dest_ip": rec.get("remote_ip", ""), "dest_port": _safe_int(rec.get("remote_port")),
        "src_ip": rec.get("local_ip", ""), "src_port": _safe_int(rec.get("local_port")),
        "protocol": rec.get("protocol", ""),
    }
    return base


def _decode_port(rec: dict) -> dict[str, Any] | None:
    """
    PORT ENDPOINT (usb_test.exe) — usb_session.cpp / usb_monitor.cpp shapes.

    NOTE: this endpoint's "pid" field (inside "device" or top-level on HID
    records) is the USB *Product ID* string (e.g. "PID_1234"), never a
    process ID — there is no process attribution for USB device activity.
    Field names below deliberately reuse vendor_id/product_id/device_name/
    device_id from the existing usb.device_connect vocabulary for rule
    consistency, even though this is a different event_type.
    """
    record_kind = rec.get("type")

    if record_kind == "usb_hid_event":
        return {
            "event_type": "titan.usb.hid_event",
            "timestamp": rec.get("timestamp") or "",
            "host": "localhost",
            "user": None,
            "process": None,
            "network": None,
            "source_collector": "titan_sensors",
            "raw": rec,
            "vendor_id": rec.get("vid", ""),
            "product_id": rec.get("pid", ""),
            "device_name": rec.get("product", ""),
            "device_id": rec.get("instance_id", ""),
            "manufacturer": rec.get("manufacturer", ""),
            "raw_input_resolved": bool(rec.get("raw_input_resolved", False)),
        }

    if record_kind == "usb_injection_alert":
        return {
            "event_type": "titan.usb.injection_alert",
            "timestamp": rec.get("timestamp") or "",
            "host": "localhost",
            "user": None,
            "process": None,
            "network": None,
            "source_collector": "titan_sensors",
            "raw": rec,
            "vendor_id": rec.get("vid", ""),
            "product_id": rec.get("pid", ""),
            "device_id": rec.get("instance_id", ""),
            "hid_injection_suspected": bool(rec.get("hid_injection_suspected", False)),
            "sample_count": rec.get("sample_count"),
            "mean_interval_ms": rec.get("mean_interval_ms"),
            "stddev_interval_ms": rec.get("stddev_interval_ms"),
            "min_interval_ms": rec.get("min_interval_ms"),
        }

    if rec.get("event_type") == "USB_SESSION_END":
        device = rec.get("device") if isinstance(rec.get("device"), dict) else {}
        activity = rec.get("activity") if isinstance(rec.get("activity"), dict) else {}
        return {
            "event_type": "titan.usb.session",
            "timestamp": rec.get("timestamp") or "",
            "host": "localhost",
            "user": None,
            "process": None,
            "network": None,
            "source_collector": "titan_sensors",
            "raw": rec,
            "session_id": rec.get("session_id", ""),
            "vendor_id": device.get("vid", ""),
            "product_id": device.get("pid", ""),
            "device_name": device.get("product", ""),
            "device_id": device.get("instance_id", ""),
            "mount_point": rec.get("mount_point", ""),
            "reads": activity.get("reads", 0),
            "writes": activity.get("writes", 0),
            "deletes": activity.get("deletes", 0),
            "executes": activity.get("executes", 0),
            "bytes_read": activity.get("bytes_read", 0),
            "bytes_written": activity.get("bytes_written", 0),
        }

    return None


def _decode_application(rec: dict) -> dict[str, Any] | None:
    """APP (application_endpoint.exe) — applog_decoder.cpp BuildJson shape."""
    if rec.get("type") != "application_log":
        return None
    return {
        "event_type": "titan.application.detection",
        "timestamp": rec.get("timestamp") or "",
        "host": "localhost",
        "user": None,
        "process": _process_block(pid=rec.get("pid"), tid=rec.get("tid")) if rec.get("pid") else None,
        "network": None,
        "source_collector": "titan_sensors",
        "raw": rec,
        "source": rec.get("source", ""),
        "event_id": rec.get("event_id", ""),
        "summary": rec.get("summary", ""),
        "script_content": rec.get("script_content", ""),
        "script_path": rec.get("script_path", ""),
        "encoded_decoded": rec.get("encoded_decoded", ""),
        "network_activity": rec.get("network_activity", ""),
        "pattern_hits": rec.get("pattern_hits", 0),
        "credential_access": bool(rec.get("credential_access", False)),
        "amsi_bypass": bool(rec.get("amsi_bypass", False)),
        "process_injection": bool(rec.get("process_injection", False)),
    }


def _decode_correlator(rec: dict) -> dict[str, Any] | None:
    """CORRELATOR (correlator.exe) — correlation_engine.cpp session_timeline shape."""
    if rec.get("type") != "session_timeline":
        return None
    return {
        "event_type": "titan.correlator.session_timeline",
        "timestamp": "",
        "host": "localhost",
        "user": None,
        "process": None,
        "network": None,
        "source_collector": "titan_sensors",
        "raw": rec,
        "members": rec.get("members", []),
    }


_DECODERS: dict[str, Any] = {
    "process": _decode_process,
    "file_integrity": _decode_file_integrity,
    "network": _decode_network,
    "port": _decode_port,
    "application": _decode_application,
    "correlator": _decode_correlator,
}


def _config_path_from_env() -> Path:
    override = os.environ.get("TITAN_CORRELATOR_CONFIG", "")
    return Path(override) if override else _default_correlator_config_path()


def _bookmark_root() -> Path:
    data_dir = Path(os.environ.get("WATCHER_DATA_DIR", "data"))
    if not data_dir.is_absolute():
        data_dir = Path(__file__).resolve().parents[2] / data_dir
    return data_dir / "bookmarks" / "titan_sensors"


# ═══════════════════════════════════════════════════════════════════════
# Collector
# ═══════════════════════════════════════════════════════════════════════


class TitanSensorCollector(Collector):
    """
    Tails all 5 TITAN ENDPOINT sensors' JSONL logs plus the Correlator's
    own session_timeline output. Read-only, non-admin, never writes into
    any of them — same read-only contract as the C++ Correlator itself.
    """

    name = "titan_sensors"
    collection_mode = "poll"
    poll_interval_s = 2
    produces = [
        "process.start", "file.create", "file.delete", "dns.query", "network.connect",
        "titan.process.stop", "titan.file.modify", "titan.network.http",
        "titan.usb.session", "titan.usb.hid_event", "titan.usb.injection_alert",
        "titan.application.detection", "titan.correlator.session_timeline",
    ]

    def __init__(self) -> None:
        self._stop_event = threading.Event()
        self._config_path = _config_path_from_env()
        self._correlator_log_dir = os.environ.get("TITAN_CORRELATOR_LOG_DIR", "")
        self._sources: dict[str, Path] = {}
        self._tailers: list[_SourceTailer] = []

    def check_prerequisites(self) -> list[str]:
        self._sources = load_source_directories(self._config_path, self._correlator_log_dir)
        if not self._sources:
            return [
                f"could not read any TITAN sensor sources from {self._config_path} "
                f"(expected 'name=directory' lines — see CORRELATOR/correlator_config.txt)"
            ]
        if not any(path.is_dir() for path in self._sources.values()):
            return [
                "none of the configured TITAN sensor log directories exist yet — "
                "run the TITAN ENDPOINT sensors (as Administrator) at least once, "
                "or fix the paths in CORRELATOR/correlator_config.txt"
            ]
        return []

    def prerequisite_warnings(self) -> list[str]:
        missing = sorted(name for name, path in self._sources.items() if not path.is_dir())
        if missing:
            return [
                f"log directory not found yet for: {', '.join(missing)} "
                f"(picked up automatically once the sensor is run and creates it)"
            ]
        return []

    def start(self, emit: Callable[[dict], None]) -> None:
        bookmark_dir = _bookmark_root()
        self._tailers = [
            _SourceTailer(name, path, bookmark_dir)
            for name, path in self._sources.items()
        ]
        logger.info(
            "[titan_sensors] Tailing %d source(s): %s",
            len(self._tailers), ", ".join(f"{t.source_name}={t.directory}" for t in self._tailers),
        )

        while not self._stop_event.is_set():
            for tailer in self._tailers:
                for line in tailer.read_new_lines():
                    emit({"source_name": tailer.source_name, "line": line})
            self._stop_event.wait(self.poll_interval_s)

    def stop(self) -> None:
        self._stop_event.set()
        # Force-persist every debounced bookmark so a clean stop never loses
        # more progress than an unclean crash already could (see
        # _FileBookmark.save()'s debounce fix).
        for tailer in self._tailers:
            tailer.flush_bookmarks()
        logger.info("[titan_sensors] Stopped.")

    def decode(self, raw_event: dict) -> dict[str, Any] | None:
        source_name = raw_event.get("source_name", "")
        line = raw_event.get("line", "")
        try:
            rec = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            return None
        if not isinstance(rec, dict):
            return None
        if rec.get("type") == "collector_health":
            return None  # status-only — every collector drops these, not rule-relevant

        decoder = _DECODERS.get(source_name)
        if decoder is None:
            return None
        try:
            return decoder(rec)
        except Exception as exc:
            logger.debug("[titan_sensors] Decode failed for source=%s: %s", source_name, exc)
            return None
