"""Persistent Windows Event Log bookmarks for gap-reduced subscriptions."""
from __future__ import annotations

import logging
import os
import re
import threading
import time
import json
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)
_LOCK = threading.Lock()
_ROOT = Path(__file__).resolve().parent.parent


class EventBookmark:
    """Loads, advances, and atomically persists one channel bookmark."""

    def __init__(self, channel: str, win32evtlog_module) -> None:
        self.channel = channel
        self.api = win32evtlog_module
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", channel)
        data_dir = os.environ.get("WATCHER_DATA_DIR", "data")
        base = Path(data_dir)
        if not base.is_absolute():
            base = _ROOT / base
        self.path = base / "bookmarks" / f"{safe_name}.xml"
        self.status_path = base / "collector_status.json"
        self.handle = None

    def subscription_args(self) -> tuple[int, object | None]:
        if not self.path.exists():
            return self.api.EvtSubscribeToFutureEvents, None
        try:
            xml = self.path.read_text(encoding="utf-8").strip()
            if xml:
                self.handle = self.api.EvtCreateBookmark(xml)
                return self.api.EvtSubscribeStartAfterBookmark, self.handle
        except Exception as exc:
            logger.warning("[%s] Bookmark load failed; starting with future events: %s", self.channel, exc)
        return self.api.EvtSubscribeToFutureEvents, None

    # Per-channel counter for throttled failure logging (module-level so it
    # survives across EventBookmark instances for the same channel — each
    # collector restart creates a fresh instance, but sustained failure
    # should still only log occasionally, not once per instance).
    _fail_counts: dict[str, int] = {}

    def advance(self, event_handle) -> None:
        try:
            if self.handle is None:
                self.handle = self.api.EvtCreateBookmark(None)
            self.api.EvtUpdateBookmark(self.handle, event_handle)
            xml = self.api.EvtRender(self.handle, self.api.EvtRenderBookmark)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".xml.tmp")
            with _LOCK:
                tmp.write_text(xml, encoding="utf-8")
                # FIX (observed live): OneDrive (this project lives in a
                # synced folder) can transiently hold a lock on the
                # destination file during sync, making os.replace() fail
                # with WinError 5 (Access Denied) on a healthy, high-volume
                # channel almost every single event -- thousands of retries
                # per minute, each logged, turning this into unbounded log
                # growth (the exact "logs go from KB -> MB -> GB" risk
                # flagged in the project's own notes). A short retry absorbs
                # the transient lock; if it's still failing after that,
                # throttled logging (every 100th) keeps the operator
                # informed without flooding the log.
                last_exc: Exception | None = None
                for attempt in range(3):
                    try:
                        os.replace(tmp, self.path)
                        last_exc = None
                        break
                    except OSError as exc:
                        last_exc = exc
                        if attempt < 2:
                            time.sleep(0.02 * (attempt + 1))
                if last_exc is not None:
                    try:
                        tmp.unlink(missing_ok=True)
                    except OSError:
                        pass
                    raise last_exc
        except Exception as exc:
            count = EventBookmark._fail_counts.get(self.channel, 0) + 1
            EventBookmark._fail_counts[self.channel] = count
            if count == 1 or count % 100 == 0:
                logger.warning(
                    "[%s] Bookmark update failed (%d total so far): %s",
                    self.channel, count, exc,
                )

    def subscribe(self, callback):
        """Subscribe after the bookmark, falling back safely if it is stale."""
        flags, handle = self.subscription_args()
        try:
            return self.api.EvtSubscribe(self.channel, flags, Bookmark=handle, Callback=callback)
        except Exception:
            if flags != self.api.EvtSubscribeStartAfterBookmark:
                raise
            logger.warning("[%s] Stored bookmark is stale; resetting to future events", self.channel)
            self._record_gap("stored bookmark became stale; resumed from future events")
            self.handle = None
            try: self.path.unlink(missing_ok=True)
            except OSError: pass
            return self.api.EvtSubscribe(
                self.channel, self.api.EvtSubscribeToFutureEvents, Callback=callback
            )

    def _record_gap(self, reason: str) -> None:
        """Expose a bookmark fallback as an operator-visible telemetry gap."""
        with _LOCK:
            try: status = json.loads(self.status_path.read_text(encoding="utf-8"))
            except (OSError, ValueError): status = {}
            gaps = status.setdefault("bookmark_gaps", {})
            gaps[self.channel] = {"at": datetime.now(timezone.utc).isoformat(), "reason": reason}
            self.status_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.status_path.with_name(f"{self.status_path.name}.{os.getpid()}.tmp")
            try:
                tmp.write_text(json.dumps(status, indent=2), encoding="utf-8")
                os.replace(tmp, self.status_path)
            except OSError as exc:
                logger.warning("[%s] Could not persist bookmark gap status: %s", self.channel, exc)
                try: tmp.unlink(missing_ok=True)
                except OSError: pass
