"""
Collector manager — `watcher/collector_manager.py`

Loads, starts, and monitors the life of all enabled collectors.

Design from execute.txt Collector Platform Redesign §2:
  - Startup check: calls check_prerequisites() on each collector. If it
    reports problems, logs them clearly and skips the collector instead of
    failing the entire agent.
  - Crash isolation: runs each collector on its own thread. If a collector
    crashes, it restarts it with exponential backoff. One collector's failure
    never takes down the others.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Any

from watcher.collectors import COLLECTOR_REGISTRY
from watcher.event_bus import EventBus
from watcher.collectors.base import Collector

logger = logging.getLogger(__name__)


class CollectorManager:
    """Manages collector lifetimes, crash detection, and restarts."""

    def __init__(self, enabled_names: list[str], bus: EventBus) -> None:
        self.enabled_names = enabled_names
        self.bus = bus
        self.active_collectors: dict[str, Collector] = {}
        self._threads: dict[str, threading.Thread] = {}
        self._stop_requested = False

    def start_all(self) -> None:
        """Instantiate, verify, and start all configured collectors."""
        logger.info("Initializing enabled collectors: %s", self.enabled_names)

        started_count = 0
        active_names = []
        collector_details = []
        failed_collectors = {}
        collector_warnings = {}
        supported_events = set()
        unsupported_events = set()

        # Check all registered collectors in COLLECTOR_REGISTRY
        all_collectors = {}
        for name, cls in COLLECTOR_REGISTRY.items():
            all_collectors[name] = cls()

        enabled_lower = [n.strip().lower() for n in self.enabled_names]

        for name, collector in all_collectors.items():
            if name in enabled_lower:
                problems = collector.check_prerequisites()
                if problems:
                    logger.error(
                        "[%s] PREREQUISITES FAILED — collector will NOT start:\n  * %s",
                        name,
                        "\n  * ".join(problems),
                    )
                    failed_collectors[name] = problems
                    unsupported_events.update(collector.produces)
                else:
                    warnings = collector.prerequisite_warnings()
                    if warnings:
                        collector_warnings[name] = warnings
                        logger.warning("[%s] Coverage warning: %s", name, "; ".join(warnings))
                    self.active_collectors[name] = collector
                    active_names.append(name)
                    collector_details.append({"name": name, "collection_mode": collector.collection_mode,
                                              "poll_interval_s": collector.poll_interval_s, "produces": collector.produces})
                    supported_events.update(collector.produces)

                    # Spin up running thread with auto-restart
                    t = threading.Thread(
                        target=self._run_with_restart,
                        args=(collector,),
                        name=f"collector-{name}",
                        daemon=True,
                    )
                    self._threads[name] = t
                    t.start()
                    started_count += 1
                    logger.info("[%s] Started successfully. Telemetry: %s", name, collector.produces)
            else:
                unsupported_events.update(collector.produces)

        # A telemetry event is supported if AT LEAST ONE active collector produces it
        unsupported_events = list(unsupported_events - supported_events)
        supported_events = list(supported_events)

        # Write data/collector_status.json
        data_dir = Path(__file__).resolve().parent.parent / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        status_file = data_dir / "collector_status.json"
        status_data = {
            "configured_collectors": enabled_lower,
            "active_collectors": active_names,
            "failed_collectors": failed_collectors,
            "collector_warnings": collector_warnings,
            "supported_events": supported_events,
            "unsupported_events": unsupported_events,
            "collector_details": collector_details,
        }

        tmp_file = status_file.with_suffix(".json.tmp")
        try:
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(status_data, f, indent=2, ensure_ascii=False)
            import os
            os.replace(tmp_file, status_file)
        except Exception as exc:
            logger.warning("Failed to write collector_status.json: %s", exc)

        if started_count == 0:
            logger.critical("Failed to start any collectors. The agent is blind!")
        else:
            logger.info("CollectorManager active: %d collector(s) live", started_count)

    def stop_all(self) -> None:
        """Signal all collectors to stop and wait for threads."""
        self._stop_requested = True
        logger.info("Stopping all collectors...")
        for name, collector in self.active_collectors.items():
            try:
                collector.stop()
            except Exception as exc:
                logger.warning("[%s] Error stopping: %s", name, exc)
        self.active_collectors.clear()

    # ── Internal ──────────────────────────────────────────────────

    def _run_with_restart(self, collector: Collector) -> None:
        """Runs the collector, catching crashes and restarting with backoff."""
        backoff = 1.0
        name = collector.name

        while not self._stop_requested:
            try:
                # Reset stop_event before (re)starting so a restarted collector
                # doesn't immediately return from blocking on an already-set event.
                if hasattr(collector, "_stop_event"):
                    collector._stop_event.clear()

                # Blocks inside the collector's wait event until stopped or crashed
                collector.start(emit=lambda raw: self.bus.publish(name, raw))
                return  # Clean stop
            except Exception as exc:
                if self._stop_requested:
                    return

                logger.error(
                    "[%s] Collector crashed: %s. Restarting in %.1fs (exponential backoff)...",
                    name, exc, backoff, exc_info=True
                )
                time.sleep(backoff)
                # Exponential backoff capped at 60s
                backoff = min(backoff * 2.0, 60.0)
