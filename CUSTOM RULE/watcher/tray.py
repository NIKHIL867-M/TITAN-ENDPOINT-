"""
System tray — `watcher/tray.py`

Puts a shield icon in the Windows system tray while the watcher runs.

Design from execute.txt §9:
  - Runs on its own daemon thread inside the watcher process
  - Menu: Open Dashboard / Pause Watching / Quit
  - Icon color / tooltip reflects status:
      green  → watching (normal)
      yellow → paused
      red    → error

Implementation note:
  - pystray requires Pillow for icon images
  - The tray icon must run on its own thread (pystray.Icon.run() blocks)
  - Communication back to the main loop is via a shared status dict
    (the same mutable dict the main loop writes to)

If pystray or Pillow is not installed, the watcher continues normally
without a tray icon — not a fatal error.
"""
from __future__ import annotations

import logging
import os
import threading
import webbrowser
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

try:
    import pystray
    from PIL import Image, ImageDraw
    _TRAY_AVAILABLE = True
except ImportError:
    _TRAY_AVAILABLE = False
    logger.warning(
        "pystray/Pillow not available — system tray icon disabled. "
        "Install with: pip install pystray Pillow"
    )


# ═══════════════════════════════════════════════════════════════════════
# Icon image builder
# ═══════════════════════════════════════════════════════════════════════

_ICON_PATH = Path(__file__).parent / "icon.png"

# Status → background color
_STATUS_COLORS = {
    "watching": (34, 197, 94),   # green
    "paused": (234, 179, 8),     # yellow
    "error": (239, 68, 68),      # red
}


def _load_or_build_icon(status: str) -> "Image.Image":
    """
    Load icon.png if available, otherwise draw a simple colored circle.
    Tint the icon based on the current status.
    """
    color = _STATUS_COLORS.get(status, _STATUS_COLORS["watching"])

    if _ICON_PATH.exists():
        try:
            img = Image.open(_ICON_PATH).convert("RGBA").resize((64, 64))
            # Tint: blend a color overlay for status indication
            overlay = Image.new("RGBA", img.size, color + (80,))  # semi-transparent
            img = Image.alpha_composite(img, overlay)
            return img
        except Exception:
            pass  # Fall through to fallback

    # Fallback: simple colored circle
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.ellipse([4, 4, 60, 60], fill=color + (255,), outline=(255, 255, 255, 180), width=3)
    # Draw a small "eye" in the center
    draw.ellipse([22, 26, 42, 38], fill=(255, 255, 255, 220))
    draw.ellipse([28, 29, 36, 35], fill=(20, 20, 60, 220))
    return img


# ═══════════════════════════════════════════════════════════════════════
# Tray controller
# ═══════════════════════════════════════════════════════════════════════


class TrayController:
    """
    Controls the system tray icon.
    Create once, then call start() to spin it up on a daemon thread.
    """

    def __init__(
        self,
        status: dict[str, Any],
        dashboard_url: str = "http://localhost:3000",
        stop_callback: Any = None,
    ) -> None:
        """
        status: shared mutable dict — main loop writes to it,
                tray reads it for tooltip / icon color.
                Expected keys: "state" (watching/paused/error), "rules_loaded" (int)
        stop_callback: called when user clicks Quit from tray menu
        """
        self._status = status
        self._dashboard_url = dashboard_url
        self._stop_callback = stop_callback
        self._icon: "pystray.Icon | None" = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start the tray icon on a daemon thread. Returns immediately."""
        if not _TRAY_AVAILABLE:
            logger.info("Tray icon skipped (pystray not available).")
            return

        self._thread = threading.Thread(
            target=self._run_tray,
            name="watcher-tray",
            daemon=True,
        )
        self._thread.start()
        logger.info("System tray icon started.")

    def stop(self) -> None:
        """Stop the tray icon."""
        if self._icon:
            self._icon.stop()

    def update_status(self, state: str, rules_loaded: int = 0) -> None:
        """Update the shared status dict — tray will pick this up on next tick."""
        self._status["state"] = state
        self._status["rules_loaded"] = rules_loaded
        # Try to update the icon immediately if possible
        if self._icon:
            try:
                self._icon.icon = _load_or_build_icon(state)
                self._icon.title = self._build_tooltip()
            except Exception:
                pass  # Not critical

    # ── Internal ──────────────────────────────────────────────────

    def _build_tooltip(self) -> str:
        state = self._status.get("state", "watching")
        rules = self._status.get("rules_loaded", 0)
        return f"Watcher Agent — {state.capitalize()} | {rules} rule(s) loaded"

    def _run_tray(self) -> None:
        """Blocking tray loop — runs on its own thread."""
        try:
            state = self._status.get("state", "watching")
            icon_img = _load_or_build_icon(state)

            def _open_dashboard(icon, item):
                webbrowser.open(self._dashboard_url)

            def _toggle_pause(icon, item):
                current = self._status.get("state", "watching")
                if current == "watching":
                    self._status["state"] = "paused"
                    logger.info("Watcher PAUSED from tray.")
                elif current == "paused":
                    self._status["state"] = "watching"
                    logger.info("Watcher RESUMED from tray.")
                # Update icon
                icon.icon = _load_or_build_icon(self._status["state"])
                icon.title = self._build_tooltip()

            def _quit(icon, item):
                logger.info("Quit requested from tray.")
                icon.stop()
                if self._stop_callback:
                    self._stop_callback()

            menu = pystray.Menu(
                pystray.MenuItem("Open Dashboard", _open_dashboard, default=True),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Pause / Resume Watching", _toggle_pause),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Quit Watcher Agent", _quit),
            )

            self._icon = pystray.Icon(
                name="watcher_agent",
                icon=icon_img,
                title=self._build_tooltip(),
                menu=menu,
            )
            self._icon.run()
        except Exception as exc:
            logger.warning("Tray icon error: %s — tray disabled.", exc)
