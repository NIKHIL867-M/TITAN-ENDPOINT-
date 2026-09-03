"""Reliable native Qt desktop launcher for GEKKO."""

import socket
import os
import secrets
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

from native_gui import run_native_gui
from PySide6.QtWidgets import QApplication, QMessageBox


HOST = "127.0.0.1"
PORT = 8765


def _child_python() -> str:
    """Use console Python for headless children even when GUI uses pythonw."""
    executable = Path(sys.executable)
    if executable.name.lower() == "pythonw.exe":
        console = executable.with_name("python.exe")
        if console.exists():
            return str(console)
    return str(executable)


def _is_ready() -> bool:
    try:
        request = urllib.request.Request(f"http://{HOST}:{PORT}/api/health")
        token = os.environ.get("GEKKO_API_TOKEN")
        if token:
            request.add_header("X-GEKKO-Token", token)
        with urllib.request.urlopen(request, timeout=0.75) as response:
            return response.status == 200
    except Exception:
        return False


class _EmbeddedApi:
    """Run uvicorn inside the desktop process to avoid a second interpreter."""

    def __init__(self) -> None:
        import uvicorn

        config = uvicorn.Config(
            "app.main:app", host=HOST, port=PORT, log_level="warning",
            access_log=False,
        )
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(
            target=self.server.run, name="gekko-api", daemon=True,
        )

    def start(self) -> None:
        self.thread.start()

    def poll(self) -> int | None:
        return None if self.thread.is_alive() else 1

    @property
    def returncode(self) -> int | None:
        return self.poll()

    def terminate(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=5.0)


def _wait_until_ready(timeout: float = 60.0, process=None) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if _is_ready(): return
        except Exception:
            pass
        if process is not None and process.poll() is not None:
            raise RuntimeError(f"The local API exited during startup (code {process.returncode}).")
        time.sleep(0.1)
    raise RuntimeError("The local application server did not start in time")


def _token_file() -> Path:
    return Path(__file__).resolve().parent / "data" / "secrets" / "gekko_api_token.dpapi"


def _publish_token(token: str) -> None:
    """
    Write the per-launch API token so the separate WPF GUI process (TitanEndpoint.App,
    which cannot see this process's environment) can authenticate its Custom Rule
    wizard calls against the fail-closed /api/* auth (see Round 3's API auth fix in
    TITAN_MASTER_CONTEXT.md). DPAPI-encrypted with the same shared/secret_store.py
    convention already used for the Groq key -- .NET's ProtectedData.Unprotect with
    DataProtectionScope.CurrentUser reads the identical CryptProtectData blob format,
    so no new cross-language protocol is needed. Best-effort: if this fails, the GUI's
    wizard simply reports the API as unreachable rather than crashing anything here.
    """
    try:
        from shared.secret_store import save_encrypted_secret, dpapi_available
        if dpapi_available():
            save_encrypted_secret(_token_file(), token, description="GEKKO API token")
    except Exception:
        pass


def _start_api() -> _EmbeddedApi | None:
    """Use an existing healthy API or host one inside the desktop process."""
    if _is_ready():
        return None
    os.environ.setdefault("GEKKO_API_TOKEN", secrets.token_urlsafe(32))
    _publish_token(os.environ["GEKKO_API_TOKEN"])
    api = _EmbeddedApi()
    api.start()
    _wait_until_ready(process=api)
    return api


def _watcher_running(pid_file: Path) -> bool:
    try:
        import psutil
        pid = int(pid_file.read_text().strip())
        process = psutil.Process(pid)
        return process.is_running() and "watcher.main" in " ".join(process.cmdline())
    except (OSError, ValueError, psutil.Error):
        return False


def main() -> None:
    api_process: _EmbeddedApi | None = None
    try:
        api_process = _start_api()
    except RuntimeError as exc:
        app = QApplication.instance() or QApplication([])
        QMessageBox.critical(None, "Startup Failed", f"{exc}\nCheck whether port {PORT} is occupied and inspect logs/backend.log.")
        return
    if os.environ.get("DESKTOP_START_WATCHER", "true").lower() == "true":
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        pid_file = Path(__file__).resolve().parent / "data" / "watcher.pid"
        running = _watcher_running(pid_file)
        if not running:
            subprocess.Popen(
            [_child_python(), "-m", "watcher.main"],
            cwd=os.path.dirname(os.path.abspath(__file__)),
            creationflags=creationflags,
            )
    try:
        run_native_gui(f"http://{HOST}:{PORT}")
    finally:
        if api_process is not None and api_process.poll() is None:
            api_process.terminate()
        if api_process is not None:
            try:
                _token_file().unlink(missing_ok=True)
            except OSError:
                pass


if __name__ == "__main__":
    main()
