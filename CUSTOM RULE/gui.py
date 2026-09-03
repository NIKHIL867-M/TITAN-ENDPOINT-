"""Visible GEKKO Qt client for an already-running local API."""

from native_gui import run_native_gui


if __name__ == "__main__":
    raise SystemExit(run_native_gui("http://127.0.0.1:8765"))
