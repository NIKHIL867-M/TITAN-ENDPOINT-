"""
Pytest fixtures for the test suite.

Provides a FastAPI test client and temporary data directories so tests
don't touch production data files.
"""
import os
import sys
import pytest

# Ensure project root is on sys.path so imports work
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


@pytest.fixture(autouse=True)
def _set_groq_api_key(monkeypatch):
    """Set a dummy GROQ_API_KEY so Settings() doesn't fail during tests."""
    monkeypatch.setenv("GROQ_API_KEY", "test-key-not-real")
    # local_api_auth fails closed by default when GEKKO_API_TOKEN is unset
    # (see app/config.py's gekko_allow_unauthenticated_local). Tests exercise
    # the API via TestClient without desktop.py's auto-generated token, so
    # explicitly opt in the same way a real local-dev launch would have to.
    monkeypatch.setenv("GEKKO_ALLOW_UNAUTHENTICATED_LOCAL", "true")


@pytest.fixture
def client(_set_groq_api_key, monkeypatch, tmp_path):
    """FastAPI test client with a fresh app instance."""
    # Reset settings singleton so test env vars take effect
    from app.config import reset_settings
    from app import rule_store
    monkeypatch.setattr(rule_store, "_DATA_DIR", tmp_path)
    monkeypatch.setattr(rule_store, "_RULES_FILE", tmp_path / "rules.jsonl")
    monkeypatch.setattr(rule_store, "_REJECTIONS_FILE", tmp_path / "rejections.jsonl")
    reset_settings()

    from fastapi.testclient import TestClient
    from app import main

    async def _offline_model_discovery():
        return []

    # Unit/integration tests must not depend on external Groq availability.
    # A separate explicit live smoke test covers the real service.
    monkeypatch.setattr(main, "discover_models", _offline_model_discovery)
    app = main.app
    with TestClient(app) as c:
        yield c
    reset_settings()


@pytest.fixture
def tmp_evidence_dir(tmp_path):
    """Provide a temporary evidence directory for retention tests."""
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    return evidence_dir
