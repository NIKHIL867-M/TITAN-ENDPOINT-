"""
Regression test for the API-auth fail-closed fix.

Previously, local_api_auth's check only activated when GEKKO_API_TOKEN
happened to be set (desktop.py's native launcher sets it automatically). A
standalone `uvicorn app.main:app` launch -- the README's own Quick Start
command -- ran fully unauthenticated with no warning. Now: no token AND no
explicit gekko_allow_unauthenticated_local opt-in => /api/* refuses to
serve (503), not silently open.
"""
import os

from fastapi.testclient import TestClient


def test_no_token_no_opt_in_refuses_api_access(monkeypatch, tmp_path):
    """The exact regression this fix closes: token-less standalone launch."""
    monkeypatch.delenv("GEKKO_API_TOKEN", raising=False)
    monkeypatch.setenv("GEKKO_ALLOW_UNAUTHENTICATED_LOCAL", "false")
    from app.config import reset_settings
    from app import rule_store
    monkeypatch.setattr(rule_store, "_DATA_DIR", tmp_path)
    monkeypatch.setattr(rule_store, "_RULES_FILE", tmp_path / "rules.jsonl")
    reset_settings()

    from app import main
    with TestClient(main.app) as client:
        response = client.get("/api/rules")

    assert response.status_code == 503
    assert response.json()["error"] == "unauthenticated_launch_refused"
    reset_settings()


def test_health_endpoint_stays_reachable_even_when_locked(monkeypatch, tmp_path):
    """/api/health must stay reachable for monitoring even in the locked state."""
    monkeypatch.delenv("GEKKO_API_TOKEN", raising=False)
    monkeypatch.setenv("GEKKO_ALLOW_UNAUTHENTICATED_LOCAL", "false")
    from app.config import reset_settings
    reset_settings()

    from app import main
    with TestClient(main.app) as client:
        response = client.get("/api/health")

    assert response.status_code == 200
    reset_settings()


def test_explicit_opt_in_allows_token_less_access(monkeypatch, tmp_path):
    """Deliberately setting the opt-in flag restores the old localhost-only behavior."""
    monkeypatch.delenv("GEKKO_API_TOKEN", raising=False)
    monkeypatch.setenv("GEKKO_ALLOW_UNAUTHENTICATED_LOCAL", "true")
    from app.config import reset_settings
    from app import rule_store
    monkeypatch.setattr(rule_store, "_DATA_DIR", tmp_path)
    monkeypatch.setattr(rule_store, "_RULES_FILE", tmp_path / "rules.jsonl")
    reset_settings()

    from app import main
    with TestClient(main.app) as client:
        response = client.get("/api/rules")

    assert response.status_code == 200
    reset_settings()


def test_wrong_token_still_rejected_when_token_configured(monkeypatch, tmp_path):
    """When GEKKO_API_TOKEN IS set, the existing token-mismatch behavior is unchanged."""
    monkeypatch.setenv("GEKKO_API_TOKEN", "the-real-token")
    from app.config import reset_settings
    reset_settings()

    from app import main
    with TestClient(main.app) as client:
        response = client.get("/api/rules", headers={"X-GEKKO-Token": "wrong-token"})

    assert response.status_code == 401
    reset_settings()
