from __future__ import annotations

import json

from fastapi.testclient import TestClient

from app import main
from app.config import Settings


def test_alert_feed_returns_newest_page_with_bounded_retention(monkeypatch, tmp_path):
    alerts = tmp_path / "alerts.jsonl"
    with alerts.open("w", encoding="utf-8") as handle:
        for index in range(250):
            handle.write(json.dumps({"id": str(index), "fired_at": f"{index:04d}"}) + "\n")
    monkeypatch.setattr(main, "_ALERTS_FILE", alerts)
    response = TestClient(main.app).get("/api/alerts?page=1&limit=10")
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 250
    assert [row["id"] for row in payload["alerts"]] == [str(i) for i in range(239, 229, -1)]


def test_llm_output_has_a_bounded_default():
    settings = Settings(groq_api_key="test")
    assert 512 <= settings.max_llm_output_tokens <= 8192
