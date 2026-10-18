"""Optional loopback event-ingest token tests."""

from __future__ import annotations

from unittest.mock import patch

from chem_shield_p1.hmi.app import create_app


EVENT = {
    "event_id": "token-test-event",
    "timestamp": "2026-10-14T09:30:00Z",
    "source": "network_model",
    "asset_id": "PLC-01",
    "event_type": "network",
    "anomaly_score": 0.9,
    "severity": "high",
    "evidence": {"fixture": "synthetic test"},
}


def _hmi_client(monkeypatch, tmp_path, token=None):
    if token is None:
        monkeypatch.delenv("CHEM_SHIELD_INGEST_TOKEN", raising=False)
    else:
        monkeypatch.setenv("CHEM_SHIELD_INGEST_TOKEN", token)
    with patch("chem_shield_p1.hmi.app.DeviceConnection.connect", return_value=True):
        app = create_app(plc_port=1, database=str(tmp_path / "hmi.db"))
    app.config.update(TESTING=True)
    return app.test_client()


def test_ingest_token_is_optional_when_environment_is_unset(monkeypatch, tmp_path):
    client = _hmi_client(monkeypatch, tmp_path)
    response = client.post("/api/risk/events", json=EVENT)
    assert response.status_code == 200


def test_ingest_token_is_required_when_environment_is_set(monkeypatch, tmp_path):
    client = _hmi_client(monkeypatch, tmp_path, "local-ingest-secret")
    missing = client.post("/api/risk/events", json=EVENT)
    assert missing.status_code == 401
    rejected = client.post(
        "/api/risk/events",
        json=EVENT,
        headers={"X-Ingest-Token": "incorrect"},
    )
    assert rejected.status_code == 401
    accepted = client.post(
        "/api/risk/events",
        json=EVENT,
        headers={"X-Ingest-Token": "local-ingest-secret"},
    )
    assert accepted.status_code == 200
