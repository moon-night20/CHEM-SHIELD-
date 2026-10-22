from __future__ import annotations

import json
import re
from unittest.mock import call, patch

import pytest

from chem_shield_p8.dashboard.app import (
    DashboardRuntime,
    HMIReadOnlyClient,
    _safe_hmi_url,
    create_app,
)


class FakeRuntime:
    def __init__(self, data_dir):
        self.data_dir = data_dir

    def snapshot(self):
        return {
            "timestamp": "2025-01-02T03:04:05+00:00",
            "plant": {
                "temperature_c": 35.0,
                "pressure_bar": 2.0,
                "level_pct": 55.0,
                "flow_l_min": 8.0,
                "coolant_valve_pct": 40.0,
                "feed_pump_on": True,
                "relief_valve_open": False,
            },
            "physics_guard": {"physics_score": 0.1, "ml_score": 0.2},
            "compliance": {"score": 90},
            "threat_level": "NORMAL",
            "alerts": [],
            "timeline": [],
            "assets": [],
            "scenario": {"result": None},
            "response": {"decisions": []},
        }

    def start_scenario(self, scenario_id):
        if scenario_id != "sensor-replay":
            raise ValueError("Unknown synthetic scenario.")
        return self.snapshot()

    def set_playing(self, playing):
        return {"playing": playing}

    def step_scenario(self):
        return {"step": 1}


def make_app(tmp_path, **config):
    return create_app({
        "TESTING": True,
        "SECRET_KEY": "dashboard-test-key",
        "P8_DATA_DIR": tmp_path,
        "P8_RUNTIME": FakeRuntime(tmp_path),
        "P8_READ_EXISTING_HMI": False,
        **config,
    })


def test_dashboard_page_renders_without_external_cdn(tmp_path):
    response = make_app(tmp_path).test_client().get("/")
    assert response.status_code == 200
    assert b"OT Defense Dashboard" in response.data
    assert b"SIMULATION ONLY" in response.data
    assert b"Live machine health first" in response.data
    assert b"Machine status &amp; data flow" in response.data
    assert b"PROCESS SIMULATOR" in response.data
    assert b"Read-only monitoring" in response.data
    assert b"LOCAL REACTOR TWIN" in response.data
    assert b"https://" not in response.data


def test_dashboard_shows_accurate_p2_to_p5_backend_pipeline_and_shortcuts(tmp_path):
    response = make_app(tmp_path).test_client().get("/")
    html = response.data.decode()

    assert response.status_code == 200
    assert 'aria-label="Backend pipeline stage shortcuts"' in html
    for stage_id in ("p2", "p3", "p4", "p5"):
        assert f'href="#pipeline-stage-{stage_id}"' in html
        assert f'id="pipeline-stage-{stage_id}"' in html
    assert html.index('id="pipeline-stage-p2"') < html.index('id="pipeline-stage-p3"')
    assert html.index('id="pipeline-stage-p3"') < html.index('id="pipeline-stage-p4"')
    assert html.index('id="pipeline-stage-p4"') < html.index('id="pipeline-stage-p5"')
    assert "P2 + P3 events" in html
    assert "Telemetry input" in html
    assert "scripts.run_chain --step-by-step" in html
    assert "P5 writes a report" in html


def test_dashboard_api_requires_loopback(tmp_path):
    client = make_app(tmp_path).test_client()
    response = client.get("/api/snapshot", environ_base={"REMOTE_ADDR": "192.0.2.55"})
    assert response.status_code == 403
    assert b"loopback" in response.data


def test_dashboard_mutations_require_csrf_and_support_step_controls(tmp_path):
    client = make_app(tmp_path).test_client()
    response = client.post(
        "/api/scenarios/start",
        json={"scenario_id": "sensor-replay"},
    )
    assert response.status_code == 400

    page = client.get("/")
    token = re.search(rb'<meta name="csrf-token" content="([^"]+)"', page.data)
    assert token
    headers = {"X-CSRFToken": token.group(1).decode()}
    response = client.post(
        "/api/scenarios/start",
        json={"scenario_id": "sensor-replay"},
        headers=headers,
    )
    assert response.status_code == 200
    response = client.post(
        "/api/scenarios/playback",
        json={"playing": False},
        headers=headers,
    )
    assert response.status_code == 200
    response = client.post("/api/scenarios/step", json={}, headers=headers)
    assert response.status_code == 200


def test_dashboard_rejects_non_loopback_hmi_integration():
    for url in (
        "http://192.0.2.2:15000",
        "https://127.0.0.1:15000",
        "http://127.0.0.1:5001",
        "http://user@127.0.0.1:15000",
    ):
        with pytest.raises(ValueError, match="only to the existing HMI"):
            _safe_hmi_url(url)


def test_read_only_hmi_client_has_fixed_safe_origin():
    client = HMIReadOnlyClient()
    assert client.base_url == "http://127.0.0.1:15000"


def test_hmi_client_reads_live_machine_and_risk_apis_independently():
    state = {
        "motor_status": "RUNNING",
        "temperature": 46.2,
        "pressure": 2.3,
        "power": 4.1,
        "rpm": 1200,
        "target_rpm": 1400,
        "machine_condition": "NORMAL",
        "limit_alerts": [],
    }
    risk = {"active_incidents": []}
    client = HMIReadOnlyClient()

    with patch.object(client, "_get", side_effect=[state, risk]) as get:
        result = client.snapshot()

    assert result["connected"] is True
    assert result["state"] == state
    assert result["risk"] == risk
    assert get.call_args_list == [call("/api/state"), call("/api/risk")]


def test_hmi_state_remains_available_when_risk_api_is_unavailable():
    state = {"motor_status": "STOPPED", "machine_condition": "NORMAL", "limit_alerts": []}
    client = HMIReadOnlyClient()

    with patch.object(client, "_get", side_effect=[state, ValueError("risk feed offline")]):
        result = client.snapshot()

    assert result["connected"] is True
    assert result["state"] == state
    assert result["risk"] is None
    assert result["risk_error"] == "ValueError: risk feed offline"


def test_runtime_includes_read_only_machine_feed_in_dashboard_snapshot(tmp_path):
    runtime = DashboardRuntime(data_dir=tmp_path)
    machine_feed = {
        "connected": True,
        "state": {"motor_status": "RUNNING", "temperature": 46.2},
        "risk": {"active_incidents": []},
        "state_error": None,
        "risk_error": None,
        "fetched_at": "2026-10-22T18:00:00+00:00",
    }
    with patch.object(runtime.hmi, "snapshot", return_value=machine_feed):
        snapshot = runtime.advance(0.1)

    assert snapshot["existing_chem_shield"] == machine_feed


def test_real_dashboard_runtime_snapshot_is_serializable_and_stable(tmp_path):
    runtime = DashboardRuntime(data_dir=tmp_path, read_existing_hmi=False)
    initial = runtime.snapshot()
    initial_chain_records = len(runtime.sis_watch.chain.records())

    runtime.advance(0.1)
    updated = runtime.snapshot()

    assert initial["sis"]["latest"]["status"] == "INTACT"
    assert updated["sis"]["chain_integrity"]["ok"] is True
    assert len(runtime.sis_watch.chain.records()) == initial_chain_records
    assert updated["plant"]["temperature_c"] != initial["plant"]["temperature_c"]
    json.dumps(updated, allow_nan=False)


def test_report_endpoint_generates_and_serves_both_artifacts(tmp_path):
    client = make_app(tmp_path).test_client()
    page = client.get("/")
    token = re.search(rb'<meta name="csrf-token" content="([^"]+)"', page.data)
    assert token
    headers = {"X-CSRFToken": token.group(1).decode()}

    response = client.post("/api/reports", json={}, headers=headers)

    assert response.status_code == 201
    report = response.get_json()
    html_response = client.get(report["html_url"])
    pdf_response = client.get(report["pdf_url"])
    assert html_response.status_code == 200
    assert b"CHEM-SHIELD" in html_response.data
    assert pdf_response.status_code == 200
    assert pdf_response.data.startswith(b"%PDF-")
    assert client.get("/api/reports/../response-decisions.jsonl").status_code == 404
