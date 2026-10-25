from __future__ import annotations

import json
import re
from unittest.mock import call, patch

import pytest

from chem_shield_p8.dashboard.app import (
    DashboardRuntime,
    HMIReadOnlyClient,
    _safe_hmi_url,
    _safe_local_page_url,
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
    assert b"Live defense services, detector signals, and incident risk at a glance." in response.data
    assert b"Machine status &amp; data flow" in response.data
    assert b"PROCESS SIMULATOR" in response.data
    assert b"Read-only monitoring" in response.data
    assert b"LOCAL REACTOR TWIN" in response.data
    assert b"Reactor twin controls" in response.data
    assert b"STOP SIMULATED PUMP" in response.data
    assert b"connected machine HMI above remains read-only" in response.data
    assert b"Admin Console" in response.data
    assert b"OPEN UPDATED DASHBOARD" not in response.data
    assert b"15081" not in response.data
    assert b"Attack Console" in response.data
    assert b"https://" not in response.data


def test_dashboard_links_to_admin_attack_console_and_machine_hmi(tmp_path):
    response = make_app(
        tmp_path,
        P8_ADMIN_URL="http://127.0.0.1:5002/",
        P8_ATTACK_CONSOLE_URL="http://127.0.0.1:5003",
    ).test_client().get("/")
    html = response.data.decode()

    assert response.status_code == 200
    assert 'href="http://127.0.0.1:5002/dashboard"' in html
    for route in ("machine", "incidents", "p7/command-center", "users", "audit"):
        assert f'href="http://127.0.0.1:5002/{route}"' not in html
    assert 'href="http://127.0.0.1:5003/"' in html
    assert 'href="http://127.0.0.1:15000/"' in html
    assert html.count('target="_blank" rel="noopener noreferrer"') == 2


def test_dashboard_does_not_promote_a_second_p8_port(tmp_path):
    client = make_app(tmp_path).test_client()

    for port in ("15080", "15081"):
        response = client.get("/", base_url=f"http://127.0.0.1:{port}")
        assert b"OPEN UPDATED DASHBOARD" not in response.data
        assert b"15081" not in response.data


@pytest.mark.parametrize(
    "value",
    (
        "https://127.0.0.1:5000",
        "http://192.0.2.5:5000",
        "http://localhost:5000",
        "http://user@127.0.0.1:5000",
        "http://127.0.0.1:5000/dashboard",
        "http://127.0.0.1:5000/?next=http://example.com",
        "http://127.0.0.1:70000",
    ),
)
def test_local_console_links_reject_non_loopback_or_non_page_urls(value):
    with pytest.raises(ValueError, match="local HTTP page on 127.0.0.1"):
        _safe_local_page_url(value, name="admin-console", default="http://127.0.0.1:5000")


@pytest.mark.parametrize(
    "setting",
    ("P8_ADMIN_URL", "P8_ATTACK_CONSOLE_URL"),
)
def test_dashboard_rejects_unsafe_console_link_configuration(tmp_path, setting):
    with pytest.raises(ValueError, match="Unsafe P8 .* link setting"):
        make_app(tmp_path, **{setting: "https://example.com"})


def test_dashboard_has_compact_navigable_backend_views(tmp_path):
    response = make_app(tmp_path).test_client().get("/")
    html = response.data.decode()

    assert response.status_code == 200
    for view in ("overview", "machine", "network", "detection", "response", "backend"):
        assert f'data-view-target="{view}"' in html
        assert f'data-view-content="{view}"' in html
    assert "Backend operations at a glance" in html
    assert "RISK CORRELATION AND SCORING" in html
    assert "AI / ML &amp; Alerts" in html
    assert 'href="http://127.0.0.1:15000/"' in html


def test_dashboard_shows_accurate_p2_to_p5_backend_pipeline_and_shortcuts(tmp_path):
    response = make_app(tmp_path).test_client().get("/")
    html = response.data.decode()

    assert response.status_code == 200
    assert 'aria-label="Backend pipeline stage shortcuts"' in html
    for stage in ("network-scoring", "telemetry-analysis", "risk-correlation", "rule-validation"):
        assert f'href="#pipeline-{stage}"' in html
        assert f'id="pipeline-{stage}"' in html
    assert html.index('id="pipeline-network-scoring"') < html.index('id="pipeline-telemetry-analysis"')
    assert html.index('id="pipeline-telemetry-analysis"') < html.index('id="pipeline-risk-correlation"')
    assert html.index('id="pipeline-risk-correlation"') < html.index('id="pipeline-rule-validation"')
    assert "network + physical evidence" in html
    assert "Telemetry input" in html
    assert "scripts.run_chain --step-by-step" in html
    assert "final analysis step writes a validation report" in html
    for implementation_label in ("P1", "P2", "P3", "P4", "P5", "P7"):
        assert implementation_label not in html


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


def test_local_twin_controls_are_csrf_protected_and_validated(tmp_path):
    runtime = DashboardRuntime(data_dir=tmp_path, read_existing_hmi=False)
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "dashboard-test-key",
        "P8_DATA_DIR": tmp_path,
        "P8_RUNTIME": runtime,
        "P8_READ_EXISTING_HMI": False,
    })
    client = app.test_client()
    assert client.post("/api/twin/playback", json={"running": False}).status_code == 400

    page = client.get("/")
    token = re.search(rb'<meta name="csrf-token" content="([^"]+)"', page.data)
    assert token
    headers = {"X-CSRFToken": token.group(1).decode()}

    response = client.post(
        "/api/twin/playback",
        json={"running": False},
        headers=headers,
    )
    assert response.status_code == 200
    assert response.get_json()["simulation"]["running"] is False

    response = client.post(
        "/api/twin/controls",
        json={"feed_pump_on": False, "coolant_valve_pct": 75},
        headers=headers,
    )
    assert response.status_code == 200
    assert response.get_json()["simulation"]["controls"] == {
        "feed_pump_on": False,
        "coolant_valve_pct": 75.0,
        "relief_valve_open": None,
    }

    for payload in (
        {"coolant_valve_pct": 101},
        {"coolant_valve_pct": True},
        {"coolant_valve_pct": float("nan")},
        {"feed_pump_on": "false"},
        {"feed_pump_on": False, "external_target": "machine"},
        {},
    ):
        response = client.post("/api/twin/controls", json=payload, headers=headers)
        assert response.status_code == 400

    assert client.post(
        "/api/twin/playback",
        json={"running": 1},
        headers=headers,
    ).status_code == 400


def test_pausing_twin_freezes_only_local_process_updates(tmp_path):
    runtime = DashboardRuntime(data_dir=tmp_path, read_existing_hmi=False)
    runtime.set_simulation_running(False)
    before = runtime.twin.state.as_dict()

    runtime.advance(1.0)
    assert runtime.twin.state.as_dict() == before

    runtime.set_twin_controls(feed_pump_on=False, coolant_valve_pct=80)
    assert runtime.snapshot()["simulation"]["controls"]["feed_pump_on"] is False
    runtime.set_simulation_running(True)
    runtime.advance(1.0)
    assert runtime.twin.state.as_dict() != before


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


def test_backend_snapshot_runs_ot_summary_and_p4_risk_analysis(tmp_path):
    runtime = DashboardRuntime(data_dir=tmp_path, read_existing_hmi=False)
    runtime.start_scenario("setpoint-manipulation")
    runtime.step_scenario()

    backend = runtime.snapshot()["backend"]

    assert backend["network"]["event_count"] == 1
    assert backend["network"]["protocols"] == ["modbus-tcp"]
    assert backend["network"]["write_count"] == 1
    assert backend["alerts"]["count"] >= 1
    assert backend["correlation"]["validation_error_count"] == 0
    assert backend["correlation"]["incident_count"] == 1
    incident = backend["correlation"]["incidents"][0]
    assert incident["asset_id"] == "PLC-REACTOR-01"
    assert incident["network_present"] is True
    assert incident["risk"]["network_score"] == 1.0
    assert incident["risk"]["final_risk"] == 0.4
    json.dumps(backend, allow_nan=False)


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
