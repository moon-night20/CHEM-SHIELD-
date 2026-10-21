from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from chem_shield_p1.communication.device_connection import DeviceConnection
from chem_shield_p1.plc.register_map import (
    OVERRIDE_POWER,
    OVERRIDE_PRESSURE,
    OVERRIDE_SPEED,
    OVERRIDE_TEMPERATURE,
    REGISTER_COUNT,
    SIM_OVERRIDE_MASK,
    SIM_POWER,
    SIM_PRESSURE,
    SIM_SPEED,
    SIM_TEMPERATURE,
)
from chem_shield_p1.process.main import apply_simulation_overrides
from chem_shield_p1.hmi.app import create_app as create_hmi_app
from the_attack.app import PARAMETERS, create_app


class FakePLC:
    def __init__(self):
        self.registers = [0] * REGISTER_COUNT
        self.registers[1:8] = [1500, 0, 2000, 100, 20, 0, 0]

    def read_holding_registers(self, address, count, slave):
        assert (address, count, slave) in ((0, 8, 1), (SIM_OVERRIDE_MASK, 5, 1))
        return SimpleNamespace(
            isError=lambda: False,
            registers=self.registers[address:address + count],
        )

    def write_register(self, address, value, slave):
        assert slave == 1
        self.registers[address] = value
        return SimpleNamespace(isError=lambda: False)

    def write_registers(self, address, values, slave):
        assert slave == 1
        self.registers[address:address + len(values)] = values
        return SimpleNamespace(isError=lambda: False)


@pytest.fixture
def console(tmp_path):
    plc = FakePLC()
    with (
        patch.object(DeviceConnection, "connect", return_value={"status": "CONNECTED"}),
        patch.object(
            DeviceConnection,
            "call",
            autospec=True,
            side_effect=lambda _device, action: action(plc),
        ),
    ):
        app = create_app(
            database=tmp_path / "console.db",
        )
        app.config.update(TESTING=True)
        client = app.test_client()
        client.environ_base["REMOTE_ADDR"] = "127.0.0.1"
        client.environ_base["HTTP_X_CONSOLE_TOKEN"] = app.config["CSRF_TOKEN"]
        yield app, client, plc


def add_telemetry(app, *, temperature=20.0, pressure=1.0, power=0.2, rpm=0.0):
    app.extensions["ot_console_telemetry"].add_telemetry({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "machine_id": "M-01",
        "plc_id": "PLC-01",
        "motor_status": "STOPPED",
        "target_rpm": 1500,
        "rpm": rpm,
        "temperature": temperature,
        "pressure": pressure,
        "power": power,
    })


def test_console_page_and_dashboard_load(console):
    _app, client, _plc = console
    response = client.get("/")
    assert response.status_code == 200
    assert b"Set a machine value" in response.data
    assert b"Latest telemetry" not in response.data
    assert b"Command history" not in response.data
    assert b'"power": 12.0' in response.data
    dashboard = client.get("/api/dashboard")
    assert dashboard.status_code == 200
    assert dashboard.get_json()["simulation_only"] is True
    assert dashboard.get_json()["plc_state"]["target_rpm"] == 1500


def test_temperature_override_waits_for_measurement(console):
    app, client, plc = console
    add_telemetry(app, temperature=20.0)

    response = client.post(
        "/api/commands",
        json={"parameter": "temperature", "value": 100},
    )

    assert response.status_code == 202
    body = response.get_json()
    assert body["status"] == "accepted"
    assert body["requested_value"] == 100
    assert body["observed_value"] is None
    assert plc.registers[SIM_OVERRIDE_MASK] & OVERRIDE_TEMPERATURE
    assert plc.registers[SIM_TEMPERATURE] == 10000


def test_command_reconnects_after_stale_plc_connection(console):
    app, client, plc = console
    add_telemetry(app, temperature=20.0)
    attempts = 0

    def fail_once_then_run(action):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise BrokenPipeError("stale PLC socket")
        return action(plc)

    with (
        patch.object(DeviceConnection, "call", side_effect=fail_once_then_run),
        patch.object(DeviceConnection, "reconnect", return_value={"status": "CONNECTED"}) as reconnect,
    ):
        response = client.post(
            "/api/commands",
            json={"parameter": "temperature", "value": 55},
        )

    assert response.status_code == 202
    assert plc.registers[SIM_OVERRIDE_MASK] & OVERRIDE_TEMPERATURE
    assert plc.registers[SIM_TEMPERATURE] == 5500
    reconnect.assert_called_once()
    assert attempts == 2


def test_direct_value_overrides_are_applied_to_simulator_state():
    state = SimpleNamespace(rpm=1450.0, temperature=60.0, pressure=4.0, power=12.0)
    registers = [0] * REGISTER_COUNT
    registers[SIM_OVERRIDE_MASK] = (
        OVERRIDE_TEMPERATURE | OVERRIDE_PRESSURE | OVERRIDE_POWER | OVERRIDE_SPEED
    )
    registers[SIM_TEMPERATURE] = 7000
    registers[SIM_PRESSURE] = 250
    registers[SIM_POWER] = 800
    registers[SIM_SPEED] = 1200
    apply_simulation_overrides(state, registers)
    assert state.temperature == 70
    assert state.pressure == 2.5
    assert state.power == 8
    assert state.rpm == 1200


@pytest.mark.parametrize(
    ("parameter", "value", "bit", "register", "scale", "telemetry_key"),
    [
        ("temperature", 75.0, OVERRIDE_TEMPERATURE, SIM_TEMPERATURE, 100, "temperature"),
        ("power", 13.0, OVERRIDE_POWER, SIM_POWER, 100, "power"),
        ("pressure", 4.5, OVERRIDE_PRESSURE, SIM_PRESSURE, 100, "pressure"),
        ("speed", 1600, OVERRIDE_SPEED, SIM_SPEED, 1, "rpm"),
    ],
)
def test_all_machine_values_are_set_and_observed(
    console, parameter, value, bit, register, scale, telemetry_key
):
    app, client, plc = console
    add_telemetry(app, temperature=60, pressure=4, rpm=1450)
    response = client.post(
        "/api/commands",
        json={"parameter": parameter, "value": value},
    )

    assert response.status_code == 202
    assert response.get_json()["status"] == "accepted"
    assert plc.registers[SIM_OVERRIDE_MASK] & bit
    assert plc.registers[register] == round(value * scale)

    sample = {
        "temperature": 60,
        "pressure": 4,
        "rpm": 1450,
    }
    sample[telemetry_key] = value
    add_telemetry(app, **sample)
    history = client.get("/api/commands").get_json()["commands"]
    assert history[0]["status"] == "observed"
    assert history[0]["observed_value"] == value
    assert history[0]["exceeded_limit"] == 1
    assert "exceeds the configured upper limit" in history[0]["warning"]


def test_clear_overrides_resumes_process_values_and_records_event(console):
    app, client, plc = console
    plc.registers[SIM_OVERRIDE_MASK] = OVERRIDE_TEMPERATURE | OVERRIDE_SPEED
    plc.registers[SIM_TEMPERATURE] = 7000
    plc.registers[SIM_SPEED] = 1200

    response = client.post("/api/overrides/clear", json={})

    assert response.status_code == 202
    assert plc.registers[SIM_OVERRIDE_MASK] == 0
    assert "cleared" in response.get_json()["message"]
    events = app.extensions["ot_console_telemetry"].recent_events()
    assert events[0]["event_type"] == "SIMULATION_OVERRIDES_CLEARED"


def test_dashboard_reports_active_override_values(console):
    _app, client, plc = console
    plc.registers[SIM_OVERRIDE_MASK] = OVERRIDE_TEMPERATURE | OVERRIDE_SPEED
    plc.registers[SIM_TEMPERATURE] = 7000
    plc.registers[SIM_SPEED] = 1200

    dashboard = client.get("/api/dashboard").get_json()

    assert dashboard["overrides"]["temperature"] == {"enabled": True, "value": 70.0}
    assert dashboard["overrides"]["speed"] == {"enabled": True, "value": 1200.0}
    assert dashboard["overrides"]["pressure"]["enabled"] is False


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"parameter": "event", "value": 1}, "Choose temperature"),
        ({"parameter": "speed", "value": "fast"}, "finite JSON number"),
        ({"parameter": "speed", "value": 3001}, "between 0 and 3000"),
        ({"parameter": "speed", "value": 1000.5}, "whole number"),
        ({"parameter": [], "value": 1}, "Choose temperature"),
    ],
)
def test_invalid_requests_are_rejected_and_audited(console, payload, message):
    app, client, _plc = console
    response = client.post("/api/commands", json=payload)
    assert response.status_code == 400
    assert message in response.get_json()["error"]
    rows = app.extensions["ot_console_commands"].recent()
    assert rows[0]["status"] == "rejected"


def test_speed_override_is_not_reported_as_observed_until_new_telemetry(console):
    app, client, plc = console
    add_telemetry(app, rpm=0.0)

    response = client.post(
        "/api/commands",
        json={"parameter": "speed", "value": 2400},
    )

    assert response.status_code == 202
    assert plc.registers[SIM_SPEED] == 2400
    assert response.get_json()["observed_value"] is None
    history = client.get("/api/commands").get_json()["commands"]
    assert history[0]["status"] == "accepted"
    assert history[0]["observed_value"] is None


def test_later_abnormal_telemetry_records_warning_and_publishes_risk_incident(console):
    app, client, _plc = console
    add_telemetry(app, temperature=20.0)
    accepted = client.post(
        "/api/commands",
        json={"parameter": "temperature", "value": 100},
    )
    assert accepted.status_code == 202

    add_telemetry(app, temperature=86.5)
    hmi = create_hmi_app(
        plc_host="127.0.0.1",
        plc_port=1,
        database=str(app.extensions["ot_console_commands"].path),
    )
    hmi.config.update(TESTING=True)
    hmi_client = hmi.test_client()
    published = []

    def capture(events):
        published.extend(events)
        response = hmi_client.post(
            "/api/risk/events",
            json={"events": events},
            headers={"X-Ingest-Token": hmi.config["INGEST_TOKEN"]},
        )
        body = response.get_json()
        return {
            "accepted": body["accepted"],
            "rejected": body["rejected"],
            "failed_batches": 0 if response.status_code == 200 else 1,
            "errors": body.get("errors", []),
        }

    with patch("the_attack.app.publish_events", side_effect=capture):
        dashboard = client.get("/api/dashboard").get_json()
        history = client.get("/api/commands").get_json()["commands"]

    assert dashboard["alerts"][0]["parameter"] == "temperature"
    assert history[0]["status"] == "observed"
    assert history[0]["requested_value"] == "100.0"
    assert history[0]["observed_value"] == 86.5
    assert history[0]["exceeded_limit"] == 1
    assert "exceeds the configured upper limit" in history[0]["warning"]
    assert history[0]["incident_status"] == "Risk event saved to HMI incident register"
    assert published[0]["event_type"] == "physical"
    assert published[0]["source"] == "ot_command_console"
    assert published[0]["anomaly_score"] == 1.0
    assert published[0]["evidence"]["value"] == 86.5
    assert published[0]["evidence"]["configured_threshold"] == 70
    incidents = hmi_client.get("/api/incidents").get_json()["incidents"]
    assert len(incidents) == 1
    assert incidents[0]["risk_level"] == "HIGH"
    assert incidents[0]["events"][0]["source"] == "ot_command_console"
    events = app.extensions["ot_console_telemetry"].recent_events()
    assert any(
        event["source"] == "OT_COMMAND_CONSOLE"
        and event["event_type"] == "temperature_high"
        for event in events
    )


def test_commands_require_fresh_telemetry(console):
    _app, client, _plc = console
    response = client.post(
        "/api/commands",
        json={"parameter": "pressure", "value": 6},
    )
    assert response.status_code == 503
    assert response.get_json()["status"] == "rejected"


def test_lower_override_value_is_accepted(console):
    app, client, _plc = console
    add_telemetry(app, temperature=45.0)
    response = client.post(
        "/api/commands",
        json={"parameter": "temperature", "value": 40},
    )
    assert response.status_code == 202
    assert response.get_json()["requested_value"] == 40


def test_override_is_applied_while_event_code_is_set(console):
    app, client, plc = console
    add_telemetry(app, temperature=20.0)
    plc.registers[6] = 5
    response = client.post(
        "/api/commands",
        json={"parameter": "temperature", "value": 100},
    )
    assert response.status_code == 202
    assert plc.registers[6] == 5
    assert plc.registers[SIM_TEMPERATURE] == 10000
    assert app.extensions["ot_console_commands"].recent()[0]["status"] == "accepted"


def test_disconnected_plc_is_reported_and_command_is_audited(console):
    app, client, _plc = console
    with patch.object(
        DeviceConnection,
        "call",
        side_effect=ConnectionError("Device is disconnected"),
    ):
        response = client.post(
            "/api/commands",
            json={"parameter": "speed", "value": 1000},
        )
        dashboard = client.get("/api/dashboard").get_json()

    assert response.status_code == 503
    assert response.get_json()["status"] == "rejected"
    assert dashboard["plc_error"] == "Device is disconnected"
    assert app.extensions["ot_console_commands"].recent()[0]["status"] == "rejected"


def test_command_requires_console_token(console):
    _app, client, _plc = console
    response = client.post(
        "/api/commands",
        json={"parameter": "speed", "value": 1000},
        headers={"X-Console-Token": "wrong"},
    )
    assert response.status_code == 403


def test_remote_plc_host_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="PLC-01 at 127.0.0.1"):
        create_app(plc_host="192.0.2.10", database=tmp_path / "remote.db")


def test_nonstandard_local_plc_port_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="simulator port 15020"):
        create_app(plc_port=15021, database=tmp_path / "other-port.db")
