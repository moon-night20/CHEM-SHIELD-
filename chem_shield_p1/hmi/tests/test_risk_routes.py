"""Flask API integration tests for correlated incident visibility."""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from chem_shield_p1.communication.device_connection import DeviceConnection
from chem_shield_p1.hmi.app import create_app


class RiskRouteTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.app = create_app(
            plc_host="127.0.0.1",
            plc_port=1,
            database=str(Path(self.temp_dir.name) / "hmi.db"),
        )
        self.app.config.update(TESTING=True)
        self.client = self.app.test_client()
        self.client.environ_base["HTTP_X_INGEST_TOKEN"] = self.app.config["INGEST_TOKEN"]

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_summary_starts_unassessed_not_low(self):
        response = self.client.get("/api/risk")
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["risk_level"], "UNASSESSED")
        self.assertIsNone(body["risk_score"])
        self.assertFalse(body["scores_are_probabilities"])

    def test_posted_event_is_correlated_persisted_and_acknowledged(self):
        response = self.client.post(
            "/api/risk/events",
            json={
                "event_id": "synthetic-ot-1",
                "timestamp": "2026-10-14T09:30:00Z",
                "source": "ot_monitor",
                "asset_id": "PLC-01",
                "event_type": "temperature_high",
                "severity": "high",
                "evidence": "synthetic test event",
                "anomaly_score": 1.0,
                "measurements": {"temperature": 92.0, "unit": "degC"},
            },
        )
        self.assertEqual(response.status_code, 200)
        incident = response.get_json()["incidents"][0]
        self.assertEqual(incident["risk_level"], "HIGH")
        self.assertEqual(incident["risk_score"], 0.6)
        incident_id = incident["incident_id"]

        history = self.client.get("/api/incidents").get_json()["incidents"]
        self.assertEqual(history[0]["incident_id"], incident_id)
        acknowledged = self.client.post(
            f"/api/incidents/{incident_id}/acknowledge",
            json={"acknowledged_by": "test-operator"},
        )
        self.assertEqual(acknowledged.status_code, 200)
        self.assertTrue(acknowledged.get_json()["acknowledged"])
        self.assertEqual(acknowledged.get_json()["risk_level"], "HIGH")
        self.assertEqual(self.client.get("/api/risk").get_json()["risk_level"], "HIGH")

    def test_rule_alert_without_score_remains_unassessed(self):
        response = self.client.post(
            "/api/risk/events",
            json={
                "event_id": "synthetic-unscored-1",
                "timestamp": "2026-10-14T09:30:00Z",
                "source": "ot_monitor",
                "asset_id": "PLC-02",
                "event_type": "pressure_high",
                "evidence": "synthetic rule alert",
            },
        )
        self.assertEqual(response.status_code, 200)
        incident = response.get_json()["incidents"][0]
        self.assertEqual(incident["risk_level"], "UNASSESSED")
        self.assertIsNone(incident["risk_score"])

    def test_existing_hmi_remains_available_when_plc_is_disconnected(self):
        response = self.client.get("/api/state")
        self.assertEqual(response.status_code, 503)
        self.assertIn("error", response.get_json())

    def test_live_machine_condition_is_critical_only_above_any_configured_limit(self):
        registers = [1, 1500, 1000, 6999, 399, 1199, 0, 0]

        class FakeClient:
            def read_holding_registers(self, address, count, slave):
                return SimpleNamespace(isError=lambda: False, registers=registers)

        fake_client = FakeClient()
        with (
            patch.object(DeviceConnection, "connect"),
            patch.object(
                DeviceConnection,
                "call",
                autospec=True,
                side_effect=lambda _device, action: action(fake_client),
            ),
        ):
            app = create_app(
                plc_host="127.0.0.1",
                plc_port=5020,
                database=str(Path(self.temp_dir.name) / "limits.db"),
            )
            app.config.update(TESTING=True)
            client = app.test_client()

            for sensor, value, event_sensor in (
                ("temperature", 7000, "temperature"),
                ("pressure", 400, "pressure"),
                ("power", 1200, "power"),
                ("rpm", 1500, "speed"),
            ):
                with self.subTest(sensor=sensor):
                    if sensor == "temperature":
                        registers[3] = value
                    elif sensor == "pressure":
                        registers[4] = value
                    elif sensor == "power":
                        registers[5] = value
                    else:
                        registers[2] = value
                    at_limit = client.get("/api/state").get_json()
                    self.assertEqual(at_limit["machine_condition"], "NORMAL")
                    self.assertEqual(at_limit["limit_alerts"], [])
                    self.assertEqual(at_limit["limits"]["temperature"]["high"], 70)
                    self.assertEqual(at_limit["limits"]["pressure"]["high"], 4)
                    self.assertEqual(at_limit["limits"]["power"]["high"], 12)
                    self.assertEqual(at_limit["limits"]["speed"]["high"], 1500)

                    if sensor == "temperature":
                        registers[3] += 1
                    elif sensor == "pressure":
                        registers[4] += 1
                    elif sensor == "power":
                        registers[5] += 1
                    else:
                        registers[2] += 1
                    above_limit = client.get("/api/state").get_json()
                    self.assertEqual(above_limit["machine_condition"], "CRITICAL")
                    self.assertEqual(
                        above_limit["limit_alerts"][0]["sensor"],
                        event_sensor,
                    )
                    self.assertEqual(above_limit["motor_status"], "RUNNING")

                    if sensor == "temperature":
                        registers[3] -= 2
                    elif sensor == "pressure":
                        registers[4] -= 2
                    elif sensor == "power":
                        registers[5] -= 2
                    else:
                        registers[2] -= 2
                    normal_again = client.get("/api/state").get_json()
                    self.assertEqual(normal_again["machine_condition"], "NORMAL")
                    self.assertEqual(normal_again["limit_alerts"], [])

    def _post_critical_incident(self):
        response = self.client.post(
            "/api/risk/events",
            json={"events": [
                {
                    "event_id": "p6-network",
                    "timestamp": "2026-10-14T09:30:00Z",
                    "source": "network_model",
                    "asset_id": "PLC-01",
                    "event_type": "network",
                    "severity": "high",
                    "evidence": {},
                    "anomaly_score": 1.0,
                },
                {
                    "event_id": "p6-physical",
                    "timestamp": "2026-10-14T09:30:01Z",
                    "source": "physical_ml",
                    "asset_id": "PLC-01",
                    "event_type": "physical",
                    "severity": "high",
                    "evidence": {},
                    "anomaly_score": 1.0,
                },
            ]},
        )
        self.assertEqual(response.status_code, 200)
        incident = response.get_json()["incidents"][0]
        self.assertEqual(incident["risk_level"], "CRITICAL")
        return incident["incident_id"]

    def test_p6_requires_page_token_operator_confirmation_and_critical_risk(self):
        token = self.app.config["P6_CONFIRM_TOKEN"]
        self.assertEqual(
            self.client.post(
                "/api/p6/respond",
                json={"incident_id": "missing", "confirm_stop": True},
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(
                "/api/p6/respond",
                json={"incident_id": "missing", "confirm_stop": True},
                headers={"X-Chem-Shield-P6-Confirmation": token},
            ).status_code,
            404,
        )
        incident_id = self._post_critical_incident()
        response = self.client.post(
            "/api/p6/respond",
            json={"incident_id": incident_id, "confirm_stop": False},
            headers={"X-Chem-Shield-P6-Confirmation": token},
        )
        self.assertEqual(response.status_code, 400)

        low_response = self.client.post(
            "/api/risk/events",
            json={
                "event_id": "p6-low-risk",
                "timestamp": "2026-10-14T09:40:00Z",
                "source": "network_model",
                "asset_id": "PLC-02",
                "event_type": "network",
                "severity": "low",
                "evidence": {},
                "anomaly_score": 0.1,
            },
        )
        self.assertEqual(low_response.status_code, 200)
        low_id = low_response.get_json()["incidents"][0]["incident_id"]
        response = self.client.post(
            "/api/p6/respond",
            json={"incident_id": low_id, "confirm_stop": True},
            headers={"X-Chem-Shield-P6-Confirmation": token},
        )
        self.assertEqual(response.status_code, 409)

    def test_p6_executes_only_after_explicit_loopback_confirmation(self):
        incident_id = self._post_critical_incident()
        token = self.app.config["P6_CONFIRM_TOKEN"]
        writes = []

        class FakeClient:
            def read_holding_registers(self, address, count, slave):
                return SimpleNamespace(
                    isError=lambda: False,
                    registers=[1, 1500, 100, 6200, 400, 1200, 0, 0],
                )

            def write_registers(self, address, values, slave):
                writes.append(("registers", address, values, slave))
                return SimpleNamespace(isError=lambda: False)

            def write_register(self, address, value, slave):
                writes.append(("register", address, value, slave))
                return SimpleNamespace(isError=lambda: False)

        fake_client = FakeClient()
        with patch.object(
            DeviceConnection,
            "call",
            autospec=True,
            side_effect=lambda _device, action: action(fake_client),
        ) as plc_call:
            response = self.client.post(
                "/api/p6/respond",
                json={"incident_id": incident_id, "confirm_stop": True},
                headers={"X-Chem-Shield-P6-Confirmation": token},
            )

        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(response.get_json()["motor_status"], "STOPPED")
        self.assertTrue(response.get_json()["simulation_only"])
        self.assertEqual(plc_call.call_count, 3)
        self.assertEqual(writes, [
            ("registers", 0, [0, 1500], 1),
            ("register", 6, 0, 1),
        ])
        events = self.client.get("/api/events").get_json()
        self.assertEqual(events[0]["event_type"], "P6_SIMULATED_STOP")

    def test_p6_refuses_non_loopback_machine_target(self):
        with patch.object(DeviceConnection, "connect", side_effect=ConnectionError):
            app = create_app(
                plc_host="192.0.2.10",
                plc_port=5020,
                database=str(Path(self.temp_dir.name) / "remote.db"),
            )
        app.config.update(TESTING=True)
        response = app.test_client().post(
            "/api/p6/respond",
            json={"incident_id": "INC-1", "confirm_stop": True},
            headers={
                "X-Chem-Shield-P6-Confirmation": app.config["P6_CONFIRM_TOKEN"]
            },
        )
        self.assertEqual(response.status_code, 403)

    def test_p6_refuses_non_loopback_caller(self):
        incident_id = self._post_critical_incident()
        response = self.client.post(
            "/api/p6/respond",
            json={"incident_id": incident_id, "confirm_stop": True},
            headers={
                "X-Chem-Shield-P6-Confirmation": self.app.config["P6_CONFIRM_TOKEN"]
            },
            environ_base={"REMOTE_ADDR": "192.0.2.5"},
        )
        self.assertEqual(response.status_code, 403)

    def test_p6_does_not_execute_without_request(self):
        with patch.object(DeviceConnection, "call", autospec=True) as plc_call:
            self._post_critical_incident()
        plc_call.assert_not_called()


if __name__ == "__main__":
    unittest.main()
