"""Flask API integration tests for correlated incident visibility."""

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from chem_shield_p1.communication.device_connection import DeviceConnection
from chem_shield_p1.hmi.app import create_app
from chem_shield_p4.correlation.incident_store import IncidentStore


class RiskRouteTests(unittest.TestCase):
    @staticmethod
    def current_timestamp(seconds_ago=0):
        from datetime import timedelta

        return (
            datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)
        ).isoformat().replace("+00:00", "Z")

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
        self.app.extensions["stop_background_tasks"]()
        self.temp_dir.cleanup()

    def test_summary_starts_unassessed_not_low(self):
        response = self.client.get("/api/risk")
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["risk_level"], "UNASSESSED")
        self.assertIsNone(body["risk_score"])
        self.assertFalse(body["scores_are_probabilities"])

    def test_operator_page_hides_sensor_limit_targets(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Mode", response.data)
        self.assertNotIn(b"70.0 \xc2\xb0C", response.data)
        self.assertNotIn(b"4.00 bar", response.data)
        self.assertNotIn(b"12.00 kW", response.data)
        self.assertIn(b'max="1450" value="1400"', response.data)

    def test_control_caps_speed_target_below_operating_limit(self):
        registers = [1, 1500, 1400, 6500, 350, 1100, 0, 0]

        class FakeClient:
            def read_holding_registers(self, address, count, slave):
                return SimpleNamespace(
                    isError=lambda: False,
                    registers=registers[address:address + count],
                )

            def write_registers(self, address, values, slave):
                registers[address:address + len(values)] = values
                return SimpleNamespace(isError=lambda: False)

            def write_register(self, address, value, slave):
                registers[address] = value
                return SimpleNamespace(isError=lambda: False)

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
            response = self.client.post(
                "/api/control",
                json={"action": "setpoint", "target_rpm": 3000},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["target_rpm"], 1450)
        self.assertEqual(registers[1], 1450)

    def test_operator_stop_clears_all_four_simulation_overrides(self):
        registers = [1, 1200, 900, 6500, 350, 1100, 0, 0, 15, 9000, 800, 1500, 2200]
        writes = []

        class FakeClient:
            def read_holding_registers(self, address, count, slave):
                return SimpleNamespace(
                    isError=lambda: False,
                    registers=registers[address:address + count],
                )

            def write_registers(self, address, values, slave):
                writes.append(("registers", address, values, slave))
                registers[address:address + len(values)] = values
                return SimpleNamespace(isError=lambda: False)

            def write_register(self, address, value, slave):
                writes.append(("register", address, value, slave))
                registers[address] = value
                return SimpleNamespace(isError=lambda: False)

        fake_client = FakeClient()
        with patch.object(
            DeviceConnection,
            "call",
            autospec=True,
            side_effect=lambda _device, action: action(fake_client),
        ):
            response = self.client.post(
                "/api/control",
                json={"action": "stop", "target_rpm": 1200},
            )

        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(registers[0], 0)
        self.assertEqual(registers[6], 0)
        self.assertEqual(registers[8], 0)
        self.assertEqual(
            writes,
            [
                ("registers", 0, [0, 1200], 1),
                ("register", 8, 0, 1),
                ("register", 6, 0, 1),
            ],
        )

    def test_posted_event_is_correlated_persisted_and_acknowledged(self):
        response = self.client.post(
            "/api/risk/events",
            json={
                "event_id": "synthetic-ot-1",
                "timestamp": self.current_timestamp(),
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
                "timestamp": self.current_timestamp(),
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

    def test_medium_incident_warning_includes_sensor_value_limit_and_time(self):
        accepted = self.client.post(
            "/api/risk/events",
            json={
                "event_id": "warning-details-temperature-high",
                "timestamp": self.current_timestamp(),
                "source": "ot_monitor",
                "asset_id": "PLC-01",
                "event_type": "physical",
                "severity": "medium",
                "anomaly_score": 0.7,
                "evidence": {
                    "sensor": "temperature",
                    "rule_id": "TEMPERATURE-HIGH",
                    "value": 90,
                    "unit": "degC",
                    "configured_threshold": 70,
                    "message": "temperature exceeded configured high limit",
                },
            },
        )
        self.assertEqual(accepted.status_code, 200)

        warning = self.client.get("/api/risk").get_json()["active_incidents"][0][
            "warning_details"
        ][0]
        summary = self.client.get("/api/risk").get_json()
        self.assertEqual(summary["popup_candidates"], [])
        self.assertEqual(warning["asset_id"], "PLC-01")
        self.assertEqual(warning["trigger"], "temperature / TEMPERATURE-HIGH")
        self.assertEqual(warning["comparison"], "90 degC vs limit 70 degC")
        self.assertEqual(warning["timestamp"], accepted.get_json()["incidents"][0]["events"][0]["timestamp"])

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
            try:
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
                        self.assertNotIn("limits", at_limit)

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
                        elif sensor == "rpm":
                            registers[2] -= 2
                        normal_again = client.get("/api/state").get_json()
                        self.assertEqual(normal_again["machine_condition"], "NORMAL")
                        self.assertEqual(normal_again["limit_alerts"], [])
            finally:
                app.extensions["stop_background_tasks"]()

    def _post_critical_incident(self):
        response = self.client.post(
            "/api/risk/events",
            json={"events": [
                {
                    "event_id": "p6-network",
                    "timestamp": self.current_timestamp(2),
                    "source": "network_model",
                    "asset_id": "PLC-01",
                    "event_type": "network",
                    "severity": "high",
                    "evidence": {},
                    "anomaly_score": 1.0,
                },
                {
                    "event_id": "p6-physical",
                    "timestamp": self.current_timestamp(),
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
                "timestamp": self.current_timestamp(),
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
        self.assertEqual(plc_call.call_count, 4)
        self.assertEqual(writes, [
            ("registers", 0, [0, 1500], 1),
            ("register", 8, 0, 1),
            ("register", 6, 0, 1),
        ])
        events = self.client.get("/api/events").get_json()
        self.assertEqual(events[0]["event_type"], "P6_SIMULATED_STOP")

    def test_critical_warning_and_acknowledgement_do_not_stop_without_confirmation(self):
        token = self.app.config["P6_CONFIRM_TOKEN"]
        with patch.object(
            DeviceConnection,
            "call",
            autospec=True,
        ) as plc_call:
            incident_id = self._post_critical_incident()
            summary = self.client.get("/api/risk").get_json()
            self.assertEqual(summary["active_incidents"][0]["risk_level"], "CRITICAL")

            response = self.client.post(
                f"/api/incidents/{incident_id}/acknowledge",
                json={"acknowledged_by": "operator", "p6_followup": True},
                headers={"X-Chem-Shield-P6-Confirmation": token},
            )
            self.assertEqual(response.status_code, 200, response.get_json())
            self.assertTrue(response.get_json()["p6_response_available"])
            plc_call.assert_not_called()

    def test_noncritical_incidents_do_not_offer_simulated_stop(self):
        token = self.app.config["P6_CONFIRM_TOKEN"]
        response = self.client.post(
            "/api/risk/events",
            json={
                "event_id": "p6-high-risk-ack",
                "timestamp": self.current_timestamp(),
                "source": "network_model",
                "asset_id": "PLC-02",
                "event_type": "network",
                "severity": "high",
                "evidence": {},
                "anomaly_score": 1.0,
            },
        )
        self.assertEqual(response.get_json()["incidents"][0]["risk_level"], "MEDIUM")
        incident_id = response.get_json()["incidents"][0]["incident_id"]
        acknowledged = self.client.post(
            f"/api/incidents/{incident_id}/acknowledge",
            json={"acknowledged_by": "operator", "p6_followup": True},
            headers={"X-Chem-Shield-P6-Confirmation": token},
        )
        self.assertEqual(acknowledged.status_code, 200)
        self.assertFalse(acknowledged.get_json()["p6_response_available"])

    def test_p6_refuses_non_loopback_machine_target(self):
        with patch.object(DeviceConnection, "connect", side_effect=ConnectionError):
            app = create_app(
                plc_host="192.0.2.10",
                plc_port=5020,
                database=str(Path(self.temp_dir.name) / "remote.db"),
            )
        app.config.update(TESTING=True)
        try:
            response = app.test_client().post(
                "/api/p6/respond",
                json={"incident_id": "INC-1", "confirm_stop": True},
                headers={
                    "X-Chem-Shield-P6-Confirmation": app.config["P6_CONFIRM_TOKEN"]
                },
            )
            self.assertEqual(response.status_code, 403)
        finally:
            app.extensions["stop_background_tasks"]()

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

    def test_stale_critical_database_row_is_not_a_popup_candidate_or_stop_timer(self):
        database = Path(self.temp_dir.name) / "stale.db"
        store = IncidentStore(database)
        timestamp = self.current_timestamp(180)
        event = {
            "event_id": "stale-critical",
            "timestamp": timestamp,
            "source": "physical_ml",
            "event_type": "physical",
            "severity": "high",
            "anomaly_score": 1.0,
            "evidence": {},
        }
        store.save_incident({
            "incident_id": "INC-STALE",
            "asset_id": "PLC-01",
            "start_time": timestamp,
            "end_time": timestamp,
            "last_event_time": timestamp,
            "status": "ACTIVE",
            "risk_level": "CRITICAL",
            "risk_score": 1.0,
            "risk_assessment": {},
            "events": [event],
        }, [event])
        app = create_app(
            plc_host="127.0.0.1",
            plc_port=1,
            database=str(database),
        )
        app.config.update(TESTING=True, P6_AUTO_STOP_SECONDS=0.05)
        try:
            summary = app.test_client().get("/api/risk").get_json()
            self.assertEqual(summary["active_incidents"], [])
            self.assertEqual(summary["popup_candidates"], [])
            self.assertEqual(app.extensions["p6_stop_timers"], {})
            self.assertEqual(
                store.get_incident("INC-STALE")["status"],
                "ACTIVE",
            )
        finally:
            app.extensions["stop_background_tasks"]()

    def test_startup_resolves_old_active_incident_and_keeps_history(self):
        database = Path(self.temp_dir.name) / "startup-stale.db"
        store = IncidentStore(database)
        timestamp = self.current_timestamp(400)
        event = {
            "event_id": "startup-stale",
            "timestamp": timestamp,
            "source": "physical_ml",
            "event_type": "physical",
            "severity": "high",
            "anomaly_score": 1.0,
            "evidence": {},
        }
        store.save_incident({
            "incident_id": "INC-STARTUP-STALE",
            "asset_id": "PLC-01",
            "start_time": timestamp,
            "end_time": timestamp,
            "last_event_time": timestamp,
            "status": "ACTIVE",
            "risk_level": "CRITICAL",
            "risk_score": 1.0,
            "risk_assessment": {},
            "events": [event],
        }, [event])
        app = create_app(
            plc_host="127.0.0.1",
            plc_port=1,
            database=str(database),
        )
        try:
            incident = store.get_incident("INC-STARTUP-STALE")
            self.assertEqual(incident["status"], "RESOLVED")
            self.assertEqual(incident["resolved_reason"], "stale at startup")
            self.assertTrue(app.test_client().get("/api/risk").get_json()["popup_candidates"] == [])
            self.assertEqual(
                app.test_client().get("/api/incidents").get_json()["incidents"][0]["incident_id"],
                "INC-STARTUP-STALE",
            )
        finally:
            app.extensions["stop_background_tasks"]()

    def test_normal_readings_cancel_countdown_and_resolve_after_30_seconds(self):
        app = self.app
        client = self.client
        incident_id = self._post_critical_incident()
        self.assertIn(incident_id, app.extensions["p6_stop_timers"])

        normal_state = {
            "temperature": 65.0,
            "pressure": 3.5,
            "power": 11.0,
            "rpm": 1400,
        }
        lifecycle_check = app.extensions["incident_lifecycle_check"]
        lifecycle_check(normal_state, now=100.0)
        self.assertNotIn(incident_id, app.extensions["p6_stop_timers"])
        lifecycle_check(normal_state, now=129.0)
        self.assertEqual(
            IncidentStore(Path(self.temp_dir.name) / "hmi.db")
            .get_incident(incident_id)["status"],
            "ACTIVE",
        )
        lifecycle_check(normal_state, now=130.0)
        self.assertEqual(
            IncidentStore(Path(self.temp_dir.name) / "hmi.db")
            .get_incident(incident_id)["resolved_reason"],
            "readings_normal",
        )
        events = client.get("/api/events").get_json()
        self.assertIn("P6_AUTO_CANCELLED", [event["event_type"] for event in events])

    def test_fresh_critical_incident_auto_stops_after_configured_delay(self):
        app = create_app(
            plc_host="127.0.0.1",
            plc_port=1,
            database=str(Path(self.temp_dir.name) / "auto-stop.db"),
        )
        app.config.update(TESTING=True, P6_AUTO_STOP_SECONDS=0.05)
        registers = [1, 1400, 1400, 9000, 350, 1100, 0, 0, 15]

        class FakeClient:
            def read_holding_registers(self, address, count, slave):
                return SimpleNamespace(
                    isError=lambda: False,
                    registers=registers[address:address + count],
                )

            def write_registers(self, address, values, slave):
                registers[address:address + len(values)] = values
                return SimpleNamespace(isError=lambda: False)

            def write_register(self, address, value, slave):
                registers[address] = value
                return SimpleNamespace(isError=lambda: False)

        fake_client = FakeClient()
        client = app.test_client()
        client.environ_base["HTTP_X_INGEST_TOKEN"] = app.config["INGEST_TOKEN"]
        try:
            with patch.object(
                DeviceConnection,
                "call",
                autospec=True,
                side_effect=lambda _device, action: action(fake_client),
            ):
                response = client.post("/api/risk/events", json={"events": [
                    {
                        "event_id": "auto-stop-network",
                        "timestamp": self.current_timestamp(2),
                        "source": "network_model",
                        "asset_id": "PLC-01",
                        "event_type": "network",
                        "severity": "high",
                        "anomaly_score": 1.0,
                        "evidence": {},
                    },
                    {
                        "event_id": "auto-stop-physical",
                        "timestamp": self.current_timestamp(),
                        "source": "physical_ml",
                        "asset_id": "PLC-01",
                        "event_type": "physical",
                        "severity": "high",
                        "anomaly_score": 1.0,
                        "evidence": {},
                    },
                ]})
                self.assertEqual(response.status_code, 200)
                risk_summary = client.get("/api/risk").get_json()
                self.assertEqual(risk_summary["popup_candidates"][0]["risk_level"], "CRITICAL")
                self.assertTrue(risk_summary["popup_candidates"][0]["is_fresh"])
                self.assertTrue(risk_summary["popup_candidates"][0]["auto_stop_at"])
                import time

                time.sleep(0.2)
            self.assertEqual(registers[0], 0)
            self.assertEqual(registers[8], 0)
            events = client.get("/api/events").get_json()
            self.assertIn("P6_SIMULATED_STOP", [event["event_type"] for event in events])
        finally:
            app.extensions["stop_background_tasks"]()


if __name__ == "__main__":
    unittest.main()
