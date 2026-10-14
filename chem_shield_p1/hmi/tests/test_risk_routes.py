"""Flask API integration tests for correlated incident visibility."""

import tempfile
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
