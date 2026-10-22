"""In-process integration coverage for the P2/P5 to HMI risk pipeline."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from chem_shield_p1.hmi.app import create_app


class PipelineIntegrationTests(unittest.TestCase):
    @patch("chem_shield_p1.hmi.app.DeviceConnection")
    def test_network_and_physical_events_create_one_scored_incident(self, device_class):
        device_class.return_value.connect.return_value = {}
        with tempfile.TemporaryDirectory() as directory:
            app = create_app(
                database=str(Path(directory) / "risk.db"),
            )
            app.config.update(TESTING=True)
            client = app.test_client()

            response = client.post(
                "/api/risk/events",
                json={
                    "events": [
                        {
                            "event_id": "integration-network-event",
                            "timestamp": "2026-10-14T10:00:00Z",
                            "source": "network_model",
                            "asset_id": "PLC-01",
                            "event_type": "network",
                            "anomaly_score": 0.7,
                            "severity": "medium",
                            "evidence": {"fixture": "synthetic"},
                        },
                        {
                            "event_id": "integration-physical-event",
                            "timestamp": "2026-10-14T10:00:04Z",
                            "source": "ot_monitor",
                            "asset_id": "PLC-01",
                            "event_type": "physical",
                            "anomaly_score": 0.8,
                            "severity": "high",
                            "evidence": {"fixture": "synthetic"},
                        },
                    ]
                },
                headers={"X-Ingest-Token": app.config["INGEST_TOKEN"]},
            )
            app.extensions["stop_background_tasks"]()

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["accepted"], 2)
        self.assertEqual(payload["rejected"], 0)
        self.assertEqual(len(payload["incidents"]), 1)
        incident = payload["incidents"][0]
        self.assertEqual(incident["asset_id"], "PLC-01")
        self.assertIsNotNone(incident["risk_score"])
        self.assertEqual(
            {event["event_type"] for event in incident["events"]},
            {"network", "physical"},
        )
        device_class.assert_called_once_with("127.0.0.1", 15020)


if __name__ == "__main__":
    unittest.main()
