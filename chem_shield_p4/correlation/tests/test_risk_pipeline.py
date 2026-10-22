"""Tests for the persistent event-to-risk pipeline."""

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from chem_shield_p1.data.store import TelemetryStore
from chem_shield_p4.correlation.incident_store import IncidentStore, is_fresh
from chem_shield_p4.correlation.risk_pipeline import RiskPipeline


class RiskPipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = Path(self.temp_dir.name) / "events.db"
        TelemetryStore(str(self.database))
        self.store = IncidentStore(self.database)
        self.pipeline = RiskPipeline(self.store)

    def tearDown(self):
        self.temp_dir.cleanup()

    @staticmethod
    def recent_timestamp(seconds_ago=0):
        return (
            datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)
        ).isoformat().replace("+00:00", "Z")

    @staticmethod
    def event(event_id, source, event_type, timestamp, score=None):
        event = {
            "event_id": event_id,
            "source": source,
            "asset_id": "PLC-01",
            "timestamp": timestamp,
            "event_type": event_type,
            "severity": "high",
            "evidence": {"fixture": "synthetic", "observation": event_type},
        }
        if score is not None:
            event["anomaly_score"] = score
        return event

    def test_unscored_rule_alert_is_preserved_as_unassessed(self):
        payload = self.event(
            "ot-1", "ot_monitor", "temperature_high", "2026-10-14T09:30:00Z"
        )
        result = self.pipeline.ingest([payload])

        self.assertEqual(result["accepted"], 1)
        stored = result["incidents"][0]
        self.assertEqual(stored["risk_level"], "UNASSESSED")
        self.assertIsNone(stored["risk_score"])
        self.assertEqual(stored["events"][0]["event_type"], "physical")
        self.assertEqual(stored["events"][0]["detection_type"], "temperature_high")
        self.assertEqual(stored["events"][0]["evidence"], payload["evidence"])

    def test_deduplicates_replays_and_escalates_with_new_event(self):
        network = self.event(
            "net-1", "network_model", "network_anomaly", self.recent_timestamp(7), 0.9
        )
        first = self.pipeline.ingest([network])
        incident_id = first["incidents"][0]["incident_id"]
        self.assertEqual(first["incidents"][0]["risk_level"], "MEDIUM")

        duplicate = self.pipeline.ingest([network])
        self.assertEqual(duplicate["accepted"], 0)
        self.assertEqual(duplicate["duplicates"], 1)
        self.assertEqual(duplicate["incidents"], [])

        physical = self.event(
            "phys-1", "ot_monitor", "process_multivariable_anomaly",
            self.recent_timestamp(3), 0.7,
        )
        escalated = self.pipeline.ingest([physical])
        self.assertEqual(escalated["incidents"][0]["incident_id"], incident_id)
        self.assertEqual(escalated["incidents"][0]["risk_level"], "HIGH")
        self.assertEqual(escalated["incidents"][0]["risk_score"], 0.78)

        critical = self.event(
            "phys-2", "ot_monitor", "process_multivariable_anomaly",
            self.recent_timestamp(0), 1.0,
        )
        escalated = self.pipeline.ingest([critical])
        self.assertEqual(escalated["incidents"][0]["risk_level"], "CRITICAL")
        self.assertEqual(escalated["incidents"][0]["risk_score"], 0.96)

    def test_old_timestamp_ingest_is_historical(self):
        payload = self.event(
            "old-replay", "network_model", "network_anomaly",
            "2020-01-01T00:00:00Z", 1.0,
        )
        result = self.pipeline.ingest([payload])

        self.assertEqual(result["accepted"], 1)
        self.assertEqual(result["incidents"][0]["status"], "HISTORICAL")
        self.assertEqual(self.store.list_incidents(active_only=True), [])
        self.assertEqual(self.store.list_incidents()[0]["status"], "HISTORICAL")

    def test_incident_freshness_and_stale_resolution_use_latest_event(self):
        result = self.pipeline.ingest([
            self.event(
                "stale-active",
                "network_model",
                "network_anomaly",
                self.recent_timestamp(),
                1.0,
            )
        ])
        incident_id = result["incidents"][0]["incident_id"]
        with self.store._connect() as connection:
            connection.execute(
                "UPDATE risk_events SET timestamp=? WHERE incident_id=?",
                (self.recent_timestamp(400), incident_id),
            )
            connection.execute(
                "UPDATE risk_incidents SET status='ACTIVE' WHERE incident_id=?",
                (incident_id,),
            )

        incident = self.store.get_incident(incident_id)
        self.assertFalse(is_fresh(incident))
        self.assertEqual(self.store.resolve_stale(300, "stale at startup"), 1)
        resolved = self.store.get_incident(incident_id)
        self.assertEqual(resolved["status"], "RESOLVED")
        self.assertEqual(resolved["resolved_reason"], "stale at startup")
        self.assertIsNotNone(resolved["resolved_at"])
        self.assertEqual(self.store.list_incidents(active_only=True), [])

    def test_bad_event_is_reported_without_creating_a_safe_incident(self):
        malformed = self.event(
            "bad", "network_model", "network_anomaly", "not-a-time", 0.8
        )
        result = self.pipeline.ingest([malformed])
        self.assertEqual(result["accepted"], 0)
        self.assertEqual(result["rejected"], 1)
        self.assertEqual(self.store.list_incidents(), [])

    def test_additive_storage_preserves_existing_telemetry_schema(self):
        with self.store._connect() as connection:
            tables = {
                row["name"]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(telemetry)")
            }
        self.assertIn("telemetry", tables)
        self.assertIn("events", tables)
        self.assertIn("risk_incidents", tables)
        self.assertEqual(
            columns,
            {
                "id", "timestamp", "machine_id", "plc_id", "motor_status",
                "target_rpm", "rpm", "temperature", "pressure", "power",
            },
        )


if __name__ == "__main__":
    unittest.main()
