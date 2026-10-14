"""Unit tests for the rule-based correlation engine."""

import sys
import unittest
from datetime import datetime
from pathlib import Path

# Allow "python -m unittest discover -s tests" from this folder in VS Code.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from correlation_engine import CorrelationEngine
from models import AnomalyEvent


def event(ts: str, asset: str, event_type: str, score: float) -> AnomalyEvent:
    return AnomalyEvent(
        timestamp=datetime.fromisoformat(ts),
        asset_id=asset,
        event_type=event_type,
        anomaly_score=score,
    )


class CorrelationEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = CorrelationEngine(time_window_seconds=10)

    def test_example_three_events_become_one_incident(self) -> None:
        events = [
            event("2026-09-18T09:31:01", "PLC_01", "network", 0.70),
            event("2026-09-18T09:31:04", "PLC_01", "physical", 0.82),
            event("2026-09-18T09:31:08", "PLC_01", "physical", 0.91),
        ]

        incidents = self.engine.correlate_events(events)

        self.assertEqual(len(incidents), 1)
        incident = incidents[0]
        self.assertEqual(incident.asset_id, "PLC_01")
        self.assertEqual(incident.number_of_events, 3)
        self.assertTrue(incident.network_present)
        self.assertTrue(incident.physical_present)
        self.assertEqual(incident.start_time, datetime.fromisoformat("2026-09-18T09:31:01"))
        self.assertEqual(incident.end_time, datetime.fromisoformat("2026-09-18T09:31:08"))
        self.assertEqual(incident.duration_seconds, 7)
        self.assertEqual(incident.max_network_score, 0.70)
        self.assertEqual(incident.max_physical_score, 0.91)

    def test_event_outside_window_starts_new_incident(self) -> None:
        events = [
            event("2026-09-18T09:31:01", "PLC_01", "network", 0.70),
            event("2026-09-18T09:31:04", "PLC_01", "physical", 0.82),
            event("2026-09-18T09:31:08", "PLC_01", "physical", 0.91),
            event("2026-09-18T09:32:30", "PLC_01", "network", 0.80),
        ]

        incidents = self.engine.correlate_events(events)

        self.assertEqual(len(incidents), 2)
        self.assertEqual(incidents[0].number_of_events, 3)
        self.assertEqual(incidents[1].number_of_events, 1)
        self.assertEqual(incidents[1].events[0].anomaly_score, 0.80)
        self.assertTrue(incidents[1].network_present)
        self.assertFalse(incidents[1].physical_present)

    def test_different_assets_are_not_correlated(self) -> None:
        events = [
            event("2026-09-18T09:31:01", "PLC_01", "network", 0.70),
            event("2026-09-18T09:31:02", "PLC_02", "physical", 0.90),
        ]

        incidents = self.engine.correlate_events(events)

        self.assertEqual(len(incidents), 2)
        assets = {incident.asset_id for incident in incidents}
        self.assertEqual(assets, {"PLC_01", "PLC_02"})
        self.assertTrue(all(incident.number_of_events == 1 for incident in incidents))

    def test_sorts_out_of_order_events(self) -> None:
        events = [
            event("2026-09-18T09:31:08", "PLC_01", "physical", 0.91),
            event("2026-09-18T09:31:01", "PLC_01", "network", 0.70),
            event("2026-09-18T09:31:04", "PLC_01", "physical", 0.82),
        ]

        incidents = self.engine.correlate_events(events)

        self.assertEqual(len(incidents), 1)
        timestamps = [item.timestamp for item in incidents[0].events]
        self.assertEqual(timestamps, sorted(timestamps))

    def test_time_window_is_configurable(self) -> None:
        events = [
            event("2026-09-18T09:31:00", "PLC_01", "network", 0.50),
            event("2026-09-18T09:31:06", "PLC_01", "physical", 0.60),
        ]

        tight = CorrelationEngine(time_window_seconds=5).correlate_events(events)
        wide = CorrelationEngine(time_window_seconds=10).correlate_events(events)

        self.assertEqual(len(tight), 2)
        self.assertEqual(len(wide), 1)

    def test_invalid_window_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            CorrelationEngine(time_window_seconds=0)

    def test_correlate_accepts_raw_detector_json(self) -> None:
        raw_events = [
            {
                "timestamp": "2026-09-18T09:31:01",
                "asset_id": "PLC_01",
                "event_type": "network",
                "anomaly_score": 0.70,
            },
            {
                "timestamp": "2026-09-18T09:31:04",
                "asset_id": "PLC_01",
                "event_type": "physical",
                "anomaly_score": 0.82,
            },
        ]

        incidents, errors = self.engine.correlate(raw_events)

        self.assertEqual(errors, [])
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].number_of_events, 2)

    def test_empty_input_returns_no_incidents(self) -> None:
        incidents = self.engine.correlate_events([])
        self.assertEqual(incidents, [])


if __name__ == "__main__":
    unittest.main()
