"""Unit tests for event validation."""

import sys
import unittest
from pathlib import Path

# Allow "python -m unittest discover -s tests" from this folder in VS Code.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from models import AnomalyEvent
from validator import EventValidator


class EventValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.validator = EventValidator()
        self.valid_event = {
            "timestamp": "2026-09-18T09:31:01",
            "asset_id": "PLC_01",
            "event_type": "network",
            "anomaly_score": 0.70,
        }

    def test_valid_event_is_accepted(self) -> None:
        parsed = self.validator.validate_one(self.valid_event)
        self.assertIsInstance(parsed, AnomalyEvent)
        self.assertEqual(parsed.asset_id, "PLC_01")
        self.assertEqual(parsed.event_type, "network")
        self.assertEqual(parsed.anomaly_score, 0.70)

    def test_missing_fields_are_rejected(self) -> None:
        raw = {"asset_id": "PLC_01", "event_type": "network"}
        with self.assertRaises(ValueError) as ctx:
            self.validator.validate_one(raw)
        self.assertIn("Missing required field", str(ctx.exception))

    def test_invalid_timestamp_is_rejected(self) -> None:
        raw = dict(self.valid_event)
        raw["timestamp"] = "18-09-2026 09:31"
        with self.assertRaises(ValueError) as ctx:
            self.validator.validate_one(raw)
        self.assertIn("Invalid timestamp", str(ctx.exception))

    def test_invalid_anomaly_score_type_is_rejected(self) -> None:
        raw = dict(self.valid_event)
        raw["anomaly_score"] = "high"
        with self.assertRaises(ValueError):
            self.validator.validate_one(raw)

    def test_anomaly_score_outside_range_is_rejected(self) -> None:
        too_high = dict(self.valid_event)
        too_high["anomaly_score"] = 1.2
        too_low = dict(self.valid_event)
        too_low["anomaly_score"] = -0.1

        with self.assertRaises(ValueError):
            self.validator.validate_one(too_high)
        with self.assertRaises(ValueError):
            self.validator.validate_one(too_low)

    def test_unknown_event_type_is_rejected(self) -> None:
        raw = dict(self.valid_event)
        raw["event_type"] = "firmware"
        with self.assertRaises(ValueError) as ctx:
            self.validator.validate_one(raw)
        self.assertIn("Unknown event_type", str(ctx.exception))

    def test_event_type_is_normalized_to_lowercase(self) -> None:
        raw = dict(self.valid_event)
        raw["event_type"] = "PHYSICAL"
        parsed = self.validator.validate_one(raw)
        self.assertEqual(parsed.event_type, "physical")

    def test_validate_many_keeps_good_events_and_reports_bad_ones(self) -> None:
        raw_events = [
            self.valid_event,
            {"timestamp": "bad", "asset_id": "PLC_01", "event_type": "network", "anomaly_score": 0.5},
            {
                "timestamp": "2026-09-18T09:31:04",
                "asset_id": "PLC_01",
                "event_type": "physical",
                "anomaly_score": 0.82,
            },
        ]

        valid, errors = self.validator.validate_many(raw_events)

        self.assertEqual(len(valid), 2)
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].index, 1)

    def test_non_dict_event_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.validator.validate_one("not-an-event")


if __name__ == "__main__":
    unittest.main()
