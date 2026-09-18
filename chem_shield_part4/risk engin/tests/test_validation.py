"""Unit tests for event validation."""

import sys
import unittest
from pathlib import Path

# Allow "python -m unittest discover -s tests" from this folder in VS Code.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from config import RiskConfig, RiskConfigurationError
from models import AnomalyEvent
from validator import EventValidator, RiskInputValidator, RiskValidationError


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


class RiskInputValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.validator = RiskInputValidator()

    def test_scores_must_be_between_zero_and_one(self) -> None:
        self.assertEqual(self.validator.validate_score(0.70, "network_score"), 0.70)
        with self.assertRaises(RiskValidationError):
            self.validator.validate_score(1.5, "network_score")
        with self.assertRaises(RiskValidationError):
            self.validator.validate_score(-0.2, "physical_score")

    def test_criticality_must_be_between_zero_and_one(self) -> None:
        self.assertEqual(self.validator.validate_score(1.0, "asset_criticality"), 1.0)
        with self.assertRaises(RiskValidationError):
            self.validator.validate_score(1.2, "asset_criticality")

    def test_ids_must_exist(self) -> None:
        with self.assertRaises(RiskValidationError):
            self.validator.require_id(None, "incident_id")
        with self.assertRaises(RiskValidationError):
            self.validator.require_id("", "asset_id")

    def test_invalid_weight_sum_is_a_configuration_error(self) -> None:
        with self.assertRaises(RiskConfigurationError):
            RiskConfig(network_weight=0.9, physical_weight=0.2)


if __name__ == "__main__":
    unittest.main()

