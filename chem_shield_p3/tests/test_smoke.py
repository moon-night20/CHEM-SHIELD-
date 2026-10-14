"""Smoke tests for the Part 3 physical-process detector."""

import unittest
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from chem_shield_p3.src.detector import PhysicalAnomalyDetector
from chem_shield_p3.src.features import FEATURE_COLUMNS, build_feature_frame
from chem_shield_p4.correlation.validator import EventValidator

ROOT = Path(__file__).resolve().parents[1]
NORMAL_DATA = ROOT / "data" / "normal_data_large.csv"
SCENARIO_DATA = ROOT / "data" / "test_scenarios.csv"
MODEL_PATH = ROOT / "models" / "isolation_forest.joblib"


class PhysicalDetectorSmokeTests(unittest.TestCase):
    def test_features_build_correctly(self):
        data = pd.read_csv(NORMAL_DATA)
        prepared, features = build_feature_frame(data, require_timestamp=False)

        self.assertGreater(len(prepared), 0)
        self.assertTrue(set(FEATURE_COLUMNS).issubset(set(features.columns)))
        self.assertIn("temperature_rate", features.columns)
        self.assertIn("vibration_rate", features.columns)
        self.assertIn("speed_rate", features.columns)

    def test_detector_loads_model_and_scores_scenarios(self):
        detector = PhysicalAnomalyDetector.load(MODEL_PATH)
        events = detector.predict(pd.read_csv(SCENARIO_DATA), stream_column="scenario")

        self.assertTrue(isinstance(events, pd.DataFrame))
        self.assertIn("anomaly_score", events.columns)
        self.assertIn("is_anomaly", events.columns)
        self.assertGreater(len(events), 0)

    def test_event_dict_matches_part4_validator(self):
        detector = PhysicalAnomalyDetector.load(MODEL_PATH)
        row = detector.predict(pd.read_csv(SCENARIO_DATA).head(1), stream_column="scenario").iloc[0].to_dict()

        timestamp = row["timestamp"]
        if isinstance(timestamp, (int, float)):
            iso = datetime.fromtimestamp(float(timestamp), tz=timezone.utc).isoformat().replace("+00:00", "Z")
        else:
            iso = str(timestamp)

        event = {
            "timestamp": iso,
            "asset_id": str(row["asset_id"]),
            "event_type": "physical",
            "anomaly_score": float(row["anomaly_score"]),
        }
        validated = EventValidator().validate_one(event)

        self.assertEqual(validated.asset_id, str(row["asset_id"]))
        self.assertEqual(validated.event_type, "physical")
        self.assertGreaterEqual(validated.anomaly_score, 0.0)
        self.assertLessEqual(validated.anomaly_score, 1.0)


if __name__ == "__main__":
    unittest.main()
