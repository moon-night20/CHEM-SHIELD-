"""Smoke tests for the Part 3 physical-process detector."""

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pandas as pd
import sklearn

from chem_shield_p3.src.detector import PhysicalAnomalyDetector
from chem_shield_p3.src.features import FEATURE_COLUMNS, build_feature_frame
from chem_shield_p4.correlation.validator import EventValidator
from chem_shield_p3.scripts.evaluate_model import calculate_evaluation, summarize_detection_latency
from chem_shield_p3.scripts.generate_test_scenarios import generate_test_scenarios

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

    def test_fixed_seed_makes_scenario_evaluation_reproducible(self):
        first = generate_test_scenarios(seed=2026)
        second = generate_test_scenarios(seed=2026)
        pd.testing.assert_frame_equal(first, second)

        detector = PhysicalAnomalyDetector.load(MODEL_PATH)
        first_events = detector.predict(first, stream_column="scenario")
        second_events = detector.predict(second, stream_column="scenario")
        pd.testing.assert_frame_equal(first_events, second_events)

        first_reports = calculate_evaluation(first_events)
        second_reports = calculate_evaluation(second_events)
        for first_report, second_report in zip(first_reports, second_reports):
            pd.testing.assert_frame_equal(first_report, second_report)
        self.assertTrue(
            {
                "accuracy",
                "precision",
                "recall",
                "f1_score",
                "false_positive_rate",
            }.issubset(first_reports[2].columns)
        )
        pd.testing.assert_frame_equal(
            summarize_detection_latency(first_reports[3]),
            summarize_detection_latency(second_reports[3]),
        )

        hard_scenarios = {"heavy_sensor_noise", "slow_gradual_drift", "stealthy_in_range"}
        self.assertTrue(hard_scenarios.issubset(set(first["scenario"])))
        stealth = first[first["scenario"] == "stealthy_in_range"]
        normal = pd.read_csv(NORMAL_DATA)
        for column in ("motor_speed", "temperature", "vibration"):
            self.assertGreaterEqual(stealth[column].min(), normal[column].min())
            self.assertLessEqual(stealth[column].max(), normal[column].max())

    def test_model_metadata_records_and_warns_on_sklearn_version_mismatch(self):
        detector = PhysicalAnomalyDetector().fit(pd.read_csv(NORMAL_DATA).head(100))
        with tempfile.TemporaryDirectory() as directory:
            model_path = Path(directory) / "model.joblib"
            detector.save(model_path)
            metadata_path = model_path.with_suffix(".metadata.json")
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            self.assertEqual(metadata["sklearn_version"], sklearn.__version__)

            metadata["sklearn_version"] = "0.0"
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            with self.assertWarnsRegex(RuntimeWarning, "version mismatch"):
                PhysicalAnomalyDetector.load(model_path)

        with patch(
            "chem_shield_p3.src.detector.joblib.load",
            side_effect=ValueError("incompatible pickle"),
        ):
            with self.assertRaisesRegex(RuntimeError, "scripts/train_model.py"):
                PhysicalAnomalyDetector.load(MODEL_PATH)


if __name__ == "__main__":
    unittest.main()
