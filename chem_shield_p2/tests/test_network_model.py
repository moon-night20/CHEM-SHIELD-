import json
import tempfile
import unittest
from pathlib import Path

from chem_shield_p2.adapters import network_feature_vector, replay_events
from chem_shield_p2.network_isolation_forest import NetworkIsolationForest
from chem_shield_p2.network_scoring import score_to_part4_events

ROOT = Path(__file__).resolve().parents[1]


class NetworkModelTests(unittest.TestCase):
    def test_model_trains_on_normal_baseline_only(self):
        baseline = json.loads((ROOT / "fixtures" / "network_baseline.json").read_text())
        holdout = json.loads((ROOT / "fixtures" / "network_holdout.json").read_text())

        model = NetworkIsolationForest(n_estimators=32, max_depth=6, random_seed=7)
        model.fit(network_feature_vector(item) for item in baseline)

        normal_rows = [network_feature_vector(item) for item in holdout if item["label"] == "normal"]
        attack_rows = [network_feature_vector(item) for item in holdout if item["label"] == "attack"]

        normal_scores = model.score_samples(normal_rows)
        attack_scores = model.score_samples(attack_rows)

        self.assertGreater(sum(attack_scores) / len(attack_scores), sum(normal_scores) / len(normal_scores))
        self.assertTrue(all(score >= 0.0 for score in normal_scores + attack_scores))
        self.assertTrue(all("label" not in item for item in baseline))

    def test_model_round_trips_through_saved_artifact(self):
        baseline = json.loads((ROOT / "fixtures" / "network_baseline.json").read_text())
        rows = [network_feature_vector(item) for item in baseline]
        model = NetworkIsolationForest(n_estimators=8, max_depth=4).fit(rows)
        expected = model.score_samples(rows[:2])

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "network-model.joblib"
            model.save(path)
            loaded = NetworkIsolationForest.load(path)

        self.assertEqual(loaded.score_samples(rows[:2]), expected)

    def test_calibrated_benign_fixtures_score_below_malicious_fixtures(self):
        baseline = json.loads((ROOT / "fixtures" / "network_baseline.json").read_text())
        benign = replay_events([ROOT / "fixtures" / "benign_network_events.json"])
        malicious = replay_events([ROOT / "fixtures" / "malicious_network_events.json"])
        model = NetworkIsolationForest(n_estimators=64, max_depth=8, random_seed=7)
        model.fit(network_feature_vector(item) for item in baseline)
        config = json.loads((ROOT / "config.example.json").read_text())

        benign_scores = [
            event["anomaly_score"]
            for event in score_to_part4_events(benign, model, config)
        ]
        malicious_scores = [
            event["anomaly_score"]
            for event in score_to_part4_events(malicious, model, config)
        ]

        self.assertTrue(benign_scores)
        self.assertTrue(malicious_scores)
        self.assertLess(max(benign_scores), 0.3)
        self.assertGreater(min(malicious_scores), max(benign_scores))
        self.assertEqual(
            {
                event["evidence"].get("function_code")
                for event in malicious
                if event["source"] == "modbus_monitor"
            },
            {5, 6, 15, 16},
        )
        self.assertTrue(any(event["source"] == "os_security" for event in malicious))
        self.assertTrue(any(event["source"] == "zeek" for event in malicious))
        self.assertTrue(any(event["source"] == "suricata" for event in malicious))


if __name__ == "__main__":
    unittest.main()
