import json
import tempfile
import unittest
from pathlib import Path

from chem_shield_p2.adapters import network_feature_vector
from chem_shield_p2.network_isolation_forest import NetworkIsolationForest

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


if __name__ == "__main__":
    unittest.main()
