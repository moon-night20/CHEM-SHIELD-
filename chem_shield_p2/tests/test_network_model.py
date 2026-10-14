import json
import unittest
from pathlib import Path

from chem_shield_p2.network_isolation_forest import NetworkIsolationForest

ROOT = Path(__file__).resolve().parents[1]


def vectorize(row):
    state_map = {"established": 1, "new": 2, "S0": 0, "REJ": 3}
    op_map = {
        "read_holding_registers": 1,
        "read_coils": 2,
        "read_input_registers": 3,
        "write_single_coil": 4,
        "write_single_register": 5,
        "write_multiple_registers": 6,
        "read_write_multiple_registers": 7,
    }
    return [
        float(row["duration"]),
        float(row["packets"]),
        float(row["bytes"]),
        float(row["dst_port"]),
        float(state_map.get(row.get("connection_state"), 0)),
        float(row["modbus_function_code"]),
        float(op_map.get(row.get("modbus_operation"), 0)),
        float(row["approved_client"]),
    ]


class NetworkModelTests(unittest.TestCase):
    def test_model_trains_on_normal_baseline_only(self):
        baseline = json.loads((ROOT / "fixtures" / "network_baseline.json").read_text())
        holdout = json.loads((ROOT / "fixtures" / "network_holdout.json").read_text())

        model = NetworkIsolationForest(n_estimators=32, max_depth=6, random_seed=7)
        model.fit([vectorize(item) for item in baseline])

        normal_rows = [vectorize(item) for item in holdout if item["label"] == "normal"]
        attack_rows = [vectorize(item) for item in holdout if item["label"] == "attack"]

        normal_scores = model.score_samples(normal_rows)
        attack_scores = model.score_samples(attack_rows)

        self.assertGreater(sum(attack_scores) / len(attack_scores), sum(normal_scores) / len(normal_scores))
        self.assertTrue(all(score >= 0.0 for score in normal_scores + attack_scores))
        self.assertTrue(all("label" not in item for item in baseline))


if __name__ == "__main__":
    unittest.main()
