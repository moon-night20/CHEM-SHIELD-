"""Generate labeled synthetic scenarios for controlled ML evaluation only."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.io_utils import DATA_DIR, write_csv


def generate_test_scenarios(seed: int) -> pd.DataFrame:
    """Create normal and anomalous laboratory scenarios with evaluation labels."""

    rng = np.random.default_rng(seed)
    records: list[dict[str, object]] = []
    timestamp = 1

    def append(speed: float, temperature: float, vibration: float, label: int, scenario: str) -> None:
        nonlocal timestamp
        records.append(
            {
                "timestamp": timestamp,
                "motor_speed": speed,
                "temperature": temperature,
                "vibration": vibration,
                "actual_label": label,
                "scenario": scenario,
            }
        )
        timestamp += 1

    for _ in range(100):
        append(
            50 + rng.normal(0, 1),
            40 + rng.normal(0, 0.5),
            0.10 + rng.normal(0, 0.02),
            0,
            "normal",
        )
    for _ in range(30):
        append(
            90 + rng.normal(0, 2),
            65 + rng.normal(0, 2),
            0.80 + rng.normal(0, 0.08),
            1,
            "sudden_change",
        )
    for _ in range(30):
        append(
            rng.uniform(80, 100),
            rng.uniform(60, 75),
            rng.uniform(0.70, 1.30),
            1,
            "unstable_behavior",
        )
    for offset in range(40):
        append(60 + (offset * 0.8), 41 + (offset * 0.4), 0.20 + (offset * 0.015), 1, "gradual_deviation")

    return pd.DataFrame.from_records(records)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate synthetic evaluation scenarios for controlled academic experiments."
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=Path, default=DATA_DIR / "test_scenarios.csv")
    args = parser.parse_args()

    scenarios = generate_test_scenarios(args.seed)
    output = write_csv(scenarios, args.output)
    print(f"Wrote {len(scenarios)} synthetic scenario observations to {output}")


if __name__ == "__main__":
    main()
