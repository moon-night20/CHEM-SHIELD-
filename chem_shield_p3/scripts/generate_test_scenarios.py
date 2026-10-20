"""Generate labeled synthetic scenarios for controlled ML evaluation only."""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from chem_shield_p3.src.io_utils import DATA_DIR, write_csv


def generate_test_scenarios(seed: int = 2026) -> pd.DataFrame:
    """Create labeled scenarios with a seed independent of training generation."""

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

    for _ in range(40):
        append(
            float(np.clip(900 + rng.normal(0, 80), 500, 1400)),
            float(np.clip(48 + rng.normal(0, 5), 32, 59)),
            float(np.clip(0.11 + rng.normal(0, 0.018), 0.08, 0.14)),
            1,
            "heavy_sensor_noise",
        )

    for offset in range(40):
        append(
            780 + offset * 4 + rng.normal(0, 1.5),
            42 + offset * 0.3 + rng.normal(0, 0.2),
            0.095 + offset * 0.0007 + rng.normal(0, 0.001),
            1,
            "slow_gradual_drift",
        )

    for offset in range(40):
        phase = offset * (2 * np.pi / 20)
        append(
            950 + 75 * np.sin(phase) + rng.normal(0, 3),
            48 - 5 * np.sin(phase) + rng.normal(0, 0.3),
            0.11 + 0.015 * np.cos(phase) + rng.normal(0, 0.001),
            1,
            "stealthy_in_range",
        )

    return pd.DataFrame.from_records(records)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate synthetic evaluation scenarios for controlled academic experiments."
    )
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--output", type=Path, default=DATA_DIR / "test_scenarios.csv")
    args = parser.parse_args()

    scenarios = generate_test_scenarios(args.seed)
    output = write_csv(scenarios, args.output)
    print(f"Wrote {len(scenarios)} synthetic scenario observations to {output}")


if __name__ == "__main__":
    main()
