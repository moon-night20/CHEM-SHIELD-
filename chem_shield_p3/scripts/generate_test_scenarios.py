"""Generate RPM-based synthetic scenarios for controlled model evaluation."""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from chem_shield_p3.scripts.generate_normal_data import generate_normal_data
from chem_shield_p3.src.io_utils import DATA_DIR, write_csv


SENSOR_COLUMNS = ("rpm", "temperature", "pressure", "power")


def generate_test_scenarios(seed: int = 2026) -> pd.DataFrame:
    """Create labeled scenario streams using P1-simulated normal RPM values."""
    rng = np.random.default_rng(seed)
    normal_reference = generate_normal_data(7200, seed + 1)
    records: list[dict[str, object]] = []
    timestamp = 1

    def reference(index: int) -> dict[str, float]:
        row = normal_reference.iloc[index % len(normal_reference)]
        return {column: float(row[column]) for column in SENSOR_COLUMNS}

    def append(values: dict[str, float], label: int, scenario: str) -> None:
        nonlocal timestamp
        records.append({
            "timestamp": timestamp,
            **values,
            "actual_label": label,
            "scenario": scenario,
        })
        timestamp += 1

    for index in range(7200):
        append(reference(index), 0, "normal")

    for index in range(30):
        values = reference(300 + index * 3)
        values["temperature"] += 6.0
        values["power"] += 1.2
        append(values, 1, "sudden_change")

    for index in range(30):
        values = reference(450 + index * 3)
        for sensor, scale in (
            ("rpm", 30.0),
            ("temperature", 2.5),
            ("pressure", 0.2),
            ("power", 0.9),
        ):
            values[sensor] += float(rng.normal(0, scale))
        append(values, 1, "unstable_behavior")

    for index in range(40):
        values = reference(550 + index * 2)
        values["temperature"] += index * 0.15
        values["pressure"] += index * 0.012
        values["power"] += index * 0.04
        append(values, 1, "gradual_deviation")

    for index in range(40):
        values = reference(650 + index * 2)
        for sensor, scale in (
            ("rpm", 90.0),
            ("temperature", 5.0),
            ("pressure", 0.35),
            ("power", 1.2),
        ):
            values[sensor] += float(rng.normal(0, scale))
        append(values, 1, "heavy_sensor_noise")

    for index in range(40):
        values = reference(750 + index * 2)
        values["rpm"] += index * 2.5
        values["temperature"] += index * 0.08
        values["pressure"] += index * 0.004
        values["power"] += index * 0.025
        append(values, 1, "slow_gradual_drift")

    for index in range(40):
        # Each channel is sampled from a normal P1 observation, but the channels
        # come from different operating points and are therefore inconsistent.
        values = {
            sensor: reference(850 + index * 5 + offset * 37)[sensor]
            for offset, sensor in enumerate(SENSOR_COLUMNS)
        }
        append(values, 1, "stealthy_in_range")

    return pd.DataFrame.from_records(records)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate synthetic RPM-based scenarios for controlled evaluation."
    )
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--output", type=Path, default=DATA_DIR / "test_scenarios.csv")
    args = parser.parse_args()

    scenarios = generate_test_scenarios(args.seed)
    output = write_csv(scenarios, args.output)
    print(f"Wrote {len(scenarios)} RPM-based scenario observations to {output}")


if __name__ == "__main__":
    main()
