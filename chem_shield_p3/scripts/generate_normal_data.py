"""Generate normal telemetry by exercising the Part 1 simulator."""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from chem_shield_p1.process.machine import ProcessUnit
from chem_shield_p3.src.io_utils import DATA_DIR, write_csv


TARGET_SCHEDULE = (
    (False, 0.0, 80),
    (True, 250.0, 80),
    (True, 500.0, 100),
    (True, 900.0, 120),
    (True, 1200.0, 120),
    (True, 1450.0, 140),
    (True, 750.0, 100),
    (False, 0.0, 100),
    (True, 350.0, 100),
    (True, 1300.0, 140),
    (False, 0.0, 100),
)


def generate_normal_data(samples: int, seed: int) -> pd.DataFrame:
    """Create normal observations from P1 start/stop and multiple RPM targets."""
    if samples < 2:
        raise ValueError("samples must be at least 2")

    unit = ProcessUnit(seed=seed)
    records: list[dict[str, float | int | str]] = []
    timestamp = 0
    while len(records) < samples:
        for motor_on, target_rpm, duration in TARGET_SCHEDULE:
            for _ in range(duration):
                state = unit.step(motor_on=motor_on, target_rpm=target_rpm, dt=0.5)
                records.append({
                    "timestamp": timestamp,
                    "target_rpm": target_rpm,
                    "rpm": round(state.rpm, 2),
                    "temperature": round(state.temperature, 2),
                    "pressure": round(state.pressure, 2),
                    "power": round(state.power, 2),
                    "motor_status": state.motor_status,
                    "actual_label": 0,
                })
                timestamp += 1
                if len(records) == samples:
                    break
            if len(records) == samples:
                break
    return pd.DataFrame.from_records(records)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate normal telemetry from the P1 process simulator."
    )
    parser.add_argument("--samples", type=int, default=6000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=Path, default=DATA_DIR / "normal_data_large.csv")
    args = parser.parse_args()
    if args.samples < 2:
        parser.error("--samples must be at least 2")

    output = write_csv(generate_normal_data(args.samples, args.seed), args.output)
    print(f"Wrote {args.samples} P1-simulated normal observations to {output}")


if __name__ == "__main__":
    main()
