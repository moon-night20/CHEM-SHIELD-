"""Generate synthetic normal-operation telemetry for laboratory experiments only."""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from chem_shield_p1.process.machine import ProcessUnit
from chem_shield_p3.src.io_utils import DATA_DIR, write_csv


def generate_normal_data(samples: int, seed: int) -> pd.DataFrame:
    """Create synthetic normal telemetry from the P1 ProcessUnit machine simulator."""

    rng = np.random.default_rng(seed)
    records: list[dict[str, float | int]] = []
    run = 0

    while len(records) < samples:
        unit = ProcessUnit(seed=seed + run)
        run += 1

        # 1. Stopped / cold baseline (10-25 steps)
        for _ in range(int(rng.integers(10, 25))):
            if len(records) >= samples:
                break
            s = unit.step(motor_on=False, target_rpm=0.0, dt=10.0)
            v = 0.09 + rng.normal(0, 0.005)
            records.append({
                "motor_speed": float(round(s.rpm, 2)),
                "temperature": float(round(s.temperature, 2)),
                "pressure": float(round(s.pressure, 2)),
                "vibration": float(round(max(0.05, v), 4)),
            })

        # 2. Ramp up sequence matching normal machine start (150 -> 300 -> 480 -> 650 -> 820 -> 980 -> 1150)
        ramp_targets = [150.0, 300.0, 480.0, 650.0, 820.0, 980.0, 1150.0]
        for t in ramp_targets:
            for _ in range(int(rng.integers(1, 3))):
                if len(records) >= samples:
                    break
                s = unit.step(motor_on=True, target_rpm=t, dt=10.0)
                v = 0.09 + 0.04 * (s.rpm / 1500.0) + rng.normal(0, 0.005)
                records.append({
                    "motor_speed": float(round(s.rpm, 2)),
                    "temperature": float(round(s.temperature, 2)),
                    "pressure": float(round(s.pressure, 2)),
                    "vibration": float(round(max(0.05, v), 4)),
                })

        # 3. Steady running at 1100-1150 rpm
        for _ in range(int(rng.integers(30, 60))):
            if len(records) >= samples:
                break
            target = 1150.0 + float(rng.uniform(-30, 30))
            s = unit.step(motor_on=True, target_rpm=target, dt=10.0)
            v = 0.09 + 0.04 * (s.rpm / 1500.0) + rng.normal(0, 0.005)
            records.append({
                "motor_speed": float(round(s.rpm, 2)),
                "temperature": float(round(s.temperature, 2)),
                "pressure": float(round(s.pressure, 2)),
                "vibration": float(round(max(0.05, v), 4)),
            })

        # 4. Setpoint variations (800, 1000, 1150)
        for t in [800.0, 1000.0, 1150.0]:
            for _ in range(int(rng.integers(15, 30))):
                if len(records) >= samples:
                    break
                s = unit.step(motor_on=True, target_rpm=t, dt=10.0)
                v = 0.09 + 0.04 * (s.rpm / 1500.0) + rng.normal(0, 0.005)
                records.append({
                    "motor_speed": float(round(s.rpm, 2)),
                    "temperature": float(round(s.temperature, 2)),
                    "pressure": float(round(s.pressure, 2)),
                    "vibration": float(round(max(0.05, v), 4)),
                })

        # 5. Coast down
        for _ in range(int(rng.integers(15, 25))):
            if len(records) >= samples:
                break
            s = unit.step(motor_on=False, target_rpm=0.0, dt=10.0)
            v = 0.09 + 0.04 * (s.rpm / 1500.0) + rng.normal(0, 0.005)
            records.append({
                "motor_speed": float(round(s.rpm, 2)),
                "temperature": float(round(s.temperature, 2)),
                "pressure": float(round(s.pressure, 2)),
                "vibration": float(round(max(0.05, v), 4)),
            })

    df = pd.DataFrame(records[:samples])
    df["timestamp"] = range(1, len(df) + 1)
    core = ["timestamp", "motor_speed", "temperature", "pressure", "vibration"]
    return df.loc[:, core]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate synthetic normal telemetry for controlled academic experiments."
    )
    parser.add_argument("--samples", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=Path, default=DATA_DIR / "normal_data_large.csv")
    args = parser.parse_args()
    if args.samples < 2:
        parser.error("--samples must be at least 2")

    output = write_csv(generate_normal_data(args.samples, args.seed), args.output)
    print(f"Wrote {args.samples} synthetic normal observations to {output}")


if __name__ == "__main__":
    main()
