"""Generate synthetic normal-operation telemetry for laboratory experiments only."""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from chem_shield_p3.src.io_utils import DATA_DIR, write_csv


def generate_normal_data(samples: int, seed: int) -> pd.DataFrame:
    """Create controlled synthetic telemetry; it is not real industrial data."""

    rng = np.random.default_rng(seed)
    motor_speed = 50 + np.cumsum(rng.normal(0, 0.5, samples))
    motor_speed = np.clip(motor_speed, 40, 60)
    temperature = 35 + (0.1 * motor_speed) + rng.normal(0, 0.5, samples)
    vibration = (0.02 * motor_speed) - 0.9 + rng.normal(0, 0.02, samples)
    return pd.DataFrame(
        {
            "timestamp": range(1, samples + 1),
            "motor_speed": motor_speed,
            "temperature": temperature,
            "vibration": vibration,
        }
    )


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
