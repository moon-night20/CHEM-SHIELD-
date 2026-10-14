"""Run a saved physical-process anomaly detector without retraining it."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.detector import PhysicalAnomalyDetector
from src.io_utils import DATA_DIR, DEFAULT_MODEL_PATH, RESULTS_DIR, read_telemetry_csv, write_csv


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create physical ML events from telemetry using an existing Isolation Forest."
    )
    parser.add_argument("--input", type=Path, default=DATA_DIR / "test_scenarios.csv")
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument(
        "--output", type=Path, default=RESULTS_DIR / "physical_ml_output.csv"
    )
    parser.add_argument("--asset-id", default=None)
    parser.add_argument(
        "--stream-column",
        default="auto",
        help="Independent-stream column; by default, use scenario when that column is present. Use an empty value to disable.",
    )
    args = parser.parse_args()

    telemetry = read_telemetry_csv(args.input)
    if args.stream_column == "auto":
        stream_column = "scenario" if "scenario" in telemetry.columns else None
    else:
        stream_column = args.stream_column or None
    detector = PhysicalAnomalyDetector.load(args.model)
    events = detector.predict(
        telemetry,
        asset_id=args.asset_id,
        stream_column=stream_column,
    )
    output = write_csv(events, args.output)
    detected = int(events["is_anomaly"].sum())
    print(f"Wrote {len(events)} physical ML events to {output}")
    print(f"Physical anomalies detected: {detected}")


if __name__ == "__main__":
    main()
