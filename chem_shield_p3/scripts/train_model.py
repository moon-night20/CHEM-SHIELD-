"""Train and persist an Isolation Forest from normal telemetry only."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.detector import PhysicalAnomalyDetector
from src.io_utils import DATA_DIR, DEFAULT_MODEL_PATH, read_telemetry_csv


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train CHEM-SHIELD physical anomaly detection on normal telemetry only."
    )
    parser.add_argument("--input", type=Path, default=DATA_DIR / "normal_data_large.csv")
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--contamination", type=float, default=0.05)
    parser.add_argument(
        "--stream-column",
        default=None,
        help="Optional column identifying independent normal telemetry streams.",
    )
    args = parser.parse_args()

    normal_data = read_telemetry_csv(args.input)
    detector = PhysicalAnomalyDetector(
        contamination=args.contamination,
        random_state=42,
    ).fit(normal_data, stream_column=args.stream_column)
    model_path = detector.save(args.model)

    print(f"Trained {detector.training_metadata['model']} on {len(normal_data)} normal observations.")
    print(f"Saved model and inference configuration to {model_path}")


if __name__ == "__main__":
    main()
