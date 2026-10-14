"""Reproducible baseline training and held-out evaluation command."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, List

from .ot_anomaly_model import PhysicalProcessIsolationForest


def read_records(path: str | Path) -> List[Dict[str, Any]]:
    records = []
    with open(path, "r", encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            for field in ("temperature", "pressure", "speed"):
                if row.get(field) not in (None, ""):
                    try:
                        row[field] = float(row[field])
                    except ValueError as exc:
                        raise ValueError(f"Invalid numeric {field!r} in {path}: {row[field]!r}") from exc
            records.append(row)
    if not records:
        raise ValueError(f"No records found in {path}")
    return records


def main() -> int:
    parser = argparse.ArgumentParser(description="Train the physical-process model on normal baseline CSV data")
    parser.add_argument("--baseline", required=True, help="CSV containing only designated normal baseline readings")
    parser.add_argument("--evaluation", required=True, help="Separate labeled evaluation CSV containing normal and abnormal rows")
    parser.add_argument("--output", required=True, help="Path for fitted joblib model artifact")
    parser.add_argument("--contamination", type=float, default=0.1, help="Expected baseline outlier fraction used for the Isolation Forest cutoff (default: 0.1)")
    args = parser.parse_args()

    baseline = read_records(args.baseline)
    evaluation = read_records(args.evaluation)
    model = PhysicalProcessIsolationForest(contamination=args.contamination).fit(baseline)
    metrics = model.evaluate(evaluation)
    model.save(args.output)
    print(json.dumps({
        "model_metadata": model.metadata,
        "held_out_metrics": metrics,
        "score_warning": "Anomaly scores are not attack probabilities.",
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
