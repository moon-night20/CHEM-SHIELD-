"""Summarize false positives and false negatives from generated evaluation output."""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

DEFAULT_ERRORS = Path(__file__).resolve().parent / "results" / "ml_errors.csv"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Summarize generated physical ML false positives and false negatives."
    )
    parser.add_argument("--input", type=Path, default=DEFAULT_ERRORS)
    args = parser.parse_args()

    errors = pd.read_csv(args.input)
    if "error_type" not in errors.columns:
        raise ValueError("error CSV must contain the generated error_type column")
    counts = errors["error_type"].value_counts()
    print(f"Incorrect predictions: {len(errors)}")
    print(f"False positives: {int(counts.get('false_positive', 0))}")
    print(f"False negatives: {int(counts.get('false_negative', 0))}")
    if not errors.empty:
        print(errors.to_string(index=False))


if __name__ == "__main__":
    main()
