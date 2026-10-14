"""Evaluate saved physical anomaly detection using labeled synthetic scenarios."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.detector import PhysicalAnomalyDetector
from src.io_utils import DATA_DIR, DEFAULT_MODEL_PATH, RESULTS_DIR, read_telemetry_csv, write_csv


def _validate_labels(data: pd.DataFrame) -> pd.Series:
    if "actual_label" not in data.columns:
        raise ValueError("evaluation telemetry must include an actual_label column with 0 or 1 values")
    labels = pd.to_numeric(data["actual_label"], errors="coerce")
    if labels.isna().any() or not labels.isin([0, 1]).all():
        raise ValueError("actual_label values must be exactly 0 (normal) or 1 (anomalous)")
    return labels.astype(int)


def _safe_rate(numerator: int, denominator: int) -> float:
    return float(numerator / denominator) if denominator else 0.0


def calculate_evaluation(
    events: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Derive overall metrics, confusion matrix, scenario rates, latency, and errors."""

    actual = _validate_labels(events)
    predicted = events["is_anomaly"].astype(bool).astype(int)
    events["actual_label"] = actual
    events["predicted_label"] = predicted

    tn, fp, fn, tp = confusion_matrix(actual, predicted, labels=[0, 1]).ravel()
    metrics = pd.DataFrame(
        [
            {"metric": "accuracy", "value": float(accuracy_score(actual, predicted))},
            {"metric": "precision", "value": float(precision_score(actual, predicted, zero_division=0))},
            {"metric": "recall", "value": float(recall_score(actual, predicted, zero_division=0))},
            {"metric": "f1_score", "value": float(f1_score(actual, predicted, zero_division=0))},
            {"metric": "false_positive_rate", "value": _safe_rate(int(fp), int(fp + tn))},
            {"metric": "true_positives", "value": int(tp)},
            {"metric": "true_negatives", "value": int(tn)},
            {"metric": "false_positives", "value": int(fp)},
            {"metric": "false_negatives", "value": int(fn)},
        ]
    )
    matrix = pd.DataFrame(
        {
            "actual": ["normal", "anomaly"],
            "predicted_normal": [int(tn), int(fn)],
            "predicted_anomaly": [int(fp), int(tp)],
        }
    )

    scenario_column = "scenario" if "scenario" in events.columns else None
    scenario_rows: list[dict[str, object]] = []
    latency_rows: list[dict[str, object]] = []
    groups = events.groupby(scenario_column, sort=False) if scenario_column else [("all", events)]
    for scenario, subset in groups:
        subset = subset.reset_index(drop=True)
        actual_subset = subset["actual_label"].astype(int)
        predicted_subset = subset["predicted_label"].astype(int)
        anomalous = int(actual_subset.sum())
        detected = int(((actual_subset == 1) & (predicted_subset == 1)).sum())
        normal_samples = int((actual_subset == 0).sum())
        false_positives = int(((actual_subset == 0) & (predicted_subset == 1)).sum())
        scenario_rows.append(
            {
                "scenario": str(scenario),
                "total_samples": int(len(subset)),
                "anomalous_samples": anomalous,
                "detected_anomalous_samples": detected,
                "detection_rate": _safe_rate(detected, anomalous),
                "normal_samples": normal_samples,
                "false_positives": false_positives,
                "false_positive_rate": _safe_rate(false_positives, normal_samples),
            }
        )

        onset_positions = np.flatnonzero(actual_subset.to_numpy() == 1)
        if onset_positions.size:
            onset = int(onset_positions[0])
            # Latency is based on the first true positive, never a later false
            # positive on a normal sample within the same scenario.
            detection_positions = np.flatnonzero(
                (actual_subset.to_numpy() == 1) & (predicted_subset.to_numpy() == 1)
            )
            first_detection = int(detection_positions[0]) if detection_positions.size else None
            latency_rows.append(
                {
                    "scenario": str(scenario),
                    "anomaly_onset_timestamp": subset.loc[onset, "timestamp"],
                    "first_detection_timestamp": (
                        subset.loc[first_detection, "timestamp"]
                        if first_detection is not None
                        else pd.NA
                    ),
                    "detection_delay_samples": (
                        first_detection - onset if first_detection is not None else pd.NA
                    ),
                    "detected": first_detection is not None,
                }
            )

    error_mask = events["actual_label"] != events["predicted_label"]
    errors = events.loc[error_mask].copy()
    errors["error_type"] = np.where(
        errors["actual_label"] == 0, "false_positive", "false_negative"
    )
    error_columns = [
        "timestamp",
        "asset_id",
        "scenario",
        "motor_speed",
        "temperature",
        "vibration",
        "temperature_rate",
        "vibration_rate",
        "speed_rate",
        "is_anomaly",
        "anomaly_score",
        "actual_label",
        "predicted_label",
        "error_type",
    ]
    errors = errors.loc[:, [column for column in error_columns if column in errors.columns]]
    return metrics, matrix, pd.DataFrame(scenario_rows), pd.DataFrame(latency_rows), errors


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Calculate actual ML metrics from labeled synthetic scenario predictions."
    )
    parser.add_argument("--input", type=Path, default=DATA_DIR / "test_scenarios.csv")
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument(
        "--predictions-output", type=Path, default=RESULTS_DIR / "physical_ml_output.csv"
    )
    parser.add_argument(
        "--metrics-output", type=Path, default=RESULTS_DIR / "evaluation_results.csv"
    )
    parser.add_argument(
        "--confusion-output", type=Path, default=RESULTS_DIR / "confusion_matrix.csv"
    )
    parser.add_argument(
        "--scenario-output", type=Path, default=RESULTS_DIR / "scenario_evaluation.csv"
    )
    parser.add_argument(
        "--latency-output", type=Path, default=RESULTS_DIR / "detection_latency.csv"
    )
    parser.add_argument(
        "--errors-output", type=Path, default=RESULTS_DIR / "ml_errors.csv"
    )
    parser.add_argument("--asset-id", default=None)
    parser.add_argument(
        "--stream-column",
        default="auto",
        help="Independent-stream column; by default, use scenario when present. Use an empty value to disable.",
    )
    args = parser.parse_args()

    telemetry = read_telemetry_csv(args.input)
    _validate_labels(telemetry)
    if args.stream_column == "auto":
        stream_column = "scenario" if "scenario" in telemetry.columns else None
    else:
        stream_column = args.stream_column or None
    if stream_column is not None and stream_column not in telemetry.columns:
        raise ValueError(f"stream column is not present in evaluation data: {stream_column}")

    detector = PhysicalAnomalyDetector.load(args.model)
    events = detector.predict(
        telemetry,
        asset_id=args.asset_id,
        stream_column=stream_column,
    )
    if not isinstance(events, pd.DataFrame):
        raise RuntimeError("batch evaluation requires a DataFrame prediction result")
    metrics, matrix, scenario_rates, latency, errors = calculate_evaluation(events)

    write_csv(events, args.predictions_output)
    write_csv(metrics, args.metrics_output)
    write_csv(matrix, args.confusion_output)
    write_csv(scenario_rates, args.scenario_output)
    write_csv(latency, args.latency_output)
    write_csv(errors, args.errors_output)

    metric_values = dict(zip(metrics["metric"], metrics["value"]))
    print(f"Evaluated {len(events)} synthetic observations from actual predictions.")
    print(
        "Accuracy={accuracy:.3f}, Precision={precision:.3f}, Recall={recall:.3f}, F1={f1_score:.3f}, FPR={false_positive_rate:.3f}".format(
            **metric_values
        )
    )
    print(f"Saved evaluation artifacts to {args.metrics_output.parent}")


if __name__ == "__main__":
    main()
