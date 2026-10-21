"""Evaluate saved physical anomaly detection using labeled synthetic scenarios."""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score

from chem_shield_p3.src.detector import PhysicalAnomalyDetector
from chem_shield_p3.src.features import FEATURE_COLUMNS
from chem_shield_p3.src.io_utils import DATA_DIR, DEFAULT_MODEL_PATH, RESULTS_DIR, read_telemetry_csv, write_csv


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
    *,
    sample_interval_seconds: float = 0.5,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Derive overall metrics, confusion matrix, scenario rates, latency, and errors."""

    if not np.isfinite(sample_interval_seconds) or sample_interval_seconds <= 0:
        raise ValueError("sample_interval_seconds must be positive and finite")
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
        true_negatives = int(((actual_subset == 0) & (predicted_subset == 0)).sum())
        false_negatives = anomalous - detected
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
                "normal_duration_hours": normal_samples * sample_interval_seconds / 3600.0,
                "false_alarms_per_hour": (
                    _safe_rate(
                        false_positives * 3600,
                        normal_samples * sample_interval_seconds,
                    )
                    if normal_samples
                    else pd.NA
                ),
                "accuracy": _safe_rate(detected + true_negatives, len(subset)),
                "precision": _safe_rate(detected, detected + false_positives),
                "recall": _safe_rate(detected, anomalous),
                "f1_score": _safe_rate(
                    2 * detected,
                    2 * detected + false_positives + false_negatives,
                ),
                "true_positives": detected,
                "true_negatives": true_negatives,
                "false_negatives": false_negatives,
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
                    "detection_delay_seconds": (
                        (first_detection - onset) * sample_interval_seconds
                        if first_detection is not None
                        else pd.NA
                    ),
                    "detected": first_detection is not None,
                }
            )

    latency_frame = pd.DataFrame(latency_rows)
    if not latency_frame.empty:
        scenario_frame = pd.DataFrame(scenario_rows).merge(
            latency_frame[
                ["scenario", "detection_delay_samples", "detection_delay_seconds"]
            ],
            on="scenario",
            how="left",
        )
    else:
        scenario_frame = pd.DataFrame(scenario_rows)

    error_mask = events["actual_label"] != events["predicted_label"]
    errors = events.loc[error_mask].copy()
    errors["error_type"] = np.where(
        errors["actual_label"] == 0, "false_positive", "false_negative"
    )
    error_columns = [
        "timestamp",
        "asset_id",
        "scenario",
        *FEATURE_COLUMNS,
        "is_anomaly",
        "anomaly_score",
        "actual_label",
        "predicted_label",
        "error_type",
    ]
    errors = errors.loc[:, [column for column in error_columns if column in errors.columns]]
    return metrics, matrix, scenario_frame, latency_frame, errors


def summarize_detection_latency(latency: pd.DataFrame) -> pd.DataFrame:
    """Summarize scenario-level detection delays in observation samples."""

    delays = pd.to_numeric(latency["detection_delay_samples"], errors="coerce").dropna()
    detected_scenarios = int(latency["detected"].astype(bool).sum())
    return pd.DataFrame(
        [
            {
                "anomalous_scenarios": int(len(latency)),
                "detected_scenarios": detected_scenarios,
                "missed_scenarios": int(len(latency) - detected_scenarios),
                "mean_detection_delay_samples": (
                    float(delays.mean()) if not delays.empty else pd.NA
                ),
                "median_detection_delay_samples": (
                    float(delays.median()) if not delays.empty else pd.NA
                ),
                "max_detection_delay_samples": (
                    int(delays.max()) if not delays.empty else pd.NA
                ),
            }
        ]
    )


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
        "--latency-summary-output",
        type=Path,
        default=RESULTS_DIR / "detection_latency_summary.csv",
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
    latency_summary = summarize_detection_latency(latency)

    write_csv(events, args.predictions_output)
    write_csv(metrics, args.metrics_output)
    write_csv(matrix, args.confusion_output)
    write_csv(scenario_rates, args.scenario_output)
    write_csv(latency, args.latency_output)
    write_csv(latency_summary, args.latency_summary_output)
    write_csv(errors, args.errors_output)

    metric_values = dict(zip(metrics["metric"], metrics["value"]))
    print(f"Evaluated {len(events)} synthetic observations from actual predictions.")
    print(
        "Accuracy={accuracy:.3f}, Precision={precision:.3f}, Recall={recall:.3f}, F1={f1_score:.3f}, FPR={false_positive_rate:.3f}".format(
            **metric_values
        )
    )
    print(
        "Detection latency: {detected_scenarios}/{anomalous_scenarios} scenarios detected, "
        "mean={mean_detection_delay_samples} samples".format(
            **latency_summary.iloc[0].to_dict()
        )
    )
    print("Metrics by scenario:")
    for row in scenario_rates.itertuples(index=False):
        print(
            f"{row.scenario}: accuracy={row.accuracy:.3f}, "
            f"precision={row.precision:.3f}, recall={row.recall:.3f}, "
            f"F1={row.f1_score:.3f}, FPR={row.false_positive_rate:.3f}"
        )
    print(f"Saved evaluation artifacts to {args.metrics_output.parent}")


if __name__ == "__main__":
    main()
