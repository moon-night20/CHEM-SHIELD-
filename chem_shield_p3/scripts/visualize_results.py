"""Create plots from generated evaluation artifacts, never hard-coded metrics."""

from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from chem_shield_p3.src.detector import PhysicalAnomalyDetector
from chem_shield_p3.src.io_utils import DEFAULT_MODEL_PATH, GRAPHS_DIR, RESULTS_DIR


def _save(figure: plt.Figure, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    figure.tight_layout()
    figure.savefig(output, dpi=300)
    plt.close(figure)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Visualize calculated physical ML experiment results."
    )
    parser.add_argument(
        "--predictions", type=Path, default=RESULTS_DIR / "physical_ml_output.csv"
    )
    parser.add_argument(
        "--metrics", type=Path, default=RESULTS_DIR / "evaluation_results.csv"
    )
    parser.add_argument(
        "--scenarios", type=Path, default=RESULTS_DIR / "scenario_evaluation.csv"
    )
    parser.add_argument(
        "--confusion", type=Path, default=RESULTS_DIR / "confusion_matrix.csv"
    )
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--output-dir", type=Path, default=GRAPHS_DIR)
    args = parser.parse_args()

    predictions = pd.read_csv(args.predictions)
    metrics = pd.read_csv(args.metrics)
    scenarios = pd.read_csv(args.scenarios)
    confusion = pd.read_csv(args.confusion)
    detector = PhysicalAnomalyDetector.load(args.model)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    # Plot 1: observed motor speed and the model's physical anomaly decisions.
    figure, axis = plt.subplots(figsize=(10, 5))
    axis.plot(predictions["timestamp"], predictions["motor_speed"], color="0.65", label="Telemetry")
    anomalies = predictions[predictions["is_anomaly"].astype(bool)]
    axis.scatter(
        anomalies["timestamp"],
        anomalies["motor_speed"],
        color="tab:red",
        s=20,
        label="Physical anomaly detected",
        zorder=3,
    )
    axis.set(xlabel="Timestamp", ylabel="Motor speed", title="Synthetic machine behavior")
    axis.legend()
    _save(figure, args.output_dir / "motor_behavior.png")

    # Plot 2: normalized indicator with the transformed native decision boundary.
    figure, axis = plt.subplots(figsize=(10, 5))
    axis.plot(predictions["timestamp"], predictions["anomaly_score"], color="tab:purple")
    threshold = detector.normalized_native_threshold
    axis.axhline(
        threshold,
        color="tab:red",
        linestyle="--",
        label="Native Isolation Forest decision boundary",
    )
    axis.set(
        xlabel="Timestamp",
        ylabel="Normalized anomaly indicator (not probability)",
        ylim=(-0.05, 1.05),
        title="Physical anomaly indicator over time",
    )
    axis.legend()
    _save(figure, args.output_dir / "anomaly_score.png")

    # Plot 3: per-scenario detection rates calculated from labeled predictions.
    anomalous_scenarios = scenarios[scenarios["anomalous_samples"] > 0]
    figure, axis = plt.subplots(figsize=(9, 5))
    bars = axis.bar(
        anomalous_scenarios["scenario"],
        anomalous_scenarios["detection_rate"],
        color="tab:blue",
    )
    axis.set(
        ylabel="Detection rate",
        ylim=(0, 1.05),
        title="Detection rate by synthetic scenario",
    )
    for bar, value in zip(bars, anomalous_scenarios["detection_rate"]):
        axis.text(bar.get_x() + bar.get_width() / 2, float(value) + 0.02, f"{value:.2f}", ha="center")
    _save(figure, args.output_dir / "scenario_detection.png")

    # Plot 4: actual confusion-matrix values produced by the evaluation script.
    values = confusion[["predicted_normal", "predicted_anomaly"]].to_numpy(dtype=int)
    figure, axis = plt.subplots(figsize=(6, 5))
    image = axis.imshow(values, cmap="Blues")
    axis.figure.colorbar(image, ax=axis)
    axis.set(
        xticks=np.arange(2),
        yticks=np.arange(2),
        xticklabels=["Normal", "Anomaly"],
        yticklabels=["Normal", "Anomaly"],
        xlabel="Predicted", ylabel="Actual", title="Confusion matrix",
    )
    for row in range(values.shape[0]):
        for column in range(values.shape[1]):
            axis.text(column, row, str(values[row, column]), ha="center", va="center")
    _save(figure, args.output_dir / "confusion_matrix.png")

    # Supplementary plot: the calculated aggregate rate metrics.
    rate_metrics = metrics[metrics["metric"].isin(["accuracy", "precision", "recall", "f1_score", "false_positive_rate"])]
    figure, axis = plt.subplots(figsize=(9, 5))
    bars = axis.bar(rate_metrics["metric"], rate_metrics["value"], color="tab:green")
    axis.set(ylabel="Value", ylim=(0, 1.05), title="Calculated evaluation metrics")
    axis.tick_params(axis="x", rotation=25)
    for bar, value in zip(bars, rate_metrics["value"]):
        axis.text(bar.get_x() + bar.get_width() / 2, float(value) + 0.02, f"{value:.2f}", ha="center")
    _save(figure, args.output_dir / "evaluation_metrics.png")

    print(f"Wrote plots to {args.output_dir}")


if __name__ == "__main__":
    main()
