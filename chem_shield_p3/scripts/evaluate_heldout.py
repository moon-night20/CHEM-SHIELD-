"""Evaluate complete attack scenarios absent from normal-only P1 training."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from chem_shield_p3.scripts.evaluate_model import calculate_evaluation
from chem_shield_p3.src.detector import PhysicalAnomalyDetector
from chem_shield_p3.src.io_utils import (
    DATA_DIR,
    RESULTS_DIR,
    read_telemetry_csv,
    write_csv,
)

HELDOUT_SCENARIOS = ("stealthy_in_range", "slow_gradual_drift")
SAMPLE_INTERVAL_SECONDS = 0.5


def select_heldout_scenarios(
    scenarios: pd.DataFrame,
    heldout: tuple[str, ...] = HELDOUT_SCENARIOS,
) -> pd.DataFrame:
    """Select normal baseline plus complete, explicitly held-out scenarios."""
    if "scenario" not in scenarios.columns:
        raise ValueError("scenario data must include a scenario column")
    present = set(scenarios["scenario"].astype(str))
    missing = set(heldout).difference(present)
    if missing:
        raise ValueError("held-out scenarios are missing: " + ", ".join(sorted(missing)))
    selected = scenarios[scenarios["scenario"].isin(("normal", *heldout))].copy()
    selected = selected.sort_values("timestamp", kind="stable").reset_index(drop=True)
    if selected.empty or "normal" not in set(selected["scenario"]):
        raise ValueError("evaluation data must include a normal baseline scenario")
    return selected


def run_heldout_evaluation(
    *,
    training_path: str | Path = DATA_DIR / "normal_data_large.csv",
    scenarios_path: str | Path = DATA_DIR / "test_scenarios.csv",
    output_dir: str | Path = RESULTS_DIR,
) -> pd.DataFrame:
    training = read_telemetry_csv(training_path)
    evaluation = select_heldout_scenarios(read_telemetry_csv(scenarios_path))

    detector = PhysicalAnomalyDetector(contamination=0.05, random_state=42).fit(training)
    predictions = detector.predict(evaluation, stream_column="scenario")
    if not isinstance(predictions, pd.DataFrame):
        raise RuntimeError("P3 detector returned a single event for batch evaluation")
    metrics, _matrix, per_scenario, _latency, _errors = calculate_evaluation(
        predictions,
        sample_interval_seconds=SAMPLE_INTERVAL_SECONDS,
    )

    output = Path(output_dir)
    write_csv(predictions, output / "heldout_predictions.csv")
    write_csv(per_scenario, output / "heldout_scenario_evaluation.csv")
    metric_values = dict(zip(metrics["metric"], metrics["value"]))
    normal_results = per_scenario.loc[per_scenario["scenario"] == "normal"]
    normal_false_alarms_per_hour = (
        float(normal_results.iloc[0]["false_alarms_per_hour"])
        if not normal_results.empty
        else 0.0
    )
    summary = {
        "protocol": "train on P1-simulated normal runs only; hold out complete attack scenarios",
        "training_rows": len(training),
        "training_attack_rows": (
            int((pd.to_numeric(training["actual_label"]) == 1).sum())
            if "actual_label" in training.columns
            else 0
        ),
        "training_rpm_unit": "rpm",
        "heldout_scenarios": list(HELDOUT_SCENARIOS),
        "sample_interval_seconds": SAMPLE_INTERVAL_SECONDS,
        "normal_false_alarms_per_hour": normal_false_alarms_per_hour,
        "accuracy": float(metric_values["accuracy"]),
        "false_positive_rate": float(metric_values["false_positive_rate"]),
        "scenario_results": per_scenario.astype(object)
        .where(pd.notna(per_scenario), None)
        .to_dict(orient="records"),
        "limitations": (
            "Synthetic P1 simulator and generated scenarios only; not evidence "
            "of real-world detection performance."
        ),
    }
    (output / "heldout_evaluation_summary.json").write_text(
        json.dumps(summary, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, allow_nan=False))
    return per_scenario


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate P3 on whole held-out attack scenarios."
    )
    parser.add_argument("--training", type=Path, default=DATA_DIR / "normal_data_large.csv")
    parser.add_argument("--scenarios", type=Path, default=DATA_DIR / "test_scenarios.csv")
    parser.add_argument("--output-dir", type=Path, default=RESULTS_DIR)
    args = parser.parse_args()
    run_heldout_evaluation(
        training_path=args.training,
        scenarios_path=args.scenarios,
        output_dir=args.output_dir,
    )


if __name__ == "__main__":
    main()
