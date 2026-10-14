# CHEM-SHIELD AI/ML: Physical-Process Anomaly Detection

The earlier `ML_README.md` content has been merged here; the separate file was
removed to keep the maintained documentation in a single place.

## Purpose and scope

This directory contains the AI/ML physical-process anomaly detector for the CHEM-SHIELD academic prototype. It answers one limited question:

> Does the current physical/process telemetry look anomalous compared with learned normal behavior?

The detector is intentionally limited to simulated motor telemetry and an Isolation Forest baseline. It does not implement network monitoring, Modbus inspection, correlation, risk scoring, automated response, PLC control, or any interaction with real industrial, military, or other operational systems. Part 4 separately accepts normalized events and renders risk in the Part 1 HMI.

**The AI/ML component does not determine overall cybersecurity risk. It provides physical-process anomaly evidence to the separate correlation and risk-engine components.**

## Architecture boundary

```text
OT simulator -> physical telemetry -> feature engineering -> Isolation Forest
             -> physical ML event -> separate correlation/risk components
```

This module stops after emitting the physical ML event. A physical anomaly is not described as an attack detection.

## Synthetic laboratory data

All included data is **synthetic laboratory data generated for controlled academic experimentation**. It does not represent real Ethiopian defense-industrial telemetry, a real machine, or a real facility. Results from the supplied scenarios demonstrate pipeline behavior only; they are not real-world performance claims.

## Input telemetry and features

The baseline accepts a chronological CSV or `pandas.DataFrame` with:

```text
timestamp,motor_speed,temperature,vibration
```

`timestamp` is required at inference so every event can be integrated downstream. The detector also accepts and preserves useful non-model columns such as `asset_id`, `scenario`, and evaluation-only `actual_label`. Additional numeric process variables may be retained in the input for future experiments, but this lightweight baseline trains only on these six documented features:

```text
motor_speed
temperature
vibration
temperature_rate
vibration_rate
speed_rate
```

Rates are differences between consecutive observations, measured per observation rather than per second. The first observation in a newly loaded independent stream receives zero rate values. For a streaming caller, the detector maintains the previous sensor state between single-observation calls; callers may reset it with `reset_stream()` or provide `previous_state`. Evaluation scenarios use `scenario` as an explicit independent-stream boundary, so their first rows are also initialized to zero rather than receiving artificial boundary spikes.

Process values are converted to numeric. Short missing runs are linearly interpolated; missing values at either edge use the nearest observed value. A required process column containing no numeric values is rejected. Timestamps must be present and non-decreasing for inference.

## Model and anomaly score

Training uses only normal-operation telemetry with scikit-learn's `IsolationForest` and `random_state=42`. The default `contamination=0.05` configures Isolation Forest's expected outlier proportion; it can be adjusted deliberately at training time. If an input training CSV includes `actual_label` or `is_anomaly`, every value must explicitly indicate normal behavior (`0` or `False`); otherwise training is rejected.

`is_anomaly` uses Isolation Forest's native binary prediction:

```text
1  -> normal -> is_anomaly=False
-1 -> anomaly -> is_anomaly=True
```

`anomaly_score` is separate from that decision. It is a normalized anomaly-indicator score in `[0, 1]`, where higher values mean stronger deviation from learned normal behavior. It is **not a probability** and is not thresholded to make the binary decision. The saved model calibrates this displayed score from the observed minimum and maximum of negated `score_samples` on the normal training data. The binary decision always remains the model's native decision boundary.

## Project layout

```text
chem_shield_p3/
├── README.md
├── requirements.txt
├── src/
│   ├── detector.py       # Reusable PhysicalAnomalyDetector API
│   ├── features.py       # Validation, imputation, and six features
│   ├── model.py          # Model-facing import
│   └── io_utils.py       # Project paths and CSV helpers
├── scripts/
│   ├── generate_normal_data.py
│   ├── generate_test_scenarios.py
│   ├── train_model.py
│   ├── run_detection.py
│   ├── evaluate_model.py
│   └── visualize_results.py
├── data/
├── models/
├── results/
└── graphs/
```

The historical top-level script names are compatibility entry points. Use `scripts/` for new work.

## Setup

From the repository root, install the Part 3 dependencies in the environment
used to run the detector:

```bash
python3 -m pip install -r chem_shield_p3/requirements.txt
```

## Training and inference

Training and inference are deliberately separate: normal telemetry is used to train once, and new telemetry uses the persisted model without retraining.

```bash
cd chem_shield_p3
# Optional: regenerate controlled synthetic inputs
python3 scripts/generate_normal_data.py
python3 scripts/generate_test_scenarios.py

# Train only from normal telemetry and save model plus feature configuration
python3 scripts/train_model.py

# Infer using the existing model; this does not retrain
python3 scripts/run_detection.py \
  --input data/test_scenarios.csv \
  --stream-column scenario \
  --output results/physical_ml_output.csv
```

The default saved artifact is `models/isolation_forest.joblib`. It contains the fitted Isolation Forest, feature order, model settings, rate policy, score calibration, and training metadata needed for compatible inference.

## Output contract

`results/physical_ml_output.csv` is machine readable. Each observation includes at least:

```text
timestamp
asset_id
motor_speed
temperature
vibration
temperature_rate
vibration_rate
speed_rate
source
is_anomaly
anomaly_score
model
```

The default `asset_id` is `MOTOR-01`; a telemetry `asset_id` is preserved, or a caller may supply one. `source` is always `physical_ml`, and `model` is `IsolationForest`. `model_decision_score` is included for transparent diagnostics and plotting. Optional input columns may be passed through, including synthetic evaluation labels, but no risk, correlation, network, criticality, or attack-type fields are created.

A representative event is:

```json
{
  "timestamp": 123,
  "asset_id": "MOTOR-01",
  "source": "physical_ml",
  "is_anomaly": true,
  "anomaly_score": 0.91,
  "model": "IsolationForest"
}
```

## Python API

```python
import pandas as pd
from src.detector import PhysicalAnomalyDetector

normal_data = pd.read_csv("data/normal_data_large.csv")
detector = PhysicalAnomalyDetector().fit(normal_data)
detector.save("models/isolation_forest.joblib")

# A single mapping returns one event dictionary and keeps stream state.
event = detector.predict({
    "timestamp": 1001,
    "motor_speed": 50.2,
    "temperature": 40.1,
    "vibration": 0.11,
    "asset_id": "MOTOR-01",
})

# A DataFrame returns one event row per telemetry observation.
events = detector.predict(pd.read_csv("data/test_scenarios.csv"), stream_column="scenario")
```

For a newly independent single-observation stream, call `detector.reset_stream()` first. Alternatively, provide `previous_state` containing `motor_speed`, `temperature`, and `vibration` when the preceding state is managed by another component.

## Part 4 handoff

There is no automatic producer-to-HMI connection. To submit a detector result,
POST the normalized event to Part 1's `POST /api/risk/events` endpoint. Preserve
the detector's actual `[0,1]` `anomaly_score`; it is not a probability. Convert
the detector timestamp to an ISO-8601 UTC string if needed. For example:

```json
{
  "timestamp": "2026-10-14T09:30:04Z",
  "source": "physical_ml",
  "asset_id": "MOTOR-01",
  "event_type": "physical_ml_anomaly",
  "anomaly_score": 0.91,
  "evidence": {"model": "IsolationForest", "is_anomaly": true}
}
```

Part 4 retains this evidence, classifies the source as physical, and correlates
it with events for the same asset in its configured time window. The example
value illustrates the output shape only; it is not a measured result. See
[Part 4's integration and risk semantics](../chem_shield_p4/correlation/README.md).

## Controlled evaluation

The supplied synthetic scenarios are `normal`, `sudden_change`, `unstable_behavior`, and `gradual_deviation`. Evaluation must use labels only after inference; labels are never model features.

```bash
python3 scripts/evaluate_model.py
python3 scripts/visualize_results.py
```

`evaluate_model.py` computes from actual predictions, with safe zero-division behavior:

- `results/evaluation_results.csv`: accuracy, precision, recall, F1-score, false-positive rate, TP, TN, FP, and FN.
- `results/confusion_matrix.csv`: actual normal/anomaly by predicted normal/anomaly.
- `results/scenario_evaluation.csv`: anomalous sample count, detected count, detection rate, and normal false-positive rate per scenario.
- `results/detection_latency.csv`: first post-onset detection and detection delay in samples for each abnormal scenario. It is not a millisecond measurement.
- `results/ml_errors.csv`: false-positive and false-negative observations with process values and anomaly outputs.
- `graphs/`: motor behavior, anomaly-score, scenario-detection, confusion-matrix, and calculated-metrics plots.

All metrics and figures are generated from the experiment artifacts; no performance numbers are embedded in the scripts or documentation.

## Limitations

This is a one-model, synthetic, controlled academic proof of concept. The baseline is not calibrated or validated for a real operational environment, does not establish cause, and does not identify an attack. It only produces physical-process anomaly evidence for a separate system component to interpret.
