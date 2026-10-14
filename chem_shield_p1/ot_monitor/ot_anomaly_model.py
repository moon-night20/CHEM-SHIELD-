"""Physical-process Isolation Forest, independent of network-flow models."""

from __future__ import annotations

import math
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

from .sensor_validation import parse_timestamp


MODEL_VERSION = "chem-shield-physical-iforest-1.0"
SENSOR_FIELDS = ("temperature", "pressure", "speed")


def _valid_measurement(record: Dict[str, Any], key: str) -> float:
    value = record.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"Model input field {key!r} must be numeric")
    value = float(value)
    if not math.isfinite(value):
        raise ValueError(f"Model input field {key!r} must be finite")
    return value


class PhysicalProcessIsolationForest:
    """Isolation Forest trained only on normal, explicitly designated telemetry.

    `anomaly_score` is a bounded monotonic transform of scikit-learn's decision
    function. It is an anomaly ranking signal, not a calibrated probability.
    """

    def __init__(
        self,
        n_estimators: int = 100,
        contamination: str | float = 0.1,
        random_state: int = 17,
    ) -> None:
        if n_estimators < 1:
            raise ValueError("n_estimators must be at least 1")
        if contamination != "auto" and not 0.0 < float(contamination) <= 0.5:
            raise ValueError("contamination must be 'auto' or in (0, 0.5]")
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        self.model: Optional[IsolationForest] = None
        self.feature_names_: List[str] = []
        self.state_categories_: List[str] = []
        self.metadata: Dict[str, Any] = {}

    def fit(self, normal_records: Iterable[Dict[str, Any]]) -> "PhysicalProcessIsolationForest":
        records = list(normal_records)
        if not records:
            raise ValueError("Normal baseline data is required")
        for index, row in enumerate(records):
            if str(row.get("label", "normal")).lower() != "normal":
                raise ValueError(f"Baseline row {index} is not labeled normal")
        self.state_categories_ = sorted({
            str(row.get("operating_state", row.get("motor_status", "UNKNOWN"))).upper()
            for row in records
            if row.get("operating_state", row.get("motor_status")) is not None
        })
        matrix, self.feature_names_ = self._features(records)
        if matrix.shape[0] < 2:
            raise ValueError("At least two baseline rows are required")
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
        )
        self.model.fit(matrix)
        self.metadata = {
            "version": MODEL_VERSION,
            "algorithm": "sklearn.ensemble.IsolationForest",
            "trained_on": "normal baseline only",
            "feature_names": list(self.feature_names_),
            "state_categories": list(self.state_categories_),
            "n_estimators": self.n_estimators,
            "contamination": self.contamination,
            "random_state": self.random_state,
        }
        return self

    def _features(self, records: Sequence[Dict[str, Any]]) -> Tuple[np.ndarray, List[str]]:
        rows: List[List[float]] = []
        previous: Dict[str, Tuple[datetime, Dict[str, float]]] = {}
        feature_names = [
            "temperature",
            "pressure",
            "speed",
            "temperature_rate_per_min",
            "pressure_rate_per_min",
            "speed_rate_per_min",
        ] + [f"operating_state={state}" for state in self.state_categories_]

        for index, record in enumerate(records):
            if not isinstance(record, dict):
                raise ValueError(f"Model row {index} must be an object")
            current = {name: _valid_measurement(record, name) for name in SENSOR_FIELDS}
            timestamp = parse_timestamp(record.get("timestamp"))
            asset_id = str(record.get("asset_id", record.get("machine_id", "default")))
            rates = [0.0, 0.0, 0.0]
            prior = previous.get(asset_id)
            if prior is not None:
                prior_time, prior_values = prior
                elapsed = (timestamp - prior_time).total_seconds() / 60.0
                if elapsed <= 0:
                    raise ValueError(f"Model rows must have increasing timestamps per asset; row {index}")
                rates = [(current[name] - prior_values[name]) / elapsed for name in SENSOR_FIELDS]
            previous[asset_id] = (timestamp, current)

            state = str(record.get("operating_state", record.get("motor_status", "UNKNOWN"))).upper()
            state_features = [1.0 if state == category else 0.0 for category in self.state_categories_]
            rows.append([
                current["temperature"],
                current["pressure"],
                current["speed"],
                *rates,
                *state_features,
            ])
        if not rows:
            raise ValueError("No model rows supplied")
        return np.asarray(rows, dtype=float), feature_names

    def score_records(self, records: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if self.model is None:
            raise ValueError("Model is not fitted")
        rows = list(records)
        matrix, feature_names = self._features(rows)
        if feature_names != self.feature_names_:
            raise ValueError("Feature configuration differs from fitted model")
        decision_values = self.model.decision_function(matrix)
        predictions = self.model.predict(matrix)
        results = []
        for raw, decision, prediction in zip(rows, decision_values, predictions):
            clipped = max(-50.0, min(50.0, -5.0 * float(decision)))
            score = 1.0 / (1.0 + math.exp(-clipped))
            results.append({
                "is_anomaly": bool(prediction == -1),
                "decision_function": float(decision),
                "anomaly_score": float(score),
                "model_version": MODEL_VERSION,
            })
        return results

    def evaluate(
        self,
        labeled_records: Iterable[Dict[str, Any]],
    ) -> Dict[str, Any]:
        records = list(labeled_records)
        if not records:
            raise ValueError("Labeled evaluation data is required")
        labels = []
        for index, row in enumerate(records):
            label = str(row.get("label", "")).lower()
            if label not in {"normal", "abnormal"}:
                raise ValueError(f"Evaluation row {index} must have label 'normal' or 'abnormal'")
            labels.append(1 if label == "abnormal" else 0)
        results = self.score_records(records)
        predictions = [1 if result["is_anomaly"] else 0 for result in results]
        tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel()
        return {
            "precision": float(precision_score(labels, predictions, zero_division=0)),
            "recall": float(recall_score(labels, predictions, zero_division=0)),
            "f1": float(f1_score(labels, predictions, zero_division=0)),
            "false_positive_rate": float(fp / (fp + tn)) if fp + tn else 0.0,
            "confusion_matrix": {
                "true_negative": int(tn),
                "false_positive": int(fp),
                "false_negative": int(fn),
                "true_positive": int(tp),
            },
        }

    def save(self, path: str | Path) -> None:
        if self.model is None:
            raise ValueError("Cannot save an unfitted model")
        joblib.dump(self, path)

    @classmethod
    def load(cls, path: str | Path) -> "PhysicalProcessIsolationForest":
        loaded = joblib.load(path)
        if not isinstance(loaded, cls):
            raise TypeError(f"Artifact at {path} is not a {cls.__name__}")
        if loaded.model is None or loaded.metadata.get("version") != MODEL_VERSION:
            raise ValueError(f"Artifact at {path} is missing a compatible fitted model")
        return loaded


__all__ = ["PhysicalProcessIsolationForest", "MODEL_VERSION"]
