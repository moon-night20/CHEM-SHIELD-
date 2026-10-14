"""Reusable Isolation Forest detector for physical-process anomalies only."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.exceptions import NotFittedError

from .features import (
    BASE_FEATURE_COLUMNS,
    FEATURE_COLUMNS,
    TelemetryValidationError,
    build_feature_frame,
    last_process_state,
)

MODEL_NAME = "IsolationForest"
EVENT_SOURCE = "physical_ml"
DEFAULT_ASSET_ID = "MOTOR-01"
ARTIFACT_VERSION = 1


class PhysicalAnomalyDetector:
    """Learn normal process behavior and emit physical anomaly events.

    The binary ``is_anomaly`` result comes directly from Isolation Forest's
    native prediction (``-1`` is anomalous; ``1`` is normal). ``anomaly_score``
    is a separately calibrated, normalized anomaly indicator in [0, 1]; it is
    not a probability and is never used as the binary decision threshold.
    """

    def __init__(self, *, contamination: float = 0.05, random_state: int = 42) -> None:
        if not 0.0 < contamination <= 0.5:
            raise ValueError("contamination must be greater than 0 and no greater than 0.5")
        self.contamination = float(contamination)
        self.random_state = int(random_state)
        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
        )
        self.feature_columns = list(FEATURE_COLUMNS)
        self.score_lower: float | None = None
        self.score_upper: float | None = None
        self.training_metadata: dict[str, Any] = {}
        self._stream_state: dict[str, float] | None = None
        self._is_fitted = False

    def fit(
        self,
        normal_data: pd.DataFrame,
        *,
        stream_column: str | None = None,
    ) -> "PhysicalAnomalyDetector":
        """Fit only on normal-operation telemetry.

        ``normal_data`` is expected to contain normal observations exclusively.
        When it has timestamps, they must already be chronological. Each newly
        loaded independent stream starts with zero rate features unless a stream
        column is explicitly supplied.
        """

        if "actual_label" in normal_data.columns:
            labels = pd.to_numeric(normal_data["actual_label"], errors="coerce")
            if labels.isna().any() or not (labels == 0).all():
                raise TelemetryValidationError(
                    "normal-only training rejects actual_label values other than 0"
                )
        if "is_anomaly" in normal_data.columns:
            anomaly_flags = normal_data["is_anomaly"].astype(str).str.strip().str.lower()
            normal_values = {"false", "0", "0.0"}
            if not anomaly_flags.isin(normal_values).all():
                raise TelemetryValidationError(
                    "normal-only training rejects is_anomaly values other than False"
                )

        prepared, features = build_feature_frame(
            normal_data,
            stream_column=stream_column,
            require_timestamp=False,
        )
        self.model.fit(features)

        # score_samples is lower for more isolated points. Negating it produces
        # anomaly evidence where a larger value means greater deviation. The
        # observed normal-training range calibrates the displayed score without
        # changing Isolation Forest's native binary decision.
        training_evidence = -self.model.score_samples(features)
        lower, upper = float(training_evidence.min()), float(training_evidence.max())
        if np.isclose(lower, upper):
            upper = float(lower + np.finfo(float).eps)

        self.score_lower = float(lower)
        self.score_upper = float(upper)
        self.training_metadata = {
            "artifact_version": ARTIFACT_VERSION,
            "model": MODEL_NAME,
            "trained_at_utc": datetime.now(timezone.utc).isoformat(),
            "training_rows": int(len(prepared)),
            "feature_columns": self.feature_columns,
            "rate_policy": (
                "Rates are consecutive-observation differences; the first row of an "
                "independent stream is assigned 0.0 unless a prior state is supplied."
            ),
            "missing_value_policy": (
                "Numeric process values are linearly interpolated within a batch; "
                "edge gaps use the nearest observed value."
            ),
            "score_calibration": (
                "anomaly_score scales negated Isolation Forest score_samples using the "
                "observed minimum and maximum from normal training telemetry."
            ),
        }
        self._stream_state = None
        self._is_fitted = True
        return self

    def reset_stream(self) -> None:
        """Start a new single-observation stream so its first rates become zero."""

        self._stream_state = None

    def _require_fitted(self) -> None:
        if not self._is_fitted or self.score_lower is None or self.score_upper is None:
            raise NotFittedError("fit the detector or load a saved model before prediction")

    def _normalized_score(self, features: pd.DataFrame) -> np.ndarray:
        self._require_fitted()
        evidence = -self.model.score_samples(features)
        denominator = self.score_upper - self.score_lower
        return np.clip((evidence - self.score_lower) / denominator, 0.0, 1.0)

    @property
    def normalized_native_threshold(self) -> float:
        """Display-only score location of the native Isolation Forest boundary."""

        self._require_fitted()
        # IsolationForest's decision_function boundary is exactly zero. Since
        # decision_function = score_samples - offset_, this is the equivalent
        # negated score_samples evidence at the native binary boundary.
        boundary_evidence = -float(self.model.offset_)
        denominator = self.score_upper - self.score_lower
        return float(np.clip((boundary_evidence - self.score_lower) / denominator, 0.0, 1.0))

    def _resolve_asset_ids(
        self, prepared: pd.DataFrame, asset_id: str | None
    ) -> pd.Series:
        if asset_id is not None:
            return pd.Series(asset_id, index=prepared.index, dtype="object")
        if "asset_id" in prepared.columns:
            return prepared["asset_id"].fillna(DEFAULT_ASSET_ID).astype(str)
        return pd.Series(DEFAULT_ASSET_ID, index=prepared.index, dtype="object")

    def _event_frame(
        self,
        prepared: pd.DataFrame,
        features: pd.DataFrame,
        *,
        asset_id: str | None,
    ) -> pd.DataFrame:
        native_prediction = self.model.predict(features)
        decision_scores = self.model.decision_function(features)
        result = prepared.copy()
        result["asset_id"] = self._resolve_asset_ids(prepared, asset_id)
        result["source"] = EVENT_SOURCE
        result["is_anomaly"] = native_prediction == -1
        result["anomaly_score"] = self._normalized_score(features)
        result["model"] = MODEL_NAME
        result["model_decision_score"] = decision_scores

        core_columns = [
            "timestamp",
            "asset_id",
            *BASE_FEATURE_COLUMNS,
            "temperature_rate",
            "vibration_rate",
            "speed_rate",
            "source",
            "is_anomaly",
            "anomaly_score",
            "model",
            "model_decision_score",
        ]
        passthrough_columns = [
            column
            for column in result.columns
            if column not in core_columns and column not in {"asset_id", "source"}
        ]
        return result.loc[:, [*core_columns, *passthrough_columns]]

    def predict(
        self,
        telemetry: pd.DataFrame | Mapping[str, Any],
        *,
        asset_id: str | None = None,
        previous_state: Mapping[str, Any] | None = None,
        stream_column: str | None = None,
    ) -> pd.DataFrame | dict[str, Any]:
        """Return ML events for a telemetry batch or one mapping.

        A DataFrame is treated as one independent batch: its first rate values
        are zero unless ``previous_state`` is supplied. A single mapping keeps
        stream state between calls; call ``reset_stream`` before a new stream.
        ``stream_column`` resets rates for each group in a batch.
        """

        self._require_fitted()
        is_single_observation = isinstance(telemetry, Mapping)
        if is_single_observation:
            frame = pd.DataFrame([dict(telemetry)])
            prior = previous_state if previous_state is not None else self._stream_state
        elif isinstance(telemetry, pd.DataFrame):
            frame = telemetry.copy()
            prior = previous_state
        else:
            raise TypeError("telemetry must be a pandas DataFrame or a mapping")

        prepared, features = build_feature_frame(
            frame,
            previous_state=prior,
            stream_column=stream_column,
            require_timestamp=True,
        )
        events = self._event_frame(prepared, features, asset_id=asset_id)
        if is_single_observation:
            if stream_column is None:
                self._stream_state = last_process_state(prepared)
            event = events.iloc[0].to_dict()
            event["is_anomaly"] = bool(event["is_anomaly"])
            event["anomaly_score"] = float(event["anomaly_score"])
            event["model_decision_score"] = float(event["model_decision_score"])
            return event
        return events

    def predict_csv(
        self,
        input_path: str | Path,
        output_path: str | Path,
        *,
        asset_id: str | None = None,
        stream_column: str | None = None,
    ) -> pd.DataFrame:
        """Read telemetry CSV, write physical ML events CSV, and return events."""

        telemetry = pd.read_csv(input_path)
        events = self.predict(
            telemetry,
            asset_id=asset_id,
            stream_column=stream_column,
        )
        if not isinstance(events, pd.DataFrame):  # Defensive guard for the API union.
            raise RuntimeError("batch prediction unexpectedly returned a single event")
        destination = Path(output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        events.to_csv(destination, index=False)
        return events

    def save(self, path: str | Path) -> Path:
        """Persist the fitted Isolation Forest and inference configuration together."""

        self._require_fitted()
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "artifact_version": ARTIFACT_VERSION,
                "model": self.model,
                "contamination": self.contamination,
                "random_state": self.random_state,
                "feature_columns": self.feature_columns,
                "score_lower": self.score_lower,
                "score_upper": self.score_upper,
                "training_metadata": self.training_metadata,
            },
            destination,
        )
        return destination

    @classmethod
    def load(cls, path: str | Path) -> "PhysicalAnomalyDetector":
        """Load a detector artifact created by :meth:`save`."""

        payload = joblib.load(path)
        required_keys = {
            "artifact_version",
            "model",
            "contamination",
            "random_state",
            "feature_columns",
            "score_lower",
            "score_upper",
            "training_metadata",
        }
        missing = required_keys.difference(payload)
        if missing:
            raise TelemetryValidationError(
                "model artifact is missing required fields: " + ", ".join(sorted(missing))
            )
        if payload["artifact_version"] != ARTIFACT_VERSION:
            raise TelemetryValidationError("unsupported model artifact version")
        if list(payload["feature_columns"]) != list(FEATURE_COLUMNS):
            raise TelemetryValidationError("model artifact feature configuration is incompatible")
        if not isinstance(payload["model"], IsolationForest):
            raise TelemetryValidationError("model artifact does not contain an IsolationForest")

        detector = cls(
            contamination=float(payload["contamination"]),
            random_state=int(payload["random_state"]),
        )
        detector.model = payload["model"]
        detector.feature_columns = list(payload["feature_columns"])
        detector.score_lower = float(payload["score_lower"])
        detector.score_upper = float(payload["score_upper"])
        detector.training_metadata = dict(payload["training_metadata"])
        detector._is_fitted = True
        return detector
