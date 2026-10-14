"""Validation and feature engineering for synthetic physical-process telemetry.

Rate features are differences between consecutive observations, expressed per
observation rather than per unit of time. For a new independent stream the
first rate is set to 0.0. A caller processing one observation at a time may
supply the preceding sensor state instead.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import numpy as np
import pandas as pd

BASE_FEATURE_COLUMNS = ("motor_speed", "temperature", "vibration")
RATE_FEATURE_COLUMNS = ("temperature_rate", "vibration_rate", "speed_rate")
FEATURE_COLUMNS = (*BASE_FEATURE_COLUMNS, *RATE_FEATURE_COLUMNS)
RATE_SOURCE_COLUMNS = {
    "temperature_rate": "temperature",
    "vibration_rate": "vibration",
    "speed_rate": "motor_speed",
}

# Explicit shared mapping from OT telemetry measurement keys to P3 model feature names
TELEMETRY_TO_FEATURE_MAP = {
    "speed": "motor_speed",
    "motor_speed": "motor_speed",
    "temperature": "temperature",
    "vibration": "vibration",
}


def map_telemetry_reading(measurements: Mapping[str, Any]) -> dict[str, float]:
    """Map raw telemetry measurements (e.g. from P5 reading) to P3 feature names."""
    result = {}
    for source_key, target_key in TELEMETRY_TO_FEATURE_MAP.items():
        if source_key in measurements and target_key not in result:
            val = measurements[source_key]
            if val is not None:
                result[target_key] = float(val)
    return result


class TelemetryValidationError(ValueError):
    """Raised when telemetry cannot be safely transformed into ML features."""


def _validate_dataframe(data: pd.DataFrame) -> None:
    if not isinstance(data, pd.DataFrame):
        raise TypeError("telemetry must be provided as a pandas DataFrame")
    if data.empty:
        raise TelemetryValidationError("telemetry must contain at least one observation")

    missing = [column for column in BASE_FEATURE_COLUMNS if column not in data.columns]
    if missing:
        raise TelemetryValidationError(
            "telemetry is missing required process columns: " + ", ".join(missing)
        )


def _validate_timestamp(data: pd.DataFrame, required: bool) -> None:
    if "timestamp" not in data.columns:
        if required:
            raise TelemetryValidationError("inference telemetry must include a timestamp")
        return

    timestamp = data["timestamp"]
    if timestamp.isna().any():
        raise TelemetryValidationError("timestamp values must not be missing")
    if not timestamp.is_monotonic_increasing:
        raise TelemetryValidationError(
            "telemetry must be ordered by non-decreasing timestamp before feature generation"
        )


def _clean_process_values(data: pd.DataFrame) -> pd.DataFrame:
    numeric = data.loc[:, list(BASE_FEATURE_COLUMNS)].apply(pd.to_numeric, errors="coerce")
    empty_columns = [
        column for column in BASE_FEATURE_COLUMNS if numeric[column].isna().all()
    ]
    if empty_columns:
        raise TelemetryValidationError(
            "process columns contain no numeric values: " + ", ".join(empty_columns)
        )

    # A short missing run is linearly interpolated, with edge gaps filled from the
    # nearest observed value. The same cleaned values are used for rates and ML input.
    cleaned = numeric.interpolate(limit_direction="both").ffill().bfill()
    if cleaned.isna().any().any():
        raise TelemetryValidationError("process values could not be completed safely")
    return cleaned.astype(float)


def _coerce_previous_state(previous_state: Mapping[str, Any] | None) -> dict[str, float] | None:
    if previous_state is None:
        return None
    if not isinstance(previous_state, Mapping):
        raise TypeError("previous_state must be a mapping of process variable names to values")

    state: dict[str, float] = {}
    for column in BASE_FEATURE_COLUMNS:
        if column not in previous_state:
            raise TelemetryValidationError(
                f"previous_state is missing required process value: {column}"
            )
        value = pd.to_numeric(previous_state[column], errors="coerce")
        if pd.isna(value) or not np.isfinite(float(value)):
            raise TelemetryValidationError(
                f"previous_state value for {column} must be finite and numeric"
            )
        state[column] = float(value)
    return state


def build_feature_frame(
    data: pd.DataFrame,
    *,
    previous_state: Mapping[str, Any] | None = None,
    stream_column: str | None = None,
    require_timestamp: bool = False,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return cleaned telemetry and the six Isolation Forest feature columns.

    If ``stream_column`` is supplied, each stream's first observation receives
    zero rates. This is useful for independently generated evaluation scenarios.
    ``previous_state`` is intentionally not combined with grouped streams because
    it describes one preceding state, not one state per stream.
    """

    _validate_dataframe(data)
    _validate_timestamp(data, required=require_timestamp)
    if stream_column is not None and stream_column not in data.columns:
        raise TelemetryValidationError(f"stream column is not present: {stream_column}")
    if stream_column is not None and data[stream_column].isna().any():
        raise TelemetryValidationError("stream column values must not be missing")
    if stream_column is not None and previous_state is not None:
        raise TelemetryValidationError(
            "provide either stream_column or previous_state, not both"
        )

    prepared = data.copy().reset_index(drop=True)
    cleaned = _clean_process_values(prepared)
    prepared.loc[:, list(BASE_FEATURE_COLUMNS)] = cleaned

    previous = _coerce_previous_state(previous_state)
    rate_values = pd.DataFrame(index=prepared.index)
    for rate_column, source_column in RATE_SOURCE_COLUMNS.items():
        if stream_column is None:
            differences = cleaned[source_column].diff()
            first_rate = (
                cleaned[source_column].iloc[0] - previous[source_column]
                if previous is not None
                else 0.0
            )
            differences.iloc[0] = first_rate
        else:
            differences = cleaned[source_column].groupby(
                prepared[stream_column], sort=False
            ).diff().fillna(0.0)
        rate_values[rate_column] = differences.astype(float)

    prepared.loc[:, list(RATE_FEATURE_COLUMNS)] = rate_values
    feature_frame = prepared.loc[:, list(FEATURE_COLUMNS)].astype(float)
    if not np.isfinite(feature_frame.to_numpy()).all():
        raise TelemetryValidationError("generated features must be finite")
    return prepared, feature_frame


def last_process_state(prepared_telemetry: pd.DataFrame) -> dict[str, float]:
    """Return the last cleaned sensor values for a caller's next observation."""

    _validate_dataframe(prepared_telemetry)
    return {
        column: float(prepared_telemetry[column].iloc[-1])
        for column in BASE_FEATURE_COLUMNS
    }
