"""Validation and feature engineering for simulated process telemetry."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import numpy as np
import pandas as pd

BASE_FEATURE_COLUMNS = ("rpm", "temperature", "pressure", "power")
RATE_FEATURE_COLUMNS = (
    "rpm_rate",
    "temperature_rate",
    "pressure_rate",
    "power_rate",
)
PHYSICS_FEATURE_COLUMNS = (
    "power_rpm_residual",
    "temperature_power_residual",
    "pressure_rpm_residual",
)
FEATURE_COLUMNS = (
    *BASE_FEATURE_COLUMNS,
    *RATE_FEATURE_COLUMNS,
    *PHYSICS_FEATURE_COLUMNS,
)
RATE_SOURCE_COLUMNS = {
    "rpm_rate": "rpm",
    "temperature_rate": "temperature",
    "pressure_rate": "pressure",
    "power_rate": "power",
}
TELEMETRY_TO_FEATURE_MAP = {
    "rpm": "rpm",
    "speed": "rpm",
    "motor_speed": "rpm",
    "temperature": "temperature",
    "pressure": "pressure",
    "power": "power",
}


def map_telemetry_reading(measurements: Mapping[str, Any]) -> dict[str, float]:
    """Map telemetry aliases to the four process channels used by P3."""
    result: dict[str, float] = {}
    for source_key, target_key in TELEMETRY_TO_FEATURE_MAP.items():
        if source_key in measurements and target_key not in result:
            value = measurements[source_key]
            if value is not None:
                result[target_key] = float(value)
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

    cleaned = numeric.interpolate(limit_direction="both").ffill().bfill()
    if cleaned.isna().any().any():
        raise TelemetryValidationError("process values could not be completed safely")
    return cleaned.astype(float)


def _coerce_previous_state(
    previous_state: Mapping[str, Any] | None,
) -> dict[str, float] | None:
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
    """Return cleaned telemetry and model features for four sensor channels.

    Rates are differences per observation. Physics residuals compare the
    measured channels against the simulator's approximate normal relationships.
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
        differences = cleaned[source_column].diff()
        if stream_column is None:
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

    normalized_rpm = np.clip(cleaned["rpm"] / 1500.0, 0.0, 1.0)
    normalized_power = np.clip((cleaned["power"] - 0.2) / 11.6, 0.0, 1.0)
    prepared["power_rpm_residual"] = cleaned["power"] - (0.2 + 11.6 * normalized_rpm)
    prepared["temperature_power_residual"] = cleaned["temperature"] - (
        20.0 + 48.0 * normalized_power
    )
    prepared["pressure_rpm_residual"] = cleaned["pressure"] - (
        1.0 + 2.95 * normalized_rpm
    )

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
