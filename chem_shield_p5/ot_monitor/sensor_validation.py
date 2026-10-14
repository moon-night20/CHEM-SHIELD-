"""Input validation for physical-process telemetry."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class ValidationIssue:
    event_type: str
    message: str
    severity: str = "high"
    field: Optional[str] = None


@dataclass
class ValidatedReading:
    timestamp: datetime
    asset_id: str
    measurements: Dict[str, float]
    units: Dict[str, str]
    operating_state: Optional[str] = None
    sensor_status: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationResult:
    reading: Optional[ValidatedReading]
    issues: List[ValidationIssue]


def parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp must be a non-empty ISO-8601 string")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"Invalid ISO-8601 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class SensorValidator:
    """Validate configured sensor fields without coercing bad values to normal data."""

    REQUIRED_SENSORS = ("temperature", "pressure", "speed")
    OPTIONAL_SENSORS = ("vibration",)

    def __init__(
        self,
        sensor_names: Optional[Dict[str, str]] = None,
        units: Optional[Dict[str, str]] = None,
        plausibility_ranges: Optional[Dict[str, Dict[str, Optional[float]]]] = None,
        stale_after_seconds: Optional[float] = None,
        accepted_sensor_status: Optional[List[str]] = None,
        validation_severity: Optional[Dict[str, str]] = None,
    ) -> None:
        self.sensor_names = {
            **{name: name for name in self.REQUIRED_SENSORS},
            **{name: name for name in self.OPTIONAL_SENSORS},
            **(sensor_names or {}),
        }
        if any(not isinstance(value, str) or not value.strip() for value in self.sensor_names.values()):
            raise ValueError("Configured sensor names must be non-empty strings")
        self.units = {
            "temperature": "degC",
            "pressure": "bar",
            "speed": "rpm",
            "vibration": "g",
            **(units or {}),
        }
        if any(not isinstance(value, str) or not value.strip() for value in self.units.values()):
            raise ValueError("Configured sensor units must be non-empty strings")
        self.plausibility_ranges = plausibility_ranges or {}
        if stale_after_seconds is not None:
            if isinstance(stale_after_seconds, bool) or not isinstance(stale_after_seconds, (int, float)):
                raise ValueError("stale_after_seconds must be a positive number")
            if not math.isfinite(float(stale_after_seconds)) or stale_after_seconds <= 0:
                raise ValueError("stale_after_seconds must be a positive finite number")
        for sensor, bounds in self.plausibility_ranges.items():
            if sensor not in (*self.REQUIRED_SENSORS, *self.OPTIONAL_SENSORS) or not isinstance(bounds, dict):
                raise ValueError(f"Invalid plausibility range configuration for {sensor!r}")
            lower, upper = bounds.get("min"), bounds.get("max")
            for name, bound in (("min", lower), ("max", upper)):
                if bound is not None and (
                    isinstance(bound, bool)
                    or not isinstance(bound, (int, float))
                    or not math.isfinite(float(bound))
                ):
                    raise ValueError(f"{sensor} plausibility {name} must be a finite number or null")
            if lower is not None and upper is not None and lower > upper:
                raise ValueError(f"{sensor} plausibility minimum must not exceed maximum")
        self.stale_after_seconds = stale_after_seconds
        self.accepted_sensor_status = {
            value.upper() for value in (accepted_sensor_status or ["OK", "GOOD", "NORMAL"])
        }
        severity = validation_severity or {}
        self.invalid_severity = severity.get("sensor_data_invalid", "high")
        self.stale_severity = severity.get("sensor_stale", "medium")

    def validate(
        self,
        record: Any,
        now: Optional[datetime] = None,
        seen_timestamps: Optional[set] = None,
    ) -> ValidationResult:
        if not isinstance(record, dict):
            return ValidationResult(None, [ValidationIssue("sensor_data_invalid", "Record must be an object", self.invalid_severity)])

        issues: List[ValidationIssue] = []
        try:
            timestamp = parse_timestamp(record.get("timestamp"))
        except ValueError as exc:
            return ValidationResult(None, [ValidationIssue("sensor_data_invalid", str(exc), self.invalid_severity, field="timestamp")])

        asset_id = record.get("asset_id", record.get("machine_id"))
        if not isinstance(asset_id, str) or not asset_id.strip():
            issues.append(ValidationIssue("sensor_data_invalid", "asset_id must be a non-empty string", field="asset_id"))
            asset_id = ""

        if seen_timestamps is not None:
            duplicate_key = (asset_id, timestamp)
            if duplicate_key in seen_timestamps:
                issues.append(ValidationIssue("sensor_data_invalid", "Duplicate timestamp for asset", field="timestamp"))
            else:
                seen_timestamps.add(duplicate_key)

        if self.stale_after_seconds is not None:
            current = now or datetime.now(timezone.utc)
            if current.tzinfo is None:
                current = current.replace(tzinfo=timezone.utc)
            age = (current.astimezone(timezone.utc) - timestamp).total_seconds()
            if age > self.stale_after_seconds:
                issues.append(ValidationIssue("sensor_stale", f"Reading is {age:.1f}s old; limit is {self.stale_after_seconds}s", self.stale_severity, field="timestamp"))
            elif age < 0:
                issues.append(ValidationIssue("sensor_data_invalid", "Reading timestamp is in the future", self.invalid_severity, field="timestamp"))

        sensor_status = record.get("sensor_status")
        if sensor_status is not None and (
            not isinstance(sensor_status, str) or sensor_status.upper() not in self.accepted_sensor_status
        ):
            issues.append(ValidationIssue("sensor_data_invalid", f"Sensor status is not accepted: {sensor_status!r}", field="sensor_status"))

        measurements: Dict[str, float] = {}
        for name in (*self.REQUIRED_SENSORS, *self.OPTIONAL_SENSORS):
            source_name = self.sensor_names[name]
            value = record.get(source_name)
            if value is None:
                if name in self.OPTIONAL_SENSORS:
                    continue
                issues.append(ValidationIssue("sensor_data_invalid", f"Missing required measurement {source_name!r}", field=source_name))
                continue
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                issues.append(ValidationIssue("sensor_data_invalid", f"Measurement {source_name!r} must be numeric", field=source_name))
                continue
            numeric = float(value)
            if not math.isfinite(numeric):
                issues.append(ValidationIssue("sensor_data_invalid", f"Measurement {source_name!r} must be finite", field=source_name))
                continue
            bounds = self.plausibility_ranges.get(name, {})
            lower, upper = bounds.get("min"), bounds.get("max")
            if (lower is not None and numeric < lower) or (upper is not None and numeric > upper):
                issues.append(ValidationIssue("sensor_data_invalid", f"Measurement {source_name!r} is outside configured plausibility range", field=source_name))
                continue
            measurements[name] = numeric

        if issues:
            for issue in issues:
                issue.severity = (
                    self.stale_severity if issue.event_type == "sensor_stale"
                    else self.invalid_severity
                )
            return ValidationResult(None, issues)

        operating_state = record.get("operating_state", record.get("motor_status"))
        if operating_state is not None and not isinstance(operating_state, str):
            return ValidationResult(None, [ValidationIssue("sensor_data_invalid", "operating_state must be a string", self.invalid_severity, field="operating_state")])

        return ValidationResult(
            ValidatedReading(
                timestamp=timestamp,
                asset_id=asset_id.strip(),
                measurements=measurements,
                units=dict(self.units),
                operating_state=operating_state.upper() if operating_state else None,
                sensor_status=sensor_status,
                raw=dict(record),
            ),
            [],
        )
