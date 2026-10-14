"""Normalize OT alerts for the CHEM-SHIELD and Part 4 event contracts."""

from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .rule_engine import RuleAlert
from .sensor_validation import ValidatedReading


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else repr(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return repr(value)


def normalize_ot_event(
    reading: Optional[ValidatedReading],
    event_type: str,
    severity: str,
    evidence: Dict[str, Any],
    rule_id: Optional[str] = None,
    model: Optional[Dict[str, Any]] = None,
    timestamp: Optional[datetime] = None,
    asset_id: Optional[str] = None,
    measurements: Optional[Dict[str, Any]] = None,
    measurement_origin: Optional[str] = None,
    units: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    event_time = reading.timestamp if reading else timestamp
    if event_time is None:
        raise ValueError("timestamp is required when no validated reading is provided")
    asset = reading.asset_id if reading else asset_id
    if not asset:
        raise ValueError("asset_id is required when no validated reading is provided")
    observed = measurements if measurements is not None else (
        dict(reading.measurements) if reading else {}
    )
    units = dict(reading.units) if reading else dict(units or {})
    origin = measurement_origin or (
        reading.raw.get("measurement_origin", "unspecified") if reading else "unspecified"
    )
    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=timezone.utc)
    event_time = event_time.astimezone(timezone.utc)
    timestamp_text = event_time.isoformat(timespec="seconds")
    identity_data = {
        "timestamp": timestamp_text,
        "asset_id": asset,
        "measurement_origin": origin,
        "event_type": event_type,
        "rule_id": rule_id,
        "evidence": _json_safe(evidence),
    }
    event_id = "OT-" + hashlib.sha256(
        json.dumps(identity_data, sort_keys=True, allow_nan=False).encode("utf-8")
    ).hexdigest()[:12].upper()
    return {
        "event_id": event_id,
        "timestamp": timestamp_text,
        "source": "ot_monitor",
        "asset_id": asset,
        "measurement_origin": origin,
        "event_type": event_type,
        "severity": severity,
        "evidence": _json_safe(evidence),
        "measurements": _json_safe(observed),
        "units": units,
        "rule_id": rule_id,
        "model": model,
    }


def rule_alert_to_event(reading: ValidatedReading, alert: RuleAlert) -> Dict[str, Any]:
    return normalize_ot_event(
        reading=reading,
        event_type=alert.event_type,
        severity=alert.severity,
        evidence={"message": alert.message, **alert.evidence},
        rule_id=alert.rule_id,
    )


def to_part4_correlation_event(
    event: Dict[str, Any],
    anomaly_score: float,
    asset_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Convert a scored physical event to Part 4's event contract."""
    score = float(anomaly_score)
    if not 0.0 <= score <= 1.0:
        raise ValueError("anomaly_score must be between 0.0 and 1.0")
    result = {
        "timestamp": event["timestamp"],
        "asset_id": asset_id or event["asset_id"],
        "event_type": "physical",
        "anomaly_score": score,
    }
    for field in ("event_id", "source", "severity", "evidence"):
        if field in event and event[field] is not None:
            result[field] = event[field]
    return result


def to_part1_event_record(event: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a rich OT alert to the event dictionary accepted by Part 1 storage."""
    evidence = event.get("evidence") or {}
    return {
        "timestamp": event["timestamp"],
        "source": "ot_monitor",
        "machine_id": event["asset_id"],
        "event_type": str(event["event_type"]).upper(),
        "parameter": event.get("rule_id") or evidence.get("sensor") or event["event_type"],
        "old_value": evidence.get("previous_value", evidence.get("configured_threshold")),
        "new_value": evidence.get("value"),
        "severity": event["severity"],
    }
