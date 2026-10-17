"""JSON handoff contracts and shared file/telemetry helpers for the chain."""

from __future__ import annotations

import json
import math
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import pandas as pd


class ContractError(ValueError):
    """Raised when a stage input or output does not match its handoff contract."""


EVENT_FIELDS = (
    "event_id",
    "timestamp",
    "source",
    "asset_id",
    "event_type",
    "anomaly_score",
    "severity",
    "evidence",
)
TELEMETRY_COLUMNS = (
    "timestamp",
    "asset_id",
    "temperature",
    "pressure",
    "speed",
    "vibration",
)


def parse_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"field '{field}' must be a non-empty ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError(f"field '{field}' must be a valid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _require_object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"field '{field}' must be a JSON object")
    return value


def _require_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"field '{field}' must be a non-empty string")
    return value


def _require_list(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise ContractError(f"field '{field}' must be a JSON list")
    return value


def validate_event(value: Any, field: str, expected_type: str | None = None) -> dict[str, Any]:
    event = _require_object(value, field)
    for name in EVENT_FIELDS:
        if name not in event:
            raise ContractError(f"field '{field}.{name}' is missing")
    _require_string(event["event_id"], f"{field}.event_id")
    parse_timestamp(event["timestamp"], f"{field}.timestamp")
    _require_string(event["source"], f"{field}.source")
    _require_string(event["asset_id"], f"{field}.asset_id")
    event_type = _require_string(event["event_type"], f"{field}.event_type")
    if event_type not in {"network", "physical"}:
        raise ContractError(f"field '{field}.event_type' must be 'network' or 'physical'")
    if expected_type is not None and event_type != expected_type:
        raise ContractError(f"field '{field}.event_type' must be '{expected_type}'")
    score = event["anomaly_score"]
    if (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not math.isfinite(float(score))
        or not 0.0 <= float(score) <= 1.0
    ):
        raise ContractError(f"field '{field}.anomaly_score' must be finite and within [0, 1]")
    _require_string(event["severity"], f"{field}.severity")
    _require_object(event["evidence"], f"{field}.evidence")
    return event


def validate_p2_handoff(value: Any) -> dict[str, Any]:
    payload = _require_object(value, "P2 handoff")
    events = _require_list(payload.get("events"), "P2.events")
    for index, event in enumerate(events):
        validate_event(event, f"P2.events[{index}]", "network")

    handoff = _require_object(payload.get("handoff"), "P2.handoff")
    threshold = handoff.get("threshold")
    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, (int, float))
        or not math.isfinite(float(threshold))
        or not 0.0 <= float(threshold) <= 1.0
    ):
        raise ContractError("field 'P2.handoff.threshold' must be finite and within [0, 1]")
    asset_ids = _require_list(handoff.get("asset_ids"), "P2.handoff.asset_ids")
    for index, asset_id in enumerate(asset_ids):
        _require_string(asset_id, f"P2.handoff.asset_ids[{index}]")
    if len(set(asset_ids)) != len(asset_ids):
        raise ContractError("field 'P2.handoff.asset_ids' must not contain duplicates")

    anomalous = [
        event for event in events
        if float(event["anomaly_score"]) >= float(threshold)
    ]
    expected_assets = sorted({event["asset_id"] for event in anomalous})
    if sorted(asset_ids) != expected_assets:
        raise ContractError(
            "field 'P2.handoff.asset_ids' does not match threshold-qualified event assets"
        )
    count = handoff.get("anomalous_event_count")
    if isinstance(count, bool) or not isinstance(count, int) or count != len(anomalous):
        raise ContractError(
            "field 'P2.handoff.anomalous_event_count' does not match threshold-qualified events"
        )

    window = handoff.get("window")
    if not anomalous:
        if window is not None:
            raise ContractError("field 'P2.handoff.window' must be null when there are no anomalies")
    else:
        window_obj = _require_object(window, "P2.handoff.window")
        if "start" not in window_obj:
            raise ContractError("field 'P2.handoff.window.start' is missing")
        if "end" not in window_obj:
            raise ContractError("field 'P2.handoff.window.end' is missing")
        start = parse_timestamp(window_obj["start"], "P2.handoff.window.start")
        end = parse_timestamp(window_obj["end"], "P2.handoff.window.end")
        event_times = [parse_timestamp(event["timestamp"], "P2.events.timestamp") for event in anomalous]
        if start > end or start != min(event_times) or end != max(event_times):
            raise ContractError(
                "field 'P2.handoff.window' must span the threshold-qualified event timestamps"
            )
    return payload


def validate_event_list(value: Any, stage: str, expected_type: str) -> list[dict[str, Any]]:
    events = _require_list(value, f"{stage} events")
    for index, event in enumerate(events):
        validate_event(event, f"{stage}.events[{index}]", expected_type)
    return events


def validate_p4_incidents(value: Any) -> list[dict[str, Any]]:
    incidents = _require_list(value, "P4 incidents")
    for index, incident_value in enumerate(incidents):
        field = f"P4.incidents[{index}]"
        incident = _require_object(incident_value, field)
        for name in ("incident_id", "asset_id", "start_time", "end_time", "risk_level", "risk_score", "events"):
            if name not in incident:
                raise ContractError(f"field '{field}.{name}' is missing")
        _require_string(incident["incident_id"], f"{field}.incident_id")
        asset_id = _require_string(incident["asset_id"], f"{field}.asset_id")
        start = parse_timestamp(incident["start_time"], f"{field}.start_time")
        end = parse_timestamp(incident["end_time"], f"{field}.end_time")
        if start > end:
            raise ContractError(f"field '{field}.start_time' must not be after end_time")
        risk_level = _require_string(incident["risk_level"], f"{field}.risk_level")
        if risk_level not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ContractError(f"field '{field}.risk_level' is not a recognized risk level")
        risk_score = incident["risk_score"]
        if (
            isinstance(risk_score, bool)
            or not isinstance(risk_score, (int, float))
            or not math.isfinite(float(risk_score))
            or not 0.0 <= float(risk_score) <= 1.0
        ):
            raise ContractError(f"field '{field}.risk_score' must be finite and within [0, 1]")
        events = _require_list(incident["events"], f"{field}.events")
        if not events:
            raise ContractError(f"field '{field}.events' must not be empty")
        for event_index, event_value in enumerate(events):
            event = validate_event(event_value, f"{field}.events[{event_index}]")
            if event["asset_id"] != asset_id:
                raise ContractError(
                    f"field '{field}.events[{event_index}].asset_id' does not match incident.asset_id"
                )
    return incidents


def validate_p5_report(value: Any) -> list[dict[str, Any]]:
    reports = _require_list(value, "P5 report")
    for index, report_value in enumerate(reports):
        field = f"P5.report[{index}]"
        report = _require_object(report_value, field)
        for name in (
            "incident_id",
            "risk_level",
            "risk_score",
            "rule_alerts",
            "sensor_validation_issues",
            "rule_confirmation",
        ):
            if name not in report:
                raise ContractError(f"field '{field}.{name}' is missing")
        _require_string(report["incident_id"], f"{field}.incident_id")
        _require_string(report["risk_level"], f"{field}.risk_level")
        score = report["risk_score"]
        if score is not None and (
            isinstance(score, bool)
            or not isinstance(score, (int, float))
            or not math.isfinite(float(score))
            or not 0.0 <= float(score) <= 1.0
        ):
            raise ContractError(f"field '{field}.risk_score' must be null or within [0, 1]")
        alerts = _require_list(report["rule_alerts"], f"{field}.rule_alerts")
        issues = _require_list(
            report["sensor_validation_issues"],
            f"{field}.sensor_validation_issues",
        )
        if not isinstance(report["rule_confirmation"], bool):
            raise ContractError(f"field '{field}.rule_confirmation' must be a boolean")
        if report["rule_confirmation"] != bool(alerts):
            raise ContractError(
                f"field '{field}.rule_confirmation' must match whether rule_alerts is non-empty"
            )
        for alert_index, alert in enumerate(alerts):
            _require_object(alert, f"{field}.rule_alerts[{alert_index}]")
        for issue_index, issue in enumerate(issues):
            _require_object(issue, f"{field}.sensor_validation_issues[{issue_index}]")
    return reports


def load_json(path: str | Path, producer: str) -> Any:
    source = Path(path)
    if not source.is_file():
        raise ContractError(f"{producer} handoff file is missing: {source}")
    try:
        with source.open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"{producer} handoff file is unreadable or invalid JSON: {source}: {exc}") from exc


def load_telemetry(path: str | Path) -> pd.DataFrame:
    source = Path(path)
    if not source.is_file():
        raise ContractError(f"telemetry CSV is missing: {source}")
    try:
        frame = pd.read_csv(source)
    except (OSError, pd.errors.ParserError, UnicodeDecodeError) as exc:
        raise ContractError(f"telemetry CSV is unreadable: {source}: {exc}") from exc
    missing = [column for column in TELEMETRY_COLUMNS if column not in frame.columns]
    if missing:
        raise ContractError("telemetry CSV is missing required column(s): " + ", ".join(missing))
    if frame.empty:
        return frame
    normalized_timestamps = []
    for index, timestamp in frame["timestamp"].items():
        parsed = parse_timestamp(timestamp, f"telemetry.timestamp[{index}]")
        normalized_timestamps.append(
            parsed.isoformat().replace("+00:00", "Z")
        )
    frame["timestamp"] = normalized_timestamps
    if frame["asset_id"].isna().any() or not frame["asset_id"].map(
        lambda value: isinstance(value, str) and bool(value.strip())
    ).all():
        raise ContractError("telemetry field 'asset_id' must contain non-empty strings")
    for column in ("temperature", "pressure", "speed", "vibration"):
        try:
            frame[column] = pd.to_numeric(frame[column], errors="raise")
        except (ValueError, TypeError) as exc:
            raise ContractError(f"telemetry column '{column}' must contain numeric values") from exc
        if not frame[column].map(lambda value: math.isfinite(float(value))).all():
            raise ContractError(f"telemetry column '{column}' must contain finite values")
    frame["_parsed_timestamp"] = frame["timestamp"].map(
        lambda value: parse_timestamp(value, "telemetry.timestamp")
    )
    frame = (
        frame.sort_values("_parsed_timestamp", kind="stable")
        .drop(columns="_parsed_timestamp")
        .reset_index(drop=True)
    )
    return frame


def write_json(path: str | Path, payload: Any, validator: Callable[[Any], Any]) -> Path:
    destination = Path(path)
    validator(payload)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            json.dump(payload, stream, indent=2, allow_nan=False)
            stream.write("\n")
        os.replace(temporary_path, destination)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()
    return destination


__all__ = [
    "ContractError",
    "EVENT_FIELDS",
    "TELEMETRY_COLUMNS",
    "load_json",
    "load_telemetry",
    "parse_timestamp",
    "validate_event",
    "validate_event_list",
    "validate_p2_handoff",
    "validate_p4_incidents",
    "validate_p5_report",
    "write_json",
]
