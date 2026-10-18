"""Read-only loader for the P4/P5 JSON handoffs."""

from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _read_json(path: Path, stage: str) -> tuple[Any, str | None]:
    try:
        if not path.is_file():
            return None, f"{stage} output is missing: {path}"
        with path.open(encoding="utf-8") as stream:
            return json.load(stream), None
    except (OSError, UnicodeDecodeError, ValueError, RecursionError, OverflowError) as error:
        return None, f"{stage} output could not be read: {error}"


def load_chain_incidents(
    p4_path: str | Path, p5_path: str | Path
) -> tuple[list[dict[str, Any]], list[str], str | None]:
    p4_file, p5_file = Path(p4_path), Path(p5_path)
    errors: list[str] = []
    p4_data, error = _read_json(p4_file, "P4")
    if error:
        errors.append(error)
    p5_data, error = _read_json(p5_file, "P5")
    if error:
        errors.append(error)

    p5_by_id: dict[str, dict[str, Any]] = {}
    if p5_data is not None:
        if not isinstance(p5_data, list):
            errors.append("P5 output must be a JSON list of incident reports")
        else:
            for index, report in enumerate(p5_data):
                if not isinstance(report, dict) or not isinstance(report.get("incident_id"), str):
                    errors.append(f"P5 report at index {index} has no valid incident_id")
                    continue
                valid_report = (
                    isinstance(report.get("rule_alerts"), list)
                    and isinstance(report.get("sensor_validation_issues"), list)
                    and isinstance(report.get("rule_confirmation"), bool)
                )
                if valid_report:
                    valid_report = (
                        all(isinstance(item, dict) for item in report["rule_alerts"])
                        and all(
                            isinstance(item, dict)
                            for item in report["sensor_validation_issues"]
                        )
                        and report["rule_confirmation"] == bool(report["rule_alerts"])
                    )
                if not valid_report:
                    errors.append(
                        f"P5 report {report['incident_id']} is missing valid rule/validation fields"
                    )
                    continue
                p5_by_id[report["incident_id"]] = report

    incidents: list[dict[str, Any]] = []
    if p4_data is not None:
        if not isinstance(p4_data, list):
            errors.append("P4 output must be a JSON list of incidents")
        else:
            for index, incident in enumerate(p4_data):
                if not isinstance(incident, dict):
                    errors.append(f"P4 incident at index {index} is not a JSON object")
                    continue
                incident_id = incident.get("incident_id")
                required = ("risk_score", "events")
                missing = [field for field in required if field not in incident]
                if not isinstance(incident_id, str) or not incident_id.strip():
                    missing.insert(0, "incident_id")
                if not isinstance(incident.get("asset_id"), str) or not incident["asset_id"].strip():
                    missing.append("asset_id")
                if not isinstance(incident.get("risk_level"), str) or incident.get(
                    "risk_level"
                ) not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
                    missing.append("risk_level")
                if not isinstance(incident.get("start_time"), str) or not incident["start_time"].strip():
                    missing.append("start_time")
                if not isinstance(incident.get("end_time"), str) or not incident["end_time"].strip():
                    missing.append("end_time")
                score = incident.get("risk_score")
                valid_score = score is None
                if isinstance(score, (int, float)) and not isinstance(score, bool):
                    try:
                        valid_score = math.isfinite(float(score)) and 0.0 <= score <= 1.0
                    except OverflowError:
                        valid_score = False
                if not valid_score:
                    missing.append("risk_score")
                if missing:
                    errors.append(
                        f"P4 incident at index {index} is missing or has invalid fields: "
                        + ", ".join(missing)
                    )
                    continue
                if not isinstance(incident["events"], list):
                    errors.append(f"P4 incident {incident_id} events must be a list")
                    continue
                if any(not isinstance(event, dict) for event in incident["events"]):
                    errors.append(f"P4 incident {incident_id} contains a non-object event")
                    continue
                events = incident["events"]
                incident_type_counts = {
                    event_type: sum(event.get("event_type") == event_type for event in events)
                    for event_type in ("network", "physical")
                }
                incidents.append({
                    **incident,
                    "events": events,
                    "event_counts": incident_type_counts,
                    "p5": p5_by_id.get(incident_id, {}),
                })

    mtimes = []
    for path in (p4_file, p5_file):
        try:
            mtimes.append(path.stat().st_mtime)
        except OSError:
            pass
    updated = (
        datetime.fromtimestamp(max(mtimes), tz=timezone.utc).isoformat(timespec="seconds")
        if mtimes
        else None
    )
    return incidents, errors, updated
