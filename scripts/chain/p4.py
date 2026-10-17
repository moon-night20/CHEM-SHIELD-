"""Stage 3: correlate P2/P3 handoffs and calculate canonical Part 4 risk."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from chem_shield_p4.correlation import CorrelationEngine
from chem_shield_p4.risk_engine import RiskEngine

from .contracts import (
    ContractError,
    load_json,
    validate_event_list,
    validate_p2_handoff,
    validate_p4_incidents,
    write_json,
)


def run(
    p2_path: str | Path,
    p3_path: str | Path,
    output_path: str | Path,
    *,
    correlation_window_seconds: float = 10.0,
) -> list[dict[str, Any]]:
    p2_payload = validate_p2_handoff(load_json(p2_path, "P2"))
    p3_events = validate_event_list(load_json(p3_path, "P3"), "P3", "physical")
    threshold = float(p2_payload["handoff"]["threshold"])
    network_events = [
        event for event in p2_payload["events"]
        if float(event["anomaly_score"]) >= threshold
    ]
    raw_events = [*network_events, *p3_events]
    correlator = CorrelationEngine(time_window_seconds=correlation_window_seconds)
    correlated, validation_errors = correlator.correlate(raw_events)
    if validation_errors:
        details = "; ".join(error.message for error in validation_errors)
        raise ContractError(f"P4 rejected invalid correlated events: {details}")

    risk_engine = RiskEngine()
    incidents = []
    for incident in correlated:
        incident_data = incident.to_dict()
        assessment = risk_engine.calculate_risk(incident_data).to_dict()
        incidents.append({
            "incident_id": incident.incident_id,
            "asset_id": incident.asset_id,
            "start_time": incident.start_time.isoformat(),
            "end_time": incident.end_time.isoformat(),
            "risk_level": assessment["risk_level"],
            "risk_score": assessment["final_risk"],
            "events": [event.to_dict() for event in incident.events],
            "network_present": incident.network_present,
            "physical_present": incident.physical_present,
            "risk_assessment": assessment,
        })

    write_json(output_path, incidents, validate_p4_incidents)
    return incidents
