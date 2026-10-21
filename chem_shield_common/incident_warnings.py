"""Format actionable warning details shared by the HMI and admin views."""

from __future__ import annotations

from typing import Any, Dict, List

WARNING_SEVERITIES = frozenset({"MEDIUM", "HIGH", "CRITICAL"})


def _number(value: Any) -> str:
    if isinstance(value, bool):
        return str(value)
    if isinstance(value, (int, float)):
        return f"{value:g}"
    return str(value)


def _comparison(evidence: Dict[str, Any], event: Dict[str, Any]) -> str:
    unit = evidence.get("unit")
    comparisons = (
        ("value", "configured_threshold", unit),
        ("anomaly_score", "configured_anomaly_threshold", None),
        ("rate_per_minute", "configured_max_abs_rate_per_minute", "per minute"),
        ("rpm_change", "minimum_rpm_increase", "RPM"),
        ("temperature_change", "minimum_temperature_drop", unit or "degC"),
        ("pressure_change", "minimum_pressure_change", unit or "bar"),
        ("frozen_seconds", "configured_duration_seconds", "seconds"),
        ("power_change", "maximum_power_change", unit or "kW"),
        ("observed_write_count", "configured_burst_threshold", "writes"),
    )
    for observed_key, limit_key, comparison_unit in comparisons:
        observed = evidence.get(observed_key)
        limit = evidence.get(limit_key)
        if (
            isinstance(observed, (int, float))
            and not isinstance(observed, bool)
            and isinstance(limit, (int, float))
            and not isinstance(limit, bool)
        ):
            if observed_key == "temperature_change":
                observed = abs(observed)
            suffix = f" {comparison_unit}" if comparison_unit else ""
            return f"{_number(observed)}{suffix} vs limit {_number(limit)}{suffix}"

    allowed_sources = evidence.get("allowed_source_addresses")
    if (
        evidence.get("client_address")
        and isinstance(allowed_sources, (list, tuple))
        and all(isinstance(address, str) for address in allowed_sources)
    ):
        return (
            f"source {evidence['client_address']} vs allowed addresses "
            f"{', '.join(allowed_sources)}"
        )
    if (
        evidence.get("function_code") is not None
        and evidence.get("expected_write_function_codes")
    ):
        expected = ", ".join(
            str(code) for code in evidence["expected_write_function_codes"]
        )
        return f"function code {evidence['function_code']} vs expected {expected}"
    register_range = evidence.get("expected_register_range")
    if (
        evidence.get("address_start") is not None
        and isinstance(register_range, (list, tuple))
        and len(register_range) == 2
    ):
        low, high = register_range
        return (
            f"register {evidence['address_start']} vs expected range "
            f"{low}-{high}"
        )
    evidence_score = evidence.get("anomaly_score")
    if isinstance(evidence_score, (int, float)) and not isinstance(evidence_score, bool):
        return (
            f"score {_number(evidence_score)} on the 0.0-1.0 scale "
            "(no numeric detector limit supplied)"
        )
    event_score = event.get("anomaly_score")
    if isinstance(event_score, (int, float)) and not isinstance(event_score, bool):
        return (
            f"score {_number(event_score)} on the 0.0-1.0 scale "
            "(no numeric detector limit supplied)"
        )
    return str(evidence.get("message") or "No numeric value or limit was supplied.")


def incident_warning_details(incident: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build concise, escaped-by-the-view warning summaries for an incident."""
    events = incident.get("events")
    if not isinstance(events, list):
        return []
    severe_events = [
        event for event in events
        if isinstance(event, dict)
        and str(event.get("severity", "")).upper() in WARNING_SEVERITIES
    ]
    if not severe_events and str(incident.get("risk_level", "")).upper() in WARNING_SEVERITIES:
        severe_events = [event for event in events if isinstance(event, dict)]

    result = []
    for event in severe_events:
        raw_evidence = event.get("evidence")
        evidence = raw_evidence if isinstance(raw_evidence, dict) else {}
        sensor = evidence.get("sensor")
        rule = evidence.get("rule_id")
        detector = evidence.get("detection_method")
        trigger_parts = [str(item) for item in (sensor, rule, detector) if item]
        trigger = " / ".join(trigger_parts)
        if not trigger:
            trigger = str(event.get("source") or event.get("event_type") or "detector")
        timestamp = event.get("timestamp") or incident.get("start_time") or "Time unavailable"
        result.append({
            "asset_id": str(event.get("asset_id") or incident.get("asset_id") or "Unknown asset"),
            "severity": str(event.get("severity") or incident.get("risk_level") or "WARNING"),
            "trigger": trigger.replace("_", " "),
            "comparison": _comparison(evidence, event),
            "timestamp": str(timestamp),
            "message": str(evidence.get("message") or event.get("event_type") or ""),
        })
    return result
