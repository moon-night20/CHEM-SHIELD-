"""Decision policy for the human-confirmed Part 6 simulated stop."""

from collections.abc import Mapping
from typing import Any


def response_decision(incident: Mapping[str, Any]) -> dict[str, Any]:
    """Describe whether an active critical incident may offer a simulated stop."""
    incident_id = incident.get("incident_id")
    eligible = (
        isinstance(incident_id, str)
        and bool(incident_id.strip())
        and incident.get("status") == "ACTIVE"
        and incident.get("risk_level") == "CRITICAL"
    )
    return {
        "incident_id": incident_id,
        "action": "simulated_stop" if eligible else "monitor_only",
        "requires_operator_confirmation": eligible,
        "simulation_only": True,
        "executed": False,
    }
