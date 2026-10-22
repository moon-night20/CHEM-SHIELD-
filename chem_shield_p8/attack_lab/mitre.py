"""Verified ATT&CK for ICS labels used by Part 8 simulated scenarios."""

from __future__ import annotations

from typing import Any

TECHNIQUES: dict[str, dict[str, str]] = {
    "T0831": {
        "id": "T0831",
        "name": "Manipulation of Control",
        "url": "https://attack.mitre.org/techniques/T0831/",
    },
    "T0836": {
        "id": "T0836",
        "name": "Modify Parameter",
        "url": "https://attack.mitre.org/techniques/T0836/",
    },
    "T1691.002": {
        "id": "T1691.002",
        "name": "Block Reporting Message",
        "url": "https://attack.mitre.org/techniques/T1691/002/",
    },
    "T1692.001": {
        "id": "T1692.001",
        "name": "Unauthorized Command Message",
        "url": "https://attack.mitre.org/techniques/T1692/001/",
    },
}

ALERT_TECHNIQUES: dict[str, tuple[str, ...]] = {
    "SETPOINT_OUT_OF_RANGE": ("T0836",),
    "ENERGY_BALANCE": ("T0831",),
    "MASS_BALANCE": ("T0831",),
    "PRESSURE_BALANCE": ("T0831",),
    "RATE_OF_CHANGE": ("T0831",),
    "COOLING_CORRELATION": ("T0831",),
    "PUMP_FLOW_CORRELATION": ("T0831",),
    "DUPLICATE_PACKET_REPLAY": ("T0831",),
    "LOSS_OF_VIEW": ("T1691.002",),
}


def techniques_for_alert(rule_id: str) -> list[dict[str, str]]:
    """Return applicable technique records; unmatched rules use command-message mapping."""
    identifiers = ALERT_TECHNIQUES.get(rule_id, ("T1692.001",))
    return [dict(TECHNIQUES[identifier]) for identifier in identifiers]


def techniques_for_scenario(identifiers: list[str]) -> list[dict[str, str]]:
    """Resolve and validate technique IDs attached to a scenario definition."""
    unknown = [identifier for identifier in identifiers if identifier not in TECHNIQUES]
    if unknown:
        raise ValueError(f"Unknown ATT&CK for ICS technique IDs: {unknown}")
    return [dict(TECHNIQUES[identifier]) for identifier in identifiers]
