"""MITRE ATT&CK for ICS mappings used by the simulated scenario captions."""

from __future__ import annotations

from typing import Any

TECHNIQUES: dict[str, dict[str, Any]] = {
    "T0831": {
        "id": "T0831",
        "name": "Manipulation of Control",
        "tactic": "Impair Process Control",
        "url": "https://attack.mitre.org/techniques/T0831/",
        "verify": False,
    },
    "T0836": {
        "id": "T0836",
        "name": "Modify Parameter",
        "tactic": "Impair Process Control",
        "url": "https://attack.mitre.org/techniques/T0836/",
        "verify": False,
    },
}

SCENARIO_TECHNIQUES = {
    "overheat": ("T0836", "T0831"),
    "pressure-spike": ("T0836", "T0831"),
    "overspeed": ("T0836", "T0831"),
    "stealthy-in-range-drift": ("T0836",),
    "cascade": ("T0836", "T0831"),
}


def techniques_for(scenario_id: str) -> list[dict[str, Any]]:
    """Return verified technique metadata for a known scenario."""
    return [dict(TECHNIQUES[item]) for item in SCENARIO_TECHNIQUES.get(scenario_id, ())]


def validate_map() -> None:
    """Ensure every scenario mapping resolves to complete technique metadata."""
    required = {"id", "name", "tactic", "url", "verify"}
    for scenario_id, technique_ids in SCENARIO_TECHNIQUES.items():
        if not scenario_id or not technique_ids:
            raise ValueError("Every scenario needs at least one technique mapping.")
        for technique_id in technique_ids:
            item = TECHNIQUES.get(technique_id)
            if item is None or not required.issubset(item):
                raise ValueError(f"Incomplete MITRE technique mapping: {technique_id}")


validate_map()
