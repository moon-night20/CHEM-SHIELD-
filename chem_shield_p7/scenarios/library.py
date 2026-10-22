"""Scenario definitions for the virtual PLC demo."""

from __future__ import annotations

from typing import Any

SENSOR_LIMITS = {
    "temperature": 70.0,
    "pressure": 4.0,
    "power": 12.0,
    "speed": 1500.0,
}

SCENARIOS: list[dict[str, Any]] = [
    {
        "id": "overheat",
        "name": "Overheat",
        "description": "Raise simulated temperature above the configured limit.",
        "expected_detection": "Part 1 live limit rule and Part 4 critical incident",
        "steps": [{"t_seconds": 0, "sensor": "temperature", "value": 92.0}],
    },
    {
        "id": "pressure-spike",
        "name": "Pressure spike",
        "description": "Raise simulated pressure above the configured limit.",
        "expected_detection": "Part 1 live limit rule and Part 4 critical incident",
        "steps": [{"t_seconds": 0, "sensor": "pressure", "value": 5.2}],
    },
    {
        "id": "overspeed",
        "name": "Overspeed",
        "description": "Raise simulated speed above the configured limit.",
        "expected_detection": "Part 1 live limit rule and Part 4 critical incident",
        "steps": [{"t_seconds": 0, "sensor": "speed", "value": 1800}],
    },
    {
        "id": "stealthy-in-range-drift",
        "name": "Stealthy in-range drift",
        "description": "Apply slowly increasing values that remain below all configured limits.",
        "expected_detection": "Part 3 may detect in-range drift; this is not guaranteed.",
        "steps": [
            {"t_seconds": 0, "sensor": "temperature", "value": 48.0},
            {"t_seconds": 8, "sensor": "temperature", "value": 57.0},
            {"t_seconds": 16, "sensor": "temperature", "value": 66.0},
        ],
    },
    {
        "id": "cascade",
        "name": "Cascade",
        "description": "Raise temperature, pressure, and power in a staged sequence.",
        "expected_detection": "Part 1 limit rules and Part 4 correlation",
        "steps": [
            {"t_seconds": 0, "sensor": "temperature", "value": 82.0},
            {"t_seconds": 25, "sensor": "pressure", "value": 4.8},
            {"t_seconds": 55, "sensor": "power", "value": 14.0},
        ],
    },
]

_BY_ID = {scenario["id"]: scenario for scenario in SCENARIOS}


def get_scenario(scenario_id: str) -> dict[str, Any]:
    """Return a known scenario or raise ValueError for arbitrary identifiers."""
    if not isinstance(scenario_id, str) or scenario_id not in _BY_ID:
        raise ValueError("Unknown scenario identifier.")
    return _BY_ID[scenario_id]


def validate_scenarios() -> None:
    """Fail fast if a scenario is malformed or exceeds simulation bounds."""
    if len(_BY_ID) != len(SCENARIOS):
        raise ValueError("Scenario identifiers must be unique.")
    for scenario in SCENARIOS:
        if not scenario.get("name") or not scenario.get("description"):
            raise ValueError("Every scenario needs a name and description.")
        if not scenario.get("expected_detection") or not scenario.get("steps"):
            raise ValueError("Every scenario needs detection notes and at least one step.")
        previous_time = -1
        for step in scenario["steps"]:
            sensor = step.get("sensor")
            value = step.get("value")
            time_offset = step.get("t_seconds")
            if sensor not in SENSOR_LIMITS:
                raise ValueError(f"Unsupported scenario sensor: {sensor!r}")
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError("Scenario sensor values must be numeric.")
            if not 0 <= value <= {"temperature": 120, "pressure": 10, "power": 20, "speed": 3000}[sensor]:
                raise ValueError("Scenario sensor value exceeds simulator input bounds.")
            if isinstance(time_offset, bool) or not isinstance(time_offset, int) or time_offset < previous_time:
                raise ValueError("Scenario steps must use ordered non-negative integer times.")
            previous_time = time_offset
            if sensor in SENSOR_LIMITS and scenario["id"] == "stealthy-in-range-drift":
                if value >= SENSOR_LIMITS[sensor]:
                    raise ValueError("Stealth drift values must remain below operating limits.")


validate_scenarios()
