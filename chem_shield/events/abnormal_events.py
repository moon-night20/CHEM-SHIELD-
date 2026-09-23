"""Ground-truth event controls for CHEM-SHIELD experiments.

These controls only write fictional values to the local virtual PLC.
"""

from datetime import datetime, timezone

from chem_shield.plc.register_map import EVENT_CODE


EVENT_DEFINITIONS = {
    "rpm_deviation": (1, "rpm", "medium"),
    "temperature_increase": (2, "temperature", "medium"),
    "pressure_spike": (3, "pressure", "high"),
    "sensor_inconsistency": (4, "rpm", "medium"),
}


def event_record(event_type: str, old_value, new_value) -> dict:
    if event_type not in EVENT_DEFINITIONS:
        raise ValueError(f"Unknown simulation event: {event_type}")
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "TEST_MODE",
        "machine_id": "M-01",
        "event_type": event_type.upper(),
        "parameter": EVENT_DEFINITIONS[event_type][1],
        "old_value": old_value,
        "new_value": new_value,
        "severity": EVENT_DEFINITIONS[event_type][2],
    }


def write_event(client, event_type: str, value: int) -> dict:
    code = EVENT_DEFINITIONS[event_type][0]
    result = client.write_registers(EVENT_CODE, [code, value], slave=1)
    if result.isError():
        raise RuntimeError(result)
    return event_record(event_type, "normal", value)