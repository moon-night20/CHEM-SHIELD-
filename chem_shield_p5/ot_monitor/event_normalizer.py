"""Part 5 event adapters for Part 1 storage and Part 4 correlation contracts."""

from __future__ import annotations

from typing import Any, Dict

from chem_shield_p1.ot_monitor.event_normalizer import (
    normalize_ot_event,
    rule_alert_to_event,
    to_part4_correlation_event,
)


def to_part1_event_record(event: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a rich OT alert to the event dictionary accepted by Part 1 storage.

    This matches `chem_shield_p1.events.abnormal_events.event_record`'s output
    keys without invoking its simulation-only PLC-writing function.
    """
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


__all__ = [
    "normalize_ot_event",
    "rule_alert_to_event",
    "to_part4_correlation_event",
    "to_part1_event_record",
]
