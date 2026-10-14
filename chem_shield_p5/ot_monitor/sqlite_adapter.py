"""Part 5 read-only adapter for Part 1 telemetry and event storage."""

from chem_shield_p1.ot_monitor.sqlite_adapter import (
    persist_ot_events,
    read_telemetry_read_only,
)

__all__ = ["persist_ot_events", "read_telemetry_read_only"]
