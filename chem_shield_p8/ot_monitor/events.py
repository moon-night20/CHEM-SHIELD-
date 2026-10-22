"""Normalize synthetic Modbus/TCP and simplified OPC UA event records."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

SUPPORTED_PROTOCOLS = {"modbus-tcp", "opcua"}
READ_FUNCTION_CODES = {1, 2, 3, 4, 23}
WRITE_FUNCTION_CODES = {5, 6, 15, 16}


@dataclass(frozen=True)
class OTEvent:
    """Protocol-neutral representation of one supplied synthetic record."""

    event_id: str
    timestamp: datetime
    source_ip: str
    destination_ip: str
    device_id: str
    protocol: str
    operation: str
    function_code: int | None
    tag: str | None
    value: float | bool | None
    fingerprint: str
    details: dict[str, Any]


def parse_event(record: dict[str, Any]) -> OTEvent:
    """Validate and normalize one Modbus/TCP or simplified OPC UA record."""
    if not isinstance(record, dict):
        raise ValueError("OT event must be a mapping.")
    protocol = str(record.get("protocol", "")).strip().casefold()
    if protocol not in SUPPORTED_PROTOCOLS:
        raise ValueError(f"Unsupported simulated protocol: {protocol or '(missing)'}")
    source_ip = _ip_address(record.get("source_ip"), "source_ip")
    destination_ip = _ip_address(record.get("destination_ip"), "destination_ip")
    timestamp = _timestamp(record.get("timestamp"))
    event_id = str(record.get("event_id", "")).strip()
    if not event_id:
        raise ValueError("OT event requires a non-empty event_id.")
    device_id = str(record.get("device_id") or destination_ip).strip()

    function_code: int | None = None
    tag: str | None = None
    value: float | bool | None = None
    details: dict[str, Any] = {}
    if protocol == "modbus-tcp":
        raw_function = record.get("function_code")
        if isinstance(raw_function, bool) or not isinstance(raw_function, int):
            raise ValueError("Modbus event function_code must be an integer.")
        function_code = raw_function
        if function_code in READ_FUNCTION_CODES:
            operation = "read"
        elif function_code in WRITE_FUNCTION_CODES:
            operation = "write"
        else:
            operation = "unknown"
        raw_tag = record.get("tag", record.get("register"))
        tag = None if raw_tag is None else str(raw_tag)
        value = _event_value(record.get("value"))
        details = {
            key: record[key]
            for key in ("unit_id", "register", "quantity", "transaction_id")
            if key in record
        }
    else:
        message = record.get("message")
        if not isinstance(message, dict):
            raise ValueError("OPC UA event requires a message mapping.")
        raw_operation = str(message.get("type", record.get("operation", ""))).casefold()
        if raw_operation not in {"read", "write"}:
            raise ValueError("OPC UA message type must be 'Read' or 'Write'.")
        operation = raw_operation
        raw_tag = message.get("node_id", record.get("tag"))
        tag = None if raw_tag is None else str(raw_tag)
        value = _event_value(message.get("value"))
        details = {
            key: message[key]
            for key in ("namespace", "status")
            if key in message
        }

    fingerprint_source = {
        "protocol": protocol,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "device_id": device_id,
        "operation": operation,
        "function_code": function_code,
        "tag": tag,
        "value": value,
        "details": details,
    }
    fingerprint = hashlib.sha256(
        json.dumps(
            fingerprint_source,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    return OTEvent(
        event_id=event_id,
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        device_id=device_id,
        protocol=protocol,
        operation=operation,
        function_code=function_code,
        tag=tag,
        value=value,
        fingerprint=fingerprint,
        details=details,
    )


def parse_event_stream(records: Iterable[dict[str, Any]]) -> list[OTEvent]:
    """Normalize a supplied finite event stream in input order."""
    return [parse_event(record) for record in records]


def _ip_address(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"OT event {name} must be an IP address.")
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as error:
        raise ValueError(f"OT event {name} must be an IP address.") from error


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("OT event timestamp must be an ISO 8601 string.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("OT event timestamp must be a valid ISO 8601 value.") from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _event_value(value: Any) -> float | bool | None:
    if value is None or isinstance(value, bool):
        return value
    if not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise ValueError("OT event value must be finite numeric data or boolean.")
    return float(value)
