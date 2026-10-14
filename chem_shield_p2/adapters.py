"""Fixture-backed adapters for common OT and enterprise network log formats.

Only adapters with tested sanitised fixture coverage are considered complete.
Planned live integrations are documented in the README rather than implemented here.
"""

from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence


ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical"}
ALLOWED_EVENT_TYPES = {"connection", "alert", "modbus", "os_security"}
STATE_FEATURES = {"established": 1, "new": 2, "s0": 0, "rej": 3}
OPERATION_FEATURES = {
    "read_holding_registers": 1,
    "read_coils": 2,
    "read_input_registers": 3,
    "write_single_coil": 4,
    "write_single_register": 5,
    "write_multiple_registers": 6,
    "read_write_multiple_registers": 7,
}


class AdapterError(ValueError):
    """Raised when a log record cannot be normalized."""


def _as_utc_iso(value: Any) -> str:
    if value is None:
        raise AdapterError("Missing timestamp value")

    if isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise AdapterError("Timestamp is blank")
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError as exc:
            raise AdapterError(f"Invalid ISO-8601 timestamp: {value!r}") from exc
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    raise AdapterError(f"Unsupported timestamp type: {type(value).__name__}")


def _event_id(source: str, timestamp: str, evidence: dict[str, Any]) -> str:
    payload = {
        "source": source,
        "timestamp": timestamp,
        "evidence": evidence,
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return digest.hexdigest()[:16]


def _coalesce(*values: Any) -> Any:
    for value in values:
        if value is not None and value != "":
            return value
    return None


def _normalize_severity(raw: Any, default: str = "low") -> str:
    value = str(raw).lower() if raw is not None else default
    if value not in ALLOWED_SEVERITIES:
        return default
    return value


def _normalize_event_type(raw: Any, default: str = "connection") -> str:
    value = str(raw).lower() if raw is not None else default
    if value not in ALLOWED_EVENT_TYPES:
        return default
    return value


def _clean_evidence(raw: dict[str, Any]) -> dict[str, Any]:
    evidence = {}
    for key, value in raw.items():
        if key in {"timestamp", "ts", "@timestamp", "time"}:
            continue
        if isinstance(value, (str, int, float, bool, dict, list)) or value is None:
            evidence[key] = value
    return evidence


def network_feature_vector(record: dict[str, Any]) -> list[float]:
    """Map fixture or normalized adapter fields to the network model features."""
    evidence = record.get("evidence", record)
    if not isinstance(evidence, dict):
        raise AdapterError("Network event evidence must be an object")

    def first_value(*names: str) -> Any:
        return next(
            (evidence[name] for name in names if evidence.get(name) is not None),
            None,
        )

    def number(value: Any, field: str, default: float = 0.0) -> float:
        if value is None:
            return default
        if isinstance(value, bool):
            return float(value)
        try:
            result = float(value)
        except (TypeError, ValueError) as exc:
            raise AdapterError(f"Network feature {field!r} must be numeric") from exc
        if not math.isfinite(result):
            raise AdapterError(f"Network feature {field!r} must be finite")
        return result

    packet_count = first_value("packets", "packet_count")
    if packet_count is None:
        packet_parts = [
            evidence.get("orig_pkts"),
            evidence.get("resp_pkts"),
            evidence.get("pkts_toserver"),
            evidence.get("pkts_toclient"),
        ]
        present_packet_parts = [value for value in packet_parts if value is not None]
        if present_packet_parts:
            packet_count = sum(
                number(value, "packets") for value in present_packet_parts
            )

    byte_count = first_value("bytes", "byte_count")
    if byte_count is None:
        byte_parts = [
            evidence.get("orig_bytes"),
            evidence.get("resp_bytes"),
            evidence.get("bytes_toserver"),
            evidence.get("bytes_toclient"),
        ]
        present_byte_parts = [value for value in byte_parts if value is not None]
        if present_byte_parts:
            byte_count = sum(number(value, "bytes") for value in present_byte_parts)

    state = first_value(
        "connection_state", "conn_state", "state", "connection_status"
    )
    if state is None:
        result = first_value("result", "action")
        if result is not None:
            result_text = str(result).strip().casefold()
            if result_text in {"success", "successful", "allowed", "accepted"}:
                state = "established"
            elif result_text in {"failure", "failed", "denied", "rejected"}:
                state = "REJ"
    signature = first_value("signature", "message", "category")
    if state is None and signature is not None and "scan" in str(signature).casefold():
        state = "S0"
    operation = first_value("modbus_operation", "operation")
    state_value = str(state).strip().casefold() if state is not None else "established"
    if state_value in {"online", "success", "successful"}:
        state_value = "established"
    elif state_value in {"failed", "failure", "denied", "rejected"}:
        state_value = "rej"
    values = [
        number(first_value("duration", "duration_seconds"), "duration", 0.12),
        number(packet_count, "packets", 22.0),
        number(byte_count, "bytes", 1100.0),
        number(first_value("dst_port", "dest_port", "server_port"), "dst_port", 502.0),
        float(STATE_FEATURES.get(state_value, 1)),
        number(
            first_value("modbus_function_code", "function_code"),
            "modbus_function_code",
            3.0,
        ),
        float(
            OPERATION_FEATURES.get(
                str(operation).lower(), 1 if operation is None else 0
            )
        ),
        number(first_value("approved_client"), "approved_client", 1.0),
    ]
    return values


def to_part4_event(
    event: dict[str, Any],
    anomaly_score: float,
    asset_id: str | None = None,
) -> dict[str, Any]:
    """Convert a scored P2 event to Part 4's network-event contract."""
    if not isinstance(event, dict):
        raise AdapterError("Network event must be an object")
    try:
        score = float(anomaly_score)
    except (TypeError, ValueError, OverflowError) as exc:
        raise AdapterError("anomaly_score must be a finite number in [0, 1]") from exc
    if not math.isfinite(score) or not 0.0 <= score <= 1.0:
        raise AdapterError("anomaly_score must be a finite number in [0, 1]")
    timestamp = event.get("timestamp")
    mapped_asset = asset_id or event.get("asset_id")
    if not isinstance(timestamp, str) or not timestamp.strip():
        raise AdapterError("timestamp must be a non-empty string")
    if not isinstance(mapped_asset, str) or not mapped_asset.strip():
        raise AdapterError("asset_id must be a non-empty string")

    source = event.get("source") or "network_model"
    evidence = event.get("evidence") or {}
    if not isinstance(evidence, dict):
        raise AdapterError("Network event evidence must be an object")
    event_id = event.get("event_id")
    if not isinstance(event_id, str) or not event_id:
        stable_identity = json.dumps(
            {"source": source, "timestamp": timestamp, "evidence": evidence},
            sort_keys=True,
            separators=(",", ":"),
        )
        event_id = hashlib.sha256(stable_identity.encode("utf-8")).hexdigest()[:16]

    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "source": source,
        "asset_id": mapped_asset.strip(),
        "event_type": "network",
        "anomaly_score": score,
        "severity": _normalize_severity(event.get("severity"), "info"),
        "evidence": {
            **evidence,
            "adapter_event_type": event.get("event_type"),
            "model": "NetworkIsolationForest",
        },
    }


class BaseAdapter:
    """Base class for deterministic log normalization."""

    source_name: str = "generic"

    def normalize(self, record: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError


class ZeekConnectionAdapter(BaseAdapter):
    source_name = "zeek"

    def normalize(self, record: dict[str, Any]) -> dict[str, Any]:
        if "id.orig_h" not in record and "id.resp_h" not in record:
            raise AdapterError("Zeek connection record missing required IP fields")

        timestamp = _as_utc_iso(_coalesce(record.get("ts"), record.get("timestamp"), record.get("@timestamp")))
        ev = {
            "event_id": _event_id(self.source_name, timestamp, {
                "src_ip": record.get("id.orig_h"),
                "dst_ip": record.get("id.resp_h"),
                "dst_port": record.get("id.resp_p"),
            }),
            "timestamp": timestamp,
            "source": self.source_name,
            "asset_id": record.get("asset_id") or _coalesce(record.get("id.resp_h"), record.get("id.orig_h")),
            "event_type": "connection",
            "severity": _normalize_severity(record.get("severity"), "medium"),
            "evidence": {
                "src_ip": record.get("id.orig_h"),
                "dst_ip": record.get("id.resp_h"),
                "src_port": record.get("id.orig_p"),
                "dst_port": record.get("id.resp_p"),
                "protocol": record.get("proto"),
                "service": record.get("service"),
                "duration_seconds": record.get("duration"),
                "orig_pkts": record.get("orig_pkts"),
                "resp_pkts": record.get("resp_pkts"),
                "orig_bytes": record.get("orig_bytes"),
                "resp_bytes": record.get("resp_bytes"),
                "conn_state": record.get("conn_state"),
                "uid": record.get("uid"),
                "history": record.get("history"),
                **_clean_evidence(record),
            },
        }
        return ev


class SuricataEveAdapter(BaseAdapter):
    source_name = "suricata"

    def normalize(self, record: dict[str, Any]) -> dict[str, Any]:
        alert = record.get("alert") or {}
        flow = record.get("flow") or {}
        src_ip = _coalesce(record.get("src_ip"), (record.get("src") if isinstance(record.get("src"), str) else None))
        dst_ip = _coalesce(record.get("dest_ip"), (record.get("dest") if isinstance(record.get("dest"), str) else None))
        timestamp = _as_utc_iso(_coalesce(record.get("timestamp"), record.get("@timestamp"), record.get("time")))
        event_type = _normalize_event_type(alert.get("category"), "alert")
        severity = _normalize_severity(alert.get("severity"), "high")
        evidence = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": record.get("src_port"),
            "dst_port": record.get("dest_port"),
            "proto": record.get("proto"),
            "signature_id": alert.get("signature_id"),
            "signature": alert.get("signature"),
            "category": alert.get("category"),
            "app_proto": record.get("app_proto"),
            "packet_count": flow.get("pkts_toserver") or flow.get("pkts_toclient"),
            "byte_count": flow.get("bytes_toserver") or flow.get("bytes_toclient"),
            "state": flow.get("state"),
            **_clean_evidence(record),
        }
        return {
            "event_id": _event_id(self.source_name, timestamp, {"src_ip": src_ip, "dst_ip": dst_ip, "signature": alert.get("signature")}),
            "timestamp": timestamp,
            "source": self.source_name,
            "asset_id": record.get("asset_id") or dst_ip or src_ip,
            "event_type": event_type,
            "severity": severity,
            "evidence": evidence,
        }


class ModbusMonitorAdapter(BaseAdapter):
    source_name = "modbus_monitor"

    def normalize(self, record: dict[str, Any]) -> dict[str, Any]:
        timestamp = _as_utc_iso(_coalesce(record.get("timestamp"), record.get("ts"), record.get("time")))
        desired = {
            "event_id": _event_id(self.source_name, timestamp, {
                "client_ip": record.get("client_ip"),
                "server_ip": record.get("server_ip"),
                "function_code": record.get("function_code"),
            }),
            "timestamp": timestamp,
            "source": self.source_name,
            "asset_id": record.get("asset_id") or record.get("server_ip") or record.get("client_ip"),
            "event_type": "modbus",
            "severity": _normalize_severity(record.get("severity"), "medium"),
            "evidence": {
                "client_ip": record.get("client_ip"),
                "server_ip": record.get("server_ip"),
                "client_port": record.get("client_port"),
                "server_port": record.get("server_port"),
                "function_code": record.get("function_code"),
                "operation": record.get("operation"),
                "register_address": record.get("register_address"),
                "register_count": record.get("register_count"),
                "approved_client": record.get("approved_client"),
                "connection_status": record.get("connection_status"),
                "response_time_ms": record.get("response_time_ms"),
                **_clean_evidence(record),
            },
        }
        return desired


class OsSecurityAdapter(BaseAdapter):
    source_name = "os_security"

    def normalize(self, record: dict[str, Any]) -> dict[str, Any]:
        timestamp = _as_utc_iso(_coalesce(record.get("timestamp"), record.get("time"), record.get("@timestamp")))
        src_ip = record.get("src_ip") or record.get("source_ip")
        dst_ip = record.get("dst_ip") or record.get("destination_ip")
        evidence = {
            "hostname": record.get("hostname"),
            "log_name": record.get("log_name"),
            "event_id_raw": record.get("event_id"),
            "process_name": record.get("process_name"),
            "user": record.get("user"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": record.get("protocol"),
            "action": record.get("action"),
            "result": record.get("result"),
            "message": record.get("message"),
            **_clean_evidence(record),
        }
        return {
            "event_id": _event_id(self.source_name, timestamp, {"hostname": record.get("hostname"), "msg": record.get("message")}),
            "timestamp": timestamp,
            "source": self.source_name,
            "asset_id": record.get("asset_id") or record.get("hostname") or dst_ip or src_ip,
            "event_type": "os_security",
            "severity": _normalize_severity(record.get("severity"), "low"),
            "evidence": evidence,
        }


ADAPTERS: dict[str, BaseAdapter] = {
    "zeek": ZeekConnectionAdapter(),
    "zeek_conn": ZeekConnectionAdapter(),
    "suricata": SuricataEveAdapter(),
    "suricata_eve": SuricataEveAdapter(),
    "modbus_monitor": ModbusMonitorAdapter(),
    "modbus": ModbusMonitorAdapter(),
    "os_security": OsSecurityAdapter(),
    "windows_security": OsSecurityAdapter(),
    "linux_auth": OsSecurityAdapter(),
}


def detect_source(raw: dict[str, Any]) -> str:
    if "source" in raw:
        return str(raw["source"]).lower()
    if "log_type" in raw:
        return str(raw["log_type"]).lower()
    if "id.orig_h" in raw or "id.resp_h" in raw:
        return "zeek"
    if "alert" in raw or "event_type" in raw and raw.get("event_type") == "alert":
        return "suricata"
    if "function_code" in raw or "approved_client" in raw or "server_ip" in raw:
        return "modbus_monitor"
    if "hostname" in raw or "log_name" in raw:
        return "os_security"
    raise AdapterError("Unable to determine log source for record")


def normalize_record(raw: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise AdapterError(f"Expected a JSON object, got {type(raw).__name__}")
    source = detect_source(raw)
    adapter = ADAPTERS.get(source)
    if adapter is None:
        raise AdapterError(f"Unsupported source: {source!r}. Completed adapters: {', '.join(sorted(ADAPTERS))}")
    return adapter.normalize(raw)


def replay_jsonl(path: str | Path) -> list[dict[str, Any]]:
    records = []
    with open(path, "r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:  # pragma: no cover - defensive path
                raise AdapterError(f"Malformed JSON line {line_no} in {path}: {exc.msg}") from exc
            records.append(normalize_record(item))
    return records


def replay_json(path: str | Path) -> list[dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if isinstance(payload, list):
        return [normalize_record(item) for item in payload]
    if isinstance(payload, dict):
        items = payload.get("events")
        if items is None:
            raise AdapterError(f"JSON payload at {path} does not contain an 'events' list")
        return [normalize_record(item) for item in items]
    raise AdapterError(f"Unsupported JSON root type in {path}: {type(payload).__name__}")


def replay_events(paths: Sequence[str | Path] | str | Path) -> list[dict[str, Any]]:
    if isinstance(paths, (str, Path)):
        paths = [paths]
    normalized_records: list[dict[str, Any]] = []
    for path in paths:
        path_obj = Path(path)
        if not path_obj.exists():
            raise FileNotFoundError(f"Input file does not exist: {path_obj}")
        suffix = path_obj.suffix.lower()
        if suffix in {".jsonl", ".ndjson"}:
            normalized_records.extend(replay_jsonl(path_obj))
        elif suffix == ".json":
            normalized_records.extend(replay_json(path_obj))
        else:
            raise AdapterError(f"Unsupported fixture format '{suffix}' for {path_obj}. Use .json or .jsonl")
    return normalized_records


__all__ = [
    "AdapterError",
    "BaseAdapter",
    "ZeekConnectionAdapter",
    "SuricataEveAdapter",
    "ModbusMonitorAdapter",
    "OsSecurityAdapter",
    "normalize_record",
    "network_feature_vector",
    "to_part4_event",
    "replay_events",
    "replay_json",
    "replay_jsonl",
]
