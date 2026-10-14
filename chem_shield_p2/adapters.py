"""Fixture-backed adapters for common OT and enterprise network log formats.

Only adapters with tested sanitised fixture coverage are considered complete.
Planned live integrations are documented in the README rather than implemented here.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence


ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical"}
ALLOWED_EVENT_TYPES = {"connection", "alert", "modbus", "os_security"}


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
    "replay_events",
    "replay_json",
    "replay_jsonl",
]
