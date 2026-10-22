"""Detection rules for passive synthetic OT protocol records."""

from __future__ import annotations

import hashlib
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from chem_shield_p8.plant_twin.model import PlantConfig, load_config

from .events import OTEvent, parse_event
from .inventory import Asset, AssetInventory

DEFAULT_MONITOR_CONFIG = Path(__file__).resolve().parents[1] / "config" / "monitor.yaml"


@dataclass(frozen=True)
class Alert:
    """One explanatory, detector-generated observation."""

    alert_id: str
    event_id: str
    timestamp: datetime
    rule_id: str
    severity: str
    message: str
    source_ip: str
    destination_ip: str
    evidence: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class MonitorConfig:
    """Thresholds and local host-role map for the passive monitor."""

    known_hosts: dict[str, str]
    allowed_modbus_function_codes: frozenset[int]
    poll_window_seconds: float
    maximum_reads_per_window: int
    replay_window_seconds: float
    engineering_role: str

    @classmethod
    def load(cls, path: str | Path = DEFAULT_MONITOR_CONFIG) -> "MonitorConfig":
        config_path = Path(path)
        try:
            with config_path.open(encoding="utf-8") as stream:
                values = yaml.safe_load(stream)
        except OSError as error:
            raise ValueError(f"Could not read monitor config {config_path}: {error}") from error
        except yaml.YAMLError as error:
            raise ValueError(f"Invalid monitor YAML {config_path}: {error}") from error
        if not isinstance(values, dict):
            raise ValueError("Monitor config must contain a YAML mapping.")
        hosts = values.get("known_hosts")
        codes = values.get("allowed_modbus_function_codes")
        if not isinstance(hosts, dict) or not isinstance(codes, list):
            raise ValueError("Monitor config requires known_hosts and allowed function codes.")
        if any(not isinstance(ip, str) or not isinstance(role, str) for ip, role in hosts.items()):
            raise ValueError("Known host addresses and roles must be strings.")
        if any(isinstance(code, bool) or not isinstance(code, int) for code in codes):
            raise ValueError("Allowed Modbus function codes must be integers.")
        poll_window = _positive_number(values.get("poll_window_seconds"), "poll_window_seconds")
        replay_window = _positive_number(values.get("replay_window_seconds"), "replay_window_seconds")
        max_reads = values.get("maximum_reads_per_window")
        if isinstance(max_reads, bool) or not isinstance(max_reads, int) or max_reads < 1:
            raise ValueError("maximum_reads_per_window must be a positive integer.")
        role = values.get("engineering_role", "engineering")
        if not isinstance(role, str) or not role.strip():
            raise ValueError("engineering_role must be a non-empty string.")
        return cls(
            known_hosts=dict(hosts),
            allowed_modbus_function_codes=frozenset(codes),
            poll_window_seconds=poll_window,
            maximum_reads_per_window=max_reads,
            replay_window_seconds=replay_window,
            engineering_role=role,
        )


class OTMonitor:
    """Apply protocol and behavior rules to supplied events; never captures traffic."""

    def __init__(
        self,
        config: MonitorConfig | None = None,
        plant_config: PlantConfig | None = None,
    ) -> None:
        self.config = config or MonitorConfig.load()
        self.plant_config = plant_config or load_config()
        self.inventory = AssetInventory(self.config.known_hosts)
        self._read_times: dict[tuple[str, str], deque[datetime]] = defaultdict(deque)
        self._fingerprints: dict[str, datetime] = {}

    def process(self, record: dict[str, Any] | OTEvent) -> list[Alert]:
        """Inspect one normalized event and update the local asset inventory."""
        event = parse_event(record) if isinstance(record, dict) else record
        if not isinstance(event, OTEvent):
            raise ValueError("OT monitor accepts OTEvent instances or event mappings.")
        alerts: list[Alert] = []
        for asset in self.inventory.observe(event):
            alerts.append(self._alert(
                event,
                "UNKNOWN_ASSET",
                "HIGH",
                f"New endpoint discovered at {asset.ip_address}; role is unknown.",
                {"asset": asset.as_dict()},
            ))

        if (
            event.protocol == "modbus-tcp"
            and event.function_code not in self.config.allowed_modbus_function_codes
        ):
            alerts.append(self._alert(
                event,
                "ILLEGAL_FUNCTION_CODE",
                "HIGH",
                f"Modbus function code {event.function_code} is not allowed by policy.",
                {"function_code": event.function_code},
            ))

        if event.operation == "write" and self.inventory.role_for(event.source_ip) != self.config.engineering_role:
            alerts.append(self._alert(
                event,
                "UNAUTHORIZED_WRITE",
                "CRITICAL",
                f"Write from {self.event_host(event.source_ip)} is not from an engineering host.",
                {
                    "source_role": self.inventory.role_for(event.source_ip),
                    "function_code": event.function_code,
                    "tag": event.tag,
                    "value": event.value,
                },
            ))

        if event.operation == "write":
            out_of_range = self._out_of_range(event)
            if out_of_range is not None:
                alerts.append(self._alert(
                    event,
                    "SETPOINT_OUT_OF_RANGE",
                    "CRITICAL",
                    f"Write to {event.tag} is outside its configured safe range.",
                    out_of_range,
                ))

        if event.operation == "read":
            alerts.extend(self._check_poll_rate(event))
        alerts.extend(self._check_replay(event))
        return alerts

    def process_stream(self, records: list[dict[str, Any]]) -> list[Alert]:
        """Process a finite synthetic stream in the order supplied."""
        alerts: list[Alert] = []
        for record in records:
            alerts.extend(self.process(record))
        return alerts

    def assets(self) -> list[Asset]:
        return self.inventory.list_assets()

    @staticmethod
    def event_host(ip_address: str) -> str:
        return ip_address

    def _out_of_range(self, event: OTEvent) -> dict[str, Any] | None:
        if event.tag is None or event.value is None:
            return None
        tag_name = event.tag.casefold()
        if tag_name in {"coolant_valve", "coolant_valve_pct"}:
            tag_name = "coolant_valve"
        elif tag_name in {"feed_pump", "feed_pump_on"}:
            tag_name = "feed_pump"
        elif tag_name in {"relief_valve", "relief_valve_open"}:
            tag_name = "relief_valve"
        spec = self.plant_config.tags.get(tag_name)
        if spec is None or isinstance(event.value, bool):
            return None
        if spec.safe_min <= float(event.value) <= spec.safe_max:
            return None
        return {
            "tag": event.tag,
            "value": event.value,
            "safe_min": spec.safe_min,
            "safe_max": spec.safe_max,
            "unit": spec.unit,
        }

    def _check_poll_rate(self, event: OTEvent) -> list[Alert]:
        key = (event.source_ip, event.destination_ip)
        events = self._read_times[key]
        cutoff = event.timestamp - timedelta(seconds=self.config.poll_window_seconds)
        while events and events[0] < cutoff:
            events.popleft()
        events.append(event.timestamp)
        if len(events) <= self.config.maximum_reads_per_window:
            return []
        return [self._alert(
            event,
            "ABNORMAL_POLLING_RATE",
            "MEDIUM",
            f"Read polling exceeded {self.config.maximum_reads_per_window} requests "
            f"within {self.config.poll_window_seconds:g} seconds.",
            {
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "reads_in_window": len(events),
                "window_seconds": self.config.poll_window_seconds,
            },
        )]

    def _check_replay(self, event: OTEvent) -> list[Alert]:
        previous = self._fingerprints.get(event.fingerprint)
        self._fingerprints[event.fingerprint] = event.timestamp
        cutoff = event.timestamp - timedelta(seconds=self.config.replay_window_seconds)
        self._fingerprints = {
            fingerprint: timestamp
            for fingerprint, timestamp in self._fingerprints.items()
            if timestamp >= cutoff
        }
        if previous is None or event.timestamp - previous > timedelta(
            seconds=self.config.replay_window_seconds
        ):
            return []
        return [self._alert(
            event,
            "DUPLICATE_PACKET_REPLAY",
            "HIGH",
            "An identical protocol message was observed again inside the replay window.",
            {
                "fingerprint": event.fingerprint,
                "first_seen": previous.isoformat(),
                "replay_window_seconds": self.config.replay_window_seconds,
            },
        )]

    @staticmethod
    def _alert(
        event: OTEvent,
        rule_id: str,
        severity: str,
        message: str,
        evidence: dict[str, Any],
    ) -> Alert:
        digest = hashlib.sha256(
            f"{event.event_id}:{rule_id}".encode("utf-8")
        ).hexdigest()[:16]
        return Alert(
            alert_id=digest,
            event_id=event.event_id,
            timestamp=event.timestamp,
            rule_id=rule_id,
            severity=severity,
            message=message,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            evidence=evidence,
        )


def _positive_number(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a positive finite number.")
    result = float(value)
    if not math_is_positive_finite(result):
        raise ValueError(f"{name} must be a positive finite number.")
    return result


def math_is_positive_finite(value: float) -> bool:
    return value > 0.0 and value < float("inf")
