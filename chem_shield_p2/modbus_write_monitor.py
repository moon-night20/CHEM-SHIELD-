"""Passive Modbus-write monitoring for the loopback virtual PLC."""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import time
from typing import Any, Callable, Deque, Dict, Iterable, Optional, Set, Tuple

from chem_shield_p1.plc.register_map import (
    REGISTER_COUNT,
    SIM_OVERRIDE_MASK,
    SIM_OVERRIDE_REGISTERS,
)

WRITE_FUNCTION_CODES = frozenset({5, 6, 15, 16, 22, 23})
EXPECTED_WRITE_FUNCTION_CODES = frozenset({6, 16})
SIM_OVERRIDE_END = SIM_OVERRIDE_MASK + SIM_OVERRIDE_REGISTERS


class ModbusTcpWriteMonitor:
    """Inspect decoded Modbus requests without changing or blocking traffic."""

    def __init__(
        self,
        *,
        allowed_sources: Iterable[str] = ("127.0.0.1",),
        expected_registers: Iterable[int] = range(REGISTER_COUNT),
        burst_threshold: int = 5,
        burst_window_seconds: float = 1.0,
        debounce_seconds: float = 10.0,
        asset_id: str = "PLC-01",
        event_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        if burst_threshold < 1:
            raise ValueError("burst_threshold must be at least one")
        if burst_window_seconds <= 0:
            raise ValueError("burst_window_seconds must be positive")
        if debounce_seconds < 0:
            raise ValueError("debounce_seconds must not be negative")
        self.allowed_sources = frozenset(
            str(ipaddress.ip_address(address)) for address in allowed_sources
        )
        self.expected_registers = frozenset(expected_registers)
        self.burst_threshold = burst_threshold
        self.burst_window_seconds = burst_window_seconds
        self.debounce_seconds = debounce_seconds
        self.asset_id = asset_id
        self.event_sink = event_sink
        self._writes: Dict[str, Deque[float]] = defaultdict(deque)
        self._last_emitted: Dict[Tuple[str, str], float] = {}

    def inspect(
        self,
        request: Any,
        source_address: str,
        *,
        now: Optional[float] = None,
    ) -> list[Dict[str, Any]]:
        """Return and optionally emit Part 4 events for suspicious writes."""
        function_code = int(getattr(request, "function_code", -1))
        if function_code not in WRITE_FUNCTION_CODES:
            return []

        moment = time.monotonic() if now is None else now
        source = str(source_address)
        start, count, address_space = self._write_range(request, function_code)
        reasons = []
        if self._normalized_source(source) not in self.allowed_sources:
            reasons.append((
                "unknown_modbus_source",
                "high",
                0.9,
                f"Modbus write came from unapproved source address {source}.",
            ))
        if address_space == "holding_register" and any(
            address not in self.expected_registers
            for address in range(start, start + count)
        ):
            reasons.append((
                "unexpected_register_write",
                "high",
                0.85,
                f"Modbus write targeted unexpected holding register range {start}-{start + count - 1}.",
            ))
        if function_code not in EXPECTED_WRITE_FUNCTION_CODES:
            reasons.append((
                "unusual_write_function_code",
                "high",
                0.8,
                f"Modbus write used unusual function code {function_code}.",
            ))
        if (
            address_space == "holding_register"
            and start < SIM_OVERRIDE_END
            and start + count > SIM_OVERRIDE_MASK
        ):
            reasons.append((
                "simulation_override_write",
                "medium",
                0.7,
                "A simulation override register write from the Attack Console was observed.",
            ))

        writes = self._writes[source]
        writes.append(moment)
        while writes and moment - writes[0] > self.burst_window_seconds:
            writes.popleft()
        if len(writes) >= self.burst_threshold:
            reasons.append((
                "modbus_write_burst",
                "medium",
                0.75,
                f"{len(writes)} Modbus writes from {source} occurred within "
                f"{self.burst_window_seconds:g} seconds.",
            ))

        events = []
        for rule_id, severity, score, message in reasons:
            if not self._should_emit(rule_id, source, moment):
                continue
            event = self._event(
                request,
                source,
                function_code,
                start,
                count,
                address_space,
                rule_id,
                severity,
                score,
                message,
                observed_write_count=len(writes),
            )
            events.append(event)
            if self.event_sink is not None:
                self.event_sink(event)
        return events

    def _should_emit(self, rule_id: str, source: str, moment: float) -> bool:
        key = (rule_id, source)
        previous = self._last_emitted.get(key)
        if previous is not None and moment - previous < self.debounce_seconds:
            return False
        self._last_emitted[key] = moment
        return True

    @staticmethod
    def _normalized_source(source: str) -> Optional[str]:
        try:
            return str(ipaddress.ip_address(source))
        except ValueError:
            return None

    @staticmethod
    def _write_range(request: Any, function_code: int) -> Tuple[int, int, str]:
        if function_code == 23:
            return (
                int(request.write_address),
                len(request.write_registers),
                "holding_register",
            )
        if function_code in {5, 15}:
            count = len(request.values) if function_code == 15 else 1
            return int(request.address), count, "coil"
        if function_code == 22:
            return int(request.address), 1, "holding_register"
        if function_code == 6:
            return int(request.address), 1, "holding_register"
        if function_code == 16:
            return int(request.address), len(request.values), "holding_register"
        raise ValueError(f"Unsupported Modbus write function code: {function_code}")

    def _event(
        self,
        request: Any,
        source: str,
        function_code: int,
        start: int,
        count: int,
        address_space: str,
        rule_id: str,
        severity: str,
        score: float,
        message: str,
        observed_write_count: int,
    ) -> Dict[str, Any]:
        timestamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        evidence = {
            "rule_id": rule_id,
            "message": message,
            "client_address": source,
            "function_code": function_code,
            "operation": getattr(request, "function_code_name", "unknown_write"),
            "address_space": address_space,
            "address_start": start,
            "address_count": count,
        }
        values = getattr(request, "values", None)
        if values is None and hasattr(request, "write_registers"):
            values = request.write_registers
        if values is None and hasattr(request, "value"):
            values = [request.value]
        if values is not None:
            evidence["requested_values"] = list(values)
        if rule_id == "unknown_modbus_source":
            evidence["allowed_source_addresses"] = sorted(self.allowed_sources)
        elif rule_id == "unexpected_register_write":
            evidence["expected_register_range"] = [
                min(self.expected_registers),
                max(self.expected_registers),
            ] if self.expected_registers else []
        elif rule_id == "unusual_write_function_code":
            evidence["expected_write_function_codes"] = sorted(
                EXPECTED_WRITE_FUNCTION_CODES
            )
        elif rule_id == "modbus_write_burst":
            evidence["observed_write_count"] = observed_write_count
            evidence["configured_burst_threshold"] = self.burst_threshold
            evidence["configured_burst_window_seconds"] = self.burst_window_seconds
        identity = {
            "timestamp": timestamp,
            "asset_id": self.asset_id,
            "source": source,
            "evidence": evidence,
        }
        event_id = "MODBUS-" + hashlib.sha256(
            json.dumps(identity, sort_keys=True).encode("utf-8")
        ).hexdigest()[:12].upper()
        return {
            "event_id": event_id,
            "timestamp": timestamp,
            "source": "modbus_write_monitor",
            "asset_id": self.asset_id,
            "event_type": "network",
            "anomaly_score": score,
            "severity": severity,
            "evidence": evidence,
        }
