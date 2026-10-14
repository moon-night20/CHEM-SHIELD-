"""Configurable engineering-limit and historical-context checks."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Deque, Dict, List, Optional, Tuple

from .sensor_validation import ValidatedReading


@dataclass
class RuleAlert:
    event_type: str
    rule_id: str
    severity: str
    message: str
    evidence: Dict[str, Any]


class RuleEngine:
    """Evaluate explicitly configured limits; unset thresholds do not trigger rules."""

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config = config or {}
        self.history: Dict[str, Deque[Tuple[datetime, Dict[str, float], Optional[str]]]] = {}

    def evaluate(self, reading: ValidatedReading) -> List[RuleAlert]:
        values = reading.measurements
        state = reading.operating_state
        previous = self.history.get(reading.asset_id, deque())
        alerts: List[RuleAlert] = []

        limits = self.config.get("limits", {})
        for sensor, event_prefix in (
            ("temperature", "temperature"),
            ("pressure", "pressure"),
            ("speed", "speed"),
        ):
            value = values[sensor]
            sensor_limits = limits.get(sensor, {})
            upper = sensor_limits.get("high")
            lower = sensor_limits.get("low")
            if upper is not None and value > upper:
                alerts.append(self._alert(
                    f"{event_prefix}_high", sensor_limits.get("high_rule_id", f"{sensor.upper()}-HIGH"),
                    sensor_limits.get("high_severity", "high"),
                    f"{sensor} exceeded configured high limit",
                    sensor, value, upper, reading,
                ))
            if lower is not None and value < lower:
                alerts.append(self._alert(
                    f"{event_prefix}_low", sensor_limits.get("low_rule_id", f"{sensor.upper()}-LOW"),
                    sensor_limits.get("low_severity", "high"),
                    f"{sensor} fell below configured low limit",
                    sensor, value, lower, reading,
                ))

        if previous:
            previous_time, previous_values, previous_state = previous[-1]
            elapsed_minutes = (reading.timestamp - previous_time).total_seconds() / 60.0
            if elapsed_minutes > 0:
                rate_config = self.config.get("rate_of_change", {})
                for sensor in ("temperature", "pressure", "speed"):
                    limit = rate_config.get(sensor)
                    if limit is None:
                        continue
                    rate = (values[sensor] - previous_values[sensor]) / elapsed_minutes
                    if abs(rate) > limit:
                        alerts.append(RuleAlert(
                            "rapid_process_change", f"{sensor.upper()}-ROC",
                            rate_config.get("severity", "medium"),
                            f"{sensor} rate of change exceeded configured limit",
                            {
                                "sensor": sensor,
                                "previous_value": previous_values[sensor],
                                "current_value": values[sensor],
                                "rate_per_minute": rate,
                                "configured_max_abs_rate_per_minute": limit,
                                "operating_state": state,
                            },
                        ))

                fluctuation = self.config.get("fluctuation", {})
                for sensor in ("temperature", "pressure", "speed"):
                    max_range = fluctuation.get(sensor)
                    if max_range is None:
                        continue
                    samples = [entry[1][sensor] for entry in list(previous)[-int(fluctuation.get("window_samples", 5)) + 1:]]
                    samples.append(values[sensor])
                    observed_range = max(samples) - min(samples)
                    if len(samples) >= int(fluctuation.get("minimum_samples", 3)) and observed_range > max_range:
                        alerts.append(RuleAlert(
                            "process_fluctuation", f"{sensor.upper()}-FLUCTUATION",
                            fluctuation.get("severity", "medium"),
                            f"{sensor} fluctuation exceeded configured range",
                            {
                                "sensor": sensor,
                                "observed_range": observed_range,
                                "configured_max_range": max_range,
                                "sample_count": len(samples),
                                "operating_state": state,
                            },
                        ))

        if state:
            state_rules = self.config.get("state_limits", {}).get(state, {})
            for sensor, key, event_type in (
                ("temperature", "temperature", "temperature_state_inconsistent"),
                ("pressure", "pressure", "pressure_state_inconsistent"),
                ("speed", "speed", "speed_state_inconsistent"),
            ):
                bounds = state_rules.get(key, {})
                value = values[sensor]
                low, high = bounds.get("low"), bounds.get("high")
                if low is not None and value < low or high is not None and value > high:
                    alerts.append(RuleAlert(
                        event_type, f"{sensor.upper()}-STATE-{state}",
                        bounds.get("severity", "medium"),
                        f"{sensor} is outside the configured range for state {state}",
                        {
                            "sensor": sensor,
                            "value": value,
                            "operating_state": state,
                            "previous_operating_state": previous_state,
                            "configured_range": {"low": low, "high": high},
                        },
                    ))

        speed_rules = self.config.get("operating_rules", {})
        if state and state in {s.upper() for s in speed_rules.get("expected_running_states", ["RUNNING"])}:
            min_speed = speed_rules.get("minimum_speed_when_running")
            if min_speed is not None and values["speed"] < min_speed:
                alerts.append(RuleAlert(
                    "speed_low", "SPEED-LOW-WHEN-RUNNING", speed_rules.get("severity", "medium"),
                    "Speed is below configured minimum while operation is expected",
                    {"speed": values["speed"], "minimum_speed": min_speed, "operating_state": state},
                ))
        if state and state in {s.upper() for s in speed_rules.get("stopped_states", ["STOPPED"])}:
            stopped_threshold = speed_rules.get("maximum_speed_when_stopped")
            if stopped_threshold is not None and values["speed"] > stopped_threshold:
                alerts.append(RuleAlert(
                    "unexpected_speed_while_stopped", "SPEED-UNEXPECTED-STOPPED",
                    speed_rules.get("severity", "high"),
                    "Speed exceeds configured stopped-state threshold",
                    {"speed": values["speed"], "maximum_speed": stopped_threshold, "operating_state": state},
                ))

        history = self.history.setdefault(reading.asset_id, deque(maxlen=int(self.config.get("history_size", 100))))
        history.append((reading.timestamp, values, state))
        return alerts

    @staticmethod
    def _alert(
        event_type: str,
        rule_id: str,
        severity: str,
        message: str,
        sensor: str,
        value: float,
        threshold: float,
        reading: ValidatedReading,
    ) -> RuleAlert:
        return RuleAlert(
            event_type, rule_id, severity, message,
            {
                "sensor": sensor,
                "value": value,
                "unit": reading.units[sensor],
                "configured_threshold": threshold,
                "operating_state": reading.operating_state,
            },
        )
