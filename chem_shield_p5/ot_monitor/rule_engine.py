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
            ("power", "power"),
            ("speed", "speed"),
        ):
            if sensor not in values:
                continue
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

            physics = self.config.get("physics_consistency", {})
            operating_rules = self.config.get("operating_rules", {})
            running_states = {
                item.upper()
                for item in operating_rules.get("expected_running_states", ["RUNNING"])
            }
            is_running = state is not None and state.upper() in running_states
            elapsed_seconds = (reading.timestamp - previous_time).total_seconds()
            rpm_change = values.get("speed", 0.0) - previous_values.get("speed", 0.0)
            power_change = values.get("power", 0.0) - previous_values.get("power", 0.0)
            temperature_change = (
                values.get("temperature", 0.0)
                - previous_values.get("temperature", 0.0)
            )
            pressure_change = (
                values.get("pressure", 0.0) - previous_values.get("pressure", 0.0)
            )

            rpm_power_rule = physics.get("rpm_rising_power_flat", {})
            minimum_rpm_increase = rpm_power_rule.get("minimum_rpm_increase")
            maximum_power_change = rpm_power_rule.get("maximum_power_change")
            if (
                is_running
                and minimum_rpm_increase is not None
                and maximum_power_change is not None
                and rpm_change >= minimum_rpm_increase
                and abs(power_change) <= maximum_power_change
                and "speed" in values
                and "power" in values
                and "speed" in previous_values
                and "power" in previous_values
            ):
                alerts.append(RuleAlert(
                    "rpm_rising_power_flat",
                    "PHYSICS-RPM-RISING-POWER-FLAT",
                    rpm_power_rule.get("severity", "medium"),
                    "RPM rose while measured power remained nearly flat",
                    {
                        "speed": values["speed"],
                        "previous_speed": previous_values["speed"],
                        "rpm_change": rpm_change,
                        "power": values["power"],
                        "previous_power": previous_values["power"],
                        "power_change": power_change,
                        "minimum_rpm_increase": minimum_rpm_increase,
                        "maximum_power_change": maximum_power_change,
                        "operating_state": state,
                    },
                ))

            temperature_rule = physics.get("temperature_falling_under_load", {})
            minimum_power = temperature_rule.get("minimum_power")
            minimum_temperature_drop = temperature_rule.get("minimum_temperature_drop")
            if (
                is_running
                and minimum_power is not None
                and minimum_temperature_drop is not None
                and values.get("power", float("-inf")) >= minimum_power
                and temperature_change <= -minimum_temperature_drop
                and "temperature" in values
                and "temperature" in previous_values
                and "power" in values
            ):
                alerts.append(RuleAlert(
                    "temperature_falling_under_load",
                    "PHYSICS-TEMPERATURE-FALLING-UNDER-LOAD",
                    temperature_rule.get("severity", "medium"),
                    "Temperature fell while the machine was running under load",
                    {
                        "temperature": values["temperature"],
                        "previous_temperature": previous_values["temperature"],
                        "temperature_change": temperature_change,
                        "power": values["power"],
                        "minimum_power": minimum_power,
                        "minimum_temperature_drop": minimum_temperature_drop,
                        "operating_state": state,
                    },
                ))

            pressure_rule = physics.get("pressure_not_tracking_rpm", {})
            minimum_rpm_change = pressure_rule.get("minimum_rpm_change")
            minimum_pressure_change = pressure_rule.get("minimum_pressure_change")
            pressure_follows_rpm = False
            if minimum_pressure_change is not None:
                pressure_follows_rpm = (
                    rpm_change > 0 and pressure_change >= minimum_pressure_change
                ) or (
                    rpm_change < 0 and pressure_change <= -minimum_pressure_change
                )
            if (
                is_running
                and minimum_rpm_change is not None
                and minimum_pressure_change is not None
                and abs(rpm_change) >= minimum_rpm_change
                and not pressure_follows_rpm
                and all(
                    sensor in values and sensor in previous_values
                    for sensor in ("speed", "pressure")
                )
            ):
                alerts.append(RuleAlert(
                    "pressure_not_tracking_rpm",
                    "PHYSICS-PRESSURE-NOT-TRACKING-RPM",
                    pressure_rule.get("severity", "medium"),
                    "Pressure did not track a significant RPM change",
                    {
                        "speed": values["speed"],
                        "previous_speed": previous_values["speed"],
                        "rpm_change": rpm_change,
                        "pressure": values["pressure"],
                        "previous_pressure": previous_values["pressure"],
                        "pressure_change": pressure_change,
                        "minimum_rpm_change": minimum_rpm_change,
                        "minimum_pressure_change": minimum_pressure_change,
                        "operating_state": state,
                    },
                ))

        frozen_rule = self.config.get("physics_consistency", {}).get("frozen_sensor", {})
        frozen_duration = frozen_rule.get("duration_seconds")
        frozen_running_states = {
            item.upper()
            for item in self.config.get("operating_rules", {}).get(
                "expected_running_states", ["RUNNING"]
            )
        }
        frozen_state_is_running = state is not None and state.upper() in frozen_running_states
        if (
            frozen_duration is not None
            and previous
            and (
                not frozen_rule.get("only_when_running", True)
                or frozen_state_is_running
            )
        ):
            tolerance = frozen_rule.get("tolerance", 0.0)
            frozen_sensors = frozen_rule.get(
                "sensors", ("temperature", "pressure", "power", "speed")
            )
            for sensor in frozen_sensors:
                if sensor not in values or sensor not in previous[-1][1]:
                    continue
                start_time = reading.timestamp
                previous_value = values[sensor]
                for prior_time, prior_values, _prior_state in reversed(previous):
                    if sensor not in prior_values or abs(prior_values[sensor] - previous_value) > tolerance:
                        break
                    start_time = prior_time
                frozen_seconds = (reading.timestamp - start_time).total_seconds()
                if frozen_seconds >= frozen_duration:
                    alerts.append(RuleAlert(
                        "sensor_frozen",
                        f"PHYSICS-{sensor.upper()}-FROZEN",
                        frozen_rule.get("severity", "medium"),
                        f"{sensor} stayed unchanged longer than its configured duration",
                        {
                            "sensor": sensor,
                            "value": values[sensor],
                            "frozen_seconds": frozen_seconds,
                            "configured_duration_seconds": frozen_duration,
                            "tolerance": tolerance,
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
