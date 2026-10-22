"""Physics residuals, rate limits, and cross-sensor consistency checks."""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

DEFAULT_RULES = Path(__file__).resolve().parents[1] / "config" / "physics.yaml"


@dataclass(frozen=True)
class PhysicsRules:
    """Configured limits for expected reactor rates and balance residuals."""

    maximum_rate_per_second: dict[str, float]
    balance_tolerance_per_second: dict[str, float]
    cooling_valve_high_pct: float
    cooling_unexplained_temperature_rate_c_per_second: float
    pump_off_flow_tolerance_l_min: float

    @classmethod
    def load(cls, path: str | Path = DEFAULT_RULES) -> "PhysicsRules":
        config_path = Path(path)
        try:
            with config_path.open(encoding="utf-8") as stream:
                values = yaml.safe_load(stream)
        except OSError as error:
            raise ValueError(f"Could not read physics rules {config_path}: {error}") from error
        except yaml.YAMLError as error:
            raise ValueError(f"Invalid physics-rule YAML {config_path}: {error}") from error
        if not isinstance(values, dict):
            raise ValueError("Physics rules must contain a YAML mapping.")
        rate_limits = _number_map(values, "maximum_rate_per_second")
        balance_limits = _number_map(values, "balance_tolerance_per_second")
        required_rates = {"temperature_c", "pressure_bar", "level_pct", "flow_l_min"}
        if not required_rates.issubset(rate_limits):
            raise ValueError("Physics rules are missing one or more sensor rate limits.")
        if not {"temperature_c", "level_pct", "pressure_bar"}.issubset(balance_limits):
            raise ValueError("Physics rules are missing one or more balance tolerances.")
        return cls(
            maximum_rate_per_second=rate_limits,
            balance_tolerance_per_second=balance_limits,
            cooling_valve_high_pct=_positive_or_zero(
                values.get("cooling_valve_high_pct"), "cooling_valve_high_pct"
            ),
            cooling_unexplained_temperature_rate_c_per_second=_positive_or_zero(
                values.get("cooling_unexplained_temperature_rate_c_per_second"),
                "cooling_unexplained_temperature_rate_c_per_second",
            ),
            pump_off_flow_tolerance_l_min=_positive_or_zero(
                values.get("pump_off_flow_tolerance_l_min"),
                "pump_off_flow_tolerance_l_min",
            ),
        )


def _number_map(values: dict[str, Any], key: str) -> dict[str, float]:
    raw_map = values.get(key)
    if not isinstance(raw_map, dict):
        raise ValueError(f"Physics rule {key} must be a mapping.")
    result: dict[str, float] = {}
    for name, value in raw_map.items():
        result[name] = _positive_or_zero(value, f"{key}.{name}")
    return result


def _positive_or_zero(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite non-negative number.")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise ValueError(f"{name} must be a finite non-negative number.")
    return result
