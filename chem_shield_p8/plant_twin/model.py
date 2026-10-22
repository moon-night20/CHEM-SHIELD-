"""Bounded, deterministic chemical-reactor process simulation."""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG = Path(__file__).resolve().parents[1] / "config" / "plant.yaml"
SENSOR_TAGS = ("temperature", "pressure", "level", "flow")


@dataclass(frozen=True)
class TagSpec:
    """Engineering metadata for one simulated plant tag."""

    unit: str
    safe_min: float
    safe_max: float
    trip_low: float | None
    trip_high: float | None
    register_scale: int


@dataclass(frozen=True)
class PlantConfig:
    """Validated reactor parameters and tag metadata loaded from YAML."""

    parameters: dict[str, float]
    noise: dict[str, float]
    tags: dict[str, TagSpec]


@dataclass
class PlantState:
    """Current simulated measurements and actuator states."""

    temperature_c: float
    pressure_bar: float
    level_pct: float
    flow_l_min: float
    coolant_valve_pct: float
    feed_pump_on: bool
    relief_valve_open: bool

    def as_dict(self) -> dict[str, float | bool]:
        """Return stable API-friendly names for the current process state."""
        return {
            "temperature_c": self.temperature_c,
            "pressure_bar": self.pressure_bar,
            "level_pct": self.level_pct,
            "flow_l_min": self.flow_l_min,
            "coolant_valve_pct": self.coolant_valve_pct,
            "feed_pump_on": self.feed_pump_on,
            "relief_valve_open": self.relief_valve_open,
        }


@dataclass(frozen=True)
class Controls:
    """Requested simulated actuator positions and commands."""

    coolant_valve_pct: float = 35.0
    feed_pump_on: bool = True
    relief_valve_open: bool | None = None


def _finite_number(value: Any, name: str, *, minimum: float | None = None) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite number.")
    result = float(value)
    if not math.isfinite(result) or (minimum is not None and result < minimum):
        raise ValueError(f"{name} must be finite and at least {minimum}.")
    return result


def load_config(path: str | Path = DEFAULT_CONFIG) -> PlantConfig:
    """Load and validate plant physics and tag limits from a YAML file."""
    config_path = Path(path)
    try:
        with config_path.open(encoding="utf-8") as stream:
            document = yaml.safe_load(stream)
    except OSError as error:
        raise ValueError(f"Could not read plant config {config_path}: {error}") from error
    except yaml.YAMLError as error:
        raise ValueError(f"Invalid YAML in plant config {config_path}: {error}") from error

    if not isinstance(document, dict):
        raise ValueError("Plant config must contain a YAML mapping.")
    raw_parameters = document.get("plant")
    raw_tags = document.get("tags")
    if not isinstance(raw_parameters, dict) or not isinstance(raw_tags, dict):
        raise ValueError("Plant config must define 'plant' and 'tags' mappings.")

    noise_value = raw_parameters.pop("sensor_noise", None)
    if not isinstance(noise_value, dict):
        raise ValueError("plant.sensor_noise must be a mapping.")
    parameters: dict[str, float] = {}
    for name, value in raw_parameters.items():
        parameters[name] = _finite_number(value, f"plant.{name}", minimum=0.0)
    required_parameters = {
        "ambient_temperature_c",
        "initial_temperature_c",
        "initial_pressure_bar",
        "initial_level_pct",
        "vessel_capacity_l",
        "thermal_capacity_kj_per_c",
        "heat_loss_kw_per_c",
        "feed_heat_kw_per_l_min",
        "coolant_capacity_kw",
        "coolant_lag_seconds",
        "feed_lag_seconds",
        "pressure_generation_bar_per_c_second",
        "relief_capacity_bar_per_second",
        "natural_pressure_relief_per_second",
        "relief_setpoint_bar",
        "nominal_product_outflow_l_min",
    }
    missing_parameters = required_parameters - parameters.keys()
    if missing_parameters:
        raise ValueError(f"Plant config is missing parameters: {sorted(missing_parameters)}")

    noise = {
        name: _finite_number(value, f"plant.sensor_noise.{name}", minimum=0.0)
        for name, value in noise_value.items()
    }
    tags: dict[str, TagSpec] = {}
    if set(raw_tags) != {
        "temperature", "pressure", "level", "flow", "coolant_valve", "feed_pump", "relief_valve"
    }:
        raise ValueError("Plant config must define all seven required reactor tags.")
    for name, raw_spec in raw_tags.items():
        if not isinstance(raw_spec, dict):
            raise ValueError(f"tags.{name} must be a mapping.")
        safe_range = raw_spec.get("safe_range")
        if not isinstance(safe_range, list) or len(safe_range) != 2:
            raise ValueError(f"tags.{name}.safe_range must have two numeric bounds.")
        safe_min = _finite_number(safe_range[0], f"tags.{name}.safe_range[0]")
        safe_max = _finite_number(safe_range[1], f"tags.{name}.safe_range[1]")
        scale = raw_spec.get("register_scale")
        if isinstance(scale, bool) or not isinstance(scale, int) or scale < 1:
            raise ValueError(f"tags.{name}.register_scale must be a positive integer.")
        trip_low = raw_spec.get("trip_low")
        trip_high = raw_spec.get("trip_high")
        tags[name] = TagSpec(
            unit=str(raw_spec.get("unit", "")),
            safe_min=safe_min,
            safe_max=safe_max,
            trip_low=(
                None if trip_low is None else _finite_number(trip_low, f"tags.{name}.trip_low")
            ),
            trip_high=(
                None if trip_high is None else _finite_number(trip_high, f"tags.{name}.trip_high")
            ),
            register_scale=scale,
        )
        if safe_min >= safe_max:
            raise ValueError(f"tags.{name}.safe_range minimum must be below its maximum.")
        spec = tags[name]
        if (
            (spec.trip_low is not None and not safe_min <= spec.trip_low <= safe_max)
            or (spec.trip_high is not None and not safe_min <= spec.trip_high <= safe_max)
            or (
                spec.trip_low is not None
                and spec.trip_high is not None
                and spec.trip_low >= spec.trip_high
            )
        ):
            raise ValueError(f"tags.{name} trip limits must be ordered within its safe range.")

    _validate_config_bounds(parameters, tags)
    return PlantConfig(parameters=parameters, noise=noise, tags=tags)


def _validate_config_bounds(parameters: dict[str, float], tags: dict[str, TagSpec]) -> None:
    if not tags["temperature"].safe_min <= parameters["initial_temperature_c"] <= tags["temperature"].safe_max:
        raise ValueError("Initial temperature must be inside the configured safe range.")
    if not tags["pressure"].safe_min <= parameters["initial_pressure_bar"] <= tags["pressure"].safe_max:
        raise ValueError("Initial pressure must be inside the configured safe range.")
    if not tags["level"].safe_min <= parameters["initial_level_pct"] <= tags["level"].safe_max:
        raise ValueError("Initial level must be inside the configured safe range.")
    for name in ("vessel_capacity_l", "thermal_capacity_kj_per_c", "coolant_lag_seconds", "feed_lag_seconds"):
        if parameters[name] <= 0:
            raise ValueError(f"plant.{name} must be greater than zero.")


@dataclass
class ReactorTwin:
    """Step a simple mass- and energy-balanced, noisy reactor model."""

    config: PlantConfig = field(default_factory=load_config)
    seed: int = 7
    state: PlantState = field(init=False)
    _rng: random.Random = field(init=False, repr=False)
    _process_state: PlantState = field(init=False, repr=False)

    def __post_init__(self) -> None:
        p = self.config.parameters
        self._rng = random.Random(self.seed)
        self._process_state = PlantState(
            temperature_c=p["initial_temperature_c"],
            pressure_bar=p["initial_pressure_bar"],
            level_pct=p["initial_level_pct"],
            flow_l_min=0.0,
            coolant_valve_pct=0.0,
            feed_pump_on=False,
            relief_valve_open=False,
        )
        self.state = self._measurement_state()

    def step(self, dt_seconds: float, controls: Controls | None = None) -> PlantState:
        """Advance the reactor model by a bounded time step and return its state."""
        dt = _finite_number(dt_seconds, "dt_seconds", minimum=0.0)
        if dt <= 0.0 or dt > 5.0:
            raise ValueError("dt_seconds must be greater than zero and no more than 5 seconds.")
        controls = controls or Controls()
        valve_target = _finite_number(
            controls.coolant_valve_pct, "coolant_valve_pct", minimum=0.0
        )
        if valve_target > 100.0:
            raise ValueError("coolant_valve_pct must be between 0 and 100.")
        if not isinstance(controls.feed_pump_on, bool):
            raise ValueError("feed_pump_on must be a boolean.")
        if controls.relief_valve_open is not None and not isinstance(controls.relief_valve_open, bool):
            raise ValueError("relief_valve_open must be a boolean or None.")

        p = self.config.parameters
        s = self._process_state
        valve_fraction = self._lag(
            s.coolant_valve_pct / 100.0,
            valve_target / 100.0,
            dt,
            p["coolant_lag_seconds"],
        )
        s.coolant_valve_pct = valve_fraction * 100.0

        feed_target = 72.0 if controls.feed_pump_on else 0.0
        s.flow_l_min = self._lag(
            s.flow_l_min,
            feed_target,
            dt,
            p["feed_lag_seconds"],
        )
        s.feed_pump_on = controls.feed_pump_on

        relief_target = (
            controls.relief_valve_open
            if controls.relief_valve_open is not None
            else s.pressure_bar >= p["relief_setpoint_bar"]
        )
        s.relief_valve_open = bool(relief_target)

        ambient = p["ambient_temperature_c"]
        heat_input_kw = s.flow_l_min * p["feed_heat_kw_per_l_min"]
        cooling_kw = p["coolant_capacity_kw"] * valve_fraction * max(
            0.0, s.temperature_c - ambient
        ) / 100.0
        heat_loss_kw = p["heat_loss_kw_per_c"] * max(0.0, s.temperature_c - ambient)
        temperature_rate = (
            heat_input_kw - cooling_kw - heat_loss_kw
        ) / p["thermal_capacity_kj_per_c"]
        s.temperature_c += temperature_rate * dt

        outflow = (
            p["nominal_product_outflow_l_min"]
            if s.level_pct > 0.0
            else 0.0
        )
        level_rate_pct_per_second = (
            s.flow_l_min - outflow
        ) * 100.0 / (60.0 * p["vessel_capacity_l"])
        s.level_pct += level_rate_pct_per_second * dt

        pressure_generation = (
            max(0.0, s.temperature_c - ambient)
            * p["pressure_generation_bar_per_c_second"]
            * (s.level_pct / 100.0)
        )
        pressure_venting = (
            p["relief_capacity_bar_per_second"]
            if s.relief_valve_open
            else p["natural_pressure_relief_per_second"]
        )
        s.pressure_bar += (pressure_generation - pressure_venting) * dt

        self._clamp_process_values()
        self.state = self._measurement_state()
        return self.state

    def trip_alarms(self) -> list[dict[str, float | str]]:
        """Return configured trip-limit violations without actuating equipment."""
        values = {
            "temperature": self.state.temperature_c,
            "pressure": self.state.pressure_bar,
            "level": self.state.level_pct,
        }
        alarms: list[dict[str, float | str]] = []
        for name, value in values.items():
            spec = self.config.tags[name]
            if spec.trip_low is not None and value < spec.trip_low:
                alarms.append({"tag": name, "value": value, "limit": spec.trip_low, "direction": "low"})
            if spec.trip_high is not None and value > spec.trip_high:
                alarms.append({"tag": name, "value": value, "limit": spec.trip_high, "direction": "high"})
        return alarms

    @staticmethod
    def _lag(current: float, target: float, dt: float, time_constant: float) -> float:
        """Exact one-step response of a first-order lag."""
        return target + (current - target) * math.exp(-dt / time_constant)

    def _measurement_state(self) -> PlantState:
        """Copy physical state to sensor values without feeding noise back into physics."""
        noise = self.config.noise
        process = self._process_state
        measured = PlantState(
            temperature_c=process.temperature_c,
            pressure_bar=process.pressure_bar,
            level_pct=process.level_pct,
            flow_l_min=process.flow_l_min,
            coolant_valve_pct=process.coolant_valve_pct,
            feed_pump_on=process.feed_pump_on,
            relief_valve_open=process.relief_valve_open,
        )
        for attribute, noise_key in (
            ("temperature_c", "temperature_c"),
            ("pressure_bar", "pressure_bar"),
            ("level_pct", "level_pct"),
            ("flow_l_min", "flow_l_min"),
        ):
            amplitude = noise.get(noise_key, 0.0)
            value = getattr(measured, attribute) + self._rng.uniform(-amplitude, amplitude)
            setattr(measured, attribute, value)
        return measured

    def _clamp_process_values(self) -> None:
        limits_by_attribute = {
            "temperature_c": "temperature",
            "pressure_bar": "pressure",
            "level_pct": "level",
            "flow_l_min": "flow",
            "coolant_valve_pct": "coolant_valve",
        }
        for attribute, tag_name in limits_by_attribute.items():
            spec = self.config.tags[tag_name]
            value = getattr(self._process_state, attribute)
            setattr(
                self._process_state,
                attribute,
                min(spec.safe_max, max(spec.safe_min, value)),
            )
