"""Explainable rule-based checks combined with the local ML anomaly score."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from chem_shield_p8.plant_twin.model import PlantConfig, PlantState, load_config

from .ml import PhysicalAnomalyModel
from .rules import PhysicsRules


@dataclass(frozen=True)
class PhysicsFinding:
    """One physical-consistency rule result."""

    rule_id: str
    severity: str
    message: str
    evidence: dict[str, Any]


@dataclass(frozen=True)
class GuardResult:
    """Side-by-side interpretable rule score and ML score."""

    physics_score: float
    ml_score: float
    findings: list[PhysicsFinding]
    explanation: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "physics_score": self.physics_score,
            "ml_score": self.ml_score,
            "findings": [
                {
                    "rule_id": finding.rule_id,
                    "severity": finding.severity,
                    "message": finding.message,
                    "evidence": finding.evidence,
                }
                for finding in self.findings
            ],
            "explanation": self.explanation,
        }


class PhysicsGuard:
    """Compare consecutive process observations with simple reactor balances."""

    def __init__(
        self,
        *,
        plant_config: PlantConfig | None = None,
        rules: PhysicsRules | None = None,
        ml_model: PhysicalAnomalyModel | None = None,
        ml_enabled: bool = True,
    ) -> None:
        self.plant_config = plant_config or load_config()
        self.rules = rules or PhysicsRules.load()
        self.ml_model = ml_model or PhysicalAnomalyModel.fit_simulated_normal(
            self.plant_config
        )
        self.ml_enabled = ml_enabled
        self._previous: PlantState | None = None

    def analyze(self, current: PlantState, dt_seconds: float) -> GuardResult:
        """Score one measurement against physical rates, balances, and ML."""
        if dt_seconds <= 0.0 or dt_seconds > 5.0:
            raise ValueError("dt_seconds must be greater than zero and no more than 5 seconds.")
        previous = self._previous
        findings: list[PhysicsFinding] = []
        if previous is not None:
            findings.extend(self._rate_findings(previous, current, dt_seconds))
            findings.extend(self._balance_findings(previous, current, dt_seconds))
            findings.extend(self._correlation_findings(previous, current, dt_seconds))
        self._previous = current
        physics_score = self._physics_score(findings)
        ml_score = (
            self.ml_model.score(current, previous, dt_seconds)
            if self.ml_enabled and self.ml_model is not None
            else 0.0
        )
        explanations = [finding.message for finding in findings]
        if not explanations:
            explanations.append(self.ml_model.explain(ml_score) if self.ml_model else "No physics inconsistency detected.")
        return GuardResult(
            physics_score=physics_score,
            ml_score=ml_score,
            findings=findings,
            explanation=" ".join(explanations),
        )

    def reset(self) -> None:
        """Start a new telemetry stream without a previous-sample dependency."""
        self._previous = None

    def _rate_findings(
        self, previous: PlantState, current: PlantState, dt_seconds: float
    ) -> list[PhysicsFinding]:
        readings = (
            ("temperature_c", previous.temperature_c, current.temperature_c, "°C"),
            ("pressure_bar", previous.pressure_bar, current.pressure_bar, "bar"),
            ("level_pct", previous.level_pct, current.level_pct, "%"),
            ("flow_l_min", previous.flow_l_min, current.flow_l_min, "L/min"),
        )
        findings: list[PhysicsFinding] = []
        for tag, before, after, unit in readings:
            delta = after - before
            rate = delta / dt_seconds
            limit = self.rules.maximum_rate_per_second[tag]
            if abs(rate) > limit:
                findings.append(PhysicsFinding(
                    rule_id="RATE_OF_CHANGE",
                    severity="HIGH",
                    message=f"{tag} changed {delta:+.2f} {unit} in {dt_seconds:g}s, exceeding its physical rate limit.",
                    evidence={"tag": tag, "delta": delta, "rate_per_second": rate, "limit_per_second": limit},
                ))
        return findings

    def _balance_findings(
        self, previous: PlantState, current: PlantState, dt_seconds: float
    ) -> list[PhysicsFinding]:
        p = self.plant_config.parameters
        tolerance = self.rules.balance_tolerance_per_second
        ambient = p["ambient_temperature_c"]
        coolant_fraction = current.coolant_valve_pct / 100.0
        heat_input_kw = current.flow_l_min * p["feed_heat_kw_per_l_min"]
        cooling_kw = (
            p["coolant_capacity_kw"]
            * coolant_fraction
            * max(0.0, current.temperature_c - ambient)
            / 100.0
        )
        heat_loss_kw = p["heat_loss_kw_per_c"] * max(
            0.0, current.temperature_c - ambient
        )
        expected_temperature_delta = (
            (heat_input_kw - cooling_kw - heat_loss_kw)
            / p["thermal_capacity_kj_per_c"]
            * dt_seconds
        )
        observed_temperature_delta = current.temperature_c - previous.temperature_c
        energy_residual = observed_temperature_delta - expected_temperature_delta
        energy_limit = tolerance["temperature_c"] * dt_seconds
        findings: list[PhysicsFinding] = []
        if abs(energy_residual) > energy_limit:
            estimated_coolant_flow = current.coolant_valve_pct * 0.8
            findings.append(PhysicsFinding(
                rule_id="ENERGY_BALANCE",
                severity="CRITICAL" if abs(energy_residual) > 10.0 else "HIGH",
                message=(
                    f"Temperature rose {observed_temperature_delta:.1f}°C but estimated "
                    f"coolant flow ({estimated_coolant_flow:.1f} L/min) and valve position "
                    f"({current.coolant_valve_pct:.0f}%) do not explain it -> possible spoofing."
                ),
                evidence={
                    "observed_temperature_delta_c": observed_temperature_delta,
                    "expected_temperature_delta_c": expected_temperature_delta,
                    "residual_c": energy_residual,
                    "coolant_flow_estimate_l_min": estimated_coolant_flow,
                    "coolant_valve_pct": current.coolant_valve_pct,
                },
            ))

        expected_level_delta = (
            (current.flow_l_min - p["nominal_product_outflow_l_min"])
            * 100.0
            / (60.0 * p["vessel_capacity_l"])
            * dt_seconds
        )
        level_residual = (current.level_pct - previous.level_pct) - expected_level_delta
        level_limit = tolerance["level_pct"] * dt_seconds
        if abs(level_residual) > level_limit:
            findings.append(PhysicsFinding(
                rule_id="MASS_BALANCE",
                severity="HIGH",
                message="Reactor level change does not match feed flow and modeled product outflow.",
                evidence={
                    "observed_level_delta_pct": current.level_pct - previous.level_pct,
                    "expected_level_delta_pct": expected_level_delta,
                    "residual_pct": level_residual,
                    "feed_flow_l_min": current.flow_l_min,
                },
            ))

        expected_pressure_delta = (
            max(0.0, current.temperature_c - ambient)
            * p["pressure_generation_bar_per_c_second"]
            * (current.level_pct / 100.0)
            - (
                p["relief_capacity_bar_per_second"]
                if current.relief_valve_open
                else p["natural_pressure_relief_per_second"]
            )
        ) * dt_seconds
        pressure_residual = (current.pressure_bar - previous.pressure_bar) - expected_pressure_delta
        pressure_limit = tolerance["pressure_bar"] * dt_seconds
        if abs(pressure_residual) > pressure_limit:
            findings.append(PhysicsFinding(
                rule_id="PRESSURE_BALANCE",
                severity="HIGH",
                message="Pressure change does not match modeled temperature, level, and relief-valve state.",
                evidence={
                    "observed_pressure_delta_bar": current.pressure_bar - previous.pressure_bar,
                    "expected_pressure_delta_bar": expected_pressure_delta,
                    "residual_bar": pressure_residual,
                    "relief_valve_open": current.relief_valve_open,
                },
            ))
        return findings

    def _correlation_findings(
        self, previous: PlantState, current: PlantState, dt_seconds: float
    ) -> list[PhysicsFinding]:
        findings: list[PhysicsFinding] = []
        temperature_rate = (current.temperature_c - previous.temperature_c) / dt_seconds
        if (
            current.coolant_valve_pct >= self.rules.cooling_valve_high_pct
            and temperature_rate
            > self.rules.cooling_unexplained_temperature_rate_c_per_second
        ):
            findings.append(PhysicsFinding(
                rule_id="COOLING_CORRELATION",
                severity="CRITICAL",
                message=(
                    "Temperature is rising rapidly while the coolant valve is highly open; "
                    "sensor spoofing or process manipulation is possible."
                ),
                evidence={
                    "temperature_rate_c_per_second": temperature_rate,
                    "coolant_valve_pct": current.coolant_valve_pct,
                },
            ))
        if (
            not current.feed_pump_on
            and current.flow_l_min > self.rules.pump_off_flow_tolerance_l_min
        ):
            findings.append(PhysicsFinding(
                rule_id="PUMP_FLOW_CORRELATION",
                severity="HIGH",
                message="Feed flow is present while the feed pump command is off.",
                evidence={
                    "flow_l_min": current.flow_l_min,
                    "feed_pump_on": current.feed_pump_on,
                },
            ))
        return findings

    @staticmethod
    def _physics_score(findings: list[PhysicsFinding]) -> float:
        weights = {"MEDIUM": 0.25, "HIGH": 0.5, "CRITICAL": 0.75}
        return min(1.0, sum(weights.get(item.severity, 0.0) for item in findings))
