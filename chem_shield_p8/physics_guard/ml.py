"""Isolation Forest anomaly model trained only on the local reactor simulation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import numpy as np
from sklearn.ensemble import IsolationForest

from chem_shield_p8.plant_twin.model import Controls, PlantConfig, PlantState, ReactorTwin, load_config

FEATURE_NAMES = (
    "temperature_fraction",
    "pressure_fraction",
    "level_fraction",
    "flow_fraction",
    "coolant_valve_fraction",
    "temperature_rate_fraction",
    "pressure_rate_fraction",
    "level_rate_fraction",
    "flow_rate_fraction",
    "feed_pump_on",
    "relief_valve_open",
)


@dataclass
class PhysicalAnomalyModel:
    """A fitted detector with a score calibrated against generated normal data."""

    config: PlantConfig
    contamination: float = 0.03
    random_state: int = 42
    estimator: IsolationForest | None = None
    threshold: float | None = None
    score_span: float | None = None
    training_rows: int = 0

    @classmethod
    def fit_simulated_normal(
        cls,
        config: PlantConfig | None = None,
        *,
        seeds: Iterable[int] = range(8),
        steps_per_seed: int = 180,
        random_state: int = 42,
    ) -> "PhysicalAnomalyModel":
        """Fit using reproducible, locally generated normal reactor trajectories."""
        plant_config = config or load_config()
        model = cls(config=plant_config, random_state=random_state)
        rows: list[np.ndarray] = []
        for seed in seeds:
            twin = ReactorTwin(config=plant_config, seed=seed)
            previous: PlantState | None = None
            controls = Controls(coolant_valve_pct=40.0, feed_pump_on=False)
            for index in range(steps_per_seed):
                if index % 30 == 0:
                    controls = Controls(
                        coolant_valve_pct=25.0 + float((index // 30 * 13 + seed * 7) % 45),
                        feed_pump_on=(index // 30 + seed) % 3 != 0,
                    )
                current = twin.step(1.0, controls)
                rows.append(model.features(current, previous, 1.0))
                previous = current
        model.fit(np.vstack(rows))
        return model

    def fit(self, samples: np.ndarray) -> None:
        """Fit on a finite two-dimensional array of simulated normal features."""
        data = np.asarray(samples, dtype=np.float64)
        if data.ndim != 2 or data.shape[1] != len(FEATURE_NAMES) or len(data) < 20:
            raise ValueError(f"Normal samples must have at least 20 rows and {len(FEATURE_NAMES)} features.")
        if not np.isfinite(data).all():
            raise ValueError("Normal samples must contain only finite values.")
        self.estimator = IsolationForest(
            n_estimators=120,
            contamination=self.contamination,
            random_state=self.random_state,
        )
        self.estimator.fit(data)
        training_evidence = -self.estimator.score_samples(data)
        self.threshold = float(np.quantile(training_evidence, 0.97))
        upper = float(np.quantile(training_evidence, 0.995))
        self.score_span = max(upper - self.threshold, 1e-6)
        self.training_rows = len(data)

    def score(
        self,
        current: PlantState,
        previous: PlantState | None,
        dt_seconds: float,
    ) -> float:
        """Return a normalized 0..1 anomaly score, not an attack probability."""
        if self.estimator is None or self.threshold is None or self.score_span is None:
            raise RuntimeError("Physical anomaly model is not fitted.")
        features = self.features(current, previous, dt_seconds).reshape(1, -1)
        evidence = -float(self.estimator.score_samples(features)[0])
        return min(1.0, max(0.0, (evidence - self.threshold) / self.score_span))

    def explain(self, score: float) -> str:
        if score >= 0.7:
            return "ML model found a strong deviation from its simulated normal training data."
        if score >= 0.35:
            return "ML model found a moderate deviation from its simulated normal training data."
        return "ML model is within its simulated normal range."

    def features(
        self,
        current: PlantState,
        previous: PlantState | None,
        dt_seconds: float,
    ) -> np.ndarray:
        """Build the fixed feature vector shared by training and inference."""
        if dt_seconds <= 0:
            raise ValueError("dt_seconds must be positive.")
        tags = self.config.tags
        if previous is None:
            rates = (0.0, 0.0, 0.0, 0.0)
        else:
            rates = tuple(
                (now - before) / dt_seconds
                for now, before in (
                    (current.temperature_c, previous.temperature_c),
                    (current.pressure_bar, previous.pressure_bar),
                    (current.level_pct, previous.level_pct),
                    (current.flow_l_min, previous.flow_l_min),
                )
            )
        normalizers = (
            max(1.0, tags["temperature"].safe_max),
            max(1.0, tags["pressure"].safe_max),
            max(1.0, tags["level"].safe_max),
            max(1.0, tags["flow"].safe_max),
            100.0,
            5.0,
            1.0,
            5.0,
            120.0,
        )
        values = (
            current.temperature_c,
            current.pressure_bar,
            current.level_pct,
            current.flow_l_min,
            current.coolant_valve_pct,
            *rates,
            float(current.feed_pump_on),
            float(current.relief_valve_open),
        )
        return np.asarray(
            [value / scale for value, scale in zip(values[:9], normalizers)]
            + list(values[9:]),
            dtype=np.float64,
        )
