"""Standalone isolation-forest-style anomaly detector for network traffic.

This model is deliberately separate from the physical telemetry model used by the
Part 1 PLC/process simulator. Scores reflect relative deviation from a baseline of
normal network behaviour; they are not attack probabilities.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

import joblib

def _mean(values: Sequence[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _variance(values: Sequence[float]) -> float:
    if len(values) < 2:
        return 0.0
    avg = _mean(values)
    return sum((value - avg) ** 2 for value in values) / (len(values) - 1)


def _cumulative_harmonic(n: int) -> float:
    # H(n) = 1 + 1/2 + ... + 1/n for n >= 1
    return sum(1.0 / i for i in range(1, n + 1)) if n > 0 else 0.0


def _adjusted_path_length(n: int) -> float:
    if n <= 1:
        return 0.0
    harmonic = _cumulative_harmonic(n - 1)
    return 2.0 * (harmonic + math.log(2.0)) - (2.0 * (n - 1) / n)


@dataclass
class _TreeNode:
    feature_index: int | None = None
    split_value: float | None = None
    left: "_TreeNode | None" = None
    right: "_TreeNode | None" = None
    depth: int = 0
    size: int = 0


class IsolationTree:
    """Simple isolation tree for one-dimensional and multi-dimensional features."""

    def __init__(self, max_depth: int = 8, random_seed: int | None = None):
        self.max_depth = max_depth
        self.random = random.Random(random_seed)

    def fit(self, rows: Sequence[Sequence[float]]) -> _TreeNode:
        if not rows:
            return _TreeNode(size=0)
        return self._build(rows, depth=0)

    def _build(self, rows: Sequence[Sequence[float]], depth: int) -> _TreeNode:
        node = _TreeNode(depth=depth, size=len(rows))
        if depth >= self.max_depth or len(rows) <= 1:
            return node

        feature_index = self._select_feature(rows)
        values = [row[feature_index] for row in rows]
        minimum = min(values)
        maximum = max(values)
        if math.isclose(minimum, maximum):
            return node

        split_value = self.random.uniform(minimum, maximum)
        left_rows = [row for row in rows if row[feature_index] < split_value]
        right_rows = [row for row in rows if row[feature_index] >= split_value]
        if not left_rows or not right_rows:
            return node

        node.feature_index = feature_index
        node.split_value = split_value
        node.left = self._build(left_rows, depth + 1)
        node.right = self._build(right_rows, depth + 1)
        return node

    def _select_feature(self, rows: Sequence[Sequence[float]]) -> int:
        feature_count = len(rows[0])
        variances = []
        for index in range(feature_count):
            values = [row[index] for row in rows]
            variances.append((index, _variance(values)))
        _, best = max(variances, key=lambda item: item[1])
        if best == 0:
            return self.random.randrange(feature_count)
        return max(variances, key=lambda item: item[1])[0]

    def path_length(self, row: Sequence[float]) -> float:
        node = self.root
        length = 0.0
        while node.feature_index is not None and node.split_value is not None:
            if row[node.feature_index] < node.split_value:
                node = node.left
            else:
                node = node.right
            length += 1.0
            if node is None:
                break
        if node is None:
            return length + 1.0
        if node.size <= 1:
            return length + _adjusted_path_length(node.size)
        return length + _adjusted_path_length(node.size)

    @property
    def root(self) -> _TreeNode:
        if not hasattr(self, "_root"):
            raise AttributeError("Tree has not been fit yet")
        return self._root

    def fit_root(self, rows: Sequence[Sequence[float]]) -> None:
        self._root = self.fit(rows)


class NetworkIsolationForest:
    """Isolation forest variant using duration, packet counts, ports, state, and Modbus fields.

    Scores are relative anomalies in a baseline population. A higher score indicates a
    stronger deviation from normal connectivity behaviour; it is not a probability of
    compromise.
    """

    def __init__(self, n_estimators: int = 64, max_depth: int = 8, random_seed: int = 7):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.random_seed = random_seed
        self.estimators_: list[IsolationTree] = []
        self.feature_names_: list[str] = []

    def fit(self, X: Iterable[Sequence[float]]) -> "NetworkIsolationForest":
        rows = [list(row) for row in X]
        if not rows:
            raise ValueError("At least one baseline row is required to fit the model")
        feature_count = len(rows[0])
        if feature_count == 0 or any(len(row) != feature_count for row in rows):
            raise ValueError("All baseline rows must have the same non-zero feature count")
        if any(not math.isfinite(float(value)) for row in rows for value in row):
            raise ValueError("Baseline features must be finite numbers")
        self.feature_names_ = [f"feature_{idx}" for idx in range(len(rows[0]))]
        self.estimators_ = []
        for index in range(self.n_estimators):
            tree = IsolationTree(max_depth=self.max_depth, random_seed=self.random_seed + index)
            sample_size = min(len(rows), max(2, len(rows) // 2))
            sample = rows[index % len(rows):] + rows[: index % len(rows)]
            sample = sample[:sample_size]
            tree.fit_root(sample)
            self.estimators_.append(tree)
        return self

    def score_samples(self, X: Iterable[Sequence[float]]) -> list[float]:
        if not self.estimators_:
            raise ValueError("Model has not been fit yet")
        scores: list[float] = []
        for row in X:
            if len(row) != len(self.feature_names_):
                raise ValueError("Feature count differs from the fitted model")
            if any(not math.isfinite(float(value)) for value in row):
                raise ValueError("Scoring features must be finite numbers")
            model_scores = []
            for tree in self.estimators_:
                path_length = tree.path_length(list(row))
                model_scores.append(path_length)
            avg_path = sum(model_scores) / len(model_scores)
            # Standard isolation-forest score transform; higher means more anomalous.
            score = 2.0 ** (-avg_path / _adjusted_path_length(max(2, len(row))))
            scores.append(float(score))
        return scores

    def save(self, path: str | Path) -> Path:
        if not self.estimators_:
            raise ValueError("Cannot save an unfitted model")
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, destination)
        return destination

    @classmethod
    def load(cls, path: str | Path) -> "NetworkIsolationForest":
        loaded = joblib.load(path)
        if not isinstance(loaded, cls):
            raise TypeError(f"Artifact at {path} is not a {cls.__name__}")
        if not loaded.estimators_ or not loaded.feature_names_:
            raise ValueError(f"Artifact at {path} does not contain a fitted model")
        return loaded

    def evaluate(self, X_normal: Iterable[Sequence[float]], X_abnormal: Iterable[Sequence[float]]) -> dict[str, float]:
        normal_scores = self.score_samples(X_normal)
        abnormal_scores = self.score_samples(X_abnormal)
        return {
            "normal_mean": sum(normal_scores) / max(len(normal_scores), 1),
            "abnormal_mean": sum(abnormal_scores) / max(len(abnormal_scores), 1),
            "normal_max": max(normal_scores) if normal_scores else 0.0,
            "abnormal_max": max(abnormal_scores) if abnormal_scores else 0.0,
        }


__all__ = ["NetworkIsolationForest", "IsolationTree"]
