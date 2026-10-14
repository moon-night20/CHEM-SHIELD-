"""Fixture-trained network scoring helpers for the P2 to Part 4 handoff."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from chem_shield_p2.adapters import network_feature_vector, to_part4_event
from chem_shield_p2.network_isolation_forest import NetworkIsolationForest


LOGGER = logging.getLogger(__name__)
PART2_DIR = Path(__file__).resolve().parent
DEFAULT_BASELINE = PART2_DIR / "fixtures" / "network_baseline.json"
DEFAULT_MODEL = PART2_DIR / "models" / "network_isolation_forest_calibrated.joblib"


def train_network_model(
    model_path: str | Path = DEFAULT_MODEL,
    baseline_path: str | Path = DEFAULT_BASELINE,
) -> NetworkIsolationForest:
    """Fit the network detector on the checked-in normal fixture and persist it."""
    with Path(baseline_path).open(encoding="utf-8") as stream:
        baseline = json.load(stream)
    if not isinstance(baseline, list) or not baseline:
        raise ValueError(f"Network baseline must be a non-empty JSON list: {baseline_path}")

    model = NetworkIsolationForest().fit(
        network_feature_vector(record) for record in baseline
    )
    model.save(model_path)
    LOGGER.info("Saved fixture-trained network model to %s", model_path)
    return NetworkIsolationForest.load(model_path)


def load_or_train_network_model(
    model_path: str | Path = DEFAULT_MODEL,
    baseline_path: str | Path = DEFAULT_BASELINE,
) -> NetworkIsolationForest:
    """Load a saved model, training and reloading only when the artifact is absent."""
    artifact = Path(model_path)
    if artifact.exists():
        return NetworkIsolationForest.load(artifact)
    return train_network_model(artifact, baseline_path)


def configured_asset_id(event: dict[str, Any], config: dict[str, Any]) -> str:
    """Map fixture endpoint identities to the configured simulated PLC asset."""
    asset_map = config.get("asset_id_map", {})
    default_asset_id = config.get("default_asset_id")
    if not isinstance(asset_map, dict):
        raise ValueError("asset_id_map must be an object")

    original = event.get("asset_id")
    mapped = None
    if original is not None:
        original_text = str(original)
        mapped = next(
            (
                value for key, value in asset_map.items()
                if str(key).casefold() == original_text.casefold()
            ),
            None,
        )
    result = mapped or default_asset_id or original
    if not isinstance(result, str) or not result.strip():
        raise ValueError("P2 config must map each event to a non-empty asset_id")
    return result.strip()


def score_to_part4_events(
    events: list[dict[str, Any]],
    model: NetworkIsolationForest,
    config: dict[str, Any],
) -> list[dict[str, Any]]:
    """Score normalized adapter events and apply the configured PLC asset mapping."""
    vectors = [network_feature_vector(event) for event in events]
    scores = model.calibrate_scores(model.score_samples(vectors))
    return [
        to_part4_event(event, score, configured_asset_id(event, config))
        for event, score in zip(events, scores)
    ]


__all__ = [
    "DEFAULT_BASELINE",
    "DEFAULT_MODEL",
    "configured_asset_id",
    "load_or_train_network_model",
    "score_to_part4_events",
    "train_network_model",
]
