"""Project-local paths and CSV helpers for the AI/ML component."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
MODELS_DIR = PROJECT_ROOT / "models"
RESULTS_DIR = PROJECT_ROOT / "results"
GRAPHS_DIR = PROJECT_ROOT / "graphs"
DEFAULT_MODEL_PATH = MODELS_DIR / "isolation_forest.joblib"


def ensure_artifact_directories() -> None:
    """Create only the local directories used for generated ML artifacts."""

    for directory in (DATA_DIR, MODELS_DIR, RESULTS_DIR, GRAPHS_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def read_telemetry_csv(path: str | Path) -> pd.DataFrame:
    """Read a machine-readable telemetry CSV without changing its schema."""

    return pd.read_csv(path)


def write_csv(data: pd.DataFrame, path: str | Path) -> Path:
    """Write a CSV, creating its parent directory when needed."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    data.to_csv(destination, index=False)
    return destination
