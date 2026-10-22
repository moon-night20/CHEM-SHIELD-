"""Canonical SIS snapshots and HMAC-signed local baselines."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

BASELINE_SCHEMA = 1


@dataclass(frozen=True)
class SISState:
    """Setpoints, bypass indicators, safety-valve state, and SIS configuration."""

    trip_setpoints: dict[str, float]
    bypass_flags: dict[str, bool]
    safety_valve_states: dict[str, bool]
    configuration: dict[str, Any] = field(default_factory=dict)

    def as_payload(self) -> dict[str, Any]:
        """Return a validated, canonicalizable snapshot."""
        setpoints: dict[str, float] = {}
        for name, value in self.trip_setpoints.items():
            if not isinstance(name, str) or not name.strip():
                raise ValueError("SIS setpoint names must be non-empty strings.")
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
                raise ValueError(f"SIS setpoint {name} must be a finite number.")
            setpoints[name] = float(value)
        bypass = _boolean_map(self.bypass_flags, "bypass_flags")
        valves = _boolean_map(self.safety_valve_states, "safety_valve_states")
        if not isinstance(self.configuration, dict):
            raise ValueError("SIS configuration must be a mapping.")
        return {
            "trip_setpoints": setpoints,
            "bypass_flags": bypass,
            "safety_valve_states": valves,
            "configuration": self.configuration,
        }

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "SISState":
        if not isinstance(payload, dict):
            raise ValueError("SIS baseline payload must be a mapping.")
        expected = {
            "trip_setpoints",
            "bypass_flags",
            "safety_valve_states",
            "configuration",
        }
        if set(payload) != expected:
            raise ValueError("SIS baseline payload has missing or unexpected fields.")
        if not all(isinstance(payload[key], dict) for key in expected):
            raise ValueError("SIS baseline payload fields must be mappings.")
        state = cls(
            trip_setpoints=payload["trip_setpoints"],
            bypass_flags=payload["bypass_flags"],
            safety_valve_states=payload["safety_valve_states"],
            configuration=payload["configuration"],
        )
        state.as_payload()
        return state


def load_or_create_key(path: str | Path) -> bytes:
    """Load an existing local key or create a private 256-bit signing key once."""
    key_path = Path(path)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(
            str(key_path),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
    except FileExistsError:
        key = key_path.read_bytes()
    else:
        key = secrets.token_bytes(32)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(key)
    if len(key) < 32:
        raise ValueError("SIS signing key must contain at least 32 bytes.")
    return key


def sign_baseline(state: SISState, key: bytes) -> dict[str, Any]:
    """Create a signed baseline document without writing files."""
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("SIS signing key must contain at least 32 bytes.")
    payload = state.as_payload()
    payload_hash = _sha256(canonical_json(payload))
    signature = hmac.new(key, payload_hash.encode("ascii"), hashlib.sha256).hexdigest()
    return {
        "schema": BASELINE_SCHEMA,
        "payload": payload,
        "payload_sha256": payload_hash,
        "signature_hmac_sha256": signature,
    }


def verify_baseline(document: dict[str, Any], key: bytes) -> bool:
    """Verify baseline structure, canonical content hash, and keyed signature."""
    try:
        if not isinstance(document, dict) or document.get("schema") != BASELINE_SCHEMA:
            return False
        if not isinstance(key, bytes) or len(key) < 32:
            return False
        payload = SISState.from_payload(document["payload"]).as_payload()
        payload_hash = _sha256(canonical_json(payload))
        if not hmac.compare_digest(payload_hash, str(document["payload_sha256"])):
            return False
        expected = hmac.new(key, payload_hash.encode("ascii"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, str(document["signature_hmac_sha256"]))
    except (KeyError, TypeError, ValueError):
        return False


def create_baseline(
    path: str | Path,
    state: SISState,
    key: bytes,
    *,
    replace_existing: bool = False,
) -> dict[str, Any]:
    """Write one signed baseline; existing baselines require explicit replacement."""
    baseline_path = Path(path)
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    if baseline_path.exists() and not replace_existing:
        raise FileExistsError(
            f"SIS baseline already exists at {baseline_path}; refusing to replace it."
        )
    document = sign_baseline(state, key)
    encoded = canonical_json(document) + "\n"
    if replace_existing:
        baseline_path.write_text(encoded, encoding="utf-8")
    else:
        try:
            descriptor = os.open(
                str(baseline_path),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError:
            raise FileExistsError(
                f"SIS baseline already exists at {baseline_path}; refusing to replace it."
            )
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(encoded)
    return document


def read_baseline(path: str | Path, key: bytes) -> SISState:
    """Read and verify a baseline, failing closed on malformed or altered data."""
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Could not read SIS baseline: {error}") from error
    if not verify_baseline(document, key):
        raise ValueError("SIS baseline signature or content hash is invalid.")
    return SISState.from_payload(document["payload"])


def canonical_json(value: Any) -> str:
    """Serialize JSON values deterministically and reject non-finite numbers."""
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise ValueError(f"SIS data is not valid canonical JSON: {error}") from error


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _boolean_map(values: dict[str, bool], name: str) -> dict[str, bool]:
    if not isinstance(values, dict):
        raise ValueError(f"SIS {name} must be a mapping.")
    result: dict[str, bool] = {}
    for key, value in values.items():
        if not isinstance(key, str) or not key.strip() or not isinstance(value, bool):
            raise ValueError(f"SIS {name} must map non-empty names to booleans.")
        result[key] = value
    return result
