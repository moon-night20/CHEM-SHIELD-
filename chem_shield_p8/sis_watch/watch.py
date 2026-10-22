"""Comparison of current simulated SIS state with its signed baseline."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .baseline import SISState, canonical_json, sign_baseline, verify_baseline
from .chain import SISHashChain


@dataclass(frozen=True)
class SISResult:
    """Signed-baseline comparison and chained decision record."""

    status: str
    changed_fields: list[str]
    baseline_hash: str
    observed_hash: str
    chain_record: dict[str, Any]
    message: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "severity": "CRITICAL" if self.status != "INTACT" else "INFO",
            "changed_fields": list(self.changed_fields),
            "baseline_hash": self.baseline_hash,
            "observed_hash": self.observed_hash,
            "chain_record": dict(self.chain_record),
            "message": self.message,
        }


class SISWatch:
    """Fail-closed monitoring for simulated SIS state and configuration."""

    def __init__(
        self,
        baseline: dict[str, Any],
        signing_key: bytes,
        chain: SISHashChain | None = None,
    ) -> None:
        if not verify_baseline(baseline, signing_key):
            raise ValueError("Cannot start SIS watch: baseline signature or hash is invalid.")
        self.baseline = baseline
        self.signing_key = signing_key
        self.chain = chain or SISHashChain()
        self._baseline_payload = dict(baseline["payload"])
        self._baseline_hash = str(baseline["payload_sha256"])

    @classmethod
    def from_file(
        cls,
        baseline_path: str | Path,
        signing_key: bytes,
        chain_path: str | Path | None = None,
    ) -> "SISWatch":
        import json

        try:
            baseline = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(f"Could not load SIS baseline: {error}") from error
        return cls(baseline, signing_key, SISHashChain(chain_path))

    def check(
        self,
        current: SISState,
        *,
        timestamp: datetime | None = None,
    ) -> SISResult:
        """Compare fields and chain an explicit INTACT or CRITICAL decision."""
        observed_payload = current.as_payload()
        observed_hash = hashlib.sha256(
            canonical_json(observed_payload).encode("utf-8")
        ).hexdigest()
        changed_fields = sorted(
            key
            for key in self._baseline_payload
            if canonical_json(self._baseline_payload[key]) != canonical_json(observed_payload[key])
        )
        status = "CRITICAL" if changed_fields else "INTACT"
        record = self.chain.append(
            status=status,
            baseline_hash=self._baseline_hash,
            observed_hash=observed_hash,
            changed_fields=changed_fields,
            timestamp=timestamp,
        )
        message = (
            "SIS state differs from its signed baseline: " + ", ".join(changed_fields)
            if changed_fields
            else "SIS state matches its signed baseline."
        )
        return SISResult(
            status=status,
            changed_fields=changed_fields,
            baseline_hash=self._baseline_hash,
            observed_hash=observed_hash,
            chain_record=record,
            message=message,
        )


def create_baseline_document(state: SISState, signing_key: bytes) -> dict[str, Any]:
    """Convenience wrapper to create the signed SIS baseline document."""
    return sign_baseline(state, signing_key)
