"""Append-only, locally verifiable hash chain for SIS check decisions."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .baseline import canonical_json

GENESIS_HASH = "0" * 64


class SISHashChain:
    """Persist SIS decision records as JSONL with linked SHA-256 hashes."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else None
        self._records: list[dict[str, Any]] = []
        if self.path is not None and self.path.exists():
            self._records = self._read_records()
            result = self.verify()
            if not result["ok"]:
                raise ValueError(f"SIS decision chain is invalid: {result['reason']}")

    def append(
        self,
        *,
        status: str,
        baseline_hash: str,
        observed_hash: str,
        changed_fields: list[str],
        timestamp: datetime | None = None,
    ) -> dict[str, Any]:
        """Append a linked check record, validating existing history first."""
        verified = self.verify()
        if not verified["ok"]:
            raise ValueError(f"Refusing to append to invalid SIS chain: {verified['reason']}")
        previous_hash = self._records[-1]["hash"] if self._records else GENESIS_HASH
        body = {
            "sequence": len(self._records) + 1,
            "timestamp": (timestamp or datetime.now(timezone.utc)).isoformat(),
            "status": status,
            "baseline_hash": baseline_hash,
            "observed_hash": observed_hash,
            "changed_fields": sorted(changed_fields),
        }
        digest = hashlib.sha256(
            (previous_hash + canonical_json(body)).encode("utf-8")
        ).hexdigest()
        record = {
            **body,
            "previous_hash": previous_hash,
            "hash": digest,
        }
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(canonical_json(record) + "\n")
        self._records.append(record)
        return dict(record)

    def records(self) -> list[dict[str, Any]]:
        """Return a copy of the stored records."""
        return [dict(record) for record in self._records]

    def verify(self) -> dict[str, Any]:
        """Verify sequence, previous links, and every record digest."""
        previous_hash = GENESIS_HASH
        for index, record in enumerate(self._records, start=1):
            body = {key: value for key, value in record.items() if key not in {"hash", "previous_hash"}}
            expected = hashlib.sha256(
                (previous_hash + canonical_json(body)).encode("utf-8")
            ).hexdigest()
            if record.get("sequence") != index:
                return {"ok": False, "first_broken_index": index, "reason": "SIS chain sequence changed."}
            if record.get("previous_hash") != previous_hash:
                return {"ok": False, "first_broken_index": index, "reason": "SIS previous-hash link changed."}
            if record.get("hash") != expected:
                return {"ok": False, "first_broken_index": index, "reason": "SIS decision hash is invalid."}
            previous_hash = expected
        return {"ok": True, "records": len(self._records)}

    def _read_records(self) -> list[dict[str, Any]]:
        if self.path is None:
            return []
        records: list[dict[str, Any]] = []
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError as error:
            raise ValueError(f"Could not read SIS decision chain: {error}") from error
        for index, line in enumerate(lines, start=1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"Invalid SIS chain JSON at line {index}: {error}") from error
            if not isinstance(record, dict):
                raise ValueError(f"Invalid SIS chain record at line {index}.")
            records.append(record)
        return records
