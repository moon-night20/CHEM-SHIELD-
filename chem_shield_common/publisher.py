"""Loopback-only event publisher for the Part 1 HMI risk endpoint."""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


DEFAULT_HMI_URL = "http://127.0.0.1:15000/api/risk/events"
LOGGER = logging.getLogger(__name__)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def _validate_url(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1":
        raise ValueError("HMI URL must use http://127.0.0.1")
    if parsed.username or parsed.password:
        raise ValueError("HMI URL must not contain credentials")


def _open_local(request: Request, timeout: float):
    opener = build_opener(_NoRedirect)
    return opener.open(request, timeout=timeout)


def _response_payload(body: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("HMI returned a non-JSON response") from exc
    if not isinstance(payload, dict):
        raise ValueError("HMI response must be a JSON object")
    for key in ("accepted", "rejected"):
        value = payload.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"HMI response must contain a non-negative integer {key!r}")
    return payload


def _batches(events: list[dict[str, Any]], batch_size: int) -> Iterable[list[dict[str, Any]]]:
    for start in range(0, len(events), batch_size):
        yield events[start : start + batch_size]


def publish_events(
    events: Iterable[dict[str, Any]],
    url: str = DEFAULT_HMI_URL,
    *,
    batch_size: int = 100,
    timeout: float = 2.0,
    retries: int = 2,
    backoff: float = 0.25,
) -> dict[str, Any]:
    """Publish event batches to a loopback HMI; report failures without raising network errors."""
    _validate_url(url)
    if batch_size < 1:
        raise ValueError("batch_size must be at least 1")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if retries < 0:
        raise ValueError("retries must not be negative")
    if backoff < 0:
        raise ValueError("backoff must not be negative")

    prepared = list(events)
    if any(not isinstance(event, dict) for event in prepared):
        raise TypeError("events must contain only dictionaries")
    try:
        json.dumps(prepared, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"events must be finite JSON values: {exc}") from exc

    result: dict[str, Any] = {
        "accepted": 0,
        "rejected": 0,
        "batches": 0,
        "failed_batches": 0,
        "errors": [],
    }
    for batch_number, batch in enumerate(_batches(prepared, batch_size), start=1):
        result["batches"] += 1
        headers = {"Content-Type": "application/json"}
        ingest_token = os.environ.get("CHEM_SHIELD_INGEST_TOKEN")
        if ingest_token:
            headers["X-Ingest-Token"] = ingest_token
        request = Request(
            url,
            data=json.dumps({"events": batch}, allow_nan=False).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        batch_error = None
        for attempt in range(retries + 1):
            status = None
            body = b""
            try:
                with _open_local(request, timeout) as response:
                    status = response.status
                    body = response.read()
            except HTTPError as exc:
                status = exc.code
                body = exc.read()
            except (URLError, TimeoutError, OSError) as exc:
                batch_error = f"batch {batch_number}: HMI request failed: {exc}"
                if attempt < retries:
                    time.sleep(backoff * (2**attempt))
                    continue
                break

            try:
                payload = _response_payload(body)
            except ValueError as exc:
                batch_error = f"batch {batch_number}: {exc}"
                break

            result["accepted"] += payload["accepted"]
            result["rejected"] += payload["rejected"]
            if status is not None and 200 <= status < 300:
                LOGGER.info(
                    "HMI accepted %d and rejected %d event(s) in batch %d",
                    payload["accepted"],
                    payload["rejected"],
                    batch_number,
                )
                batch_error = None
                break

            batch_error = f"batch {batch_number}: HMI returned HTTP {status}"
            if status is not None and (status == 429 or status >= 500) and attempt < retries:
                time.sleep(backoff * (2**attempt))
                continue
            break

        if batch_error:
            result["failed_batches"] += 1
            result["errors"].append(batch_error)
            LOGGER.warning("%s", batch_error)

    return result


__all__ = ["DEFAULT_HMI_URL", "publish_events"]
