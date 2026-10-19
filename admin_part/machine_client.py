"""Read-only client for the loopback machine HMI APIs."""

from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


DEFAULT_HMI_URL = "http://127.0.0.1:15000"
ALLOWED_ENDPOINTS = {
    "state": "/api/state",
    "connection": "/api/connection",
    "telemetry": "/api/telemetry",
    "risk": "/api/risk",
    "incidents": "/api/incidents",
}
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}
LOGGER = logging.getLogger(__name__)


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def open_hmi_url(request: Request, timeout: float):
    return build_opener(_NoRedirectHandler()).open(request, timeout=timeout)


def validate_hmi_url(value: str | None) -> str:
    if value:
        try:
            parsed = urlsplit(value.strip())
            host = (parsed.hostname or "").lower()
            if (
                parsed.scheme in {"http", "https"}
                and parsed.netloc
                and host in ALLOWED_HOSTS
                and not parsed.username
                and not parsed.password
                and not parsed.query
                and not parsed.fragment
            ):
                return value.strip().rstrip("/")
        except ValueError:
            pass
        LOGGER.warning("Invalid CHEM_SHIELD_HMI_URL; using %s", DEFAULT_HMI_URL)
    return DEFAULT_HMI_URL


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class MachineClient:
    """Fetch allowlisted HMI JSON endpoints without issuing control commands."""

    def __init__(self, base_url: str | None = None, timeout: float = 2.0) -> None:
        self.base_url = validate_hmi_url(base_url)
        self.timeout = timeout

    def get(self, name: str) -> dict[str, Any]:
        endpoint = ALLOWED_ENDPOINTS.get(name)
        if endpoint is None:
            return {
                "ok": False,
                "data": None,
                "error": "Unsupported read-only machine endpoint",
                "fetched_at": _now(),
            }
        try:
            request = Request(
                f"{self.base_url}{endpoint}",
                headers={"Accept": "application/json"},
                method="GET",
            )
            with open_hmi_url(request, timeout=self.timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
            return {"ok": True, "data": data, "error": None, "fetched_at": _now()}
        except Exception as error:
            LOGGER.warning("Machine HMI GET %s failed: %s", endpoint, error)
            return {
                "ok": False,
                "data": None,
                "error": str(error),
                "fetched_at": _now(),
            }

    def live(self) -> dict[str, Any]:
        names = ("state", "connection", "risk", "telemetry")
        with ThreadPoolExecutor(max_workers=len(names)) as executor:
            pending = {name: executor.submit(self.get, name) for name in names}
            results = {name: future.result() for name, future in pending.items()}
        state = results["state"]
        connection = results["connection"]
        risk = results["risk"]
        telemetry = results["telemetry"]
        return {
            "ok": all(results[name]["ok"] for name in names),
            "state": state,
            "connection": connection,
            "risk": risk,
            "telemetry": telemetry,
            "fetched_at": telemetry["fetched_at"],
        }
