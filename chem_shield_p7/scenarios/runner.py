"""Threaded scenario runner that only uses the loopback Attack Console API."""

from __future__ import annotations

import html
import json
import os
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from chem_shield_p7.notifier import queue_critical_message
from chem_shield_p7.scenarios.library import get_scenario
from chem_shield_p7.timeline.mitre_map import techniques_for
from chem_shield_p7.timeline.store import TimelineStore, utc_now

CONSOLE_URL = "http://127.0.0.1:5001"
HMI_URL = "http://127.0.0.1:15000"
TOKEN_PATTERN = re.compile(
    r'<meta\s+name=["\']console-token["\']\s+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class AttackConsoleClient:
    """Small HTTP client for the existing loopback-only simulation console."""

    def __init__(
        self,
        base_url: str = CONSOLE_URL,
        ingest_token: str | None = None,
        *,
        timeout: float = 3.0,
        opener: Any = None,
    ):
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "http"
            or parsed.hostname != "127.0.0.1"
            or parsed.port != 5001
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Scenario commands are restricted to the loopback OT Console.")
        token = ingest_token if ingest_token is not None else os.environ.get("CHEM_SHIELD_INGEST_TOKEN")
        if not token:
            raise ValueError("CHEM_SHIELD_INGEST_TOKEN is required for scenario commands.")
        self.base_url = base_url.rstrip("/")
        self.ingest_token = token
        self.timeout = timeout
        self.opener = opener or build_opener(_NoRedirect)
        self._csrf_token: str | None = None

    def _open(self, request: Request):
        try:
            return self.opener.open(request, timeout=self.timeout)
        except (HTTPError, URLError, TimeoutError, OSError) as error:
            raise RuntimeError(f"Loopback OT Console request failed: {error}") from error

    def _json_request(self, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        headers = {"Accept": "application/json"}
        body = None
        method = "GET"
        if payload is not None:
            if not self._csrf_token:
                self._load_csrf_token()
            headers.update({
                "Content-Type": "application/json",
                "X-Console-Token": self._csrf_token or "",
                "X-Ingest-Token": self.ingest_token,
            })
            body = json.dumps(payload, allow_nan=False).encode("utf-8")
            method = "POST"
        request = Request(
            f"{self.base_url}{path}",
            data=body,
            headers=headers,
            method=method,
        )
        with self._open(request) as response:
            result = json.loads(response.read().decode("utf-8"))
        if not isinstance(result, dict):
            raise RuntimeError("OT Console returned an invalid response.")
        return result

    def _load_csrf_token(self) -> None:
        request = Request(f"{self.base_url}/", headers={"Accept": "text/html"})
        with self._open(request) as response:
            page = response.read().decode("utf-8")
        match = TOKEN_PATTERN.search(page)
        if not match:
            raise RuntimeError("OT Console did not provide its request token.")
        self._csrf_token = html.unescape(match.group(1))

    def apply_step(self, sensor: str, value: float) -> dict[str, Any]:
        """Submit a validated sensor setpoint through the existing console."""
        if sensor not in {"temperature", "pressure", "power", "speed"}:
            raise ValueError("Unsupported scenario sensor.")
        return self._json_request(
            "/api/commands",
            {"parameter": sensor, "value": value},
        )

    def clear_overrides(self) -> dict[str, Any]:
        """Clear simulated sensor overrides through the existing console."""
        return self._json_request("/api/overrides/clear", {})

    def command_status(self) -> dict[str, Any]:
        """Read the existing command audit endpoint."""
        return self._json_request("/api/commands")


class HmiMonitorClient:
    """Read-only client for the loopback HMI state, risk, and event feeds."""

    def __init__(self, base_url: str = HMI_URL, *, timeout: float = 2.0):
        parsed = urlsplit(base_url)
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port != 15000:
            raise ValueError("Scenario monitoring is restricted to the loopback HMI.")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.opener = build_opener(_NoRedirect)

    def snapshot(self) -> dict[str, Any]:
        """Read machine state, canonical risk state, and the existing event feed."""
        result = {}
        for name in ("state", "risk", "events"):
            request = Request(f"{self.base_url}/api/{name}", headers={"Accept": "application/json"})
            try:
                with self.opener.open(request, timeout=self.timeout) as response:
                    result[name] = json.loads(response.read().decode("utf-8"))
            except (HTTPError, URLError, TimeoutError, OSError, ValueError) as error:
                raise RuntimeError(f"Loopback HMI {name} feed is unavailable: {error}") from error
        return result


class ScenarioRunner:
    """Run one validated sensor scenario at a time and always clear overrides."""

    def __init__(
        self,
        store: TimelineStore,
        *,
        admin_database: str,
        report_dir: str,
        console: Any = None,
        monitor: Any = None,
        audit: Callable[..., None] | None = None,
        outbox_path: str | None = None,
        poll_interval: float = 0.5,
        outcome_timeout: float | None = None,
    ):
        self.store = store
        self.admin_database = admin_database
        self.report_dir = report_dir
        self.console = console
        self.monitor = monitor
        self.monitor_enabled = monitor is not False
        self.audit = audit
        self.outbox_path = outbox_path
        self.poll_interval = max(0.05, poll_interval)
        self.outcome_timeout = outcome_timeout
        self._lock = threading.RLock()
        self._abort_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._run_id: str | None = None
        self._status: dict[str, Any] = {"running": False, "run_id": None, "scenario_id": None}
        self._detected = False
        self._notification_sent = False
        self._seen_hmi_event_ids: set[str] = set()

    def _console_client(self) -> Any:
        if self.console is not None:
            return self.console
        return AttackConsoleClient()

    def _monitor_client(self) -> Any:
        if self.monitor is not None:
            return self.monitor
        return HmiMonitorClient()

    def _record(
        self,
        run_id: str,
        event_type: str,
        *,
        source: str,
        detail: dict[str, Any] | None = None,
        detector: str = "",
        mitre: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        event = self.store.append_event(
            run_id,
            event_type,
            source=source,
            detail=detail,
            detector=detector,
            mitre=mitre,
        )
        if self.audit:
            self.audit(
                username="scenario-engine",
                role="system",
                source_ip="127.0.0.1",
                action=f"p7_{event_type.casefold()}",
                incident_id=None,
                detail=json.dumps(event, ensure_ascii=True, sort_keys=True),
            )
        return event

    def start(self, scenario_id: str) -> str:
        """Start a known scenario unless another run is still active."""
        scenario = get_scenario(scenario_id)
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                raise RuntimeError("A scenario is already running.")
            run_id = uuid.uuid4().hex
            started = utc_now()
            self.store.create_run(run_id, scenario_id, scenario["name"], started)
            self._abort_event = threading.Event()
            self._run_id = run_id
            self._detected = False
            self._notification_sent = False
            self._seen_hmi_event_ids.clear()
            self._status = {
                "running": True,
                "run_id": run_id,
                "scenario_id": scenario_id,
                "scenario_name": scenario["name"],
                "started_at": started,
                "status": "RUNNING",
                "error": None,
            }
            self._thread = threading.Thread(
                target=self._run,
                args=(run_id, scenario),
                name=f"chem-shield-p7-{scenario_id}",
                daemon=True,
            )
            self._thread.start()
            return run_id

    def abort(self) -> bool:
        """Request cooperative abort; the worker clears all simulation overrides."""
        with self._lock:
            if not self._thread or not self._thread.is_alive():
                return False
            self._abort_event.set()
            self._status["status"] = "ABORTING"
            return True

    def status(self) -> dict[str, Any]:
        """Return a thread-safe status snapshot."""
        with self._lock:
            return dict(self._status)

    def _pause_until(self, deadline: float, run_id: str) -> None:
        if self._abort_event.is_set():
            raise InterruptedError("Scenario aborted by operator.")
        while time.monotonic() < deadline:
            if self._abort_event.is_set():
                raise InterruptedError("Scenario aborted by operator.")
            self._observe(run_id)
            self._abort_event.wait(min(self.poll_interval, max(0.0, deadline - time.monotonic())))

    def _wait_command(self, console: Any, command_id: str | None) -> None:
        if not command_id:
            return
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline and not self._abort_event.is_set():
            payload = console.command_status()
            commands = payload.get("commands", [])
            command = next(
                (item for item in commands if isinstance(item, dict) and item.get("id") == command_id),
                None,
            )
            if command and command.get("status") != "accepted":
                return
            self._abort_event.wait(self.poll_interval)
        if not self._abort_event.is_set():
            raise TimeoutError("The OT Console did not confirm the simulated setpoint.")

    def _observe(self, run_id: str) -> dict[str, Any] | None:
        if not self.monitor_enabled:
            return None
        snapshot = self._monitor_client().snapshot()
        state = snapshot.get("state", {})
        risk = snapshot.get("risk", {})
        event_feed = snapshot.get("events", [])
        if isinstance(state, dict):
            self.store.record_readings(run_id, state)
        active = risk.get("active_incidents", []) if isinstance(risk, dict) else []
        candidates = risk.get("popup_candidates", []) if isinstance(risk, dict) else []
        alerts = state.get("limit_alerts", []) if isinstance(state, dict) else []
        critical = (
            isinstance(state, dict) and state.get("machine_condition") == "CRITICAL"
        ) or bool(alerts) or any(
            isinstance(item, dict) and item.get("risk_level") in {"HIGH", "CRITICAL"}
            for item in candidates
        )
        if critical and not self._detected:
            self._detected = True
            detected_at = utc_now()
            self.store.update_run(run_id, detected_at=detected_at)
            incident = next(
                (
                    item for item in active
                    if isinstance(item, dict) and item.get("risk_level") in {"HIGH", "CRITICAL"}
                ),
                {},
            )
            source = "Part 4 risk API" if incident else "Part 1 live limit rule"
            sensor = "machine reading"
            value: Any = None
            unit = ""
            if alerts:
                first = alerts[0]
                sensor = str(first.get("sensor", "machine reading"))
                value = first.get("value")
                unit = str(first.get("unit", ""))
            self._record(
                run_id,
                "DETECTED",
                source=source,
                detector=str(
                    (incident.get("risk_assessment") or {}).get("detection_method", source)
                ),
                detail={"incident_id": incident.get("incident_id"), "sensor": sensor, "value": value},
                mitre=techniques_for(self._status.get("scenario_id", "")),
            )
            self._record(
                run_id,
                "WARNING_SHOWN",
                source="HMI",
                detail={"risk_level": incident.get("risk_level", "CRITICAL")},
            )
            if not self._notification_sent and self.outbox_path:
                seconds = max(0, int(os.environ.get("CHEM_SHIELD_AUTO_STOP_SECONDS", "900")))
                countdown_text = f"{seconds // 60:02d}:{seconds % 60:02d}"
                message = queue_critical_message(
                    self.outbox_path,
                    sensor=sensor,
                    value=float(value) if isinstance(value, (int, float)) else 0.0,
                    unit=unit,
                    countdown=countdown_text,
                )
                self._record(
                    run_id,
                    "NOTIFICATION_QUEUED",
                    source="local mock notifier",
                    detail={"message": message},
                )
                self._notification_sent = True

        countdown = risk.get("auto_stop_at") if isinstance(risk, dict) else None
        if countdown and not self._has_event(run_id, "COUNTDOWN_STARTED"):
            self._record(
                run_id,
                "COUNTDOWN_STARTED",
                source="Part 6 guarded auto-stop",
                detail={"auto_stop_at": countdown},
            )
        if isinstance(event_feed, list):
            for event in event_feed:
                if not isinstance(event, dict) or event.get("event_type") != "P6_AUTO_CANCELLED":
                    continue
                event_id = str(event.get("id") or event.get("timestamp") or "")
                if event_id and event_id in self._seen_hmi_event_ids:
                    continue
                if event_id:
                    self._seen_hmi_event_ids.add(event_id)
                self._record(
                    run_id,
                    "COUNTDOWN_CANCELLED",
                    source="Part 6 event feed",
                    detail={
                        "reason": event.get("new_value"),
                        "event_timestamp": event.get("timestamp"),
                    },
                )
        for incident in active:
            if not isinstance(incident, dict):
                continue
            if incident.get("acknowledged_at") and not self._has_event(run_id, "OPERATOR_RESPONDED"):
                responded_at = str(incident["acknowledged_at"])
                self.store.update_run(run_id, responded_at=responded_at)
                self._record(
                    run_id,
                    "OPERATOR_RESPONDED",
                    source="HMI acknowledgement",
                    detail={"incident_id": incident.get("incident_id")},
                )
        recent = risk.get("recent_incidents", []) if isinstance(risk, dict) else []
        automatically_stopped = next(
            (
                item for item in recent
                if isinstance(item, dict)
                and item.get("resolved_reason") == "automatic simulated stop"
            ),
            None,
        )
        if automatically_stopped and not self._has_event(run_id, "AUTO_STOP"):
            self.store.update_run(run_id, automatic_stop=1)
            self._record(
                run_id,
                "AUTO_STOP",
                source="Part 6 guarded auto-stop",
                detail={"incident_id": automatically_stopped.get("incident_id")},
            )
        return snapshot

    def _has_event(self, run_id: str, event_type: str) -> bool:
        run = self.store.get_run(run_id)
        return bool(run and any(event["event_type"] == event_type for event in run["events"]))

    def _wait_for_outcome(self, run_id: str) -> str:
        timeout = self.outcome_timeout
        if timeout is None:
            try:
                timeout = float(os.environ.get("CHEM_SHIELD_AUTO_STOP_SECONDS", "900")) + 70.0
            except ValueError:
                timeout = 970.0
        deadline = time.monotonic() + max(1.0, timeout)
        while time.monotonic() < deadline:
            if self._abort_event.is_set():
                raise InterruptedError("Scenario aborted by operator.")
            self._observe(run_id)
            if self._has_event(run_id, "AUTO_STOP"):
                return "AUTO_STOP"
            if self._has_event(run_id, "OPERATOR_RESPONDED"):
                return "OPERATOR_RESPONDED"
            self._abort_event.wait(self.poll_interval)
        raise TimeoutError("No operator response or automatic stop was observed before timeout.")

    def _run(self, run_id: str, scenario: dict[str, Any]) -> None:
        started_monotonic = time.monotonic()
        outcome = "COMPLETED"
        status = "COMPLETED"
        error_message = None
        persistence_errors: list[str] = []
        console = None
        try:
            console = self._console_client()
            self._record(
                run_id,
                "SCENARIO_STARTED",
                source="Part 7 scenario engine",
                detail={"scenario_id": scenario["id"], "scenario_name": scenario["name"]},
                mitre=techniques_for(scenario["id"]),
            )
            for step in scenario["steps"]:
                self._pause_until(started_monotonic + step["t_seconds"], run_id)
                result = console.apply_step(step["sensor"], step["value"])
                self._record(
                    run_id,
                    "ABNORMAL_READING",
                    source="Attack Console simulated sensor override",
                    detail={
                        "sensor": step["sensor"],
                        "value": step["value"],
                        "t_seconds": step["t_seconds"],
                        "command_id": result.get("id"),
                    },
                    mitre=techniques_for(scenario["id"]),
                )
                self._wait_command(console, result.get("id"))
                self._observe(run_id)
                if self._abort_event.is_set():
                    raise InterruptedError("Scenario aborted by operator.")
                if self._has_event(run_id, "OPERATOR_RESPONDED"):
                    break
            if self._detected:
                outcome = self._wait_for_outcome(run_id)
            elif scenario["id"] == "stealthy-in-range-drift":
                outcome = "COMPLETED; Part 3 detection depends on the configured model"
        except InterruptedError as error:
            outcome = "ABORTED"
            status = "ABORTED"
            error_message = str(error)
            try:
                self._record(run_id, "ABORTED", source="operator", detail={"message": error_message})
            except Exception as record_error:
                persistence_errors.append(f"ABORTED event: {type(record_error).__name__}: {record_error}")
        except Exception as error:
            outcome = "FAILED"
            status = "FAILED"
            error_message = f"{type(error).__name__}: {error}"
            try:
                self._record(
                    run_id,
                    "RUN_FAILED",
                    source="scenario engine",
                    detail={"message": error_message},
                )
            except Exception as record_error:
                persistence_errors.append(
                    f"RUN_FAILED event: {type(record_error).__name__}: {record_error}"
                )
        finally:
            clear_error = None
            if console is not None:
                try:
                    console.clear_overrides()
                except Exception as error:
                    clear_error = f"{type(error).__name__}: {error}"
                    outcome = "FAILED to clear overrides: " + clear_error
                    status = "FAILED"

            final_events = (
                [("OVERRIDE_CLEAR_FAILED", "Attack Console", {"message": clear_error})]
                if clear_error
                else [
                    (
                        "OVERRIDES_CLEARED",
                        "Attack Console",
                        {"message": "All simulated sensor overrides cleared."},
                    ),
                    ("RESOLVED", "Part 7 scenario engine", {"outcome": outcome}),
                ]
            )
            for event_type, source, detail in final_events:
                try:
                    self._record(run_id, event_type, source=source, detail=detail)
                except Exception as error:
                    persistence_errors.append(
                        f"{event_type} event: {type(error).__name__}: {error}"
                    )

            if persistence_errors:
                status = "FAILED"
                outcome = "FAILED to persist scenario history: " + "; ".join(persistence_errors)
            ended = utc_now()
            try:
                self.store.update_run(run_id, status=status, ended_at=ended, outcome=outcome)
            except Exception as error:
                status = "FAILED"
                outcome = f"FAILED to update scenario status: {type(error).__name__}: {error}"
                persistence_errors.append(outcome)
            with self._lock:
                self._status.update({
                    "running": False,
                    "status": status,
                    "outcome": outcome,
                    "error": error_message or clear_error or (
                        "; ".join(persistence_errors) if persistence_errors else None
                    ),
                    "ended_at": ended,
                })
