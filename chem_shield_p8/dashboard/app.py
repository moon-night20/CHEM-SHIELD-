"""Loopback dashboard API for the entirely local Part 8 simulator."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    render_template,
    request,
    send_from_directory,
    stream_with_context,
    url_for,
)
from flask_wtf.csrf import CSRFProtect

from chem_shield_p4.correlation.correlation_engine import CorrelationEngine
from chem_shield_p4.risk_engine.risk_engine import RiskEngine
from chem_shield_p8.attack_lab import ReplayRunner, ReplaySession
from chem_shield_p8.attack_lab.replay import BASE_SIS_STATE
from chem_shield_p8.physics_guard import PhysicsGuard, PhysicalAnomalyModel
from chem_shield_p8.plant_twin.model import Controls, ReactorTwin, load_config
from chem_shield_p8.plant_twin.plc import SimulatedPLC
from chem_shield_p8.response import ResponseManager
from chem_shield_p8.reports import generate_incident_report
from chem_shield_p8.sis_watch import SISWatch, create_baseline, load_or_create_key
from chem_shield_p8.zones import ZonePolicy, compute_compliance

LOGGER = logging.getLogger(__name__)
P8_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA_DIR = P8_ROOT / "data"
DEFAULT_HMI_URL = "http://127.0.0.1:15000"
DEFAULT_ADMIN_URL = "http://127.0.0.1:5000"
DEFAULT_ATTACK_CONSOLE_URL = "http://127.0.0.1:5001"
SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _safe_hmi_url(value: str | None) -> str:
    """Accept only the existing project's local HMI origin."""
    candidate = value or DEFAULT_HMI_URL
    parsed = urlsplit(candidate)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.port != 15000
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("P8 can connect only to the existing HMI at http://127.0.0.1:15000.")
    return "http://127.0.0.1:15000"


def _safe_local_page_url(value: str | None, *, name: str, default: str) -> str:
    """Allow navigation only to a bare HTTP page on the local loopback host."""
    candidate = value or default
    parsed = urlsplit(candidate)
    try:
        valid_port = parsed.port is not None and 1 <= parsed.port <= 65535
    except ValueError:
        valid_port = False
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or not valid_port
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError(f"P8 {name} link must be a local HTTP page on 127.0.0.1.")
    return f"http://127.0.0.1:{parsed.port}/"


class HMIReadOnlyClient:
    """Read existing HMI state/risk endpoints; never send control requests."""

    def __init__(self, base_url: str = DEFAULT_HMI_URL, timeout: float = 0.4) -> None:
        self.base_url = _safe_hmi_url(base_url)
        self.timeout = timeout

    def snapshot(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "connected": False,
            "state": None,
            "risk": None,
            "state_error": None,
            "risk_error": None,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            result["state"] = self._get("/api/state")
            result["connected"] = True
        except (HTTPError, URLError, TimeoutError, OSError, ValueError) as error:
            result["state_error"] = f"{type(error).__name__}: {error}"
            LOGGER.info("Existing HMI state feed unavailable: %s", error)
        try:
            result["risk"] = self._get("/api/risk")
        except (HTTPError, URLError, TimeoutError, OSError, ValueError) as error:
            result["risk_error"] = f"{type(error).__name__}: {error}"
            LOGGER.info("Existing HMI risk feed unavailable: %s", error)
        return result

    def _get(self, path: str) -> dict[str, Any]:
        request_obj = Request(
            self.base_url + path,
            headers={"Accept": "application/json"},
            method="GET",
        )
        with urlopen(request_obj, timeout=self.timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"Existing HMI returned invalid JSON at {path}.")
        return payload


class DashboardRuntime:
    """Own the P8 twin and combine local detector, policy, response, and replay state."""

    def __init__(
        self,
        *,
        data_dir: str | Path = DEFAULT_DATA_DIR,
        hmi_url: str = DEFAULT_HMI_URL,
        read_existing_hmi: bool = True,
    ) -> None:
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.plant_config = load_config()
        self.twin = ReactorTwin(config=self.plant_config)
        self.plc = SimulatedPLC(self.plant_config)
        self.policy = ZonePolicy.load()
        self.guard = PhysicsGuard(
            plant_config=self.plant_config,
            ml_model=PhysicalAnomalyModel.fit_simulated_normal(self.plant_config),
        )
        self.replay_runner = ReplayRunner()
        self.response_manager = ResponseManager(
            policy=self.policy,
            log_path=self.data_dir / "response-decisions.jsonl",
        )
        self._initialize_sis_watch()
        self._last_sis = self.sis_watch.check(BASE_SIS_STATE)
        self.hmi = HMIReadOnlyClient(hmi_url) if read_existing_hmi else None
        self._lock = threading.RLock()
        self._last_physics = self.guard.analyze(self.twin.state, 1.0)
        self._session: ReplaySession | None = None
        self._playing = False
        self._simulation_running = True
        self._latest_alerts: list[dict[str, Any]] = []
        self._timeline: list[dict[str, Any]] = []
        self._last_hmi: dict[str, Any] = {
            "connected": False,
            "state": None,
            "risk": None,
            "error": "Not configured.",
        }
        self._last_step_at: datetime | None = None
        self._controls = {
            "coolant_valve_pct": 40.0,
            "feed_pump_on": True,
            "relief_valve_open": None,
        }
        self.response_manager.state.controls = dict(self._controls)

    def _initialize_sis_watch(self) -> None:
        key_path = self.data_dir / "sis-signing.key"
        baseline_path = self.data_dir / "sis-baseline.json"
        key = load_or_create_key(key_path)
        if not baseline_path.exists():
            create_baseline(baseline_path, BASE_SIS_STATE, key)
        self.sis_watch = SISWatch.from_file(
            baseline_path,
            key,
            self.data_dir / "sis-decisions.jsonl",
        )

    def advance(self, dt_seconds: float = 1.0) -> dict[str, Any]:
        """Advance the enabled local twin and one step of synthetic replay."""
        with self._lock:
            controls_data = self.response_manager.state.controls
            if controls_data != self._controls:
                self._controls = dict(controls_data)
            if self._simulation_running:
                controls = Controls(
                    coolant_valve_pct=float(self._controls["coolant_valve_pct"]),
                    feed_pump_on=bool(self._controls["feed_pump_on"]),
                    relief_valve_open=self._controls["relief_valve_open"],
                )
                state = self.twin.step(dt_seconds, controls)
                self.plc.publish_state(state)
                self._last_physics = self.guard.analyze(state, dt_seconds)
            self._advance_replay()
            if self.hmi is not None:
                self._last_hmi = self.hmi.snapshot()
            self._last_step_at = datetime.now(timezone.utc)
            return self.snapshot()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            state = self.twin.state.as_dict()
            decision_records = self.response_manager.list_decisions()
            scenario_result = self._session.result() if self._session is not None else None
            compliance = compute_compliance(
                self.policy,
                self._session.events() if self._session is not None else (),
            ) if self._session is not None else compute_compliance(self.policy)
            severities = [
                str(alert.get("severity", "INFO"))
                for alert in self._latest_alerts
            ]
            threat = max(severities, key=lambda item: SEVERITY_RANK.get(item, 0)) if severities else "NORMAL"
            backend = self._backend_analysis()
            return {
                "timestamp": (self._last_step_at or datetime.now(timezone.utc)).isoformat(),
                "plant": state,
                "trip_alarms": self.twin.trip_alarms(),
                "plc": {
                    "holding_registers": self.plc.read_holding_registers(0, self.plc.HOLDING_COUNT),
                    "input_registers": self.plc.read_input_registers(0, self.plc.INPUT_COUNT),
                    "coils": self.plc.read_coils(0, self.plc.COIL_COUNT),
                },
                "physics_guard": self._last_physics.as_dict(),
                "threat_level": threat,
                "alerts": list(self._latest_alerts),
                "timeline": list(self._timeline[-100:]),
                "assets": self._session.assets() if self._session is not None else [],
                "zones": [
                    {"id": zone.zone_id, "name": zone.name, "level": zone.level}
                    for zone in self.policy.zones
                ],
                "compliance": compliance.as_dict(),
                "scenario": {
                    "playing": self._playing,
                    "complete": self._session.complete if self._session is not None else True,
                    "current_step": self._session.current_step if self._session is not None else 0,
                    "result": scenario_result.as_dict() if scenario_result else None,
                },
                "scenarios": [
                    {
                        "id": item["id"],
                        "name": item["name"],
                        "description": item["description"],
                        "techniques": item["techniques"],
                    }
                    for item in self.replay_runner.scenarios
                ],
                "response": {
                    "playbooks": [
                        {
                            "id": playbook.playbook_id,
                            "name": playbook.name,
                            "description": playbook.description,
                        }
                        for playbook in self.response_manager.playbooks.values()
                    ],
                    "decisions": [decision.as_dict() for decision in decision_records],
                    "state": {
                        "isolated_zones": sorted(self.response_manager.state.isolated_zones),
                        "blocked_conduits": sorted(self.response_manager.state.blocked_conduits),
                        "controls": dict(self._controls),
                        "notifications": list(self.response_manager.state.notifications),
                    },
                    "log_integrity": self.response_manager.verify_log(),
                },
                "simulation": {
                    "running": self._simulation_running,
                    "controls": dict(self.response_manager.state.controls),
                },
                "backend": backend,
                "sis": {
                    "chain_integrity": self.sis_watch.chain.verify(),
                    "latest": self._last_sis.as_dict(),
                },
                "existing_chem_shield": self._last_hmi,
            }

    def _backend_analysis(self) -> dict[str, Any]:
        """Summarize real P8 stage outputs and run P4 correlation/risk in memory."""
        result = self._session.result() if self._session is not None else None
        alerts = result.alerts if result is not None else []
        timeline = result.timeline if result is not None else []
        network_events = self._session.events() if self._session is not None else []
        zone_decisions = [
            entry.detail.get("zone_decision")
            for entry in timeline
            if entry.event_type == "SYNTHETIC_OT_EVENT"
        ]
        protocols = sorted({event.protocol for event in network_events})
        network_alerts = []
        physical_alerts = []
        network_rules = {
            "UNKNOWN_ASSET",
            "ILLEGAL_FUNCTION_CODE",
            "UNAUTHORIZED_WRITE",
            "SETPOINT_OUT_OF_RANGE",
            "DUPLICATE_PACKET_REPLAY",
            "UNKNOWN_ZONE_FLOW",
            "DIRECT_IT_TO_CONTROL",
            "MISSING_CONDUIT",
            "PROTOCOL_NOT_ALLOWED",
            "ENDPOINT_NOT_ALLOWED",
        }
        severity_scores = {"INFO": 0.1, "LOW": 0.25, "MEDIUM": 0.5, "HIGH": 0.75, "CRITICAL": 1.0}
        for index, alert in enumerate(alerts):
            matching_event = next(
                (event for event in network_events if event.timestamp == alert.timestamp),
                None,
            )
            asset_id = matching_event.device_id if matching_event is not None else (
                "SIS-01" if alert.rule_id == "SIS_BASELINE_CHANGE" else "P8-REACTOR-TWIN"
            )
            event = {
                "timestamp": alert.timestamp.isoformat(),
                "asset_id": asset_id,
                "event_type": "network" if alert.rule_id in network_rules else "physical",
                "anomaly_score": severity_scores.get(alert.severity, 0.0),
                "event_id": f"p8-{self._session.scenario['id']}-{index}" if self._session else f"p8-alert-{index}",
                "source": "P8 OT monitor" if alert.rule_id in network_rules else "P8 safety/process monitor",
                "severity": alert.severity,
                "evidence": {"rule_id": alert.rule_id, **alert.evidence},
            }
            (network_alerts if event["event_type"] == "network" else physical_alerts).append(event)

        physics = self._last_physics.as_dict()
        if physics["findings"] or physics["ml_score"] >= 0.5:
            physical_alerts.append({
                "timestamp": (self._last_step_at or datetime.now(timezone.utc)).isoformat(),
                "asset_id": "P8-REACTOR-TWIN",
                "event_type": "physical",
                "anomaly_score": max(physics["physics_score"], physics["ml_score"]),
                "event_id": "p8-reactor-twin-current-sample",
                "source": "P8 physics guard / ML",
                "severity": "HIGH" if physics["physics_score"] >= 0.5 else "MEDIUM",
                "evidence": {
                    "physics_score": physics["physics_score"],
                    "ml_score": physics["ml_score"],
                    "findings": physics["findings"],
                },
            })

        correlated, validation_errors = CorrelationEngine().correlate(
            network_alerts + physical_alerts
        )
        risk_engine = RiskEngine()
        incidents = []
        for incident in correlated:
            details = incident.to_dict()
            risk = risk_engine.calculate_risk(details).to_dict()
            incidents.append({
                **details,
                "risk": risk,
                "events": [
                    {
                        "event_type": event.event_type,
                        "source": event.source,
                        "severity": event.severity,
                        "anomaly_score": event.anomaly_score,
                        "timestamp": event.timestamp.isoformat(),
                    }
                    for event in incident.events
                ],
            })
        return {
            "network": {
                "event_count": len(network_events),
                "protocols": protocols,
                "write_count": sum(event.operation == "write" for event in network_events),
                "alert_count": len(network_alerts),
            },
            "ot": {
                "event_count": len(network_events),
                "asset_count": len(self._session.assets()) if self._session is not None else 0,
                "allowed_flows": sum(decision in {"SAME_ZONE_PROTOCOL", "CONDUIT_ALLOWED"} for decision in zone_decisions),
                "blocked_flows": sum(decision not in {None, "SAME_ZONE_PROTOCOL", "CONDUIT_ALLOWED"} for decision in zone_decisions),
            },
            "ai_ml": {
                "physics_score": physics["physics_score"],
                "ml_score": physics["ml_score"],
                "finding_count": len(physics["findings"]),
                "model_enabled": self.guard.ml_enabled,
            },
            "correlation": {
                "window_seconds": CorrelationEngine().time_window_seconds,
                "incident_count": len(incidents),
                "dual_signal_count": sum(
                    incident["network_present"] and incident["physical_present"]
                    for incident in incidents
                ),
                "validation_error_count": len(validation_errors),
                "incidents": incidents,
            },
            "alerts": {
                "count": len(alerts),
                "critical_count": sum(alert.severity == "CRITICAL" for alert in alerts),
                "high_count": sum(alert.severity == "HIGH" for alert in alerts),
                "rules": sorted({alert.rule_id for alert in alerts}),
            },
            "sis": {
                "integrity_ok": self.sis_watch.chain.verify()["ok"],
                "status": self._last_sis.status,
            },
        }

    def set_simulation_running(self, running: bool) -> dict[str, Any]:
        """Pause or resume only the local reactor-twin process model."""
        if not isinstance(running, bool):
            raise ValueError("running must be a boolean.")
        with self._lock:
            self._simulation_running = running
            return self.snapshot()

    def set_twin_controls(
        self,
        *,
        coolant_valve_pct: float | None = None,
        feed_pump_on: bool | None = None,
    ) -> dict[str, Any]:
        """Set bounded actuators for the local twin without contacting the HMI."""
        if coolant_valve_pct is None and feed_pump_on is None:
            raise ValueError("At least one local twin control is required.")
        if coolant_valve_pct is not None and (
            isinstance(coolant_valve_pct, bool)
            or not isinstance(coolant_valve_pct, (int, float))
            or not 0.0 <= coolant_valve_pct <= 100.0
        ):
            raise ValueError("coolant_valve_pct must be a finite number between 0 and 100.")
        if feed_pump_on is not None and not isinstance(feed_pump_on, bool):
            raise ValueError("feed_pump_on must be a boolean.")
        with self._lock:
            controls = dict(self.response_manager.state.controls)
            if coolant_valve_pct is not None:
                controls["coolant_valve_pct"] = float(coolant_valve_pct)
            if feed_pump_on is not None:
                controls["feed_pump_on"] = feed_pump_on
            self.response_manager.state.controls = controls
            self._controls = dict(controls)
            return self.snapshot()

    def start_scenario(self, scenario_id: str) -> dict[str, Any]:
        with self._lock:
            self._session = self.replay_runner.start(scenario_id)
            self._playing = True
            self._latest_alerts = []
            self._timeline = []
            return self.snapshot()

    def set_playing(self, playing: bool) -> dict[str, Any]:
        with self._lock:
            if self._session is None or self._session.complete:
                raise ValueError("Start a scenario before changing playback.")
            self._playing = bool(playing)
            return self.snapshot()

    def step_scenario(self) -> dict[str, Any]:
        with self._lock:
            if self._session is None or self._session.complete:
                raise ValueError("There is no step available; start another scenario.")
            self._run_scenario_step()
            if self._session.complete:
                self._playing = False
            return self.snapshot()

    def _advance_replay(self) -> None:
        if self._session is not None and self._playing and not self._session.complete:
            self._run_scenario_step()
        if self._session is not None and self._session.complete:
            self._playing = False

    def _run_scenario_step(self) -> None:
        if self._session is None:
            return
        update = self._session.step()
        for alert in update["alerts"]:
            self._latest_alerts.insert(0, alert)
        result = self._session.result()
        self._timeline = [
            event.as_dict()
            for event in result.timeline
        ]


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    """Create the standalone Part 8 app; never bind or proxy beyond loopback."""
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.config.update(
        SECRET_KEY=os.environ.get("CHEM_SHIELD_P8_SECRET_KEY") or secrets.token_hex(32),
        WTF_CSRF_ENABLED=True,
        WTF_CSRF_TIME_LIMIT=3600,
        P8_DATA_DIR=DEFAULT_DATA_DIR,
        P8_HMI_URL=os.environ.get("CHEM_SHIELD_P8_HMI_URL", DEFAULT_HMI_URL),
        P8_READ_EXISTING_HMI=True,
        P8_ADMIN_URL=os.environ.get("CHEM_SHIELD_P8_ADMIN_URL", DEFAULT_ADMIN_URL),
        P8_ATTACK_CONSOLE_URL=os.environ.get(
            "CHEM_SHIELD_P8_ATTACK_CONSOLE_URL",
            DEFAULT_ATTACK_CONSOLE_URL,
        ),
    )
    if test_config:
        app.config.update(test_config)
    try:
        app.config["P8_HMI_URL"] = _safe_hmi_url(app.config["P8_HMI_URL"])
    except ValueError as error:
        raise ValueError(f"Unsafe P8 HMI integration setting: {error}") from error
    for setting, name, default in (
        ("P8_ADMIN_URL", "admin-console", DEFAULT_ADMIN_URL),
        ("P8_ATTACK_CONSOLE_URL", "attack-console", DEFAULT_ATTACK_CONSOLE_URL),
    ):
        try:
            app.config[setting] = _safe_local_page_url(
                app.config[setting],
                name=name,
                default=default,
            )
        except ValueError as error:
            raise ValueError(f"Unsafe P8 {name} link setting: {error}") from error
    csrf = CSRFProtect()
    csrf.init_app(app)
    runtime = app.config.get("P8_RUNTIME")
    if runtime is None:
        runtime = DashboardRuntime(
            data_dir=app.config["P8_DATA_DIR"],
            hmi_url=app.config["P8_HMI_URL"],
            read_existing_hmi=app.config["P8_READ_EXISTING_HMI"],
        )
    app.extensions["p8_runtime"] = runtime

    @app.before_request
    def require_loopback():
        address = request.remote_addr
        try:
            allowed = address is not None and ipaddress.ip_address(address).is_loopback
        except ValueError:
            allowed = False
        if not allowed:
            return jsonify({"error": "Part 8 dashboard is available only on loopback."}), 403
        return None

    @app.after_request
    def security_headers(response: Response) -> Response:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; base-uri 'self'; form-action 'self'; "
            "frame-ancestors 'none'; object-src 'none'; style-src 'self'; "
            "script-src 'self'; img-src 'self'; connect-src 'self'"
        )
        return response

    @app.get("/")
    def dashboard():
        return render_template(
            "index.html",
            admin_url=f"{app.config['P8_ADMIN_URL']}dashboard",
            attack_console_url=app.config["P8_ATTACK_CONSOLE_URL"],
        )

    @app.get("/api/snapshot")
    def snapshot_api():
        return jsonify(runtime.snapshot())

    @app.get("/api/stream")
    def event_stream():
        @stream_with_context
        def generate():
            while True:
                snapshot = runtime.advance(1.0)
                yield "data: " + json.dumps(snapshot, allow_nan=False) + "\n\n"
                time.sleep(1.0)

        return Response(
            generate(),
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.post("/api/twin/playback")
    def twin_playback():
        payload = request.get_json()
        if not isinstance(payload, dict) or set(payload) != {"running"}:
            return jsonify({"error": "A boolean running value is required."}), 400
        if not isinstance(payload["running"], bool):
            return jsonify({"error": "running must be a boolean."}), 400
        return jsonify(runtime.set_simulation_running(payload["running"]))

    @app.post("/api/twin/controls")
    def twin_controls():
        payload = request.get_json()
        allowed = {"coolant_valve_pct", "feed_pump_on"}
        if (
            not isinstance(payload, dict)
            or not payload
            or set(payload) - allowed
        ):
            return jsonify({"error": "Provide coolant_valve_pct and/or feed_pump_on only."}), 400
        try:
            return jsonify(runtime.set_twin_controls(**payload))
        except (TypeError, ValueError) as error:
            return jsonify({"error": str(error)}), 400

    @app.post("/api/scenarios/start")
    def start_scenario():
        payload = request.get_json()
        if not isinstance(payload, dict) or not isinstance(payload.get("scenario_id"), str):
            return jsonify({"error": "scenario_id is required."}), 400
        try:
            return jsonify(runtime.start_scenario(payload["scenario_id"]))
        except ValueError as error:
            return jsonify({"error": str(error)}), 400

    @app.post("/api/scenarios/playback")
    def scenario_playback():
        payload = request.get_json()
        if not isinstance(payload, dict) or not isinstance(payload.get("playing"), bool):
            return jsonify({"error": "playing must be a boolean."}), 400
        try:
            return jsonify(runtime.set_playing(payload["playing"]))
        except ValueError as error:
            return jsonify({"error": str(error)}), 409

    @app.post("/api/scenarios/step")
    def scenario_step():
        if request.get_json() not in ({}, None):
            return jsonify({"error": "Step request does not accept parameters."}), 400
        try:
            return jsonify(runtime.step_scenario())
        except ValueError as error:
            return jsonify({"error": str(error)}), 409

    @app.post("/api/response/propose")
    def propose_response():
        payload = request.get_json()
        if not isinstance(payload, dict):
            return jsonify({"error": "A JSON request body is required."}), 400
        try:
            decision = runtime.response_manager.propose(
                str(payload.get("playbook_id", "")),
                proposed_by=str(payload.get("operator", "")),
                parameters=payload.get("parameters"),
                context={"alert": payload.get("alert")},
            )
        except (TypeError, ValueError) as error:
            return jsonify({"error": str(error)}), 400
        return jsonify(decision.as_dict()), 201

    @app.post("/api/response/<action_id>/approve")
    def approve_response(action_id: str):
        payload = request.get_json()
        if not isinstance(payload, dict):
            return jsonify({"error": "A JSON request body is required."}), 400
        try:
            decision = runtime.response_manager.approve(
                action_id,
                approved_by=str(payload.get("operator", "")),
                note=str(payload.get("note", "")),
            )
        except ValueError as error:
            return jsonify({"error": str(error)}), 400
        except RuntimeError as error:
            return jsonify({"error": str(error)}), 500
        return jsonify(decision.as_dict())

    @app.post("/api/response/<action_id>/reject")
    def reject_response(action_id: str):
        payload = request.get_json()
        if not isinstance(payload, dict):
            return jsonify({"error": "A JSON request body is required."}), 400
        try:
            decision = runtime.response_manager.reject(
                action_id,
                rejected_by=str(payload.get("operator", "")),
                reason=str(payload.get("reason", "")),
            )
        except ValueError as error:
            return jsonify({"error": str(error)}), 400
        return jsonify(decision.as_dict())

    @app.post("/api/reports")
    def create_report():
        payload = request.get_json(silent=True)
        if payload not in ({}, None):
            return jsonify({"error": "Report request does not accept parameters."}), 400
        report_dir = Path(runtime.data_dir) / "reports"
        try:
            files = generate_incident_report(runtime.snapshot(), report_dir)
        except (OSError, ValueError) as error:
            LOGGER.exception("Could not generate local incident report.")
            return jsonify({"error": f"Report generation failed: {error}"}), 500
        return jsonify({
            "report_id": files.report_id,
            "html_url": url_for("download_report", filename=files.html_path.name),
            "pdf_url": url_for("download_report", filename=files.pdf_path.name),
        }), 201

    @app.get("/api/reports/<path:filename>")
    def download_report(filename: str):
        if not re.fullmatch(r"incident-\d{8}T\d{6}_\d{6}Z\.(?:html|pdf)", filename):
            abort(404)
        return send_from_directory(
            Path(runtime.data_dir) / "reports",
            filename,
            as_attachment=True,
        )

    return app
