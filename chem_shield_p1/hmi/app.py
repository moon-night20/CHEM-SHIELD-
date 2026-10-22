"""Minimal Flask operator panel for the isolated virtual lab."""

import argparse
import hmac
import ipaddress
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, jsonify, render_template, request
from chem_shield_p1.communication.device_connection import DeviceConnection
from chem_shield_p1.data.store import TelemetryStore
from chem_shield_p1.events.abnormal_events import write_event
from chem_shield_common.incident_warnings import incident_warning_details
from chem_shield_p1.process.modbus_server import DEFAULT_PLC_PORT
from chem_shield_p4.correlation.incident_store import IncidentStore, is_fresh
from chem_shield_p4.correlation.risk_pipeline import RiskPipeline
from chem_shield_p5.ot_monitor.ot_monitor import MonitorConfig
from chem_shield_p6.response import response_decision
from chem_shield_p6.warning_popup import warning_popup

DEFAULT_ADMIN_URL = "http://127.0.0.1:5000"
DEFAULT_OT_CONFIG = (
    Path(__file__).resolve().parents[2]
    / "chem_shield_p5"
    / "ot_monitor"
    / "config.example.json"
)


def _machine_limit_alerts(state, limits):
    alerts = []
    for sensor, state_key, unit in (
        ("temperature", "temperature", "degC"),
        ("pressure", "pressure", "bar"),
        ("power", "power", "kW"),
        ("speed", "rpm", "rpm"),
    ):
        threshold = limits.get(sensor, {}).get("high")
        value = state[state_key]
        if threshold is not None and value > threshold:
            alerts.append({
                "sensor": sensor,
                "value": value,
                "threshold": threshold,
                "unit": unit,
                "severity": "critical",
                "message": f"{sensor} {value:g} {unit} exceeds the {threshold:g} {unit} upper limit",
            })
    return alerts


def _with_warning_details(incident):
    return {
        **incident,
        "warning_details": incident_warning_details(incident),
        "is_fresh": is_fresh(incident),
    }


def _admin_url() -> str:
    configured = os.environ.get("CHEM_SHIELD_ADMIN_URL", DEFAULT_ADMIN_URL).strip()
    try:
        parsed = urlsplit(configured)
        if (
            parsed.scheme in {"http", "https"}
            and parsed.hostname
            and not parsed.username
            and not parsed.password
            and not parsed.query
            and not parsed.fragment
        ):
            return configured.rstrip("/")
    except ValueError:
        pass
    logging.getLogger(__name__).warning(
        "Invalid CHEM_SHIELD_ADMIN_URL; using %s", DEFAULT_ADMIN_URL
    )
    return DEFAULT_ADMIN_URL


def create_app(
    plc_host="127.0.0.1",
    plc_port=DEFAULT_PLC_PORT,
    database="chem_shield_p1/data/telemetry.db",
    risk_criticality_by_asset=None,
):
    app = Flask(__name__)
    app.register_blueprint(warning_popup)
    ingest_token = os.environ.get("CHEM_SHIELD_INGEST_TOKEN")
    if not ingest_token:
        ingest_token = secrets.token_urlsafe(32)
        app.logger.warning(
            "CHEM_SHIELD_INGEST_TOKEN is unset; generated a per-process ingest token."
        )
    app.config["INGEST_TOKEN"] = ingest_token
    app.config["P6_CONFIRM_TOKEN"] = secrets.token_urlsafe(32)
    app.config["OT_LIMITS_FILE"] = DEFAULT_OT_CONFIG
    ot_config = json.loads(
        Path(app.config["OT_LIMITS_FILE"]).read_text(encoding="utf-8")
    )
    machine_limits = MonitorConfig.from_dict(ot_config).rules.get("limits", {})
    store = TelemetryStore(database)
    incident_store = IncidentStore(database)
    incident_store.resolve_stale(300, "stale at startup")
    risk_pipeline = RiskPipeline(
        incident_store, criticality_by_asset=risk_criticality_by_asset
    )
    paused = False
    device = DeviceConnection(plc_host, plc_port)
    p6_stop_lock = threading.Lock()
    p6_stop_timers = {}
    p6_timer_event_times = {}
    p6_timer_deadlines = {}
    p6_cancelled_event_times = {}
    p6_stopped_incidents = set()
    watchdog_stop = threading.Event()
    app.extensions["incident_watchdog_stop"] = watchdog_stop
    app.extensions["p6_stop_timers"] = p6_stop_timers
    try:
        auto_stop_seconds = int(os.environ.get("CHEM_SHIELD_AUTO_STOP_SECONDS", "900"))
    except ValueError as error:
        raise ValueError(
            "CHEM_SHIELD_AUTO_STOP_SECONDS must be a positive integer"
        ) from error
    if auto_stop_seconds <= 0:
        raise ValueError("CHEM_SHIELD_AUTO_STOP_SECONDS must be a positive integer")
    app.config["P6_AUTO_STOP_SECONDS"] = auto_stop_seconds
    try:
        device.connect()
    except ConnectionError:
        pass

    def plc_call(action):
        return device.call(action)

    def machine_related_incident(incident):
        sources = {
            str(event.get("source") or "").casefold().replace("-", "_")
            for event in incident.get("events", [])
        }
        return any(
            source.startswith((
                "ot_command_console", "ot_monitor", "physical_ml", "plc",
                "process", "hmi", "attack_console",
            ))
            for source in sources
        )

    def cancel_p6_timer(incident_id, reason):
        with p6_stop_lock:
            timer = p6_stop_timers.pop(incident_id, None)
            event_time = p6_timer_event_times.pop(incident_id, None)
            p6_timer_deadlines.pop(incident_id, None)
            if event_time:
                p6_cancelled_event_times[incident_id] = event_time
        if timer:
            timer.cancel()
            store.add_event({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": "P6",
                "machine_id": "M-01",
                "event_type": "P6_AUTO_CANCELLED",
                "parameter": f"auto_stop ({incident_id})",
                "old_value": "COUNTDOWN",
                "new_value": reason,
                "severity": "info",
            })
            app.logger.info(
                "Part 6 automatic stop cancelled for incident %s: %s",
                incident_id,
                reason,
            )

    def execute_p6_stop(incident_id, *, automatic=False):
        nonlocal paused
        with p6_stop_lock:
            if incident_id in p6_stopped_incidents:
                return
            try:
                plc_ip = ipaddress.ip_address(device.host)
            except ValueError as error:
                raise ValueError(
                    "Part 6 is limited to loopback simulation only."
                ) from error
            if not plc_ip.is_loopback:
                raise ValueError("Part 6 is limited to loopback simulation only.")

            incident = incident_store.get_incident(incident_id)
            if incident is None:
                raise ValueError("Incident not found.")
            decision = response_decision(incident)
            if incident.get("risk_level") != "CRITICAL":
                raise ValueError("A simulated stop is available only for CRITICAL incidents.")
            if not automatic and (
                incident.get("status") != "ACTIVE"
                or not decision["requires_operator_confirmation"]
            ):
                raise ValueError("A simulated stop is available only for active CRITICAL incidents.")

            current = plc_call(read_state)
            live_alerts = _machine_limit_alerts(current, machine_limits)
            if automatic and not live_alerts and not (
                incident.get("status") == "ACTIVE" and is_fresh(incident)
            ):
                raise ValueError("The critical condition is no longer current.")
            registers_result = plc_call(
                lambda client: client.write_registers(
                    0, [0, current["target_rpm"]], slave=1
                )
            )
            if registers_result.isError():
                raise RuntimeError(f"Simulator rejected the Part 6 stop: {registers_result}")
            override_result = plc_call(
                lambda client: client.write_register(8, 0, slave=1)
            )
            if override_result.isError():
                raise RuntimeError(
                    f"Simulator rejected the Part 6 override reset: {override_result}"
                )
            event_result = plc_call(lambda client: client.write_register(6, 0, slave=1))
            if event_result.isError():
                raise RuntimeError(f"Simulator rejected the Part 6 reset: {event_result}")
            store.add_event({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": "P6",
                "machine_id": "M-01",
                "event_type": "P6_SIMULATED_STOP",
                "parameter": f"motor_status ({incident_id})",
                "old_value": current["motor_status"],
                "new_value": "STOPPED",
                "severity": "critical",
            })
            p6_stopped_incidents.add(incident_id)
            paused = False
            incident_store.resolve_incident(
                incident_id,
                "automatic simulated stop" if automatic else "operator simulated stop",
            )
            timer = p6_stop_timers.pop(incident_id, None)
            p6_timer_event_times.pop(incident_id, None)
            p6_timer_deadlines.pop(incident_id, None)
            if timer:
                timer.cancel()

    def auto_stop_after_countdown(incident_id):
        with p6_stop_lock:
            p6_stop_timers.pop(incident_id, None)
            p6_timer_event_times.pop(incident_id, None)
            p6_timer_deadlines.pop(incident_id, None)
        try:
            incident = incident_store.get_incident(incident_id)
            if (
                incident is None
                or incident.get("risk_level") != "CRITICAL"
            ):
                app.logger.info(
                    "Part 6 automatic stop skipped for stale or changed incident %s",
                    incident_id,
                )
                return
            execute_p6_stop(incident_id, automatic=True)
            app.logger.warning(
                "Part 6 automatic simulated stop applied to incident %s",
                incident_id,
            )
        except (ConnectionError, RuntimeError, ValueError, sqlite3.Error) as error:
            app.logger.error(
                "Part 6 automatic simulated stop failed for incident %s: %s",
                incident_id,
                error,
            )

    def arm_p6_auto_stop(incident, *, live_alert=False, recent_ingest=False):
        if (
            incident.get("status") != "ACTIVE"
            or incident.get("risk_level") != "CRITICAL"
            or not is_fresh(incident)
        ):
            return False
        incident_id = incident["incident_id"]
        if not live_alert and not recent_ingest:
            try:
                live_alert = bool(
                    _machine_limit_alerts(plc_call(read_state), machine_limits)
                )
            except (ConnectionError, RuntimeError):
                live_alert = False
        if not live_alert and not recent_ingest:
            return False
        event_time = incident.get("last_event_time")
        if not event_time:
            return False
        with p6_stop_lock:
            if incident_id in p6_stopped_incidents:
                return False
            existing = p6_stop_timers.get(incident_id)
            if existing and existing.is_alive():
                return True
            if p6_cancelled_event_times.get(incident_id) == event_time:
                if not live_alert:
                    return False
            p6_cancelled_event_times.pop(incident_id, None)
            timer = threading.Timer(
                app.config["P6_AUTO_STOP_SECONDS"],
                auto_stop_after_countdown,
                args=(incident_id,),
            )
            timer.daemon = True
            p6_stop_timers[incident_id] = timer
            p6_timer_event_times[incident_id] = event_time
            p6_timer_deadlines[incident_id] = time.time() + app.config["P6_AUTO_STOP_SECONDS"]
            timer.start()
        app.logger.warning(
            "Part 6 automatic simulated stop armed for incident %s in %s seconds",
            incident_id,
            app.config["P6_AUTO_STOP_SECONDS"],
        )
        return True

    def resolve_machine_incidents(reason):
        for incident in incident_store.list_incidents(limit=100, active_only=True):
            if machine_related_incident(incident):
                cancel_p6_timer(incident["incident_id"], reason)
                incident_store.resolve_incident(incident["incident_id"], reason)

    def read_state(client):
        result = client.read_holding_registers(0, count=8, slave=1)
        if result.isError():
            raise RuntimeError(result)
        values = result.registers
        return {
            "motor_status": "PAUSED" if paused or values[6] == 5 else ("RUNNING" if values[0] and values[2] > 1 else "STOPPED"),
            "target_rpm": values[1], "rpm": values[2],
            "temperature": values[3] / 100, "pressure": values[4] / 100,
            "power": values[5] / 100,
        }

    @app.get("/")
    def index():
        return render_template(
            "index.html",
            admin_url=_admin_url(),
            p6_confirm_token=app.config["P6_CONFIRM_TOKEN"],
        )

    @app.get("/api/state")
    def state():
        try:
            current = plc_call(read_state)
            alerts = _machine_limit_alerts(current, machine_limits)
            return jsonify({
                **current,
                "machine_condition": "CRITICAL" if alerts else "NORMAL",
                "limit_alerts": alerts,
            })
        except (ConnectionError, RuntimeError) as error:
            return jsonify({"error": str(error)}), 503

    @app.get("/api/connection")
    def connection_status():
        return jsonify(device.snapshot())

    @app.post("/api/connection")
    def connection_control():
        payload = request.get_json(silent=True) or {}
        action = payload.get("action", "connect")
        try:
            if action == "disconnect":
                return jsonify(device.disconnect())
            if action in ("connect", "reconnect"):
                device.configure(payload.get("host", device.host), payload.get("port", device.port), payload.get("name", device.name))
                return jsonify(device.reconnect() if action == "reconnect" else device.connect())
            raise ValueError("Action must be connect, disconnect, or reconnect")
        except (ConnectionError, ValueError) as error:
            return jsonify({**device.snapshot(), "status": "CONNECTION ERROR", "error": str(error)}), 400

    @app.get("/api/telemetry")
    def telemetry():
        return jsonify(store.recent())

    @app.get("/api/events")
    def event_feed():
        return jsonify(store.recent_events())

    @app.post("/api/risk/events")
    def risk_event_ingest():
        ingest_token = app.config["INGEST_TOKEN"]
        if not hmac.compare_digest(
            request.headers.get("X-Ingest-Token", ""), ingest_token
        ):
            return jsonify({"error": "Valid X-Ingest-Token header is required"}), 401
        payload = request.get_json(silent=True)
        if isinstance(payload, dict) and "events" in payload:
            incoming = payload["events"]
        elif isinstance(payload, dict):
            incoming = [payload]
        else:
            incoming = payload
        try:
            result = risk_pipeline.ingest(incoming)
            for incident in result["incidents"]:
                arm_p6_auto_stop(
                    incident,
                    recent_ingest=(
                        incident.get("risk_level") == "CRITICAL"
                        and is_fresh(incident)
                    ),
                )
            status_code = 400 if result["rejected"] and not result["accepted"] else 200
            return jsonify(result), status_code
        except (ValueError, sqlite3.Error) as error:
            app.logger.exception("Risk event ingestion failed")
            return jsonify({"error": str(error)}), 400 if isinstance(error, ValueError) else 503

    @app.get("/api/risk")
    def risk_summary():
        try:
            active = [
                item for item in incident_store.list_incidents(
                    limit=100, active_only=True
                )
                if is_fresh(item)
            ]
            scored = [item for item in active if item["risk_score"] is not None]
            rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
            highest = max(
                scored, key=lambda item: rank.get(item["risk_level"], -1), default=None
            )
            ingest_state = incident_store.ingest_status()
            last_received = ingest_state["last_received_at"]
            last_accepted = ingest_state["last_accepted_at"]
            if not last_accepted:
                input_status = "DEGRADED" if ingest_state["rejected_count"] else "NOT_CONNECTED"
            elif ingest_state["rejected_count"]:
                input_status = "DEGRADED"
            else:
                last_time = datetime.fromisoformat(last_accepted.replace("Z", "+00:00"))
                input_status = (
                    "STALE"
                    if datetime.now(timezone.utc) - last_time > timedelta(seconds=60)
                    else "ACTIVE"
                )
            def incident_payload(item):
                payload = _with_warning_details(item)
                with p6_stop_lock:
                    deadline = p6_timer_deadlines.get(item["incident_id"])
                if deadline is not None:
                    payload["auto_stop_at"] = datetime.fromtimestamp(
                        deadline, timezone.utc
                    ).isoformat().replace("+00:00", "Z")
                return payload

            with p6_stop_lock:
                next_deadline = min(p6_timer_deadlines.values(), default=None)
            return jsonify({
                "risk_level": highest["risk_level"] if highest else "UNASSESSED",
                "risk_score": highest["risk_score"] if highest else None,
                "incident": incident_payload(highest) if highest else None,
                "auto_stop_at": (
                    datetime.fromtimestamp(next_deadline, timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z")
                    if next_deadline is not None else None
                ),
                "active_incidents": [incident_payload(item) for item in active],
                "popup_candidates": [
                    incident_payload(item)
                    for item in active
                    if item.get("risk_level") in {"HIGH", "CRITICAL"}
                    and not item.get("acknowledged")
                ],
                "recent_incidents": [
                    _with_warning_details(item)
                    for item in incident_store.list_incidents(limit=20)
                ],
                "input_status": input_status,
                "last_received_at": last_received,
                "accepted_count": ingest_state["accepted_count"],
                "rejected_count": ingest_state["rejected_count"],
                "score_scale": "0.0-1.0",
                "scores_are_probabilities": False,
            })
        except sqlite3.Error as error:
            app.logger.exception("Risk summary is unavailable")
            return jsonify({"error": f"Risk summary unavailable: {error}"}), 503

    @app.get("/api/incidents")
    def incident_history():
        try:
            limit = min(100, max(1, int(request.args.get("limit", 50))))
            active_only = request.args.get("active", "false").lower() in ("true", "1")
            return jsonify({
                "incidents": [
                    _with_warning_details(item)
                    for item in incident_store.list_incidents(limit, active_only)
                ]
            })
        except (ValueError, sqlite3.Error) as error:
            app.logger.exception("Incident history is unavailable")
            return jsonify({"error": str(error)}), 400 if isinstance(error, ValueError) else 503

    @app.get("/api/incidents/<incident_id>")
    def incident_detail(incident_id):
        try:
            incident = incident_store.get_incident(incident_id)
            if incident is None:
                return jsonify({"error": "Incident not found."}), 404
            return jsonify(_with_warning_details(incident))
        except sqlite3.Error as error:
            app.logger.exception("Incident details are unavailable")
            return jsonify({"error": str(error)}), 503

    @app.post("/api/incidents/<incident_id>/acknowledge")
    def acknowledge_incident(incident_id):
        payload = request.get_json(silent=True) or {}
        acknowledged_by = payload.get("acknowledged_by", "operator")
        arm_p6_followup = payload.get("p6_followup", False)
        if not isinstance(acknowledged_by, str) or not acknowledged_by.strip():
            return jsonify({"error": "acknowledged_by must be a non-empty string."}), 400
        if not isinstance(arm_p6_followup, bool):
            return jsonify({"error": "p6_followup must be a boolean."}), 400
        if arm_p6_followup:
            supplied_token = request.headers.get("X-Chem-Shield-P6-Confirmation", "")
            if not hmac.compare_digest(supplied_token, app.config["P6_CONFIRM_TOKEN"]):
                return jsonify({"error": "Part 6 confirmation token is missing or invalid."}), 403
            try:
                caller_ip = ipaddress.ip_address(request.remote_addr or "")
                plc_ip = ipaddress.ip_address(device.host)
            except ValueError:
                return jsonify({"error": "Part 6 is limited to loopback simulation only."}), 403
            if not caller_ip.is_loopback or not plc_ip.is_loopback:
                return jsonify({"error": "Part 6 is limited to loopback simulation only."}), 403
        try:
            incident = incident_store.acknowledge(incident_id, acknowledged_by.strip())
            if incident is None:
                return jsonify({"error": "Active incident not found."}), 404
            response = _with_warning_details(incident)
            if arm_p6_followup:
                decision = response_decision(incident)
                response["p6_response_available"] = decision[
                    "requires_operator_confirmation"
                ]
            return jsonify(response)
        except sqlite3.Error as error:
            app.logger.exception("Incident acknowledgement failed")
            return jsonify({"error": str(error)}), 503

    @app.post("/api/p6/respond")
    def p6_respond():
        nonlocal paused
        if not request.is_json:
            return jsonify({"error": "A JSON confirmation is required."}), 415
        supplied_token = request.headers.get("X-Chem-Shield-P6-Confirmation", "")
        if not hmac.compare_digest(supplied_token, app.config["P6_CONFIRM_TOKEN"]):
            return jsonify({"error": "Part 6 confirmation token is missing or invalid."}), 403
        payload = request.get_json(silent=True) or {}
        incident_id = payload.get("incident_id")
        if not isinstance(incident_id, str) or not incident_id.strip():
            return jsonify({"error": "incident_id must be a non-empty string."}), 400
        if payload.get("confirm_stop") is not True:
            return jsonify({"error": "Explicit operator confirmation is required."}), 400

        try:
            caller_ip = ipaddress.ip_address(request.remote_addr or "")
            plc_ip = ipaddress.ip_address(device.host)
        except ValueError:
            return jsonify({"error": "Part 6 is limited to loopback simulation only."}), 403
        if not caller_ip.is_loopback or not plc_ip.is_loopback:
            app.logger.warning(
                "Rejected Part 6 response from %s targeting PLC host %s",
                request.remote_addr,
                device.host,
            )
            return jsonify({"error": "Part 6 is limited to loopback simulation only."}), 403

        try:
            incident = incident_store.get_incident(incident_id.strip())
            if incident is None:
                return jsonify({"error": "Incident not found."}), 404
            decision = response_decision(incident)
            if not decision["requires_operator_confirmation"]:
                return jsonify({
                    "error": "A simulated stop is available only for active CRITICAL incidents.",
                    "decision": decision,
                }), 409
            execute_p6_stop(incident_id.strip())
            resolve_machine_incidents("operator simulated stop")
        except (ConnectionError, RuntimeError, ValueError) as error:
            app.logger.warning("Part 6 simulated stop failed: %s", error)
            return jsonify({"error": str(error)}), 503
        except sqlite3.Error as error:
            app.logger.exception("Part 6 response could not be recorded")
            return jsonify({"error": f"Part 6 response could not be recorded: {error}"}), 503

        return jsonify({
            "ok": True,
            "incident_id": incident_id.strip(),
            "action": "simulated_stop",
            "motor_status": "STOPPED",
            "simulation_only": True,
            "executed": True,
        })

    @app.post("/api/control")
    def control():
        nonlocal paused
        payload = request.get_json(silent=True) or {}
        try:
            target = max(0, min(1450, int(payload.get("target_rpm", 1400))))
            current = plc_call(read_state)
            action = payload.get("action")
            if action == "pause":
                paused = True
            elif action == "start":
                paused = False
            elif action == "stop":
                paused = False
            motor = 1 if action == "start" else 0 if action in ("pause", "stop") else (1 if current["motor_status"] == "RUNNING" else 0)
            plc_call(lambda client: client.write_registers(0, [motor, target], slave=1))
            if action == "stop":
                override_result = plc_call(
                    lambda client: client.write_register(8, 0, slave=1)
                )
                if override_result.isError():
                    raise RuntimeError(
                        f"Simulator rejected the override reset: {override_result}"
                    )
                resolve_machine_incidents("operator stop")
            plc_call(lambda client: client.write_register(6, 5 if action == "pause" else 0, slave=1))
            motor_changed = (motor == 1 and current["motor_status"] != "RUNNING") or (motor == 0 and current["motor_status"] != "STOPPED")
            if action in ("start", "pause", "stop") and motor_changed:
                store.add_event({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source": "HMI", "machine_id": "M-01",
                    "event_type": "MOTOR_COMMAND" if motor else ("MOTOR_PAUSE" if action == "pause" else "MOTOR_STOP"),
                    "parameter": "motor_status", "old_value": current["motor_status"],
                    "new_value": "RUNNING" if motor else ("PAUSED" if action == "pause" else "STOPPED"), "severity": "info",
                })
            if target != current["target_rpm"]:
                store.add_event({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source": "HMI", "machine_id": "M-01",
                    "event_type": "SETPOINT_CHANGE", "parameter": "target_rpm",
                    "old_value": current["target_rpm"], "new_value": target, "severity": "info",
                })
            return jsonify({"ok": True, "motor_status": "RUNNING" if motor else ("PAUSED" if action == "pause" else "STOPPED"), "target_rpm": target})
        except (ConnectionError, RuntimeError, ValueError) as error:
            return jsonify({"error": str(error)}), 400

    @app.post("/api/events")
    def events():
        payload = request.get_json(silent=True) or {}
        event_type = payload.get("event_type")
        value = int(payload.get("value", 1500))
        try:
            event = plc_call(lambda client: write_event(client, event_type, value))
            store.add_event(event)
            return jsonify(event), 201
        except (ConnectionError, RuntimeError, ValueError) as error:
            return jsonify({"error": str(error)}), 400

    normal_since = [None]

    def check_incident_lifecycle(state, now=None):
        current_time = time.monotonic() if now is None else now
        alerts = _machine_limit_alerts(state, machine_limits)
        active = incident_store.list_incidents(limit=100, active_only=True)
        if alerts:
            normal_since[0] = None
            for incident in active:
                if incident.get("risk_level") == "CRITICAL":
                    arm_p6_auto_stop(incident, live_alert=True)
            return

        with p6_stop_lock:
            timer_ids = list(p6_stop_timers)
        active_by_id = {incident["incident_id"]: incident for incident in active}
        for incident_id in timer_ids:
            incident = active_by_id.get(incident_id)
            if incident is None:
                incident = incident_store.get_incident(incident_id)
            if incident is None or not is_fresh(incident):
                cancel_p6_timer(incident_id, "incident_stale")
            elif machine_related_incident(incident):
                cancel_p6_timer(incident_id, "readings_normal")
        if normal_since[0] is None:
            normal_since[0] = current_time
        if current_time - normal_since[0] >= 30:
            resolve_machine_incidents("readings_normal")

    app.extensions["incident_lifecycle_check"] = check_incident_lifecycle

    def incident_watchdog():
        while not watchdog_stop.wait(5):
            try:
                incident_store.resolve_stale(300, "no new events")
                current = plc_call(read_state)
                check_incident_lifecycle(current)
            except (ConnectionError, RuntimeError, sqlite3.Error):
                app.logger.exception("Incident lifecycle watchdog check failed")

    watchdog_thread = threading.Thread(
        target=incident_watchdog,
        name="chem-shield-incident-watchdog",
        daemon=True,
    )
    watchdog_thread.start()
    app.extensions["incident_watchdog_thread"] = watchdog_thread

    def stop_background_tasks():
        watchdog_stop.set()
        with p6_stop_lock:
            timers = list(p6_stop_timers.values())
            p6_stop_timers.clear()
            p6_timer_event_times.clear()
            p6_timer_deadlines.clear()
        for timer in timers:
            timer.cancel()
        watchdog_thread.join(timeout=1)

    app.extensions["stop_background_tasks"] = stop_background_tasks
    return app


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CHEM-SHIELD Virtual Machine operator HMI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=15000)
    parser.add_argument("--plc-port", type=int, default=DEFAULT_PLC_PORT)
    parser.add_argument("--database", default="chem_shield_p1/data/telemetry.db")
    args = parser.parse_args()
    app = create_app(plc_port=args.plc_port, database=args.database)
    app.run(host=args.host, port=args.port, debug=False)