"""Minimal Flask operator panel for the isolated virtual lab."""

import argparse
import hmac
import logging
import os
import sqlite3
from datetime import datetime, timezone, timedelta
from urllib.parse import urlsplit

from flask import Flask, jsonify, render_template, request
from chem_shield_p1.communication.device_connection import DeviceConnection
from chem_shield_p1.data.store import TelemetryStore
from chem_shield_p1.events.abnormal_events import write_event
from chem_shield_p4.correlation.incident_store import IncidentStore
from chem_shield_p4.correlation.risk_pipeline import RiskPipeline

DEFAULT_ADMIN_URL = "http://127.0.0.1:5000"


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
    plc_port=5020,
    database="chem_shield_p1/data/telemetry.db",
    risk_criticality_by_asset=None,
):
    app = Flask(__name__)
    app.config["INGEST_TOKEN"] = os.environ.get("CHEM_SHIELD_INGEST_TOKEN")
    store = TelemetryStore(database)
    incident_store = IncidentStore(database)
    risk_pipeline = RiskPipeline(
        incident_store, criticality_by_asset=risk_criticality_by_asset
    )
    paused = False
    device = DeviceConnection(plc_host, plc_port)
    try:
        device.connect()
    except ConnectionError:
        pass

    def plc_call(action):
        return device.call(action)

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
        return render_template("index.html", admin_url=_admin_url())

    @app.get("/api/state")
    def state():
        try:
            return jsonify(plc_call(read_state))
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
        if ingest_token and not hmac.compare_digest(
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
            status_code = 400 if result["rejected"] and not result["accepted"] else 200
            return jsonify(result), status_code
        except (ValueError, sqlite3.Error) as error:
            app.logger.exception("Risk event ingestion failed")
            return jsonify({"error": str(error)}), 400 if isinstance(error, ValueError) else 503

    @app.get("/api/risk")
    def risk_summary():
        try:
            active = incident_store.list_incidents(limit=100, active_only=True)
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
            return jsonify({
                "risk_level": highest["risk_level"] if highest else "UNASSESSED",
                "risk_score": highest["risk_score"] if highest else None,
                "incident": highest,
                "active_incidents": active,
                "recent_incidents": incident_store.list_incidents(limit=20),
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
            return jsonify({"incidents": incident_store.list_incidents(limit, active_only)})
        except (ValueError, sqlite3.Error) as error:
            app.logger.exception("Incident history is unavailable")
            return jsonify({"error": str(error)}), 400 if isinstance(error, ValueError) else 503

    @app.get("/api/incidents/<incident_id>")
    def incident_detail(incident_id):
        try:
            incident = incident_store.get_incident(incident_id)
            if incident is None:
                return jsonify({"error": "Incident not found."}), 404
            return jsonify(incident)
        except sqlite3.Error as error:
            app.logger.exception("Incident details are unavailable")
            return jsonify({"error": str(error)}), 503

    @app.post("/api/incidents/<incident_id>/acknowledge")
    def acknowledge_incident(incident_id):
        payload = request.get_json(silent=True) or {}
        acknowledged_by = payload.get("acknowledged_by", "operator")
        if not isinstance(acknowledged_by, str) or not acknowledged_by.strip():
            return jsonify({"error": "acknowledged_by must be a non-empty string."}), 400
        try:
            incident = incident_store.acknowledge(incident_id, acknowledged_by.strip())
            if incident is None:
                return jsonify({"error": "Active incident not found."}), 404
            return jsonify(incident)
        except sqlite3.Error as error:
            app.logger.exception("Incident acknowledgement failed")
            return jsonify({"error": str(error)}), 503

    @app.post("/api/control")
    def control():
        nonlocal paused
        payload = request.get_json(silent=True) or {}
        try:
            target = max(0, min(3000, int(payload.get("target_rpm", 1500))))
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

    return app


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CHEM-SHIELD Virtual Machine operator HMI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--plc-port", type=int, default=5020)
    parser.add_argument("--database", default="chem_shield_p1/data/telemetry.db")
    args = parser.parse_args()
    app = create_app(plc_port=args.plc_port, database=args.database)
    app.run(host=args.host, port=args.port, debug=False)