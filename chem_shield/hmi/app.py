"""Minimal Flask operator panel for the isolated virtual lab."""

import argparse
from datetime import datetime, timezone

from flask import Flask, jsonify, render_template, request
from chem_shield.communication.device_connection import DeviceConnection
from chem_shield.data.store import TelemetryStore
from chem_shield.events.abnormal_events import write_event


def create_app(plc_host="127.0.0.1", plc_port=5020, database="chem_shield/data/telemetry.db"):
    app = Flask(__name__)
    store = TelemetryStore(database)
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
        return render_template("index.html")

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
    parser.add_argument("--database", default="chem_shield/data/telemetry.db")
    args = parser.parse_args()
    app = create_app(plc_port=args.plc_port, database=args.database)
    app.run(host=args.host, port=args.port, debug=False)