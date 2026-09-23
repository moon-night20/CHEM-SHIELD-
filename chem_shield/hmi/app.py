"""Minimal Flask operator panel for the isolated virtual lab."""

import argparse
from datetime import datetime, timezone

from flask import Flask, jsonify, render_template, request
from pymodbus.client import ModbusTcpClient

from chem_shield.data.store import TelemetryStore
from chem_shield.events.abnormal_events import write_event


def create_app(plc_host="127.0.0.1", plc_port=5020, database="chem_shield/data/telemetry.db"):
    app = Flask(__name__)
    store = TelemetryStore(database)

    def plc_call(action):
        client = ModbusTcpClient(plc_host, port=plc_port)
        if not client.connect():
            raise ConnectionError("PLC is offline")
        try:
            return action(client)
        finally:
            client.close()

    def read_state(client):
        result = client.read_holding_registers(0, count=8, slave=1)
        if result.isError():
            raise RuntimeError(result)
        values = result.registers
        return {
            "motor_status": "RUNNING" if values[0] and values[2] > 1 else "STOPPED",
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

    @app.get("/api/telemetry")
    def telemetry():
        return jsonify(store.recent())

    @app.get("/api/events")
    def event_feed():
        return jsonify(store.recent_events())

    @app.post("/api/control")
    def control():
        payload = request.get_json(silent=True) or {}
        try:
            target = max(0, min(3000, int(payload.get("target_rpm", 1500))))
            current = plc_call(read_state)
            action = payload.get("action")
            motor = 1 if action == "start" else 0 if action == "stop" else (1 if current["motor_status"] == "RUNNING" else 0)
            plc_call(lambda client: client.write_registers(0, [motor, target], slave=1))
            motor_changed = (motor == 1 and current["motor_status"] != "RUNNING") or (motor == 0 and current["motor_status"] != "STOPPED")
            if action in ("start", "stop") and motor_changed:
                store.add_event({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source": "HMI", "machine_id": "M-01",
                    "event_type": "MOTOR_COMMAND" if motor else "MOTOR_STOP",
                    "parameter": "motor_status", "old_value": current["motor_status"],
                    "new_value": "RUNNING" if motor else "STOPPED", "severity": "info",
                })
            if target != current["target_rpm"]:
                store.add_event({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source": "HMI", "machine_id": "M-01",
                    "event_type": "SETPOINT_CHANGE", "parameter": "target_rpm",
                    "old_value": current["target_rpm"], "new_value": target, "severity": "info",
                })
            return jsonify({"ok": True, "motor_status": "RUNNING" if motor else "STOPPED", "target_rpm": target})
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