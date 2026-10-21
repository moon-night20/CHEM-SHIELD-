"""Manual, loopback-only command console for the CHEM-SHIELD virtual PLC."""

from __future__ import annotations

import argparse
import hmac
import ipaddress
import json
import logging
import math
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

from flask import Flask, jsonify, render_template, request

from chem_shield_common.publisher import publish_events
from chem_shield_p1.communication.device_connection import DeviceConnection
from chem_shield_p1.data.store import TelemetryStore
from chem_shield_p1.plc.register_map import (
    EVENT_CODE,
    OVERRIDE_POWER,
    OVERRIDE_PRESSURE,
    OVERRIDE_SPEED,
    OVERRIDE_TEMPERATURE,
    SIM_OVERRIDE_MASK,
    SIM_OVERRIDE_REGISTERS,
    SIM_POWER,
    SIM_PRESSURE,
    SIM_SPEED,
    SIM_TEMPERATURE,
    SLAVE_ID,
)
from chem_shield_p1.process.modbus_server import DEFAULT_PLC_PORT


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATABASE = ROOT / "chem_shield_p1" / "data" / "telemetry.db"
DEFAULT_LIMITS_FILE = ROOT / "chem_shield_p5" / "ot_monitor" / "config.example.json"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5001
SIMULATOR_FRESH_SECONDS = 3.0
SIMULATION_EVENT_PARAMETERS = set()

PARAMETERS = {
    "temperature": {
        "unit": "°C",
        "minimum": 0.0,
        "maximum": 120.0,
        "telemetry_key": "temperature",
        "register": SIM_TEMPERATURE,
        "override_bit": OVERRIDE_TEMPERATURE,
        "scale": 100,
        "limit_key": "temperature",
    },
    "pressure": {
        "unit": "bar",
        "minimum": 0.0,
        "maximum": 10.0,
        "telemetry_key": "pressure",
        "register": SIM_PRESSURE,
        "override_bit": OVERRIDE_PRESSURE,
        "scale": 100,
        "limit_key": "pressure",
    },
    "power": {
        "unit": "kW",
        "minimum": 0.0,
        "maximum": 20.0,
        "telemetry_key": "power",
        "register": SIM_POWER,
        "override_bit": OVERRIDE_POWER,
        "scale": 100,
        "limit_key": "power",
    },
    "speed": {
        "unit": "RPM",
        "minimum": 0.0,
        "maximum": 3000.0,
        "telemetry_key": "rpm",
        "register": SIM_SPEED,
        "override_bit": OVERRIDE_SPEED,
        "scale": 1,
        "limit_key": "speed",
    },
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_fresh(timestamp: Optional[str]) -> bool:
    if not timestamp:
        return False
    try:
        observed_at = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return False
    if observed_at.tzinfo is None:
        observed_at = observed_at.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - observed_at).total_seconds() <= SIMULATOR_FRESH_SECONDS


class CommandHistoryStore:
    """Additive audit table sharing the project's local telemetry database."""

    def __init__(self, database: Union[str, Path]):
        self.path = Path(database)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS ot_console_commands (
                    id TEXT PRIMARY KEY,
                    requested_at TEXT NOT NULL,
                    telemetry_id_before INTEGER NOT NULL,
                    parameter TEXT NOT NULL,
                    requested_value TEXT,
                    unit TEXT,
                    status TEXT NOT NULL,
                    validation_result TEXT NOT NULL,
                    observed_at TEXT,
                    observed_value REAL,
                    exceeded_limit INTEGER,
                    warning TEXT,
                    incident_status TEXT NOT NULL
                )"""
            )

    def latest_telemetry(self) -> Optional[dict[str, Any]]:
        with sqlite3.connect(self.path) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT id,timestamp,motor_status,target_rpm,rpm,temperature,pressure,power "
                "FROM telemetry ORDER BY id DESC LIMIT 1"
            ).fetchone()
        return dict(row) if row else None

    def telemetry_id(self) -> int:
        with sqlite3.connect(self.path) as connection:
            row = connection.execute("SELECT COALESCE(MAX(id),0) FROM telemetry").fetchone()
        return int(row[0])

    def record(
        self,
        command_id: str,
        requested_at: str,
        telemetry_id_before: int,
        parameter: str,
        requested_value: Any,
        unit: Optional[str],
        status: str,
        validation_result: str,
        incident_status: str = "No incident linked",
    ) -> None:
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                """INSERT INTO ot_console_commands
                (id,requested_at,telemetry_id_before,parameter,requested_value,unit,
                 status,validation_result,incident_status)
                VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    command_id,
                    requested_at,
                    telemetry_id_before,
                    parameter,
                    None if requested_value is None else str(requested_value),
                    unit,
                    status,
                    validation_result,
                    incident_status,
                ),
            )

    def pending(self) -> list[dict[str, Any]]:
        with sqlite3.connect(self.path) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                "SELECT * FROM ot_console_commands WHERE status='accepted' "
                "ORDER BY requested_at ASC LIMIT 100"
            ).fetchall()
        return [dict(row) for row in rows]

    def newer_telemetry(self, telemetry_id: int) -> Optional[dict[str, Any]]:
        with sqlite3.connect(self.path) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT id,timestamp,motor_status,target_rpm,rpm,temperature,pressure,power "
                "FROM telemetry WHERE id>? ORDER BY id ASC LIMIT 1",
                (telemetry_id,),
            ).fetchone()
        return dict(row) if row else None

    def mark_observed(
        self,
        command_id: str,
        observed_at: str,
        observed_value: float,
        exceeded_limit: bool,
        warning: Optional[str],
    ) -> bool:
        with sqlite3.connect(self.path) as connection:
            result = connection.execute(
                """UPDATE ot_console_commands
                SET status='observed',observed_at=?,observed_value=?,
                    exceeded_limit=?,warning=?,incident_status=?
                WHERE id=? AND status='accepted'""",
                (
                    observed_at,
                    observed_value,
                    int(exceeded_limit),
                    warning,
                    "Warning recorded; risk event publication pending"
                    if exceeded_limit
                    else "No incident linked",
                    command_id,
                ),
            )
        return result.rowcount == 1

    def update_incident_status(self, command_id: str, status: str) -> None:
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                "UPDATE ot_console_commands SET incident_status=? WHERE id=?",
                (status, command_id),
            )

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        with sqlite3.connect(self.path) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                "SELECT id,requested_at,parameter,requested_value,unit,status,"
                "validation_result,observed_at,observed_value,exceeded_limit,warning,"
                "incident_status FROM ot_console_commands "
                "ORDER BY requested_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]


def _read_registers(client: Any) -> list[int]:
    result = client.read_holding_registers(0, count=8, slave=SLAVE_ID)
    if result.isError():
        raise RuntimeError(f"Virtual PLC rejected the telemetry read: {result}")
    return result.registers


def _read_override_registers(client: Any) -> list[int]:
    result = client.read_holding_registers(
        SIM_OVERRIDE_MASK,
        count=SIM_OVERRIDE_REGISTERS,
        slave=SLAVE_ID,
    )
    if result.isError():
        raise RuntimeError(f"Virtual PLC rejected the override read: {result}")
    return result.registers


def _load_limits(
    path: Union[str, Path]
) -> dict[str, dict[str, Optional[float]]]:
    config = json.loads(Path(path).read_text(encoding="utf-8"))
    limits = config.get("rules", {}).get("limits", {})
    return {
        "temperature": limits.get("temperature", {}),
        "pressure": limits.get("pressure", {}),
        "power": limits.get("power", {}),
        "speed": limits.get("speed", {}),
    }


def create_app(
    plc_host: str = DEFAULT_HOST,
    plc_port: int = DEFAULT_PLC_PORT,
    database: Union[str, Path] = DEFAULT_DATABASE,
    limits_file: Union[str, Path] = DEFAULT_LIMITS_FILE,
) -> Flask:
    try:
        address = ipaddress.ip_address(plc_host)
    except ValueError as error:
        raise ValueError("PLC host must be the loopback address 127.0.0.1") from error
    if address != ipaddress.ip_address(DEFAULT_HOST):
        raise ValueError("OT Command Console can connect only to PLC-01 at 127.0.0.1")
    if plc_port != DEFAULT_PLC_PORT:
        raise ValueError(
            f"OT Command Console supports only PLC-01 simulator port {DEFAULT_PLC_PORT}"
        )

    app = Flask(__name__)
    app.config["CSRF_TOKEN"] = secrets.token_urlsafe(32)
    limits = _load_limits(limits_file)
    telemetry = TelemetryStore(str(database))
    commands = CommandHistoryStore(database)
    device = DeviceConnection(str(address), plc_port, name="PLC-01")
    app.extensions["ot_console_telemetry"] = telemetry
    app.extensions["ot_console_commands"] = commands
    app.extensions["ot_console_device"] = device

    try:
        device.connect()
    except ConnectionError:
        app.logger.info("Virtual PLC is not connected at console startup")

    def plc_call(action):
        try:
            return device.call(action)
        except ConnectionError as first_error:
            app.logger.warning(
                "Virtual PLC connection dropped; reconnecting to %s:%s",
                device.host,
                device.port,
            )
            try:
                device.reconnect()
            except ConnectionError as reconnect_error:
                raise reconnect_error from first_error
            return device.call(action)

    def limit_for(parameter: str) -> Optional[float]:
        limit_key = PARAMETERS.get(parameter, {}).get("limit_key", parameter)
        value = limits.get(limit_key, {}).get("high")
        return float(value) if value is not None else None

    def alerts_for(
        record: Optional[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        if record is None:
            return []
        alerts = []
        for parameter in ("temperature", "pressure", "power", "speed"):
            threshold = limit_for(parameter)
            value = record[PARAMETERS[parameter]["telemetry_key"]]
            if threshold is not None and value > threshold:
                unit = PARAMETERS[parameter]["unit"]
                alerts.append({
                    "parameter": parameter,
                    "value": value,
                    "threshold": threshold,
                    "unit": unit,
                    "message": (
                        f"{parameter.title()} {value:g} {unit} exceeds the "
                        f"configured upper limit of {threshold:g} {unit}"
                    ),
                })
        return alerts

    def reconcile_commands() -> None:
        for command in commands.pending():
            sample = commands.newer_telemetry(command["telemetry_id_before"])
            if sample is None:
                continue
            parameter = command["parameter"]
            if parameter not in PARAMETERS:
                continue
            measured_key = PARAMETERS.get(parameter, {}).get("telemetry_key")
            if measured_key is None:
                continue
            observed_value = float(sample[measured_key])
            limit_key = PARAMETERS[parameter]["limit_key"]
            threshold = limit_for(parameter)
            exceeded = threshold is not None and observed_value > threshold
            warning = None
            if exceeded:
                measured_unit = PARAMETERS[parameter]["unit"]
                warning = (
                    f"{parameter.title()} {observed_value:g} "
                    f"{measured_unit} exceeds the configured upper "
                    f"limit of {threshold:g} {measured_unit}"
                )
            if commands.mark_observed(
                command["id"],
                sample["timestamp"],
                observed_value,
                exceeded,
                warning,
            ) and exceeded:
                telemetry.add_event({
                    "timestamp": sample["timestamp"],
                    "source": "OT_COMMAND_CONSOLE",
                    "machine_id": "M-01",
                    "event_type": f"{limit_key}_high",
                    "parameter": limit_key,
                    "old_value": threshold,
                    "new_value": observed_value,
                    "severity": limits.get(limit_key, {}).get("high_severity", "high"),
                })
                event = {
                    "event_id": f"ot-command-{command['id']}",
                    "timestamp": sample["timestamp"],
                    "source": "ot_command_console",
                    "asset_id": "PLC-01",
                    "event_type": "physical",
                    "anomaly_score": 1.0,
                    "severity": str(
                        limits.get(limit_key, {}).get("high_severity", "critical")
                    ).upper(),
                    "evidence": {
                        "sensor": limit_key,
                        "rule_id": f"{limit_key.upper()}-HIGH",
                        "detection_method": "configured_limit",
                        "value": observed_value,
                        "configured_threshold": threshold,
                        "unit": PARAMETERS[parameter]["unit"],
                        "message": warning,
                    },
                }
                result = publish_events([event])
                if result["accepted"] > 0 and result["failed_batches"] == 0:
                    commands.update_incident_status(
                        command["id"], "Risk event saved to HMI incident register"
                    )
                else:
                    publication_error = "; ".join(result["errors"]) or (
                        f"HMI rejected {result['rejected']} risk event(s)"
                    )
                    commands.update_incident_status(
                        command["id"], f"Risk event was not saved: {publication_error}"
                    )
                    app.logger.error(
                        "OT command risk event was not persisted by HMI: %s",
                        publication_error,
                    )

    @app.get("/")
    def index():
        return render_template(
            "index.html",
            csrf_token=app.config["CSRF_TOKEN"],
            parameters=PARAMETERS,
            limits={name: limit_for(name) for name in PARAMETERS},
            plc_port=plc_port,
            web_port=DEFAULT_PORT,
        )

    @app.get("/api/dashboard")
    def dashboard():
        try:
            latest = commands.latest_telemetry()
            plc_state = None
            plc_error = None
            overrides = {}
            try:
                registers = plc_call(_read_registers)
                override_registers = plc_call(_read_override_registers)
                override_mask = override_registers[0]
                plc_state = {
                    "motor_status": (
                        "PAUSED"
                        if registers[EVENT_CODE] == 5
                        else "RUNNING" if registers[0] and registers[2] > 1 else "STOPPED"
                    ),
                    "target_rpm": registers[1],
                    "rpm": registers[2],
                    "temperature": registers[3] / 100,
                    "pressure": registers[4] / 100,
                    "power": registers[5] / 100,
                }
                overrides = {
                    parameter: {
                        "enabled": bool(override_mask & spec["override_bit"]),
                        "value": (
                            override_registers[spec["register"] - SIM_OVERRIDE_MASK]
                            / spec["scale"]
                        ),
                    }
                    for parameter, spec in PARAMETERS.items()
                }
            except (ConnectionError, RuntimeError) as error:
                plc_error = str(error)
            reconcile_commands()
            latest = commands.latest_telemetry()
            return jsonify({
                "plc": device.snapshot(),
                "plc_error": plc_error,
                "plc_state": plc_state,
                "overrides": overrides,
                "simulator_connected": bool(latest and _is_fresh(latest["timestamp"])),
                "telemetry": latest,
                "alerts": alerts_for(latest),
                "limits": {name: limit_for(name) for name in PARAMETERS},
                "supported_parameters": PARAMETERS,
                "simulation_only": True,
            })
        except sqlite3.Error as error:
            app.logger.exception("OT console dashboard could not read local telemetry")
            return jsonify({"error": f"Telemetry is unavailable: {error}"}), 503

    @app.get("/api/commands")
    def command_history():
        try:
            reconcile_commands()
            return jsonify({"commands": commands.recent()})
        except sqlite3.Error as error:
            app.logger.exception("OT console command history is unavailable")
            return jsonify({"error": f"Command history is unavailable: {error}"}), 503

    @app.post("/api/connection")
    def connection_control():
        if not request.is_json:
            return jsonify({"error": "A JSON request is required"}), 415
        if not _local_request():
            return jsonify({"error": "This control is available only from loopback"}), 403
        if not _valid_csrf():
            return jsonify({"error": "Missing or invalid console request token"}), 403
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "A JSON object is required"}), 400
        action = payload.get("action")
        try:
            if action == "disconnect":
                result = device.disconnect()
            elif action in ("connect", "reconnect"):
                result = device.reconnect() if action == "reconnect" else device.connect()
            else:
                return jsonify({"error": "Action must be connect, disconnect, or reconnect"}), 400
            return jsonify(result)
        except ConnectionError as error:
            return jsonify({**device.snapshot(), "error": str(error)}), 503

    def _audit_rejection(parameter: Any, raw_value: Any, reason: str) -> None:
        commands.record(
            secrets.token_urlsafe(12),
            _utc_now(),
            commands.telemetry_id(),
            str(parameter)[:80] if parameter is not None else "unknown",
            raw_value,
            PARAMETERS.get(parameter, {}).get("unit")
            if isinstance(parameter, str)
            else None,
            "rejected",
            reason,
        )

    def _local_request() -> bool:
        try:
            return ipaddress.ip_address(request.remote_addr or "").is_loopback
        except ValueError:
            return False

    def _valid_csrf() -> bool:
        return hmac.compare_digest(
            request.headers.get("X-Console-Token", ""),
            app.config["CSRF_TOKEN"],
        )

    def write_override(client: Any, parameter: str, value: float) -> None:
        result = client.read_holding_registers(
            SIM_OVERRIDE_MASK,
            count=SIM_OVERRIDE_REGISTERS,
            slave=SLAVE_ID,
        )
        if result.isError():
            raise RuntimeError(f"Virtual PLC rejected the override read: {result}")
        values = list(result.registers)
        spec = PARAMETERS[parameter]
        values[0] |= spec["override_bit"]
        values[spec["register"] - SIM_OVERRIDE_MASK] = round(
            value * spec["scale"]
        )
        written = client.write_registers(
            SIM_OVERRIDE_MASK,
            values,
            slave=SLAVE_ID,
        )
        if written.isError():
            raise RuntimeError(f"Virtual PLC rejected the {parameter} override: {written}")

    @app.post("/api/overrides/clear")
    def clear_overrides():
        if not request.is_json:
            return jsonify({"error": "A JSON request is required"}), 415
        if not _local_request():
            return jsonify({"error": "This control is available only from loopback"}), 403
        if not _valid_csrf():
            return jsonify({"error": "Missing or invalid console request token"}), 403
        try:
            def clear(client):
                result = client.read_holding_registers(
                    SIM_OVERRIDE_MASK,
                    count=SIM_OVERRIDE_REGISTERS,
                    slave=SLAVE_ID,
                )
                if result.isError():
                    raise RuntimeError(f"Virtual PLC rejected the override read: {result}")
                values = list(result.registers)
                values[0] = 0
                written = client.write_registers(
                    SIM_OVERRIDE_MASK,
                    values,
                    slave=SLAVE_ID,
                )
                if written.isError():
                    raise RuntimeError(f"Virtual PLC rejected override reset: {written}")

            plc_call(clear)
            telemetry.add_event({
                "timestamp": _utc_now(),
                "source": "OT_COMMAND_CONSOLE",
                "machine_id": "M-01",
                "event_type": "SIMULATION_OVERRIDES_CLEARED",
                "parameter": "all",
                "old_value": "active overrides",
                "new_value": "process model",
                "severity": "info",
            })
            return jsonify({
                "status": "accepted",
                "message": "Simulation overrides cleared; process-model values will resume on subsequent ticks.",
            }), 202
        except (ConnectionError, RuntimeError) as error:
            app.logger.warning("Could not clear simulation overrides: %s", error)
            return jsonify({"error": str(error)}), 503
        except sqlite3.Error as error:
            app.logger.exception("Override reset could not be recorded")
            return jsonify({"error": f"Override reset audit failed: {error}"}), 503

    def legacy_submit_command():
        if not request.is_json:
            app.logger.warning("Rejected non-JSON OT command request")
            return jsonify({"error": "A JSON command request is required"}), 415
        if not _local_request():
            app.logger.warning("Rejected OT command request from non-loopback address")
            return jsonify({"error": "Commands are restricted to loopback clients"}), 403
        if not _valid_csrf():
            app.logger.warning("Rejected OT command request without a valid console token")
            return jsonify({"error": "Missing or invalid console request token"}), 403
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            payload = {}
        parameter = payload.get("parameter")
        raw_value = payload.get("value")
        reason = None
        if not isinstance(parameter, str) or parameter not in PARAMETERS:
            reason = "Choose temperature, pressure, power, or speed."
        elif isinstance(raw_value, bool) or not isinstance(raw_value, (int, float)):
            reason = "Value must be a finite JSON number."
        elif not math.isfinite(float(raw_value)):
            reason = "Value must be a finite JSON number."
        elif not PARAMETERS[parameter]["minimum"] <= float(raw_value) <= PARAMETERS[parameter]["maximum"]:
            spec = PARAMETERS[parameter]
            reason = (
                f"{parameter} must be between {spec['minimum']:g} and "
                f"{spec['maximum']:g} {spec['unit']}."
            )
        elif parameter == "speed" and not float(raw_value).is_integer():
            reason = "Speed must be a whole number of RPM."
        else:
            spec = PARAMETERS[parameter]
        if reason:
            try:
                _audit_rejection(parameter, raw_value, reason)
            except sqlite3.Error as error:
                app.logger.exception("Rejected command could not be recorded")
                return jsonify({"error": f"{reason} Audit record failed: {error}"}), 503
            app.logger.warning(
                "Rejected simulation command parameter=%s value=%s reason=%s",
                parameter,
                raw_value,
                reason,
            )
            return jsonify({"status": "rejected", "error": reason}), 400

        requested_value = float(raw_value)
        spec = PARAMETERS[parameter]
        command_id = secrets.token_urlsafe(12)
        submitted_at = _utc_now()
        telemetry_id_before = commands.telemetry_id()
        plc_accepted = False

        try:
            latest = commands.latest_telemetry()
            if parameter in SIMULATION_EVENT_PARAMETERS:
                if latest is None or not _is_fresh(latest["timestamp"]):
                    reason = "Fresh simulator telemetry is required for this test event."
                    _audit_rejection(parameter, requested_value, reason)
                    return jsonify({"status": "rejected", "error": reason}), 503
                registers = plc_call(_read_registers)
                if registers[EVENT_CODE] != 0:
                    reason = (
                        "The virtual PLC has a pending simulation event or is paused; "
                        "wait for it to clear or resume the simulator before submitting "
                        "another test event."
                    )
                    _audit_rejection(parameter, requested_value, reason)
                    app.logger.warning(
                        "Rejected simulation command parameter=%s value=%s reason=%s",
                        parameter,
                        requested_value,
                        reason,
                    )
                    return jsonify({"status": "rejected", "error": reason}), 409
                if parameter in ("temperature", "pressure"):
                    current_value = float(latest[spec["telemetry_key"]])
                    if requested_value < current_value:
                        reason = (
                            "The existing simulation event interface supports upward "
                            f"{parameter} stimuli only; requested value is below the "
                            "latest measured value."
                        )
                        _audit_rejection(parameter, requested_value, reason)
                        return jsonify({"status": "rejected", "error": reason}), 400
                    event_value = round(
                        (requested_value - current_value) * spec["increment_unit"]
                    )
                    if event_value == 0 and requested_value > current_value:
                        reason = (
                            f"{parameter.title()} test events have a minimum increment "
                            "of 0.1 engineering units."
                        )
                        _audit_rejection(parameter, requested_value, reason)
                        return jsonify({"status": "rejected", "error": reason}), 400
                elif parameter == "sensor_inconsistency":
                    event_value = 0
                else:
                    event_value = round(float(requested_value))

                def write_test_event(client):
                    result = client.write_registers(
                        EVENT_CODE,
                        [spec["event_code"], event_value],
                        slave=SLAVE_ID,
                    )
                    if result.isError():
                        raise RuntimeError(f"Virtual PLC rejected the test event: {result}")
            else:
                def write_test_event(client):
                    result = client.write_register(1, round(requested_value), slave=SLAVE_ID)
                    if result.isError():
                        raise RuntimeError(f"Virtual PLC rejected the RPM target: {result}")

            plc_call(write_test_event)
            plc_accepted = True
            commands.record(
                command_id,
                submitted_at,
                telemetry_id_before,
                parameter,
                requested_value,
                spec["unit"],
                "accepted",
                "Accepted by the loopback virtual PLC; waiting for a later telemetry sample.",
            )
            telemetry.add_event({
                "timestamp": submitted_at,
                "source": "OT_COMMAND_CONSOLE",
                "machine_id": "M-01",
                "event_type": "SIMULATION_COMMAND_ACCEPTED",
                "parameter": parameter,
                "old_value": latest.get(spec["telemetry_key"]) if latest else None,
                "new_value": requested_value,
                "severity": "info",
            })
            app.logger.info(
                "Accepted simulation command id=%s parameter=%s value=%s",
                command_id,
                parameter,
                requested_value,
            )
            return jsonify({
                "id": command_id,
                "status": "accepted",
                "parameter": parameter,
                "requested_value": requested_value,
                "unit": spec["unit"],
                "observed_value": None,
                "message": "Command accepted by the virtual PLC; measured telemetry is still pending.",
                "simulation_only": True,
            }), 202
        except (ConnectionError, RuntimeError) as error:
            try:
                _audit_rejection(parameter, requested_value, str(error))
            except sqlite3.Error:
                app.logger.exception("Failed command audit record could not be saved")
            app.logger.warning("Simulation command failed: %s", error)
            return jsonify({"status": "rejected", "error": str(error)}), 503
        except sqlite3.Error as error:
            app.logger.exception("Command request persistence failed")
            if not plc_accepted:
                return jsonify({
                    "status": "rejected",
                    "error": f"Command could not be audited and was not sent: {error}",
                }), 503
            return jsonify({
                "status": "accepted",
                "error": f"PLC accepted the command, but audit persistence failed: {error}",
            }), 503

    @app.post("/api/commands")
    def submit_command():
        if not request.is_json:
            return jsonify({"error": "A JSON command request is required"}), 415
        if not _local_request():
            return jsonify({"error": "Commands are restricted to loopback clients"}), 403
        if not _valid_csrf():
            return jsonify({"error": "Missing or invalid console request token"}), 403
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "A JSON object is required"}), 400

        parameter = payload.get("parameter")
        value = payload.get("value")
        if not isinstance(parameter, str) or parameter not in PARAMETERS:
            reason = "Choose temperature, pressure, power, or speed."
        elif isinstance(value, bool) or not isinstance(value, (int, float)):
            reason = "Value must be a finite JSON number."
        elif not math.isfinite(float(value)):
            reason = "Value must be a finite JSON number."
        else:
            spec = PARAMETERS[parameter]
            numeric_value = float(value)
            if not spec["minimum"] <= numeric_value <= spec["maximum"]:
                reason = (
                    f"{parameter} must be between {spec['minimum']:g} and "
                    f"{spec['maximum']:g} {spec['unit']}."
                )
            elif parameter == "speed" and not numeric_value.is_integer():
                reason = "Speed must be a whole number of RPM."
            else:
                reason = None
        if reason:
            try:
                _audit_rejection(parameter, value, reason)
            except sqlite3.Error as error:
                app.logger.exception("Rejected command could not be recorded")
                return jsonify({"error": f"{reason} Audit record failed: {error}"}), 503
            app.logger.warning(
                "Rejected simulation override parameter=%s value=%s reason=%s",
                parameter,
                value,
                reason,
            )
            return jsonify({"status": "rejected", "error": reason}), 400

        numeric_value = float(value)
        spec = PARAMETERS[parameter]
        command_id = secrets.token_urlsafe(12)
        submitted_at = _utc_now()
        telemetry_id_before = commands.telemetry_id()
        plc_accepted = False
        try:
            latest = commands.latest_telemetry()
            if latest is None or not _is_fresh(latest["timestamp"]):
                reason = "Fresh simulator telemetry is required to apply a value."
                _audit_rejection(parameter, numeric_value, reason)
                return jsonify({"status": "rejected", "error": reason}), 503

            plc_call(
                lambda client: write_override(
                    client,
                    parameter,
                    numeric_value,
                )
            )
            plc_accepted = True
            commands.record(
                command_id,
                submitted_at,
                telemetry_id_before,
                parameter,
                numeric_value,
                spec["unit"],
                "accepted",
                "Accepted by the loopback virtual PLC; waiting for the next telemetry sample.",
            )
            telemetry.add_event({
                "timestamp": submitted_at,
                "source": "OT_COMMAND_CONSOLE",
                "machine_id": "M-01",
                "event_type": "SIMULATION_VALUE_OVERRIDE",
                "parameter": parameter,
                "old_value": latest[spec["telemetry_key"]],
                "new_value": numeric_value,
                "severity": "info",
            })
            app.logger.info(
                "Accepted simulation override id=%s parameter=%s value=%s",
                command_id,
                parameter,
                numeric_value,
            )
            return jsonify({
                "id": command_id,
                "status": "accepted",
                "parameter": parameter,
                "requested_value": numeric_value,
                "unit": spec["unit"],
                "observed_value": None,
                "message": (
                    "Value accepted by the virtual PLC. The simulator will apply "
                    "it to telemetry and keep it active until changed or cleared."
                ),
                "simulation_only": True,
            }), 202
        except (ConnectionError, RuntimeError) as error:
            try:
                _audit_rejection(parameter, numeric_value, str(error))
            except sqlite3.Error:
                app.logger.exception("Failed command audit record could not be saved")
            app.logger.warning("Simulation override failed: %s", error)
            return jsonify({"status": "rejected", "error": str(error)}), 503
        except sqlite3.Error as error:
            app.logger.exception("Command request persistence failed")
            if not plc_accepted:
                return jsonify({
                    "status": "rejected",
                    "error": f"Command could not be audited and was not sent: {error}",
                }), 503
            return jsonify({
                "status": "accepted",
                "error": f"PLC accepted the command, but audit persistence failed: {error}",
            }), 503

    return app


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Start the loopback-only CHEM-SHIELD OT command testing console."
    )
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--plc-port", type=int, default=DEFAULT_PLC_PORT)
    parser.add_argument("--database", default=str(DEFAULT_DATABASE))
    args = parser.parse_args(argv)
    try:
        if args.host != DEFAULT_HOST:
            raise ValueError("OT Command Console must bind to 127.0.0.1")
        if not 1 <= args.port <= 65535:
            raise ValueError("Web port must be between 1 and 65535")
        if not 1 <= args.plc_port <= 65535:
            raise ValueError("PLC port must be between 1 and 65535")
        app = create_app(plc_port=args.plc_port, database=args.database)
        app.run(host=DEFAULT_HOST, port=args.port, debug=False)
    except ValueError as error:
        logging.getLogger(__name__).error("%s", error)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
