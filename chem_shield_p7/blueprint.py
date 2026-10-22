"""Authenticated Admin routes for the additive Part 7 Command Center."""

from __future__ import annotations

import ipaddress
import json
import re
import uuid
from pathlib import Path
from typing import Any

from flask import Blueprint, abort, current_app, flash, jsonify, redirect, render_template, request, send_file, session, url_for

from admin_part.storage import add_audit
from chem_shield_p7.audit_chain.chain import verify_chain
from chem_shield_p7.command_center import calculate_posture_score
from chem_shield_p7.report.generator import REPORT_ID_PATTERN, generate_report
from chem_shield_p7.scenarios.library import SCENARIOS, SENSOR_LIMITS, get_scenario
from chem_shield_p7.scenarios.runner import ScenarioRunner
from chem_shield_p7.timeline.mitre_map import techniques_for
from chem_shield_p7.timeline.store import TimelineStore

RUN_ID_PATTERN = re.compile(r"^[a-f0-9]{32}$")
P7_ROLES = {"administrator", "analyst", "operator"}


def _loopback(remote_addr: str | None) -> bool:
    if not remote_addr:
        return False
    try:
        return ipaddress.ip_address(remote_addr).is_loopback
    except ValueError:
        return remote_addr.casefold() == "localhost"


def _configured_limits() -> dict[str, float]:
    path = current_app.config.get("P7_LIMITS_FILE")
    if path:
        with Path(path).open(encoding="utf-8") as stream:
            config = json.load(stream)
        rules = config.get("rules", {}).get("limits", {})
        limits = {
            key: float(rules[key]["high"])
            for key in ("temperature", "pressure", "power", "speed")
            if isinstance(rules.get(key), dict) and rules[key].get("high") is not None
        }
        if len(limits) == 4:
            return limits
    return dict(SENSOR_LIMITS)


def _latest_run(store: TimelineStore, requested_id: str | None = None) -> dict[str, Any] | None:
    if requested_id:
        if not RUN_ID_PATTERN.fullmatch(requested_id):
            abort(400)
        run = store.get_run(requested_id)
        if run is None:
            abort(404)
        return run
    return store.latest_run()


def _machine_data(name: str) -> tuple[bool, Any]:
    result = current_app.extensions["machine_client"].get(name)
    return bool(result.get("ok")), result.get("data")


def _incident_report_source(incident_id: str) -> dict[str, Any]:
    ok, data = _machine_data("incidents")
    if not ok:
        abort(503, description="Machine incident history is unavailable.")
    if isinstance(data, list):
        incidents = data
    elif isinstance(data, dict):
        incidents = list(data.get("active_incidents", [])) + list(data.get("recent_incidents", []))
    else:
        incidents = []
    incident = next(
        (item for item in incidents if isinstance(item, dict) and item.get("incident_id") == incident_id),
        None,
    )
    if incident is None:
        abort(404)
    started = incident.get("start_time") or incident.get("created_at")
    events = []
    peak_readings: dict[str, float] = {}
    for source_event in incident.get("events", []):
        if not isinstance(source_event, dict):
            continue
        evidence = source_event.get("evidence")
        evidence = evidence if isinstance(evidence, dict) else {}
        sensor = evidence.get("sensor")
        value = evidence.get("value")
        if sensor in {"temperature", "pressure", "power", "speed"} and isinstance(value, (int, float)):
            peak_readings[sensor] = max(float(value), peak_readings.get(sensor, float("-inf")))
        events.append({
            "event_type": "DETECTED",
            "timestamp": source_event.get("timestamp") or incident.get("last_event_time") or started,
            "source": source_event.get("source", "Part 4 incident store"),
            "detector": evidence.get("detection_method") or evidence.get("rule_id", ""),
            "detail": {
                "sensor": sensor,
                "value": value,
                "message": evidence.get("message") or evidence.get("detail"),
            },
            "mitre": techniques_for("overheat") if sensor else [],
        })
    return {
        "run_id": uuid.uuid4().hex,
        "scenario_name": f"Incident {incident_id}",
        "scenario_id": "incident-report",
        "status": incident.get("status", "HISTORICAL"),
        "outcome": incident.get("resolved_reason") or incident.get("risk_level", "Incident recorded"),
        "started_at": started or "",
        "ended_at": incident.get("end_time") or incident.get("last_event_time"),
        "detected_at": incident.get("last_event_time"),
        "responded_at": incident.get("acknowledged_at"),
        "automatic_stop": incident.get("resolved_reason") == "automatic simulated stop",
        "peak_readings": peak_readings,
        "events": events,
    }, incident


def create_blueprint(admin_app) -> Blueprint:
    """Create a Part 7 blueprint using the Admin app's existing security config."""
    blueprint = Blueprint(
        "p7",
        __name__,
        template_folder=str(Path(__file__).resolve().parents[1] / "admin_part" / "templates"),
    )
    database = str(admin_app.config["ADMIN_DB_PATH"])
    store = TimelineStore(database)
    report_dir = Path(admin_app.config.get("P7_REPORT_DIR", Path(__file__).resolve().parents[1] / "out" / "reports"))
    outbox_path = Path(admin_app.config.get("P7_OUTBOX_PATH", Path(__file__).resolve().parents[1] / "out" / "outbox.log"))
    audit_callback = lambda **fields: add_audit(database, **fields)
    runner = ScenarioRunner(
        store,
        admin_database=database,
        report_dir=str(report_dir),
        audit=audit_callback,
        outbox_path=str(outbox_path),
    )
    admin_app.extensions["p7_timeline_store"] = store
    admin_app.extensions["p7_scenario_runner"] = runner

    @blueprint.before_request
    def protect_part7():
        if not _loopback(request.remote_addr):
            return jsonify({"error": "Part 7 is available only to loopback clients."}), 403
        if session.get("role") not in P7_ROLES or not session.get("username"):
            return redirect(url_for("login", next=request.path))
        return None

    @blueprint.get("/scenarios")
    def scenarios_page():
        return render_template(
            "p7_scenarios.html",
            username=session["username"],
            role=session["role"],
            scenarios=SCENARIOS,
        )

    @blueprint.get("/api/scenarios")
    def scenarios_api():
        return jsonify({"scenarios": SCENARIOS, "active": runner.status()})

    @blueprint.post("/scenarios/<scenario_id>/run")
    def run_scenario(scenario_id: str):
        if session.get("role") not in {"administrator", "analyst"}:
            return jsonify({"error": "Analyst or administrator access is required."}), 403
        try:
            get_scenario(scenario_id)
            run_id = runner.start(scenario_id)
        except ValueError as error:
            if not request.is_json:
                flash(str(error), "error")
                return redirect(url_for("p7.scenarios_page"))
            return jsonify({"error": str(error)}), 400
        except RuntimeError as error:
            if not request.is_json:
                flash(str(error), "error")
                return redirect(url_for("p7.scenarios_page"))
            return jsonify({"error": str(error)}), 409
        if not request.is_json:
            return redirect(url_for("p7.timeline_page", run_id=run_id))
        return jsonify({"ok": True, "run_id": run_id}), 202

    @blueprint.post("/scenarios/abort")
    def abort_scenario():
        if not runner.abort():
            return jsonify({"error": "No scenario is running."}), 409
        return jsonify({"ok": True, "status": "ABORTING"}), 202

    @blueprint.get("/scenarios/status")
    def scenario_status():
        status = runner.status()
        run = store.get_run(status.get("run_id")) if status.get("run_id") else store.latest_run()
        return jsonify({"runner": status, "run": run})

    @blueprint.get("/timeline")
    def timeline_page():
        run_id = request.args.get("run_id")
        run = _latest_run(store, run_id) if run_id else store.latest_run()
        return render_template(
            "p7_timeline.html",
            username=session["username"],
            role=session["role"],
            run=run,
        )

    @blueprint.get("/api/timeline")
    def timeline_api():
        run_id = request.args.get("run_id")
        run = _latest_run(store, run_id) if run_id else store.latest_run()
        return jsonify({"run": run, "runner": runner.status()})

    @blueprint.get("/api/command-center")
    def command_center_api():
        state_ok, state = _machine_data("state")
        risk_ok, risk = _machine_data("risk")
        state = state if isinstance(state, dict) else {}
        risk = risk if isinstance(risk, dict) else {}
        run = store.latest_run()
        integrity = verify_chain(database)
        limits = _configured_limits()
        readings = {
            "temperature": state.get("temperature"),
            "pressure": state.get("pressure"),
            "power": state.get("power"),
            "speed": state.get("rpm"),
        }
        active_levels = {
            item.get("risk_level")
            for item in risk.get("active_incidents", [])
            if isinstance(item, dict)
        }
        condition = "UNAVAILABLE"
        if state_ok:
            if state.get("machine_condition") == "CRITICAL" or risk.get("risk_level") == "CRITICAL":
                condition = "CRITICAL"
            elif active_levels.intersection({"HIGH", "MEDIUM"}) or risk.get("risk_level") in {"HIGH", "MEDIUM"}:
                condition = "WARNING"
            elif state.get("motor_status") == "STOPPED":
                condition = "STOPPED"
            else:
                condition = "NORMAL"
        return jsonify({
            "ok": state_ok and risk_ok,
            "machine": {
                "condition": condition,
                "motor_status": state.get("motor_status", "UNAVAILABLE"),
                "readings": readings,
                "limits": limits,
                "limit_alerts": state.get("limit_alerts", []),
            },
            "risk": risk,
            "runner": runner.status(),
            "run": run,
            "runs": store.recent_runs(),
            "scenarios": SCENARIOS,
            "posture": calculate_posture_score(run, integrity),
            "audit_integrity": integrity,
            "outbox": _read_outbox(outbox_path),
        })

    @blueprint.get("/command-center")
    def command_center_page():
        return render_template(
            "p7_command_center.html",
            username=session["username"],
            role=session["role"],
        )

    @blueprint.get("/integrity")
    def integrity_page():
        return render_template(
            "p7_integrity.html",
            username=session["username"],
            role=session["role"],
            result=verify_chain(database),
        )

    @blueprint.get("/audit/verify")
    def verify_audit_api():
        return jsonify(verify_chain(database))

    @blueprint.post("/reports")
    def create_report():
        payload = request.get_json(silent=True) if request.is_json else request.form
        payload = payload or {}
        run_id = str(payload.get("run_id", "")).strip()
        incident_id = str(payload.get("incident_id", "")).strip()
        if run_id:
            run = _latest_run(store, run_id)
            if run is None:
                abort(404)
        elif incident_id:
            run, _incident = _incident_report_source(incident_id)
        else:
            run = store.latest_run()
            if run is None:
                abort(404)
        peaks: dict[str, float] = dict(run.get("peak_readings") or {})
        report_id = uuid.uuid4().hex
        path = generate_report(
            report_id,
            run,
            output_dir=report_dir,
            limits=_configured_limits(),
            peak_readings=peaks,
            audit_status=verify_chain(database),
        )
        add_audit(
            database,
            username=session["username"],
            role=session["role"],
            source_ip=request.remote_addr or "127.0.0.1",
            action="p7_report_generated",
            detail=f"Report {report_id} generated for run {run.get('run_id')}.",
        )
        current_app.logger.info("Part 7 report generated: %s", path.name)
        if request.is_json:
            return jsonify({"ok": True, "report_id": report_id, "url": url_for("p7.report_file", report_id=report_id)})
        return redirect(url_for("p7.report_file", report_id=report_id))

    @blueprint.get("/reports/<report_id>")
    def report_file(report_id: str):
        if not REPORT_ID_PATTERN.fullmatch(report_id):
            abort(404)
        base = report_dir.resolve()
        path = (base / f"{report_id}.html").resolve()
        if path.parent != base or not path.is_file():
            abort(404)
        return send_file(
            path,
            mimetype="text/html",
            as_attachment=False,
            download_name="chem-shield-incident-report.html",
        )

    return blueprint


def _read_outbox(path: Path) -> list[str]:
    """Return the last local mock notifications without contacting any service."""
    if not path.is_file():
        return []
    with path.open(encoding="utf-8") as stream:
        return [line.rstrip("\r\n") for line in stream.readlines()[-10:]]
