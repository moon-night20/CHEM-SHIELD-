"""Loopback-only, human-in-the-loop incident console."""

from __future__ import annotations

import argparse
import json
import ipaddress
import logging
import math
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, session, url_for
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.security import check_password_hash

from admin_part.detection.login_detector import failed_login_alerts
from admin_part.incident_data import load_chain_incidents
from chem_shield_common.incident_warnings import incident_warning_details
from admin_part.machine_client import (
    DEFAULT_HMI_URL,
    MachineClient,
    open_hmi_url,
    validate_hmi_url,
)
from admin_part.storage import (
    add_audit,
    audit_detail,
    count_recent_failures,
    get_statuses,
    initialize,
    list_audit,
    list_ot_audit,
    record_incident_action,
)
from admin_part.manage_users import ROLES


BASE_DIR = Path(__file__).resolve().parent
REPO_ROOT = BASE_DIR.parent
DEFAULT_ADMIN_HOST = "127.0.0.1"
DEFAULT_COMMAND_CONSOLE_URL = "http://127.0.0.1:5001"
MAX_FAILURES = 5
LOCKOUT_MINUTES = 5
SESSION_MINUTES = 20
ALLOWED_ACTIONS = {
    "acknowledge": "acknowledged",
    "escalate": "escalated",
    "false_positive": "false_positive",
    "simulated_response": "simulated_response_recorded",
}
NOTE_REQUIRED_ACTIONS = {"escalate", "false_positive", "simulated_response"}
ALL_ROLES = ("administrator", "analyst", "operator")
ANALYST_ROLES = ("administrator", "analyst")
RISK_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
LOGGER = logging.getLogger(__name__)


def _safe_hmi_url(value: str | None) -> str:
    return validate_hmi_url(value)


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
    except ValueError:
        return None


def _machine_risk_assessment(state: Any) -> dict[str, Any]:
    if not isinstance(state, dict):
        return {"risk_level": "UNAVAILABLE", "risk_score": None, "sensor": None}

    ratios = []
    for sensor, state_key in (
        ("temperature", "temperature"),
        ("pressure", "pressure"),
        ("power", "power"),
        ("speed", "rpm"),
    ):
        limits = state.get("limits")
        sensor_limits = limits.get(sensor) if isinstance(limits, dict) else None
        limit = sensor_limits.get("high") if isinstance(sensor_limits, dict) else None
        value = state.get(state_key)
        if (
            isinstance(limit, bool)
            or not isinstance(limit, (int, float))
            or limit <= 0
            or isinstance(value, bool)
            or not isinstance(value, (int, float))
        ):
            continue
        ratio = float(value) / float(limit)
        if math.isfinite(ratio) and ratio >= 0:
            ratios.append((ratio, sensor))

    if not ratios:
        return {"risk_level": "UNAVAILABLE", "risk_score": None, "sensor": None}

    score, sensor = max(ratios)
    if score > 1.0:
        level = "CRITICAL"
    elif score < 0.75:
        level = "NORMAL"
    else:
        level = "MEDIUM"
    return {
        "risk_level": level,
        "risk_score": round(score, 3),
        "sensor": sensor,
    }


def _time_windows_overlap(first: dict[str, Any], second: dict[str, Any]) -> bool:
    if first.get("asset_id") != second.get("asset_id"):
        return False
    first_start = _parse_timestamp(first.get("start_time"))
    first_end = _parse_timestamp(first.get("end_time"))
    second_start = _parse_timestamp(second.get("start_time"))
    second_end = _parse_timestamp(second.get("end_time"))
    return bool(
        first_start
        and first_end
        and second_start
        and second_end
        and first_start <= second_end
        and second_start <= first_end
    )


def server_options(environ: dict[str, str] | None = None) -> dict[str, Any]:
    values = os.environ if environ is None else environ
    host = values.get("CHEM_SHIELD_ADMIN_HOST", DEFAULT_ADMIN_HOST).strip()
    try:
        port = int(values.get("CHEM_SHIELD_ADMIN_PORT", "5000"))
    except ValueError as error:
        raise ValueError("CHEM_SHIELD_ADMIN_PORT must be an integer from 1 to 65535") from error
    if not 1 <= port <= 65535:
        raise ValueError("CHEM_SHIELD_ADMIN_PORT must be an integer from 1 to 65535")
    allow_remote = values.get("CHEM_SHIELD_ALLOW_REMOTE") == "1"
    try:
        is_loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError as error:
        raise ValueError("CHEM_SHIELD_ADMIN_HOST must be a loopback IP or localhost") from error
    secret_key = values.get("CHEM_SHIELD_SECRET_KEY", "")
    if not is_loopback and not allow_remote:
        raise ValueError(
            "Refusing non-loopback admin bind; set CHEM_SHIELD_ALLOW_REMOTE=1 only for a protected lab"
        )
    if not is_loopback:
        if not secret_key:
            raise ValueError(
                "CHEM_SHIELD_SECRET_KEY must be explicitly set before allowing a remote bind"
            )
        LOGGER.critical(
            "REMOTE ADMIN CONSOLE ENABLED on %s. Lab use only; secure HTTPS, firewall, and "
            "trusted network controls are required. Never expose this service to the internet.",
            host,
        )
    return {
        "host": host,
        "port": port,
        "debug": values.get("CHEM_SHIELD_DEBUG") == "1",
        "secret_key": secret_key or None,
        "cookie_secure": values.get("CHEM_SHIELD_COOKIE_SECURE") == "1",
        "remote": not is_loopback,
    }


def _load_users(path: Path) -> dict[str, dict[str, Any]]:
    if not path.is_file():
        return {}
    with path.open(encoding="utf-8") as stream:
        payload = json.load(stream)
    if not isinstance(payload, dict):
        raise ValueError("users.json must contain a JSON object")
    return {
        name: user for name, user in payload.items()
        if isinstance(name, str) and isinstance(user, dict)
    }


def _read_login_events(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    events: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict):
                events.append(event)
    return events


def _append_login_event(path: Path, event: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, ensure_ascii=True) + "\n")


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__)
    generated_secret = not bool(os.environ.get("CHEM_SHIELD_SECRET_KEY"))
    secret_key = os.environ.get("CHEM_SHIELD_SECRET_KEY") or secrets.token_hex(32)
    app.config.from_mapping(
        SECRET_KEY=secret_key,
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=SESSION_MINUTES),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("CHEM_SHIELD_COOKIE_SECURE") == "1",
        WTF_CSRF_ENABLED=True,
        WTF_CSRF_TIME_LIMIT=3600,
        ADMIN_DB_PATH=BASE_DIR / "data" / "admin.db",
        OT_DATABASE_PATH=REPO_ROOT / "chem_shield_p1" / "data" / "telemetry.db",
        USERS_FILE=BASE_DIR / "data" / "users.json",
        LOGIN_EVENTS_FILE=BASE_DIR / "data" / "events" / "login_events.jsonl",
        P4_OUTPUT_FILE=REPO_ROOT / "out" / "p4_incidents.json",
        P5_OUTPUT_FILE=REPO_ROOT / "out" / "p5_report.json",
        HMI_URL=_safe_hmi_url(os.environ.get("CHEM_SHIELD_HMI_URL")),
        MACHINE_CLIENT=None,
    )
    if test_config:
        app.config.update(test_config)
    if generated_secret and not test_config:
        app.logger.warning(
            "CHEM_SHIELD_SECRET_KEY is unset; a random key was generated. "
            "Sessions will reset when the admin console restarts."
        )

    app.config["ADMIN_DB_PATH"] = Path(app.config["ADMIN_DB_PATH"])
    app.config["OT_DATABASE_PATH"] = Path(app.config["OT_DATABASE_PATH"])
    app.config["USERS_FILE"] = Path(app.config["USERS_FILE"])
    app.config["LOGIN_EVENTS_FILE"] = Path(app.config["LOGIN_EVENTS_FILE"])
    app.config["P4_OUTPUT_FILE"] = Path(app.config["P4_OUTPUT_FILE"])
    app.config["P5_OUTPUT_FILE"] = Path(app.config["P5_OUTPUT_FILE"])
    app.config["HMI_URL"] = _safe_hmi_url(str(app.config["HMI_URL"]))
    initialize(app.config["ADMIN_DB_PATH"])
    CSRFProtect(app)
    app.extensions["machine_client"] = (
        app.config["MACHINE_CLIENT"] or MachineClient(app.config["HMI_URL"])
    )

    @app.context_processor
    def shared_template_context():
        return {
            "hmi_url": app.config["HMI_URL"],
            "command_console_url": DEFAULT_COMMAND_CONSOLE_URL,
        }

    def audit(
        action: str,
        *,
        username: str | None = None,
        role: str | None = None,
        incident_id: str | None = None,
        detail: str = "",
    ) -> None:
        add_audit(
            app.config["ADMIN_DB_PATH"],
            username=username or str(session.get("username", "anonymous")),
            role=role or str(session.get("role", "anonymous")),
            source_ip=request.remote_addr or "unknown",
            action=action,
            incident_id=incident_id,
            detail=detail,
        )

    def role_required(*roles: str) -> Callable:
        allowed_roles = set(roles)

        def decorate(view: Callable) -> Callable:
            @wraps(view)
            def wrapped(*args: Any, **kwargs: Any):
                username = session.get("username")
                role = session.get("role")
                if not username:
                    return redirect(url_for("login", next=request.path))
                if role not in allowed_roles:
                    audit(
                        "forbidden_access",
                        detail=audit_detail(path=request.path, endpoint=request.endpoint),
                    )
                    app.logger.warning(
                        "Forbidden admin-console access: user=%s role=%s path=%s",
                        username,
                        role,
                        request.path,
                    )
                    return render_template(
                        "message.html",
                        title="403 - Forbidden",
                        message="Your role is not permitted to access this page.",
                    ), 403
                return view(*args, **kwargs)

            return wrapped

        return decorate

    def current_incidents() -> tuple[list[dict[str, Any]], list[str], str | None, str]:
        chain_incidents, errors, updated = load_chain_incidents(
            app.config["P4_OUTPUT_FILE"], app.config["P5_OUTPUT_FILE"]
        )
        hmi_result = app.extensions["machine_client"].get("incidents")
        if not hmi_result["ok"]:
            incidents = chain_incidents
            source_label = "from last chain run (HMI offline)"
        else:
            payload = hmi_result["data"]
            hmi_incidents = payload.get("incidents") if isinstance(payload, dict) else payload
            if not isinstance(hmi_incidents, list) or any(
                not isinstance(item, dict) for item in hmi_incidents
            ):
                app.logger.warning("Machine HMI returned an invalid incident list; using chain output")
                incidents = chain_incidents
                source_label = "from last chain run (HMI offline)"
            else:
                incidents = []
                source_label = "live from machine HMI"
                for machine_incident in hmi_incidents:
                    match = next(
                        (
                            item
                            for item in chain_incidents
                            if _time_windows_overlap(machine_incident, item)
                        ),
                        {},
                    )
                    events = machine_incident.get("events", [])
                    if not isinstance(events, list):
                        events = []
                    counts = {
                        "network": 0,
                        "physical": 0,
                    }
                    for event in events:
                        if not isinstance(event, dict):
                            continue
                        event_type = str(event.get("event_type", "")).lower()
                        source = str(event.get("source", "")).lower()
                        if event_type == "network" or "network" in source:
                            counts["network"] += 1
                        if event_type == "physical" or "physical" in source or "ot_monitor" in source:
                            counts["physical"] += 1
                    status = str(machine_incident.get("status", "ACTIVE")).lower()
                    p5_report = match.get("p5", {})
                    confirmation = p5_report.get("rule_confirmation")
                    incidents.append({
                        **machine_incident,
                        "events": events,
                        "event_counts": counts,
                        "status_record": {
                            "status": status,
                            "updated_by": machine_incident.get("acknowledged_by", ""),
                            "updated_at": machine_incident.get("acknowledged_at", ""),
                            "note": "",
                        },
                        "p5": p5_report,
                        "rule_confirmation": confirmation if isinstance(confirmation, bool) else None,
                        "chain_events": match.get("events", []),
                        "chain_incident_id": match.get("incident_id"),
                    })
        statuses = get_statuses(app.config["ADMIN_DB_PATH"])
        for incident in incidents:
            local_status = statuses.get(incident["incident_id"])
            if local_status:
                incident["status_record"] = local_status
            else:
                incident.setdefault("status_record", {
                    "status": "new",
                    "updated_by": "",
                    "updated_at": "",
                    "note": "",
                })
            incident.setdefault("chain_events", [])
            incident["warning_details"] = incident_warning_details(incident)
            p5_report = incident.get("p5", {})
            confirmation = p5_report.get("rule_confirmation")
            incident["rule_confirmation"] = confirmation if isinstance(confirmation, bool) else None
            incident["source_label"] = source_label
        if source_label == "live from machine HMI":
            errors = []
        return incidents, errors, updated, source_label

    def post_hmi_acknowledgement(incident_id: str, username: str) -> tuple[bool, str | None]:
        from urllib.parse import quote

        endpoint = (
            f"{app.config['HMI_URL']}/api/incidents/"
            f"{quote(incident_id, safe='')}/acknowledge"
        )
        request_body = json.dumps({"acknowledged_by": username}).encode("utf-8")
        hmi_request = Request(
            endpoint,
            data=request_body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with open_hmi_url(hmi_request, timeout=2.0) as response:
                if response.status < 200 or response.status >= 300:
                    return False, f"Machine HMI returned HTTP {response.status}"
                return True, None
        except (HTTPError, URLError, OSError, TimeoutError, ValueError) as error:
            app.logger.warning("HMI acknowledgement failed for %s: %s", incident_id, error)
            return False, str(error)

    def record_auth_event(username: str, event_type: str, result: str) -> None:
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        source_ip = request.remote_addr or "unknown"
        add_audit(
            app.config["ADMIN_DB_PATH"],
            username=username or "unknown",
            role=str(session.get("role", "anonymous")),
            source_ip=source_ip,
            action=event_type,
            detail=result,
            timestamp=timestamp,
        )
        _append_login_event(
            app.config["LOGIN_EVENTS_FILE"],
            {
                "timestamp": timestamp,
                "username": username or "unknown",
                "source_ip": source_ip,
                "event_type": event_type,
                "result": result,
            },
        )

    def render_login(status_code: int = 200):
        try:
            account_setup_required = not bool(
                _load_users(app.config["USERS_FILE"])
            )
        except (OSError, json.JSONDecodeError, ValueError):
            app.logger.exception("Admin-console user store is unavailable")
            return render_template(
                "login.html",
                account_setup_error=True,
                account_setup_required=False,
            ), 503
        return render_template(
            "login.html",
            account_setup_required=account_setup_required,
            account_setup_error=False,
        ), status_code

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; base-uri 'self'; form-action 'self'; "
            "frame-ancestors 'none'; object-src 'none'; style-src 'self'; "
            "script-src 'self'; img-src 'self'; connect-src 'self'"
        )
        return response

    @app.errorhandler(CSRFError)
    def csrf_error(_error: CSRFError):
        app.logger.info("Rejected request with an invalid or missing CSRF token: %s", _error.description)
        return render_template(
            "message.html",
            title="400 - Request rejected",
            message="The form security token is missing or expired. Reload the page and try again.",
        ), 400

    @app.errorhandler(404)
    def not_found(_error):
        app.logger.debug("Admin-console route returned %s", _error.code)
        return render_template(
            "message.html", title="404 - Not found", message="That incident or page was not found."
        ), 404

    @app.route("/", methods=["GET", "POST"])
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if session.get("username"):
            return redirect(url_for("dashboard"))
        if request.method == "GET":
            return render_login()

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        source_ip = request.remote_addr or "unknown"
        cutoff = (
            datetime.now(timezone.utc) - timedelta(minutes=LOCKOUT_MINUTES)
        ).isoformat(timespec="seconds")
        try:
            failures = count_recent_failures(
                app.config["ADMIN_DB_PATH"],
                username=username,
                source_ip=source_ip,
                since=cutoff,
            )
            users = _load_users(app.config["USERS_FILE"])
            user = users.get(username)
            valid = (
                failures < MAX_FAILURES
                and isinstance(user, dict)
                and isinstance(user.get("password_hash"), str)
                and user.get("role") in ROLES
                and check_password_hash(user["password_hash"], password)
            )
        except (OSError, json.JSONDecodeError, sqlite3.Error, ValueError):
            app.logger.exception("Admin-console login data is unavailable")
            valid = False
            user = None
            failures = 0

        if not valid:
            record_auth_event(username or "unknown", "login_failure", "failure")
            flash("Invalid username or password.", "error")
            return render_login(401)

        session.clear()
        session.permanent = True
        session["username"] = username
        session["role"] = user["role"]
        record_auth_event(username, "login_success", "success")
        return redirect(url_for("dashboard"))

    @app.post("/logout")
    @role_required(*ALL_ROLES)
    def logout():
        record_auth_event(session["username"], "logout", "success")
        session.clear()
        return redirect(url_for("login"))

    @app.get("/dashboard")
    @role_required(*ALL_ROLES)
    def dashboard():
        try:
            incidents, errors, updated, source_label = current_incidents()
            if session["role"] == "operator":
                incidents = [
                    incident for incident in incidents
                    if incident["event_counts"]["physical"] > 0
                ]
            counts = {
                level: sum(incident.get("risk_level") == level for incident in incidents)
                for level in RISK_LEVELS
            }
            login_alerts = (
                failed_login_alerts(_read_login_events(app.config["LOGIN_EVENTS_FILE"]))
                if session["role"] in ANALYST_ROLES
                else []
            )
        except (OSError, sqlite3.Error, ValueError, TypeError) as error:
            app.logger.exception("Admin dashboard could not load its data")
            incidents, errors, updated, login_alerts = [], [str(error)], None, []
            source_label = "unavailable"
            counts = {level: 0 for level in RISK_LEVELS}
        return render_template(
            "dashboard.html",
            incidents=incidents,
            errors=errors,
            chain_updated=updated,
            counts=counts,
            login_alerts=login_alerts,
            username=session["username"],
            role=session["role"],
            can_act=session["role"] in ANALYST_ROLES,
            hmi_url=app.config["HMI_URL"],
            source_label=source_label,
        )

    @app.get("/api/live")
    @role_required(*ALL_ROLES)
    def live_api():
        live = app.extensions["machine_client"].live()
        state = live.get("state", {})
        state_data = state.get("data") if isinstance(state, dict) and state.get("ok") else None
        live["machine_risk"] = _machine_risk_assessment(state_data)
        return jsonify(live)

    @app.get("/machine")
    @role_required(*ALL_ROLES)
    def machine():
        return render_template(
            "machine.html",
            hmi_url=app.config["HMI_URL"],
            username=session["username"],
            role=session["role"],
        )

    @app.get("/incidents")
    @role_required(*ALL_ROLES)
    def incidents_page():
        try:
            incidents, errors, updated, source_label = current_incidents()
            if session["role"] == "operator":
                incidents = [
                    incident for incident in incidents
                    if incident["event_counts"]["physical"] > 0
                ]
        except (OSError, sqlite3.Error, ValueError, TypeError) as error:
            app.logger.exception("Incident list could not load")
            incidents, errors, updated, source_label = [], [str(error)], None, "unavailable"
        return render_template(
            "incidents.html",
            incidents=incidents,
            errors=errors,
            chain_updated=updated,
            username=session["username"],
            role=session["role"],
            hmi_url=app.config["HMI_URL"],
            source_label=source_label,
        )

    @app.get("/incidents/<incident_id>")
    @role_required(*ALL_ROLES)
    def incident_detail(incident_id: str):
        incidents, errors, updated, _ = current_incidents()
        incident = next(
            (item for item in incidents if item["incident_id"] == incident_id), None
        )
        if incident is None:
            abort(404)
        if session["role"] == "operator" and incident["event_counts"]["physical"] == 0:
            abort(404)
        telemetry_result = app.extensions["machine_client"].get("telemetry")
        telemetry_rows = telemetry_result.get("data") if telemetry_result["ok"] else []
        if not isinstance(telemetry_rows, list):
            telemetry_rows = []
        start_time = _parse_timestamp(incident.get("start_time"))
        end_time = _parse_timestamp(incident.get("end_time"))
        machine_context = [
            row for row in telemetry_rows
            if isinstance(row, dict)
            and start_time is not None
            and end_time is not None
            and (timestamp := _parse_timestamp(row.get("timestamp"))) is not None
            and start_time <= timestamp <= end_time
        ]
        return render_template(
            "incident.html",
            incident=incident,
            errors=errors,
            chain_updated=updated,
            username=session["username"],
            role=session["role"],
            can_act=session["role"] in ANALYST_ROLES,
            machine_context=machine_context,
            machine_context_online=telemetry_result["ok"],
        )

    @app.post("/incidents/<incident_id>/action")
    @role_required(*ANALYST_ROLES)
    def incident_action(incident_id: str):
        action = request.form.get("action", "")
        if action not in ALLOWED_ACTIONS:
            return render_template(
                "message.html", title="400 - Invalid action", message="Unknown incident action."
            ), 400
        note = request.form.get("note", "").strip()
        if action in NOTE_REQUIRED_ACTIONS and len(note) < 5:
            return render_template(
                "message.html",
                title="400 - Note required",
                message="Please provide a note of at least 5 characters for this action.",
            ), 400
        incidents, _, _, _ = current_incidents()
        if not any(incident["incident_id"] == incident_id for incident in incidents):
            abort(404)

        status = ALLOWED_ACTIONS[action]
        hmi_ack_error = None
        if action == "acknowledge":
            acknowledged, hmi_ack_error = post_hmi_acknowledgement(
                incident_id, session["username"]
            )
            if not acknowledged:
                flash(
                    "Machine HMI is offline or could not record the acknowledgement; "
                    "the decision was recorded in the local admin log.",
                    "warning",
                )
        detail = audit_detail(action=action, note=note)
        record_incident_action(
            app.config["ADMIN_DB_PATH"],
            incident_id=incident_id,
            status=status,
            updated_by=session["username"],
            note=note,
            role=session["role"],
            source_ip=request.remote_addr or "unknown",
            action=f"incident_{action}",
            detail=detail,
        )
        flash(
            "Simulation only - recorded, nothing is executed."
            if action == "simulated_response"
            else f"Incident marked {status.replace('_', ' ')}."
            if not hmi_ack_error
            else "Local decision recorded; machine acknowledgement remains pending.",
            "success",
        )
        return redirect(url_for("incident_detail", incident_id=incident_id))

    @app.get("/audit")
    @role_required("administrator")
    def audit_page():
        user_filter = request.args.get("user", "").strip()[:64]
        action_filter = request.args.get("action", "").strip()[:64]
        entries = list_audit(
            app.config["ADMIN_DB_PATH"],
            username=user_filter,
            action=action_filter,
        )
        ot_entries = list_ot_audit(app.config["OT_DATABASE_PATH"])
        if user_filter:
            ot_entries = [
                entry for entry in ot_entries
                if user_filter.casefold() in entry["username"].casefold()
            ]
        if action_filter:
            ot_entries = [
                entry for entry in ot_entries
                if action_filter.casefold() in entry["action"].casefold()
            ]
        entries = sorted(
            [*entries, *ot_entries],
            key=lambda entry: entry["timestamp"],
            reverse=True,
        )[:500]
        return render_template(
            "audit.html",
            entries=entries,
            user_filter=user_filter,
            action_filter=action_filter,
            username=session["username"],
            role=session["role"],
        )

    @app.get("/users")
    @role_required("administrator")
    def users_page():
        try:
            users = [
                {"username": username, "role": record.get("role", "invalid")}
                for username, record in sorted(_load_users(app.config["USERS_FILE"]).items())
            ]
            error = None
        except (OSError, json.JSONDecodeError, ValueError) as exception:
            app.logger.exception("Admin user list could not be loaded")
            users, error = [], f"User list unavailable: {exception}"
        return render_template(
            "users.html", users=users, error=error,
            username=session["username"], role=session["role"],
        )

    @app.get("/settings")
    @role_required("administrator")
    def settings():
        return render_template(
            "settings.html",
            ingest_token_enabled=True,
            username=session["username"],
            role=session["role"],
        )

    return app


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CHEM-SHIELD local admin console")
    parser.add_argument("--port", type=int, default=None)
    args = parser.parse_args()
    options = server_options()
    application = create_app()
    if options["secret_key"]:
        application.config["SECRET_KEY"] = options["secret_key"]
    application.config["SESSION_COOKIE_SECURE"] = options["cookie_secure"]
    port = args.port if args.port is not None else options["port"]
    if not 1 <= port <= 65535:
        parser.error("--port must be an integer from 1 to 65535")
    application.run(
        host=options["host"],
        port=port,
        debug=options["debug"],
    )
