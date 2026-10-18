"""Loopback-only, human-in-the-loop incident console."""

from __future__ import annotations

import json
import ipaddress
import logging
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Callable
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import urlopen

from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.security import check_password_hash

from admin_part.detection.login_detector import failed_login_alerts
from admin_part.incident_data import load_chain_incidents
from admin_part.storage import (
    add_audit,
    audit_detail,
    count_recent_failures,
    get_statuses,
    initialize,
    list_audit,
    record_incident_action,
)
from admin_part.manage_users import ROLES


BASE_DIR = Path(__file__).resolve().parent
REPO_ROOT = BASE_DIR.parent
DEFAULT_HMI_URL = "http://127.0.0.1:15000"
DEFAULT_ADMIN_HOST = "127.0.0.1"
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
    if value:
        try:
            parsed = urlsplit(value.strip())
            if (
                parsed.scheme in {"http", "https"}
                and parsed.netloc
                and parsed.hostname
                and not parsed.username
                and not parsed.password
                and not parsed.query
                and not parsed.fragment
            ):
                return value.strip().rstrip("/")
        except ValueError:
            pass
    if value:
        LOGGER.warning("Invalid CHEM_SHIELD_HMI_URL; using %s", DEFAULT_HMI_URL)
    return DEFAULT_HMI_URL


def server_options(environ: dict[str, str] | None = None) -> dict[str, Any]:
    values = os.environ if environ is None else environ
    host = values.get("CHEM_SHIELD_ADMIN_HOST", DEFAULT_ADMIN_HOST).strip()
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
        USERS_FILE=BASE_DIR / "data" / "users.json",
        LOGIN_EVENTS_FILE=BASE_DIR / "data" / "events" / "login_events.jsonl",
        P4_OUTPUT_FILE=REPO_ROOT / "out" / "p4_incidents.json",
        P5_OUTPUT_FILE=REPO_ROOT / "out" / "p5_report.json",
        HMI_URL=_safe_hmi_url(os.environ.get("CHEM_SHIELD_HMI_URL")),
    )
    if test_config:
        app.config.update(test_config)
    if generated_secret and not test_config:
        app.logger.warning(
            "CHEM_SHIELD_SECRET_KEY is unset; a random key was generated. "
            "Sessions will reset when the admin console restarts."
        )

    app.config["ADMIN_DB_PATH"] = Path(app.config["ADMIN_DB_PATH"])
    app.config["USERS_FILE"] = Path(app.config["USERS_FILE"])
    app.config["LOGIN_EVENTS_FILE"] = Path(app.config["LOGIN_EVENTS_FILE"])
    app.config["P4_OUTPUT_FILE"] = Path(app.config["P4_OUTPUT_FILE"])
    app.config["P5_OUTPUT_FILE"] = Path(app.config["P5_OUTPUT_FILE"])
    initialize(app.config["ADMIN_DB_PATH"])
    CSRFProtect(app)

    @app.context_processor
    def shared_template_context():
        return {"hmi_url": app.config["HMI_URL"]}

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

    def current_incidents() -> tuple[list[dict[str, Any]], list[str], str | None]:
        incidents, errors, updated = load_chain_incidents(
            app.config["P4_OUTPUT_FILE"], app.config["P5_OUTPUT_FILE"]
        )
        statuses = get_statuses(app.config["ADMIN_DB_PATH"])
        for incident in incidents:
            incident["status_record"] = statuses.get(
                incident["incident_id"],
                {
                    "status": "new",
                    "updated_by": "",
                    "updated_at": "",
                    "note": "",
                },
            )
            p5_report = incident.get("p5", {})
            confirmation = p5_report.get("rule_confirmation")
            incident["rule_confirmation"] = confirmation if isinstance(confirmation, bool) else None
        return incidents, errors, updated

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
            incidents, errors, updated = current_incidents()
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
        )

    @app.get("/machine")
    @role_required(*ALL_ROLES)
    def machine():
        snapshot: dict[str, Any] = {"status": "OFFLINE"}
        error_message = None
        try:
            with urlopen(f"{app.config['HMI_URL']}/api/state", timeout=1.5) as response:
                body = json.loads(response.read().decode("utf-8"))
            if isinstance(body, dict) and "error" not in body:
                snapshot = {"status": "ONLINE", **body}
            else:
                error_message = (
                    str(body.get("error", "Machine HMI returned invalid state"))
                    if isinstance(body, dict)
                    else "Machine HMI returned invalid state"
                )
        except (OSError, URLError, TimeoutError, ValueError, json.JSONDecodeError) as error:
            error_message = str(error)
        return render_template(
            "machine.html",
            snapshot=snapshot,
            error_message=error_message,
            hmi_url=app.config["HMI_URL"],
            username=session["username"],
            role=session["role"],
        )

    @app.get("/incidents")
    @role_required(*ALL_ROLES)
    def incidents_page():
        try:
            incidents, errors, updated = current_incidents()
            if session["role"] == "operator":
                incidents = [
                    incident for incident in incidents
                    if incident["event_counts"]["physical"] > 0
                ]
        except (OSError, sqlite3.Error, ValueError, TypeError) as error:
            app.logger.exception("Incident list could not load")
            incidents, errors, updated = [], [str(error)], None
        return render_template(
            "incidents.html",
            incidents=incidents,
            errors=errors,
            chain_updated=updated,
            username=session["username"],
            role=session["role"],
            hmi_url=app.config["HMI_URL"],
        )

    @app.get("/incidents/<incident_id>")
    @role_required(*ALL_ROLES)
    def incident_detail(incident_id: str):
        incidents, errors, updated = current_incidents()
        incident = next(
            (item for item in incidents if item["incident_id"] == incident_id), None
        )
        if incident is None:
            abort(404)
        if session["role"] == "operator" and incident["event_counts"]["physical"] == 0:
            abort(404)
        return render_template(
            "incident.html",
            incident=incident,
            errors=errors,
            chain_updated=updated,
            username=session["username"],
            role=session["role"],
            can_act=session["role"] in ANALYST_ROLES,
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
        incidents, _, _ = current_incidents()
        if not any(incident["incident_id"] == incident_id for incident in incidents):
            abort(404)

        status = ALLOWED_ACTIONS[action]
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
            else f"Incident marked {status.replace('_', ' ')}.",
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
            ingest_token_enabled=bool(os.environ.get("CHEM_SHIELD_INGEST_TOKEN")),
            username=session["username"],
            role=session["role"],
        )

    return app


if __name__ == "__main__":
    options = server_options()
    application = create_app()
    if options["secret_key"]:
        application.config["SECRET_KEY"] = options["secret_key"]
    application.config["SESSION_COOKIE_SECURE"] = options["cookie_secure"]
    application.run(host=options["host"], port=5000, debug=options["debug"])
