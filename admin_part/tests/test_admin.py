from __future__ import annotations

import json
import re
import socket
import subprocess
import urllib.request
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError
from unittest.mock import MagicMock

import pytest
from werkzeug.security import generate_password_hash

from admin_part.app import _safe_hmi_url, create_app, server_options
from admin_part.manage_users import main as manage_users


INCIDENT_ID = "INC-0001"
P4_SAMPLE = [{
    "incident_id": INCIDENT_ID,
    "asset_id": "PLC-01",
    "risk_level": "CRITICAL",
    "risk_score": 0.804,
    "start_time": "2026-10-14T10:00:14Z",
    "end_time": "2026-10-14T10:00:20Z",
    "events": [
        {
            "event_id": "net-1",
            "event_type": "network",
            "source": "network_model",
            "evidence": {"detail": "<script>alert(1)</script>"},
        },
        {
            "event_id": "phys-1",
            "event_type": "physical",
            "source": "physical_ml",
            "evidence": {"temperature": 90},
        },
    ],
}]
P5_SAMPLE = [{
    "incident_id": INCIDENT_ID,
    "risk_level": "CRITICAL",
    "risk_score": 0.804,
    "rule_alerts": [{"event_type": "temperature_high", "evidence": "high reading"}],
    "sensor_validation_issues": [],
    "rule_confirmation": True,
}]


class FakeMachineClient:
    def __init__(self):
        self.responses = {
            "state": {"ok": False, "data": None, "error": "offline", "fetched_at": "2026-10-18T00:00:00Z"},
            "connection": {"ok": False, "data": None, "error": "offline", "fetched_at": "2026-10-18T00:00:00Z"},
            "risk": {"ok": False, "data": None, "error": "offline", "fetched_at": "2026-10-18T00:00:00Z"},
            "telemetry": {"ok": False, "data": None, "error": "offline", "fetched_at": "2026-10-18T00:00:00Z"},
            "incidents": {"ok": False, "data": None, "error": "offline", "fetched_at": "2026-10-18T00:00:00Z"},
        }

    def get(self, name):
        return self.responses[name]

    def live(self):
        return {
            "ok": all(self.responses[name]["ok"] for name in ("state", "connection", "risk", "telemetry")),
            "state": self.responses["state"],
            "connection": self.responses["connection"],
            "risk": self.responses["risk"],
            "telemetry": self.responses["telemetry"],
            "fetched_at": self.responses["telemetry"]["fetched_at"],
        }


@pytest.fixture
def setup_console(tmp_path: Path):
    data_dir = tmp_path / "data"
    users_file = data_dir / "users.json"
    users_file.parent.mkdir(parents=True)
    users_file.write_text(json.dumps({
        "admin": {"password_hash": generate_password_hash("Admin-password-123", method="pbkdf2:sha256"), "role": "administrator"},
        "analyst": {"password_hash": generate_password_hash("Analyst-password-123", method="pbkdf2:sha256"), "role": "analyst"},
        "operator": {"password_hash": generate_password_hash("Operator-password-123", method="pbkdf2:sha256"), "role": "operator"},
    }), encoding="utf-8")
    p4_path = tmp_path / "out" / "p4_incidents.json"
    p5_path = tmp_path / "out" / "p5_report.json"
    p4_path.parent.mkdir()
    p4_path.write_text(json.dumps(P4_SAMPLE), encoding="utf-8")
    p5_path.write_text(json.dumps(P5_SAMPLE), encoding="utf-8")
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-only-key",
        "ADMIN_DB_PATH": data_dir / "admin.db",
        "USERS_FILE": users_file,
        "LOGIN_EVENTS_FILE": data_dir / "events" / "login_events.jsonl",
        "P4_OUTPUT_FILE": p4_path,
        "P5_OUTPUT_FILE": p5_path,
        "HMI_URL": "http://127.0.0.1:15000",
        "MACHINE_CLIENT": FakeMachineClient(),
    })
    return app, app.test_client(), data_dir, p4_path, p5_path


def csrf_token(client) -> str:
    response = client.get("/login")
    if response.status_code == 302:
        response = client.get("/dashboard")
    assert response.status_code == 200
    match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
    assert match
    return match.group(1).decode()


def login(client, username: str, password: str, remote_addr: str = "127.0.0.1"):
    token = csrf_token(client)
    return client.post(
        "/login",
        data={"csrf_token": token, "username": username, "password": password},
        environ_base={"REMOTE_ADDR": remote_addr},
    )


def post_action(client, action: str, note: str = "", *, token: str | None = None):
    return client.post(
        f"/incidents/{INCIDENT_ID}/action",
        data={
            **({"csrf_token": token} if token is not None else {}),
            "action": action,
            "note": note,
        },
        follow_redirects=True,
    )


def test_login_success_and_cookie_security(setup_console):
    app, client, *_ = setup_console
    response = login(client, "admin", "Admin-password-123")
    assert response.status_code == 302
    cookie = response.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie
    assert app.permanent_session_lifetime.total_seconds() == 20 * 60
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    audit = client.get("/audit")
    assert b"login_success" in audit.data


def test_login_unknown_and_wrong_password_have_same_message(setup_console):
    _, client, data_dir, *_ = setup_console
    invalid_user = login(client, "missing", "not-the-password")
    wrong_password = login(client, "admin", "incorrect-password")
    assert invalid_user.status_code == wrong_password.status_code == 401
    assert b"Invalid username or password." in invalid_user.data
    assert b"Invalid username or password." in wrong_password.data
    import sqlite3

    with sqlite3.connect(data_dir / "admin.db") as connection:
        failure_count = connection.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = ?",
            ("login_failure",),
        ).fetchone()[0]
    assert failure_count == 2


def test_lockout_is_scoped_to_username_and_source_ip(setup_console):
    _, client, *_ = setup_console
    token = csrf_token(client)
    for _ in range(5):
        client.post(
            "/login",
            data={"csrf_token": token, "username": "admin", "password": "wrong"},
            environ_base={"REMOTE_ADDR": "192.0.2.10"},
        )
    blocked = client.post(
        "/login",
        data={"csrf_token": token, "username": "admin", "password": "Admin-password-123"},
        environ_base={"REMOTE_ADDR": "192.0.2.10"},
    )
    assert blocked.status_code == 401
    other_ip = login(client, "admin", "Admin-password-123", "192.0.2.11")
    assert other_ip.status_code == 302


@pytest.mark.parametrize(
    ("username", "password", "allowed", "forbidden"),
    [
        ("admin", "Admin-password-123", ["/dashboard", "/machine", "/incidents", f"/incidents/{INCIDENT_ID}", "/audit", "/users", "/settings"], []),
        ("analyst", "Analyst-password-123", ["/dashboard", "/machine", "/incidents", f"/incidents/{INCIDENT_ID}"], ["/audit", "/users", "/settings"]),
        ("operator", "Operator-password-123", ["/dashboard", "/machine", "/incidents", f"/incidents/{INCIDENT_ID}"], ["/audit", "/users", "/settings"]),
    ],
)
def test_role_page_access(setup_console, username, password, allowed, forbidden):
    _, client, *_ = setup_console
    assert login(client, username, password).status_code == 302
    for route in allowed:
        assert client.get(route).status_code == 200
    for route in forbidden:
        assert client.get(route).status_code == 403


def test_operator_is_forbidden_from_actions_and_audit(setup_console):
    app, client, *_ = setup_console
    login(client, "operator", "Operator-password-123")
    response = post_action(client, "acknowledge", token=csrf_token(client))
    assert response.status_code == 403
    assert client.get("/audit").status_code == 403
    assert b"forbidden_access" not in response.data
    admin_client = app.test_client()
    login(admin_client, "admin", "Admin-password-123")
    audit_log = admin_client.get("/audit")
    assert b"forbidden_access" in audit_log.data


def test_home_and_protected_pages_follow_standalone_login_flow(setup_console):
    _, client, *_ = setup_console
    assert client.get("/").status_code == 200
    for route in ("/dashboard", "/machine", "/incidents", "/audit"):
        response = client.get(route)
        assert response.status_code == 302
        assert "/login" in response.headers["Location"]


def test_login_page_explains_safe_setup_when_user_store_is_missing(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-only-key",
        "ADMIN_DB_PATH": data_dir / "admin.db",
        "USERS_FILE": data_dir / "users.json",
        "LOGIN_EVENTS_FILE": data_dir / "events" / "login_events.jsonl",
        "P4_OUTPUT_FILE": tmp_path / "p4.json",
        "P5_OUTPUT_FILE": tmp_path / "p5.json",
    })
    response = app.test_client().get("/")
    assert response.status_code == 200
    assert b"No admin account is configured yet" in response.data
    assert b"python -m admin_part.manage_users create ADMIN_NAME" in response.data
    assert b"default password" in response.data


def test_role_navigation_and_machine_offline_status(setup_console):
    _, client, *_ = setup_console
    login(client, "analyst", "Analyst-password-123")
    dashboard = client.get("/", follow_redirects=True)
    assert b"analyst - analyst" in dashboard.data
    assert b"Dashboard" in dashboard.data
    assert b"Machine" in dashboard.data
    assert b"Incidents" in dashboard.data
    assert b"Audit" not in dashboard.data
    assert b"Users" not in dashboard.data
    assert b"Back to machine HMI" in dashboard.data
    assert b'href="http://127.0.0.1:15000"' in dashboard.data
    machine = client.get("/machine")
    assert machine.status_code == 200
    assert b"OFFLINE" in machine.data
    assert b"START" not in machine.data


def test_administrator_navigation_includes_audit_and_users(setup_console):
    _, client, *_ = setup_console
    login(client, "admin", "Admin-password-123")
    response = client.get("/dashboard")
    assert b"Audit" in response.data
    assert b"Users" in response.data


def test_remote_bind_requires_opt_in_and_explicit_secret():
    with pytest.raises(ValueError, match="Refusing non-loopback"):
        server_options({"CHEM_SHIELD_ADMIN_HOST": "0.0.0.0"})
    with pytest.raises(ValueError, match="CHEM_SHIELD_SECRET_KEY"):
        server_options({
            "CHEM_SHIELD_ADMIN_HOST": "0.0.0.0",
            "CHEM_SHIELD_ALLOW_REMOTE": "1",
        })
    options = server_options({
        "CHEM_SHIELD_ADMIN_HOST": "0.0.0.0",
        "CHEM_SHIELD_ALLOW_REMOTE": "1",
        "CHEM_SHIELD_SECRET_KEY": "explicit-test-secret",
        "CHEM_SHIELD_COOKIE_SECURE": "1",
    })
    assert options["host"] == "0.0.0.0"
    assert options["cookie_secure"] is True


def test_hmi_url_validation_allows_http_s_but_rejects_embedded_secrets():
    assert _safe_hmi_url("https://localhost:15000") == (
        "https://localhost:15000"
    )
    assert _safe_hmi_url("https://machine.example.test/?token=secret") == (
        "http://127.0.0.1:15000"
    )


def test_hmi_url_validation_rejects_non_loopback_hosts():
    assert _safe_hmi_url("http://machine.example.test:15000") == (
        "http://127.0.0.1:15000"
    )


def test_action_post_without_csrf_token_is_rejected(setup_console):
    _, client, *_ = setup_console
    login(client, "analyst", "Analyst-password-123")
    response = post_action(client, "acknowledge")
    assert response.status_code == 400
    assert b"security token is missing or expired" in response.data


def test_login_and_logout_post_require_csrf_tokens(setup_console):
    _, client, *_ = setup_console
    missing_login_token = client.post(
        "/login", data={"username": "admin", "password": "Admin-password-123"}
    )
    assert missing_login_token.status_code == 400
    login(client, "analyst", "Analyst-password-123")
    missing_logout_token = client.post("/logout")
    assert missing_logout_token.status_code == 400
    assert client.get("/dashboard").status_code == 200


def test_logout_is_audited_and_uses_post(setup_console):
    _, client, data_dir, *_ = setup_console
    login(client, "analyst", "Analyst-password-123")
    response = client.post(
        "/logout",
        data={"csrf_token": csrf_token(client)},
    )
    assert response.status_code == 302
    import sqlite3

    with sqlite3.connect(data_dir / "admin.db") as connection:
        logout = connection.execute(
            "SELECT username, action FROM audit_log WHERE action = ?",
            ("logout",),
        ).fetchone()
    assert logout == ("analyst", "logout")
    assert client.get("/dashboard").status_code == 302


def test_dashboard_merges_chain_outputs_and_handles_missing_or_malformed(setup_console):
    _, client, _, p4_path, p5_path = setup_console
    login(client, "analyst", "Analyst-password-123")
    dashboard = client.get("/dashboard")
    assert b"CRITICAL" in dashboard.data
    assert b"INC-0001" in dashboard.data
    assert b"0.804" in dashboard.data
    assert b"Confirmed" in dashboard.data

    p4_path.unlink()
    missing = client.get("/dashboard")
    assert missing.status_code == 200
    assert b"python -m scripts.run_chain" in missing.data
    assert b"P4 output is missing" in missing.data

    p4_path.write_text("{not-json", encoding="utf-8")
    p5_path.write_text(json.dumps({"not": "a list"}), encoding="utf-8")
    malformed = client.get("/dashboard")
    assert malformed.status_code == 200
    assert b"could not be read" in malformed.data
    assert b"must be a JSON list" in malformed.data


def test_dashboard_uses_chain_fallback_when_machine_hmi_is_offline(setup_console):
    _, client, *_ = setup_console
    login(client, "analyst", "Analyst-password-123")
    response = client.get("/dashboard")
    assert b"from last chain run (HMI offline)" in response.data
    assert b"INC-0001" in response.data


def test_dashboard_shows_login_failure_alerts_grouped_by_user_and_ip(setup_console):
    _, client, data_dir, *_ = setup_console
    login(client, "analyst", "Analyst-password-123")
    event_path = data_dir / "events" / "login_events.jsonl"
    event_path.parent.mkdir(parents=True, exist_ok=True)
    event_path.write_text(
        "".join(
            json.dumps({
                "timestamp": f"2026-10-17T20:00:0{index}+00:00",
                "username": "attacker",
                "source_ip": "192.0.2.9",
                "event_type": "login_failure",
            }) + "\n"
            for index in range(5)
        ),
        encoding="utf-8",
    )
    dashboard = client.get("/dashboard")
    assert b"Repeated failed login attempts" in dashboard.data
    assert b"192.0.2.9" in dashboard.data


def test_incident_detail_escapes_event_html(setup_console):
    _, client, *_ = setup_console
    login(client, "analyst", "Analyst-password-123")
    response = client.get(f"/incidents/{INCIDENT_ID}")
    assert response.status_code == 200
    assert b"&lt;script&gt;alert(1)&lt;/script&gt;" in response.data
    assert b"<script>alert(1)</script>" not in response.data


def test_incident_detail_includes_only_telemetry_inside_incident_window(setup_console):
    app, client, *_ = setup_console
    login(client, "analyst", "Analyst-password-123")
    machine = app.extensions["machine_client"]
    machine.responses["telemetry"] = {
        "ok": True,
        "data": [
            {"timestamp": "2026-10-14T10:00:15Z", "motor_status": "RUNNING", "rpm": 1500, "temperature": 88, "pressure": 4, "power": 9},
            {"timestamp": "2026-10-14T10:00:21Z", "motor_status": "RUNNING", "rpm": 1600, "temperature": 90, "pressure": 4, "power": 9},
        ],
        "error": None,
        "fetched_at": "2026-10-18T00:00:00Z",
    }
    response = client.get(f"/incidents/{INCIDENT_ID}")
    assert response.status_code == 200
    assert b"2026-10-14T10:00:15Z" in response.data
    assert b"2026-10-14T10:00:21Z" not in response.data


def test_live_incidents_match_chain_by_asset_and_overlapping_window(setup_console):
    app, client, *_ = setup_console
    login(client, "analyst", "Analyst-password-123")
    app.extensions["machine_client"].responses["incidents"] = {
        "ok": True,
        "data": {"incidents": [{
            "incident_id": "HMI-DIFFERENT-ID",
            "asset_id": "PLC-01",
            "start_time": "2026-10-14T10:00:15Z",
            "end_time": "2026-10-14T10:00:19Z",
            "status": "ACTIVE",
            "risk_level": "CRITICAL",
            "risk_score": 0.804,
            "events": [{"event_type": "physical", "source": "physical_ml"}],
        }]},
        "error": None,
        "fetched_at": "2026-10-18T00:00:00Z",
    }
    response = client.get("/incidents")
    assert response.status_code == 200
    assert b"live from machine HMI" in response.data
    assert b"HMI-DIFFERENT-ID" in response.data


def test_admin_acknowledgement_posts_once_to_machine_hmi_and_records_locally(setup_console):
    _, client, data_dir, *_ = setup_console
    login(client, "analyst", "Analyst-password-123")
    response_object = MagicMock()
    response_object.status = 200
    response_object.__enter__ = MagicMock(return_value=response_object)
    response_object.__exit__ = MagicMock(return_value=False)
    with patch("admin_part.app.open_hmi_url", return_value=response_object) as post:
        response = post_action(client, "acknowledge", token=csrf_token(client))
    assert response.status_code == 200
    assert post.call_count == 1
    request = post.call_args.args[0]
    assert request.method == "POST"
    assert request.full_url.endswith(f"/api/incidents/{INCIDENT_ID}/acknowledge")
    assert json.loads(request.data) == {"acknowledged_by": "analyst"}
    import sqlite3

    with sqlite3.connect(data_dir / "admin.db") as connection:
        status = connection.execute(
            "SELECT status FROM incident_status WHERE incident_id = ?",
            (INCIDENT_ID,),
        ).fetchone()[0]
    assert status == "acknowledged"


def test_admin_acknowledgement_failure_warns_but_keeps_local_decision(setup_console):
    _, client, data_dir, *_ = setup_console
    login(client, "analyst", "Analyst-password-123")
    with patch("admin_part.app.open_hmi_url", side_effect=URLError("HMI offline")) as post:
        response = post_action(client, "acknowledge", token=csrf_token(client))
    assert response.status_code == 200
    assert post.call_count == 1
    assert b"could not record the acknowledgement" in response.data
    import sqlite3

    with sqlite3.connect(data_dir / "admin.db") as connection:
        status = connection.execute(
            "SELECT status FROM incident_status WHERE incident_id = ?",
            (INCIDENT_ID,),
        ).fetchone()[0]
    assert status == "acknowledged"


def test_live_api_returns_machine_data_and_safe_offline_result(setup_console):
    app, client, *_ = setup_console
    login(client, "analyst", "Analyst-password-123")
    live_result = app.extensions["machine_client"]
    online = {
        "ok": True,
        "data": {"rpm": 1500},
        "error": None,
        "fetched_at": "2026-10-18T00:00:00Z",
    }
    live_result.responses.update({
        "state": online,
        "connection": online,
        "risk": {"ok": True, "data": {"risk_level": "HIGH"}, "error": None, "fetched_at": online["fetched_at"]},
        "telemetry": {"ok": True, "data": [{"rpm": 1500}], "error": None, "fetched_at": online["fetched_at"]},
    })
    online_response = client.get("/api/live")
    assert online_response.status_code == 200
    online_data = online_response.get_json()
    assert online_data["ok"] is True
    assert online_data["state"]["data"]["rpm"] == 1500
    assert online_data["risk"]["data"]["risk_level"] == "HIGH"

    live_result.responses["state"] = {
        "ok": False, "data": None, "error": "connection refused",
        "fetched_at": online["fetched_at"],
    }
    offline_response = client.get("/api/live")
    assert offline_response.status_code == 200
    offline_data = offline_response.get_json()
    assert offline_data["ok"] is False
    assert offline_data["state"]["data"] is None
    assert offline_data["state"]["error"] == "connection refused"


def test_incident_action_updates_status_and_audit(setup_console):
    _, client, data_dir, p4_path, p5_path = setup_console
    p4_before = p4_path.read_bytes()
    p5_before = p5_path.read_bytes()
    login(client, "analyst", "Analyst-password-123")
    response = post_action(client, "escalate", "Needs supervisor review", token=csrf_token(client))
    assert response.status_code == 200

    import sqlite3

    with sqlite3.connect(data_dir / "admin.db") as connection:
        status = connection.execute(
            "SELECT status, updated_by, note FROM incident_status WHERE incident_id = ?",
            (INCIDENT_ID,),
        ).fetchone()
        audit = connection.execute(
            "SELECT action, incident_id, detail FROM audit_log WHERE action = ?",
            ("incident_escalate",),
        ).fetchone()
    assert status == ("escalated", "analyst", "Needs supervisor review")
    assert audit[0:2] == ("incident_escalate", INCIDENT_ID)
    assert "Needs supervisor review" in audit[2]
    assert p4_path.read_bytes() == p4_before
    assert p5_path.read_bytes() == p5_before


def test_administrator_can_record_an_incident_action(setup_console):
    _, client, data_dir, *_ = setup_console
    login(client, "admin", "Admin-password-123")
    response = post_action(client, "acknowledge", token=csrf_token(client))
    assert response.status_code == 200
    assert b"acknowledged" in response.data
    import sqlite3

    with sqlite3.connect(data_dir / "admin.db") as connection:
        audit = connection.execute(
            "SELECT username, action, incident_id FROM audit_log WHERE action = ?",
            ("incident_acknowledge",),
        ).fetchone()
    assert audit == ("admin", "incident_acknowledge", INCIDENT_ID)


def test_user_manager_stores_hash_and_enforces_password_length(tmp_path):
    users_path = tmp_path / "users.json"
    answers = iter(["short", "short"])
    assert manage_users(
        ["create", "analyst1", "--role", "analyst"],
        users_path=users_path,
        prompt=lambda prompt_text: (prompt_text, next(answers))[1],
    ) == 1
    answers = iter(["Long-password-123", "Long-password-123"])
    assert manage_users(
        ["create", "demo_admin", "--role", "administrator"],
        users_path=users_path,
        prompt=lambda prompt_text: (prompt_text, next(answers))[1],
    ) == 0
    stored = json.loads(users_path.read_text(encoding="utf-8"))
    assert stored["demo_admin"]["password_hash"] != "Long-password-123"
    assert stored["demo_admin"]["role"] == "administrator"


def test_unknown_incidents_actions_and_short_notes_are_rejected(setup_console):
    _, client, *_ = setup_console
    login(client, "analyst", "Analyst-password-123")
    token = csrf_token(client)
    unknown = client.post(
        "/incidents/UNKNOWN/action",
        data={"csrf_token": token, "action": "acknowledge"},
    )
    assert unknown.status_code == 404
    bad_action = client.post(
        f"/incidents/{INCIDENT_ID}/action",
        data={"csrf_token": token, "action": "run_shell"},
    )
    assert bad_action.status_code == 400
    short_note = client.post(
        f"/incidents/{INCIDENT_ID}/action",
        data={"csrf_token": token, "action": "false_positive", "note": "no"},
    )
    assert short_note.status_code == 400
    valid_note = client.post(
        f"/incidents/{INCIDENT_ID}/action",
        data={"csrf_token": token, "action": "false_positive", "note": "Reviewed data"},
    )
    assert valid_note.status_code == 302


def test_simulated_response_records_only_and_makes_no_outbound_calls(setup_console):
    _, client, *_ = setup_console
    login(client, "analyst", "Analyst-password-123")
    token = csrf_token(client)
    with (
        patch.object(socket, "create_connection") as create_connection,
        patch.object(subprocess, "Popen") as popen,
        patch.object(urllib.request, "urlopen") as urlopen,
    ):
        response = post_action(
            client, "simulated_response", "Record decision only", token=token
        )
    assert response.status_code == 200
    assert b"Simulation only - recorded, nothing is executed." in response.data
    create_connection.assert_not_called()
    popen.assert_not_called()
    urlopen.assert_not_called()
