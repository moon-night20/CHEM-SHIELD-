from __future__ import annotations

import json
import re
from pathlib import Path

from werkzeug.security import generate_password_hash

from admin_part.app import create_app


class OfflineMachineClient:
    def get(self, name):
        return {"ok": False, "data": None, "error": "offline"}


def setup_app(tmp_path: Path):
    users = tmp_path / "users.json"
    users.write_text(
        json.dumps({
            "admin": {
                "password_hash": generate_password_hash(
                    "Admin-password-123", method="pbkdf2:sha256"
                ),
                "role": "administrator",
            }
        }),
        encoding="utf-8",
    )
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-only-key",
        "ADMIN_DB_PATH": tmp_path / "admin.db",
        "OT_DATABASE_PATH": tmp_path / "telemetry.db",
        "USERS_FILE": users,
        "LOGIN_EVENTS_FILE": tmp_path / "login.jsonl",
        "P4_OUTPUT_FILE": tmp_path / "p4.json",
        "P5_OUTPUT_FILE": tmp_path / "p5.json",
        "P7_REPORT_DIR": tmp_path / "reports",
        "P7_OUTBOX_PATH": tmp_path / "outbox.log",
        "MACHINE_CLIENT": OfflineMachineClient(),
    })
    client = app.test_client()
    return app, client


def test_part7_routes_require_login_and_csrf(tmp_path):
    _app, client = setup_app(tmp_path)
    response = client.get("/p7/command-center")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]

    login_page = client.get("/login")
    token = re.search(rb'name="csrf_token" value="([^"]+)"', login_page.data)
    assert token
    response = client.post(
        "/login",
        data={
            "csrf_token": token.group(1).decode(),
            "username": "admin",
            "password": "Admin-password-123",
        },
    )
    assert response.status_code == 302
    assert client.get("/p7/command-center").status_code == 200
    assert client.post("/p7/scenarios/abort").status_code == 400
    valid_token = re.search(rb'name="csrf_token" value="([^"]+)"', client.get("/dashboard").data)
    assert valid_token
    response = client.post(
        "/p7/scenarios/abort",
        headers={"X-CSRFToken": valid_token.group(1).decode()},
    )
    assert response.status_code == 409


def test_part7_routes_refuse_non_loopback_requests(tmp_path):
    _app, client = setup_app(tmp_path)
    response = client.get(
        "/p7/command-center",
        environ_base={"REMOTE_ADDR": "192.0.2.4"},
    )
    assert response.status_code == 403
    assert b"loopback" in response.data
