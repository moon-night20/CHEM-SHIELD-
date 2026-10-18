"""Tests for the operator HMI's navigation-only admin link."""

from pathlib import Path
from unittest.mock import patch

from chem_shield_p1.hmi.app import create_app


def _client(tmp_path: Path):
    app = create_app(
        plc_host="127.0.0.1",
        plc_port=1,
        database=str(tmp_path / "hmi.db"),
    )
    app.config.update(TESTING=True)
    return app.test_client()


def test_admin_link_uses_configured_http_url_without_credentials(tmp_path):
    with patch.dict("os.environ", {"CHEM_SHIELD_ADMIN_URL": "https://admin.example.test/console"}):
        response = _client(tmp_path).get("/")
    assert response.status_code == 200
    assert (
        b'<a class="admin-link" href="https://admin.example.test/console" '
        b'target="_blank" rel="noopener noreferrer">Admin</a>'
    ) in response.data
    assert b"token" not in response.data.lower()
    assert b"username" not in response.data.lower()
    assert b"password" not in response.data.lower()


def test_invalid_admin_url_falls_back_and_never_reaches_html(tmp_path):
    with patch.dict("os.environ", {"CHEM_SHIELD_ADMIN_URL": "javascript:alert(1)"}):
        response = _client(tmp_path).get("/")
    assert response.status_code == 200
    assert b'href="http://127.0.0.1:5000"' in response.data
    assert b"javascript:alert(1)" not in response.data


def test_admin_link_rejects_query_parameters_that_could_carry_credentials(tmp_path):
    with patch.dict(
        "os.environ",
        {"CHEM_SHIELD_ADMIN_URL": "https://admin.example.test/?token=secret"},
    ):
        response = _client(tmp_path).get("/")
    assert response.status_code == 200
    assert b'href="http://127.0.0.1:5000"' in response.data
    assert b"token=secret" not in response.data
