"""Tests for the operator HMI's navigation-only admin link."""

from pathlib import Path
import re
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
    admin_href = re.search(rb'<a class="admin-link" href="([^"]+)"', response.data)
    assert admin_href
    assert all(
        secret not in admin_href.group(1).lower()
        for secret in (b"token", b"username", b"password")
    )


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


def test_index_sections_render_in_fixed_dashboard_order(tmp_path):
    response = _client(tmp_path).get("/")
    assert response.status_code == 200
    html = response.data.decode("utf-8")
    section_positions = [
        html.index('class="network-strip panel"'),
        html.index('class="risk-panel panel"'),
        html.index('class="monitor-panel"'),
        html.index('class="control-panel panel"'),
    ]
    assert section_positions == sorted(section_positions)
    assert 'class="admin-link"' in html
    assert 'id="risk-alert-sim-stop"' in html
    assert 'name="p6-confirm-token"' in html
    css = Path(__file__).parents[1].joinpath("static", "style.css").read_text(encoding="utf-8")
    fixed_grid = re.search(r"\.fixed-dashboard\s*\{([^}]*)\}", css)
    assert fixed_grid
    assert "grid-template-rows:auto auto minmax(0,1fr) auto" in fixed_grid.group(1)
    assert "max-height:clamp(70px,14vh,150px)" in css
