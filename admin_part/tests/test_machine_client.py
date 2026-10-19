"""Read-only HMI client boundary tests; all network calls are mocked."""

import io
from urllib.error import URLError
from unittest.mock import patch

from admin_part.machine_client import DEFAULT_HMI_URL, MachineClient


def test_client_parses_allowlisted_hmi_json_and_uses_get_only():
    with patch(
        "admin_part.machine_client.open_hmi_url",
        return_value=io.BytesIO(b'{"motor_status":"RUNNING","rpm":1500}'),
    ) as open_url:
        result = MachineClient("http://localhost:15000").get("state")
    assert result["ok"] is True
    assert result["data"] == {"motor_status": "RUNNING", "rpm": 1500}
    request = open_url.call_args.args[0]
    assert request.get_method() == "GET"
    assert request.full_url == "http://localhost:15000/api/state"
    assert open_url.call_args.kwargs["timeout"] == 2.0


def test_client_refuses_non_loopback_hmi_url_before_requesting():
    client = MachineClient("http://example.test:15000")
    assert client.base_url == DEFAULT_HMI_URL
    with patch(
        "admin_part.machine_client.open_hmi_url",
        side_effect=URLError("test endpoint is offline"),
    ) as open_url:
        result = client.get("state")
    open_url.assert_called_once()
    assert open_url.call_args.args[0].full_url.startswith(DEFAULT_HMI_URL)
    assert result["ok"] is False


def test_client_returns_safe_offline_result_instead_of_raising():
    with patch(
        "admin_part.machine_client.open_hmi_url",
        side_effect=URLError("connection refused"),
    ):
        result = MachineClient().get("telemetry")
    assert set(result) == {"ok", "data", "error", "fetched_at"}
    assert result["ok"] is False
    assert result["data"] is None
    assert "connection refused" in result["error"]
    assert result["fetched_at"]


def test_live_fetch_returns_empty_safe_shapes_when_hmi_state_is_offline():
    with patch(
        "admin_part.machine_client.open_hmi_url",
        side_effect=URLError("offline"),
    ) as open_url:
        result = MachineClient().live()
    assert result["ok"] is False
    assert result["state"]["data"] is None
    assert result["connection"]["error"] == result["state"]["error"]
    assert result["risk"]["error"] == result["state"]["error"]
    assert result["telemetry"]["error"] == result["state"]["error"]
    assert open_url.call_count == 4


def test_client_supports_loopback_ipv6_url():
    client = MachineClient("http://[::1]:15000")
    assert client.base_url == "http://[::1]:15000"
