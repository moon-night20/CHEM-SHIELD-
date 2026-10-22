from __future__ import annotations

import pytest

from chem_shield_p8 import run


@pytest.mark.parametrize(
    "value, expected",
    [(None, 15080), ("8080", 8080), ("65535", 65535), ("1", 1)],
)
def test_dashboard_port_accepts_valid_values(value, expected, monkeypatch):
    monkeypatch.delenv("CHEM_SHIELD_P8_PORT", raising=False)
    assert run.dashboard_port(value) == expected


@pytest.mark.parametrize("value", ["", "abc", "0", "65536", "-1"])
def test_dashboard_port_rejects_invalid_values(value):
    with pytest.raises(ValueError, match="between 1 and 65535"):
        run.dashboard_port(value)


def test_launcher_binds_loopback_and_disables_debug(monkeypatch):
    calls = {}

    class FakeApp:
        def run(self, **kwargs):
            calls.update(kwargs)

    monkeypatch.setenv("CHEM_SHIELD_P8_PORT", "8085")
    monkeypatch.setattr(run, "create_app", lambda: FakeApp())

    run.main()

    assert calls == {
        "host": "127.0.0.1",
        "port": 8085,
        "debug": False,
        "use_reloader": False,
        "threaded": True,
    }
