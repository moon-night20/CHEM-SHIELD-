from chem_shield_p1.hmi.app import create_app


def test_auto_status_endpoint_and_non_loopback_is_disabled(tmp_path):
    app = create_app(plc_host="127.0.0.1", plc_port=1, database=str(tmp_path / "a.db"))
    status = app.test_client().get("/api/p6/auto").get_json()
    assert status["state"] == "IDLE" and status["simulation_only"] is True
    assert status["countdown_seconds"] == 15 and status["enabled"] is True

    remote = create_app(plc_host="192.0.2.10", plc_port=1, database=str(tmp_path / "b.db"))
    assert remote.test_client().get("/api/p6/auto").get_json()["enabled"] is False
