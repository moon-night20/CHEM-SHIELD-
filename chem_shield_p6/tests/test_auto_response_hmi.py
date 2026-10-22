from chem_shield_p1.hmi.app import create_app


def test_hmi_does_not_expose_automatic_response_endpoint(tmp_path):
    app = create_app(plc_host="127.0.0.1", plc_port=1, database=str(tmp_path / "a.db"))
    try:
        assert app.test_client().get("/api/p6/auto").status_code == 404
    finally:
        app.extensions["stop_background_tasks"]()
