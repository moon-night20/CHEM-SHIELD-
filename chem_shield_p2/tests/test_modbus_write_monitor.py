import asyncio
import threading
import time

from chem_shield_p1.data.store import TelemetryStore
from chem_shield_p1.plc.register_map import REGISTER_COUNT, SIM_OVERRIDE_MASK
from chem_shield_p1.process.modbus_server import (
    MonitoredModbusTcpServer,
    ProcessRegisterBank,
    create_context,
)
from chem_shield_p2.modbus_write_monitor import ModbusTcpWriteMonitor
from chem_shield_p4.correlation.validator import EventValidator


def write_request(address=1, values=None, function_code=16):
    if values is None:
        values = [100]
    return type("WriteRequest", (), {
        "function_code": function_code,
        "function_code_name": "write_multiple_registers",
        "address": address,
        "values": values,
    })()


def start_virtual_plc(monitor, events):
    loop = asyncio.new_event_loop()
    ready = threading.Event()
    state = {}

    def run_loop():
        try:
            asyncio.set_event_loop(loop)

            async def start():
                server = MonitoredModbusTcpServer(
                    create_context(ProcessRegisterBank()),
                    address=("127.0.0.1", 0),
                    write_monitor=monitor,
                    event_sink=events.append,
                )
                await server.listen()
                state["server"] = server
                state["port"] = server.transport.sockets[0].getsockname()[1]
                ready.set()

            loop.run_until_complete(start())
            loop.run_forever()
        except Exception as error:
            state["error"] = error
            ready.set()

    thread = threading.Thread(target=run_loop, daemon=True)
    thread.start()
    if not ready.wait(5):
        raise RuntimeError("temporary virtual PLC did not start")
    if "error" in state:
        raise RuntimeError("temporary virtual PLC failed to start") from state["error"]
    return loop, thread, state


def stop_virtual_plc(loop, thread, state):
    shutdown = asyncio.run_coroutine_threadsafe(state["server"].shutdown(), loop)
    shutdown.result(timeout=5)
    loop.call_soon_threadsafe(loop.stop)
    thread.join(timeout=5)
    loop.close()


def test_flags_unknown_sources_unexpected_registers_and_unusual_functions():
    monitor = ModbusTcpWriteMonitor()

    unknown_source = monitor.inspect(write_request(), "192.0.2.20", now=0)
    unexpected_register = monitor.inspect(
        write_request(address=REGISTER_COUNT + 1), "127.0.0.1", now=20
    )
    unusual_function = monitor.inspect(
        write_request(function_code=15), "127.0.0.1", now=40
    )

    assert unknown_source[0]["evidence"]["rule_id"] == "unknown_modbus_source"
    assert unexpected_register[0]["evidence"]["rule_id"] == "unexpected_register_write"
    assert unusual_function[0]["evidence"]["rule_id"] == "unusual_write_function_code"
    for event in (unknown_source[0], unexpected_register[0], unusual_function[0]):
        validated = EventValidator().validate_one(event)
        assert validated.event_type == "network"
        assert validated.anomaly_score is not None


def test_write_bursts_are_debounced():
    monitor = ModbusTcpWriteMonitor(
        burst_threshold=3,
        burst_window_seconds=1,
        debounce_seconds=10,
    )

    assert not monitor.inspect(write_request(), "127.0.0.1", now=0)
    assert not monitor.inspect(write_request(), "127.0.0.1", now=0.1)
    first_burst = monitor.inspect(write_request(), "127.0.0.1", now=0.2)
    repeated_burst = monitor.inspect(write_request(), "127.0.0.1", now=0.3)

    assert [event["evidence"]["rule_id"] for event in first_burst] == [
        "modbus_write_burst"
    ]
    assert repeated_burst == []


def test_attack_console_override_traffic_is_monitored_end_to_end(tmp_path, monkeypatch):
    from the_attack import app as attack_app

    events = []
    monitor = ModbusTcpWriteMonitor(event_sink=events.append)
    loop, thread, state = start_virtual_plc(monitor, events)
    database = tmp_path / "attack-console.db"
    monkeypatch.setattr(attack_app, "DEFAULT_PLC_PORT", state["port"])

    try:
        app = attack_app.create_app(
            plc_port=state["port"],
            database=database,
        )
        app.config.update(TESTING=True)
        client = app.test_client()
        client.environ_base["REMOTE_ADDR"] = "127.0.0.1"
        client.environ_base["HTTP_X_CONSOLE_TOKEN"] = app.config["CSRF_TOKEN"]
        TelemetryStore(str(database)).add_telemetry({
            "timestamp": attack_app._utc_now(),
            "machine_id": "M-01",
            "plc_id": "PLC-01",
            "motor_status": "RUNNING",
            "target_rpm": 1000,
            "rpm": 900,
            "temperature": 45,
            "pressure": 2,
            "power": 7,
        })

        response = client.post(
            "/api/commands",
            json={"parameter": "temperature", "value": 70},
        )
        deadline = time.monotonic() + 2
        while not events and time.monotonic() < deadline:
            time.sleep(0.01)

        assert response.status_code == 202
        assert any(
            event["evidence"]["rule_id"] == "simulation_override_write"
            and event["evidence"]["address_start"] == SIM_OVERRIDE_MASK
            for event in events
        )
    finally:
        if "app" in locals():
            app.extensions["ot_console_device"].disconnect()
        stop_virtual_plc(loop, thread, state)
