"""Continuous process runtime connected to PLC-01 over Modbus TCP."""

from __future__ import annotations

import argparse
import time
from datetime import datetime, timezone

from pymodbus.client import ModbusTcpClient

from chem_shield.data.store import TelemetryStore
from chem_shield.plc.register_map import EVENT_CODE, EVENT_VALUE
from .machine import ProcessUnit


def read_registers(client) -> list[int]:
    result = client.read_holding_registers(0, count=8, slave=1)
    if result.isError():
        raise RuntimeError(result)
    return result.registers


def write_registers(client, values: list[int]) -> None:
    result = client.write_registers(0, values, slave=1)
    if result.isError():
        raise RuntimeError(result)


def run(host: str, port: int, interval: float, database: str) -> None:
    client = ModbusTcpClient(host, port=port)
    unit = ProcessUnit()
    store = TelemetryStore(database)
    if not client.connect():
        raise ConnectionError(f"Could not connect to PLC at {host}:{port}")
    try:
        while True:
            registers = read_registers(client)
            motor_on = bool(registers[0])
            target_rpm = registers[1]
            paused = registers[EVENT_CODE] == 5
            state = unit.state if paused else unit.step(motor_on, target_rpm, interval)

            event_code, event_value = registers[EVENT_CODE], registers[EVENT_VALUE]
            if not paused and event_code == 1:
                unit.state.rpm = max(0.0, unit.state.rpm + event_value - 1000)
            elif not paused and event_code == 2:
                unit.state.temperature += event_value / 10
            elif not paused and event_code == 3:
                unit.state.pressure += event_value / 10
            elif not paused and event_code == 4:
                unit.state.rpm += 250

            values = list(registers)
            values[2] = round(unit.state.rpm)
            values[3] = round(unit.state.temperature * 100)
            values[4] = round(unit.state.pressure * 100)
            values[5] = round(unit.state.power * 100)
            values[EVENT_CODE] = 5 if paused else 0
            values[EVENT_VALUE] = 0
            write_registers(client, values)

            store.add_telemetry({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "machine_id": unit.machine_id,
                "plc_id": "PLC-01",
                "motor_status": state.motor_status,
                "target_rpm": target_rpm,
                "rpm": round(unit.state.rpm, 2),
                "temperature": round(unit.state.temperature, 2),
                "pressure": round(unit.state.pressure, 2),
                "power": round(unit.state.power, 2),
            })
            time.sleep(interval)
    finally:
        client.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CHEM-SHIELD Virtual Machine process simulator")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5020)
    parser.add_argument("--interval", type=float, default=0.5)
    parser.add_argument("--database", default="chem_shield/data/telemetry.db")
    args = parser.parse_args()
    run(args.host, args.port, args.interval, args.database)