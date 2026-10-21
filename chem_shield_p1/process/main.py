"""Continuous process runtime connected to PLC-01 over Modbus TCP."""

from __future__ import annotations

import argparse
import time
from datetime import datetime, timezone

from pymodbus.client import ModbusTcpClient

from chem_shield_p1.data.store import TelemetryStore
from chem_shield_p1.process.modbus_server import DEFAULT_PLC_HOST, DEFAULT_PLC_PORT
from chem_shield_p1.plc.register_map import (
    EVENT_CODE,
    EVENT_VALUE,
    OVERRIDE_POWER,
    OVERRIDE_PRESSURE,
    OVERRIDE_SPEED,
    OVERRIDE_TEMPERATURE,
    REGISTER_COUNT,
    SIM_OVERRIDE_MASK,
    SIM_POWER,
    SIM_PRESSURE,
    SIM_SPEED,
    SIM_TEMPERATURE,
)
from .machine import (
    NORMAL_POWER_CEILING,
    NORMAL_PRESSURE_CEILING,
    NORMAL_SPEED_CEILING,
    NORMAL_TEMPERATURE_CEILING,
    ProcessUnit,
)


def read_registers(client) -> list[int]:
    result = client.read_holding_registers(0, count=REGISTER_COUNT, slave=1)
    if result.isError():
        raise RuntimeError(result)
    return result.registers


def write_registers(client, values: list[int]) -> None:
    result = client.write_registers(0, values, slave=1)
    if result.isError():
        raise RuntimeError(result)


def apply_simulation_overrides(state, registers: list[int]) -> None:
    """Apply explicitly enabled local test values to simulated sensor state."""
    mask = registers[SIM_OVERRIDE_MASK]
    if mask & OVERRIDE_TEMPERATURE:
        state.temperature = registers[SIM_TEMPERATURE] / 100.0
    if mask & OVERRIDE_PRESSURE:
        state.pressure = registers[SIM_PRESSURE] / 100.0
    if mask & OVERRIDE_POWER:
        state.power = registers[SIM_POWER] / 100.0
    if mask & OVERRIDE_SPEED:
        state.rpm = float(registers[SIM_SPEED])


def cap_uncommanded_values(state, registers: list[int]) -> None:
    """Keep normal process changes within operating limits unless overridden."""
    mask = registers[SIM_OVERRIDE_MASK]
    if not mask & OVERRIDE_TEMPERATURE:
        state.temperature = min(NORMAL_TEMPERATURE_CEILING, max(20.0, state.temperature))
    if not mask & OVERRIDE_PRESSURE:
        state.pressure = min(NORMAL_PRESSURE_CEILING, max(0.0, state.pressure))
    if not mask & OVERRIDE_POWER:
        state.power = min(NORMAL_POWER_CEILING, max(0.0, state.power))
    if not mask & OVERRIDE_SPEED:
        state.rpm = min(NORMAL_SPEED_CEILING, max(0.0, state.rpm))


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

            cap_uncommanded_values(unit.state, registers)
            apply_simulation_overrides(unit.state, registers)

            values = list(registers[:8])
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
    parser.add_argument("--host", default=DEFAULT_PLC_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PLC_PORT)
    parser.add_argument("--interval", type=float, default=0.5)
    parser.add_argument("--database", default="chem_shield/data/telemetry.db")
    args = parser.parse_args()
    run(args.host, args.port, args.interval, args.database)