"""Modbus TCP endpoint representing the process-side I/O boundary."""

from __future__ import annotations

from threading import Lock

from pymodbus.datastore import ModbusSequentialDataBlock, ModbusServerContext, ModbusSlaveContext
from pymodbus.server import StartTcpServer

from chem_shield.plc.register_map import (
    ACTUAL_RPM,
    MOTOR_COMMAND,
    POWER,
    PRESSURE,
    REGISTER_COUNT,
    SLAVE_ID,
    TARGET_RPM,
    TEMPERATURE,
    decode_decimal,
    encode_power,
    encode_pressure,
    encode_temperature,
)


class ProcessRegisterBank:
    """Thread-safe register bank shared by the Modbus server and process loop."""

    def __init__(self) -> None:
        self._lock = Lock()
        self.values = [0] * REGISTER_COUNT
        self.values[TARGET_RPM] = 1500

    def read_commands(self) -> tuple[bool, float]:
        with self._lock:
            return bool(self.values[MOTOR_COMMAND]), float(self.values[TARGET_RPM])

    def write_telemetry(self, state: dict) -> None:
        with self._lock:
            self.values[ACTUAL_RPM] = round(state["rpm"])
            self.values[TEMPERATURE] = encode_temperature(state["temperature"])
            self.values[PRESSURE] = encode_pressure(state["pressure"])
            self.values[POWER] = encode_power(state["power"])

    def snapshot(self) -> dict[str, float | int]:
        with self._lock:
            return {
                "motor_command": self.values[MOTOR_COMMAND],
                "target_rpm": self.values[TARGET_RPM],
                "actual_rpm": self.values[ACTUAL_RPM],
                "temperature": decode_decimal(self.values[TEMPERATURE]),
                "pressure": decode_decimal(self.values[PRESSURE]),
                "power": decode_decimal(self.values[POWER]),
            }


def create_context(bank: ProcessRegisterBank) -> ModbusServerContext:
    # The callback block lets Modbus clients observe and change the shared bank.
    class BankBlock(ModbusSequentialDataBlock):
        def __init__(self):
            # PyModbus 3.8 uses one-based internal datastore addresses.
            super().__init__(1, [0] * (REGISTER_COUNT + 1))

        def getValues(self, address, count=1):
            with bank._lock:
                return bank.values[address - 1:address - 1 + count]

        def setValues(self, address, values):
            with bank._lock:
                bank.values[address - 1:address - 1 + len(values)] = values

    store = ModbusSlaveContext(hr=BankBlock())
    return ModbusServerContext(slaves=store, single=True)


def serve(bank: ProcessRegisterBank, host: str = "127.0.0.1", port: int = 5020) -> None:
    StartTcpServer(create_context(bank), address=(host, port))