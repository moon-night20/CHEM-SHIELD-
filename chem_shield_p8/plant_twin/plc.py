"""In-memory Modbus-style PLC register map for the reactor twin."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TypeVar

from .model import Controls, PlantState, PlantConfig

RegisterValue = TypeVar("RegisterValue")


@dataclass
class SimulatedPLC:
    """Expose simulated controls and measurements without opening a socket."""

    config: PlantConfig
    _holding: list[int] = field(default_factory=lambda: [3500, 1, 2])
    _inputs: list[int] = field(default_factory=lambda: [0] * 7)
    _coils: list[bool] = field(default_factory=lambda: [True, False, True])

    HOLDING_COUNT = 3
    INPUT_COUNT = 7
    COIL_COUNT = 3
    COOLANT_SETPOINT = 0
    FEED_PUMP_COMMAND = 1
    RELIEF_VALVE_COMMAND = 2

    def read_holding_registers(self, address: int, count: int = 1) -> list[int]:
        return self._read(self._holding, address, count, "holding register")

    def write_holding_register(self, address: int, value: int) -> None:
        if address not in range(self.HOLDING_COUNT):
            raise ValueError(f"Holding register address {address} is not writable.")
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 65535:
            raise ValueError("Holding register value must be an unsigned 16-bit integer.")
        if address == self.COOLANT_SETPOINT and value > 100 * self.config.tags["coolant_valve"].register_scale:
            raise ValueError("Coolant valve setpoint is outside the configured 0-100% range.")
        if address == self.FEED_PUMP_COMMAND and value not in (0, 1):
            raise ValueError("Pump and relief commands must be 0 or 1.")
        if address == self.RELIEF_VALVE_COMMAND and value not in (0, 1, 2):
            raise ValueError("Relief command must be 0 (closed), 1 (open), or 2 (automatic).")
        self._holding[address] = value
        if address == self.FEED_PUMP_COMMAND:
            self._coils[0] = bool(value)
        elif address == self.RELIEF_VALVE_COMMAND:
            if value != 2:
                self._coils[1] = bool(value)

    def read_input_registers(self, address: int, count: int = 1) -> list[int]:
        return self._read(self._inputs, address, count, "input register")

    def write_input_register(self, address: int, _value: int) -> None:
        del _value
        raise ValueError(f"Input register address {address} is read-only.")

    def read_coils(self, address: int, count: int = 1) -> list[bool]:
        return self._read(self._coils, address, count, "coil")

    def write_coil(self, address: int, value: bool) -> None:
        if address not in range(self.COIL_COUNT):
            raise ValueError(f"Coil address {address} is outside the simulated map.")
        if not isinstance(value, bool):
            raise ValueError("Coil value must be boolean.")
        if address == 2:
            self._coils[address] = value
            return
        self.write_holding_register(
            self.FEED_PUMP_COMMAND if address == 0 else self.RELIEF_VALVE_COMMAND,
            int(value),
        )

    def controls(self) -> Controls:
        """Decode current writable register values into process controls."""
        scale = self.config.tags["coolant_valve"].register_scale
        return Controls(
            coolant_valve_pct=self._holding[self.COOLANT_SETPOINT] / scale,
            feed_pump_on=bool(self._holding[self.FEED_PUMP_COMMAND]),
            relief_valve_open=(
                None
                if self._holding[self.RELIEF_VALVE_COMMAND] == 2
                else bool(self._holding[self.RELIEF_VALVE_COMMAND])
            ),
        )

    def publish_state(self, state: PlantState) -> None:
        """Publish process measurements into scaled read-only input registers."""
        values = (
            ("temperature", state.temperature_c),
            ("pressure", state.pressure_bar),
            ("level", state.level_pct),
            ("flow", state.flow_l_min),
            ("coolant_valve", state.coolant_valve_pct),
        )
        self._inputs[:5] = [
            self._encode(tag_name, value) for tag_name, value in values
        ]
        self._inputs[5] = int(state.feed_pump_on)
        self._inputs[6] = int(state.relief_valve_open)
        self._coils[0] = state.feed_pump_on
        self._coils[1] = state.relief_valve_open

    def _encode(self, tag_name: str, value: float) -> int:
        spec = self.config.tags[tag_name]
        scaled = round(value * spec.register_scale)
        if not 0 <= scaled <= 65535:
            raise ValueError(f"Tag {tag_name} cannot be represented as a 16-bit register.")
        return scaled

    @staticmethod
    def _read(
        registers: list[RegisterValue], address: int, count: int, label: str
    ) -> list[RegisterValue]:
        if isinstance(address, bool) or not isinstance(address, int) or address < 0:
            raise ValueError(f"{label} address must be a non-negative integer.")
        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            raise ValueError(f"{label} count must be a positive integer.")
        if address + count > len(registers):
            raise ValueError(f"Requested {label} range is outside the simulated map.")
        return list(registers[address : address + count])
