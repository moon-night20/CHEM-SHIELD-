"""Fictional physical process model, independent from the PLC."""

from __future__ import annotations

import random
from dataclasses import dataclass


@dataclass
class MachineState:
    rpm: float = 0.0
    temperature: float = 20.0
    pressure: float = 1.0
    power: float = 0.2
    motor_status: str = "STOPPED"


class ProcessUnit:
    """Generic motor and rotating process load for an isolated lab."""

    def __init__(self, machine_id: str = "M-01", seed: int = 42):
        self.machine_id = machine_id
        self.state = MachineState()
        self._random = random.Random(seed)

    def step(self, motor_on: bool, target_rpm: float, dt: float = 0.5) -> MachineState:
        """Advance the fictional process by one time interval."""
        target_rpm = max(0.0, min(float(target_rpm), 3000.0)) if motor_on else 0.0
        response = min(1.0, dt / 4.0)
        self.state.rpm += (target_rpm - self.state.rpm) * response

        load = self.state.rpm / 1500.0
        target_temperature = 20.0 + 42.0 * min(load, 1.5)
        target_pressure = 1.0 + 3.2 * min(load, 1.5)
        target_power = 0.2 + 12.0 * min(load, 1.5)
        thermal_response = min(1.0, dt / 18.0)
        self.state.temperature += (target_temperature - self.state.temperature) * thermal_response
        self.state.pressure += (target_pressure - self.state.pressure) * min(1.0, dt / 5.0)
        self.state.power += (target_power - self.state.power) * min(1.0, dt / 3.0)
        self.state.motor_status = "RUNNING" if motor_on and self.state.rpm > 1 else "STOPPED"

        self.state.rpm = max(0.0, self.state.rpm + self._random.gauss(0, 1.5))
        self.state.temperature = max(20.0, self.state.temperature + self._random.gauss(0, 0.08))
        self.state.pressure = max(0.0, self.state.pressure + self._random.gauss(0, 0.015))
        self.state.power = max(0.0, self.state.power + self._random.gauss(0, 0.05))
        return self.state