"""Sensor boundary for the fictional process unit."""

from __future__ import annotations

from dataclasses import asdict

from .machine import MachineState


class VirtualSensors:
    def read(self, state: MachineState) -> dict[str, float | str]:
        return asdict(state)