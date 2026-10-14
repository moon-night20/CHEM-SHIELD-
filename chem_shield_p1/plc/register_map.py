"""Stable Modbus holding-register contract for the virtual laboratory."""

REGISTER_COUNT = 8
SLAVE_ID = 1

MOTOR_COMMAND = 0
TARGET_RPM = 1
ACTUAL_RPM = 2
TEMPERATURE = 3
PRESSURE = 4
POWER = 5
EVENT_CODE = 6
EVENT_VALUE = 7

EVENTS = {
    0: "none",
    1: "rpm_deviation",
    2: "temperature_increase",
    3: "pressure_spike",
    4: "sensor_inconsistency",
}

REGISTER_NAMES = {
    MOTOR_COMMAND: "motor_command",
    TARGET_RPM: "target_rpm",
    ACTUAL_RPM: "actual_rpm",
    TEMPERATURE: "temperature",
    PRESSURE: "pressure",
    POWER: "power",
}


def encode_temperature(value: float) -> int:
    """Store Celsius with two decimal places in a 16-bit register."""
    return max(0, min(65535, round(value * 100)))


def encode_pressure(value: float) -> int:
    """Store bar with two decimal places in a 16-bit register."""
    return max(0, min(65535, round(value * 100)))


def encode_power(value: float) -> int:
    """Store kW with two decimal places in a 16-bit register."""
    return max(0, min(65535, round(value * 100)))


def decode_decimal(value: int) -> float:
    return value / 100.0