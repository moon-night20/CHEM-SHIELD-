# CHEM-SHIELD Virtual Machine: Part 1 OT Laboratory

This small prototype separates the operator interface, PLC, network boundary,
physical process, sensors, and telemetry. It uses only loopback networking and
fictional values.

## What was reused and what changed

The archive supplied for the earlier implementation had useful gradual-response
and noise ideas in `simulator/machine.py` and `simulator/sensors.py`. Its
`VirtualPLC` and scenario classes were coupled through direct Python calls and
the output path was CSV-only. The smallest useful architectural change was to
retain the physical-response concept while replacing that call path with a
documented Modbus TCP register contract.

The new path is:

```text
Flask HMI -> virtual PLC Modbus TCP server -> process Modbus TCP client
                                                -> Process Unit M-01
                                                -> SQLite telemetry
```

The default PLC server is a tiny standalone Python runtime for reproducibility.
It is compatible with the register layout documented in
[plc/README.md](plc/README.md), where an OpenPLC runtime can be substituted in a
later lab setup without changing the HMI or process client.

## Setup

Python 3.10+ is recommended.

```bash
cd chem_shield
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

To run the machine, open three terminals from the repository root and run one
command in each terminal:

```bash
chem_shield/.venv/bin/python -m chem_shield.plc.modbus_plc --host 127.0.0.1 --port 15020
```

```bash
chem_shield/.venv/bin/python -m chem_shield.process.main --host 127.0.0.1 --port 15020 --database chem_shield/data/telemetry.db
```

```bash
chem_shield/.venv/bin/python -m chem_shield.hmi.app --host 127.0.0.1 --port 15000 --plc-port 15020 --database chem_shield/data/telemetry.db
```

Then open `http://127.0.0.1:15000`.
Press START and watch the RPM ramp toward the
target. STOP demonstrates the gradual coast-down and cooling response. The
TEST MODE controls generate simulation-only ground-truth events.

The operator console shows the PLC connection state, actual and target RPM,
temperature, pressure, power, operator command history, and the latest machine
events. Commands and test events are disabled while the PLC is offline.

## Register map

All values are holding registers, slave ID 1, zero-based addresses. Temperature,
pressure, and power are stored as integer hundredths.

| Address | Name | Read/write | Meaning |
| ---: | --- | --- | --- |
| 0 | Motor command | HMI -> PLC | 0 STOP, 1 RUN |
| 1 | Target RPM | HMI -> PLC | Fictional setpoint, 0-3000 |
| 2 | Actual RPM | Process -> PLC | Current sensed RPM |
| 3 | Temperature | Process -> PLC | Celsius x 100 |
| 4 | Pressure | Process -> PLC | bar x 100 |
| 5 | Power | Process -> PLC | kW x 100 |
| 6 | Event code | Test mode -> process | 0 none, 1 RPM deviation, 2 temperature increase, 3 pressure spike, 4 sensor inconsistency |
| 7 | Event value | Test mode -> process | Event-specific fictional value |

## Outputs for later CHEM-SHIELD phases

`data/telemetry.db` contains the stable `telemetry` table with timestamp,
machine ID, PLC ID, motor status, target RPM, RPM, temperature, pressure, and
power. The `events` table uses the common event format and is ready for later
network, ML, correlation, and risk components.

## Tests

```bash
python -m unittest discover -s chem_shield/tests -v
```

All components are simulation-only and should remain bound to `127.0.0.1` for
this academic prototype.


We are using pip version 21.2.4; however, version 26.0.1 is available.
You should consider upgrading via the '/Users/moonlit-night/Desktop/CHEM-SHIELD-/chem_shield/.venv/bin/python -m pip install --upgrade pip' command.


