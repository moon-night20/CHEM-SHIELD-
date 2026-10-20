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

Install the project dependencies from the repository root so the operator HMI
and admin console are both available:

```bash
python3 -m venv chem_shield_p1/.venv
chem_shield_p1/.venv/bin/python -m pip install -r requirements.txt
```

This is the way the project was run during implementation: open three
terminals from the repository root and run one command in each terminal:

```bash
chem_shield_p1/.venv/bin/python -m chem_shield_p1.plc.modbus_plc --host 127.0.0.1 --port 15020
```



```bash
chem_shield_p1/.venv/bin/python -m chem_shield_p1.process.main --host 127.0.0.1 --port 15020 --database chem_shield_p1/data/telemetry.db
```

```bash
chem_shield_p1/.venv/bin/python -m chem_shield_p1.hmi.app --host 127.0.0.1 --port 15000 --plc-port 15020 --database chem_shield_p1/data/telemetry.db
```

Then open `http://127.0.0.1:15000`.
Press START and watch the RPM ramp toward the
target. STOP demonstrates the gradual coast-down and cooling response. The
TEST MODE controls generate simulation-only ground-truth events.

The operator HMI dedicates its full viewport to the virtual machine, live
process history, and controls. Detector risk and the persistent incident
register are shown in the authenticated Admin console.

The operator console shows the PLC connection state, actual and target RPM,
temperature, pressure, power, operator command history, and the latest machine
events. Commands and test events are disabled while the PLC is offline.
Its live process-condition badge reads CRITICAL only while temperature is above
80 °C, pressure is above 5 bar, or speed is above 3000 rpm; at or below all
upper limits it reads NORMAL. This is an alert-only simulation status and does
not stop the machine. The separate Part 4 incident-risk score is unchanged.

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

`chem_shield_p1/data/telemetry.db` contains the stable `telemetry` table with timestamp,
machine ID, PLC ID, motor status, target RPM, RPM, temperature, pressure, and
power. P5 may read this telemetry in read-only mode; the existing schema is
unchanged.

## Data flow

The loopback P1 simulator writes telemetry to SQLite. P2 independently replays
sanitized network fixtures, and P5 reads telemetry or its synthetic CSV while
using P3's physical model. Their shared publisher sends only scored events to
the P1 HMI's Part 4 risk endpoint; P4 correlates and displays incidents.

## Tests

```bash
chem_shield_p1/.venv/bin/python -m unittest discover -s chem_shield_p1/tests -v
chem_shield_p1/.venv/bin/python -m unittest discover -s chem_shield_p5/ot_monitor/tests -v
chem_shield_p1/.venv/bin/python -m unittest discover -s chem_shield_p1/hmi/tests -v
```

## Optional OT physical-process monitoring

The separate read-only physical telemetry monitor is maintained in
[Part 5](../chem_shield_p5/ot_monitor/README.md). It maps existing `temperature`,
`pressure`, `rpm`, `motor_status`, and `machine_id` fields without changing the
Part 1 PLC, HMI, or SQLite schema.

All components are simulation-only and should remain bound to `127.0.0.1` for
this academic prototype.

## Part 4 incident and risk dashboard

The existing HMI also exposes Part 4 correlation/risk endpoints. P2 and P5 can
publish scored normalized records to `POST /api/risk/events` using the
loopback-only shared publisher. This path does not call PLC write functions or
alter the existing `telemetry` or `events` tables. Risk-specific data uses
additive `risk_incidents`, `risk_events`, and `risk_ingest_state` tables in the
same SQLite file.

See [Part 4 correlation and risk documentation](../chem_shield_p4/correlation/README.md)
for event shapes, score handling, acknowledgement semantics, curl examples, and
the focused test command. The web service has no authentication layer and must
remain bound to localhost in this academic prototype.
