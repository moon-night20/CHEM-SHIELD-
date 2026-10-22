# CHEM-SHIELD Part 8 — Local OT Defense Lab

Part 8 is a standalone, offline-capable, simulation-only OT defense lab. It
combines a chemical reactor twin, in-memory PLC register map, synthetic OT
event monitor, process-physics and ML anomaly scoring, SIS baseline checks,
Purdue-zone policy, six defensive replay scenarios, approval-gated simulated
response, and HTML/PDF incident reports.

The dashboard reads the existing CHEM-SHIELD Part 1 HMI's
`http://127.0.0.1:15000/api/state` and `/api/risk` endpoints and presents the
live virtual machine status, readings, and data path first. This integration
is read-only: Part 8 never writes to, sends commands to, scans, or controls
Part 1–7 services or physical equipment. The reactor twin and scenario traffic
are separate local synthetic data, clearly labeled as simulation.

## Requirements

- Python 3.9 or newer.
- Dependencies listed in [`requirements.txt`](./requirements.txt).
- No external service or CDN is required at runtime. Install dependencies
  before going offline.

From the repository root, create an environment and install the Part 8
dependencies:

```sh
python3 -m venv .venv-p8
source .venv-p8/bin/activate
python -m pip install -r chem_shield_p8/requirements.txt
```

## Run

From the repository root, start the dashboard with one command:

```sh
python -m chem_shield_p8.run
```

Open <http://127.0.0.1:15080>. The service binds only to loopback. If port
15080 is occupied, select a different local port:

```sh
CHEM_SHIELD_P8_PORT=15081 python -m chem_shield_p8.run
```

Part 8 can run independently if the existing HMI is not running. To display
the HMI integration panel, start the Part 1 HMI separately before opening
Part 8. The P8 panel will report the feed as unavailable when Part 1 is
stopped; the reactor twin, detectors, scenarios, responses, and reports
continue to work locally.

## Use the dashboard

1. Check the **Live Virtual Machine** panel for machine connectivity, motor
   status, current readings, and the simulator → PLC → HMI → dashboard path.
   The panel is read-only; use the existing machine HMI for operator controls.
2. Review the separately labeled local reactor twin, physics/ML scores, zones,
   and discovered synthetic assets.
3. Choose one of the six scenarios and use **PLAY**, **PAUSE**, or **STEP**.
   The timeline slider scrubs the generated events.
4. After the scenario section, use the **P2–P5 backend workflow** shortcuts
   to review how network replay, physical model scoring, risk correlation,
   and OT validation connect. This is an architecture guide; it does not
   start the file-backed chain.
5. Propose a response playbook and explicitly approve or reject it. Approval
   only updates Part 8's in-memory demo state and local audit log.
6. Select **GENERATE INCIDENT REPORT** to create HTML and PDF snapshots. Files
   are saved under `chem_shield_p8/data/reports/` and can be downloaded from
   the dashboard.

To run the existing P2–P5 offline pipeline from the repository root:

```sh
chem_shield_p1/.venv/bin/python -m scripts.run_chain --step-by-step
```

Use `--publish` only when you intentionally want the scored P2/P3 events sent
to the existing loopback HMI. The sequential P5 step produces a validation
report; the dashboard's pipeline panel does not execute this command.

## Test

From the repository root:

```sh
python -m pytest -q chem_shield_p8/tests
```

The test suite covers each module, dashboard loopback and CSRF controls,
report exports, launcher binding, and one integrated end-to-end run/report
for each synthetic scenario.

## Safety and interpretation

- All Part 8 services bind to `127.0.0.1`; the dashboard also rejects
  non-loopback clients.
- Synthetic scenarios are detector tests, not attack tools. The OT monitor
  processes supplied event records; no network discovery or protocol traffic
  is generated.
- Response proposals have no effect until operator approval. Approved actions
  affect only the Part 8 simulation and its local decision log.
- The compliance score is illustrative, not an IEC 62443 or NIST certification.
- The ML score is a deviation score, not an attack probability.
- SIS signing material and audit files are local demonstration artifacts, not
  a hardware root of trust.

See [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) for the module layout and
[`docs/DEMO.md`](./docs/DEMO.md) for a three-minute walkthrough.
