# CHEM-SHIELD — Local OT Defense Dashboard

The OT Defense Dashboard is a standalone, offline-capable, simulation-only lab. It
combines a chemical reactor twin, in-memory PLC register map, synthetic OT
event monitor, process-physics and ML anomaly scoring, SIS baseline checks,
Purdue-zone policy, six defensive replay scenarios, approval-gated simulated
response, and HTML/PDF incident reports.

The dashboard reads the existing machine HMI's
`http://127.0.0.1:15000/api/state` and `/api/risk` endpoints and presents the
live virtual machine status, readings, and data path first. This integration
is read-only: the dashboard never writes to, sends commands to, scans, or controls
the connected machine services or physical equipment. The reactor twin and scenario traffic
are separate local synthetic data, clearly labeled as simulation.

## Requirements

- Python 3.9 or newer.
- Dependencies listed in [`requirements.txt`](./requirements.txt).
- No external service or CDN is required at runtime. Install dependencies
  before going offline.

From the repository root, create an environment and install the dashboard
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

The dashboard can run independently if the machine HMI is not running. To show
live machine readings, start the machine services before opening the dashboard.
The panel reports the feed as unavailable when the machine HMI is
stopped; the reactor twin, detectors, scenarios, responses, and reports
continue to work locally.

The Admin Console is the main project navigation hub for Dashboard, Machine,
Incidents, Scenario Command Center, and administrator-only Users and Audit
pages. It links to this read-only OT Defense Dashboard. The dashboard keeps its own
Dashboard, Machine, Network & OT, AI / ML & Alerts, Response, and Backend views,
and provides a single **Admin Console** link back to the hub; it does not repeat
Admin's page navigation. The Attack Console has its own link and the Machine HMI
is available in the Machine view. Defaults are
`http://127.0.0.1:5000` and `http://127.0.0.1:5001`; override them with
`CHEM_SHIELD_P8_ADMIN_URL` and `CHEM_SHIELD_P8_ATTACK_CONSOLE_URL` when those
services use different loopback ports. For safety, P8 accepts only bare HTTP
URLs on `127.0.0.1` with an explicit valid port.

## Use the dashboard

The dashboard is organized into viewport-sized tabs to keep the overview
compact. On smaller displays, individual views can scroll without growing the
whole dashboard page. The overview reports live results from its defense
services; the separate offline analysis workflow is not started by the dashboard.

1. Use **Dashboard** for current network, OT-policy, AI/ML, correlation,
   risk, alert, and SIS-integrity summaries.
2. Open **Machine** for machine HMI readings and the local reactor twin. The HMI
   data is read-only; use the existing machine HMI for its controls.
3. Use **Reactor twin controls** to pause/resume the local reactor model, toggle
   its simulated feed pump, or set the simulated coolant-valve target. These
   controls affect only the local twin; monitoring stays online and the
   connected machine remains read-only.
4. In **Network & OT**, choose one of six synthetic scenarios and use **PLAY**,
   **PAUSE**, or **STEP**. Review protocol events, Purdue-zone decisions, and
   discovered assets. The timeline slider scrubs generated events.
5. Use **AI / ML & Alerts** for the physics and Isolation Forest scores,
   findings, ATT&amp;CK annotations, and alert evidence.
6. Use **Backend** to inspect the live in-memory correlation and risk results
   alongside the offline analysis workflow. The risk engine correlates validated
   synthetic alerts by asset and time; it does not write to the incident database.
   The workflow guide does not start the separate file-backed analysis chain.
7. In **Response**, propose a response playbook and explicitly approve or
   reject it. Approval
   only updates the dashboard's in-memory demo state and local audit log.
8. Select **GENERATE INCIDENT REPORT** in **AI / ML & Alerts** to create HTML
   and PDF snapshots. Files
   are saved under `chem_shield_p8/data/reports/` and can be downloaded from
   the dashboard.

To run the separate offline analysis workflow from the repository root:

```sh
chem_shield_p1/.venv/bin/python -m scripts.run_chain --step-by-step
```

Use `--publish` only when you intentionally want the scored network and
physical events sent to the existing loopback HMI. The final analysis step produces a validation
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

- All dashboard services bind to `127.0.0.1`; the dashboard also rejects
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
