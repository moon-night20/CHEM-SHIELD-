# CHEM-SHIELD

CHEM-SHIELD is an academic, simulation-first OT monitoring and defensive
cybersecurity project. Keep the virtual PLC bound to loopback for local demos.
The project does not authorize production OT connections or automated
mitigation.

## Project parts

- [Part 1: virtual OT lab and operator HMI](./chem_shield_p1/README.md)
- [Part 2: fixture-backed network adapters and scoring](./chem_shield_p2/README.md)
- [Part 3: physical-process ML detector](./chem_shield_p3/README.md)
- [Part 4: correlation and canonical risk engine](./chem_shield_p4/correlation/README.md)
- [Part 5: OT monitoring entry point](./chem_shield_p5/ot_monitor/README.md)
- Part 6: operator-confirmed simulated response

> **Part 3 held-out synthetic evaluation:** training on 6,000 P1-simulated
> normal samples and testing on complete unseen attack scenarios detected
> **87.5%** of `stealthy_in_range` samples (first detection: **0 s**) and
> **7.5%** of `slow_gradual_drift` samples (first detection: **0.5 s**).
> The separate one-hour normal run produced **339 false alarms/hour**
> (4.71% false-positive rate). These simulator-only figures are not real-world
> performance claims; see `chem_shield_p3/results/heldout_scenario_evaluation.csv`.

The Part 1 HMI provides the Part 4 risk API and SQLite persistence; detector
risk and incident history are presented in the separate Admin console. The
Admin dashboard also shows a live machine-reading risk band and a limit-ratio
score based on the highest configured temperature, pressure, power, or speed
reading. Readings below 75% of a limit are NORMAL; readings from 75% through the
limit are MEDIUM; exceeding any configured limit is CRITICAL. Current upper
limits are 70 °C, 4 bar, 12 kW, and 1500 RPM. This operational indicator is
separate from the Part 4 detector score and is not a probability.
P2 network replay and the P5 physical monitor can explicitly publish scored
events to the HMI's loopback `POST /api/risk/events` endpoint. No background
capture or automated response is enabled.

## Start the complete virtual machine

This starts the local virtual PLC, its physical-process simulator, the
operator's machine screen, the separate admin console, and the OT Command
Testing Console. Run the commands
from the repository root. Keep each server terminal open while using the
machine.

### One-time setup

Python 3.10 or newer is recommended; the current local environment has also
been exercised with Python 3.9. Create the environment and install the
repository's combined dependencies once:

```bash
python3 --version
python3 -m venv chem_shield_p1/.venv
chem_shield_p1/.venv/bin/python -m pip install -r requirements.txt
```

If `chem_shield_p1/.venv` already exists, keep using it; skip the `venv`
creation command. To create a local admin account on a fresh checkout, run this
once and enter a password when prompted. The password is not included in the
command:

```bash
chem_shield_p1/.venv/bin/python -m admin_part.manage_users create admin --role administrator
```

User accounts are local to this machine. Their password hashes are kept in the
ignored `admin_part/data/users.json`, not in the repository. If accounts
already exist, do not create a duplicate; inspect usernames and roles with:

```bash
chem_shield_p1/.venv/bin/python -m admin_part.manage_users list
```

### Start the machine (five terminals)

Open five terminals, set each terminal's working directory to the repository
root, then run one command in each. Start them in this order.

**Terminal 1 — virtual PLC**

```bash
chem_shield_p1/.venv/bin/python -m chem_shield_p1.plc.modbus_plc --host 127.0.0.1 --port 15020
```

This starts PLC-01's local Modbus TCP register server.

**Terminal 2 — physical-process simulator**

```bash
chem_shield_p1/.venv/bin/python -m chem_shield_p1.process.main --host 127.0.0.1 --port 15020 --database chem_shield_p1/data/telemetry.db
```

This reads commands from the PLC, advances the fictional motor/process model,
updates its sensor registers, and appends telemetry to SQLite.

The HMI protects its event-ingest API with `CHEM_SHIELD_INGEST_TOKEN`. For
manual multi-terminal startup, export the same local demo token in every
terminal before starting the HMI or a publisher:

```bash
export CHEM_SHIELD_INGEST_TOKEN="local-demo-only-change-me"
```

This value is only for the loopback demo; do not reuse it for another
environment. `scripts/run_all.py` generates one token when this variable is
unset and passes it to its child services. If you run the optional pipeline
demo against an HMI started by `run_all.py`, set an explicit token in the
terminal before starting `run_all.py` and keep that same exported value for
the pipeline-demo command.

**Terminal 3 — operator machine screen**

```bash
chem_shield_p1/.venv/bin/python -m chem_shield_p1.hmi.app --host 127.0.0.1 --port 15000 --plc-port 15020 --database chem_shield_p1/data/telemetry.db
```

This starts the full-screen machine console and connects it to the PLC. Open
**http://127.0.0.1:15000**. Use **START** to run the simulated motor, **STOP**
for normal operator stop, **PAUSE** to pause, and **APPLY TARGET** to update
the simulated RPM target.

**Terminal 4 — admin console**

```bash
chem_shield_p1/.venv/bin/python -m admin_part.app
```

Open **http://127.0.0.1:5000** and sign in with a local admin-console account.
Use its Dashboard and Incidents pages for detector risk and incident review;
the operator machine controls remain on port 15000. The admin Machine page is
read-only.

**Terminal 5 — OT Command Testing Console**

```bash
chem_shield_p1/.venv/bin/python -m the_attack.app --host 127.0.0.1 --port 5001 --plc-port 15020 --database chem_shield_p1/data/telemetry.db
```

Open **http://127.0.0.1:5001**. This separate, loopback-only page accepts a
numeric temperature, power, pressure, or speed value and applies it directly
to the corresponding simulated machine telemetry. Values remain active until
changed or cleared with **Clear all overrides**. Supported ranges are
temperature **0–120 °C**, power **0–20 kW**, pressure **0–10 bar**, and speed
**0–3000 RPM** (whole numbers). Accepted requests are audited; the history
stays pending until later telemetry confirms the requested value. When measured
telemetry exceeds a configured OT limit, the console publishes a risk event to
the HMI incident register; the Admin dashboard counts it and the administrator
Audit page includes the OT command and risk-event records. The ingest token
must be shared with the HMI as described above. This does not automatically
stop or otherwise control the motor. Use the **Attack Console** link in the
Admin navigation or **Open Attack Console** on the Incidents page.

The normal virtual machine fluctuates below its operating limits of **70 °C**,
**4 bar**, **12 kW**, and **1500 RPM**, rather than holding at the limits. The
Attack Console accepts values above these operating limits;
such explicit overrides appear as critical warnings. Input bounds do not
change those monitoring thresholds. These are simulated sensor-value
overrides only and do not operate physical equipment.

Run the focused tests with:

```bash
chem_shield_p1/.venv/bin/python -m pytest -q the_attack/tests/test_console.py scripts/chain/tests/test_run_all.py
```

### One-command demo launcher

From the repository root, run the cross-platform launcher with the Python
environment configured above:

```bash
python scripts/run_all.py
```

It starts the same five commands in the same order, waits for the virtual PLC
on `127.0.0.1:15020` before starting its dependents, and prefixes each child's
output with its service name. Press **Ctrl+C** once to stop all children. The
launcher refuses non-loopback hosts. To use the individual commands instead,
keep using the five-terminal instructions above.

### Stop and restart

To shut down, press **Ctrl+C** in each of the five server terminals. Start
again in the same order. Use the operator screen's **START** control when you
are ready to run the simulated motor; detector alerts do not start or stop it.
Telemetry and risk incidents are stored locally in
`chem_shield_p1/data/telemetry.db` and persist when the web server restarts.

### Troubleshooting startup

- **PLC address already in use:** confirm no other program is using port
  `15020`. Stop an older copy with **Ctrl+C** in its terminal, then restart
  Terminal 1.
- **HMI shows PLC offline:** verify Terminal 1 and Terminal 2 are running on
  `127.0.0.1:15020`, and Terminal 3 was started with `--plc-port 15020`.
- **Admin page cannot open:** verify Terminal 4 is still running on port
  `5000`; the machine console at port `15000` is a separate service.
- **Login rejected:** check the local account list with the command above.
  If needed, create a distinct user with
  `chem_shield_p1/.venv/bin/python -m admin_part.manage_users create USER --role administrator`;
  it securely prompts for the password. Repeated failed attempts are
  rate-limited temporarily.
- **OT Command Testing Console cannot connect:** verify the PLC and process
  simulator are running on `127.0.0.1:15020`; the console is on port `5001`.
- **Dependency/import error:** rerun the pip install command from the
  repository root using `chem_shield_p1/.venv/bin/python`.

Keep all services bound to `127.0.0.1`. These are fictional simulation
components, not a real PLC or a safety controller. Do not expose the HMI,
Modbus port, or admin console to another network.

## How the virtual machine works

The four terminals are separate processes, connected through the same
interfaces a small lab control system would use:

```text
Browser / operator
        |
        v
Part 1 operator HMI :15000 ---- Modbus TCP ---- Part 1 virtual PLC :15020
        |                                            ^
        |                                            | sensor registers
        |                                            |
        +-- SQLite telemetry <---- Part 1 process simulator
        |
        +-- Part 4 risk API <---- Part 2 and Part 5 (explicit local publish)
                 |                           |
                 +---- SQLite incidents      +-- Part 3 physical model
                 |
                 +---- read-only admin feed :5000
```

- **Part 1 — virtual machine / OT lab:** The PLC server owns an eight-register
  Modbus holding-register map. The HMI writes the motor command and target RPM;
  the separate process simulator reads those values, models acceleration,
  temperature, pressure and power, then writes the resulting readings back.
  It also stores telemetry and operator/test events in the shared SQLite
  database. The page is a simulator UI, although its connection panel uses
  device/PLC terminology.
- **Part 2 — network-event replay:** Replays sanitized JSON/JSONL fixtures.
  Its adapters normalize records and a fixture-trained model adds an anomaly
  score. It processes fixture/replayed Zeek, Suricata, and Modbus-monitor data;
  it does not perform live packet capture or connect to the virtual PLC.
- **Part 3 — physical anomaly model:** Supplies the saved model used to score
  telemetry features when available. A model score ranks relative anomaly; it
  is not a probability or a determination of an attack.
- **Part 4 — event correlation and risk:** Validates and groups scored
  network/physical events by asset and time, computes the configured
  experimental risk score, and persists incident history alongside the HMI
  database. Risk is reviewed in the Admin console. The HMI can display a
  high/critical alert, but risk does not automatically stop or control the
  process.
- **Part 5 — OT physical monitor:** Validates telemetry and applies configured
  engineering/state rules, optionally scores readings with Part 3, and can
  explicitly publish scored events to the local Part 4 API. Its rule events
  are alerts, not PLC commands. CSV sample data is synthetic.
- **Part 6 — operator-confirmed simulated response:** The HMI offers a
  simulated stop only for an eligible active CRITICAL risk incident. The
  operator must explicitly confirm it; no detector, rule, risk score, or admin
  page automatically stops the machine. It is not a physical safety function.

The HMI's machine-condition badge uses the configured upper limits (temperature
70 °C, pressure 4 bar, power 12 kW, and speed 1500 RPM). Exceeding any one
reports CRITICAL; otherwise it reports NORMAL. This is a status only and does
not cause a stop. It is separate from the Part 4 detector-based incident-risk
score.

## Run the optional detection demos

The basic four-terminal machine runs without the detection pipeline. Start the
four services first if you want detector events to appear in the admin live
risk view.

Reproduce the held-out Part 3 evaluation with:

```bash
chem_shield_p1/.venv/bin/python -m chem_shield_p3.scripts.evaluate_heldout
```

The model is trained only on P1-generated normal runs; the full
`stealthy_in_range` and `slow_gradual_drift` attack scenarios are absent from
training. Per-scenario detection rates, first-detection delay, and false alarms
per hour of normal telemetry are written under `chem_shield_p3/results/`.

To replay the bundled network and physical demo fixtures and publish their
scored events to the loopback HMI:

```bash
chem_shield_p1/.venv/bin/python -m scripts.run_pipeline_demo
```

This is a one-shot fixture demonstration, not a background detector. It does
not connect to or control the virtual PLC.

To run the staged, file-backed P2 -> P3 -> P4 -> P5 chain and write its reports
under `out/`:

```bash
chem_shield_p1/.venv/bin/python -m scripts.run_chain --step-by-step
```

Add `--publish` to explicitly send the scored P2/P3 events from that run to the
local HMI. The HMI must already be running. This chain uses its configured
fixture/CSV inputs and is separate from the continuously running Part 1
machine. See [Pipeline outputs](#strict-sequential-p2-to-p5-chain) for the
JSON handoffs.

To run Part 5 directly on its bundled synthetic telemetry CSV and publish
scored events:

```bash
chem_shield_p1/.venv/bin/python -m chem_shield_p5.ot_monitor \
  --csv chem_shield_p5/ot_monitor/samples/abnormal_telemetry.csv \
  --config chem_shield_p5/ot_monitor/config.example.json \
  --publish --hmi-url http://127.0.0.1:15000/api/risk/events
```

Published events may use fixture timestamps and represent a demonstration,
not a live alert. Do not interpret demo scores as current machine condition.

## Data flow

P1 simulation telemetry is stored locally and can be read by P5; P2 replays
sanitized network fixtures. P2 scores network records, while P5 keeps its
sensor validation/rules and scores telemetry with P3's saved physical model.
Both producers use the shared publisher to send scored events to the P1 HMI,
where P4 correlates by asset and time, calculates experimental risk, and feeds
the dashboard.

## Strict sequential P2-to-P5 chain

The offline chain enforces one JSON handoff per stage. No stage reads a later
stage's output, and P1 is only an optional final dashboard sink:

```text
network JSON/JSONL
      |
      v
P2 replay + network scoring --> out/p2_events.json
      |
      v
P3 saved physical model <--- telemetry CSV
      |                       (P2 anomaly window +/- 10 s)
      v
P4 correlation + canonical risk --> out/p4_incidents.json
      |                       out/p3_events.json
      v
P5 sensor validation + rules <--- same telemetry CSV
      |
      +--> out/p5_report.json
      |
      +--> optional P1 HMI sink (loopback only, with --publish)
```

The handoff contracts are:

- **P2** writes an object containing `events` (scored network events in the
  Part 4 event format) and `handoff` (`asset_ids`, `window`, `threshold`, and
  `anomalous_event_count`). The window spans events with a score at or above
  the configurable threshold.
- **P3** reads the P2 handoff and telemetry CSV, selects rows within the P2
  time window plus/minus the 10-second correlation window, and writes a list
  of Part 4 physical events to `p3_events.json`. The saved P3 model is used
  here; the P5 step does not score telemetry again. The configured PLC asset
  ID is the canonical ID for demo telemetry aliases such as `M-01`.
- **P4** reads the P2 and P3 files, correlates events by asset and the existing
  10-second rule, calculates risk using Part 4's unchanged risk engine, and
  writes incidents to `p4_incidents.json`.
- **P5** reads the P4 incidents and the same telemetry CSV. It runs only
  `SensorValidator` and `RuleEngine` (no P3 model, PLC writes, or database
  persistence) and writes per-incident results to `p5_report.json`.

Run the demo using aligned fixture timestamps:

```bash
chem_shield_p1/.venv/bin/python -m scripts.run_chain --step-by-step
```

The runner defaults to `chem_shield_p2/fixtures/demo_network_events.json`,
`chem_shield_p5/ot_monitor/samples/abnormal_telemetry.csv`, threshold `0.5`,
and `out/`. Override inputs and output location with `--network-input`,
`--telemetry`, and `--out-dir`. Use `--from-stage N --to-stage N` to rerun
one numbered chain stage (1=P2, 2=P3, 3=P4, 4=P5) from its saved predecessor
handoff. `--publish --hmi-url http://127.0.0.1:15000/api/risk/events` sends
the P2 and P3 event files to the loopback HMI only.

Troubleshooting:

- **No anomalies from P2:** check the P2 threshold and fixture contents. With
  no threshold-qualified P2 events, P3 writes an empty event list and the
  runner reports `no network trigger`.
- **Telemetry outside the P2 window:** P3 only scores rows within 10 seconds
  of the P2 anomaly window; align fixture timestamps or supply a matching CSV.
- **Asset ID mismatch:** P2's configured asset mapping and P5's
  `risk_asset_id` must agree. Telemetry source IDs are mapped to that canonical
  PLC ID only for this configured single-asset demo.
- **HMI not running:** the pipeline works without an HMI unless `--publish` is
  selected. Start the HMI on `127.0.0.1:15000` before publishing.

## Part 6: operator-confirmed simulated response

Part 6 is available in the operator HMI's existing risk-alert popup. For an
active CRITICAL incident, the operator may explicitly confirm a simulated
stop there; HIGH and lower incidents cannot invoke it. No stop is automatic.
Part 6 also supplies the HMI's small warning popup: it displays when configured
machine sensor limits are exceeded or a new MEDIUM/HIGH/CRITICAL event or risk
incident is reported. Warnings are informational only; opening or dismissing
one never sends a machine command.
The endpoint requires a page-generated confirmation token and rejects requests
unless both the caller and configured PLC address are loopback. The response
is recorded in the local event log. This is for the virtual PLC lab only; it
does not authorize production connections or safety-system use.

## Test the risk-event API

Risk input is independent of PLC control and can be tested with sanitized,
synthetic events. Start the HMI using the four-terminal instructions above
before posting:

```bash
curl -X POST http://127.0.0.1:15000/api/risk/events \
  -H 'Content-Type: application/json' \
  -d '{"events":[{"event_id":"demo-network-1","timestamp":"2026-10-14T09:30:00Z","source":"network_model","asset_id":"PLC-01","event_type":"network","anomaly_score":0.9,"evidence":{"fixture":"synthetic demonstration"}},{"event_id":"demo-physical-1","timestamp":"2026-10-14T09:30:04Z","source":"ot_monitor","asset_id":"PLC-01","event_type":"physical","anomaly_score":0.9,"evidence":{"fixture":"synthetic demonstration"}}]}'
```

The default Part 4 formula and thresholds are experimental project values, not
validated industrial safety settings. Scores are not probabilities. Read the
Part 4 documentation for lifecycle semantics, API routes, and tests.

## Run the connected fixture demo

The runner starts a temporary loopback HMI when needed, publishes P2 and P5
fixture events, then prints the correlated scored incidents:

```bash
chem_shield_p1/.venv/bin/python -m scripts.run_pipeline_demo --start-hmi
```

Alternatively, omit `--start-hmi` when the HMI is already running on
`127.0.0.1:15000`.

## Admin console

The operator machine HMI (`127.0.0.1:15000`) and supervisor admin console
(`127.0.0.1:5000`) are separate pages and processes. The HMI's **Admin** link
opens the console login in a new tab; the admin console has its own credentials
and session, and provides a **Back to machine HMI** link. The admin console is
the supervisory view of live detector risk and P4/P5 incidents. It reads the
HMI's live risk feed and `out/p4_incidents.json` / `out/p5_report.json`; it does
not launch the pipeline or change its handoff files. The operator HMI reserves
its full screen for the virtual machine. The admin Machine page is read-only
and reports OFFLINE when the HMI is unreachable; START/STOP and test controls
remain only in the operator HMI.

```text
P2 network scoring -> P3 physical ML -> P4 correlation/risk -> P5 OT validation -> Admin console
```

| Role | Permissions |
| --- | --- |
| administrator | Incidents, decisions, users, settings, and audit log |
| analyst | View incidents, acknowledge, escalate, mark false positive, add notes, and record a simulated response |
| operator | Read-only view of incidents affecting the process and their status |

Create users locally with the commands below. No default password is shipped;
the password is prompted for and stored only as a Werkzeug hash in the ignored
`admin_part/data/users.json` file. The admin interface has its own stylesheet
and login page.

```bash
chem_shield_p1/.venv/bin/python -m admin_part.manage_users create ADMIN_NAME --role administrator
chem_shield_p1/.venv/bin/python -m admin_part.manage_users list
chem_shield_p1/.venv/bin/python -m admin_part.manage_users delete USER_NAME
```

The four-terminal startup section above starts the console. If
`CHEM_SHIELD_SECRET_KEY` is not set, the app generates a random session key at
startup, so browser sessions reset when the admin process restarts. To retain
sessions across restarts, set a stable secret in the admin terminal before
starting the app. The local user accounts and password hashes persist
independently of the session key.

The P6 operator-confirmation token is generated by the HMI for each process
start; restarting the HMI rotates it. P1 ingest also requires a token: without
`CHEM_SHIELD_INGEST_TOKEN`, the HMI generates a random per-process token that
is not exposed in its logs or API. For a stable local demo, use example-only
values and set them before starting the relevant processes:

```bash
export CHEM_SHIELD_SECRET_KEY="demo-only-session-key"
export CHEM_SHIELD_INGEST_TOKEN="demo-only-ingest-token"
```

Set the session key in the admin console environment, and set the ingest token
in both the HMI and any P2/P5 publisher environment. These example values are
for local demonstrations only; do not reuse them as real credentials.

Open `http://127.0.0.1:5000`. If chain outputs are absent or malformed, the
console reports that state and shows the chain command. P1 ingest always
requires `X-Ingest-Token`: when `CHEM_SHIELD_INGEST_TOKEN` is unset, the HMI
generates an unpredictable per-process token (and logs that generation without
revealing its value). For P2/P5 publishing, set the same
`CHEM_SHIELD_INGEST_TOKEN` in the HMI and publisher environments; the publisher
reads it and sends it as the request header. A generated token is not exposed
over an endpoint or in logs. The console is simulation-only and loopback-only. Decisions,
including a simulated response, are recorded in a local audit log and are
never executed against equipment.

The admin Dashboard and Machine page poll the loopback HMI's state, connection,
risk, and telemetry APIs every three seconds using GET-only requests. They show
the last update and an OFFLINE/STALE notice when live data is unavailable or
older than ten seconds. The incident register uses HMI incidents when available
and falls back to the most recent P4/P5 chain files when the HMI cannot be
reached; incidents are associated across sources only by matching asset and
overlapping time windows. An admin acknowledgement is the only machine-HMI
write exposed here: it calls the HMI's existing incident acknowledgement route.
All other supervisory decisions are local audit records. A simulated response
does not invoke `chem_shield_p6/` or shut down the machine.

The HMI's Admin link defaults to `http://127.0.0.1:5000`; set
`CHEM_SHIELD_ADMIN_URL` to another `http://` or `https://` admin URL if needed.
Set `CHEM_SHIELD_HMI_URL` to the reachable machine HMI URL (default
`http://127.0.0.1:15000`) to configure the admin console's backlink and
read-only Machine page. Only HTTP(S) URLs without credentials, query strings,
or fragments are accepted. `CHEM_SHIELD_ADMIN_HOST` changes the admin bind
address (default `127.0.0.1`). Non-loopback binding is refused unless
`CHEM_SHIELD_ALLOW_REMOTE=1` and an explicit `CHEM_SHIELD_SECRET_KEY` are set;
`CHEM_SHIELD_COOKIE_SECURE=1` enables the Secure session-cookie flag for HTTPS
deployment. `CHEM_SHIELD_DEBUG=1` enables development debug mode.

**Lab use only. Never expose this console or the machine HMI to the internet.**
Remote binding is an explicit, warned exception for a protected lab network,
not a production deployment mode. A link does not grant access, and the admin
console never sends control commands to the machine.
