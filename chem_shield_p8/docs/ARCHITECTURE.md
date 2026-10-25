# Part 8 architecture

Part 8 is a standalone local application. The Flask dashboard coordinates
separate Python modules and serves a same-origin HTML/CSS/JavaScript client.
Its compact, navigable views keep the live overview separate from machine,
network/OT, detection, response, and backend detail panels.
The process twin and protocol scenarios are independent synthetic sources;
the existing Part 1 virtual machine is displayed from its HMI's read-only API.
The integrated machine and the local reactor twin are separate data sources.

```mermaid
flowchart LR
    Browser["Browser UI<br/>127.0.0.1"] <-->|"same-origin HTTP / SSE<br/>CSRF on mutations"| Dashboard["Flask dashboard"]
    Dashboard --> Runtime["DashboardRuntime"]
    Runtime --> Twin["plant_twin<br/>reactor physics + PLC map"]
    Runtime --> Guard["physics_guard<br/>rules + Isolation Forest"]
    Runtime --> SIS["sis_watch<br/>signed baseline + hash chain"]
    Runtime --> Replay["attack_lab<br/>synthetic scenario timeline"]
    Replay --> Monitor["ot_monitor<br/>event parsing + detection + inventory"]
    Replay --> Zones["zones<br/>Purdue conduit policy"]
    Runtime --> Response["response<br/>proposal / operator approval"]
    Runtime --> Reports["reports<br/>HTML + PDF snapshot"]
    Process["Part 1 process simulator"] <-->|"simulated registers"| PLC["Part 1 virtual PLC<br/>127.0.0.1:15020"]
    ExistingHMI["Part 1 operator HMI<br/>127.0.0.1:15000"] -->|"read process state"| PLC
    Runtime -. "GET /api/state, /api/risk only" .-> ExistingHMI
    ExistingHMI -. "read-only machine snapshot" .-> Browser
    Response --> LocalState["Part 8 in-memory demo state<br/>local decision log"]
    SIS --> LocalAudit["Part 8 local SIS hash chain"]
    Reports --> LocalFiles["Part 8 data/reports/"]
```

## Data flow

1. `plant_twin` advances a deterministic reactor model using bounded local
   controls and publishes scaled values to an in-memory PLC-style map. The
   dashboard can pause/resume this model and adjust its simulated feed pump
   and coolant-valve target; the monitoring service remains online while the
   twin is paused.
2. `physics_guard` compares telemetry against rate, energy, mass, and
   cross-sensor rules and reports a separate locally trained Isolation Forest
   deviation score.
3. `attack_lab` steps through JSON event timelines. Its replay session passes
   only those supplied records to `ot_monitor`, `zones`, and `sis_watch`.
4. The dashboard reads machine status from the Part 1 HMI API while separately
   advancing the local reactor twin. Its first panel makes the simulator →
   virtual PLC → HMI → read-only dashboard path visible. Findings are
   correlated into a snapshot and SSE stream; scenario evidence, asset
   inventory, compliance checks, and response decisions remain local.
5. P8 summarizes network, OT-zone, AI/ML, alert, and SIS outputs from those
   local modules. It passes validated synthetic network and physical detector
   alerts to the existing P4 correlation and risk engine in memory; it does
   not write to the P4 incident store or combine distinct asset identities.
6. Operators can propose a response. The `response` module records a pending
   decision; only an explicit approve action applies its simulated effect.
7. `reports` turns a point-in-time dashboard snapshot into self-contained HTML
   and PDF files for local download.

## Existing P2–P5 offline pipeline

The dashboard includes a read-only guide to the repository's separate
file-backed runner, `scripts.run_chain`. This is not the Part 8 scenario
runtime and is not started by opening the dashboard.
P8's in-memory P4 analysis is a separate display path and does not start the
P2–P5 runner.

```mermaid
flowchart LR
    Net["Sanitized network fixture"] --> P2["P2 replay + network scoring"]
    P2 --> Handoff["Asset IDs + anomaly time window"]
    Handoff --> P3["P3 saved physical model"]
    Telemetry["Local telemetry CSV"] --> P3
    P3 --> Physical["Physical anomaly events"]
    P2 --> P4["P4 correlate P2 + P3; calculate risk"]
    Physical --> P4
    P4 --> Incidents["P4 incident handoff"]
    Incidents --> P5["P5 sensor validation + rules"]
    Telemetry --> P5
    P5 --> Report["P5 validation report"]
    P2 -. "optional --publish" .-> HMI["Part 1 HMI · loopback"]
    Physical -. "optional --publish" .-> HMI
```

P3 uses the P2-selected telemetry window and saved physical model. P4
correlates P2 network events and P3 physical events. P5 checks the P4 incident
windows against telemetry with sensor validation and rules; it does not run
the P3 model again. The optional `--publish` flag sends the P2/P3 events to
the loopback HMI; P5 writes its report locally.

## Trust boundaries

- The Flask server is hard-bound to `127.0.0.1`; requests from non-loopback
  addresses are rejected. Mutating browser routes require CSRF validation.
- Existing CHEM-SHIELD integration is restricted to the validated Part 1 HMI
  loopback origin and GET requests. CSRF-protected P8 controls mutate only the
  local reactor twin; no Part 8 action is forwarded to the Part 1 HMI.
- Synthetic scenario IP addresses use documentation-only ranges. No packets,
  scans, firewall changes, or device commands are generated.
- Response, SIS, and report files are written under the Part 8 data directory.
- Compliance and ML outputs are demonstrative analysis, not formal
  certification or probability claims.

## Configuration and persistence

YAML under `config/` describes process tags and limits, OT-monitor rules,
physics settings, Purdue zones/conduits, and response playbooks. Scenario
timelines are in `attack_lab/scenarios.json`. Runtime keys, hash-chain logs,
response logs, and generated reports are stored in the ignored `data/`
directory.
