const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || "";
const byId = (id) => document.getElementById(id);
let latestSnapshot = null;
let displayedTimeline = [];

function safeText(value, fallback = "—") {
  return value === null || value === undefined ? fallback : String(value);
}

function machineNumber(value, digits = 1) {
  const number = Number(value);
  return Number.isFinite(number) ? number.toFixed(digits) : "—";
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

async function postJson(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRFToken": csrfToken,
      "Accept": "application/json",
    },
    body: JSON.stringify(body),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

function showMessage(message) {
  byId("footer-status").textContent = message;
  window.setTimeout(() => {
    if (byId("footer-status").textContent === message) {
      byId("footer-status").textContent = "Machine feed is read-only; test scenarios are simulated.";
    }
  }, 6000);
}

function updateGauge(elementId, valueId, level, label) {
  const gauge = byId(elementId);
  gauge.classList.remove("warning", "critical");
  if (level === "MEDIUM" || level === "HIGH") gauge.classList.add("warning");
  if (level === "CRITICAL") gauge.classList.add("critical");
  byId(valueId).textContent = label;
}

function renderPlant(snapshot) {
  const plant = snapshot.plant;
  byId("kpi-temperature").textContent = Number(plant.temperature_c).toFixed(1);
  byId("kpi-pressure").textContent = Number(plant.pressure_bar).toFixed(2);
  byId("kpi-level").textContent = Number(plant.level_pct).toFixed(1);
  byId("temperature-limit").textContent = `Trip: ${snapshot.trip_alarms.find((item) => item.tag === "temperature")?.limit ?? 100} °C`;
  byId("pressure-limit").textContent = `Trip: ${snapshot.trip_alarms.find((item) => item.tag === "pressure")?.limit ?? 10} bar`;
  byId("temperature-state").className = `state-dot ${plant.temperature_c >= 100 ? "critical" : plant.temperature_c >= 85 ? "warning" : ""}`;
  byId("pressure-state").className = `state-dot ${plant.pressure_bar >= 10 ? "critical" : plant.pressure_bar >= 8 ? "warning" : ""}`;
  byId("feed-pump-state").className = `state-dot ${plant.feed_pump_on ? "" : "warning"}`;
  byId("feed-state").textContent = plant.feed_pump_on ? "Feed pump running" : "Feed pump offline";
  byId("pid-temperature").textContent = `${Number(plant.temperature_c).toFixed(1)}°C`;
  byId("pid-pressure").textContent = `${Number(plant.pressure_bar).toFixed(1)} bar`;
  byId("pid-level").textContent = `${Number(plant.level_pct).toFixed(0)}%`;
  byId("pid-flow").textContent = `${Number(plant.flow_l_min).toFixed(0)}`;
  byId("pid-coolant").textContent = `${Number(plant.coolant_valve_pct).toFixed(0)}%`;
  byId("pid-relief").textContent = plant.relief_valve_open ? "OPEN" : "AUTO";
  const highestSeverity = snapshot.threat_level;
  byId("plant-status").textContent = highestSeverity === "NORMAL" ? "NORMAL" : highestSeverity;
  byId("plant-status").className = `status-badge ${highestSeverity === "CRITICAL" ? "critical" : highestSeverity === "NORMAL" ? "normal" : "warning"}`;
  const vessel = byId("reactor-vessel");
  vessel.classList.remove("warning", "critical");
  if (highestSeverity === "CRITICAL") vessel.classList.add("critical");
  else if (highestSeverity !== "NORMAL") vessel.classList.add("warning");
  byId("coolant-valve").classList.toggle("open", plant.coolant_valve_pct >= 75);
  byId("relief-valve").classList.toggle("alert", plant.relief_valve_open);
  byId("twin-updated").textContent = `TWIN UPDATED ${new Date(snapshot.timestamp).toLocaleTimeString()}`;
}

function renderPhysics(snapshot) {
  const physics = snapshot.physics_guard;
  byId("physics-score").textContent = Number(physics.physics_score).toFixed(2);
  byId("ml-score").textContent = Number(physics.ml_score).toFixed(2);
  byId("physics-bar").style.width = `${Math.min(100, Math.max(0, physics.physics_score * 100))}%`;
  byId("ml-bar").style.width = `${Math.min(100, Math.max(0, physics.ml_score * 100))}%`;
  byId("physics-explanation").textContent = physics.explanation;
  const list = byId("physics-findings");
  list.replaceChildren();
  for (const finding of physics.findings || []) {
    list.append(element("li", "", `${finding.severity}: ${finding.message}`));
  }
}

function renderZones(snapshot) {
  const map = byId("zone-map");
  map.replaceChildren();
  const activeZones = new Set();
  for (const event of snapshot.timeline || []) {
    const detail = event.detail || {};
    const source = detail.source_ip;
    const destination = detail.destination_ip;
    for (const zone of snapshot.zones) {
      if (zone.id === "control" && destination === "192.0.2.20") activeZones.add(zone.id);
      if (zone.id === "engineering" && source === "192.0.2.10") activeZones.add(zone.id);
      if (zone.id === "business_it" && source === "203.0.113.20") activeZones.add(zone.id);
      if (zone.id === "supervisory" && source === "192.0.2.30") activeZones.add(zone.id);
    }
  }
  for (const zone of snapshot.zones) {
    const card = element("div", `zone-card ${activeZones.has(zone.id) ? "active" : ""}`);
    card.append(element("strong", "", zone.name));
    card.append(element("small", "", zone.id === "industrial_dmz" ? "LEVEL 3.5" : `LEVEL ${zone.level}`));
    card.append(element("span", "", zone.id));
    map.append(card);
  }
}

function renderCompliance(snapshot) {
  const result = snapshot.compliance;
  byId("compliance-score").textContent = result.score;
  const arc = Math.round(Number(result.score) * 3.6);
  byId("compliance-gauge").style.background = `conic-gradient(var(--green) 0deg ${arc}deg, #293b40 ${arc}deg 360deg)`;
}

function renderScenarioControls(snapshot) {
  const picker = byId("scenario-picker");
  const selected = picker.value;
  if (picker.options.length !== snapshot.scenarios.length) {
    picker.replaceChildren();
    for (const scenario of snapshot.scenarios) {
      const option = element("option", "", scenario.name);
      option.value = scenario.id;
      picker.append(option);
    }
  }
  if (selected && [...picker.options].some((option) => option.value === selected)) picker.value = selected;
  const chosen = snapshot.scenarios.find((item) => item.id === picker.value) || snapshot.scenarios[0];
  if (chosen) byId("scenario-description").textContent = chosen.description;
  byId("scenario-pause").textContent = snapshot.scenario.playing ? "Ⅱ PAUSE" : "▶ RESUME";
}

function renderTimeline(snapshot) {
  const result = snapshot.scenario.result;
  const entries = snapshot.timeline || [];
  displayedTimeline = entries;
  const slider = byId("time-slider");
  slider.max = Math.max(0, entries.length - 1);
  slider.value = Math.min(Number(slider.value), Number(slider.max));
  renderTimelineAt(Number(slider.value));
  const metrics = byId("scenario-metrics");
  metrics.replaceChildren();
  if (!result) return;
  for (const [label, value] of [
    ["DETECTION", result.detection_time_seconds === null ? "MISSED" : `${result.detection_time_seconds.toFixed(1)}s`],
    ["MISSED RULES", result.missed_steps.length],
    ["FALSE POSITIVES", result.false_positive_count],
  ]) metrics.append(element("span", "", `${label}: ${value}`));
}

function renderTimelineAt(selectedIndex) {
  const target = byId("scenario-timeline");
  target.replaceChildren();
  const visible = displayedTimeline.slice(0, selectedIndex + 1);
  byId("time-position").textContent = `${visible.length} / ${displayedTimeline.length}`;
  if (!visible.length) {
    target.append(element("li", "empty-state", "Scenario events will appear here."));
    return;
  }
  for (const entry of visible) {
    const item = element("li");
    item.append(element("strong", "", `${new Date(entry.timestamp).toLocaleTimeString()} · ${entry.event_type}`));
    const detail = entry.detail || {};
    item.append(element("span", "", detail.message || detail.rule_id || detail.protocol || detail.status || "Simulation event"));
    for (const technique of entry.techniques || []) {
      const badge = element("span", "mitre-chip", `${technique.id} ${technique.name}`);
      badge.title = technique.url;
      item.append(badge);
    }
    target.append(item);
  }
  target.scrollTop = target.scrollHeight;
}

function renderAssets(snapshot) {
  const target = byId("asset-table");
  target.replaceChildren();
  const assets = snapshot.assets || [];
  if (!assets.length) {
    target.append(element("tr", "", ""));
    const cell = element("td", "empty-state", "No replay assets discovered yet.");
    cell.colSpan = 4;
    target.lastElementChild.append(cell);
    return;
  }
  for (const asset of assets) {
    const row = document.createElement("tr");
    for (const value of [
      asset.device_id,
      `${asset.role}${asset.known ? "" : " · NEW"}`,
      asset.ip_address,
      new Date(asset.last_seen).toLocaleTimeString(),
    ]) row.append(element("td", "", value));
    target.append(row);
  }
}

function renderAlerts(snapshot) {
  const target = byId("alert-table");
  target.replaceChildren();
  const alerts = snapshot.alerts || [];
  byId("alert-feed-count").textContent = `${alerts.length} EVENT${alerts.length === 1 ? "" : "S"}`;
  byId("active-alert-count").textContent = String(alerts.length).padStart(2, "0");
  updateGauge("threat-gauge", "threat-value", snapshot.threat_level, snapshot.threat_level);
  if (!alerts.length) {
    const row = element("tr");
    const cell = element("td", "empty-state", "No active scenario alerts.");
    cell.colSpan = 5;
    row.append(cell);
    target.append(row);
    return;
  }
  for (const alert of [...alerts].reverse()) {
    const row = document.createElement("tr");
    row.append(element("td", "", new Date(alert.timestamp).toLocaleTimeString()));
    const severity = element("td");
    severity.append(element("span", `severity-pill ${alert.severity.toLowerCase()}`, alert.severity));
    row.append(severity);
    row.append(element("td", "", alert.rule_id));
    row.append(element("td", "", alert.message));
    const techniques = element("td");
    for (const technique of alert.techniques || []) {
      const badge = element("span", "mitre-chip", technique.id);
      badge.title = technique.name;
      techniques.append(badge);
    }
    row.append(techniques);
    target.append(row);
  }
}

function renderResponse(snapshot) {
  const response = snapshot.response;
  const target = byId("playbook-list");
  if (!target.dataset.ready) {
    target.replaceChildren();
    for (const playbook of response.playbooks) {
      const button = element("button", "playbook-button", `＋ ${playbook.name}`);
      button.type = "button";
      button.title = playbook.description;
      button.addEventListener("click", async () => {
        try {
          const result = await postJson("/api/response/propose", {
            playbook_id: playbook.id,
            operator: byId("operator-name").value.trim(),
            alert: snapshot.alerts[0]?.rule_id || null,
          });
          showMessage(`${playbook.name} is awaiting operator approval.`);
          renderResponse({...snapshot, response: {...response, decisions: [...response.decisions, result]}});
        } catch (error) { showMessage(error.message); }
      });
      target.append(button);
    }
    target.dataset.ready = "true";
  }
  const pending = byId("pending-responses");
  pending.replaceChildren();
  const waiting = response.decisions.filter((decision) => decision.status === "PENDING_APPROVAL");
  if (!waiting.length) {
    pending.append(element("p", "empty-state", "No response proposals pending."));
    return;
  }
  for (const decision of waiting) {
    const playbook = response.playbooks.find((item) => item.id === decision.playbook_id);
    const card = element("div", "pending-card");
    card.append(element("strong", "", playbook?.name || decision.playbook_id));
    card.append(element("p", "", `Proposed by ${decision.proposed_by}. Review and approve or reject this simulation action.`));
    const actions = element("div", "pending-actions");
    const approve = element("button", "approve-button", "APPROVE");
    approve.type = "button";
    approve.addEventListener("click", async () => {
      try {
        await postJson(`/api/response/${encodeURIComponent(decision.action_id)}/approve`, {
          operator: byId("operator-name").value.trim(),
        });
        showMessage("Simulated response approved and recorded.");
        refreshSnapshot();
      } catch (error) { showMessage(error.message); }
    });
    const reject = element("button", "reject-button", "REJECT");
    reject.type = "button";
    reject.addEventListener("click", async () => {
      try {
        await postJson(`/api/response/${encodeURIComponent(decision.action_id)}/reject`, {
          operator: byId("operator-name").value.trim(),
          reason: "Operator declined the simulated response.",
        });
        showMessage("Response proposal rejected and recorded.");
        refreshSnapshot();
      } catch (error) { showMessage(error.message); }
    });
    actions.append(approve, reject);
    card.append(actions);
    pending.append(card);
  }
}

function renderIntegration(snapshot) {
  const integration = snapshot.existing_chem_shield;
  const state = integration?.state;
  const connected = Boolean(integration?.connected && state);
  const status = byId("machine-link-state");
  status.textContent = connected ? "MACHINE CONNECTED" : "MACHINE FEED OFFLINE";
  status.className = `status-badge ${connected ? "normal" : "warning"}`;
  byId("machine-flow").classList.toggle("connected", connected);
  const limitAlerts = Array.isArray(state?.limit_alerts) ? state.limit_alerts : [];

  for (const [id, value, digits, sensor] of [
    ["machine-temperature", state?.temperature, 1, "temperature"],
    ["machine-pressure", state?.pressure, 2, "pressure"],
    ["machine-power", state?.power, 2, "power"],
    ["machine-rpm", state?.rpm, 0, "speed"],
    ["machine-target-rpm", state?.target_rpm, 0, ""],
  ]) {
    byId(id).textContent = connected ? machineNumber(value, digits) : "—";
    byId(id).closest(".machine-reading").classList.toggle(
      "critical",
      connected && limitAlerts.some((alert) => alert.sensor === sensor),
    );
  }

  const motorStatus = connected ? safeText(state.motor_status, "UNKNOWN") : "Unavailable";
  byId("machine-flow-motor").textContent = connected
    ? `Motor status: ${motorStatus}`
    : "Start the machine services to connect";
  const condition = connected ? safeText(state.machine_condition, "UNKNOWN").toUpperCase() : "UNAVAILABLE";
  const activeIncidents = integration?.risk?.active_incidents;
  const incidentCount = Array.isArray(activeIncidents) ? activeIncidents.length : 0;
  const conditionText = byId("machine-condition-text");
  const level = !connected || condition !== "NORMAL"
    ? (condition === "CRITICAL" && connected ? "critical" : "warning")
    : incidentCount || integration?.risk_error ? "warning" : "normal";
  conditionText.className = `machine-condition-text ${level}`;
  if (!connected) {
    conditionText.textContent = "Machine data unavailable. Start the PLC, process simulator, and HMI.";
  } else if (limitAlerts.length) {
    const sensors = limitAlerts.map((alert) => safeText(alert.sensor, "sensor")).join(", ");
    conditionText.textContent = `MACHINE CRITICAL · limit exceeded: ${sensors}`;
  } else if (integration?.risk_error) {
    conditionText.textContent = "MACHINE NORMAL · risk summary is unavailable";
  } else {
    conditionText.textContent = `MACHINE ${condition} · ${incidentCount} active risk incident${incidentCount === 1 ? "" : "s"}`;
  }
  byId("machine-updated").textContent = connected && integration.fetched_at
    ? `Updated ${new Date(integration.fetched_at).toLocaleTimeString()}`
    : "Waiting for live machine data";
}

function render(snapshot) {
  latestSnapshot = snapshot;
  byId("clock").textContent = new Date(snapshot.timestamp).toLocaleTimeString();
  byId("connection-status").textContent = "LIVE · LOCAL";
  byId("connection-status").classList.add("online");
  renderPlant(snapshot);
  renderPhysics(snapshot);
  renderZones(snapshot);
  renderCompliance(snapshot);
  renderScenarioControls(snapshot);
  renderTimeline(snapshot);
  renderAssets(snapshot);
  renderAlerts(snapshot);
  renderResponse(snapshot);
  renderIntegration(snapshot);
}

async function refreshSnapshot() {
  try {
    const response = await fetch("/api/snapshot", {headers: {Accept: "application/json"}});
    const snapshot = await response.json();
    if (!response.ok) throw new Error(snapshot.error || `Snapshot request failed (${response.status})`);
    render(snapshot);
  } catch (error) { showMessage(error.message); }
}

byId("scenario-play").addEventListener("click", async () => {
  try {
    const result = await postJson("/api/scenarios/start", {
      scenario_id: byId("scenario-picker").value,
    });
    render(result);
    showMessage("Synthetic scenario started; no traffic was sent.");
  } catch (error) { showMessage(error.message); }
});

byId("scenario-pause").addEventListener("click", async () => {
  try {
    const playing = !latestSnapshot?.scenario.playing;
    render(await postJson("/api/scenarios/playback", {playing}));
  } catch (error) { showMessage(error.message); }
});

byId("scenario-step").addEventListener("click", async () => {
  try { render(await postJson("/api/scenarios/step", {})); }
  catch (error) { showMessage(error.message); }
});

byId("scenario-picker").addEventListener("change", () => {
  const scenario = latestSnapshot?.scenarios.find((item) => item.id === byId("scenario-picker").value);
  if (scenario) byId("scenario-description").textContent = scenario.description;
});

byId("time-slider").addEventListener("input", (event) => {
  renderTimelineAt(Number(event.target.value));
});

byId("report-export").addEventListener("click", async () => {
  const button = byId("report-export");
  button.disabled = true;
  try {
    const report = await postJson("/api/reports", {});
    const links = byId("report-downloads");
    links.replaceChildren();
    for (const [label, url] of [["PDF", report.pdf_url], ["HTML", report.html_url]]) {
      const link = element("a", "report-link", `DOWNLOAD ${label}`);
      link.href = url;
      link.download = "";
      links.append(link);
    }
    showMessage(`Incident report ${report.report_id} generated.`);
  } catch (error) {
    showMessage(error.message);
  } finally {
    button.disabled = false;
  }
});

const stream = new EventSource("/api/stream");
stream.onmessage = (event) => {
  try { render(JSON.parse(event.data)); }
  catch (error) { showMessage(`Live update could not be rendered: ${error.message}`); }
};
stream.onerror = () => {
  byId("connection-status").textContent = "RECONNECTING";
  byId("connection-status").classList.remove("online");
};

refreshSnapshot();
