const csrfToken = document.querySelector('input[name="csrf_token"]')?.value || "";
const labels = {
  temperature: ["Temperature", "°C"],
  pressure: ["Pressure", "bar"],
  power: ["Power", "kW"],
  speed: ["Speed", "RPM"],
};
let currentRunId = "";
let demoStep = -1;
const demoStages = [
  "Healthy machine: confirm NORMAL readings and an empty warning state.",
  "Simulated attack: starting the Overheat scenario through the OT Console.",
  "Warning and countdown: watch the HMI and timeline for detection.",
  "Response: acknowledge the warning in the HMI, or wait for the guarded auto-stop.",
  "Report and integrity: generate the run report and verify the audit chain.",
];

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

async function getJson(url) {
  const response = await fetch(url, {headers: {Accept: "application/json"}});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

async function postJson(url, body = {}) {
  const response = await fetch(url, {
    method: "POST",
    headers: {"Content-Type": "application/json", "X-CSRFToken": csrfToken},
    body: JSON.stringify(body),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

function renderGauges(machine) {
  const target = document.getElementById("p7-gauges");
  target.replaceChildren();
  for (const [sensor, [label, unit]] of Object.entries(labels)) {
    const value = machine.readings?.[sensor];
    const limit = machine.limits?.[sensor];
    const ratio = Number.isFinite(Number(value)) && Number.isFinite(Number(limit)) && Number(limit) > 0
      ? Math.max(0, Number(value) / Number(limit)) : 0;
    const level = ratio > 1 ? "critical" : ratio >= .75 ? "warning" : "";
    const card = node("article", "p7-gauge");
    card.append(node("h3", "", label));
    card.append(node("strong", "p7-gauge-value", Number.isFinite(Number(value)) ? `${Number(value).toFixed(2)} ${unit}` : "Unavailable"));
    card.append(node("span", "p7-gauge-meta", `Configured limit: ${limit ?? "Unavailable"} ${unit}`));
    const meter = node("div", "p7-meter");
    meter.setAttribute("role", "meter");
    meter.setAttribute("aria-label", `${label} as a fraction of configured limit`);
    meter.setAttribute("aria-valuenow", String(Math.round(ratio * 100)));
    const fill = node("span", level);
    fill.style.width = `${Math.min(100, ratio * 100)}%`;
    meter.append(fill);
    card.append(meter);
    target.append(card);
  }
}

function renderTimeline(run, targetId, compact = false) {
  const target = document.getElementById(targetId);
  target.replaceChildren();
  const events = run?.events || [];
  if (!events.length) {
    target.append(node("li", "p7-empty", "No scenario timeline events yet."));
    return;
  }
  const start = Date.parse(run.started_at);
  const limited = compact ? events.slice(-8) : events;
  for (const event of limited) {
    const item = node("li");
    const offset = Math.max(0, Math.round((Date.parse(event.timestamp) - start) / 1000));
    const minutes = Math.floor(offset / 60);
    const seconds = offset % 60;
    item.append(node("strong", "", `+${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")} ${event.event_type}`));
    item.append(node("span", "p7-event-meta", `${event.detector || event.source || "Part 7"} · ${event.detail?.message || event.detail?.sensor || ""}`));
    for (const tag of event.mitre || []) {
      const badge = node("span", "p7-mitre", `${tag.id} ${tag.name}`);
      badge.title = `${tag.tactic}${tag.verify ? " — verify mapping" : ""}`;
      item.append(badge);
    }
    target.append(item);
  }
}

function renderScenarioButtons(scenarios, active) {
  const target = document.getElementById("p7-scenarios");
  target.replaceChildren();
  for (const scenario of scenarios || []) {
    const row = node("div", "p7-scenario");
    const description = node("div");
    description.append(node("strong", "", scenario.name));
    description.append(node("p", "", scenario.description));
    const button = node("button", "", "RUN");
    button.type = "button";
    button.disabled = Boolean(active?.running);
    button.addEventListener("click", async () => {
      button.disabled = true;
      document.getElementById("p7-run-status").textContent = `Starting ${scenario.name}…`;
      try {
        const result = await postJson(`/p7/scenarios/${encodeURIComponent(scenario.id)}/run`);
        currentRunId = result.run_id;
      } catch (error) {
        document.getElementById("p7-run-status").textContent = error.message;
      } finally {
        await refresh();
      }
    });
    row.append(description, button);
    target.append(row);
  }
}

async function refresh() {
  try {
    const data = await getJson("/p7/api/command-center");
    const condition = data.machine.condition || "UNAVAILABLE";
    const conditionNode = document.getElementById("p7-condition");
    conditionNode.textContent = condition;
    conditionNode.className = `p7-condition ${condition.toLowerCase()}`;
    document.getElementById("p7-motor").textContent = `Motor: ${data.machine.motor_status}`;
    document.getElementById("p7-updated").textContent = new Date().toLocaleTimeString();
    renderGauges(data.machine);
    renderScenarioButtons(data.scenarios, data.runner);
    const run = data.run;
    if (run) {
      currentRunId = run.run_id;
      document.getElementById("p7-run-name").textContent = `${run.scenario_name} · ${run.status} · ${run.run_id}`;
      document.getElementById("p7-report-run-id").value = run.run_id;
      document.getElementById("p7-generate-report").disabled = false;
      renderTimeline(run, "p7-mini-timeline", true);
    } else {
      document.getElementById("p7-generate-report").disabled = true;
      renderTimeline(null, "p7-mini-timeline", true);
    }
    const posture = data.posture;
    document.getElementById("p7-score").textContent = posture.score;
    document.getElementById("p7-formula").textContent = posture.formula;
    const breakdown = document.getElementById("p7-breakdown");
    breakdown.replaceChildren();
    for (const [name, value] of Object.entries(posture.breakdown)) {
      breakdown.append(node("dt", "", name.replaceAll("_", " ")));
      breakdown.append(node("dd", "", `${value} / 25`));
    }
    const integrity = data.audit_integrity;
    const integrityNode = document.getElementById("p7-integrity-summary");
    integrityNode.textContent = integrity.ok
      ? `INTACT — ${integrity.records} audit records verified`
      : `TAMPERED at record #${integrity.first_broken_index}`;
    integrityNode.className = `p7-integrity ${integrity.ok ? "ok" : "bad"}`;
    const status = data.runner;
    document.getElementById("p7-run-status").textContent = status.running
      ? `${status.scenario_name || status.scenario_id} · ${status.status}` : (status.outcome || "No scenario running");
    const outbox = document.getElementById("p7-outbox");
    outbox.replaceChildren();
    for (const message of data.outbox || []) outbox.append(node("li", "", message));
    if (!outbox.children.length) outbox.append(node("li", "", "Waiting for a critical simulated event."));
  } catch (error) {
    document.getElementById("p7-run-status").textContent = error.message;
  }
}

document.getElementById("p7-abort").addEventListener("click", async () => {
  try { await postJson("/p7/scenarios/abort"); }
  catch (error) { document.getElementById("p7-run-status").textContent = error.message; }
  await refresh();
});

document.getElementById("p7-demo-start").addEventListener("click", () => {
  demoStep = 0;
  document.getElementById("p7-demo-caption").textContent = demoStages[demoStep];
  document.getElementById("p7-demo-step").textContent = "Step 1 of 5";
  document.getElementById("p7-demo-next").disabled = false;
});

document.getElementById("p7-demo-next").addEventListener("click", async () => {
  demoStep = Math.min(demoStages.length - 1, demoStep + 1);
  document.getElementById("p7-demo-caption").textContent = demoStages[demoStep];
  document.getElementById("p7-demo-step").textContent = `Step ${demoStep + 1} of 5`;
  if (demoStep === 1) {
    try {
      const result = await postJson("/p7/scenarios/overheat/run");
      currentRunId = result.run_id;
    } catch (error) {
      document.getElementById("p7-demo-caption").textContent = error.message;
    }
  }
  if (demoStep === 4 && currentRunId) {
    try {
      const result = await postJson("/p7/reports", {run_id: currentRunId});
      document.getElementById("p7-demo-caption").textContent =
        `Report generated. Open it here: ${new URL(result.url, location.href).href}`;
    } catch (error) {
      document.getElementById("p7-demo-caption").textContent = error.message;
    }
  }
  await refresh();
  if (demoStep === demoStages.length - 1) document.getElementById("p7-demo-next").disabled = true;
});

window.setInterval(refresh, 2000);
refresh();
