(() => {
  const panels = Array.from(document.querySelectorAll("[data-live-panel]"));
  const riskPanels = Array.from(document.querySelectorAll("[data-live-risk-panel]"));
  if (!panels.length && !riskPanels.length) return;

  const keys = ["rpm", "temperature", "pressure", "power"];
  let requestPending = false;
  let lastGoodAt = null;

  const setText = (panel, selector, value) => {
    const element = panel.querySelector(selector);
    if (element) element.textContent = value == null ? "--" : String(value);
  };

  const status = (panel, mode, message) => {
    const state = panel.querySelector("[data-live-state]");
    const banner = panel.querySelector("[data-live-banner]");
    if (state) {
      state.textContent = mode;
      state.className = `live-state ${mode.toLowerCase()}`;
    }
    if (banner) {
      banner.hidden = mode === "ONLINE";
      banner.className = `live-banner ${mode.toLowerCase()}`;
      banner.textContent = message;
    }
  };

  const updateTrend = (panel, rows) => {
    const samples = Array.isArray(rows) ? rows.slice(-30) : [];
    keys.forEach((key) => {
      const line = panel.querySelector(`[data-trend="${key}"]`);
      if (!line) return;
      const values = samples.map((sample) => Number(sample[key])).filter(Number.isFinite);
      if (values.length < 2) {
        line.setAttribute("points", "");
        return;
      }
      const low = Math.min(...values);
      const spread = Math.max(...values) - low || 1;
      const points = values.map((value, index) => {
        const x = 40 + (index * 550) / (values.length - 1);
        const y = 140 - ((value - low) / spread) * 120;
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      });
      line.setAttribute("points", points.join(" "));
    });
  };

  const updateLiveRisk = (panel, result) => {
    const risk = result?.ok ? result.data : null;
    const level = risk?.risk_level || "UNAVAILABLE";
    const badge = panel.querySelector("[data-live-risk-level]");
    const score = panel.querySelector("[data-live-risk-score]");
    const input = panel.querySelector("[data-live-risk-input]");
    const updated = panel.querySelector("[data-live-risk-updated]");
    const incidents = panel.querySelector("[data-live-risk-incidents]");
    const levelClass = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNASSESSED"].includes(level)
      ? level.toLowerCase()
      : "unassessed";

    badge.textContent = level;
    badge.className = `live-risk-badge ${levelClass}`;
    score.textContent = risk?.risk_score == null
      ? "--"
      : Number(risk.risk_score).toFixed(3);
    input.textContent = risk?.input_status?.replaceAll("_", " ") || "ERROR";
    updated.textContent = risk?.last_received_at
      ? `Last event ${new Date(risk.last_received_at).toLocaleString()}`
      : result?.error || "No detector events received";

    incidents.replaceChildren();
    const recent = Array.isArray(risk?.recent_incidents) ? risk.recent_incidents : [];
    if (!recent.length) {
      const empty = document.createElement("p");
      empty.className = "empty-state";
      empty.textContent = risk ? "No incidents recorded." : "Live detector risk is unavailable.";
      incidents.appendChild(empty);
      return;
    }

    recent.forEach((incident) => {
      const card = document.createElement("article");
      const incidentLevel = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNASSESSED"].includes(incident.risk_level)
        ? incident.risk_level.toLowerCase()
        : "unassessed";
      card.className = `live-risk-incident ${incidentLevel}`;
      const heading = document.createElement("div");
      heading.className = "live-risk-incident-heading";
      const identity = document.createElement("strong");
      identity.textContent = `${incident.incident_id} · ${incident.asset_id}`;
      const severity = document.createElement("span");
      severity.textContent = incident.risk_level || "UNASSESSED";
      heading.append(identity, severity);
      const details = document.createElement("p");
      const eventCount = Array.isArray(incident.events) ? incident.events.length : 0;
      const timestamp = incident.start_time
        ? new Date(incident.start_time).toLocaleString()
        : "Time unavailable";
      const incidentScore = incident.risk_score == null
        ? "score unavailable"
        : `score ${Number(incident.risk_score).toFixed(3)}`;
      details.textContent = `${incident.status || "UNKNOWN"} · ${eventCount} event(s) · ${timestamp} · ${incidentScore}`;
      card.append(heading, details);
      incidents.appendChild(card);
    });
  };

  const updateMachineRisk = (panel, risk) => {
    const level = risk?.risk_level || "UNAVAILABLE";
    const badge = panel.querySelector("[data-machine-risk-level]");
    const score = panel.querySelector("[data-machine-risk-score]");
    const detail = panel.querySelector("[data-machine-risk-detail]");
    const levelClass = ["NORMAL", "MEDIUM", "HIGH", "CRITICAL"].includes(level)
      ? level.toLowerCase()
      : "unavailable";
    badge.textContent = level;
    badge.className = `machine-risk-badge ${levelClass}`;
    score.textContent = risk?.risk_score == null ? "--" : `${Number(risk.risk_score).toFixed(3)}×`;
    if (risk?.sensor) {
      detail.textContent = `Highest normalized reading: ${risk.sensor}. NORMAL < 0.75×; MEDIUM 0.75–1.00×; CRITICAL above 1.00× (over the limit).`;
    } else {
      detail.textContent = "Machine risk is unavailable until live readings and configured limits are available.";
    }
  };

  const refresh = async () => {
    if (requestPending) return;
    requestPending = true;
    try {
      const response = await fetch("/api/live", {
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      });
      if (!response.ok) throw new Error(`Live feed returned HTTP ${response.status}`);
      const live = await response.json();
      riskPanels.forEach((panel) => updateLiveRisk(panel, live.risk));
      panels.forEach((panel) => updateMachineRisk(panel, live.machine_risk));
      const fetchedAt = Date.parse(live.fetched_at || "");
      if (!live.ok || !live.state?.ok) {
        panels.forEach((panel) => status(
          panel,
          "OFFLINE",
          `OFFLINE - machine HMI is unavailable${live.state?.error ? `: ${live.state.error}` : "."}`,
        ));
        return;
      }
      lastGoodAt = Number.isFinite(fetchedAt) ? fetchedAt : Date.now();
      panels.forEach((panel) => {
        status(panel, "ONLINE", "");
        const state = live.state.data || {};
        const risk = live.risk?.data || {};
        const connection = live.connection?.data || {};
        setText(panel, '[data-reading="motor_status"]', state.motor_status || connection.status);
        setText(panel, '[data-reading="risk_level"]', risk.risk_level);
        keys.forEach((key) => setText(panel, `[data-reading="${key}"]`, state[key]));
        setText(panel, "[data-live-updated]", new Date(lastGoodAt).toLocaleTimeString());
        updateTrend(panel, live.telemetry?.data);
      });
    } catch (error) {
      riskPanels.forEach((panel) => updateLiveRisk(
        panel,
        { ok: false, error: error instanceof Error ? error.message : "Live feed unavailable" },
      ));
      panels.forEach((panel) => status(
        panel,
        "OFFLINE",
        `OFFLINE - unable to retrieve machine data${error instanceof Error ? `: ${error.message}` : "."}`,
      ));
    } finally {
      requestPending = false;
    }
  };

  window.setInterval(() => {
    if (lastGoodAt && Date.now() - lastGoodAt > 10000) {
      panels.forEach((panel) => status(panel, "STALE", "STALE - machine data is more than 10 seconds old."));
    }
  }, 1000);

  refresh();
  window.setInterval(refresh, 3000);
})();
