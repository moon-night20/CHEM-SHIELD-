(() => {
  const panels = Array.from(document.querySelectorAll("[data-live-panel]"));
  if (!panels.length) return;

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
