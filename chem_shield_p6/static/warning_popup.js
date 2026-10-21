(() => {
  const container = document.getElementById('warning-toasts');
  if (!container) return;

  const warningSvg = '<svg viewBox="0 0 64 64" width="42" height="42" aria-hidden="true"><path d="M32 6 2 58h60L32 6Z" fill="#e0a642" stroke="#7a5410" stroke-width="3" stroke-linejoin="round"/><rect x="29" y="22" width="6" height="19" rx="3" fill="#2a1d05"/><circle cx="32" cy="48" r="3.6" fill="#2a1d05"/></svg>';
  const severityLabels = {medium: 'WARNING', high: 'HIGH WARNING', critical: 'CRITICAL'};
  const seenEvents = new Set();
  const seenRisks = new Set();
  let eventsPrimed = false;
  let currentMachineWarning = null;

  function showWarning(level, title, detail) {
    while (container.children.length >= 4) container.firstElementChild.remove();

    const toast = document.createElement('article');
    toast.className = `warning-toast ${level}`;
    toast.setAttribute('role', 'alert');

    const icon = document.createElement('span');
    icon.className = 'warning-icon';
    icon.innerHTML = warningSvg;

    const text = document.createElement('span');
    text.className = 'warning-text';
    const heading = document.createElement('strong');
    heading.textContent = title;
    const message = document.createElement('span');
    message.textContent = detail;
    text.append(heading, message);

    const close = document.createElement('button');
    close.className = 'warning-close';
    close.type = 'button';
    close.setAttribute('aria-label', 'Dismiss warning');
    close.textContent = '×';
    const dismiss = () => toast.remove();
    close.addEventListener('click', dismiss);

    toast.append(icon, text, close);
    container.append(toast);
    window.setTimeout(dismiss, level === 'critical' ? 15000 : 9000);
  }

  function machineState(state) {
    const alerts = Array.isArray(state.limit_alerts) ? state.limit_alerts : [];
    if (state.machine_condition !== 'CRITICAL' || alerts.length === 0) {
      currentMachineWarning = null;
      return;
    }

    const detail = alerts.map((alert) => alert.message).filter(Boolean).join(' · ');
    const key = alerts.map((alert) => alert.sensor).filter(Boolean).sort().join('|');
    if (!detail || !key || key === currentMachineWarning) return;
    currentMachineWarning = key;
    showWarning('critical', 'MACHINE CONDITION WARNING', detail);
  }

  function eventWarnings(events) {
    const fresh = [];
    for (const event of events) {
      const key = `${event.timestamp}|${event.event_type}|${event.parameter}`;
      if (seenEvents.has(key)) continue;
      seenEvents.add(key);
      const severity = String(event.severity || '').toLowerCase();
      if (event.source !== 'P6' && severity in severityLabels) {
        fresh.push({event, severity});
      }
    }
    if (!eventsPrimed) {
      eventsPrimed = true;
      return;
    }
    for (const {event, severity} of fresh.slice(0, 3)) {
      showWarning(
        severity,
        `${severityLabels[severity]}: ${String(event.event_type || 'machine event').replaceAll('_', ' ')}`,
        `${event.parameter || 'Machine'} reading abnormal (${event.new_value ?? '--'}). Review the machine.`,
      );
    }
  }

  function riskWarnings(summary) {
    const fresh = [];
    for (const incident of summary.active_incidents || []) {
      if (!['MEDIUM', 'HIGH', 'CRITICAL'].includes(incident.risk_level)) continue;
      const key = `${incident.incident_id}|${incident.risk_level}`;
      if (seenRisks.has(key)) continue;
      seenRisks.add(key);
      fresh.push(incident);
    }
    for (const incident of fresh.slice(0, 3)) {
      const level = incident.risk_level.toLowerCase();
      const score = Number(incident.risk_score);
      const scoreText = incident.risk_score == null || !Number.isFinite(score)
        ? 'unavailable'
        : score.toFixed(2);
      const warning = (incident.warning_details || [])[0];
      const time = warning?.timestamp
        ? new Date(warning.timestamp).toLocaleString()
        : 'Time unavailable';
      const detail = warning
        ? `${warning.trigger || 'Detector'} · ${warning.comparison || 'Numeric limit unavailable'} · ${time}${warning.message ? ` · ${warning.message}` : ''}`
        : `Trigger details unavailable · ${new Date(incident.start_time).toLocaleString()}`;
      showWarning(
        level,
        `${incident.risk_level} RISK on ${incident.asset_id}`,
        `${detail} · risk score ${scoreText}. Review the incident.`,
      );
    }
  }

  let lastAutoState = null;
  const autoTitles = {
    COUNTDOWN: ['critical', 'AUTOMATIC STOP PENDING'],
    RECOVERING: ['critical', 'MACHINE STOPPED AUTOMATICALLY'],
    WATCHING: ['medium', 'MACHINE RESTARTED AFTER RECOVERY'],
    LOCKED_OUT: ['critical', 'OPERATOR REQUIRED: MACHINE KEPT STOPPED'],
  };

  function autoResponse(status) {
    if (!status || !status.enabled || status.state === lastAutoState) return;
    const previous = lastAutoState;
    lastAutoState = status.state;
    const entry = autoTitles[status.state];
    if (previous === null && status.state === 'IDLE') return;
    if (entry) showWarning(entry[0], entry[1], status.message);
  }

  window.ChemShieldP6WarningPopup = Object.freeze({
    autoResponse,
    machineState,
    eventWarnings,
    riskWarnings,
  });
})();
