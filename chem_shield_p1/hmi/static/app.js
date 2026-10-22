const $ = (id) => document.getElementById(id);
let connected = false;
const trendHistory = [];
const trendLimit = 60;
let sequenceCounter = 0;
let selectedFocus = 'temperature';
let alertIncidentId = null;
let alertIncidentIsCritical = false;
let lastNotifiedIncident = null;
let initialRiskLoaded = false;
let currentRiskSummary = null;
let currentMachineState = null;
let alertIsMachineCondition = false;
let refreshPending = false;
let riskRefreshPending = false;
const p6ConfirmToken = document.querySelector('meta[name="p6-confirm-token"]').content;

const focusConfig = {
  temperature: {label: 'TEMPERATURE', unit: '°C', value: (state) => state.temperature, target: () => 'AUTO'},
  speed: {label: 'SPEED', unit: 'RPM', value: (state) => state.rpm, target: (state) => `${Math.min(1450, Math.round(state.target_rpm))} RPM`},
  pressure: {label: 'PRESSURE', unit: 'bar', value: (state) => state.pressure, target: () => 'AUTO'},
  power: {label: 'POWER', unit: 'kW', value: (state) => state.power, target: () => 'AUTO'},
};

function formatFocusValue(focus, value) {
  return focus === 'speed' ? Math.round(value) : Number(value).toFixed(2);
}

function updateFocus(state) {
  const config = focusConfig[selectedFocus];
  $('focus-label').textContent = config.label;
  $('focus-value').textContent = formatFocusValue(selectedFocus, config.value(state));
  $('focus-unit').textContent = config.unit;
  $('focus-target').textContent = config.target(state);
  $('focus-status').textContent = state.motor_status === 'PAUSED' ? 'PAUSED' : state.motor_status === 'RUNNING' ? 'WITHIN RANGE' : 'STOPPED';
}

function recordTrend(state) {
  const historyWindow = $('history-window');
  const wasAtLiveEdge = historyWindow.scrollHeight - historyWindow.scrollTop - historyWindow.clientHeight < 24;
  trendHistory.push({
    sequence: ++sequenceCounter,
    time: new Date(),
    rpm: state.rpm,
    temperature: state.temperature,
    pressure: state.pressure,
    power: state.power,
  });
  if (trendHistory.length > trendLimit) trendHistory.shift();
  $('trend-window').textContent = `${trendHistory.length} RECORD${trendHistory.length === 1 ? '' : 'S'}`;
  $('sequence-list').innerHTML = trendHistory.map((sample, index) => `
    <article class="sequence-record ${index === trendHistory.length - 1 ? 'latest-record' : ''}">
      <span class="sequence-time"><span class="unit-tag">M-01</span><b>${String(sample.sequence).padStart(3, '0')}</b><small>${sample.time.toLocaleTimeString([], {hour: '2-digit', minute: '2-digit', second: '2-digit'})}</small></span>
      <strong>${Math.round(sample.rpm)} <small>RPM</small></strong>
      <strong>${sample.temperature.toFixed(1)} <small>°C</small></strong>
      <strong>${sample.pressure.toFixed(2)} <small>bar</small></strong>
      <strong>${sample.power.toFixed(2)} <small>kW</small></strong>
    </article>
  `).join('');
  if (wasAtLiveEdge) historyWindow.scrollTop = historyWindow.scrollHeight;
}

function setConnection(online) {
  connected = online;
  $('connection-text').textContent = online ? 'PLC-01 CONNECTED' : 'PLC-01 OFFLINE';
  $('connection').classList.toggle('offline', !online);
  if ($('offline-banner')) $('offline-banner').hidden = online;
  document.querySelectorAll('[data-action], #apply-setpoint, #event-button').forEach((button) => { button.disabled = !online; });
}

function setNetworkStatus(connection) {
  const status = $('network-status');
  if (!status) return;
  const state = connection.status || 'DISCONNECTED';
  status.className = `network-status ${state === 'CONNECTED' ? 'connected' : state === 'CONNECTING' ? 'connecting' : state === 'CONNECTION ERROR' ? 'error' : ''}`;
  $('network-status-label').textContent = state;
  $('network-feedback').textContent = connection.error || 'Live process data source';
  if (connection.host) $('device-ip').value = connection.host;
  if (connection.port) $('device-port').value = connection.port;
  if (connection.name) $('device-name').value = connection.name;
}

function setState(state) {
  currentMachineState = state;
  const running = state.motor_status === 'RUNNING';
  const condition = state.machine_condition || 'NORMAL';
  const limitAlerts = state.limit_alerts || [];
  const conditionBadge = $('machine-condition');
  conditionBadge.textContent = condition;
  conditionBadge.className = `machine-condition ${condition.toLowerCase()}`;
  conditionBadge.title = limitAlerts.length
    ? limitAlerts.map((alert) => alert.message).join('; ')
    : 'Current sensor readings are within configured upper limits';
  const conditionDetails = $('machine-condition-details');
  conditionDetails.hidden = limitAlerts.length === 0;
  conditionDetails.textContent = limitAlerts.map((alert) => alert.message).join(' · ');
  window.ChemShieldP6WarningPopup.machineState(state);
  updateProblemStatus();
  $('state-label').textContent = state.motor_status;
  $('command-state').textContent = state.motor_status;
  $('state-badge').className = `state-badge ${running ? 'running' : state.motor_status === 'PAUSED' ? 'paused' : 'stopped'}`;
  const targetRpm = Math.min(1450, Math.round(state.target_rpm));
  $('target-input').value = targetRpm;
  $('target-range').value = targetRpm;
  updateFocus(state);
  if (state.motor_status !== 'PAUSED') recordTrend(state);
}

function renderEvents(events) {
  window.ChemShieldP6WarningPopup.eventWarnings(events);
  if (!$('event-count') || !$('event-list')) return;
  $('event-count').textContent = `${events.length} EVENT${events.length === 1 ? '' : 'S'}`;
  if (!events.length) {
    $('event-list').innerHTML = '<div class="empty-state">No events recorded yet.</div>';
    return;
  }

  $('event-list').innerHTML = events.map((event) => {
    const time = new Date(event.timestamp).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'});
    const title = event.event_type.replaceAll('_', ' ');
    const detail = `${event.source} · ${event.parameter || 'system'} · ${event.old_value ?? '--'} → ${event.new_value ?? '--'}`;
    return `<div class="event-row"><span class="event-severity ${event.severity}"></span><div><p class="event-title">${title}</p><span class="event-detail">${detail}</span></div><span class="event-time">${time}</span></div>`;
  }).join('');
}

async function getJson(url, options) {
  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch(url, {...options, signal: controller.signal});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `Request failed: ${response.status}`);
    return data;
  } finally {
    window.clearTimeout(timeoutId);
  }
}

function updateProblemStatus() {
  const machineProblem = currentMachineState?.machine_condition === 'CRITICAL';
  const activeRisk = (currentRiskSummary?.active_incidents || []).some((item) =>
    item.is_fresh && ['HIGH', 'CRITICAL'].includes(item.risk_level)
  );
  const badge = $('machine-condition');
  if (machineProblem) {
    badge.textContent = 'CRITICAL';
    badge.className = 'machine-condition critical';
  } else if (activeRisk) {
    badge.textContent = 'ACTIVE RISK';
    badge.className = 'machine-condition critical';
  } else {
    badge.textContent = currentMachineState ? 'NO ACTIVE PROBLEM' : 'WAITING FOR LIVE STATE';
    badge.className = 'machine-condition normal';
    window.ChemShieldP6WarningPopup.clearWarnings();
  }
}

function maybeShowRiskAlert(summary, state) {
  const liveAlerts = state?.machine_condition === 'CRITICAL'
    ? (state.limit_alerts || [])
    : [];
  const riskRank = {HIGH: 2, CRITICAL: 3};
  if (!initialRiskLoaded) {
    for (const item of summary.popup_candidates || []) {
      seenInitialIncidentKeys.add(`${item.incident_id}:${item.risk_level}`);
    }
    initialRiskLoaded = true;
  }

  if (liveAlerts.length) {
    const key = `live-machine:${liveAlerts.map((alert) => alert.sensor).sort().join('|')}`;
    if (key === lastNotifiedIncident || $('risk-alert-dialog').open) return;
    lastNotifiedIncident = key;
    alertIncidentId = null;
    alertIncidentIsCritical = true;
    alertIsMachineCondition = true;
    $('risk-alert-title').textContent = 'LIVE MACHINE LIMIT EXCEEDED';
    $('risk-alert-message').textContent =
      'Current machine readings exceed configured limits. Stop the loopback simulator now or allow the automatic stop countdown to continue.';
    $('risk-alert-trigger').textContent = liveAlerts.map((alert) => alert.message).join(' · ');
    $('risk-alert-ack').hidden = true;
    $('risk-alert-sim-stop').hidden = false;
    $('risk-alert-sim-stop').disabled = false;
    $('risk-alert-close').textContent = 'DISMISS';
    $('risk-alert-countdown').hidden = !summary.auto_stop_at;
    $('risk-alert-countdown').dataset.deadline = summary.auto_stop_at || '';
    $('risk-alert-p6-message').textContent = summary.auto_stop_at
      ? 'The automatic stop is cancelled if readings return to normal. Operator STOP also clears all simulated overrides.'
      : 'No automatic stop is armed for this live limit warning. Operator STOP clears all simulated overrides.';
    $('risk-alert-dialog').showModal();
    return;
  }
  if (alertIsMachineCondition) {
    if ($('risk-alert-dialog').open) $('risk-alert-dialog').close();
    alertIsMachineCondition = false;
    alertIncidentId = null;
  }

  const incident = (summary.popup_candidates || [])
    .filter((item) => item.risk_level in riskRank
      && !item.acknowledged
      && item.is_fresh
      && Number.isFinite(Date.parse(item.last_event_time)))
    .sort((left, right) => (
      riskRank[right.risk_level] - riskRank[left.risk_level]
      || (right.risk_score || 0) - (left.risk_score || 0)
    ))[0];
  if (alertIncidentId && !summary.active_incidents?.some(
    (item) => item.incident_id === alertIncidentId
  )) {
    if ($('risk-alert-dialog').open) $('risk-alert-dialog').close();
    alertIncidentId = null;
  }
  if (!incident) return;
  const key = `${incident.incident_id}:${incident.risk_level}`;
  if (seenInitialIncidentKeys.has(key) || key === lastNotifiedIncident
    || $('risk-alert-dialog').open) return;
  lastNotifiedIncident = key;
  alertIncidentId = incident.incident_id;
  alertIncidentIsCritical = incident.risk_level === 'CRITICAL';
  alertIsMachineCondition = false;
  $('risk-alert-title').textContent = `${incident.risk_level} RISK INCIDENT`;
  const score = Number(incident.risk_score);
  const scoreText = incident.risk_score == null || !Number.isFinite(score)
    ? 'unavailable'
    : score.toFixed(3);
  $('risk-alert-message').textContent = `${incident.asset_id}: score ${scoreText} on a 0.0-1.0 scale. Acknowledging records operator awareness only; it does not lower risk or resolve the incident.`;
  const warning = (incident.warning_details || [])[0];
  const warningTime = warning?.timestamp
    ? new Date(warning.timestamp).toLocaleString()
    : 'Time unavailable';
  $('risk-alert-trigger').textContent = warning
    ? `${warning.asset_id || incident.asset_id} · ${warning.trigger || 'Detector'} · ${warning.comparison || 'Numeric limit unavailable'} · ${warningTime}${warning.message ? ` · ${warning.message}` : ''}`
    : `${incident.asset_id} · Trigger details unavailable · Time ${new Date(incident.start_time).toLocaleString()}`;
  const stopButton = $('risk-alert-sim-stop');
  stopButton.hidden = true;
  stopButton.disabled = false;
  stopButton.textContent = 'STOP MACHINE NOW';
  $('risk-alert-ack').hidden = false;
  $('risk-alert-countdown').hidden = !incident.auto_stop_at;
  $('risk-alert-countdown').dataset.deadline = incident.auto_stop_at || '';
  $('risk-alert-close').textContent = 'CLOSE';
  $('risk-alert-p6-message').textContent = alertIncidentIsCritical
    ? 'An automatic stop countdown is active while the critical condition remains current. Acknowledge to open the operator stop prompt.'
    : 'Part 6 offers a simulated stop only for an active CRITICAL incident.';
  $('risk-alert-dialog').showModal();
}

const seenInitialIncidentKeys = new Set();

function updateCountdown() {
  const element = $('risk-alert-countdown');
  if (!element || element.hidden || !element.dataset.deadline) return;
  const remaining = Math.max(
    0,
    Math.ceil((Date.parse(element.dataset.deadline) - Date.now()) / 1000),
  );
  const minutes = Math.floor(remaining / 60);
  const seconds = remaining % 60;
  element.textContent = `AUTOMATIC STOP IN ${minutes}:${String(seconds).padStart(2, '0')}`;
}

function syncRiskCountdown(summary) {
  const element = $('risk-alert-countdown');
  if (!element) return;
  const incident = alertIncidentId
    ? (summary.active_incidents || []).find(
      (item) => item.incident_id === alertIncidentId,
    )
    : null;
  const deadline = alertIsMachineCondition
    ? summary.auto_stop_at
    : incident?.auto_stop_at;
  element.hidden = !deadline;
  element.dataset.deadline = deadline || '';
  if (deadline) updateCountdown();
}

async function refreshRisk() {
  if (riskRefreshPending) return;
  riskRefreshPending = true;
  try {
    const summary = await getJson('/api/risk');
    currentRiskSummary = summary;
    window.ChemShieldP6WarningPopup.riskWarnings(summary);
    updateProblemStatus();
    maybeShowRiskAlert(summary, currentMachineState);
    syncRiskCountdown(summary);
  } catch (error) {
    console.warn('Risk alert check failed:', error);
  } finally {
    riskRefreshPending = false;
  }
}

async function refresh() {
  if (refreshPending) return;
  refreshPending = true;
  try {
    const [state, events, connection, risk] = await Promise.all([
      getJson('/api/state'), getJson('/api/events'), getJson('/api/connection'),
      getJson('/api/risk'),
    ]);
    setConnection(true); setState(state); renderEvents(events);
    setNetworkStatus(connection);
    currentRiskSummary = risk;
    window.ChemShieldP6WarningPopup.riskWarnings(risk);
    updateProblemStatus();
    maybeShowRiskAlert(risk, state);
    syncRiskCountdown(risk);
    $('last-update').textContent = `UPDATED ${new Date().toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'})}`;
  } catch (error) {
    setConnection(false); setNetworkStatus({status: 'CONNECTION ERROR', error: error.message}); console.warn(error);
  } finally {
    refreshPending = false;
  }
}

async function acknowledgeIncident(incidentId) {
  try {
    const result = await getJson(`/api/incidents/${encodeURIComponent(incidentId)}/acknowledge`, {
      method:'POST',
      headers:{
        'Content-Type':'application/json',
        ...(alertIncidentIsCritical
          ? {'X-Chem-Shield-P6-Confirmation':p6ConfirmToken}
          : {}),
      },
      body:JSON.stringify({
        acknowledged_by:'operator',
        ...(alertIncidentIsCritical ? {p6_followup:true} : {}),
      }),
    });
    if ($('risk-alert-dialog').open && alertIncidentId === incidentId) {
      $('risk-alert-dialog').close();
    }
    await refreshRisk();
    if (alertIncidentIsCritical && result.p6_response_available) {
      showP6StopPrompt();
    }
  } catch (error) {
    $('risk-alert-message').textContent = `Acknowledgement failed: ${error.message}`;
  }
}

function showP6StopPrompt() {
  $('risk-alert-title').textContent = 'STOP THE MACHINE NOW';
  $('risk-alert-message').textContent =
    'Acknowledgment recorded. Press STOP MACHINE NOW to stop the loopback simulator. Closing this prompt will leave the simulator running.';
  $('risk-alert-ack').hidden = true;
  $('risk-alert-sim-stop').hidden = false;
  $('risk-alert-sim-stop').disabled = false;
  $('risk-alert-sim-stop').textContent = 'STOP MACHINE NOW';
  $('risk-alert-close').textContent = 'DISMISS';
  $('risk-alert-p6-message').textContent =
    'The automatic stop countdown remains active while the critical condition is current. Confirm STOP MACHINE NOW to stop immediately.';
  $('risk-alert-dialog').showModal();
}

async function confirmSimulatedStop() {
  const button = $('risk-alert-sim-stop');
  if (button.disabled) return;
  button.disabled = true;
  try {
    const result = alertIncidentId
      ? await getJson('/api/p6/respond', {
        method:'POST',
        headers:{
          'Content-Type':'application/json',
          'X-Chem-Shield-P6-Confirmation':p6ConfirmToken,
        },
        body:JSON.stringify({incident_id:alertIncidentId, confirm_stop:true}),
      })
      : await getJson('/api/control', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({action:'stop'}),
      });
    $('risk-alert-message').textContent = result.simulation_only || alertIsMachineCondition
      ? 'Simulation only: the local virtual machine recorded the stop and cleared simulated overrides.'
      : 'Part 6 response recorded.';
    button.textContent = 'SIMULATED STOP RECORDED';
    $('risk-alert-p6-message').textContent =
      'The loopback simulator has been stopped. It will not restart automatically.';
    $('risk-alert-countdown').hidden = true;
    await refresh();
  } catch (error) {
    $('risk-alert-message').textContent = `Simulated stop was not confirmed: ${error.message}`;
    button.disabled = false;
  }
}

async function sendCommand(action) {
  const feedback = $('command-feedback');
  const actionLabel = action === 'start' ? 'Starting' : action === 'pause' ? 'Pausing' : 'Stopping';
  feedback.textContent = action === 'setpoint' ? 'Applying target speed...' : `${actionLabel} motor...`;
  try {
    await getJson('/api/control', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({action, target_rpm:$('target-input').value})});
    feedback.textContent = action === 'setpoint' ? 'Target RPM applied to PLC-01.' : `Motor ${action === 'start' ? 'start' : action === 'pause' ? 'pause' : 'stop'} command sent to PLC-01.`;
    await refresh();
    if (action !== 'setpoint') {
      await new Promise((resolve) => setTimeout(resolve, 650));
      await refresh();
    }
  } catch (error) { feedback.textContent = `Command failed: ${error.message}`; $('last-update').textContent = 'COMMAND FAILED'; }
}

document.querySelectorAll('[data-action]').forEach((button) => button.addEventListener('click', () => sendCommand(button.dataset.action)));
document.querySelectorAll('[data-focus]').forEach((button) => button.addEventListener('click', () => {
  selectedFocus = button.dataset.focus;
  document.querySelectorAll('[data-focus]').forEach((item) => item.classList.toggle('selected', item === button));
  refresh();
}));
$('apply-setpoint').addEventListener('click', () => sendCommand('setpoint'));
$('target-range').addEventListener('input', (event) => { $('target-input').value = event.target.value; });
$('target-input').addEventListener('input', (event) => { $('target-range').value = Math.max(0, Math.min(1450, event.target.value)); });
$('event-button').addEventListener('click', async () => {
  const button = $('event-button'); const feedback = $('event-feedback'); button.disabled = true; feedback.textContent = 'Sending event to process...';
  try {
    await getJson('/api/events', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({event_type:$('event-type').value, value:$('event-value').value})});
    feedback.textContent = 'Event sent and added to the audit trail.'; await refresh();
  } catch (error) { feedback.textContent = error.message; }
  button.disabled = !connected;
});

async function changeConnection(action) {
  const buttons = document.querySelectorAll('.network-actions button');
  buttons.forEach((button) => { button.disabled = true; });
  setNetworkStatus({status: 'CONNECTING', error: 'Applying device configuration...'});
  try {
    const connection = await getJson('/api/connection', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({action, host:$('device-ip').value, port:$('device-port').value, name:$('device-name').value})});
    setNetworkStatus(connection); await refresh();
  } catch (error) { setNetworkStatus({status:'CONNECTION ERROR', error:error.message}); }
  buttons.forEach((button) => { button.disabled = false; });
}

$('connect-device').addEventListener('click', () => changeConnection('connect'));
$('disconnect-device').addEventListener('click', () => changeConnection('disconnect'));
$('reconnect-device').addEventListener('click', () => changeConnection('reconnect'));
$('risk-alert-ack').addEventListener('click', () => {
  if (alertIncidentId) void acknowledgeIncident(alertIncidentId);
});
$('risk-alert-sim-stop').addEventListener('click', () => void confirmSimulatedStop());
$('risk-alert-close').addEventListener('click', () => {
  $('risk-alert-dialog').close();
  $('risk-alert-close').textContent = 'CLOSE';
});

setConnection(false); setNetworkStatus({status:'DISCONNECTED', error:'Not connected'}); refresh(); setInterval(refresh, 1000);
