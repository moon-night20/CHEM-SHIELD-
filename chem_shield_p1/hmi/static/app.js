const $ = (id) => document.getElementById(id);
let connected = false;
const trendHistory = [];
const trendLimit = 60;
let sequenceCounter = 0;
let selectedFocus = 'temperature';
let alertIncidentId = null;
let lastNotifiedIncident = null;
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
  if (!$('event-count') || !$('event-list')) return;
  $('event-count').textContent = `${events.length} EVENT${events.length === 1 ? '' : 'S'}`;
  if (!events.length) {
    $('event-list').innerHTML = '<div class="empty-state">No events recorded yet.</div>';
    return;
  }

  function checkEventWarnings(events) {
    window.ChemShieldP6WarningPopup.eventWarnings(events);
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

function maybeShowRiskAlert(summary) {
  const riskRank = {MEDIUM: 1, HIGH: 2, CRITICAL: 3};
  const incident = (summary.active_incidents || [])
    .filter((item) => !item.acknowledged && item.risk_level in riskRank)
    .sort((left, right) => (
      riskRank[right.risk_level] - riskRank[left.risk_level]
      || (right.risk_score || 0) - (left.risk_score || 0)
    ))[0];
  if (!incident) return;
  const key = `${incident.incident_id}:${incident.risk_level}`;
  if (key === lastNotifiedIncident || $('risk-alert-dialog').open) return;
  lastNotifiedIncident = key;
  alertIncidentId = incident.incident_id;
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
  stopButton.hidden = incident.risk_level !== 'CRITICAL';
  stopButton.disabled = false;
  stopButton.textContent = 'CONFIRM SIMULATED STOP';
  $('risk-alert-p6-message').textContent = incident.risk_level === 'CRITICAL'
    ? 'Part 6 is simulation only. Nothing stops unless you explicitly confirm here; it is available only while the HMI and simulator use loopback.'
    : 'Part 6 offers a simulated stop only for an active CRITICAL incident.';
  $('risk-alert-dialog').showModal();
}

async function refreshRisk() {
  if (riskRefreshPending) return;
  riskRefreshPending = true;
  try {
    const summary = await getJson('/api/risk');
    window.ChemShieldP6WarningPopup.riskWarnings(summary);
    maybeShowRiskAlert(summary);
  } catch (error) {
    console.warn('Risk alert check failed:', error);
  } finally {
    riskRefreshPending = false;
  }
}

async function refresh() {
  if (refreshPending) return;
  refreshPending = true;
  void refreshRisk();
  try {
    const [state, events, connection] = await Promise.all([getJson('/api/state'), getJson('/api/events'), getJson('/api/connection')]);
    setConnection(true); setState(state); renderEvents(events);
    setNetworkStatus(connection);
    $('last-update').textContent = `UPDATED ${new Date().toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'})}`;
  } catch (error) {
    setConnection(false); setNetworkStatus({status: 'CONNECTION ERROR', error: error.message}); console.warn(error);
  } finally {
    refreshPending = false;
  }
}

async function acknowledgeIncident(incidentId) {
  try {
    await getJson(`/api/incidents/${encodeURIComponent(incidentId)}/acknowledge`, {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({acknowledged_by:'operator'}),
    });
    if ($('risk-alert-dialog').open && alertIncidentId === incidentId) {
      $('risk-alert-dialog').close();
    }
    await refreshRisk();
  } catch (error) {
    $('risk-alert-message').textContent = `Acknowledgement failed: ${error.message}`;
  }
}

async function confirmSimulatedStop() {
  const button = $('risk-alert-sim-stop');
  if (!alertIncidentId || button.disabled) return;
  button.disabled = true;
  try {
    const result = await getJson('/api/p6/respond', {
      method:'POST',
      headers:{
        'Content-Type':'application/json',
        'X-Chem-Shield-P6-Confirmation':p6ConfirmToken,
      },
      body:JSON.stringify({incident_id:alertIncidentId, confirm_stop:true}),
    });
    $('risk-alert-message').textContent = result.simulation_only
      ? 'Simulation only: the local virtual machine recorded the stop. No physical device was contacted.'
      : 'Part 6 response recorded.';
    button.textContent = 'SIMULATED STOP RECORDED';
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
$('risk-alert-close').addEventListener('click', () => $('risk-alert-dialog').close());

setConnection(false); setNetworkStatus({status:'DISCONNECTED', error:'Not connected'}); refresh(); setInterval(refresh, 1000);
