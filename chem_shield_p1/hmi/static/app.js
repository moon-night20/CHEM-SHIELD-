const $ = (id) => document.getElementById(id);
let connected = false;
const trendHistory = [];
const trendLimit = 60;
let sequenceCounter = 0;
let selectedFocus = 'temperature';
let allIncidents = [];
let alertIncidentId = null;
let lastNotifiedIncident = null;
let refreshPending = false;
let riskRefreshPending = false;
const p6ConfirmToken = document.querySelector('meta[name="p6-confirm-token"]').content;

const focusConfig = {
  temperature: {label: 'TEMPERATURE', unit: '°C', value: (state) => state.temperature, target: () => '80.0 °C'},
  speed: {label: 'SPEED', unit: 'RPM', value: (state) => state.rpm, target: (state) => `${Math.round(state.target_rpm)} RPM`},
  pressure: {label: 'PRESSURE', unit: 'bar', value: (state) => state.pressure, target: () => '4.00 bar'},
  power: {label: 'POWER', unit: 'kW', value: (state) => state.power, target: () => '12.00 kW'},
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
  $('state-label').textContent = state.motor_status;
  $('command-state').textContent = state.motor_status;
  $('state-badge').className = `state-badge ${running ? 'running' : state.motor_status === 'PAUSED' ? 'paused' : 'stopped'}`;
  $('target-input').value = Math.round(state.target_rpm);
  $('target-range').value = Math.round(state.target_rpm);
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

function appendText(parent, tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  node.textContent = text;
  parent.appendChild(node);
  return node;
}

function renderIncidents(incidents) {
  const list = $('incident-list');
  const filter = $('incident-filter').value;
  allIncidents = incidents;
  const visibleIncidents = allIncidents.filter((incident) => {
    if (filter === 'all') return true;
    if (filter === 'active') return incident.status === 'ACTIVE';
    if (filter === 'unacknowledged') return !incident.acknowledged && incident.status === 'ACTIVE';
    return incident.risk_level.toLowerCase() === filter;
  });
  list.replaceChildren();
  if (!visibleIncidents.length) {
    appendText(list, 'p', 'incident-empty', incidents.length ? 'No incidents match this filter.' : 'No incidents recorded.');
    return;
  }
  visibleIncidents.forEach((incident) => {
    const level = (incident.risk_level || 'UNASSESSED').toLowerCase();
    const card = document.createElement('article');
    card.className = `incident-card ${level}`;
    card.dataset.incidentId = incident.incident_id;
    const head = appendText(card, 'div', 'incident-card-head', '');
    appendText(head, 'span', 'incident-id', `${incident.incident_id} · ${incident.asset_id}`);
    const actions = appendText(head, 'div', 'incident-actions', '');
    appendText(actions, 'span', `risk-badge ${level}`, incident.risk_level);
    if (incident.acknowledged) {
      appendText(actions, 'span', 'acknowledged-label', 'ACKNOWLEDGED');
    } else if (incident.status === 'ACTIVE') {
      const ack = appendText(actions, 'button', '', 'ACKNOWLEDGE');
      ack.type = 'button';
      ack.dataset.ackIncident = incident.incident_id;
    }
    appendText(
      card,
      'p',
      'incident-meta',
      `${incident.status} · ${incident.events.length} event(s) · ${new Date(incident.start_time).toLocaleString()}${incident.risk_score === null ? ' · score unavailable' : ` · score ${Number(incident.risk_score).toFixed(3)}`}`
    );
    const details = document.createElement('details');
    appendText(details, 'summary', '', 'Evidence and detections');
    incident.events.forEach((event) => {
      const evidence = typeof event.evidence === 'string' ? event.evidence : JSON.stringify(event.evidence || {});
      appendText(
        details,
        'p',
        'incident-evidence',
        `${event.source || 'unknown source'} · ${event.detection_type || event.event_type}${event.anomaly_score === null ? ' · no anomaly score' : ` · score ${event.anomaly_score}`}${evidence ? ` · ${evidence}` : ''}`
      );
    });
    card.appendChild(details);
    list.appendChild(card);
  });
}

function maybeShowRiskAlert(summary) {
  const incident = (summary.active_incidents || [])
    .filter((item) => !item.acknowledged && ['HIGH', 'CRITICAL'].includes(item.risk_level))
    .sort((left, right) => (right.risk_score || 0) - (left.risk_score || 0))[0];
  if (!incident || incident.acknowledged || !['HIGH', 'CRITICAL'].includes(incident.risk_level)) return;
  const key = `${incident.incident_id}:${incident.risk_level}`;
  if (key === lastNotifiedIncident || $('risk-alert-dialog').open) return;
  lastNotifiedIncident = key;
  alertIncidentId = incident.incident_id;
  $('risk-alert-title').textContent = `${incident.risk_level} RISK INCIDENT`;
  $('risk-alert-message').textContent = `${incident.asset_id}: score ${Number(incident.risk_score).toFixed(3)} on a 0.0-1.0 scale. Acknowledging records operator awareness only; it does not lower risk or resolve the incident.`;
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
    const level = summary.risk_level.toLowerCase();
    $('risk-badge').textContent = summary.risk_level;
    $('risk-badge').className = `risk-badge ${level}`;
    $('risk-score').textContent = summary.risk_score === null ? '--' : Number(summary.risk_score).toFixed(3);
    $('risk-input-status').textContent = summary.input_status.replaceAll('_', ' ');
    $('risk-last-update').textContent = summary.last_received_at
      ? `Last event ${new Date(summary.last_received_at).toLocaleString()}`
      : 'No risk events received';
    renderIncidents(summary.recent_incidents || []);
    maybeShowRiskAlert(summary);
  } catch (error) {
    $('risk-badge').textContent = 'UNAVAILABLE';
    $('risk-badge').className = 'risk-badge unassessed';
    $('risk-score').textContent = '--';
    $('risk-input-status').textContent = 'ERROR';
    $('risk-last-update').textContent = error.message;
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
$('target-input').addEventListener('input', (event) => { $('target-range').value = Math.max(0, Math.min(3000, event.target.value)); });
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
$('incident-filter').addEventListener('change', () => renderIncidents(allIncidents));
$('incident-list').addEventListener('click', (event) => {
  const button = event.target.closest('[data-ack-incident]');
  if (button) void acknowledgeIncident(button.dataset.ackIncident);
});
$('risk-alert-ack').addEventListener('click', () => {
  if (alertIncidentId) void acknowledgeIncident(alertIncidentId);
});
$('risk-alert-sim-stop').addEventListener('click', () => void confirmSimulatedStop());
$('risk-alert-close').addEventListener('click', () => $('risk-alert-dialog').close());

setConnection(false); setNetworkStatus({status:'DISCONNECTED', error:'Not connected'}); refresh(); setInterval(refresh, 1000);
