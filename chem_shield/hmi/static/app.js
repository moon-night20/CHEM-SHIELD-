const $ = (id) => document.getElementById(id);
let connected = false;

function setConnection(online) {
  connected = online;
  $('connection-text').textContent = online ? 'PLC-01 CONNECTED' : 'PLC-01 OFFLINE';
  $('connection').classList.toggle('offline', !online);
  $('offline-banner').hidden = online;
  document.querySelectorAll('.command-buttons button, #apply-setpoint, #event-button').forEach((button) => { button.disabled = !online; });
}

function setState(state) {
  const running = state.motor_status === 'RUNNING';
  $('state-label').textContent = state.motor_status;
  $('command-state').textContent = state.motor_status;
  $('state-badge').className = `state-badge ${running ? 'running' : 'stopped'}`;
  $('rpm').textContent = Math.round(state.rpm);
  $('target').textContent = Math.round(state.target_rpm);
  $('temperature').textContent = state.temperature.toFixed(1);
  $('pressure').textContent = state.pressure.toFixed(2);
  $('power').textContent = state.power.toFixed(2);
  $('target-input').value = Math.round(state.target_rpm);
  $('target-range').value = Math.round(state.target_rpm);
}

function renderEvents(events) {
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
  const response = await fetch(url, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `Request failed: ${response.status}`);
  return data;
}

async function refresh() {
  try {
    const [state, events] = await Promise.all([getJson('/api/state'), getJson('/api/events')]);
    setConnection(true); setState(state); renderEvents(events);
    $('last-update').textContent = `UPDATED ${new Date().toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'})}`;
  } catch (error) {
    setConnection(false); console.warn(error);
  }
}

async function sendCommand(action) {
  const feedback = $('command-feedback');
  feedback.textContent = action === 'setpoint' ? 'Applying target speed...' : `${action === 'start' ? 'Starting' : 'Stopping'} motor...`;
  try {
    await getJson('/api/control', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({action, target_rpm:$('target-input').value})});
    feedback.textContent = action === 'setpoint' ? 'Target RPM applied to PLC-01.' : `Motor ${action === 'start' ? 'start' : 'stop'} command sent to PLC-01.`;
    await refresh();
  } catch (error) { feedback.textContent = `Command failed: ${error.message}`; $('last-update').textContent = 'COMMAND FAILED'; }
}

document.querySelectorAll('[data-action]').forEach((button) => button.addEventListener('click', () => sendCommand(button.dataset.action)));
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

setConnection(false); refresh(); setInterval(refresh, 1000);
