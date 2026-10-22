function timelineNode(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

async function refreshTimeline() {
  const query = new URLSearchParams(location.search);
  const runId = query.get("run_id");
  const url = runId ? `/p7/api/timeline?run_id=${encodeURIComponent(runId)}` : "/p7/api/timeline";
  try {
    const response = await fetch(url, {headers: {Accept: "application/json"}});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `Timeline request failed (${response.status})`);
    const run = data.run;
    const list = document.getElementById("p7-full-timeline");
    list.replaceChildren();
    if (!run) {
      document.getElementById("p7-timeline-title").textContent = "Waiting for a scenario";
      list.append(timelineNode("li", "p7-empty", "Run a scenario from the Command Center to populate this timeline."));
      return;
    }
    document.getElementById("p7-timeline-title").textContent = `${run.scenario_name} · ${run.run_id}`;
    document.getElementById("p7-timeline-status").textContent = `${run.status} · ${run.outcome || "In progress"}`;
    const start = Date.parse(run.started_at);
    for (const event of run.events || []) {
      const item = timelineNode("li");
      const seconds = Math.max(0, Math.round((Date.parse(event.timestamp) - start) / 1000));
      const offset = `+${String(Math.floor(seconds / 60)).padStart(2, "0")}:${String(seconds % 60).padStart(2, "0")}`;
      item.append(timelineNode("strong", "", `${offset}s · ${event.event_type}`));
      item.append(timelineNode("span", "p7-event-meta", `${event.detector || event.source || "Part 7"}${event.detail?.message ? ` · ${event.detail.message}` : ""}`));
      for (const tag of event.mitre || []) {
        const badge = timelineNode("span", "p7-mitre", `${tag.id} ${tag.name}`);
        badge.title = `${tag.tactic}${tag.verify ? " — verify mapping" : ""}`;
        item.append(badge);
      }
      list.append(item);
    }
    const detectedAt = run.detected_at ? Date.parse(run.detected_at) : NaN;
    const respondedAt = run.responded_at ? Date.parse(run.responded_at) : NaN;
    document.getElementById("p7-detection-latency").textContent =
      Number.isFinite(detectedAt) ? `${Math.max(0, (detectedAt - start) / 1000).toFixed(2)} s` : "Not detected";
    document.getElementById("p7-response-latency").textContent =
      Number.isFinite(respondedAt) && Number.isFinite(detectedAt)
        ? `${Math.max(0, (respondedAt - detectedAt) / 1000).toFixed(2)} s` : "No response yet";
    document.getElementById("p7-timeline-run-id").value = run.run_id;
    document.getElementById("p7-timeline-report").hidden = false;
  } catch (error) {
    document.getElementById("p7-timeline-status").textContent = error.message;
  }
}

window.setInterval(refreshTimeline, 1500);
refreshTimeline();
