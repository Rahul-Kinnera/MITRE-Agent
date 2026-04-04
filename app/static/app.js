const statusEl = document.getElementById("status");
const syncButton = document.getElementById("syncButton");
const analyzeForm = document.getElementById("analyzeForm");
const downloadsEl = document.getElementById("downloads");
const summaryEl = document.getElementById("summary");
const attackMatrixEl = document.getElementById("attackMatrix");
const d3fendMatrixEl = document.getElementById("d3fendMatrix");
const actorOverlapEl = document.getElementById("actorOverlap");

syncButton.addEventListener("click", async () => {
  setStatus("Syncing official MITRE ATT&CK and D3FEND data...");
  try {
    const response = await fetch("/api/sync", { method: "POST" });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.detail || "Sync failed");
    }
    setStatus("MITRE data sync completed. You can analyze logs now.");
  } catch (error) {
    setStatus(`Sync failed: ${error.message}`);
  }
});

analyzeForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const fileInput = document.getElementById("logFiles");
  if (!fileInput.files.length) {
    setStatus("Choose one or more local log files first.");
    return;
  }

  const formData = new FormData();
  for (const file of fileInput.files) {
    formData.append("files", file);
  }

  setStatus("Uploading files and running local analysis...");
  hideResults();

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      body: formData,
    });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.detail || "Analysis failed");
    }
    renderResults(payload);
    setStatus("Analysis complete.");
  } catch (error) {
    setStatus(`Analysis failed: ${error.message}`);
  }
});

function setStatus(message) {
  statusEl.textContent = message;
}

function hideResults() {
  for (const element of [downloadsEl, summaryEl, attackMatrixEl, d3fendMatrixEl, actorOverlapEl]) {
    element.classList.add("hidden");
    element.innerHTML = "";
  }
}

function renderResults(payload) {
  renderDownloads(payload);
  renderSummary(payload.summary, payload.observed_techniques);
  renderAttackMatrix(payload.attack_matrix);
  renderD3fendMatrix(payload.d3fend_matrix);
  renderActorOverlap(payload.threat_actor_hypotheses);
}

function renderDownloads(payload) {
  downloadsEl.classList.remove("hidden");
  downloadsEl.innerHTML = `
    <h2>Downloads</h2>
    <div class="download-links">
      <a class="download-link" href="${payload.downloads.report_html}" target="_blank" rel="noreferrer">Open HTML report</a>
      <a class="download-link" href="${payload.downloads.navigator_layer}" target="_blank" rel="noreferrer">Download ATT&CK layer JSON</a>
      <a class="download-link" href="${payload.downloads.analysis_json}" target="_blank" rel="noreferrer">Download raw analysis JSON</a>
      <a class="download-link" href="${payload.navigator_hint_url}" target="_blank" rel="noreferrer">Open ATT&CK Navigator</a>
    </div>
    <p class="muted">Analysis ID: ${payload.analysis_id}. Import the generated layer JSON into the local Navigator instance for a full ATT&CK Navigator view.</p>
  `;
}

function renderSummary(summary, observedTechniques) {
  summaryEl.classList.remove("hidden");
  const techniqueCards = observedTechniques.length
    ? observedTechniques.map((item) => `
        <article class="technique-card">
          <h3><a href="${item.url}" target="_blank" rel="noreferrer">${item.attack_id} ${escapeHtml(item.name)}</a></h3>
          <p class="meta">${escapeHtml(item.behavior)} | Hits: ${item.hits} | Severity: ${item.severity} | Confidence: ${item.confidence} | Score: ${item.score}</p>
          <div>${item.tactics.map((tactic) => `<span class="pill">${escapeHtml(tactic)}</span>`).join("")}</div>
          <p class="meta">Matched rules: ${item.rules_matched.map((ruleId) => escapeHtml(ruleId)).join(", ")}</p>
          <p>${item.examples.map((example) => escapeHtml(example)).join("<br />")}</p>
        </article>
      `).join("")
    : "<p class=\"muted\">No ATT&CK techniques matched the current heuristic rules.</p>";

  summaryEl.innerHTML = `
    <h2>Summary</h2>
    <div class="summary-grid">
      <div class="stat"><div class="stat-label">Files analyzed</div><div class="stat-value">${summary.files_analyzed}</div></div>
      <div class="stat"><div class="stat-label">Lines analyzed</div><div class="stat-value">${summary.lines_analyzed}</div></div>
      <div class="stat"><div class="stat-label">Observed techniques</div><div class="stat-value">${summary.techniques_detected}</div></div>
      <div class="stat"><div class="stat-label">High-confidence techniques</div><div class="stat-value">${summary.high_confidence_techniques}</div></div>
    </div>
    <div class="observed-list">${techniqueCards}</div>
  `;
}

function renderAttackMatrix(matrix) {
  attackMatrixEl.classList.remove("hidden");
  const columns = matrix.length
    ? matrix.map((column) => `
        <div class="matrix-column">
          <h3>${escapeHtml(column.tactic)}</h3>
          <ul class="clean">
            ${column.techniques.map((technique) => `
              <li><a href="${technique.url}" target="_blank" rel="noreferrer">${escapeHtml(technique.attack_id)} ${escapeHtml(technique.name)}</a></li>
            `).join("")}
          </ul>
        </div>
      `).join("")
    : "<p class=\"muted\">No ATT&CK matrix view is available yet for this run.</p>";

  attackMatrixEl.innerHTML = `
    <h2>ATT&CK Visual Map</h2>
    <p class="muted">This local matrix mirrors the ATT&CK Navigator structure and is paired with a downloadable Navigator layer JSON.</p>
    <div class="matrix-grid">${columns}</div>
  `;
}

function renderD3fendMatrix(matrix) {
  d3fendMatrixEl.classList.remove("hidden");
  const columns = matrix.length
    ? matrix.map((column) => `
        <div class="matrix-column">
          <h3>${escapeHtml(column.tactic)}</h3>
          <ul class="clean">
            ${column.defenses.map((defense) => `
              <li><a href="${defense.url}" target="_blank" rel="noreferrer">${escapeHtml(defense.d3fend_id)} ${escapeHtml(defense.name)}</a> <span class="meta">from ${escapeHtml(defense.attack_id)}</span></li>
            `).join("")}
          </ul>
        </div>
      `).join("")
    : "<p class=\"muted\">No D3FEND mappings were found for the observed ATT&CK techniques.</p>";

  d3fendMatrixEl.innerHTML = `
    <h2>D3FEND Visual Map</h2>
    <p class="muted">D3FEND defenses are grouped by tactic when that metadata is available from the locally cached official D3FEND matrix.</p>
    <div class="matrix-grid">${columns}</div>
  `;
}

function renderActorOverlap(actors) {
  actorOverlapEl.classList.remove("hidden");
  const cards = actors.length
    ? actors.map((actor) => `
        <article class="actor-card">
          <h3><a href="${actor.url}" target="_blank" rel="noreferrer">${escapeHtml(actor.group_id)} ${escapeHtml(actor.name)}</a></h3>
          <p class="meta">Confidence: ${actor.confidence} | Technique overlap: ${actor.overlap_count} | Support: ${actor.support_ratio} | Score: ${actor.score}</p>
          <p class="meta">${escapeHtml(actor.summary)}</p>
          <p>${actor.matching_techniques.slice(0, 5).map((technique) => escapeHtml(`${technique.attack_id} ${technique.name} (weight ${technique.weight})`)).join("<br />")}</p>
        </article>
      `).join("")
    : "<p class=\"muted\">No ATT&CK intrusion-set overlap was identified from the currently observed techniques.</p>";

  actorOverlapEl.innerHTML = `
    <h2>Initial Threat Actor Analysis</h2>
    <p class="muted">This is a conservative ATT&CK overlap view for triage only. Single-technique overlaps and weak matches are suppressed to reduce overconfident attribution.</p>
    <div class="actor-grid">${cards}</div>
  `;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
