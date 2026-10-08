// Aba "Incidentes" (Roadmap v2, R3). Carregado depois de app.js e redblue.js:
// reutiliza os seus globais (API_BASE, API_KEY, escapeHtml, severityBadge,
// formatTimestamp, renderPanelError, periodSelect) — não redeclarar nenhum
// aqui. Só mostra dados reais de /api/incidents/*; sem dados, estado vazio.
// Todo o texto dinâmico passa por escapeHtml (notas e payloads vêm do analista
// e do Wazuh).

const INC_REFRESH_MS = 30000;
const INC_STATUS_LABELS = {
  NEW: "Novo", INVESTIGATING: "Em investigação", CONTAINED: "Contido", RESOLVED: "Resolvido", CLOSED: "Fechado",
};
const INC_EVENT_LABELS = {
  created: "Incidente criado", evidence_added: "Evidência adicionada", attack_linked: "Ataque ligado",
  severity_changed: "Severidade alterada", status_changed: "Estado alterado", note_added: "Nota",
};

let incSelectedId = null;
let incRefreshing = false;

function incCell(value) {
  if (value === null || value === undefined || value === "") return "—";
  return escapeHtml(String(value));
}

function incSetText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function incFormatSeconds(seconds) {
  if (seconds === null || seconds === undefined) return "—";
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  return `${Math.floor(seconds / 60)} min ${Math.round(seconds % 60)} s`;
}

function incStatusBadge(status) {
  const label = INC_STATUS_LABELS[status] || status;
  return `<span class="inc-status inc-status-${escapeHtml(status)}">${escapeHtml(label)}</span>`;
}

async function incRequest(method, path, body) {
  const response = await fetch(`${API_BASE}${path}`, {
    method,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    try {
      const data = await response.json();
      if (data && typeof data.detail === "string") detail = data.detail;
    } catch (_) { /* corpo não-JSON: fica o código HTTP */ }
    const error = new Error(detail);
    error.status = response.status;
    throw error;
  }
  return response.json();
}

function incWindowHours() {
  // period-select está em dias; o endpoint aceita no máximo 720 h (30 dias).
  return Math.min(Number(periodSelect.value) * 24, 720);
}

function renderIncidentsKpis(summary) {
  incSetText("kpi-inc-open", summary.open);
  incSetText("kpi-inc-high", summary.high_or_critical_open);
  incSetText("kpi-inc-mttd", incFormatSeconds(summary.avg_mttd_seconds));
  incSetText("kpi-inc-total", summary.total);
}

function renderIncidentsTable(incidents) {
  const body = document.getElementById("incidents-body");
  if (!incidents.length) {
    body.innerHTML = `<tr><td colspan="8" class="empty-state">Sem incidentes nesta janela. Se ainda não importaste o histórico, usa «Importar histórico».</td></tr>`;
    return;
  }
  body.innerHTML = incidents.map((i) => {
    const mitre = i.techniques.length ? i.techniques.join(", ") : "—";
    const attack = i.attack_ids.length ? ` (ataque #${i.attack_ids.join(", #")})` : "";
    return `<tr class="inc-row${i.id === incSelectedId ? " selected" : ""}" data-id="${escapeHtml(i.id)}" tabindex="0">
      <td>${escapeHtml(i.id)}</td>
      <td>${severityBadge(i.severity)}</td>
      <td>${incStatusBadge(i.status)}</td>
      <td>${incCell(i.asset)}</td>
      <td>${escapeHtml(formatTimestamp(i.first_evidence_at))}</td>
      <td>${escapeHtml(formatTimestamp(i.last_evidence_at))}</td>
      <td>${incCell(i.evidence_count)}</td>
      <td>${escapeHtml(mitre + attack)}</td>
    </tr>`;
  }).join("");
}

function incEvidenceDescription(e) {
  if (e.kind === "wazuh_alert" && e.alert) {
    const a = e.alert;
    return `${a.friendly_name || "Alerta"} — ${a.rule_description || "sem descrição"} (${a.agent_name || "?"})`;
  }
  if (e.kind === "network_detection" && e.payload) {
    const p = e.payload;
    return `${p.type} ${p.src_ip || "?"} → ${p.dst_ip || "?"}`;
  }
  return "—";
}

function incTimelineText(ev) {
  const d = ev.data || {};
  switch (ev.kind) {
    case "created": return `${INC_EVENT_LABELS.created} em ${d.asset || "?"} (${d.severity || "?"})`;
    case "evidence_added": return `${INC_EVENT_LABELS.evidence_added}: ${d.kind || ""} (${d.severity || "?"})`;
    case "attack_linked": return `${INC_EVENT_LABELS.attack_linked}: ${d.scenario || "?"} / ${d.technique || "?"} / ${d.tool || "?"}${d.attack_id != null ? ` (#${d.attack_id})` : ""}`;
    case "severity_changed": return `${INC_EVENT_LABELS.severity_changed}: ${d.from} → ${d.to}`;
    case "status_changed": return `${INC_EVENT_LABELS.status_changed}: ${d.from} → ${d.to}${d.note ? ` — ${d.note}` : ""}`;
    case "note_added": return `${INC_EVENT_LABELS.note_added}: ${d.text || ""}`;
    default: return ev.kind;
  }
}

function renderIncidentDetail(incident) {
  const panel = document.getElementById("incident-detail-panel");
  panel.hidden = false;
  incSetText("inc-detail-title", `Incidente ${incident.id}`);

  const ml = incident.ml_summary
    ? `${incident.ml_summary.ml_anomalies}/${incident.ml_summary.scored} anomalias ML · ${incident.ml_summary.rule_flagged} por regra`
    : "sem modelo ML";
  document.getElementById("inc-detail-meta").innerHTML = `
    <span>${severityBadge(incident.severity)}</span> <span>${incStatusBadge(incident.status)}</span>
    <span>Ativo: <strong>${incCell(incident.asset)}</strong></span>
    <span>MITRE: ${incCell(incident.techniques.join(", "))}</span>
    <span>MTTD: ${escapeHtml(incFormatSeconds(incident.mttd_seconds))}</span>
    <span>1.ª resposta: ${escapeHtml(incFormatSeconds(incident.time_to_first_response_seconds))}</span>
    <span>${escapeHtml(ml)}</span>`;

  document.getElementById("inc-actions").innerHTML = incident.available_transitions.map((s) =>
    `<button type="button" class="inc-transition" data-status="${escapeHtml(s)}">→ ${escapeHtml(INC_STATUS_LABELS[s] || s)}</button>`
  ).join("") || `<span class="panel-note">Estado final — sem transições.</span>`;

  document.getElementById("inc-evidence-body").innerHTML = incident.evidence.map((e) => `<tr>
    <td>${escapeHtml(formatTimestamp(e.ts))}</td><td>${escapeHtml(e.kind)}</td>
    <td>${severityBadge(e.severity)}</td><td>${escapeHtml(incEvidenceDescription(e))}</td></tr>`).join("");

  document.getElementById("inc-timeline").innerHTML = incident.timeline.map((ev) =>
    `<li><time>${escapeHtml(formatTimestamp(ev.ts))}</time> <em>${escapeHtml(ev.actor)}</em> — ${escapeHtml(incTimelineText(ev))}</li>`
  ).join("");
}

function incShowDetailError(message) {
  const el = document.getElementById("inc-detail-error");
  el.hidden = !message;
  el.textContent = message ? `⚠️ ${message}` : "";
}

async function selectIncident(id) {
  incSelectedId = id;
  incShowDetailError("");
  try {
    renderIncidentDetail(await incRequest("GET", `/api/incidents/${encodeURIComponent(id)}`));
    document.querySelectorAll("#incidents-body tr[data-id]").forEach((tr) =>
      tr.classList.toggle("selected", tr.dataset.id === id));
  } catch (err) {
    incShowDetailError(err.message);
  }
}

async function incApply(promise) {
  incShowDetailError("");
  try {
    renderIncidentDetail(await promise);
    document.getElementById("inc-note-input").value = "";
    await refreshIncidentsTab();
  } catch (err) {
    incShowDetailError(err.message);
  }
}

async function refreshIncidentsTab() {
  if (incRefreshing) return;
  incRefreshing = true;
  try {
    const params = new URLSearchParams({ hours: String(incWindowHours()) });
    const status = document.getElementById("inc-status-filter").value;
    const severity = document.getElementById("inc-severity-filter").value;
    if (status) params.set("status", status);
    if (severity) params.set("severity", severity);
    const data = await incRequest("GET", `/api/incidents?${params}`);
    renderPanelError("#incidents-panel", "");
    renderIncidentsKpis(data.summary);
    renderIncidentsTable(data.incidents);
  } catch (err) {
    renderPanelError("#incidents-panel", `Não foi possível carregar os incidentes: ${err.message}`);
    document.getElementById("incidents-body").innerHTML =
      `<tr><td colspan="8" class="empty-state">Indisponível.</td></tr>`;
  } finally {
    incRefreshing = false;
  }
}

async function backfillIncidents() {
  const btn = document.getElementById("inc-backfill-btn");
  btn.disabled = true;
  incSetText("inc-notice", "A importar alertas do Wazuh…");
  try {
    const r = await incRequest("POST", "/api/incidents/backfill", { days: Number(periodSelect.value) });
    incSetText("inc-notice",
      `Importados ${r.fetched} alertas: ${r.opened} incidentes abertos, ${r.attached} anexados, ${r.duplicate} já conhecidos, ${r.ignored} abaixo do limiar, ${r.invalid} inválidos.` +
      (r.truncated ? " ⚠️ Atingido o teto de alertas por importação — alguns ficaram de fora." : "") +
      " Só alertas Wazuh (as deteções de rede só existem em memória).");
    await refreshIncidentsTab();
  } catch (err) {
    incSetText("inc-notice", `⚠️ Falha ao importar: ${err.message}`);
  } finally {
    btn.disabled = false;
  }
}

document.getElementById("incidents-body").addEventListener("click", (event) => {
  const tr = event.target.closest("tr[data-id]");
  if (tr) selectIncident(tr.dataset.id);
});
document.getElementById("incidents-body").addEventListener("keydown", (event) => {
  const tr = event.target.closest("tr[data-id]");
  if (tr && (event.key === "Enter" || event.key === " ")) {
    event.preventDefault();
    selectIncident(tr.dataset.id);
  }
});

document.getElementById("inc-actions").addEventListener("click", (event) => {
  const btn = event.target.closest("button.inc-transition");
  if (!btn || !incSelectedId) return;
  const note = document.getElementById("inc-note-input").value.trim();
  const isFalsePositive = btn.dataset.status === "CLOSED" &&
    document.querySelector("#inc-detail-meta .inc-status-NEW") !== null;
  if (isFalsePositive && !note) {
    incShowDetailError("Escreve uma nota (falso positivo) antes de fechar um incidente novo.");
    return;
  }
  incApply(incRequest("POST", `/api/incidents/${encodeURIComponent(incSelectedId)}/status`,
    { status: btn.dataset.status, note: note || null }));
});

document.getElementById("inc-note-btn").addEventListener("click", () => {
  const text = document.getElementById("inc-note-input").value.trim();
  if (!text || !incSelectedId) return;
  incApply(incRequest("POST", `/api/incidents/${encodeURIComponent(incSelectedId)}/notes`, { text }));
});

document.getElementById("inc-backfill-btn").addEventListener("click", backfillIncidents);
document.getElementById("inc-status-filter").addEventListener("change", refreshIncidentsTab);
document.getElementById("inc-severity-filter").addEventListener("change", refreshIncidentsTab);
periodSelect.addEventListener("change", refreshIncidentsTab);
document.addEventListener("sentrylens:new-alert", refreshIncidentsTab);

refreshIncidentsTab();
setInterval(refreshIncidentsTab, INC_REFRESH_MS);
