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
  triage_performed: "Triagem JEV", assignment_changed: "Atribuição alterada",
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
    case "triage_performed": return `🔮 Triagem JEV: ${d.model || "jev-latest"} — compromisso: ${d.answers?.is_compromise?.probability !== undefined ? (d.answers.is_compromise.probability * 100).toFixed(0) + "%" : "—"}, severidade: ${d.answers?.severity?.choice || "—"}`;
    case "assignment_changed": return `${INC_EVENT_LABELS.assignment_changed}: ${d.from || "—"} → ${d.to || "—"}`;
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
  const assigned = incident.assigned_to ? `👤 ${escapeHtml(incident.assigned_to)}` : "👤 Não atribuído";
  document.getElementById("inc-detail-meta").innerHTML = `
    <span>${severityBadge(incident.severity)}</span> <span>${incStatusBadge(incident.status)}</span>
    <span>Ativo: <strong>${incCell(incident.asset)}</strong></span>
    <span>Analista: <strong>${assigned}</strong></span>
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

  // Populate assignment input
  const assignmentInput = document.getElementById("inc-assignment-input");
  const assignmentStatus = document.getElementById("inc-assignment-status");
  if (incident.assigned_to) {
    assignmentInput.value = incident.assigned_to;
    assignmentStatus.textContent = `Atribuído a ${escapeHtml(incident.assigned_to)}`;
  } else {
    assignmentInput.value = "";
    assignmentStatus.textContent = "";
  }

  // Show triage section with cached result if available
  const triageSection = document.getElementById("inc-triage-section");
  const triageResult = document.getElementById("inc-triage-result");
  const triageStatus = document.getElementById("inc-triage-status");
  if (incident.triage) {
    triageSection.hidden = false;
    triageStatus.textContent = incident.triage.cached ? "📋 Resultado em cache (clique para re-executar)" : "✅ Triagem concluída";
    incRenderTriageResult(triageResult, incident.triage);
  } else {
    triageSection.hidden = false;
    triageStatus.textContent = "";
    triageResult.hidden = true;
  }
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

// Preenche o filtro "Analista" com os analistas ativos. O backend filtra
// assigned_to pelo texto guardado na atribuição, por isso value = nome.
// Se o pedido falhar fica só "Todos", sem mensagem extra.
async function incLoadAnalystFilter() {
  const select = document.getElementById("inc-assigned-filter");
  if (!select) return;
  const atual = select.value;
  let nomes = [];
  try {
    const data = await incRequest("GET", "/api/soc/analysts?active_only=true");
    nomes = (data.analysts || []).filter((a) => a && a.active !== false && a.name).map((a) => a.name);
  } catch (err) {
    nomes = [];
  }
  select.innerHTML = `<option value="">Todos</option>` +
    nomes.map((n) => `<option value="${escapeHtml(n)}">${escapeHtml(n)}</option>`).join("");
  select.value = nomes.includes(atual) ? atual : "";
}

async function refreshIncidentsTab() {
  if (incRefreshing) return;
  incRefreshing = true;
  try {
    const params = new URLSearchParams({ hours: String(incWindowHours()) });
    const status = document.getElementById("inc-status-filter").value;
    const severity = document.getElementById("inc-severity-filter").value;
    const assigned = document.getElementById("inc-assigned-filter").value;
    if (status) params.set("status", status);
    if (severity) params.set("severity", severity);
    if (assigned) params.set("assigned_to", assigned);
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

document.getElementById("inc-triage-btn").addEventListener("click", () => incTriage(incSelectedId));

document.getElementById("inc-assignment-btn").addEventListener("click", () => incAssign(incSelectedId));

document.getElementById("inc-backfill-btn").addEventListener("click", backfillIncidents);
document.getElementById("inc-status-filter").addEventListener("change", refreshIncidentsTab);
document.getElementById("inc-severity-filter").addEventListener("change", refreshIncidentsTab);
document.getElementById("inc-assigned-filter").addEventListener("change", refreshIncidentsTab);
periodSelect.addEventListener("change", refreshIncidentsTab);
document.addEventListener("sentrylens:new-alert", refreshIncidentsTab);

incLoadAnalystFilter().then(refreshIncidentsTab);
setInterval(refreshIncidentsTab, INC_REFRESH_MS);

// --- JEV Triagem ---
let incTriageCache = new Map();

async function incTriage(incidentId) {
  if (!incidentId) return;
  const btn = document.getElementById("inc-triage-btn");
  const statusEl = document.getElementById("inc-triage-status");
  const resultEl = document.getElementById("inc-triage-result");
  
  // Check if we have cached result and user wants to re-run
  const force = !incTriageCache.has(incidentId) || confirm("Já existe resultado em cache. Re-executar triagem?");
  
  btn.disabled = true;
  btn.textContent = "🔮 A triar...";
  statusEl.textContent = "A contactar TypeSafe AI...";
  resultEl.hidden = true;
  
  try {
    const response = await incRequest("POST", `/api/incidents/${encodeURIComponent(incidentId)}/triage${force ? "?force=1" : ""}`);
    incTriageCache.set(incidentId, response);
    incRenderTriageResult(resultEl, response);
    statusEl.textContent = response.cached ? "📋 Resultado em cache" : "✅ Triagem concluída";
  } catch (err) {
    if (err.status === 503) {
      statusEl.textContent = "⚠️ JEV desativado — configure SENTRYLENS_JEV_ENABLED=1 e TYPESAFE_API_KEY no backend";
    } else if (err.status === 502) {
      statusEl.textContent = `⚠️ Erro no JEV: ${err.message}`;
    } else {
      statusEl.textContent = `❌ Falha: ${err.message}`;
    }
    resultEl.hidden = true;
  } finally {
    btn.disabled = false;
    btn.textContent = "🔮 Triar com JEV";
  }
}

function incRenderTriageResult(container, data) {
  container.hidden = false;
  const answers = data.answers || {};
  const model = data.model || "jev-latest";
  
  const questionLabels = {
    is_compromise: "Compromisso bem-sucedido?",
    is_brute_force: "Força bruta / password guessing?",
    severity: "Severidade geral"
  };
  
  let html = "";
  
  for (const [key, answer] of Object.entries(answers)) {
    const label = questionLabels[key] || key;
    
    if (answer.probability !== undefined) {
      // NOUL question (sim/não)
      const prob = Math.round(answer.probability * 100);
      const fillClass = prob >= 50 ? "yes" : "no";
      html += `
        <div class="inc-triage-question">
          <h4>${escapeHtml(label)}</h4>
          <div class="inc-triage-prob">
            <span class="inc-triage-prob-label">Sim</span>
            <div class="inc-triage-prob-bar"><div class="inc-triage-prob-fill ${fillClass}" style="width: ${prob}%"></div></div>
            <span class="inc-triage-prob-value">${prob}%</span>
          </div>
          <div class="inc-triage-prob">
            <span class="inc-triage-prob-label">Não</span>
            <div class="inc-triage-prob-bar"><div class="inc-triage-prob-fill ${prob >= 50 ? "no" : "yes"}" style="width: ${100 - prob}%"></div></div>
            <span class="inc-triage-prob-value">${100 - prob}%</span>
          </div>
        </div>`;
    } else if (answer.choice) {
      // CHOICE question
      const probs = answer.probabilities || {};
      const confidence = answer.confidence !== undefined ? Math.round(answer.confidence * 100) : null;
      html += `
        <div class="inc-triage-question">
          <h4>${escapeHtml(label)}</h4>
          <div class="inc-triage-choice">Classificação: ${escapeHtml(answer.choice)}</div>
          ${confidence !== null ? `<div class="inc-triage-confidence">Confidence (concentração): ${confidence}%</div>` : ""}
          <div style="margin-top: 8px;">Probabilidades:</div>
          ${Object.entries(probs).map(([choice, p]) => {
            const pct = Math.round(p * 100);
            return `<div class="inc-triage-prob">
              <span class="inc-triage-prob-label">${escapeHtml(choice)}</span>
              <div class="inc-triage-prob-bar"><div class="inc-triage-prob-fill choice" style="width: ${pct}%"></div></div>
              <span class="inc-triage-prob-value">${pct}%</span>
            </div>`;
          }).join("")}
        </div>`;
    }
  }
  
  html += `<div class="inc-triage-model">Modelo: ${escapeHtml(model)} · <em>Confidence = concentração da distribuição, não probabilidade de acerto</em></div>`;
  
  container.innerHTML = html;
}

// --- Atribuição de analista ---
async function incAssign(incidentId) {
  if (!incidentId) return;
  const btn = document.getElementById("inc-assignment-btn");
  const input = document.getElementById("inc-assignment-input");
  const statusEl = document.getElementById("inc-assignment-status");
  
  const analyst = input.value.trim() || null;
  
  btn.disabled = true;
  btn.textContent = "⏳ A atribuir...";
  statusEl.textContent = analyst ? `A atribuir a ${analyst}...` : "A desatribuir...";
  
  try {
    await incRequest("PATCH", `/api/incidents/${encodeURIComponent(incidentId)}/assignment`, { analyst });
    statusEl.textContent = analyst ? `✅ Atribuído a ${analyst}` : "✅ Desatribuído";
    input.value = analyst || "";
    await incLoadAnalystFilter();
    await refreshIncidentsTab();
    // Refresh detail to show updated assignment
    selectIncident(incidentId);
  } catch (err) {
    statusEl.textContent = `❌ Falha: ${err.message}`;
  } finally {
    btn.disabled = false;
    btn.textContent = "✅ Atribuir";
  }
}
