// Aba "Equipa SOC" (Tier 1/2/3). Carregado depois de app.js, api.js e state.js (apiRequest, apiErrorMessage, stt*):
// reutiliza os seus globais (API_BASE, API_KEY, escapeHtml, severityBadge,
// formatTimestamp, renderPanelError, periodSelect) — não redeclarar nenhum aqui.
// Só mostra dados reais de /api/soc/*; sem dados, estado vazio.

function stText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function stCell(value) {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
}

function tierBadge(tier) {
  if (!tier) return htmlT`<span class="inc-status inc-status-NEW">—</span>`;
  const labels = { 1: "Tier 1", 2: "Tier 2", 3: "Tier 3" };
  const cls = { 1: "inc-status-NEW", 2: "inc-status-INVESTIGATING", 3: "inc-status-CONTAINED" };
  return htmlT`<span class="inc-status ${cls[tier]}">${String(labels[tier] || tier)}</span>`;
}

function roleBadge(role) {
  const labels = { primary: "Principal", secondary: "Secundário", on_call: "De prevenção" };
  const cls = { primary: "inc-status-CONTAINED", secondary: "inc-status-INVESTIGATING", on_call: "inc-status-NEW" };
  return htmlT`<span class="inc-status ${cls[role]}">${String(labels[role] || role)}</span>`;
}

function formatDateTimeLocal(ts) {
  if (!ts) return "—";
  const d = new Date(ts.replace(/([+-]\d{2})(\d{2})$/, "$1:$2"));
  if (isNaN(d.getTime())) return String(ts);
  return d.toLocaleString("pt-PT");
}

function formatTimeOnly(ts) {
  if (!ts) return "—";
  const d = new Date(ts.replace(/([+-]\d{2})(\d{2})$/, "$1:$2"));
  if (isNaN(d.getTime())) return String(ts);
  return d.toLocaleTimeString("pt-PT", { hour: "2-digit", minute: "2-digit" });
}

// Estados de carregar/vazio/erro (state.js) dentro de <tbody> ou <ul>: o <p> do
// state.js não é filho válido de tbody/ul, por isso vai embrulhado em <tr><td>/<li>.
function stShowState(container, kind, textOrErr, colspan) {
  if (!container) return;
  // Auto-refresh: o «A carregar» só aparece na primeira carga, para não piscar.
  if (kind === "loading" && container.dataset.stReady) return;
  if (kind === "loading" || kind === "error") delete container.dataset.stReady;
  else container.dataset.stReady = "1";
  const isList = container.tagName === "UL";
  const wrap = document.createElement(isList ? "li" : "tr");
  const cell = isList ? wrap : document.createElement("td");
  if (!isList) {
    cell.colSpan = colspan || 1;
    wrap.appendChild(cell);
  }
  if (kind === "loading") sttShowLoading(cell, textOrErr);
  else if (kind === "error") sttShowError(cell, textOrErr);
  else sttShowEmpty(cell, textOrErr);
  container.replaceChildren(wrap);
}

// Erro de carregamento de um painel: aviso, banner e estado na tabela.
function stLoadFailed(err, noticeId, panelSel, label, body, colspan) {
  const msg = apiErrorMessage(err);
  stText(noticeId, `⚠️ ${msg}`);
  if (panelSel) renderPanelError(panelSel, `${label}: ${msg}`);
  if (body) stShowState(body, "error", err, colspan);
}

// ====== Analysts ======

let stAnalystsCache = [];

async function loadAnalysts() {
  stText("analyst-notice", "A carregar analistas...");
  stShowState(document.getElementById("analysts-body"), "loading", "A carregar analistas…", 6);
  try {
    const tier = document.getElementById("analyst-tier-filter").value;
    const filter = slAnalystActiveFilter(document.getElementById("analyst-active-filter").value);
    const params = new URLSearchParams();
    if (tier) params.set("tier", tier);
    params.set("active_only", filter.activeOnly ? "true" : "false");
    const data = await apiRequest(`/api/soc/analysts?${params}`);
    const received = data.analysts || [];
    // O select de turnos precisa dos analistas ativos da resposta completa,
    // por isso recebe a lista antes do filtro "Inativos" (feito no cliente).
    updateShiftAnalystSelect(received);
    stAnalystsCache = filter.onlyInactive ? received.filter(a => !a.active) : received;
    renderAnalystsTable(stAnalystsCache);
    stText("analyst-notice", `${stAnalystsCache.length} analista(s)`);
  } catch (err) {
    stAnalystsCache = [];
    stLoadFailed(err, "analyst-notice", "#analysts-section", "Falha ao carregar analistas", document.getElementById("analysts-body"), 6);
  }
}

function renderAnalystsTable(analysts) {
  const body = document.getElementById("analysts-body");
  if (!analysts.length) {
    stShowState(body, "empty", "Sem analistas.", 6);
    return;
  }
  body.dataset.stReady = "1";
  htmRender(body, htmlT`${analysts.map((a) => htmlT`
    <tr data-id="${a.id}">
      <td>${a.id}</td>
      <td>${a.name}</td>
      <td>${tierBadge(a.tier)}</td>
      <td>${stCell(a.email)}</td>
      <td>${a.active ? htmlT`<span class="inc-status inc-status-RESOLVED">Ativo</span>` : htmlT`<span class="inc-status inc-status-CLOSED">Inativo</span>`}</td>
      <td>
        <button class="btn-sm" data-action="edit" data-id="${a.id}">Editar</button>
        ${a.active ? htmlT`<button class="btn-sm btn-danger" data-action="deactivate" data-id="${a.id}">Desativar</button>` : ""}
      </td>
    </tr>
  `)}`);
}

function updateShiftAnalystSelect(analysts) {
  const select = document.getElementById("shift-analyst");
  const current = select.value;
  const tierLabels = { 1: "Tier 1", 2: "Tier 2", 3: "Tier 3" };
  htmRender(select, htmlT`<option value="">Selecione...</option>${analysts.filter(a => a.active).map(a =>
    htmlT`<option value="${a.id}">${a.name} (${a.tier ? String(tierLabels[a.tier] || a.tier) : "—"})</option>`)}`);
  if (analysts.some(a => a.id === current)) select.value = current;
}

// Delegação de eventos: o nome do analista nunca passa pelo DOM como código.
function stOnAnalystsClick(event) {
  const btn = event.target.closest("button[data-action]");
  if (!btn) return;
  const analyst = stAnalystsCache.find((a) => a.id === btn.dataset.id);
  if (!analyst) return;
  if (btn.dataset.action === "edit") openAnalystModal("edit", analyst.id);
  else if (btn.dataset.action === "deactivate") deactivateAnalyst(analyst.id, analyst.name);
}

document.getElementById("analyst-tier-filter").addEventListener("change", loadAnalysts);
document.getElementById("analyst-active-filter").addEventListener("change", loadAnalysts);

document.getElementById("analyst-create-btn").addEventListener("click", () => openAnalystModal("create"));

document.getElementById("analyst-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const id = document.getElementById("analyst-modal-id").value;
  const analystId = document.getElementById("analyst-id").value.trim();
  const name = document.getElementById("analyst-name").value.trim();
  const tier = parseInt(document.getElementById("analyst-tier").value, 10);
  const email = document.getElementById("analyst-email").value.trim() || null;
  const active = document.getElementById("analyst-active").value;

  const modal = document.getElementById("analyst-modal");
  const btn = modal.querySelector('button[type="submit"]');
  btn.disabled = true;
  btn.textContent = "A guardar...";

  try {
    if (id) {
      await apiRequest(`/api/soc/analysts/${encodeURIComponent(id)}`, { method: "PATCH", body: { tier, email, active: parseInt(active, 10) } });
      stText("analyst-notice", `✅ Analista ${name} atualizado`);
    } else {
      await apiRequest("/api/soc/analysts", { method: "POST", body: { id: analystId, name, tier, email } });
      stText("analyst-notice", `✅ Analista ${name} criado`);
    }
    closeAnalystModal();
    await loadAnalysts();
  } catch (err) {
    stText("analyst-notice", `❌ ${apiErrorMessage(err)}`);
  } finally {
    btn.disabled = false;
    btn.textContent = "Guardar";
  }
});

document.getElementById("analyst-cancel-btn").addEventListener("click", closeAnalystModal);

function openAnalystModal(mode, analystId = null) {
  const form = document.getElementById("analyst-form");
  form.reset();
  document.getElementById("analyst-modal-id").value = "";
  document.getElementById("analyst-active-row").hidden = true;
  document.getElementById("analyst-id").disabled = false;
  document.getElementById("analyst-name").disabled = false;

  if (mode === "edit" && analystId) {
    const analyst = stAnalystsCache.find(a => a.id === analystId);
    if (!analyst) return;
    document.getElementById("analyst-modal-title").textContent = `Editar Analista: ${analyst.name}`;
    document.getElementById("analyst-modal-id").value = analyst.id;
    document.getElementById("analyst-id").value = analyst.id;
    document.getElementById("analyst-id").disabled = true;
    document.getElementById("analyst-name").value = analyst.name;
    // O PATCH (AnalystUpdate) não aceita nome: bloquear evita uma alteração perdida em silêncio.
    document.getElementById("analyst-name").disabled = true;
    document.getElementById("analyst-tier").value = analyst.tier;
    document.getElementById("analyst-email").value = analyst.email || "";
    document.getElementById("analyst-active").value = analyst.active ? "1" : "0";
    document.getElementById("analyst-active-row").hidden = false;
  } else {
    document.getElementById("analyst-modal-title").textContent = "Novo Analista";
    document.getElementById("analyst-active-row").hidden = true;
  }
  stOpenModal("analyst-modal", mode === "edit" ? "analyst-tier" : "analyst-id");
}

function closeAnalystModal() {
  stCloseModal("analyst-modal");
}

async function deactivateAnalyst(id, name) {
  if (!confirm(`Desativar analista ${name}?`)) return;
  try {
    await apiRequest(`/api/soc/analysts/${encodeURIComponent(id)}/deactivate`, { method: "POST" });
    stText("analyst-notice", `✅ Analista ${name} desativado`);
    await loadAnalysts();
  } catch (err) {
    stText("analyst-notice", `❌ ${apiErrorMessage(err)}`);
  }
}

// ====== Shifts ======

async function loadShifts() {
  stText("shift-notice", "A carregar turnos...");
  stShowState(document.getElementById("shifts-body"), "loading", "A carregar turnos…", 5);
  try {
    const analystId = document.getElementById("shift-analyst-filter").value;
    const params = new URLSearchParams();
    if (analystId) params.set("analyst_id", analystId);
    const data = await apiRequest(`/api/soc/shifts?${params}`);
    renderShiftsTable(data.shifts || []);
    stText("shift-notice", `${(data.shifts || []).length} turno(s)`);
  } catch (err) {
    stLoadFailed(err, "shift-notice", "#shifts-section", "Falha ao carregar turnos", document.getElementById("shifts-body"), 5);
  }
}

function renderShiftsTable(shifts) {
  const body = document.getElementById("shifts-body");
  if (!shifts.length) {
    stShowState(body, "empty", "Sem turnos.", 5);
    return;
  }
  body.dataset.stReady = "1";
  htmRender(body, htmlT`${shifts.map((s) => htmlT`
    <tr data-id="${String(s.id)}">
      <td>${stCell(s.analyst_name || s.analyst_id)}</td>
      <td>${tierBadge(s.analyst_tier)}</td>
      <td>${formatDateTimeLocal(s.start_ts)}</td>
      <td>${formatDateTimeLocal(s.end_ts)}</td>
      <td>${roleBadge(s.role)}</td>
    </tr>
  `)}`);
}

document.getElementById("shift-analyst-filter").addEventListener("change", loadShifts);

document.getElementById("shift-create-btn").addEventListener("click", () => openShiftModal("create"));

document.getElementById("shift-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const analyst_id = document.getElementById("shift-analyst").value;
  const start_ts = document.getElementById("shift-start").value;
  const end_ts = document.getElementById("shift-end").value;
  const role = document.getElementById("shift-role").value;

  const btn = document.querySelector("#shift-modal button[type=\"submit\"]");
  btn.disabled = true;
  btn.textContent = "A guardar...";

  try {
    await apiRequest("/api/soc/shifts", { method: "POST", body: { analyst_id, start_ts, end_ts, role } });
    stText("shift-notice", "✅ Turno criado");
    closeShiftModal();
    await loadShifts();
  } catch (err) {
    stText("shift-notice", `❌ ${apiErrorMessage(err)}`);
  } finally {
    btn.disabled = false;
    btn.textContent = "Guardar";
  }
});

document.getElementById("shift-cancel-btn").addEventListener("click", closeShiftModal);

function openShiftModal(mode) {
  const form = document.getElementById("shift-form");
  form.reset();
  document.getElementById("shift-analyst").value = "";

  document.getElementById("shift-modal-title").textContent = "Novo Turno";
  stOpenModal("shift-modal", "shift-analyst");
}

function closeShiftModal() {
  stCloseModal("shift-modal");
}

// ====== Escalation Rules ======

async function loadEscalationRules() {
  stText("escalation-notice", "A carregar regras...");
  stShowState(document.getElementById("escalation-body"), "loading", "A carregar regras…", 5);
  try {
    const data = await apiRequest("/api/soc/escalation-rules");
    renderEscalationTable(data.rules || []);
    stText("escalation-notice", `${(data.rules || []).length} regra(s)`);
  } catch (err) {
    stLoadFailed(err, "escalation-notice", "#escalation-section", "Falha ao carregar regras", document.getElementById("escalation-body"), 5);
  }
}

function renderEscalationTable(rules) {
  const body = document.getElementById("escalation-body");
  if (!rules.length) {
    stShowState(body, "empty", "Sem regras de escalamento.", 5);
    return;
  }
  body.dataset.stReady = "1";
  htmRender(body, htmlT`${rules.map((r) => htmlT`
    <tr data-id="${String(r.id)}">
      <td>${tierBadge(r.from_tier)}</td>
      <td>${r.to_tier ? tierBadge(r.to_tier) : htmlT`<span class="inc-status inc-status-CLOSED">Final</span>`}</td>
      <td>${htmlRaw(severityBadge(r.severity))}</td>
      <td>${r.auto_escalate ? htmlT`<span class="inc-status inc-status-RESOLVED">Sim</span>` : htmlT`<span class="inc-status inc-status-NEW">Não</span>`}</td>
      <td>${stCell(r.sla_minutes)}</td>
    </tr>
  `)}`);
}

document.getElementById("escalation-create-btn").addEventListener("click", () => openEscalationModal("create"));

document.getElementById("escalation-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const from_tier = parseInt(document.getElementById("escalation-from-tier").value, 10);
  const to_tier = document.getElementById("escalation-to-tier").value;
  const severity = document.getElementById("escalation-severity").value;
  const auto_escalate = parseInt(document.getElementById("escalation-auto").value, 10);
  const sla_minutes = document.getElementById("escalation-sla").value;
  const sla = sla_minutes ? parseInt(sla_minutes, 10) : null;

  const btn = document.querySelector("#escalation-modal button[type=\"submit\"]");
  btn.disabled = true;
  btn.textContent = "A guardar...";

  try {
    await apiRequest("/api/soc/escalation-rules", { method: "POST", body: { from_tier, to_tier: to_tier ? parseInt(to_tier, 10) : null, severity, auto_escalate, sla_minutes: sla } });
    stText("escalation-notice", "✅ Regra criada");
    closeEscalationModal();
    await loadEscalationRules();
  } catch (err) {
    stText("escalation-notice", `❌ ${apiErrorMessage(err)}`);
  } finally {
    btn.disabled = false;
    btn.textContent = "Guardar";
  }
});

document.getElementById("escalation-cancel-btn").addEventListener("click", closeEscalationModal);

function openEscalationModal(mode) {
  const form = document.getElementById("escalation-form");
  form.reset();

  document.getElementById("escalation-modal-title").textContent = "Nova Regra de Escalamento";
  stOpenModal("escalation-modal", "escalation-from-tier");
}

function closeEscalationModal() {
  stCloseModal("escalation-modal");
}

// ====== On-Call / Primary ======

async function loadOnCall() {
  stText("oncall-notice", "A carregar...");
  stShowState(document.getElementById("oncall-list"), "loading", "A carregar…");
  stShowState(document.getElementById("primary-list"), "loading", "A carregar…");
  try {
    const tier = parseInt(document.getElementById("oncall-tier-filter").value, 10);
    const [oncallData, primaryData] = await Promise.all([
      apiRequest(`/api/soc/on-call?tier=${tier}`),
      apiRequest(`/api/soc/primary?tier=${tier}`),
    ]);
    renderOnCallList(oncallData.on_call || [], "oncall-list");
    renderOnCallList(primaryData.primary || [], "primary-list");
    stText("oncall-notice", `Tier ${tier} — ${(oncallData.on_call || []).length} on-call, ${(primaryData.primary || []).length} principal`);
  } catch (err) {
    stLoadFailed(err, "oncall-notice", null, "", null);
    stShowState(document.getElementById("oncall-list"), "error", err);
    stShowState(document.getElementById("primary-list"), "error", err);
  }
}

function renderOnCallList(analysts, listId) {
  const list = document.getElementById(listId);
  if (!analysts.length) {
    stShowState(list, "empty", "Nenhum");
    return;
  }
  list.dataset.stReady = "1";
  htmRender(list, htmlT`${analysts.map(a => htmlT`<li>${a.name} (${a.id})${a.email ? ` — ${a.email}` : ""}</li>`)}`);
}

document.getElementById("oncall-tier-filter").addEventListener("change", loadOnCall);
document.getElementById("oncall-refresh-btn").addEventListener("click", loadOnCall);

// ====== SLA Breaches ======

async function loadSLABreaches() {
  stText("sla-breaches-notice", "A carregar...");
  stShowState(document.getElementById("sla-breaches-body"), "loading", "A carregar…", 7);
  try {
    const data = await apiRequest("/api/soc/sla-breaches");
    renderSLABreaches(data.breaches || []);
    stText("sla-breaches-notice", `${(data.breaches || []).length} breach(es)`);
  } catch (err) {
    stLoadFailed(err, "sla-breaches-notice", null, "", document.getElementById("sla-breaches-body"), 7);
  }
}

function renderSLABreaches(breaches) {
  const body = document.getElementById("sla-breaches-body");
  if (!breaches.length) {
    stShowState(body, "empty", "Nenhum SLA breach.", 7);
    return;
  }
  const now = new Date();
  body.dataset.stReady = "1";
  htmRender(body, htmlT`${breaches.map((b) => {
    const deadline = new Date(b.sla_deadline.replace(/([+-]\d{2})(\d{2})$/, "$1:$2"));
    const overdue = now > deadline;
    return htmlT`
      <tr>
        <td>${b.id}</td>
        <td>${htmlRaw(severityBadge(b.severity))}</td>
        <td>${stCell(b.asset)}</td>
        <td>${tierBadge(b.assigned_team_tier)}</td>
        <td>${stCell(b.assigned_to)}</td>
        <td>${formatDateTimeLocal(b.sla_deadline)} ${overdue ? htmlT`<span class="sla-overdue">⚠️ ULTRAPASSADO</span>` : ""}</td>
        <td>${b.status}</td>
      </tr>
    `;
  })}`);
}

// ====== Summary by Tier ======

async function loadTierSummary() {
  stText("tier-summary-notice", "A carregar...");
  stShowState(document.getElementById("tier-summary-body"), "loading", "A carregar…", 5);
  try {
    const days = parseInt(periodSelect.value, 10);
    const hours = slTierWindowHours(days);
    const clamped = Number.isFinite(days) && days > 0 && days * 24 > hours;
    const data = await apiRequest(`/api/soc/summary-by-tier?hours=${hours}`);
    renderTierSummary(data.by_tier || {});
    stText("tier-summary-notice", clamped ? `Janela de ${hours} h (máximo desta fonte)` : `Janela de ${hours} h`);
  } catch (err) {
    stLoadFailed(err, "tier-summary-notice", null, "", document.getElementById("tier-summary-body"), 5);
  }
}

function renderTierSummary(byTier) {
  const body = document.getElementById("tier-summary-body");
  const tiers = [1, 2, 3, 0].filter(t => byTier[t] !== undefined); // 0 = sem tier
  if (!tiers.length) {
    stShowState(body, "empty", "Sem dados", 5);
    return;
  }
  body.dataset.stReady = "1";
  htmRender(body, htmlT`${tiers.map(t => {
    const d = byTier[t];
    const statusStr = Object.entries(d.by_status || {}).map(([s, c]) => `${s}: ${c}`).join(", ") || "—";
    const sevStr = Object.entries(d.by_severity || {}).map(([s, c]) => `${s}: ${c}`).join(", ") || "—";
    const tierLabel = t === 0 ? "Sem tier" : `Tier ${t}`;
    return htmlT`<tr>
      <td>${tierLabel}</td>
      <td>${d.total}</td>
      <td>${d.open}</td>
      <td>${statusStr}</td>
      <td>${sevStr}</td>
    </tr>`;
  })}`);
}

// ====== Modais ======

const ST_MODAL_IDS = ["analyst-modal", "shift-modal", "escalation-modal"];
let stModalOpener = null;

function stOpenModal(modalId, focusId) {
  stModalOpener = document.activeElement;
  document.getElementById(modalId).hidden = false;
  const target = document.getElementById(focusId);
  if (target) target.focus();
}

function stCloseModal(modalId) {
  document.getElementById(modalId).hidden = true;
  if (stModalOpener && typeof stModalOpener.focus === "function" && document.contains(stModalOpener)) {
    stModalOpener.focus();
  }
  stModalOpener = null;
}

// ====== Main ======

function stInit() {
  ST_MODAL_IDS.forEach(id => {
    const modal = document.getElementById(id);
    modal.addEventListener("click", ev => { if (ev.target === modal) stCloseModal(id); });
  });
  document.addEventListener("keydown", ev => {
    if (ev.key !== "Escape") return;
    const open = ST_MODAL_IDS.find(id => !document.getElementById(id).hidden);
    if (open) stCloseModal(open);
  });
  document.getElementById("analysts-body").addEventListener("click", stOnAnalystsClick);
  loadAnalysts();
  loadShifts();
  loadEscalationRules();
  loadOnCall();
  loadSLABreaches();
  loadTierSummary();

  // Auto-refresh
  setInterval(() => {
    if (document.getElementById("tab-soc-team").classList.contains("active")) {
      loadOnCall();
      loadSLABreaches();
    }
  }, 60000);

  // Tab visibility change
  const observer = new MutationObserver(() => {
    const tab = document.getElementById("tab-soc-team");
    if (tab && tab.classList.contains("active")) {
      loadOnCall();
      loadSLABreaches();
    }
  });
  observer.observe(document.getElementById("tab-soc-team"), { attributes: true, attributeFilter: ["class"] });
}

// Initialize when DOM ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", stInit);
} else {
  stInit();
}
