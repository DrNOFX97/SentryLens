// Aba "Equipa SOC" (Tier 1/2/3). Carregado depois de app.js e incidents.js:
// reutiliza os seus globais (API_BASE, API_KEY, escapeHtml, severityBadge,
// formatTimestamp, renderPanelError, periodSelect) — não redeclarar nenhum aqui.
// Só mostra dados reais de /api/soc/*; sem dados, estado vazio.

function stText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function stCell(value) {
  if (value === null || value === undefined || value === "") return "—";
  return escapeHtml(String(value));
}

function tierBadge(tier) {
  if (!tier) return '<span class="inc-status inc-status-NEW">—</span>';
  const labels = { 1: "Tier 1", 2: "Tier 2", 3: "Tier 3" };
  const cls = { 1: "inc-status-NEW", 2: "inc-status-INVESTIGATING", 3: "inc-status-CONTAINED" };
  return `<span class="inc-status ${cls[tier]}">${labels[tier] || tier}</span>`;
}

function roleBadge(role) {
  const labels = { primary: "Principal", secondary: "Secundário", on_call: "De prevenção" };
  const cls = { primary: "inc-status-CONTAINED", secondary: "inc-status-INVESTIGATING", on_call: "inc-status-NEW" };
  return `<span class="inc-status ${cls[role]}">${labels[role] || role}</span>`;
}

function formatDateTimeLocal(ts) {
  if (!ts) return "—";
  const d = new Date(ts.replace(/([+-]\d{2})(\d{2})$/, "$1:$2"));
  if (isNaN(d.getTime())) return escapeHtml(ts);
  return d.toLocaleString("pt-PT");
}

function formatTimeOnly(ts) {
  if (!ts) return "—";
  const d = new Date(ts.replace(/([+-]\d{2})(\d{2})$/, "$1:$2"));
  if (isNaN(d.getTime())) return escapeHtml(ts);
  return d.toLocaleTimeString("pt-PT", { hour: "2-digit", minute: "2-digit" });
}

async function stRequest(method, path, body) {
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
    } catch (_) { }
    const error = new Error(detail);
    error.status = response.status;
    throw error;
  }
  return response.json();
}

// ====== Analysts ======

let stAnalystsCache = [];

async function loadAnalysts() {
  stText("analyst-notice", "A carregar analistas...");
  try {
    const tier = document.getElementById("analyst-tier-filter").value;
    const active = document.getElementById("analyst-active-filter").value;
    const params = new URLSearchParams();
    if (tier) params.set("tier", tier);
    params.set("active_only", active === "" ? "true" : active);
    const data = await stRequest("GET", `/api/soc/analysts?${params}`);
    stAnalystsCache = data.analysts || [];
    renderAnalystsTable(stAnalystsCache);
    updateShiftAnalystSelect(stAnalystsCache);
    stText("analyst-notice", `${stAnalystsCache.length} analista(s)`);
  } catch (err) {
    renderPanelError("#analysts-section", `Falha ao carregar analistas: ${err.message}`);
    stText("analyst-notice", `⚠️ ${err.message}`);
  }
}

function renderAnalystsTable(analysts) {
  const body = document.getElementById("analysts-body");
  if (!analysts.length) {
    body.innerHTML = '<tr><td colspan="6" class="empty-state">Sem analistas.</td></tr>';
    return;
  }
  body.innerHTML = analysts.map((a) => `
    <tr data-id="${escapeHtml(a.id)}">
      <td>${escapeHtml(a.id)}</td>
      <td>${escapeHtml(a.name)}</td>
      <td>${tierBadge(a.tier)}</td>
      <td>${stCell(a.email)}</td>
      <td>${a.active ? '<span class="inc-status inc-status-RESOLVED">Ativo</span>' : '<span class="inc-status inc-status-CLOSED">Inativo</span>'}</td>
      <td>
        <button class="btn-sm" data-action="edit" data-id="${escapeHtml(a.id)}">Editar</button>
        ${a.active ? `<button class="btn-sm btn-danger" data-action="deactivate" data-id="${escapeHtml(a.id)}">Desativar</button>` : ""}
      </td>
    </tr>
  `).join("");
}

function updateShiftAnalystSelect(analysts) {
  const select = document.getElementById("shift-analyst");
  const current = select.value;
  select.innerHTML = '<option value="">Selecione...</option>' +
    analysts.filter(a => a.active).map(a => `<option value="${escapeHtml(a.id)}">${escapeHtml(a.name)} (${tierBadge(a.tier).replace(/<[^>]+>/g, '')})</option>`).join("");
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
      await stRequest("PATCH", `/api/soc/analysts/${encodeURIComponent(id)}`, { tier, email, active: parseInt(active, 10) });
      stText("analyst-notice", `✅ Analista ${name} atualizado`);
    } else {
      await stRequest("POST", "/api/soc/analysts", { id: analystId, name, tier, email });
      stText("analyst-notice", `✅ Analista ${name} criado`);
    }
    closeAnalystModal();
    await loadAnalysts();
  } catch (err) {
    stText("analyst-notice", `❌ ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = "Guardar";
  }
});

document.getElementById("analyst-cancel-btn").addEventListener("click", closeAnalystModal);

function openAnalystModal(mode, analystId = null) {
  const modal = document.getElementById("analyst-modal");
  const form = document.getElementById("analyst-form");
  form.reset();
  document.getElementById("analyst-modal-id").value = "";
  document.getElementById("analyst-active-row").hidden = true;
  document.getElementById("analyst-id").disabled = false;

  if (mode === "edit" && analystId) {
    const analyst = stAnalystsCache.find(a => a.id === analystId);
    if (!analyst) return;
    document.getElementById("analyst-modal-title").textContent = `Editar Analista: ${analyst.name}`;
    document.getElementById("analyst-modal-id").value = analyst.id;
    document.getElementById("analyst-id").value = analyst.id;
    document.getElementById("analyst-id").disabled = true;
    document.getElementById("analyst-name").value = analyst.name;
    document.getElementById("analyst-tier").value = analyst.tier;
    document.getElementById("analyst-email").value = analyst.email || "";
    document.getElementById("analyst-active").value = analyst.active ? "1" : "0";
    document.getElementById("analyst-active-row").hidden = false;
  } else {
    document.getElementById("analyst-modal-title").textContent = "Novo Analista";
    document.getElementById("analyst-active-row").hidden = true;
  }
  modal.hidden = false;
}

function closeAnalystModal() {
  document.getElementById("analyst-modal").hidden = true;
}

async function deactivateAnalyst(id, name) {
  if (!confirm(`Desativar analista ${name}?`)) return;
  try {
    await stRequest("POST", `/api/soc/analysts/${encodeURIComponent(id)}/deactivate`);
    stText("analyst-notice", `✅ Analista ${name} desativado`);
    await loadAnalysts();
  } catch (err) {
    stText("analyst-notice", `❌ ${err.message}`);
  }
}

// ====== Shifts ======

async function loadShifts() {
  stText("shift-notice", "A carregar turnos...");
  try {
    const analystId = document.getElementById("shift-analyst-filter").value;
    const params = new URLSearchParams();
    if (analystId) params.set("analyst_id", analystId);
    const data = await stRequest("GET", `/api/soc/shifts?${params}`);
    renderShiftsTable(data.shifts || []);
    stText("shift-notice", `${(data.shifts || []).length} turno(s)`);
  } catch (err) {
    renderPanelError("#shifts-section", `Falha ao carregar turnos: ${err.message}`);
    stText("shift-notice", `⚠️ ${err.message}`);
  }
}

function renderShiftsTable(shifts) {
  const body = document.getElementById("shifts-body");
  if (!shifts.length) {
    body.innerHTML = '<tr><td colspan="5" class="empty-state">Sem turnos.</td></tr>';
    return;
  }
  body.innerHTML = shifts.map((s) => `
    <tr data-id="${escapeHtml(String(s.id))}">
      <td>${stCell(s.analyst_name || s.analyst_id)}</td>
      <td>${tierBadge(s.analyst_tier)}</td>
      <td>${formatDateTimeLocal(s.start_ts)}</td>
      <td>${formatDateTimeLocal(s.end_ts)}</td>
      <td>${roleBadge(s.role)}</td>
    </tr>
  `).join("");
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
    await stRequest("POST", "/api/soc/shifts", { analyst_id, start_ts, end_ts, role });
    stText("shift-notice", "✅ Turno criado");
    closeShiftModal();
    await loadShifts();
  } catch (err) {
    stText("shift-notice", `❌ ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = "Guardar";
  }
});

document.getElementById("shift-cancel-btn").addEventListener("click", closeShiftModal);

function openShiftModal(mode) {
  const modal = document.getElementById("shift-modal");
  const form = document.getElementById("shift-form");
  form.reset();
  document.getElementById("shift-analyst").value = "";

  document.getElementById("shift-modal-title").textContent = "Novo Turno";
  modal.hidden = false;
}

function closeShiftModal() {
  document.getElementById("shift-modal").hidden = true;
}

// ====== Escalation Rules ======

async function loadEscalationRules() {
  stText("escalation-notice", "A carregar regras...");
  try {
    const data = await stRequest("GET", "/api/soc/escalation-rules");
    renderEscalationTable(data.rules || []);
    stText("escalation-notice", `${(data.rules || []).length} regra(s)`);
  } catch (err) {
    renderPanelError("#escalation-section", `Falha ao carregar regras: ${err.message}`);
    stText("escalation-notice", `⚠️ ${err.message}`);
  }
}

function renderEscalationTable(rules) {
  const body = document.getElementById("escalation-body");
  if (!rules.length) {
    body.innerHTML = '<tr><td colspan="5" class="empty-state">Sem regras de escalamento.</td></tr>';
    return;
  }
  body.innerHTML = rules.map((r) => `
    <tr data-id="${escapeHtml(String(r.id))}">
      <td>${tierBadge(r.from_tier)}</td>
      <td>${r.to_tier ? tierBadge(r.to_tier) : '<span class="inc-status inc-status-CLOSED">Final</span>'}</td>
      <td>${severityBadge(r.severity)}</td>
      <td>${r.auto_escalate ? '<span class="inc-status inc-status-RESOLVED">Sim</span>' : '<span class="inc-status inc-status-NEW">Não</span>'}</td>
      <td>${stCell(r.sla_minutes)}</td>
    </tr>
  `).join("");
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
    await stRequest("POST", "/api/soc/escalation-rules", { from_tier, to_tier: to_tier ? parseInt(to_tier, 10) : null, severity, auto_escalate, sla_minutes: sla });
    stText("escalation-notice", "✅ Regra criada");
    closeEscalationModal();
    await loadEscalationRules();
  } catch (err) {
    stText("escalation-notice", `❌ ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = "Guardar";
  }
});

document.getElementById("escalation-cancel-btn").addEventListener("click", closeEscalationModal);

function openEscalationModal(mode) {
  const modal = document.getElementById("escalation-modal");
  const form = document.getElementById("escalation-form");
  form.reset();

  document.getElementById("escalation-modal-title").textContent = "Nova Regra de Escalamento";
  modal.hidden = false;
}

function closeEscalationModal() {
  document.getElementById("escalation-modal").hidden = true;
}

// ====== On-Call / Primary ======

async function loadOnCall() {
  stText("oncall-notice", "A carregar...");
  try {
    const tier = parseInt(document.getElementById("oncall-tier-filter").value, 10);
    const [oncallData, primaryData] = await Promise.all([
      stRequest("GET", `/api/soc/on-call?tier=${tier}`),
      stRequest("GET", `/api/soc/primary?tier=${tier}`),
    ]);
    renderOnCallList(oncallData.on_call || [], "oncall-list");
    renderOnCallList(primaryData.primary || [], "primary-list");
    stText("oncall-notice", `Tier ${tier} — ${oncallData.on_call?.length || 0} on-call, ${primaryData.primary?.length || 0} principal`);
  } catch (err) {
    stText("oncall-notice", `⚠️ ${err.message}`);
  }
}

function renderOnCallList(analysts, listId) {
  const list = document.getElementById(listId);
  if (!analysts.length) {
    list.innerHTML = '<li class="empty-state">Nenhum</li>';
    return;
  }
  list.innerHTML = analysts.map(a => `<li>${escapeHtml(a.name)} (${escapeHtml(a.id)})${a.email ? ` — ${escapeHtml(a.email)}` : ""}</li>`).join("");
}

document.getElementById("oncall-tier-filter").addEventListener("change", loadOnCall);
document.getElementById("oncall-refresh-btn").addEventListener("click", loadOnCall);

// ====== SLA Breaches ======

async function loadSLABreaches() {
  stText("sla-breaches-notice", "A carregar...");
  try {
    const data = await stRequest("GET", "/api/soc/sla-breaches");
    renderSLABreaches(data.breaches || []);
    stText("sla-breaches-notice", `${data.count || 0} breach(es)`);
  } catch (err) {
    stText("sla-breaches-notice", `⚠️ ${err.message}`);
  }
}

function renderSLABreaches(breaches) {
  const body = document.getElementById("sla-breaches-body");
  if (!breaches.length) {
    body.innerHTML = '<tr><td colspan="7" class="empty-state">Nenhum SLA breach.</td></tr>';
    return;
  }
  const now = new Date();
  body.innerHTML = breaches.map((b) => {
    const deadline = new Date(b.sla_deadline.replace(/([+-]\d{2})(\d{2})$/, "$1:$2"));
    const overdue = now > deadline;
    return `
      <tr>
        <td>${escapeHtml(b.id)}</td>
        <td>${severityBadge(b.severity)}</td>
        <td>${stCell(b.asset)}</td>
        <td>${tierBadge(b.assigned_team_tier)}</td>
        <td>${stCell(b.assigned_to)}</td>
        <td>${formatDateTimeLocal(b.sla_deadline)} ${overdue ? '<span style="color:#e74c3c">⚠️ ULTRAPASSADO</span>' : ""}</td>
        <td>${b.status}</td>
      </tr>
    `;
  }).join("");
}

// ====== Summary by Tier ======

async function loadTierSummary() {
  stText("tier-summary-notice", "A carregar...");
  try {
    const hours = parseInt(periodSelect.value, 10) * 24;
    const data = await stRequest("GET", `/api/soc/summary-by-tier?hours=${hours}`);
    renderTierSummary(data.by_tier || {});
    stText("tier-summary-notice", `Janela de ${hours}h`);
  } catch (err) {
    stText("tier-summary-notice", `⚠️ ${err.message}`);
  }
}

function renderTierSummary(byTier) {
  const body = document.getElementById("tier-summary-body");
  const tiers = [1, 2, 3, 0].filter(t => byTier[t] !== undefined); // 0 = sem tier
  if (!tiers.length) {
    body.innerHTML = '<tr><td colspan="5" class="empty-state">Sem dados.</td></tr>';
    return;
  }
  body.innerHTML = tiers.map(t => {
    const d = byTier[t];
    const statusStr = Object.entries(d.by_status || {}).map(([s, c]) => `${s}: ${c}`).join(", ") || "—";
    const sevStr = Object.entries(d.by_severity || {}).map(([s, c]) => `${s}: ${c}`).join(", ") || "—";
    const tierLabel = t === 0 ? "Sem tier" : `Tier ${t}`;
    return `<tr>
      <td>${tierLabel}</td>
      <td>${d.total}</td>
      <td>${d.open}</td>
      <td>${statusStr}</td>
      <td>${sevStr}</td>
    </tr>`;
  }).join("");
}

// ====== Main ======

function stInit() {
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
