// Aba "Attack Library" (Roadmap v2, R5). Carregado depois de app.js e
// attack_registry.js: reutiliza os seus globais (API_BASE, API_KEY,
// escapeHtml, renderPanelError) — não redeclarar nenhum aqui. Um só pedido
// a GET /api/attack-library (catálogo estático, não depende do período
// selecionado); refiltra em memória quando os filtros mudam. Só mostra
// dados reais; sem dados -> "Sem dados". Não abre WebSocket, não pede nada
// com a aba escondida. Todo o texto dinâmico passa por escapeHtml (o YAML é
// controlado pelo projeto, mas a regra do projeto é sempre escapar).

const ALIB_RISK_LABELS = { low: "Baixo", medium: "Médio", high: "Alto" };
const ALIB_SENSOR_LABELS = { rule: "Regra", ml: "ML", network: "Rede" };

const alibTab = document.getElementById("tab-attack-library");
let alibEntries = [];
let alibLoaded = false;
let alibLoading = false;
let alibSelectedId = null;

function alibIsActive() {
  return alibTab.classList.contains("active") && document.visibilityState === "visible";
}

function alibCell(value) {
  if (value === null || value === undefined || value === "") return "—";
  return escapeHtml(String(value));
}

function alibSensors(list) {
  return list && list.length ? list.map((s) => ALIB_SENSOR_LABELS[s] || s).join(", ") : "—";
}

function alibRiskBadge(risk) {
  const label = ALIB_RISK_LABELS[risk] || risk;
  return `<span class="alib-risk alib-risk-${escapeHtml(risk)}">${escapeHtml(label)}</span>`;
}

function alibReplayableBadge(replayable) {
  return `<span class="alib-replayable alib-replayable-${replayable ? "yes" : "no"}">${replayable ? "Sim" : "Não"}</span>`;
}

async function alibRequest(path) {
  const response = await fetch(`${API_BASE}${path}`, { headers: { "X-API-Key": API_KEY } });
  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    try {
      const data = await response.json();
      if (data && typeof data.detail === "string") detail = data.detail;
    } catch (_) { /* corpo não-JSON: fica o código HTTP */ }
    throw new Error(detail);
  }
  return response.json();
}

function alibFilteredEntries() {
  const risk = document.getElementById("alib-risk-filter").value;
  const sensor = document.getElementById("alib-sensor-filter").value;
  return alibEntries.filter((e) =>
    (!risk || e.risk === risk) && (!sensor || (e.expected_sensors || []).includes(sensor)));
}

function renderAttackLibraryTable(entries) {
  const body = document.getElementById("alib-body");
  if (!entries.length) {
    body.innerHTML = `<tr><td colspan="8" class="empty-state">Sem dados — nenhum cenário corresponde aos filtros.</td></tr>`;
    return;
  }
  body.innerHTML = entries.map((e) => `<tr class="atk-row${e.id === alibSelectedId ? " selected" : ""}" data-id="${escapeHtml(e.id)}" tabindex="0">
    <td>${alibCell(e.id)}</td>
    <td>${alibCell(e.name)}</td>
    <td>${alibCell(e.mitre_technique)}</td>
    <td>${alibCell(e.tool)}</td>
    <td>${alibRiskBadge(e.risk)}</td>
    <td>${escapeHtml(alibSensors(e.expected_sensors))}</td>
    <td>${alibReplayableBadge(e.replayable)}</td>
    <td>${alibCell(e.duration_estimate)}</td>
  </tr>`).join("");
}

function renderAttackLibraryDetail(entry) {
  const panel = document.getElementById("attack-library-detail-panel");
  panel.hidden = false;
  document.getElementById("alib-detail-title").textContent = entry.name || entry.id;
  document.getElementById("alib-detail-meta").innerHTML = `
    <span>${alibRiskBadge(entry.risk)}</span>
    <span>Cenário: <strong>${alibCell(entry.id)}</strong></span>
    <span>MITRE: ${alibCell(entry.mitre_technique)} (${alibCell(entry.mitre_tactic)})</span>
    <span>Ferramenta: ${alibCell(entry.tool)}</span>
    <span>Event IDs: ${alibCell((entry.event_ids || []).join(", "))}</span>
    <span>Duração estimada: ${alibCell(entry.duration_estimate)}</span>`;
  document.getElementById("alib-detail-prereqs").textContent = entry.prerequisites || "—";
  const steps = entry.cleanup_steps || [];
  document.getElementById("alib-detail-cleanup").innerHTML = steps.length
    ? steps.map((s) => `<li>${escapeHtml(s)}</li>`).join("")
    : `<li class="empty-state">Sem passos de limpeza registados.</li>`;
  document.getElementById("alib-detail-replayable").innerHTML =
    `${alibReplayableBadge(entry.replayable)} — ${escapeHtml(entry.replayable_reason || "sem motivo registado")}`;
}

function alibShowDetailError(message) {
  renderPanelError("#attack-library-detail-panel", message);
}

let alibSelectSeq = 0;
async function selectAttackLibraryEntry(id) {
  const seq = ++alibSelectSeq;
  alibSelectedId = id;
  document.querySelectorAll("#alib-body tr[data-id]").forEach((tr) =>
    tr.classList.toggle("selected", tr.dataset.id === id));
  try {
    const entry = await alibRequest(`/api/attack-library/${encodeURIComponent(id)}`);
    if (seq !== alibSelectSeq) return;
    alibShowDetailError("");
    renderAttackLibraryDetail(entry);
  } catch (err) {
    if (seq !== alibSelectSeq) return;
    alibShowDetailError(`Não foi possível carregar o detalhe: ${err.message}`);
  }
}

function alibApplyFilters() {
  renderAttackLibraryTable(alibFilteredEntries());
}

async function refreshAttackLibrary() {
  if (alibLoading) return;
  alibLoading = true;
  try {
    const data = await alibRequest("/api/attack-library");
    renderPanelError("#attack-library-panel", "");
    alibEntries = data.entries || [];
    document.getElementById("alib-notice").textContent =
      alibEntries.length ? `${data.total} cenário(s) no catálogo.` : "";
    alibApplyFilters();
  } catch (err) {
    const message = `Não foi possível carregar a Attack Library: ${err.message}`;
    renderPanelError("#attack-library-panel", message);
    document.getElementById("alib-body").innerHTML =
      `<tr><td colspan="8" class="empty-state">Sem dados — ${escapeHtml(err.message)}.</td></tr>`;
  } finally {
    alibLoading = false;
  }
}

document.getElementById("alib-body").addEventListener("click", (event) => {
  const tr = event.target.closest("tr[data-id]");
  if (tr) selectAttackLibraryEntry(tr.dataset.id);
});
document.getElementById("alib-body").addEventListener("keydown", (event) => {
  const tr = event.target.closest("tr[data-id]");
  if (tr && (event.key === "Enter" || event.key === " ")) {
    event.preventDefault();
    selectAttackLibraryEntry(tr.dataset.id);
  }
});
document.getElementById("alib-risk-filter").addEventListener("change", alibApplyFilters);
document.getElementById("alib-sensor-filter").addEventListener("change", alibApplyFilters);

// Ciclo de vida: catálogo estático -> um só carregamento, só com a aba
// visível (nunca em segundo plano, nunca com o separador escondido).
function alibOnShow() {
  if (!alibIsActive() || alibLoaded) return;
  alibLoaded = true;
  refreshAttackLibrary();
}
const alibObserver = new MutationObserver(alibOnShow);
alibObserver.observe(alibTab, { attributes: true, attributeFilter: ["class"] });
document.addEventListener("visibilitychange", alibOnShow);
alibOnShow();
