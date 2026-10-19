// Aba "Attack Library" (Roadmap v2, R5). Carregado depois de app.js e
// attack_registry.js: reutiliza os seus globais (API_BASE, API_KEY,
// renderPanelError) — não redeclarar nenhum aqui. Um só pedido
// a GET /api/attack-library (catálogo estático, não depende do período
// selecionado); refiltra em memória quando os filtros mudam. Só mostra
// dados reais; sem dados -> "Sem dados". Não abre WebSocket, não pede nada
// com a aba escondida. Todo o texto dinâmico é escapado pelo htmlT (o YAML é
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

// Texto simples: o htmlT escapa na interpolação.
function alibCell(value) {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
}

function alibSensors(list) {
  return list && list.length ? list.map((s) => ALIB_SENSOR_LABELS[s] || s).join(", ") : "—";
}

function alibRiskBadge(risk) {
  const label = ALIB_RISK_LABELS[risk] || risk;
  return htmlT`<span class="alib-risk alib-risk-${risk}">${label}</span>`;
}

function alibReplayableBadge(replayable) {
  return htmlT`<span class="alib-replayable alib-replayable-${replayable ? "yes" : "no"}">${replayable ? "Sim" : "Não"}</span>`;
}

function alibRequest(path) {
  return apiRequest(path);
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
    htmRender(body, htmlT`<tr><td colspan="8" class="empty-state">Sem dados — nenhum cenário corresponde aos filtros.</td></tr>`);
    return;
  }
  htmRender(body, htmlT`${entries.map((e) => htmlT`<tr class="atk-row${e.id === alibSelectedId ? " selected" : ""}" data-id="${e.id}" tabindex="0">
    <td>${alibCell(e.id)}</td>
    <td>${alibCell(e.name)}</td>
    <td>${alibCell(e.mitre_technique)}</td>
    <td>${alibCell(e.tool)}</td>
    <td>${alibRiskBadge(e.risk)}</td>
    <td>${alibSensors(e.expected_sensors)}</td>
    <td>${alibReplayableBadge(e.replayable)}</td>
    <td>${alibCell(e.duration_estimate)}</td>
  </tr>`)}`);
}

function renderAttackLibraryDetail(entry) {
  const panel = document.getElementById("attack-library-detail-panel");
  panel.hidden = false;
  document.getElementById("alib-detail-title").textContent = entry.name || entry.id;
  htmRender(document.getElementById("alib-detail-meta"), htmlT`
    <span>${alibRiskBadge(entry.risk)}</span>
    <span>Cenário: <strong>${alibCell(entry.id)}</strong></span>
    <span>MITRE: ${alibCell(entry.mitre_technique)} (${alibCell(entry.mitre_tactic)})</span>
    <span>Ferramenta: ${alibCell(entry.tool)}</span>
    <span>Event IDs: ${alibCell((entry.event_ids || []).join(", "))}</span>
    <span>Duração estimada: ${alibCell(entry.duration_estimate)}</span>`);
  document.getElementById("alib-detail-prereqs").textContent = entry.prerequisites || "—";
  const steps = entry.cleanup_steps || [];
  htmRender(document.getElementById("alib-detail-cleanup"), steps.length
    ? htmlT`${steps.map((s) => htmlT`<li>${s}</li>`)}`
    : htmlT`<li class="empty-state">Sem passos de limpeza registados.</li>`);
  htmRender(document.getElementById("alib-detail-replayable"),
    htmlT`${alibReplayableBadge(entry.replayable)} — ${entry.replayable_reason || "sem motivo registado"}`);
}

function alibShowDetailError(message) {
  if (message) document.getElementById("attack-library-detail-panel").hidden = false;
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
    alibShowDetailError(`Não foi possível carregar o detalhe: ${apiErrorMessage(err)}`);
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
    const message = `Não foi possível carregar a Biblioteca de ataques: ${apiErrorMessage(err)}`;
    renderPanelError("#attack-library-panel", message);
    htmRender(document.getElementById("alib-body"),
      htmlT`<tr><td colspan="8" class="empty-state">Sem dados — ${apiErrorMessage(err)}.</td></tr>`);
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
