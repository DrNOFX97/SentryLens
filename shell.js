// Shell do dashboard: seletores globais, cabeçalho (SIEM health), exportação,
// período, navegação/abas, router e arranque. Carrega depois de todos os
// ficheiros de domínio e antes dos módulos de aba.

const windowSelect = document.getElementById("window-select");
const severityFilter = document.getElementById("severity-filter");
const refreshBtn = document.getElementById("refresh-btn");
const statusIndicator = document.getElementById("status-indicator");
// Estado real do SIEM (/api/siem/health); só "sem ligação" se o próprio backend falhar.
async function refreshHeaderStatus() {
  let estado;
  try {
    estado = slHeaderStatus(await fetchJSON("/api/siem/health"), false);
  } catch (err) {
    console.error(err);
    estado = slHeaderErrorStatus(err);
  }
  statusIndicator.textContent = estado.text;
  statusIndicator.className = "status-indicator " + estado.cls;
}

async function exportReport() {
  const btn = document.getElementById("export-report-btn");
  const hours = appPeriodHours();
  if (btn) {
    btn.disabled = true;
    btn.textContent = "⏳ A gerar...";
  }
  try {
    let response;
    try {
      response = await fetch(`${API_BASE}/api/export/report?hours=${hours}`, {
        headers: { "X-API-Key": API_KEY },
      });
    } catch (_) {
      throw new ApiError("network_error", 0);
    }
    if (!response.ok) {
      const body = await response.json().catch(() => null);
      throw new ApiError(apiCodeFromResponse(response.status, body), response.status);
    }
    const blob = await response.blob();
    const disposition = response.headers.get("Content-Disposition") || "";
    const match = disposition.match(/filename="([^"]+)"/);
    const filename = match ? match[1] : "relatorio.html";

    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  } catch (err) {
    console.error("Erro ao exportar relatório:", err);
    alert("Erro ao exportar relatório. " + apiErrorMessage(err));
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = "📄 Exportar relatório";
    }
  }
}

document.getElementById("export-report-btn")?.addEventListener("click", exportReport);

// Janela global (W5.3): o único seletor do cabeçalho está em horas e cada fonte
// tem o seu teto. As abas dizem a janela efetiva com `<p class="window-note"
// data-window-max="<horas>">`, preenchido aqui.

function appRenderWindowNotes() {
  document.querySelectorAll("[data-window-max]").forEach((el) => {
    el.textContent = slWindowNote(windowSelect.value, Number(el.dataset.windowMax));
  });
}

// Ponto de entrada dos painéis que não passam pelo refreshDashboard() (ciclo de
// vida, privilégios, contas admin, ML anomalias, conformidade).
async function refreshNewPanels() {
  await Promise.allSettled([
    loadLifecyclePanel(appPeriodDays()),
    loadPrivilegesPanel(appPeriodDays()),
    loadAdminActivityPanel(appPeriodDays()),
    loadMlAnomaliesPanel(appPeriodHours()),
    loadCompliancePanel(appPeriodHours()),
  ]);
}

windowSelect.addEventListener("change", () => {
  appRenderWindowNotes();
  refreshNewPanels();
});

async function refreshDashboard() {
  const hours = appPeriodHours();
  const severity = severityFilter.value;

  try {
    await Promise.all([
      loadStats(hours),
      loadAgents(),
      loadAlerts(hours, severity),
      loadBruteForce(hours),
      loadSystemPanel(),
    ]);
  } catch (err) {
    console.error(err);
  }
  await refreshHeaderStatus();
}

refreshBtn.addEventListener("click", refreshDashboard);
windowSelect.addEventListener("change", refreshDashboard);
severityFilter.addEventListener("change", refreshDashboard);

// --- Abas ---
// Todos os dados são sempre carregados em background (refreshDashboard),
// as abas só controlam o que está visível — evita reestruturar a lógica
// assíncrona por causa da navegação.
//
// Navegação em sidebar (W5.1): cada entrada do menu tem `data-tab`; uma
// entrada que agrupa várias abas lista-as em `data-tabs` e as abas
// secundárias abrem-se pela sub-navegação (`.subnav-item[data-tab]`) dentro
// da própria secção. O que ainda não existe vive na página #tab-roadmap.
const navItems = document.querySelectorAll(".nav-item");
const subnavItems = document.querySelectorAll(".subnav-item");
const tabContents = document.querySelectorAll(".tab-content");
const sidebarEl = document.getElementById("sidebar");
const sidebarToggle = document.getElementById("sidebar-toggle");

function setSidebarOpen(open) {
  sidebarEl.classList.toggle("open", open);
  sidebarToggle.setAttribute("aria-expanded", String(open));
}

function showTab(contentId, activeItem, tabId) {
  navItems.forEach((b) => {
    const isActive = b === activeItem;
    b.classList.toggle("active", isActive);
    if (isActive) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  });
  subnavItems.forEach((b) => {
    if (b.dataset.tab === tabId) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  });
  tabContents.forEach((c) => c.classList.toggle("active", c.id === contentId));
  appCurrentTabId = tabId || null;
  if (appCurrentTabId) rtActivate(appCurrentTabId);
  else rtDeactivate();
  if (activeItem) activeItem.closest("details")?.setAttribute("open", "");
  setSidebarOpen(false);
  // Canvas nascem com tamanho 0 dentro de uma aba escondida (display:none);
  // o Chart.js não deteta sozinho quando ficam visíveis, por isso forçamos
  // um resize ao trocar de aba.
  Object.values(charts).forEach((chart) => chart.resize());
}

// O item do menu que contém a aba: o próprio (data-tab) ou o que a lista em data-tabs.
function navItemForTab(tabName) {
  return [...navItems].find((b) => b.dataset.tab === tabName || (b.dataset.tabs || "").split(" ").includes(tabName));
}

function activateTab(tabName) {
  const item = navItemForTab(tabName);
  if (!item || !document.getElementById(`tab-${tabName}`)) return;
  showTab(`tab-${tabName}`, item, tabName);
  history.replaceState(null, "", `#${tabName}`);
}

navItems.forEach((btn) => btn.addEventListener("click", () => activateTab(btn.dataset.tab)));
subnavItems.forEach((btn) => btn.addEventListener("click", () => activateTab(btn.dataset.tab)));

sidebarToggle.addEventListener("click", () => setSidebarOpen(!sidebarEl.classList.contains("open")));

document.getElementById("system-summary-card").addEventListener("click", () => activateTab("system"));

// --- Ciclo de vida das abas (W3.2) ---
// Formato do id de aba para o router (rtActivate/rtRegisterTab): o valor de
// `data-tab` do item do nav em index.html, SEM o prefixo "tab-" da secção
// (nav `data-tab="admin-activity"` <-> `<div id="tab-admin-activity">` <-> id
// "admin-activity"). Abas sem registo (ex.: roadmap) deixam o router sem aba ativa.
// "overview" NÃO é registado aqui (é de overview.js); cada módulo regista só
// as suas abas, um id repetido rebenta o registo.
let appCurrentTabId = "overview"; // Overview vem ativa no HTML

const APP_LIFECYCLE_MAX_HOURS = 90 * 24; // /api/lifecycle|privileges|admin-activity: days le=90
const APP_ALERTS_MAX_HOURS = 168; // /api/alerts, /api/ml-anomalies, /api/compliance: hours le=168

// Dias para as rotas de contas (le=90) e horas para alertas/ML/conformidade (le=168),
// sempre derivados da janela global.
function appPeriodDays() {
  return slWindowDays(slEffectiveWindow(windowSelect.value, APP_LIFECYCLE_MAX_HOURS).hours);
}
function appPeriodHours() {
  return slEffectiveWindow(windowSelect.value, APP_ALERTS_MAX_HOURS).hours;
}

function appRegisterTabs() {
  const refreshMs = 30000;
  rtRegisterTab({ id: "alerts", refreshMs, load: () => loadAlerts(appPeriodHours(), severityFilter.value) });
  rtRegisterTab({ id: "agents", refreshMs, load: () => loadAgents() });
  rtRegisterTab({ id: "system", refreshMs, load: () => loadSystemPanel() });
  rtRegisterTab({ id: "lifecycle", refreshMs, load: () => loadLifecyclePanel(appPeriodDays()) });
  rtRegisterTab({ id: "privileges", refreshMs, load: () => loadPrivilegesPanel(appPeriodDays()) });
  rtRegisterTab({ id: "admin-activity", refreshMs, load: () => loadAdminActivityPanel(appPeriodDays()) });
  // /api/ml-anomalies e /api/compliance usam "hours" (máx. 168), não dias.
  rtRegisterTab({ id: "ml-anomalies", refreshMs, load: () => loadMlAnomaliesPanel(appPeriodHours()) });
  rtRegisterTab({ id: "compliance", refreshMs, load: () => loadCompliancePanel(appPeriodHours()) });
}

// Cabeçalho (SIEM health): corre sempre, em qualquer aba, mas pára com a
// página escondida e volta com um refresh imediato quando fica visível.
const APP_HEADER_REFRESH_MS = 30000;
let appHeaderTimerId = null;

function appHeaderStart() {
  if (appHeaderTimerId !== null) return;
  appHeaderTimerId = setInterval(() => {
    if (document.visibilityState === "visible") refreshHeaderStatus();
  }, APP_HEADER_REFRESH_MS);
}

function appHeaderStop() {
  if (appHeaderTimerId === null) return;
  clearInterval(appHeaderTimerId);
  appHeaderTimerId = null;
}

function appHeaderOnVisibility() {
  if (document.visibilityState === "visible") {
    refreshHeaderStatus();
    appHeaderStart();
  } else {
    appHeaderStop();
  }
}

appRegisterTabs();
document.addEventListener("visibilitychange", appHeaderOnVisibility);
if (document.visibilityState === "visible") appHeaderStart();
// --- fim do ciclo de vida das abas ---

// Deep link: #redblue, #alerts, #ml-evaluation… (sem hash válido fica
// na Visão Geral, que já vem ativa no HTML).
function applyHash() {
  let hash = "";
  try {
    hash = decodeURIComponent(location.hash.slice(1));
  } catch (_) {
    return; // hash malformado (ex.: #%E0): tratar como sem hash
  }
  if (!hash) return;
  activateTab(hash);
}
window.addEventListener("hashchange", applyHash);
applyHash();

// Carrega ao abrir e liga o WebSocket de tempo real (/ws/alerts); o polling
// fixo de 30s só volta a existir via startPollFallback() se a ligação
// WebSocket falhar definitivamente (ver connectWebSocket()).
appRenderWindowNotes();
refreshDashboard();
connectWebSocket();

// Abas de outros módulos registam-se depois de app.js: quando tudo carregou,
// se a aba atual (ex.: Overview, ou um deep link) ainda não está ativa no
// router, ativa-a agora.
window.addEventListener("load", () => {
  const id = appCurrentTabId;
  if (id && rtRouter.getActiveId() !== id) rtActivate(id);
});
