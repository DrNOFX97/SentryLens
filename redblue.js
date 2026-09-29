// Aba "Red vs Blue" (Fase 11, Onda 3). Carregado depois de app.js e
// reutiliza os seus globais (fetchJSON, escapeHtml, formatTimestamp,
// renderPanelError, API_BASE, API_KEY) — não redeclarar nenhum deles aqui.
// Só mostra dados reais dos endpoints do backend; sem dados, estado vazio.

const RB_REFRESH_MS = 30000;
const RB_METRICS_HOURS = 168; // máximo aceite por /api/redblue/metrics
const RB_MAX_PACKET_ROWS = 200;
const RB_NETWORK_WS_URL = `${API_BASE.replace(/^http/, "ws")}/ws/network?api_key=${encodeURIComponent(API_KEY)}`;

let rbMetrics = null;
let rbAttackLog = null;

function rbCell(value) {
  if (value === null || value === undefined || value === "") return "—";
  return escapeHtml(String(value));
}

function rbFormatSeconds(seconds) {
  if (seconds === null || seconds === undefined) return "—";
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  return `${Math.floor(seconds / 60)} min ${Math.round(seconds % 60)} s`;
}

function rbFormatPercent(rate, attempts) {
  if (!attempts) return "—";
  return `${Math.round(rate * 100)}%`;
}

function rbSetText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function renderRedBlueKpis(data) {
  const overall = data.overall || {};
  const attempts = overall.total_attempts || 0;
  rbSetText("kpi-rb-attempts", attempts);
  rbSetText("kpi-rb-coverage", rbFormatPercent(overall.coverage_rate, attempts));
  rbSetText("kpi-rb-mttd", rbFormatSeconds(overall.avg_mttd_seconds));
  rbSetText("kpi-rb-network-only", data.network_capture_configured ? (overall.detected_by_network_only ?? 0) : "—");
  rbSetText("kpi-rb-neither", overall.detected_by_neither ?? 0);
  rbSetText("kpi-rb-alerts-fetched", data.alerts_fetched ?? "—");
  rbSetText("kpi-rb-capture", data.network_capture_configured ? "Configurada" : "Não configurada");

  const notices = [];
  if (attempts === 0) {
    notices.push("Sem ataques na janela de 7 dias — não há nada para correlacionar (cobertura e MTTD não se aplicam). O painel Red Team lista o log completo.");
  }
  if (data.alerts_truncated) {
    notices.push(`Foram analisados ${data.alerts_fetched} alertas (teto de 1000): a cobertura pode estar subestimada.`);
  }
  const counts = [
    ["not_executed", "não executadas"],
    ["unknown_scenario", "de cenário desconhecido"],
    ["invalid_entries", "inválidas"],
  ];
  counts.forEach(([key, label]) => {
    const n = (data[key] || []).length;
    if (n > 0) notices.push(`${n} entrada(s) do log ${label} ficaram de fora da correlação.`);
  });
  document.getElementById("redblue-notices").innerHTML = notices
    .map((n) => `<div class="rb-notice">⚠️ ${escapeHtml(n)}</div>`)
    .join("");
}

async function loadRedBlueMetrics() {
  try {
    rbMetrics = await fetchJSON(`/api/redblue/metrics?hours=${RB_METRICS_HOURS}`);
    renderPanelError("#redblue-summary-panel", null);
    renderRedBlueKpis(rbMetrics);
  } catch (err) {
    console.error(err);
    rbMetrics = null;
    const message = err.status === 503
      ? "Modelo de ML ainda não foi treinado. Corre scripts/train_anomaly_model.py."
      : (err.message || "Erro ao carregar a correlação Red vs Blue.");
    renderPanelError("#redblue-summary-panel", message);
  }
  if (typeof renderBluePanel === "function") renderBluePanel(rbMetrics);
  if (typeof renderRedPanel === "function") renderRedPanel(rbAttackLog, rbMetrics);
}

async function loadManagerPanel() {
  const tbody = document.getElementById("redblue-agents-body");
  try {
    const [health, agents] = await Promise.all([fetchJSON("/api/health"), fetchJSON("/api/agents")]);
    renderPanelError("#redblue-manager-panel", null);
    rbSetText("kpi-rb-backend", health.status === "ok" ? "Ativo" : String(health.status));
    const list = agents.agents || [];
    rbSetText("kpi-rb-agents", list.filter((a) => a.status === "active").length);
    if (list.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" class="empty-state">Nenhum agente encontrado</td></tr>';
      return;
    }
    tbody.innerHTML = list
      .map(
        (a) => `
      <tr>
        <td>${rbCell(a.name)}</td>
        <td class="mono">${rbCell(a.ip)}</td>
        <td><span class="agent-status ${escapeHtml(a.status)}">${rbCell(a.status)}</span></td>
        <td class="mono">${escapeHtml(formatTimestamp(a.last_keep_alive))}</td>
      </tr>`,
      )
      .join("");
  } catch (err) {
    console.error(err);
    renderPanelError("#redblue-manager-panel", err.message || "Erro ao carregar agentes.");
  }
}

async function refreshRedBlueTab() {
  await Promise.allSettled([
    loadRedBlueMetrics(),
    loadManagerPanel(),
    typeof loadRedPanel === "function" ? loadRedPanel() : Promise.resolve(),
    typeof loadNetworkPanel === "function" ? loadNetworkPanel() : Promise.resolve(),
  ]);
}

refreshRedBlueTab();
setInterval(refreshRedBlueTab, RB_REFRESH_MS);
