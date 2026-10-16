// Dashboard de Cibersegurança — lógica de frontend
// Consome a API FastAPI (backend/main.py) e preenche a interface

const API_BASE = "http://localhost:8001";
// A chave vem de /config.js, gerado por scripts/serve_frontend.py a partir de
// SENTRYLENS_API_KEY em scripts/.env (nunca vai para o repositório). Esse
// endpoint só responde ao próprio origin do dashboard (ver serve_frontend.py).
// Se config.js não existir (outro servidor estático), fica vazia e a API
// responde 401 — o dashboard mostra "sem ligação", não falha em silêncio.
const API_KEY = (window.SENTRYLENS_CONFIG && window.SENTRYLENS_CONFIG.apiKey) || "";

// WebSocket de alertas em tempo real (/ws/alerts) — ver connectWebSocket()
// mais abaixo. Autenticação vai por query param (não header) porque o
// handshake de WebSocket do browser não permite headers HTTP arbitrários.
const WS_URL = `${API_BASE.replace(/^http/, "ws")}/ws/alerts?api_key=${encodeURIComponent(API_KEY)}`;
const WS_RECONNECT_DELAYS_MS = [1000, 2000, 4000, 8000, 16000];
// Depois de esgotar as 5 tentativas iniciais, deixa de fazer backoff
// exponencial (não faz sentido continuar a espaçar mais) e passa a tentar
// uma vez a este ritmo fixo, em paralelo com o próprio polling de fallback
// — mesma cadência de 30s, para o WebSocket poder recuperar sozinho sem
// precisar de recarregar a página.
const WS_RECOVERY_INTERVAL_MS = 30000;

let ws = null;
let wsReconnectAttempts = 0;
let pollFallbackIntervalId = null;
let wsRecoveryIntervalId = null;
let inRealtimeFallback = false;
let realtimeFallbackBannerEl = null;

const windowSelect = document.getElementById("window-select");
const severityFilter = document.getElementById("severity-filter");
const refreshBtn = document.getElementById("refresh-btn");
const statusIndicator = document.getElementById("status-indicator");
const periodSelect = document.getElementById("period-select");

// Dados do Wazuh (nomes de agente, descrições de regra, username de logons
// falhados, etc.) podem conter texto controlado por um atacante — escapamos
// tudo antes de meter em innerHTML para evitar XSS armazenado.
function escapeHtml(value) {
  if (value === null || value === undefined) return "";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

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

// Aviso fixo no topo do dashboard quando o WebSocket de tempo real falha
// definitivamente (5 tentativas de reconexão esgotadas) — ver
// connectWebSocket(). Não há classe de banner de página inteira reutilizável
// em style.css (.panel-error-banner é para dentro de um .panel de fundo
// branco), por isso estiliza-se inline aqui; amarelo/laranja de aviso,
// consistente com o resto da paleta (ver .level-aviso em style.css).
function showRealtimeFallbackWarning() {
  if (realtimeFallbackBannerEl) return;
  realtimeFallbackBannerEl = document.createElement("div");
  realtimeFallbackBannerEl.textContent =
    "⚠️ Ligação em tempo real indisponível — a atualizar a cada 30s.";
  realtimeFallbackBannerEl.style.cssText =
    "background:#7a5200;color:#fff;text-align:center;padding:8px;font-size:14px;position:sticky;top:0;z-index:1000;";
  document.body.insertBefore(realtimeFallbackBannerEl, document.body.firstChild);
}

function hideRealtimeFallbackWarning() {
  if (realtimeFallbackBannerEl) {
    realtimeFallbackBannerEl.remove();
    realtimeFallbackBannerEl = null;
  }
}

// Único sítio onde o polling fixo de 30s ainda existe — só arranca quando o
// WebSocket falha definitivamente (ver connectWebSocket()/onclose abaixo).
function startPollFallback() {
  if (pollFallbackIntervalId) return;
  pollFallbackIntervalId = setInterval(refreshDashboard, 30000);
}

// Enquanto em fallback, tenta recuperar o WebSocket a cada
// WS_RECOVERY_INTERVAL_MS — cada tentativa é uma ligação nova e única (não
// volta a encadear o backoff exponencial, já esgotado). Se conseguir,
// ws.onopen trata de limpar este intervalo e sair do fallback; se falhar,
// ws.onclose vê inRealtimeFallback=true e não faz nada mais (deixa o
// próprio intervalo tentar outra vez no próximo tick).
function startWsRecovery() {
  if (wsRecoveryIntervalId) return;
  wsRecoveryIntervalId = setInterval(connectWebSocket, WS_RECOVERY_INTERVAL_MS);
}

// Cada alerta novo chega por WebSocket e, antes, chamava refreshDashboard()
// diretamente — uma rajada de alertas (ex.: um ataque) redesenhava os gráficos
// e repetia 5 pedidos várias vezes por segundo. Agora agrupa-se: o primeiro
// alerta atualiza logo (se passou o intervalo mínimo) e os seguintes dentro
// da janela viram UM único refresh no fim dela.
const REALTIME_REFRESH_MIN_MS = 15000;
let lastRealtimeRefreshAt = 0;
let realtimeRefreshTimerId = null;

function scheduleRealtimeRefresh() {
  if (realtimeRefreshTimerId) return; // já há um refresh agendado para cobrir este alerta
  const wait = Math.max(0, lastRealtimeRefreshAt + REALTIME_REFRESH_MIN_MS - Date.now());
  realtimeRefreshTimerId = setTimeout(() => {
    realtimeRefreshTimerId = null;
    lastRealtimeRefreshAt = Date.now();
    refreshDashboard();
  }, wait);
}

// Liga o WebSocket de alertas em tempo real (/ws/alerts). Ao receber
// {"type":"new_alert"} agenda refreshDashboard() (ver scheduleRealtimeRefresh) em vez de inserir a linha
// manualmente — refreshDashboard() já busca/filtra tudo (severidade/janela
// temporal selecionadas) e não vale a pena duplicar essa lógica aqui.
// Reconecta com backoff exponencial (1s..16s, 5 tentativas); depois disso
// entra em fallback de polling (startPollFallback + showRealtimeFallbackWarning)
// mas continua a tentar recuperar sozinho a cada 30s (startWsRecovery) — só
// esta função chama new WebSocket(...), tanto nas tentativas iniciais como
// nas de recuperação, por isso toda a lógica de estado vive só aqui.
function connectWebSocket() {
  ws = new WebSocket(WS_URL);

  ws.onopen = () => {
    wsReconnectAttempts = 0;
    inRealtimeFallback = false;
    hideRealtimeFallbackWarning();
    if (pollFallbackIntervalId) {
      clearInterval(pollFallbackIntervalId);
      pollFallbackIntervalId = null;
    }
    if (wsRecoveryIntervalId) {
      clearInterval(wsRecoveryIntervalId);
      wsRecoveryIntervalId = null;
    }
  };

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      if (msg && msg.type === "new_alert") {
        scheduleRealtimeRefresh();
        document.dispatchEvent(new CustomEvent("sentrylens:new-alert", { detail: msg.alert }));
      }
    } catch (err) {
      console.error("Mensagem WebSocket inválida:", err);
    }
  };

  ws.onerror = () => {
    ws.close();
  };

  ws.onclose = () => {
    if (inRealtimeFallback) {
      // Foi só uma tentativa de recuperação a falhar — startWsRecovery()
      // já está a correr e tenta outra vez no próximo tick, sem repetir o
      // aviso nem duplicar o polling (já ativos).
      return;
    }
    if (wsReconnectAttempts < WS_RECONNECT_DELAYS_MS.length) {
      const delay = WS_RECONNECT_DELAYS_MS[wsReconnectAttempts];
      wsReconnectAttempts++;
      setTimeout(connectWebSocket, delay);
    } else {
      inRealtimeFallback = true;
      showRealtimeFallbackWarning();
      startPollFallback();
      startWsRecovery();
    }
  };
}

function severityBadge(severity) {
  const labels = {
    critical: "Crítico",
    high: "Alto",
    medium: "Médio",
    low: "Baixo",
    info: "Info",
  };
  const label = labels[severity] || severity;
  return `<span class="severity-badge ${escapeHtml(severity)}">${escapeHtml(label)}</span>`;
}

// O backend dos painéis novos (ciclo de vida, privilégios, contas admin)
// devolve severidade em slugs PT ("critico"/"alto"/"medio"/"baixo"); a app
// usa classes em inglês (severityBadge, .detection-item, .alert-row, etc.)
// — traduz aqui, num único sítio, para os 3 painéis novos.
function mapSeverity(sev) {
  const map = { critico: "critical", alto: "high", medio: "medium", baixo: "low" };
  return map[sev] || sev;
}

function formatTimestamp(ts) {
  return slFormatTimestamp(ts);
}

// Invólucro fino sobre apiRequest (api.js): mesma assinatura (path -> JSON).
// O erro lançado é um ApiError (status numérico + mensagem fixa em PT).
async function fetchJSON(path) {
  return apiRequest(path);
}

// Texto seguro para mostrar num painel: só mensagens de ApiError (fixas, em
// PT, com ação sugerida); qualquer outro erro (ex.: bug de renderização)
// cai no texto de reserva, nunca no texto da exceção.
function panelErrorText(err, fallback) {
  return err instanceof ApiError ? err.message : fallback;
}

// --- Helpers partilhados pelos painéis novos (ciclo de vida, privilégios,
// contas admin) — reutilizáveis pelos 3, ver docs/README ou o comentário
// de refreshNewPanels() mais abaixo para a estrutura esperada. ---

// Renderiza uma lista de deteções de risco ({name, severity, explanation})
// dentro do container indicado. severity vem em slugs PT do backend e é
// traduzida com mapSeverity() antes de aplicar a classe .level-<...>.
function renderDetections(containerId, detections) {
  const container = document.getElementById(containerId);
  if (!container) return;

  if (!detections || detections.length === 0) {
    sttShowEmpty(container, "Sem deteções neste período");
    return;
  }

  container.innerHTML = detections
    .map((d) => {
      const level = escapeHtml(mapSeverity(d.severity));
      return `
        <div class="detection-item level-${level}">
          <strong>${escapeHtml(d.name)}</strong>
          <span>${escapeHtml(d.explanation)}</span>
        </div>
      `;
    })
    .join("");
}

// Mostra (ou, com message vazio/null, esconde) um banner de erro dentro do
// painel indicado por panelSelector (ex: "#lifecycle-panel").
//
// Decisão de paleta: reutilizamos a paleta CLARA já usada em
// .card.critical/.alert-row.critical (fundo #fdf1f0, texto #c0392b), e não
// a paleta escura de .status-error (#5c1e1e/#ff8080). Motivo: .status-error
// foi pensada para o indicador de estado sobre o fundo navy do header; os
// painéis novos são .panel com fundo branco/claro, tal como todos os
// outros painéis da app, por isso a paleta clara é a que já convive bem
// com esse fundo (é a mesma usada em #brute-force-panel/.alert-row.critical).
function renderPanelError(panelSelector, message) {
  const panel = document.querySelector(panelSelector);
  if (!panel) return;

  let banner = panel.querySelector(".panel-error-banner");
  if (!message) {
    if (banner) banner.remove();
    return;
  }

  if (!banner) {
    banner = document.createElement("div");
    banner.className = "panel-error-banner";
    const heading = panel.querySelector("h2");
    if (heading) {
      heading.insertAdjacentElement("afterend", banner);
    } else {
      panel.insertBefore(banner, panel.firstChild);
    }
  }
  sttShowError(banner, `⚠️ ${message}`);
}

async function loadStats(hours) {
  let stats;
  try {
    stats = await fetchJSON(`/api/stats?hours=${hours}`);
  } catch (err) {
    console.error(err);
    renderPanelError("#overview-error-anchor", panelErrorText(err, "Erro ao carregar as estatísticas."));
    return;
  }
  renderPanelError("#overview-error-anchor", null);

  document.getElementById("kpi-total").textContent = stats.total_alerts ?? 0;
  document.getElementById("kpi-critical").textContent = stats.by_severity?.critical ?? 0;
  document.getElementById("kpi-high").textContent = stats.by_severity?.high ?? 0;
  document.getElementById("kpi-medium").textContent = stats.by_severity?.medium ?? 0;
  document.getElementById("kpi-low").textContent = stats.by_severity?.low ?? 0;

  renderSeverityDonutChart(stats.by_severity);
  renderTopEventsChart(stats.top_events);
}

async function loadAgents() {
  let data;
  try {
    data = await fetchJSON(`/api/agents`);
  } catch (err) {
    console.error(err);
    document.getElementById("agents-table-body").innerHTML =
      `<tr><td colspan="5" class="error-state" role="alert">${escapeHtml(panelErrorText(err, "Erro ao carregar agentes."))}</td></tr>`;
    return;
  }
  const activeCount = (data.agents || []).filter((a) => a.status === "active").length;
  document.getElementById("kpi-agents").textContent = activeCount;

  const tbody = document.getElementById("agents-table-body");
  tbody.innerHTML = "";

  if (!data.agents || data.agents.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-state">Nenhum agente encontrado</td></tr>';
    return;
  }

  data.agents.forEach((agent) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(agent.name)}</td>
      <td class="mono">${escapeHtml(agent.ip || "-")}</td>
      <td>${escapeHtml(agent.os || "-")}</td>
      <td><span class="agent-status ${escapeHtml(agent.status)}">${escapeHtml(agent.status)}</span></td>
      <td class="mono">${escapeHtml(formatTimestamp(agent.last_keep_alive))}</td>
    `;
    tbody.appendChild(tr);
  });
}

async function loadAlerts(hours, severity) {
  let url = `/api/alerts?hours=${hours}`;
  if (severity) url += `&severity=${severity}`;

  let data;
  try {
    data = await fetchJSON(url);
  } catch (err) {
    console.error(err);
    renderPanelError("#alerts-panel", panelErrorText(err, "Erro ao carregar os alertas."));
    document.getElementById("alerts-table-body").innerHTML =
      `<tr><td colspan="9" class="empty-state">Indisponível.</td></tr>`;
    return;
  }
  renderPanelError("#alerts-panel", null);
  const tbody = document.getElementById("alerts-table-body");
  tbody.innerHTML = "";

  if (!data.alerts || data.alerts.length === 0) {
    tbody.innerHTML = '<tr><td colspan="9" class="empty-state">Sem alertas neste período</td></tr>';
    renderAlertsTimelineChart([], hours);
    return;
  }

  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sorted = [...data.alerts].sort(
    (a, b) => (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5)
  );

  sorted.slice(0, 100).forEach((alert) => {
    const tr = document.createElement("tr");
    tr.className = `alert-row ${escapeHtml(alert.severity)}`;
    tr.innerHTML = `
      <td class="mono">${escapeHtml(formatTimestamp(alert.timestamp))}</td>
      <td>${severityBadge(alert.severity)}</td>
      <td>${escapeHtml(alert.agent_name)}</td>
      <td class="mono">${escapeHtml(alert.agent_ip)}</td>
      <td class="mono">${alert.windows_event_id != null ? escapeHtml(alert.windows_event_id) : "-"}</td>
      <td class="wrap">${escapeHtml(alert.friendly_name)}<div class="table-sub">${escapeHtml(alert.rule_description || "")}</div></td>
      <td>${alert.wazuh_level != null ? escapeHtml(alert.wazuh_level) : "-"}</td>
      <td class="wrap">${escapeHtml(alert.recommendation)}</td>
      <td class="log-cell">${escapeHtml(alert.full_log)}</td>
    `;
    tbody.appendChild(tr);
  });

  renderAlertsTimelineChart(data.alerts, hours);
}

async function loadBruteForce(hours) {
  const panel = document.getElementById("brute-force-panel");
  const list = document.getElementById("brute-force-list");
  let data;
  try {
    data = await fetchJSON(`/api/brute-force?hours=${hours}`);
  } catch (err) {
    // Painel opcional (só aparece quando há suspeitas): numa falha fica
    // escondido como por omissão, em vez de ficar preso em "A carregar...".
    console.error(err);
    panel.style.display = "none";
    return;
  }

  if (!data.suspects || data.suspects.length === 0) {
    panel.style.display = "none";
    return;
  }

  panel.style.display = "block";
  list.innerHTML = "";
  data.suspects.forEach((s) => {
    const item = document.createElement("div");
    item.className = "bf-item";
    item.innerHTML = `
      <span><strong>${escapeHtml(s.user)}</strong> — ${escapeHtml(s.failed_attempts)} tentativas falhadas (${escapeHtml(s.source_agent)})</span>
      <span>${escapeHtml(formatTimestamp(s.last_attempt))}</span>
    `;
    list.appendChild(item);
  });
}

function formatBytes(bytes) {
  if (bytes == null) return "-";
  const gb = bytes / 1024 ** 3;
  return `${gb.toFixed(1)} GB`;
}

function formatDuration(seconds) {
  const totalMinutes = Math.max(0, Math.floor(seconds / 60));
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  return hours > 0 ? `${hours}h ${minutes}m` : `${minutes}m`;
}

function metricLabel(metric) {
  if (metric === "cpu") return "CPU";
  if (metric === "ram") return "RAM";
  if (metric === "network_download") return "Rede (download)";
  if (metric === "network_upload") return "Rede (upload)";
  if (metric.startsWith("disk:")) return `Disco ${metric.slice(5)}`;
  return metric;
}

function setProgressBar(barEl, percent, level) {
  barEl.style.width = slProgressWidth(percent);
  // Sem valor a barra fica vazia e sem cor de nível (nunca verde a 100%).
  barEl.className = slNumberOrNull(percent) === null ? "progress-fill" : `progress-fill level-${level}`;
}

// Resume os módulos de RAM instalados (ex: "2× 16 GB DDR5 @ 6200 MHz") —
// agrupa módulos idênticos em vez de listar linha a linha, que é o caso
// comum (kits parelhos).
function summarizeRamModules(modules) {
  if (!modules || modules.length === 0) return null;

  const groups = new Map();
  modules.forEach((m) => {
    const key = `${m.capacity_bytes}|${m.speed_mhz}|${m.memory_type}`;
    groups.set(key, (groups.get(key) || 0) + 1);
  });
  const sizeLine = [...groups.entries()]
    .map(([key, count]) => {
      const [capacityBytes, speed, type] = key.split("|");
      const gb = (Number(capacityBytes) / 1024 ** 3).toFixed(0);
      return `${count}× ${gb} GB ${type} @ ${speed} MHz`;
    })
    .join(" + ");

  const first = modules[0];
  const modelLine = first.manufacturer && first.part_number
    ? `${first.manufacturer} • ${first.part_number}`
    : null;

  return { sizeLine, modelLine };
}

function renderNetworkInterfaces(interfaces) {
  const tbody = document.getElementById("network-interfaces-body");
  tbody.innerHTML = "";
  if (!interfaces || interfaces.length === 0) {
    tbody.innerHTML = '<tr><td colspan="3" class="empty-state">Nenhuma interface ativa encontrada</td></tr>';
    return;
  }
  interfaces.forEach((iface) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(iface.interface)}</td>
      <td class="mono">${escapeHtml(iface.ip)}</td>
      <td class="mono">${iface.speed_mbps ? escapeHtml(iface.speed_mbps) + " Mbps" : "-"}</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderViolationsHistory(history) {
  const tbody = document.getElementById("violations-history-body");
  tbody.innerHTML = "";
  if (!history || history.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" class="empty-state">Sem violações resolvidas ainda</td></tr>';
    return;
  }
  const sorted = [...history].sort((a, b) => new Date(b.started_at) - new Date(a.started_at));
  sorted.slice(0, 50).forEach((v) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(metricLabel(v.metric))}</td>
      <td>${v.level === "critico" ? "Crítico" : "Aviso"}</td>
      <td class="mono">${escapeHtml(formatTimestamp(v.started_at))}</td>
      <td class="mono">${escapeHtml(formatDuration(v.duration_seconds))}</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderSystemSummaryCard({
  cpuPct, cpuLvl, ramPct, ramLvl, worstDisk, worstDiskLevel, downloadLevel, uploadLevel, networkMeasured, activeCount, criticalCount,
}) {
  const badge = document.getElementById("summary-health-badge");
  let healthLabel = "OK";
  let healthLevel = "normal";
  if (criticalCount > 0) {
    healthLabel = "Crítico";
    healthLevel = "critico";
  } else if (activeCount > 0) {
    healthLabel = "Aviso";
    healthLevel = "aviso";
  }
  badge.textContent = healthLabel;
  badge.className = `health-badge level-${healthLevel}`;

  setProgressBar(document.getElementById("summary-cpu-bar"), cpuPct, cpuLvl);
  document.getElementById("summary-cpu-pct").textContent = slFmtPct(cpuPct);

  setProgressBar(document.getElementById("summary-ram-bar"), ramPct, ramLvl);
  document.getElementById("summary-ram-pct").textContent = slFmtPct(ramPct);

  const diskPct = worstDisk ? worstDisk.usage_percent : null;
  setProgressBar(document.getElementById("summary-disk-bar"), diskPct, worstDiskLevel);
  document.getElementById("summary-disk-pct").textContent = slFmtPct(diskPct);

  const netLevel =
    downloadLevel === "critico" || uploadLevel === "critico"
      ? "critico"
      : downloadLevel === "aviso" || uploadLevel === "aviso"
        ? "aviso"
        : "normal";
  const netLabelMap = { normal: "OK", aviso: "Aviso", critico: "Crítico" };
  // Download/upload não são naturalmente uma percentagem 0-100; a barra fica
  // sempre cheia, só a cor muda com o nível — mantém o mesmo ritmo visual
  // das outras três métricas em vez de destoar com um formato diferente.
  setProgressBar(document.getElementById("summary-network-bar"), networkMeasured ? 100 : null, netLevel);
  document.getElementById("summary-network-status").textContent = networkMeasured ? netLabelMap[netLevel] : "—";
}

// Cartão de resumo do Overview sem dados: badge e textos a "—", barras vazias.
function resetSystemSummaryCard() {
  const badge = document.getElementById("summary-health-badge");
  badge.textContent = "—";
  badge.className = "health-badge";
  ["cpu", "ram", "disk", "network"].forEach((k) => {
    setProgressBar(document.getElementById(`summary-${k}-bar`), null, "normal");
  });
  ["summary-cpu-pct", "summary-ram-pct", "summary-disk-pct", "summary-network-status"].forEach((id) => {
    document.getElementById(id).textContent = "—";
  });
}

// Painel Sistema sem dados: valores a "—", barras vazias, listas "Sem dados".
function resetSystemPanelValues() {
  ["sys-cpu-value", "sys-ram-value", "sys-cpu-detail", "sys-ram-detail",
    "sys-net-download", "sys-net-upload"].forEach((id) => {
    document.getElementById(id).textContent = "—";
  });
  document.getElementById("sys-net-sub").textContent = "Última medição: —";
  ["sys-cpu-bar", "sys-ram-bar", "sys-net-bar"].forEach((id) => {
    setProgressBar(document.getElementById(id), null, "normal");
  });
  document.getElementById("sys-disk-cards").innerHTML = "";
  document.getElementById("network-interfaces-body").innerHTML =
    '<tr><td colspan="3" class="empty-state">Sem dados</td></tr>';
  document.getElementById("system-alerts-list").innerHTML = '<p class="empty-state">Sem dados</p>';
  document.getElementById("violations-history-body").innerHTML =
    '<tr><td colspan="4" class="empty-state">Sem dados</td></tr>';
}

async function loadSystemPanel() {
  try {
    const [specs, alertsData, usageHistoryData, historyData] = await Promise.all([
      fetchJSON("/api/system/specs"),
      fetchJSON("/api/system/alerts"),
      fetchJSON("/api/system/usage-history"),
      fetchJSON("/api/system/history"),
    ]);

    const levelByMetric = {};
    (alertsData.active_violations || []).forEach((v) => {
      levelByMetric[v.metric] = v.level;
    });

    // CPU
    const cpuPct = specs.cpu.usage_percent;
    const cpuLvl = levelByMetric["cpu"] || "normal";
    document.getElementById("sys-cpu-value").textContent = slFmtPct(cpuPct, 1);
    setProgressBar(document.getElementById("sys-cpu-bar"), cpuPct, cpuLvl);
    const cpuModelLine = specs.cpu.frequency_mhz
      ? `${specs.cpu.model} @ ${(specs.cpu.frequency_mhz / 1000).toFixed(2)} GHz`
      : specs.cpu.model;
    document.getElementById("sys-cpu-detail").textContent =
      `${specs.cpu.physical_cores} núcleos físicos / ${specs.cpu.logical_cores} lógicos · ${cpuModelLine}`;

    // RAM
    const ramPct = specs.ram.usage_percent;
    const ramLvl = levelByMetric["ram"] || "normal";
    document.getElementById("sys-ram-value").textContent = slFmtPct(ramPct, 1);
    setProgressBar(document.getElementById("sys-ram-bar"), ramPct, ramLvl);
    const ramModules = summarizeRamModules(specs.ram.modules);
    const ramDetailParts = [
      `${formatBytes(specs.ram.used_bytes)} / ${formatBytes(specs.ram.total_bytes)}`,
      ramModules?.sizeLine,
      ramModules?.modelLine,
    ].filter(Boolean);
    document.getElementById("sys-ram-detail").textContent = ramDetailParts.join(" · ");

    // Disco (um card por partição)
    const diskContainer = document.getElementById("sys-disk-cards");
    diskContainer.innerHTML = "";
    let worstDisk = null;
    let worstDiskLevel = "normal";
    (specs.disk || []).forEach((disk) => {
      const metricName = `disk:${disk.mountpoint}`;
      const level = levelByMetric[metricName] || "normal";
      if (!worstDisk || disk.usage_percent > worstDisk.usage_percent) {
        worstDisk = disk;
        worstDiskLevel = level;
      }
      const diskDetailParts = [
        `${formatBytes(disk.used_bytes)} / ${formatBytes(disk.total_bytes)}`,
        disk.filesystem,
        disk.physical_model,
        disk.bus_type,
      ].filter(Boolean);
      const card = document.createElement("div");
      card.className = "system-card";
      card.innerHTML = `
        <div class="system-card-header">
          <h3>Disco ${escapeHtml(disk.mountpoint)}</h3>
          ${disk.media_type ? `<span class="media-badge ${escapeHtml(disk.media_type.toLowerCase())}">${escapeHtml(disk.media_type)}</span>` : ""}
          <span class="system-card-value">${escapeHtml(slFmtPct(disk.usage_percent, 1))}</span>
        </div>
        <div class="progress-track"><div class="progress-fill level-${escapeHtml(level)}" style="width:${slProgressWidth(disk.usage_percent)}"></div></div>
        <div class="system-sub">${escapeHtml(diskDetailParts.join(" · "))}</div>
      `;
      diskContainer.appendChild(card);
    });

    // Rede (velocidade medida)
    const net = specs.network_speed;
    const downloadLevel = levelByMetric["network_download"] || "normal";
    const uploadLevel = levelByMetric["network_upload"] || "normal";
    const downloadEl = document.getElementById("sys-net-download");
    const uploadEl = document.getElementById("sys-net-upload");
    downloadEl.textContent = slNumberOrNull(net?.download_mbps)?.toFixed(0) ?? "—";
    uploadEl.textContent = slNumberOrNull(net?.upload_mbps)?.toFixed(0) ?? "—";
    downloadEl.className = `level-${downloadLevel}`;
    uploadEl.className = `level-${uploadLevel}`;
    const netBarLevel =
      downloadLevel === "critico" || uploadLevel === "critico"
        ? "critico"
        : downloadLevel === "aviso" || uploadLevel === "aviso"
          ? "aviso"
          : "normal";
    setProgressBar(document.getElementById("sys-net-bar"), net ? 100 : null, netBarLevel);
    document.getElementById("sys-net-sub").textContent = net
      ? `Última medição: ${formatTimestamp(net.measured_at)} · ping ${slNumberOrNull(net.ping_ms)?.toFixed(0) ?? "—"} ms · ${net.server || "-"}`
      : "Ainda sem medição de rede";

    // Interfaces de rede desta máquina (separado da medição de velocidade acima)
    renderNetworkInterfaces(specs.network || []);

    // Alertas de sistema ativos
    const list = document.getElementById("system-alerts-list");
    const active = alertsData.active_violations || [];
    if (active.length === 0) {
      list.innerHTML = '<p class="empty-state">Sem violações ativas</p>';
    } else {
      list.innerHTML = "";
      active.forEach((v) => {
        const item = document.createElement("div");
        item.className = `system-alert-item level-${v.level}`;
        item.innerHTML = `
          <span><strong>${escapeHtml(metricLabel(v.metric))}</strong> — ${v.level === "critico" ? "Crítico" : "Aviso"}</span>
          <span>a decorrer há ${escapeHtml(formatDuration(v.duration_seconds))}</span>
        `;
        list.appendChild(item);
      });
    }

    renderViolationsHistory(historyData.history || []);
    renderSystemUsageChart(usageHistoryData.history || []);
    renderSystemSummaryCard({
      cpuPct,
      cpuLvl,
      ramPct,
      ramLvl,
      worstDisk,
      worstDiskLevel,
      downloadLevel,
      uploadLevel,
      networkMeasured: Boolean(net),
      activeCount: active.length,
      criticalCount: active.filter((v) => v.level === "critico").length,
    });
    renderPanelError("#system-panel", null);
  } catch (err) {
    console.error(err);
    renderPanelError("#system-panel", panelErrorText(err, "Não foi possível ler o estado desta máquina."));
    resetSystemPanelValues();
    resetSystemSummaryCard();
  }
}

async function forceSpeedtest() {
  const btn = document.getElementById("speedtest-btn");
  btn.disabled = true;
  btn.textContent = "⏳ A medir...";
  try {
    await apiRequest("/api/system/speedtest", { method: "POST" });
    await loadSystemPanel();
  } catch (err) {
    console.error(err);
    renderPanelError("#system-panel", "Não foi possível medir a rede. " + panelErrorText(err, "Tenta de novo daqui a pouco."));
  } finally {
    btn.disabled = false;
    btn.textContent = "🔄 Medir agora";
  }
}

document.getElementById("speedtest-btn").addEventListener("click", forceSpeedtest);

async function exportReport() {
  const btn = document.getElementById("export-report-btn");
  const hours = windowSelect.value;
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

// --- Gráficos (Chart.js) ---

Chart.defaults.font.family = "'Inter', -apple-system, BlinkMacSystemFont, sans-serif";
Chart.defaults.color = "#666";

const charts = {};

function renderChart(canvasId, config) {
  const canvas = document.getElementById(canvasId);
  if (charts[canvasId]) {
    charts[canvasId].data = config.data;
    charts[canvasId].options = config.options;
    charts[canvasId].update("none"); // sem animação: um refresh não deve "piscar" os gráficos
    return;
  }
  charts[canvasId] = new Chart(canvas.getContext("2d"), config);
}

function renderAlertsTimelineChart(alerts, hours) {
  const groupByDay = hours > 48; // janelas curtas agrupam por hora, longas por dia
  const sorted = [...(alerts || [])]
    .filter((a) => a.timestamp)
    .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

  const buckets = new Map();
  sorted.forEach((a) => {
    const d = new Date(a.timestamp);
    const key = groupByDay
      ? d.toLocaleDateString("pt-PT")
      : `${d.toLocaleDateString("pt-PT")} ${String(d.getHours()).padStart(2, "0")}h`;
    buckets.set(key, (buckets.get(key) || 0) + 1);
  });

  renderChart("chart-alerts-timeline", {
    type: "line",
    data: {
      labels: [...buckets.keys()],
      datasets: [{
        label: "Alertas",
        data: [...buckets.values()],
        borderColor: "#0b7d92",
        backgroundColor: "rgba(11,125,146,0.12)",
        fill: true,
        tension: 0.25,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
    },
  });
}

function renderSeverityDonutChart(bySeverity) {
  const order = ["critical", "high", "medium", "low", "info"];
  const colorMap = { critical: "#e74c3c", high: "#f39c12", medium: "#d4ac0d", low: "#27ae60", info: "#3498db" };
  const labelMap = { critical: "Crítico", high: "Alto", medium: "Médio", low: "Baixo", info: "Info" };

  const labels = [];
  const values = [];
  const colors = [];
  order.forEach((sev) => {
    const count = bySeverity?.[sev] || 0;
    if (count > 0) {
      labels.push(labelMap[sev]);
      values.push(count);
      colors.push(colorMap[sev]);
    }
  });

  renderChart("chart-severity-donut", {
    type: "doughnut",
    data: { labels, datasets: [{ data: values, backgroundColor: colors, borderWidth: 0 }] },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { position: "bottom", labels: { boxWidth: 12, font: { size: 11 } } } },
    },
  });
}

function renderTopEventsChart(topEvents) {
  const sorted = [...(topEvents || [])].sort((a, b) => b.count - a.count).slice(0, 10);

  renderChart("chart-top-events", {
    type: "bar",
    data: {
      labels: sorted.map((e) => `#${e.event_id}`),
      datasets: [{ label: "Ocorrências", data: sorted.map((e) => e.count), backgroundColor: "#0b7d92" }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: { callbacks: { label: (item) => `${sorted[item.dataIndex].name}: ${item.raw}` } },
      },
      scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
    },
  });
}

// Histórico de uso de CPU/RAM/disco: vem de /api/system/usage-history, um
// buffer em memória no backend (~1h a 30s/amostra) alimentado pelo loop de
// background — persiste entre recargas da página e é partilhado por
// qualquer separador que abra o dashboard.
function renderSystemUsageChart(history) {
  const diskLabel = history.length && history[history.length - 1].disk_mountpoint
    ? `Disco ${history[history.length - 1].disk_mountpoint} %`
    : "Disco %";

  renderChart("chart-system-usage", {
    type: "line",
    data: {
      labels: history.map((s) => new Date(s.timestamp).toLocaleTimeString("pt-PT", { hour: "2-digit", minute: "2-digit" })),
      datasets: [
        { label: "CPU %", data: history.map((s) => s.cpu_percent), borderColor: "#0b7d92", backgroundColor: "rgba(11,125,146,0.08)", fill: true, tension: 0.3 },
        { label: "RAM %", data: history.map((s) => s.ram_percent), borderColor: "#8e44ad", backgroundColor: "rgba(142,68,173,0.08)", fill: true, tension: 0.3 },
        { label: diskLabel, data: history.map((s) => s.disk_percent), borderColor: "#16a085", backgroundColor: "rgba(22,160,133,0.08)", fill: true, tension: 0.3 },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { position: "bottom", labels: { boxWidth: 12, font: { size: 11 } } } },
      scales: { y: { beginAtZero: true, max: 100 } },
    },
  });
}

// --- Painel: Ciclo de Vida de Contas (tab-lifecycle) ---

// event_id do Windows -> rótulo em português para a coluna "Tipo".
const lifecycleEventLabels = {
  4720: "Criada",
  4722: "Ativada",
  4725: "Desativada",
  4726: "Eliminada",
  4740: "Bloqueada",
};

function lifecycleEventTypeLabel(eventId) {
  return lifecycleEventLabels[eventId] || String(eventId);
}

// Guarda o último resultado do fetch para os filtros (tipo/utilizador)
// filtrarem client-side sem precisar de um novo pedido ao backend.
let lastLifecycleEvents = [];

function renderLifecycleEventsTable(events) {
  const tbody = document.getElementById("lifecycle-events-body");
  tbody.innerHTML = "";

  if (!events || events.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-state">Sem eventos neste período</td></tr>';
    return;
  }

  events.forEach((ev) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono">${escapeHtml(formatTimestamp(ev.timestamp))}</td>
      <td>${escapeHtml(lifecycleEventTypeLabel(ev.event_id))}</td>
      <td>${escapeHtml(ev.target_user)}</td>
      <td>${escapeHtml(ev.executed_by)}</td>
      <td>${escapeHtml(ev.agent_name)}</td>
    `;
    tbody.appendChild(tr);
  });
}

function applyLifecycleFilters() {
  const typeFilter = document.getElementById("lifecycle-type-filter").value;
  const userFilter = document.getElementById("lifecycle-user-filter").value.trim().toLowerCase();

  let filtered = lastLifecycleEvents;
  if (typeFilter) {
    filtered = filtered.filter((ev) => String(ev.event_id) === typeFilter);
  }
  if (userFilter) {
    filtered = filtered.filter((ev) => (ev.target_user || "").toLowerCase().includes(userFilter));
  }
  renderLifecycleEventsTable(filtered);
}

function renderLifecycleTimelineChart(timeline) {
  const data = timeline || [];
  renderChart("chart-lifecycle-timeline", {
    type: "line",
    data: {
      labels: data.map((t) => t.date),
      datasets: [
        { label: "Criadas", data: data.map((t) => t.created), borderColor: "#0b7d92", backgroundColor: "rgba(11,125,146,0.08)", fill: false, tension: 0.25 },
        { label: "Ativadas", data: data.map((t) => t.activated), borderColor: "#16a085", backgroundColor: "rgba(22,160,133,0.08)", fill: false, tension: 0.25 },
        { label: "Desativadas", data: data.map((t) => t.disabled), borderColor: "#f39c12", backgroundColor: "rgba(243,156,18,0.08)", fill: false, tension: 0.25 },
        { label: "Eliminadas", data: data.map((t) => t.deleted), borderColor: "#e74c3c", backgroundColor: "rgba(231,76,60,0.08)", fill: false, tension: 0.25 },
        { label: "Bloqueadas", data: data.map((t) => t.locked), borderColor: "#8e44ad", backgroundColor: "rgba(142,68,173,0.08)", fill: false, tension: 0.25 },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { position: "bottom", labels: { boxWidth: 12, font: { size: 11 } } } },
      scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
    },
  });
}

async function loadLifecyclePanel(days) {
  try {
    const data = await fetchJSON(`/api/lifecycle?days=${days}`);
    renderPanelError("#lifecycle-panel", null);

    const counts = data.counts || {};
    document.getElementById("kpi-lifecycle-created").textContent = counts.created ?? 0;
    document.getElementById("kpi-lifecycle-activated").textContent = counts.activated ?? 0;
    document.getElementById("kpi-lifecycle-disabled").textContent = counts.disabled ?? 0;
    document.getElementById("kpi-lifecycle-deleted").textContent = counts.deleted ?? 0;
    document.getElementById("kpi-lifecycle-locked").textContent = counts.locked ?? 0;

    renderLifecycleTimelineChart(data.timeline || []);

    lastLifecycleEvents = data.events || [];
    applyLifecycleFilters();

    renderDetections("lifecycle-detections", data.detections || []);
  } catch (err) {
    console.error(err);
    renderPanelError("#lifecycle-panel", panelErrorText(err, "Erro ao carregar o painel de ciclo de vida."));
  }
}

document.getElementById("lifecycle-type-filter").addEventListener("change", applyLifecycleFilters);
document.getElementById("lifecycle-user-filter").addEventListener("input", applyLifecycleFilters);

// --- Painel: Auditoria de Privilégios (tab-privileges) ---

function renderPrivilegesDeviationsTable(deviations) {
  const tbody = document.getElementById("privileges-deviations-body");
  tbody.innerHTML = "";

  if (!deviations || deviations.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Sem desvios ao baseline neste período</td></tr>';
    return;
  }

  deviations.forEach((d) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(d.user)}</td>
      <td>${escapeHtml(d.cargo)}</td>
      <td>${escapeHtml(d.group)}</td>
      <td class="wrap">${escapeHtml(d.reason)}</td>
      <td>${escapeHtml(d.executed_by)}</td>
      <td class="mono">${escapeHtml(formatTimestamp(d.timestamp))}</td>
    `;
    tbody.appendChild(tr);
  });
}

// Bloco de destaque (sempre visível, ver .critical-additions-block em
// style.css) para adições a grupos críticos — zero é informação de auditoria,
// por isso nunca escondemos o bloco, só mudamos a mensagem.
function renderCriticalAdditionsBlock(additions) {
  const container = document.getElementById("privileges-critical-block");

  if (!additions || additions.length === 0) {
    container.innerHTML = '<p class="empty-state">Nenhuma adição a grupo crítico neste período</p>';
    return;
  }

  container.innerHTML = additions
    .map(
      (a) => `
        <div class="bf-item">
          <span><strong>${escapeHtml(a.user)}</strong> adicionado a <strong>${escapeHtml(a.group)}</strong> por ${escapeHtml(a.executed_by)}</span>
          <span>${escapeHtml(formatTimestamp(a.timestamp))}</span>
        </div>
      `
    )
    .join("");
}

function renderPrivilegesGroupsChart(groupRanking) {
  const sorted = [...(groupRanking || [])].sort((a, b) => b.count - a.count).slice(0, 10);

  renderChart("chart-privileges-groups", {
    type: "bar",
    data: {
      labels: sorted.map((g) => g.group),
      datasets: [{ label: "Movimentações", data: sorted.map((g) => g.count), backgroundColor: "#0b7d92" }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
    },
  });
}

async function loadPrivilegesPanel(days) {
  try {
    const data = await fetchJSON(`/api/privileges?days=${days}`);
    renderPanelError("#privileges-panel", null);

    document.getElementById("kpi-privileges-total").textContent = data.total_movements ?? 0;
    document.getElementById("kpi-privileges-deviations").textContent = (data.deviations || []).length;
    document.getElementById("kpi-privileges-critical").textContent = (data.critical_additions || []).length;

    renderPrivilegesGroupsChart(data.group_ranking || []);
    renderPrivilegesDeviationsTable(data.deviations || []);
    renderCriticalAdditionsBlock(data.critical_additions || []);
  } catch (err) {
    console.error(err);
    renderPanelError("#privileges-panel", panelErrorText(err, "Erro ao carregar o painel de privilégios."));
  }
}

// --- Painel: Contas Privilegiadas (tab-admin-activity) ---

function renderAdminEventComparisonChart(eventCounts) {
  const admin = eventCounts?.admin ?? 0;
  const normal = eventCounts?.normal ?? 0;

  renderChart("chart-admin-event-comparison", {
    type: "doughnut",
    data: {
      labels: ["Administrativos", "Normais"],
      datasets: [{ data: [admin, normal], backgroundColor: ["#8e44ad", "#0b7d92"], borderWidth: 0 }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { position: "bottom", labels: { boxWidth: 12, font: { size: 11 } } } },
    },
  });
}

// Procura o timestamp mais recente entre scheduled_tasks/processes cujo user
// corresponda à conta indicada; devolve null se não encontrar nenhum (nunca
// inventamos um valor, a coluna "Última Atividade" mostra "—" nesse caso).
function findLastActivity(user, scheduledTasks, processes) {
  const events = [...(scheduledTasks || []), ...(processes || [])].filter(
    (e) => e.user === user && e.timestamp
  );
  if (events.length === 0) return null;
  return events.reduce((latest, e) => (new Date(e.timestamp) > new Date(latest.timestamp) ? e : latest)).timestamp;
}

function renderAdminAccountsTable(accounts, specialPrivilegesByUser, scheduledTasks, processes) {
  const tbody = document.getElementById("admin-accounts-body");
  tbody.innerHTML = "";

  if (!accounts || accounts.length === 0) {
    tbody.innerHTML = '<tr><td colspan="3" class="empty-state">Nenhuma conta administrativa identificada neste período</td></tr>';
    return;
  }

  accounts.forEach((user) => {
    const count = specialPrivilegesByUser?.[user] ?? 0;
    const lastActivity = findLastActivity(user, scheduledTasks, processes);
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(user)}</td>
      <td>${escapeHtml(count)}</td>
      <td class="mono">${lastActivity ? escapeHtml(formatTimestamp(lastActivity)) : "—"}</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderAdminScheduledTasksTable(tasks) {
  const tbody = document.getElementById("admin-scheduled-tasks-body");
  tbody.innerHTML = "";

  if (!tasks || tasks.length === 0) {
    tbody.innerHTML = '<tr><td colspan="3" class="empty-state">Sem tarefas agendadas por contas administrativas neste período</td></tr>';
    return;
  }

  tasks.forEach((t) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(t.user)}</td>
      <td class="mono">${escapeHtml(formatTimestamp(t.timestamp))}</td>
      <td>${escapeHtml(t.agent_name)}</td>
    `;
    tbody.appendChild(tr);
  });
}

async function loadAdminActivityPanel(days) {
  try {
    const data = await fetchJSON(`/api/admin-activity?days=${days}`);
    renderPanelError("#admin-activity-panel", null);

    renderAdminEventComparisonChart(data.event_counts || {});
    renderAdminAccountsTable(
      data.admin_accounts || [],
      data.special_privileges_by_user || {},
      data.scheduled_tasks || [],
      data.processes || []
    );
    renderAdminScheduledTasksTable(data.scheduled_tasks || []);
    renderDetections("admin-activity-detections", data.detections || []);
  } catch (err) {
    console.error(err);
    renderPanelError("#admin-activity-panel", panelErrorText(err, "Erro ao carregar o painel de contas administrativas."));
  }
}

// --- Painel: ML Anomalias (tab-ml-anomalies) ---

function renderMlAnomaliesTable(results) {
  const tbody = document.getElementById("ml-anomalies-body");
  tbody.innerHTML = "";

  if (!results || results.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty-state">Sem eventos neste período</td></tr>';
    return;
  }

  results.forEach((r) => {
    const tr = document.createElement("tr");
    tr.className = r.agreement === "diverge" ? "row-diverge" : "";
    const mlScore = slNumberOrNull(r.ml_score);
    const agreementLabel = r.agreement === "agree" ? "✅ Concorda" : r.agreement === "diverge" ? "⚡ Diverge" : "—";
    tr.innerHTML = `
      <td class="mono">${escapeHtml(formatTimestamp(r.timestamp))}</td>
      <td>${escapeHtml(r.agent_name)}</td>
      <td>${escapeHtml(r.target_user)}</td>
      <td>${escapeHtml(String(r.windows_event_id))}</td>
      <td>${severityBadge(r.severity)}</td>
      <td class="mono">${escapeHtml(mlScore === null ? "—" : mlScore.toFixed(4))}</td>
      <td>${r.ml_is_anomaly ? "⚠️ Sim" : "Não"}</td>
      <td><span class="agreement-badge agreement-${escapeHtml(String(r.agreement))}">${escapeHtml(agreementLabel)}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

async function loadMlAnomaliesPanel(hours) {
  try {
    const data = await fetchJSON(`/api/ml-anomalies?hours=${hours}`);
    renderPanelError("#ml-anomalies-panel", null);

    document.getElementById("kpi-ml-total").textContent = data.total ?? 0;
    document.getElementById("kpi-ml-anomalies").textContent = data.ml_anomalies_count ?? 0;
    document.getElementById("kpi-ml-rule-flagged").textContent = data.rule_flagged_count ?? 0;
    document.getElementById("kpi-ml-agreement").textContent = slAgreementText(data.agree_count, data.total);
    document.getElementById("kpi-ml-diverge").textContent = data.diverge_count ?? 0;

    renderMlAnomaliesTable(data.results || []);
  } catch (err) {
    console.error(err);
    if (err.status === 503) {
      renderPanelError("#ml-anomalies-panel", "Modelo de ML ainda não foi treinado. Corre scripts/train_anomaly_model.py.");
    } else {
      renderPanelError("#ml-anomalies-panel", panelErrorText(err, "Erro ao carregar o painel de ML."));
    }
  }
}

// --- Painel: Conformidade (tab-compliance) ---

function renderComplianceTable(alerts) {
  const tbody = document.getElementById("compliance-body");
  tbody.innerHTML = "";

  if (!alerts || alerts.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty-state">Sem alertas neste período</td></tr>';
    return;
  }

  alerts.forEach((a) => {
    const tr = document.createElement("tr");
    const c = a.compliance || {};
    const cell = (v) => {
      const { label, title } = slComplianceVerdict(v);
      return `<td title="${escapeHtml(title)}">${escapeHtml(label)}</td>`;
    };
    tr.innerHTML = `
      <td class="mono">${escapeHtml(formatTimestamp(a.timestamp))}</td>
      <td>${escapeHtml(a.agent_name)}</td>
      <td>${escapeHtml(a.friendly_name)}</td>
      <td>${severityBadge(a.severity)}</td>
      ${cell(c.rgpd)}
      ${cell(c.nis2)}
      ${cell(c.ai_act)}
    `;
    tbody.appendChild(tr);
  });
}

async function loadCompliancePanel(hours) {
  try {
    const data = await fetchJSON(`/api/compliance?hours=${hours}`);
    renderPanelError("#compliance-panel", null);

    document.getElementById("kpi-compliance-total").textContent = data.total ?? 0;
    document.getElementById("kpi-compliance-rgpd").textContent = (data.summary && data.summary.rgpd && data.summary.rgpd.aplicavel) ?? 0;
    document.getElementById("kpi-compliance-nis2").textContent = (data.summary && data.summary.nis2 && data.summary.nis2.aplicavel) ?? 0;
    document.getElementById("kpi-compliance-ai-act").textContent = (data.summary && data.summary.ai_act && data.summary.ai_act.aplicavel) ?? 0;

    const profile = data.org_profile || {};
    const orgNote = document.getElementById("compliance-org-note");
    if (orgNote) {
      orgNote.textContent =
        `Perfil da organização: ${profile.nome || "-"} — ` +
        `sujeita a NIS2: ${profile.estatuto_nis2_aplicavel ? "sim" : "não"}, ` +
        `componentes de IA ativos: ${profile.tem_componentes_ia_ativos ? "sim" : "não"}.`;
    }

    renderComplianceTable(data.alerts || []);
  } catch (err) {
    console.error(err);
    renderPanelError("#compliance-panel", panelErrorText(err, "Erro ao carregar o painel de conformidade."));
  }
}

// Ponto de entrada dos painéis novos (ciclo de vida, privilégios, contas
// admin, ML anomalias, conformidade) — independente de refreshDashboard()
// (painéis Wazuh antigos) e do window-select (horas); usa sempre
// period-select (dias) no momento da chamada, nunca reatribui esse .value.
async function refreshNewPanels() {
  const days = periodSelect.value;
  await Promise.allSettled([
    loadLifecyclePanel(days),
    loadPrivilegesPanel(days),
    loadAdminActivityPanel(days),
    // /api/ml-anomalies usa "hours" (Query(24, ge=1, le=168)), não "dias" como
    // os outros 3 painéis — convertemos e limitamos ao máximo aceite pelo
    // endpoint (168h = 7 dias), para "30 dias"/"90 dias" mostrarem sempre os
    // últimos 7 dias em vez de serem lidos como 30/90 HORAS.
    loadMlAnomaliesPanel(Math.min(Number(days) * 24, 168)),
    // /api/compliance tem a mesma assinatura de /api/ml-anomalies
    // (Query(24, ge=1, le=168)) — mesma conversão dias->horas.
    loadCompliancePanel(Math.min(Number(days) * 24, 168)),
  ]);
}

periodSelect.addEventListener("change", refreshNewPanels);

async function refreshDashboard() {
  const hours = windowSelect.value;
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
// Navegação em sidebar (Roadmap v2, R1): itens com data-tab abrem um painel
// real; itens com data-planned (is-planned) ainda não têm fonte de dados e
// abrem o painel genérico #tab-planned com "Sem dados" — nunca dados
// inventados.
const navItems = document.querySelectorAll(".nav-item");
const tabContents = document.querySelectorAll(".tab-content");
const sidebarEl = document.getElementById("sidebar");
const sidebarToggle = document.getElementById("sidebar-toggle");
const PLANNED_HASH_PREFIX = "planned:";

function setSidebarOpen(open) {
  sidebarEl.classList.toggle("open", open);
  sidebarToggle.setAttribute("aria-expanded", String(open));
}

function showTab(contentId, activeItem) {
  navItems.forEach((b) => {
    const isActive = b === activeItem;
    b.classList.toggle("active", isActive);
    if (isActive) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  });
  tabContents.forEach((c) => c.classList.toggle("active", c.id === contentId));
  appCurrentTabId = (activeItem && activeItem.dataset.tab) || null;
  if (appCurrentTabId) rtActivate(appCurrentTabId);
  else rtDeactivate();
  if (activeItem) activeItem.closest("details")?.setAttribute("open", "");
  setSidebarOpen(false);
  // Canvas nascem com tamanho 0 dentro de uma aba escondida (display:none);
  // o Chart.js não deteta sozinho quando ficam visíveis, por isso forçamos
  // um resize ao trocar de aba.
  Object.values(charts).forEach((chart) => chart.resize());
}

function activateTab(tabName) {
  const item = document.querySelector(`.nav-item[data-tab="${CSS.escape(tabName)}"]`);
  if (!item) return;
  showTab(`tab-${tabName}`, item);
  history.replaceState(null, "", `#${tabName}`);
}

function activatePlanned(item) {
  document.getElementById("planned-title").textContent = item.dataset.label;
  document.getElementById("planned-phase").textContent = item.dataset.planned;
  showTab("tab-planned", item);
  history.replaceState(null, "", `#${PLANNED_HASH_PREFIX}${item.dataset.label}`);
}

navItems.forEach((btn) => {
  btn.addEventListener("click", () => {
    if (btn.dataset.planned) activatePlanned(btn);
    else activateTab(btn.dataset.tab);
  });
});

sidebarToggle.addEventListener("click", () => setSidebarOpen(!sidebarEl.classList.contains("open")));

document.getElementById("system-summary-card").addEventListener("click", () => activateTab("system"));

// --- Ciclo de vida das abas (W3.2) ---
// Formato do id de aba para o router (rtActivate/rtRegisterTab): o valor de
// `data-tab` do item do nav em index.html, SEM o prefixo "tab-" da secção
// (nav `data-tab="admin-activity"` <-> `<div id="tab-admin-activity">` <-> id
// "admin-activity"). Itens `data-planned` não têm id: chamam rtDeactivate().
// "overview" NÃO é registado aqui (é de overview.js); cada módulo regista só
// as suas abas, um id repetido rebenta o registo.
let appCurrentTabId = "overview"; // Overview vem ativa no HTML

function appPeriodDays() {
  return periodSelect.value;
}
function appPeriodHours() {
  return Math.min(Number(appPeriodDays()) * 24, 168);
}

function appRegisterTabs() {
  const refreshMs = 30000;
  rtRegisterTab({ id: "alerts", refreshMs, load: () => loadAlerts(windowSelect.value, severityFilter.value) });
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

// Deep link: #redblue, #alerts, #planned:Incidentes… (sem hash válido fica
// na Visão Geral, que já vem ativa no HTML).
function applyHash() {
  let hash = "";
  try {
    hash = decodeURIComponent(location.hash.slice(1));
  } catch (_) {
    return; // hash malformado (ex.: #%E0): tratar como sem hash
  }
  if (!hash) return;
  if (hash.startsWith(PLANNED_HASH_PREFIX)) {
    const label = hash.slice(PLANNED_HASH_PREFIX.length);
    const item = [...navItems].find((b) => b.dataset.planned && b.dataset.label === label);
    if (item) activatePlanned(item);
  } else {
    activateTab(hash);
  }
}
window.addEventListener("hashchange", applyHash);
applyHash();

// Carrega ao abrir e liga o WebSocket de tempo real (/ws/alerts); o polling
// fixo de 30s só volta a existir via startPollFallback() se a ligação
// WebSocket falhar definitivamente (ver connectWebSocket()).
refreshDashboard();
connectWebSocket();

// Abas de outros módulos registam-se depois de app.js: quando tudo carregou,
// se a aba atual (ex.: Overview, ou um deep link) ainda não está ativa no
// router, ativa-a agora.
window.addEventListener("load", () => {
  const id = appCurrentTabId;
  if (id && rtRouter.getActiveId() !== id) rtActivate(id);
});
