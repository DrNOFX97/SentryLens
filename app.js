// Dashboard de Cibersegurança — lógica de frontend
// Consome a API FastAPI (backend/main.py) e preenche a interface

const API_BASE = "http://localhost:8001";

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

function setStatus(ok) {
  statusIndicator.textContent = ok ? "● ligado ao Wazuh" : "● sem ligação";
  statusIndicator.className = "status-indicator " + (ok ? "status-ok" : "status-error");
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
  if (!ts) return "-";
  try {
    return new Date(ts).toLocaleString("pt-PT");
  } catch {
    return ts;
  }
}

async function fetchJSON(path) {
  const response = await fetch(`${API_BASE}${path}`);
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail || `Erro HTTP ${response.status}`);
  }
  return response.json();
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
    container.innerHTML = '<p class="empty-state">Sem deteções neste período</p>';
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
  banner.innerHTML = `⚠️ ${escapeHtml(message)}`;
}

async function loadStats(hours) {
  const stats = await fetchJSON(`/api/stats?hours=${hours}`);

  document.getElementById("kpi-total").textContent = stats.total_alerts ?? 0;
  document.getElementById("kpi-critical").textContent = stats.by_severity?.critical ?? 0;
  document.getElementById("kpi-high").textContent = stats.by_severity?.high ?? 0;
  document.getElementById("kpi-medium").textContent = stats.by_severity?.medium ?? 0;
  document.getElementById("kpi-low").textContent = stats.by_severity?.low ?? 0;

  renderSeverityDonutChart(stats.by_severity);
  renderTopEventsChart(stats.top_events);
}

async function loadAgents() {
  const data = await fetchJSON(`/api/agents`);
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

  const data = await fetchJSON(url);
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
  const data = await fetchJSON(`/api/brute-force?hours=${hours}`);
  const panel = document.getElementById("brute-force-panel");
  const list = document.getElementById("brute-force-list");

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

// CPU não tem threshold definido no backend (system_monitor.THRESHOLDS só
// cobre RAM/disco/rede) — usamos aqui um limiar só visual, não ligado ao
// sistema de alertas/histórico.
function cpuLevel(usagePercent) {
  if (usagePercent >= 95) return "critico";
  if (usagePercent >= 80) return "aviso";
  return "normal";
}

function metricLabel(metric) {
  if (metric === "ram") return "RAM";
  if (metric === "network_download") return "Rede (download)";
  if (metric === "network_upload") return "Rede (upload)";
  if (metric.startsWith("disk:")) return `Disco ${metric.slice(5)}`;
  return metric;
}

function setProgressBar(barEl, percent, level) {
  barEl.style.width = `${Math.min(100, Math.max(0, percent))}%`;
  barEl.className = `progress-fill level-${level}`;
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
  cpuPct, cpuLvl, ramPct, ramLvl, worstDisk, worstDiskLevel, downloadLevel, uploadLevel, activeCount, criticalCount,
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
  document.getElementById("summary-cpu-pct").textContent = `${cpuPct.toFixed(0)}%`;

  setProgressBar(document.getElementById("summary-ram-bar"), ramPct, ramLvl);
  document.getElementById("summary-ram-pct").textContent = `${ramPct.toFixed(0)}%`;

  if (worstDisk) {
    setProgressBar(document.getElementById("summary-disk-bar"), worstDisk.usage_percent, worstDiskLevel);
    document.getElementById("summary-disk-pct").textContent = `${worstDisk.usage_percent.toFixed(0)}%`;
  }

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
  setProgressBar(document.getElementById("summary-network-bar"), 100, netLevel);
  document.getElementById("summary-network-status").textContent = netLabelMap[netLevel];
}

async function loadSystemPanel() {
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
  const cpuLvl = cpuLevel(cpuPct);
  document.getElementById("sys-cpu-value").textContent = `${cpuPct.toFixed(1)}%`;
  setProgressBar(document.getElementById("sys-cpu-bar"), cpuPct, cpuLvl);
  const cpuModelLine = specs.cpu.frequency_mhz
    ? `${specs.cpu.model} @ ${(specs.cpu.frequency_mhz / 1000).toFixed(2)} GHz`
    : specs.cpu.model;
  document.getElementById("sys-cpu-detail").textContent =
    `${specs.cpu.physical_cores} núcleos físicos / ${specs.cpu.logical_cores} lógicos · ${cpuModelLine}`;

  // RAM
  const ramPct = specs.ram.usage_percent;
  const ramLvl = levelByMetric["ram"] || "normal";
  document.getElementById("sys-ram-value").textContent = `${ramPct.toFixed(1)}%`;
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
        <span class="system-card-value">${disk.usage_percent.toFixed(1)}%</span>
      </div>
      <div class="progress-track"><div class="progress-fill level-${escapeHtml(level)}" style="width:${Math.min(100, disk.usage_percent)}%"></div></div>
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
  downloadEl.textContent = net ? net.download_mbps.toFixed(0) : "—";
  uploadEl.textContent = net ? net.upload_mbps.toFixed(0) : "—";
  downloadEl.className = `level-${downloadLevel}`;
  uploadEl.className = `level-${uploadLevel}`;
  const netBarLevel =
    downloadLevel === "critico" || uploadLevel === "critico"
      ? "critico"
      : downloadLevel === "aviso" || uploadLevel === "aviso"
        ? "aviso"
        : "normal";
  setProgressBar(document.getElementById("sys-net-bar"), 100, netBarLevel);
  document.getElementById("sys-net-sub").textContent = net
    ? `Última medição: ${formatTimestamp(net.measured_at)} · ping ${net.ping_ms != null ? net.ping_ms.toFixed(0) : "—"} ms · ${net.server || "-"}`
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
    activeCount: active.length,
    criticalCount: active.filter((v) => v.level === "critico").length,
  });
}

async function forceSpeedtest() {
  const btn = document.getElementById("speedtest-btn");
  btn.disabled = true;
  btn.textContent = "⏳ A medir...";
  try {
    const response = await fetch(`${API_BASE}/api/system/speedtest`, { method: "POST" });
    if (!response.ok) throw new Error(`Erro HTTP ${response.status}`);
    await loadSystemPanel();
  } catch (err) {
    console.error(err);
  } finally {
    btn.disabled = false;
    btn.textContent = "🔄 Medir agora";
  }
}

document.getElementById("speedtest-btn").addEventListener("click", forceSpeedtest);

// --- Gráficos (Chart.js) ---

Chart.defaults.font.family = "'Inter', -apple-system, BlinkMacSystemFont, sans-serif";
Chart.defaults.color = "#666";

const charts = {};

function renderChart(canvasId, config) {
  const canvas = document.getElementById(canvasId);
  if (charts[canvasId]) {
    charts[canvasId].data = config.data;
    charts[canvasId].options = config.options;
    charts[canvasId].update();
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
    renderPanelError("#lifecycle-panel", err.message || "Erro ao carregar o painel de ciclo de vida.");
  }
}

document.getElementById("lifecycle-type-filter").addEventListener("change", applyLifecycleFilters);
document.getElementById("lifecycle-user-filter").addEventListener("input", applyLifecycleFilters);

// Ponto de entrada dos painéis novos (ciclo de vida, privilégios, contas
// admin) — independente de refreshDashboard() (painéis Wazuh antigos) e do
// window-select (horas); usa sempre period-select (dias) no momento da
// chamada, nunca reatribui esse .value.
//
// Estrutura preparada para os painéis 2 e 3 (privilégios, contas admin):
// quando existirem loadPrivilegesPanel(days)/loadAdminActivityPanel(days),
// basta acrescentá-los a este array do Promise.allSettled.
async function refreshNewPanels() {
  const days = periodSelect.value;
  await Promise.allSettled([
    loadLifecyclePanel(days),
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
    setStatus(true);
  } catch (err) {
    console.error(err);
    setStatus(false);
  }
}

refreshBtn.addEventListener("click", refreshDashboard);
windowSelect.addEventListener("change", refreshDashboard);
severityFilter.addEventListener("change", refreshDashboard);

// --- Abas ---
// Todos os dados são sempre carregados em background (refreshDashboard),
// as abas só controlam o que está visível — evita reestruturar a lógica
// assíncrona por causa da navegação.
const tabButtons = document.querySelectorAll(".tab-btn");
const tabContents = document.querySelectorAll(".tab-content");

function activateTab(tabName) {
  tabButtons.forEach((b) => b.classList.toggle("active", b.dataset.tab === tabName));
  tabContents.forEach((c) => c.classList.toggle("active", c.id === `tab-${tabName}`));
  // Canvas nascem com tamanho 0 dentro de uma aba escondida (display:none);
  // o Chart.js não deteta sozinho quando ficam visíveis, por isso forçamos
  // um resize ao trocar de aba.
  Object.values(charts).forEach((chart) => chart.resize());
}

tabButtons.forEach((btn) => {
  btn.addEventListener("click", () => activateTab(btn.dataset.tab));
});

document.getElementById("system-summary-card").addEventListener("click", () => activateTab("system"));

// Carrega ao abrir e depois atualiza automaticamente a cada 30s
refreshDashboard();
setInterval(refreshDashboard, 30000);

// Painéis novos (ciclo de vida, privilégios, contas admin) — independentes
// dos painéis Wazuh acima, correm no seu próprio ciclo de 30s.
refreshNewPanels();
setInterval(refreshNewPanels, 30000);
