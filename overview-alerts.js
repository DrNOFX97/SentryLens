// Visão geral: alertas, estatísticas, agentes, brute-force e gráficos (Chart.js).

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
    htmRender(document.getElementById("agents-table-body"),
      htmlT`<tr><td colspan="5" class="error-state" role="alert">${panelErrorText(err, "Erro ao carregar agentes.")}</td></tr>`);
    return;
  }
  const activeCount = (data.agents || []).filter((a) => a.status === "active").length;
  document.getElementById("kpi-agents").textContent = activeCount;

  const tbody = document.getElementById("agents-table-body");
  tbody.replaceChildren();

  if (!data.agents || data.agents.length === 0) {
    htmRender(tbody, htmlT`<tr><td colspan="5" class="empty-state">Nenhum agente encontrado</td></tr>`);
    return;
  }

  data.agents.forEach((agent) => {
    const tr = document.createElement("tr");
    htmRender(tr, htmlT`
      <td>${agent.name}</td>
      <td class="mono">${agent.ip || "-"}</td>
      <td>${agent.os || "-"}</td>
      <td><span class="agent-status ${agent.status}">${agent.status}</span></td>
      <td class="mono">${formatTimestamp(agent.last_keep_alive)}</td>
    `);
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
    htmRender(document.getElementById("alerts-table-body"),
      htmlT`<tr><td colspan="9" class="empty-state">Indisponível.</td></tr>`);
    return;
  }
  renderPanelError("#alerts-panel", null);
  const tbody = document.getElementById("alerts-table-body");
  tbody.replaceChildren();

  if (!data.alerts || data.alerts.length === 0) {
    htmRender(tbody, htmlT`<tr><td colspan="9" class="empty-state">Sem alertas neste período</td></tr>`);
    renderAlertsTimelineChart([], hours);
    return;
  }

  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sorted = [...data.alerts].sort(
    (a, b) => (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5)
  );

  sorted.slice(0, 100).forEach((alert) => {
    const tr = document.createElement("tr");
    tr.className = `alert-row ${alert.severity}`;
    htmRender(tr, htmlT`
      <td class="mono">${formatTimestamp(alert.timestamp)}</td>
      <td>${htmlRaw(severityBadge(alert.severity))}</td>
      <td>${alert.agent_name}</td>
      <td class="mono">${alert.agent_ip}</td>
      <td class="mono">${alert.windows_event_id != null ? alert.windows_event_id : "-"}</td>
      <td class="wrap">${alert.friendly_name}<div class="table-sub">${alert.rule_description || ""}</div></td>
      <td>${alert.wazuh_level != null ? alert.wazuh_level : "-"}</td>
      <td class="wrap">${alert.recommendation}</td>
      <td class="log-cell">${alert.full_log}</td>
    `);
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
  list.replaceChildren();
  data.suspects.forEach((s) => {
    const item = document.createElement("div");
    item.className = "bf-item";
    htmRender(item, htmlT`
      <span><strong>${s.user}</strong> — ${s.failed_attempts} tentativas falhadas (${s.source_agent})</span>
      <span>${formatTimestamp(s.last_attempt)}</span>
    `);
    list.appendChild(item);
  });
}

// --- Gráficos (Chart.js) ---

Chart.defaults.font.family = "'Inter', -apple-system, BlinkMacSystemFont, sans-serif";

// Cores de gráficos vêm dos tokens CSS, lidos em runtime (tema claro/escuro).
function cssToken(name) { return slCssToken(getComputedStyle(document.documentElement), name); }
function tokenColor(name, alpha) { return alpha === undefined ? cssToken(name) : slColorAlpha(cssToken(name), alpha); }
// Scriptable: o Chart.js volta a chamar em cada desenho, por isso o tema novo aplica-se num update().
const chartColor = (name, alpha) => () => tokenColor(name, alpha);
function applyChartTheme() {
  Chart.defaults.color = cssToken("--text-secondary");
  Chart.defaults.borderColor = cssToken("--border");
}
applyChartTheme();
function refreshChartsTheme() {
  applyChartTheme();
  Object.values(charts).forEach((c) => {
    c.update("none");
  });
}
window.matchMedia?.("(prefers-color-scheme: dark)").addEventListener?.("change", refreshChartsTheme);
new MutationObserver(refreshChartsTheme).observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });

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
        borderColor: chartColor("--accent"),
        backgroundColor: chartColor("--accent", 0.12),
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
  const labelMap = { critical: "Crítico", high: "Alto", medium: "Médio", low: "Baixo", info: "Info" };

  const labels = [];
  const values = [];
  const colors = [];
  order.forEach((sev) => {
    const count = bySeverity?.[sev] || 0;
    if (count > 0) {
      labels.push(labelMap[sev]);
      values.push(count);
      colors.push(chartColor(slSeverityToken(sev)));
    }
  });

  renderChart("chart-severity-donut", {
    type: "doughnut",
    data: { labels, datasets: [{ data: values, backgroundColor: (c) => colors[c.dataIndex](), borderWidth: 0 }] },
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
      datasets: [{ label: "Ocorrências", data: sorted.map((e) => e.count), backgroundColor: chartColor("--accent") }],
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

