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

  renderSeverityChart(stats.by_severity);
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
const CHART_EMPTY_TEXT = "Sem dados nesta janela";

Chart.defaults.locale = "pt-PT";

// Peças de apoio de cada gráfico (mensagem de vazio e tabela «Ver dados»), criadas uma só vez.
function chartParts(canvas) {
  const wrap = canvas.parentElement;
  let empty = document.getElementById(`${canvas.id}-empty`);
  if (!empty) {
    empty = document.createElement("p");
    empty.id = `${canvas.id}-empty`;
    empty.className = "chart-empty";
    empty.setAttribute("role", "status");
    empty.hidden = true;
    wrap.after(empty);
  }
  let details = document.getElementById(`${canvas.id}-data`);
  if (!details) {
    details = document.createElement("details");
    details.id = `${canvas.id}-data`;
    details.className = "chart-data";
    details.hidden = true;
    htmRender(details, htmlT`<summary>Ver dados</summary><div class="chart-data-body"></div>`);
    empty.after(details);
  }
  return { wrap, empty, details, body: details.querySelector(".chart-data-body") };
}

function chartFillTable(body, columns, rows) {
  htmRender(body, htmlT`<table class="chart-data-table"><thead><tr>${columns.map((c) => htmlT`<th scope="col">${c}</th>`)}</tr></thead><tbody>${rows.map((r) => htmlT`<tr>${r.map((v, i) => (i === 0 ? htmlT`<th scope="row">${v}</th>` : htmlT`<td class="num">${v}</td>`))}</tr>`)}</tbody></table>`);
}

// Único ponto de desenho (D7). `meta` = { title, empty, emptyText, columns, rows }:
// aria-label sempre, «Sem dados nesta janela» quando vazio (sem gráfico, para não
// deixar valores velhos) e a tabela «Ver dados» com os mesmos números.
function renderChart(canvasId, config, meta) {
  const canvas = document.getElementById(canvasId);
  const m = meta || {};
  const parts = chartParts(canvas);
  const empty = m.empty === true;
  canvas.setAttribute("role", "img");
  canvas.setAttribute("aria-label", m.title || "Gráfico");
  parts.wrap.hidden = empty;
  parts.empty.hidden = !empty;
  parts.empty.textContent = m.emptyText || CHART_EMPTY_TEXT;
  parts.details.hidden = empty || !(m.rows && m.rows.length);
  if (!parts.details.hidden) chartFillTable(parts.body, m.columns || [], m.rows);
  if (empty) {
    if (charts[canvasId]) {
      charts[canvasId].destroy();
      delete charts[canvasId];
    }
    return;
  }
  if (charts[canvasId]) {
    charts[canvasId].data = config.data;
    charts[canvasId].options = config.options;
    charts[canvasId].update("none"); // sem animação: um refresh não deve "piscar" os gráficos
    return;
  }
  charts[canvasId] = new Chart(canvas.getContext("2d"), config);
}

// Valor escrito no fim de cada barra horizontal (rótulo direto, sem biblioteca extra).
const chartValueLabels = {
  id: "chartValueLabels",
  afterDatasetsDraw(chart) {
    const ctx = chart.ctx;
    ctx.save();
    ctx.font = `600 11px ${Chart.defaults.font.family}`;
    ctx.fillStyle = cssToken("--text");
    ctx.textBaseline = "middle";
    chart.getDatasetMeta(0).data.forEach((bar, i) => {
      ctx.fillText(fmtNumber(chart.data.datasets[0].data[i]), bar.x + 6, bar.y);
    });
    ctx.restore();
  },
};

// Barras horizontais com o rótulo completo no tooltip e cortado no eixo.
function chartHBarOptions(fullLabels) {
  return {
    indexAxis: "y",
    responsive: true,
    maintainAspectRatio: false,
    layout: { padding: { right: 44 } },
    plugins: {
      legend: { display: false },
      tooltip: { callbacks: { title: (items) => fullLabels[items[0].dataIndex], label: (item) => fmtNumber(item.raw) } },
    },
    scales: {
      x: { display: false, beginAtZero: true },
      y: { grid: { display: false }, ticks: { callback(v) { return slTruncate(this.getLabelForValue(v), 22); } } },
    },
  };
}

function renderAlertsTimelineChart(alerts, hours) {
  const buckets = slBucketSeries((alerts || []).map((a) => a.timestamp), hours, Date.now());
  const total = buckets.reduce((acc, b) => acc + b.count, 0);
  const peak = buckets.reduce((a, b) => (b.count > a.count ? b : a), buckets[0]);
  const title = total
    ? `Alertas ao longo do tempo: ${fmtNumber(total)} no total, pico em ${peak.label} (${fmtNumber(peak.count)})`
    : "Alertas ao longo do tempo: sem dados nesta janela";

  renderChart("chart-alerts-timeline", {
    type: "bar",
    data: {
      labels: buckets.map((b) => b.label),
      datasets: [{ label: "Alertas", data: buckets.map((b) => b.count), backgroundColor: chartColor("--accent"), maxBarThickness: 22 }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: { callbacks: { title: (items) => fmtDate(buckets[items[0].dataIndex].startMs), label: (item) => `${fmtNumber(item.raw)} alertas` } },
      },
      scales: { x: { grid: { display: false }, ticks: { autoSkip: true, maxTicksLimit: 8 } }, y: { beginAtZero: true, ticks: { precision: 0 } } },
    },
  }, { title, empty: total === 0, columns: ["Intervalo", "Alertas"], rows: buckets.map((b) => [b.label, fmtNumber(b.count)]) });
}

function renderSeverityChart(bySeverity) {
  const { rows, total } = slSeverityBars(bySeverity);
  renderChart("chart-severity-bars", {
    type: "bar",
    data: {
      labels: rows.map((r) => r.label),
      datasets: [{ label: "Alertas", data: rows.map((r) => r.value), backgroundColor: (c) => tokenColor(slSeverityToken(rows[c.dataIndex].key)), maxBarThickness: 20 }],
    },
    options: chartHBarOptions(rows.map((r) => r.label)),
    plugins: [chartValueLabels],
  }, {
    title: total ? slChartAriaLabel("Alertas por severidade", rows.map((r) => ({ label: r.label, value: fmtNumber(r.value) }))) : "Alertas por severidade: sem dados nesta janela",
    empty: total === 0,
    columns: ["Severidade", "Alertas"],
    rows: rows.map((r) => [r.label, fmtNumber(r.value)]),
  });
}

function renderTopEventsChart(topEvents) {
  const rows = slEventBars(topEvents, 10);
  renderChart("chart-top-events", {
    type: "bar",
    data: {
      labels: rows.map((r) => r.label),
      datasets: [{ label: "Ocorrências", data: rows.map((r) => r.value), backgroundColor: chartColor("--accent"), maxBarThickness: 18 }],
    },
    options: chartHBarOptions(rows.map((r) => r.label)),
    plugins: [chartValueLabels],
  }, {
    title: rows.length ? slChartAriaLabel("Eventos mais frequentes", rows.map((r) => ({ label: r.label, value: fmtNumber(r.value) }))) : "Eventos mais frequentes: sem dados nesta janela",
    empty: rows.length === 0,
    columns: ["Evento", "Ocorrências"],
    rows: rows.map((r) => [r.label, fmtNumber(r.value)]),
  });
}

