// Painel Sistema: CPU/RAM/disco/rede da máquina local.

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
  tbody.replaceChildren();
  if (!interfaces || interfaces.length === 0) {
    htmRender(tbody, htmlT`<tr><td colspan="3" class="empty-state">Nenhuma interface ativa encontrada</td></tr>`);
    return;
  }
  interfaces.forEach((iface) => {
    const tr = document.createElement("tr");
    htmRender(tr, htmlT`
      <td>${iface.interface}</td>
      <td class="mono">${iface.ip}</td>
      <td class="mono">${iface.speed_mbps ? `${iface.speed_mbps} Mbps` : "-"}</td>
    `);
    tbody.appendChild(tr);
  });
}

function renderViolationsHistory(history) {
  const tbody = document.getElementById("violations-history-body");
  tbody.replaceChildren();
  if (!history || history.length === 0) {
    htmRender(tbody, htmlT`<tr><td colspan="4" class="empty-state">Sem violações resolvidas ainda</td></tr>`);
    return;
  }
  const sorted = [...history].sort((a, b) => new Date(b.started_at) - new Date(a.started_at));
  sorted.slice(0, 50).forEach((v) => {
    const tr = document.createElement("tr");
    htmRender(tr, htmlT`
      <td>${metricLabel(v.metric)}</td>
      <td>${v.level === "critico" ? "Crítico" : "Aviso"}</td>
      <td class="mono">${formatTimestamp(v.started_at)}</td>
      <td class="mono">${formatDuration(v.duration_seconds)}</td>
    `);
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
  document.getElementById("sys-disk-cards").replaceChildren();
  htmRender(document.getElementById("network-interfaces-body"), htmlT`<tr><td colspan="3" class="empty-state">Sem dados</td></tr>`);
  sttShowEmpty(document.getElementById("system-alerts-list"), "Sem dados");
  htmRender(document.getElementById("violations-history-body"), htmlT`<tr><td colspan="4" class="empty-state">Sem dados</td></tr>`);
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
    diskContainer.replaceChildren();
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
      htmRender(card, htmlT`
        <div class="system-card-header">
          <h3>Disco ${disk.mountpoint}</h3>
          ${disk.media_type ? htmlT`<span class="media-badge ${disk.media_type.toLowerCase()}">${disk.media_type}</span>` : ""}
          <span class="system-card-value">${slFmtPct(disk.usage_percent, 1)}</span>
        </div>
        <div class="progress-track"><div class="progress-fill level-${level}" style="width:${slProgressWidth(disk.usage_percent)}"></div></div>
        <div class="system-sub">${diskDetailParts.join(" · ")}</div>
      `);
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
      sttShowEmpty(list, "Sem violações ativas");
    } else {
      list.replaceChildren();
      active.forEach((v) => {
        const item = document.createElement("div");
        item.className = `system-alert-item level-${v.level}`;
        htmRender(item, htmlT`
          <span><strong>${metricLabel(v.metric)}</strong> — ${v.level === "critico" ? "Crítico" : "Aviso"}</span>
          <span>a decorrer há ${formatDuration(v.duration_seconds)}</span>
        `);
        list.appendChild(item);
      });
    }

    renderViolationsHistory(historyData.history || []);
    renderSystemUsageChart(usageHistoryData.history || [], await sysLoadThresholds());
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

// Histórico de uso de CPU/RAM/disco: vem de /api/system/usage-history, um
// buffer em memória no backend (~1h a 30s/amostra) alimentado pelo loop de
// background — persiste entre recargas da página e é partilhado por
// qualquer separador que abra o dashboard.
// Limiares de aviso/crítico: fonte única no backend (/api/system/thresholds).
// Em caso de erro devolve {} e tenta de novo no próximo refresh; o gráfico fica sem linhas de referência.
let sysThresholdsCache = null;
async function sysLoadThresholds() {
  if (sysThresholdsCache) return sysThresholdsCache;
  try {
    sysThresholdsCache = await apiRequest("/api/system/thresholds");
    return sysThresholdsCache;
  } catch (err) {
    console.error(err);
    return {};
  }
}

// Linhas tracejadas nos limiares de cada série e o nome da série escrito no fim da linha.
const sysUsagePlugin = {
  id: "sysUsagePlugin",
  afterDatasetsDraw(chart, args, opts) {
    const ctx = chart.ctx;
    const area = chart.chartArea;
    const y = chart.scales.y;
    ctx.save();
    ctx.font = `600 11px ${Chart.defaults.font.family}`;
    ctx.textBaseline = "middle";
    chart.data.datasets.forEach((ds, i) => {
      const th = (opts.thresholds || {})[ds.metric];
      if (th) {
        [["warning", 0.4], ["critical", 0.85]].forEach(([level, alpha]) => {
          if (!Number.isFinite(th[level])) return;
          const py = y.getPixelForValue(th[level]);
          ctx.setLineDash([4, 4]);
          ctx.lineWidth = 1;
          ctx.strokeStyle = tokenColor(ds.token, alpha);
          ctx.beginPath();
          ctx.moveTo(area.left, py);
          ctx.lineTo(area.right, py);
          ctx.stroke();
        });
        ctx.setLineDash([]);
      }
      const pts = chart.getDatasetMeta(i).data;
      const last = pts[pts.length - 1];
      if (last) {
        ctx.fillStyle = tokenColor(ds.token);
        ctx.fillText(ds.label, area.right + 6, last.y);
      }
    });
    ctx.restore();
  },
};

const SYS_USAGE_SERIES = [
  { metric: "cpu", token: "--cat-1", field: "cpu_percent", label: "CPU" },
  { metric: "ram", token: "--cat-7", field: "ram_percent", label: "RAM" },
  { metric: "disk", token: "--cat-3", field: "disk_percent", label: "Disco" },
];

function renderSystemUsageChart(history, thresholds) {
  const diskMount = history.length && history[history.length - 1].disk_mountpoint ? history[history.length - 1].disk_mountpoint : "";
  const times = history.map((s) => new Date(s.timestamp).toLocaleTimeString("pt-PT", { hour: "2-digit", minute: "2-digit" }));
  const series = SYS_USAGE_SERIES.map((d) => ({ ...d, label: d.metric === "disk" && diskMount ? `Disco ${diskMount}` : d.label }));
  const last = history[history.length - 1] || {};

  renderChart("chart-system-usage", {
    type: "line",
    data: {
      labels: times,
      datasets: series.map((d) => ({
        label: d.label,
        metric: d.metric,
        token: d.token,
        data: history.map((s) => s[d.field]),
        borderColor: chartColor(d.token),
        backgroundColor: chartColor(d.token),
        borderWidth: 2,
        pointRadius: 0,
        pointHoverRadius: 4,
        tension: 0,
        fill: false,
      })),
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      layout: { padding: { right: 78 } },
      plugins: {
        legend: { display: false },
        tooltip: { mode: "index", intersect: false, callbacks: { label: (item) => `${item.dataset.label}: ${fmtPct(item.raw, { decimals: 0 })}` } },
        sysUsagePlugin: { thresholds: thresholds || {} },
      },
      scales: { x: { grid: { display: false }, ticks: { maxTicksLimit: 8 } }, y: { beginAtZero: true, max: 100, ticks: { callback: (v) => `${v}%` } } },
      interaction: { mode: "index", intersect: false },
    },
    plugins: [sysUsagePlugin],
  }, {
    title: history.length
      ? slChartAriaLabel("Uso do sistema, última amostra", series.map((d) => ({ label: d.label, value: fmtPct(last[d.field], { decimals: 0 }) })))
      : "Uso do sistema: sem dados nesta janela",
    empty: history.length === 0,
    columns: ["Hora", ...series.map((d) => d.label)],
    rows: history.map((s, i) => [times[i], ...series.map((d) => fmtPct(s[d.field], { decimals: 0 }))]),
  });
}

