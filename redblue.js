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

// Conta tentativas anteriores à janela de alertas consultada no Wazuh
// (agora - hours). Timestamps inválidos não contam como antigos.
function rbCountStaleAttempts(attempts, hours) {
  const cutoff = Date.now() - hours * 3600 * 1000;
  return (attempts || []).filter((a) => {
    const t = Date.parse(a && a.timestamp);
    return !Number.isNaN(t) && t < cutoff;
  }).length;
}

function renderRedBlueKpis(data) {
  const overall = data.overall || {};
  const attempts = overall.total_attempts || 0;
  const stale = rbCountStaleAttempts(data.attempts, RB_METRICS_HOURS);
  const allStale = attempts > 0 && stale === attempts;
  rbSetText("kpi-rb-attempts", attempts);
  rbSetText("kpi-rb-coverage", allStale ? "—" : rbFormatPercent(overall.coverage_rate, attempts));
  rbSetText("kpi-rb-mttd", allStale ? "—" : rbFormatSeconds(overall.avg_mttd_seconds));
  rbSetText("kpi-rb-network-only", data.network_capture_configured ? (overall.detected_by_network_only ?? 0) : "—");
  rbSetText("kpi-rb-neither", allStale ? "—" : (overall.detected_by_neither ?? 0));
  rbSetText("kpi-rb-alerts-fetched", data.alerts_fetched ?? "—");
  rbSetText("kpi-rb-capture", data.network_capture_configured ? "Configurada" : "Não configurada");

  const notices = [];
  if (attempts === 0) {
    notices.push("Sem ataques no log — não há nada para correlacionar (cobertura e MTTD não se aplicam).");
  }
  if (stale > 0) {
    notices.push(`${stale} tentativa(s) anterior(es) à janela de alertas (7 dias): o Wazuh não foi consultado para esse período, por isso não podem ter correspondência — a cobertura não é fiável para elas.`);
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

async function loadRedPanel() {
  try {
    rbAttackLog = await fetchJSON("/api/redblue/attack-log");
    renderPanelError("#redblue-red-panel", null);
  } catch (err) {
    console.error(err);
    rbAttackLog = null;
    renderPanelError("#redblue-red-panel", err.message || "Erro ao carregar o log de ataques.");
  }
  renderRedPanel(rbAttackLog, rbMetrics);
}

function renderRedPanel(attackLog) {
  const tbody = document.getElementById("redblue-attack-body");
  if (!attackLog) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Log de ataques indisponível</td></tr>';
    return;
  }
  const entries = attackLog.entries || [];
  if (entries.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Nenhum ataque registado em attack_log.jsonl</td></tr>';
    return;
  }
  const scenarios = attackLog.scenarios || {};
  const sorted = [...entries].sort((a, b) => String(b.timestamp).localeCompare(String(a.timestamp)));
  tbody.innerHTML = sorted
    .map((e) => {
      const s = scenarios[e.scenario];
      const mitre = s ? `${s.mitre_technique} — ${s.mitre_tactic}` : null;
      const status = String(e.status);
      return `
      <tr>
        <td class="mono">${escapeHtml(formatTimestamp(e.timestamp))}</td>
        <td>${rbCell(e.scenario)}</td>
        <td class="mono">${rbCell(e.target)}</td>
        <td>${rbCell(e.tool)}</td>
        <td><span class="rb-badge ${escapeHtml(status)}">${escapeHtml(status)}</span></td>
        <td>${rbCell(mitre)}</td>
      </tr>`;
    })
    .join("");
}

function rbMttdByTechnique(attempts) {
  const groups = new Map();
  (attempts || []).forEach((a) => {
    const g = groups.get(a.mitre_technique) || {
      technique: a.mitre_technique, tactic: a.mitre_tactic, attempts: 0, detected: 0, mttds: [], items: [],
    };
    g.attempts += 1;
    g.items.push(a);
    if (a.detected) g.detected += 1;
    if (a.mttd_seconds !== null && a.mttd_seconds !== undefined) g.mttds.push(a.mttd_seconds);
    groups.set(a.mitre_technique, g);
  });
  return [...groups.values()]
    .map((g) => ({
      technique: g.technique,
      tactic: g.tactic,
      attempts: g.attempts,
      detected: g.detected,
      avgMttd: g.mttds.length ? g.mttds.reduce((x, y) => x + y, 0) / g.mttds.length : null,
      staleAttempts: rbCountStaleAttempts(g.items, RB_METRICS_HOURS),
    }))
    .sort((x, y) => String(x.technique).localeCompare(String(y.technique)));
}

const RB_STALE_TITLE = "Todas as tentativas são anteriores à janela de alertas (7 dias): sem correspondência possível";

function renderBluePanel(metrics) {
  const body = document.getElementById("redblue-blue-body");
  const techBody = document.getElementById("redblue-technique-body");
  const note = document.getElementById("redblue-blue-note");
  note.textContent =
    "Ações de resposta: a aplicação não regista ações de resposta (nem manuais), por isso não há nada para mostrar aqui. " +
    "Este painel mostra apenas o que foi detetado, por que método e ao fim de quanto tempo.";

  if (!metrics) {
    body.innerHTML = '<tr><td colspan="9" class="empty-state">Correlação indisponível</td></tr>';
    techBody.innerHTML = '<tr><td colspan="5" class="empty-state">Correlação indisponível</td></tr>';
    return;
  }

  const names = Object.keys(metrics.by_scenario || {}).sort();
  if (names.length === 0) {
    body.innerHTML = '<tr><td colspan="9" class="empty-state">Sem tentativas de ataque na janela de 7 dias</td></tr>';
  } else {
    body.innerHTML = names
      .map((name) => {
        const b = metrics.by_scenario[name];
        const own = (metrics.attempts || []).filter((a) => a.scenario === name);
        const stale = rbCountStaleAttempts(own, RB_METRICS_HOURS);
        const allStale = b.attempts > 0 && own.length === b.attempts && stale === own.length;
        const dash = "—";
        const rowAttr = allStale ? ` class="rb-stale" title="${escapeHtml(RB_STALE_TITLE)}"` : "";
        return `
        <tr${rowAttr}>
          <td>${rbCell(name)}</td>
          <td>${b.attempts}</td>
          <td>${allStale ? dash : rbFormatPercent(b.coverage_rate, b.attempts)}</td>
          <td>${allStale ? dash : rbFormatSeconds(b.avg_mttd_seconds)}</td>
          <td>${allStale ? dash : b.detected_by_rule}</td>
          <td>${allStale ? dash : b.detected_by_ml}</td>
          <td>${allStale ? dash : b.detected_by_both}</td>
          <td>${allStale || !metrics.network_capture_configured ? dash : b.detected_by_network_only}</td>
          <td>${allStale ? dash : b.detected_by_neither}</td>
        </tr>`;
      })
      .join("");
  }

  const techniques = rbMttdByTechnique(metrics.attempts);
  if (techniques.length === 0) {
    techBody.innerHTML = '<tr><td colspan="5" class="empty-state">Sem tentativas de ataque na janela de 7 dias</td></tr>';
  } else {
    techBody.innerHTML = techniques
      .map((t) => {
        const allStale = t.attempts > 0 && t.staleAttempts === t.attempts;
        const rowAttr = allStale ? ` class="rb-stale" title="${escapeHtml(RB_STALE_TITLE)}"` : "";
        return `
      <tr${rowAttr}>
        <td>${rbCell(t.technique)}</td>
        <td>${rbCell(t.tactic)}</td>
        <td>${t.attempts}</td>
        <td>${allStale ? "—" : t.detected}</td>
        <td>${allStale ? "—" : rbFormatSeconds(t.avgMttd)}</td>
      </tr>`;
      })
      .join("");
  }
}

refreshRedBlueTab();
setInterval(refreshRedBlueTab, RB_REFRESH_MS);
