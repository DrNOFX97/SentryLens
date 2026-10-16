// Aba "Red vs Blue" (Fase 11, Onda 3). Carregado depois de app.js e
// reutiliza os seus globais (apiRequest/apiErrorMessage de api.js, escapeHtml, formatTimestamp,
// renderPanelError, API_BASE, API_KEY) — não redeclarar nenhum deles aqui.
// Só mostra dados reais dos endpoints do backend; sem dados, estado vazio.

const RB_REFRESH_MS = 30000;
const RB_METRICS_HOURS = 168; // máximo aceite por /api/redblue/metrics
const RB_MAX_PACKET_ROWS = 200;
const RB_TAB_ID = "redblue"; // o mesmo data-tab do nav em index.html / app.js
const RB_MAX_PACKETS_MEM = RB_MAX_PACKET_ROWS * 10; // teto em memória (W3.3)
const RB_MAX_DETECTIONS_MEM = 1000;
const RB_NETWORK_WS_URL = `${API_BASE.replace(/^http/, "ws")}/ws/network?api_key=${encodeURIComponent(API_KEY)}`;

let rbMetrics = null;
let rbAttackLog = null;

function rbCell(value) {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
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

// Uma tentativa é "antiga" se for anterior à janela de alertas consultada no
// Wazuh (agora - hours): nunca pode ter correspondência. Timestamps inválidos
// não contam como antigos (contam como dentro da janela).
function rbIsStaleAttempt(a, hours) {
  const t = Date.parse(a && a.timestamp);
  return !Number.isNaN(t) && t < Date.now() - hours * 3600 * 1000;
}

function rbCountStaleAttempts(attempts, hours) {
  return (attempts || []).filter((a) => rbIsStaleAttempt(a, hours)).length;
}

function rbFreshAttempts(attempts, hours) {
  return (attempts || []).filter((a) => !rbIsStaleAttempt(a, hours));
}

// Métricas derivadas só de tentativas dentro da janela (não usa agregados do backend).
function rbSummarize(fresh) {
  const mttds = fresh
    .map((a) => a.mttd_seconds)
    .filter((m) => m !== null && m !== undefined);
  const by = (k) => fresh.filter((a) => a.detected_by === k).length;
  return {
    count: fresh.length,
    detected: fresh.filter((a) => a.detected).length,
    avgMttd: mttds.length ? mttds.reduce((x, y) => x + y, 0) / mttds.length : null,
    rule: by("rule"),
    ml: by("ml"),
    both: by("both"),
    neither: fresh.filter((a) => a.detected_by === "none" && !a.detected_by_network).length,
    networkOnly: fresh.filter((a) => a.coverage_gap).length,
  };
}

function renderRedBlueKpis(data) {
  const overall = data.overall || {};
  const attempts = overall.total_attempts || 0;
  const stale = rbCountStaleAttempts(data.attempts, RB_METRICS_HOURS);
  const sum = rbSummarize(rbFreshAttempts(data.attempts, RB_METRICS_HOURS));
  const none = sum.count === 0;
  rbSetText("kpi-rb-attempts", attempts);
  rbSetText("kpi-rb-coverage", none ? "—" : rbFormatPercent(sum.detected / sum.count, sum.count));
  rbSetText("kpi-rb-mttd", none ? "—" : rbFormatSeconds(sum.avgMttd));
  rbSetText("kpi-rb-network-only", data.network_capture_configured && !none ? sum.networkOnly : "—");
  rbSetText("kpi-rb-neither", none ? "—" : sum.neither);
  rbSetText("kpi-rb-alerts-fetched", data.alerts_fetched ?? "—");
  rbSetText("kpi-rb-capture", data.network_capture_configured ? "Configurada" : "Não configurada");

  const notices = [];
  if (attempts === 0) {
    notices.push("Sem ataques no log — não há nada para correlacionar (cobertura e MTTD não se aplicam).");
  }
  if (stale > 0) {
    notices.push(`${stale} tentativa(s) anterior(es) à janela de alertas (7 dias) estão excluídas dos números mostrados (cobertura, MTTD e deteções): o Wazuh não foi consultado para esse período, por isso não podem ter correspondência.`);
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
  htmRender(document.getElementById("redblue-notices"),
    htmlT`${notices.map((n) => htmlT`<div class="rb-notice">⚠️ ${n}</div>`)}`);
}

async function loadRedBlueMetrics() {
  try {
    rbMetrics = await apiRequest(`/api/redblue/metrics?hours=${RB_METRICS_HOURS}`);
    renderPanelError("#redblue-summary-panel", null);
    renderRedBlueKpis(rbMetrics);
  } catch (err) {
    console.error(err);
    rbMetrics = null;
    ["kpi-rb-attempts", "kpi-rb-coverage", "kpi-rb-mttd", "kpi-rb-network-only", "kpi-rb-neither"]
      .forEach((id) => rbSetText(id, "—"));
    const noticesEl = document.getElementById("redblue-notices");
    if (noticesEl) noticesEl.replaceChildren();
    const message = err.status === 503
      ? "Modelo de ML ainda não foi treinado. Corre scripts/train_anomaly_model.py."
      : apiErrorMessage(err);
    renderPanelError("#redblue-summary-panel", message);
  }
  if (typeof renderBluePanel === "function") renderBluePanel(rbMetrics);
  if (typeof renderRedPanel === "function") renderRedPanel(rbAttackLog, rbMetrics);
}

// Estado «A carregar» numa tabela (só na 1.ª carga, para não piscar nos refresh).
function rbTableLoading(tbodyId, cols) {
  const tbody = document.getElementById(tbodyId);
  if (!tbody || tbody.children.length > 0) return;
  const td = document.createElement("td");
  td.colSpan = cols;
  const tr = document.createElement("tr");
  tr.appendChild(td);
  tbody.replaceChildren(tr);
  sttShowLoading(td);
}

// Estado de erro numa tabela: mensagem PT fixa (nunca texto de exceção).
function rbTableError(tbodyId, cols, err) {
  const tbody = document.getElementById(tbodyId);
  if (!tbody) return;
  const td = document.createElement("td");
  td.colSpan = cols;
  const tr = document.createElement("tr");
  tr.appendChild(td);
  tbody.replaceChildren(tr);
  sttShowError(td, err);
}

async function loadManagerPanel() {
  const tbody = document.getElementById("redblue-agents-body");
  rbTableLoading("redblue-agents-body", 4);
  try {
    const [health, agents] = await Promise.all([apiRequest("/api/health"), apiRequest("/api/agents")]);
    renderPanelError("#redblue-manager-panel", null);
    rbSetText("kpi-rb-backend", health.status === "ok" ? "Ativo" : String(health.status));
    const list = agents.agents || [];
    rbSetText("kpi-rb-agents", list.filter((a) => a.status === "active").length);
    if (list.length === 0) {
      htmRender(tbody, htmlT`<tr><td colspan="4" class="empty-state">Nenhum agente encontrado</td></tr>`);
      return;
    }
    htmRender(tbody, htmlT`${list.map((a) => htmlT`
      <tr>
        <td>${rbCell(a.name)}</td>
        <td class="mono">${rbCell(a.ip)}</td>
        <td><span class="agent-status ${a.status}">${rbCell(a.status)}</span></td>
        <td class="mono">${formatTimestamp(a.last_keep_alive)}</td>
      </tr>`)}`);
  } catch (err) {
    console.error(err);
    renderPanelError("#redblue-manager-panel", apiErrorMessage(err));
    rbTableError("redblue-agents-body", 4, err);
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
  rbTableLoading("redblue-attack-body", 6);
  try {
    rbAttackLog = await apiRequest("/api/redblue/attack-log");
    renderPanelError("#redblue-red-panel", null);
  } catch (err) {
    console.error(err);
    rbAttackLog = null;
    renderPanelError("#redblue-red-panel", apiErrorMessage(err));
  }
  renderRedPanel(rbAttackLog, rbMetrics);
}

function renderRedPanel(attackLog) {
  const tbody = document.getElementById("redblue-attack-body");
  if (!attackLog) {
    htmRender(tbody, htmlT`<tr><td colspan="6" class="empty-state">Log de ataques indisponível</td></tr>`);
    return;
  }
  const entries = attackLog.entries || [];
  if (entries.length === 0) {
    htmRender(tbody, htmlT`<tr><td colspan="6" class="empty-state">Nenhum ataque registado em attack_log.jsonl</td></tr>`);
    return;
  }
  const scenarios = attackLog.scenarios || {};
  const sorted = [...entries].sort((a, b) => String(b.timestamp).localeCompare(String(a.timestamp)));
  htmRender(tbody, htmlT`${sorted.map((e) => {
      const s = scenarios[e.scenario];
      const mitre = s ? `${s.mitre_technique} — ${s.mitre_tactic}` : null;
      const status = String(e.status);
      return htmlT`
      <tr>
        <td class="mono">${formatTimestamp(e.timestamp)}</td>
        <td>${rbCell(e.scenario)}</td>
        <td class="mono">${rbCell(e.target)}</td>
        <td>${rbCell(e.tool)}</td>
        <td><span class="rb-badge ${status}">${status}</span></td>
        <td>${rbCell(mitre)}</td>
      </tr>`;
    })}`);
}

function rbMttdByTechnique(attempts) {
  const groups = new Map();
  (attempts || []).forEach((a) => {
    const g = groups.get(a.mitre_technique) || {
      technique: a.mitre_technique, tactic: a.mitre_tactic, attempts: 0, fresh: 0, detected: 0, mttds: [], items: [],
    };
    g.attempts += 1;
    g.items.push(a);
    if (!rbIsStaleAttempt(a, RB_METRICS_HOURS)) {
      g.fresh += 1;
      if (a.detected) g.detected += 1;
      if (a.mttd_seconds !== null && a.mttd_seconds !== undefined) g.mttds.push(a.mttd_seconds);
    }
    groups.set(a.mitre_technique, g);
  });
  return [...groups.values()]
    .map((g) => ({
      technique: g.technique,
      tactic: g.tactic,
      attempts: g.attempts,
      freshAttempts: g.fresh,
      detected: g.detected,
      avgMttd: g.mttds.length ? g.mttds.reduce((x, y) => x + y, 0) / g.mttds.length : null,
      staleAttempts: rbCountStaleAttempts(g.items, RB_METRICS_HOURS),
    }))
    .sort((x, y) => String(x.technique).localeCompare(String(y.technique)));
}

const RB_STALE_TITLE = "Todas as tentativas são anteriores à janela de alertas (7 dias): sem correspondência possível";

function rbAttemptsLabel(total, fresh) {
  return fresh < total ? `${total} (${fresh} na janela)` : String(total);
}

function renderBluePanel(metrics) {
  const body = document.getElementById("redblue-blue-body");
  const techBody = document.getElementById("redblue-technique-body");
  const note = document.getElementById("redblue-blue-note");
  note.textContent =
    "Este painel mostra o que foi detetado, por que método e ao fim de quanto tempo. " +
    "O seguimento (estados, notas, atribuição) está na aba Incidentes.";

  if (!metrics) {
    htmRender(body, htmlT`<tr><td colspan="9" class="empty-state">Correlação indisponível</td></tr>`);
    htmRender(techBody, htmlT`<tr><td colspan="5" class="empty-state">Correlação indisponível</td></tr>`);
    return;
  }

  const names = Object.keys(metrics.by_scenario || {}).sort();
  if (names.length === 0) {
    htmRender(body, htmlT`<tr><td colspan="9" class="empty-state">Sem tentativas de ataque na janela de 7 dias</td></tr>`);
  } else {
    htmRender(body, htmlT`${names.map((name) => {
        const own = (metrics.attempts || []).filter((a) => a.scenario === name);
        const sum = rbSummarize(rbFreshAttempts(own, RB_METRICS_HOURS));
        const total = own.length || (metrics.by_scenario[name] || {}).attempts || 0;
        const allStale = sum.count === 0;
        const dash = "—";
        const rowAttr = allStale ? htmlT` class="rb-stale" title="${RB_STALE_TITLE}"` : "";
        return htmlT`
        <tr${rowAttr}>
          <td>${rbCell(name)}</td>
          <td>${rbAttemptsLabel(total, sum.count)}</td>
          <td>${allStale ? dash : rbFormatPercent(sum.detected / sum.count, sum.count)}</td>
          <td>${allStale ? dash : rbFormatSeconds(sum.avgMttd)}</td>
          <td>${allStale ? dash : sum.rule}</td>
          <td>${allStale ? dash : sum.ml}</td>
          <td>${allStale ? dash : sum.both}</td>
          <td>${allStale || !metrics.network_capture_configured ? dash : sum.networkOnly}</td>
          <td>${allStale ? dash : sum.neither}</td>
        </tr>`;
      })}`);
  }

  const techniques = rbMttdByTechnique(metrics.attempts);
  if (techniques.length === 0) {
    htmRender(techBody, htmlT`<tr><td colspan="5" class="empty-state">Sem tentativas de ataque na janela de 7 dias</td></tr>`);
  } else {
    htmRender(techBody, htmlT`${techniques.map((t) => {
        const allStale = t.freshAttempts === 0;
        const rowAttr = allStale ? htmlT` class="rb-stale" title="${RB_STALE_TITLE}"` : "";
        return htmlT`
      <tr${rowAttr}>
        <td>${rbCell(t.technique)}</td>
        <td>${rbCell(t.tactic)}</td>
        <td>${rbAttemptsLabel(t.attempts, t.freshAttempts)}</td>
        <td>${allStale ? "—" : t.detected}</td>
        <td>${allStale ? "—" : rbFormatSeconds(t.avgMttd)}</td>
      </tr>`;
      })}`);
  }
}

const rbNetwork = { configured: false, packets: [], detections: [], history: [] };
let rbNetworkWs = null;
let rbNetworkReconnectAttempts = 0;

function rbDetectionDetail(detail) {
  if (!detail || typeof detail !== "object") return "—";
  return Object.entries(detail).map(([k, v]) => `${k}: ${v}`).join(", ");
}

function renderNetworkPanel() {
  const note = document.getElementById("redblue-network-note");
  const detBody = document.getElementById("redblue-detections-body");
  const pktBody = document.getElementById("redblue-packets-body");

  if (!rbNetwork.configured) {
    note.textContent =
      "Captura de rede não configurada: define VM_SSH_HOST, VM_SSH_USER e VM_SSH_KEY_PATH em scripts/.env e ativa a captura na VM (docs/LAB_WAZUH_HYPERV.md).";
    rbSetText("kpi-rb-packets", "—");
    rbSetText("kpi-rb-detections", "—");
    rbSetText("kpi-rb-history", "—");
    htmRender(detBody, htmlT`<tr><td colspan="5" class="empty-state">Captura não configurada</td></tr>`);
    htmRender(pktBody, htmlT`<tr><td colspan="5" class="empty-state">Captura não configurada</td></tr>`);
    return;
  }

  note.textContent = "Metadados de pacotes capturados na VM Wazuh (sem payload). Deteções por regras fixas: port scan, brute force e volume.";
  rbSetText("kpi-rb-packets", rbNetwork.packets.length);
  rbSetText("kpi-rb-detections", rbNetwork.detections.length);
  rbSetText("kpi-rb-history", rbNetwork.history.length);

  const dets = [...rbNetwork.history].reverse();
  htmRender(detBody, dets.length
    ? htmlT`${dets.map((d) => htmlT`
      <tr>
        <td class="mono">${formatTimestamp(d.timestamp)}</td>
        <td>${rbCell(d.type)}</td>
        <td class="mono">${rbCell(d.src_ip)}</td>
        <td class="mono">${rbCell(d.dst_ip)}</td>
        <td>${rbDetectionDetail(d.detail)}</td>
      </tr>`)}`
    : htmlT`<tr><td colspan="5" class="empty-state">Nenhuma deteção de rede até agora</td></tr>`);

  const pkts = rbNetwork.packets.slice(-RB_MAX_PACKET_ROWS).reverse();
  htmRender(pktBody, pkts.length
    ? htmlT`${pkts.map((p) => {
          const src = p.src_port != null ? `${p.src_ip}:${p.src_port}` : p.src_ip;
          const dst = p.dst_port != null ? `${p.dst_ip}:${p.dst_port}` : p.dst_ip;
          return htmlT`
      <tr>
        <td class="mono">${formatTimestamp(p.timestamp)}</td>
        <td class="mono">${rbCell(src)}</td>
        <td class="mono">${rbCell(dst)}</td>
        <td>${rbCell(p.protocol)}</td>
        <td>${rbCell(p.length)}</td>
      </tr>`;
        })}`
    : htmlT`<tr><td colspan="5" class="empty-state">Sem pacotes no buffer</td></tr>`);
}

async function loadNetworkPanel() {
  try {
    const data = await apiRequest("/api/redblue/network");
    renderPanelError("#redblue-network-panel", null);
    rbNetwork.configured = !!data.configured;
    rbNetwork.packets = data.packets || [];
    rbNetwork.detections = data.detections || [];
    rbNetwork.history = data.detection_history || [];
    renderNetworkPanel();
    if (rbNetwork.configured && !rbNetworkWs) connectNetworkSocket();
  } catch (err) {
    console.error(err);
    renderPanelError("#redblue-network-panel", apiErrorMessage(err));
  }
}

function rbTrim(arr, max) {
  if (arr.length > max) arr.splice(0, arr.length - max);
}

// A aba só desenha quando é a ativa e o separador está visível; fora disso o
// socket continua a acumular (com teto) mas não renderiza.
function rbNetworkVisible() {
  const docVisible = typeof document === "undefined" || document.visibilityState === "visible";
  return docVisible && typeof rtRouter !== "undefined" && rtRouter.getActiveId() === RB_TAB_ID;
}

let rbRenderScheduled = false;
let rbRenderDirty = false;

// Várias mensagens no mesmo frame -> um só render (requestAnimationFrame).
function rbScheduleNetworkRender() {
  if (rbRenderScheduled) return;
  rbRenderScheduled = true;
  const raf = typeof requestAnimationFrame === "function" ? requestAnimationFrame : (fn) => setTimeout(fn, 16);
  raf(() => {
    rbRenderScheduled = false;
    if (!rbNetworkVisible()) {
      rbRenderDirty = true;
      return;
    }
    rbRenderDirty = false;
    renderNetworkPanel();
  });
}

function connectNetworkSocket() {
  rbNetworkWs = new WebSocket(RB_NETWORK_WS_URL);
  rbNetworkWs.onopen = () => {
    rbNetworkReconnectAttempts = 0;
  };
  rbNetworkWs.onmessage = (event) => {
    let msg;
    try {
      msg = JSON.parse(event.data);
    } catch (err) {
      console.error("Mensagem /ws/network inválida:", err);
      return;
    }
    if (msg && msg.type === "packet" && msg.packet) {
      rbNetwork.packets.push(msg.packet);
      rbTrim(rbNetwork.packets, RB_MAX_PACKETS_MEM);
    } else if (msg && msg.type === "network_detection" && msg.detection) {
      rbNetwork.detections.push(msg.detection);
      rbNetwork.history.push(msg.detection);
      rbTrim(rbNetwork.detections, RB_MAX_DETECTIONS_MEM);
      rbTrim(rbNetwork.history, RB_MAX_DETECTIONS_MEM);
    } else {
      return;
    }
    rbScheduleNetworkRender();
  };
  rbNetworkWs.onerror = () => rbNetworkWs.close();
  rbNetworkWs.onclose = () => {
    rbNetworkWs = null;
    // Sem tempo real, o refresh de 30s (loadNetworkPanel) continua a atualizar
    // o painel por snapshot — e volta a abrir o socket se a captura estiver ativa.
    if (rbNetworkReconnectAttempts < WS_RECONNECT_DELAYS_MS.length) {
      const delay = WS_RECONNECT_DELAYS_MS[rbNetworkReconnectAttempts];
      rbNetworkReconnectAttempts += 1;
      setTimeout(() => {
        if (rbNetwork.configured && !rbNetworkWs) connectNetworkSocket();
      }, delay);
    }
  };
}

// W3.2: o router só chama refreshRedBlueTab com a aba ativa e o separador visível.
function rbOnHide() {
  rbRenderDirty = true; // o próximo load/mensagem redesenha
}

if (typeof rtRegisterTab === "function") {
  rtRegisterTab({ id: RB_TAB_ID, load: refreshRedBlueTab, refreshMs: RB_REFRESH_MS, onHide: rbOnHide });
}
