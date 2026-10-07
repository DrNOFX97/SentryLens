// Aba "Live SOC" (Roadmap v2, R2). Carregado depois de app.js: reutiliza os
// seus globais (API_BASE, API_KEY, escapeHtml, severityBadge, ws,
// inRealtimeFallback) — não redeclarar nenhum aqui. NÃO abre um 2º
// WebSocket: o feed é alimentado pelo evento "sentrylens:new-alert" que
// app.js dispara a partir da ligação /ws/alerts já existente (detail = alerta
// enriquecido). A saúde do SIEM vem de GET /api/siem/health; sem dados
// reais mostra "Indisponível"/"Sem dados", nunca números inventados.
// Todo o texto dinâmico (agente, regra, erros) passa por escapeHtml.

const LS_FEED_MAX = 50;
const LS_REFRESH_MS = 30000;
const LS_TICK_MS = 5000;

let lsFeed = [];
let lsPending = [];
let lsPaused = false;
let lsHealth = null;
let lsHealthFetchedAt = 0;
let lsRefreshing = false;

const lsTab = document.getElementById("tab-live-soc");

function lsIsActive() {
  return lsTab.classList.contains("active") && document.visibilityState === "visible";
}

function lsText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function lsAlertKey(a) {
  return [a.timestamp, a.rule_id, a.agent_name, a.full_log].join("|");
}

function lsFormatTime(ts) {
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleTimeString("pt-PT");
}

function lsFormatAge(seconds) {
  if (seconds === null || seconds === undefined) return "—";
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.floor(s / 60)} min ${s % 60} s`;
  return `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min`;
}

// ----- Feed ao vivo -----

function lsAddToFeed(alerts) {
  const seen = new Set(lsFeed.map(lsAlertKey));
  const fresh = alerts.filter((a) => !seen.has(lsAlertKey(a)));
  if (!fresh.length) return;
  lsFeed = fresh.concat(lsFeed).slice(0, LS_FEED_MAX);
}

function lsRenderFeed() {
  const body = document.getElementById("ls-feed-body");
  if (!lsFeed.length) {
    body.innerHTML = '<tr><td colspan="4" class="empty-state">Sem alertas recebidos ainda.</td></tr>';
  } else {
    body.innerHTML = lsFeed.map((a) => `
      <tr>
        <td>${escapeHtml(lsFormatTime(a.timestamp))}</td>
        <td>${severityBadge(a.severity)}</td>
        <td>${escapeHtml(a.agent_name)}</td>
        <td>${escapeHtml(a.windows_event_id ? `${a.windows_event_id} — ${a.friendly_name}` : (a.rule_description || a.friendly_name))}</td>
      </tr>`).join("");
  }
  document.getElementById("ls-pause-btn").textContent = lsPaused ? "▶ Retomar" : "⏸ Pausar";
  lsText("ls-pending", lsPaused && lsPending.length ? `${lsPending.length} novo(s) em pausa` : "");
}

function lsRenderConnection() {
  const el = document.getElementById("ls-conn");
  let cls = "ls-conn-wait";
  let label = "A ligar...";
  if (typeof inRealtimeFallback !== "undefined" && inRealtimeFallback) {
    cls = "ls-conn-fallback";
    label = "Fallback (polling a cada 30 s)";
  } else if (typeof ws !== "undefined" && ws && ws.readyState === WebSocket.OPEN) {
    cls = "ls-conn-live";
    label = "Tempo real (WebSocket)";
  }
  el.className = `ls-conn ${cls}`;
  el.textContent = `● ${label}`;
}

async function lsLoadInitialFeed() {
  try {
    const response = await fetch(`${API_BASE}/api/alerts?hours=1`, { headers: { "X-API-Key": API_KEY } });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    // O backend devolve do mais recente para o mais antigo.
    lsFeed = (data.alerts || []).slice(0, LS_FEED_MAX);
  } catch (err) {
    document.getElementById("ls-feed-body").innerHTML =
      `<tr><td colspan="4" class="empty-state">Sem dados: ${escapeHtml(err.message)}</td></tr>`;
    return;
  }
  lsRenderFeed();
}

document.addEventListener("sentrylens:new-alert", (event) => {
  const alert = event.detail;
  if (!alert) return;
  if (lsPaused) lsPending.unshift(alert);
  else lsAddToFeed([alert]);
  lsRenderFeed();
});

document.getElementById("ls-pause-btn").addEventListener("click", () => {
  lsPaused = !lsPaused;
  if (!lsPaused && lsPending.length) {
    lsAddToFeed(lsPending.slice().reverse());
    lsPending = [];
  }
  lsRenderFeed();
});

// ----- Saúde do SIEM -----

function lsComponent(id, component) {
  const el = document.getElementById(id);
  const ok = component && component.status === "ok";
  el.textContent = ok ? "Operacional" : "Indisponível";
  el.className = `value ls-state ${ok ? "ls-ok" : "ls-down"}`;
  el.title = ok ? "" : (component && component.error) || "";
}

const LS_STATUS = {
  ok: ["ls-banner-ok", "SIEM operacional"],
  degraded: ["ls-banner-degraded", "SIEM degradado"],
  down: ["ls-banner-down", "SIEM indisponível"],
};

function lsRenderStatus(h) {
  const el = document.getElementById("ls-status");
  const [cls, label] = (h && LS_STATUS[h.status]) || ["ls-banner-wait", "Estado do SIEM: sem dados"];
  const reasons = [];
  if (h) {
    if (h.manager.status !== "ok") reasons.push("Manager inacessível");
    if (h.indexer.status !== "ok") reasons.push("Indexer inacessível");
    if (h.stale) reasons.push("sem alertas recentes (> 5 min) — possível falha de ingestão");
  }
  el.className = `ls-banner ${cls}`;
  el.textContent = reasons.length ? `${label}: ${reasons.join("; ")}` : label;
}

function lsRenderHealth() {
  const h = lsHealth;
  if (!h) return;
  lsRenderStatus(h);
  lsComponent("ls-manager", h.manager);
  lsComponent("ls-indexer", h.indexer);
  const agents = h.agents;
  lsText("ls-agents-active", agents ? String(agents.active) : "Sem dados");
  lsText("ls-agents-down", agents ? String(agents.disconnected) : "Sem dados");
  lsText("ls-rate", h.alerts_per_minute === null ? "Sem dados" : `${h.truncated ? "≥ " : ""}${h.alerts_per_minute} /min`);

  let lag;
  if (h.indexer.status !== "ok") lag = "Indisponível";
  else if (h.last_alert_at === null) lag = "Sem alertas na última hora";
  else lag = lsFormatAge(h.ingestion_lag_seconds + (Date.now() - lsHealthFetchedAt) / 1000);
  lsText("ls-lag", lag);
  lsText("ls-health-note",
    `Janela da taxa: ${h.window_minutes} min. Atraso = idade do alerta mais recente no Indexer (pesquisa limitada à última hora).` +
    (h.truncated ? " Aviso: resultado truncado (limite de alertas lido) — a taxa é um mínimo." : ""));
}

async function lsRefreshHealth() {
  if (lsRefreshing) return;
  lsRefreshing = true;
  try {
    const response = await fetch(`${API_BASE}/api/siem/health`, { headers: { "X-API-Key": API_KEY } });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    lsHealth = await response.json();
    lsHealthFetchedAt = Date.now();
    lsRenderHealth();
  } catch (err) {
    lsHealth = null;
    lsRenderStatus(null);
    ["ls-manager", "ls-indexer", "ls-agents-active", "ls-agents-down", "ls-rate", "ls-lag"].forEach((id) => {
      const el = document.getElementById(id);
      el.textContent = "Sem dados";
      el.className = el.className.replace(/ls-(ok|down)/g, "").trim();
    });
    lsText("ls-health-note", `Backend inacessível: ${err.message}`);
  } finally {
    lsRefreshing = false;
  }
}

// ----- Ciclo de vida: só trabalha com a aba ativa e visível -----

let lsLoadedOnce = false;

function lsOnShow() {
  if (!lsIsActive()) return;
  lsRenderConnection();
  lsRefreshHealth();
  if (!lsLoadedOnce) {
    lsLoadedOnce = true;
    lsLoadInitialFeed();
  }
}

new MutationObserver(lsOnShow).observe(lsTab, { attributes: true, attributeFilter: ["class"] });
document.addEventListener("visibilitychange", lsOnShow);

setInterval(() => { if (lsIsActive()) lsRefreshHealth(); }, LS_REFRESH_MS);
// Tick leve (sem rede): estado da ligação e contador do atraso.
setInterval(() => {
  if (!lsIsActive()) return;
  lsRenderConnection();
  lsRenderHealth();
}, LS_TICK_MS);

lsOnShow();
