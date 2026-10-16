// Visão Geral (Roadmap v2, Overview profissional, Fase A). Carregado depois
// de app.js: reutiliza os seus globais (API_BASE, API_KEY, escapeHtml,
// activateTab, ws, inRealtimeFallback) — não redeclarar nenhum aqui. NÃO edita
// app.js nem abre um 2º WebSocket: o estado "tempo real" lê o `ws` existente.
//
// Responde a 3 perguntas com dados que os endpoints já têm:
//   1. A infraestrutura de deteção está saudável?   GET /api/siem/health
//   2. O que exige ação agora?                      /api/incidents, /api/vaccines
//   3. Quão bem detetamos?                          GET /api/metrics
// Cada fonte é isolada (Promise.allSettled): uma em baixo nunca esconde as
// outras. Sem dados reais mostra "—"/"Sem dados", nunca 0 inventado, e a
// lista "Requer atenção" nunca diz "tudo em ordem" se alguma fonte falhou.
// Só pede dados com a aba ativa e o separador visível (não é WS-driven: o
// Overview não deve "piscar" a cada alerta). Todo o texto dinâmico passa por
// escapeHtml.

const OVW_REFRESH_MS = 30000;
const OVW_WINDOW_HOURS = 168;
const OVW_MAX_ATTENTION = 8;
const OVW_SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const OVW_SEV_LABEL = { critical: "Crítico", high: "Alto", medium: "Médio", low: "Baixo", info: "Info" };
const OVW_OPEN_STATUSES = ["NEW", "INVESTIGATING", "CONTAINED"];

const ovwTab = document.getElementById("tab-overview");
let ovwLoadedOnce = false;
let ovwRefreshing = false;

function ovwIsActive() {
  return ovwTab.classList.contains("active") && document.visibilityState === "visible";
}

function ovwRequest(path) {
  return apiRequest(path);
}

function ovwText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function ovwFormatSeconds(value) {
  if (value === null || value === undefined) return "—";
  const s = Number(value);
  if (!Number.isFinite(s)) return "—";
  if (s < 60) return `${s.toFixed(1)} s`;
  if (s < 3600) return `${Math.floor(s / 60)} min ${Math.round(s % 60)} s`;
  return `${Math.floor(s / 3600)} h ${Math.round((s % 3600) / 60)} min`;
}

function ovwFormatAge(seconds) {
  if (seconds === null || seconds === undefined || !Number.isFinite(Number(seconds))) return "—";
  const s = Math.max(0, Math.round(Number(seconds)));
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.floor(s / 60)} min`;
  if (s < 86400) return `${Math.floor(s / 3600)} h`;
  return `${Math.floor(s / 86400)} d`;
}

// Wazuh envia "+0000"; Safari/Firefox exigem "+00:00" em new Date().
function ovwParseDate(ts) {
  return new Date(String(ts).replace(/([+-]\d{2})(\d{2})$/, "$1:$2"));
}

// ----- Faixa de estado -----

function ovwSetChip(id, level, text) {
  const el = document.getElementById(id);
  if (!el) return;
  el.className = `ovw-chip ovw-${level}`;
  el.textContent = text;
}

function ovwRenderStatus(health, error) {
  if (!health) {
    ovwSetChip("ovw-chip-siem", "unknown", error ? "SIEM: indisponível" : "SIEM: a carregar…");
    for (const id of ["ovw-chip-manager", "ovw-chip-indexer", "ovw-chip-agents", "ovw-chip-ingest"]) {
      ovwSetChip(id, "unknown", "—");
    }
  } else {
    const siemLevel = { ok: "ok", degraded: "warn", down: "bad" }[health.status] || "unknown";
    const siemLabel = { ok: "SIEM operacional", degraded: "SIEM degradado", down: "SIEM em baixo" }[health.status] || "SIEM: estado desconhecido";
    ovwSetChip("ovw-chip-siem", siemLevel, siemLabel);
    ovwSetChip("ovw-chip-manager", health.manager.status === "ok" ? "ok" : "bad",
      `Manager ${health.manager.status === "ok" ? "ligado" : "indisponível"}`);
    ovwSetChip("ovw-chip-indexer", health.indexer.status === "ok" ? "ok" : "bad",
      `Indexer ${health.indexer.status === "ok" ? "ligado" : "indisponível"}`);

    const a = health.agents;
    if (a) {
      const offline = a.disconnected + a.never_connected;
      ovwSetChip("ovw-chip-agents", offline > 0 ? "warn" : "ok", `Agentes ${a.active}/${a.total} ativos`);
    } else {
      ovwSetChip("ovw-chip-agents", "unknown", "Agentes: sem dados");
    }

    if (health.last_alert_at && health.ingestion_lag_seconds !== null && health.ingestion_lag_seconds !== undefined) {
      const lag = `último alerta há ${ovwFormatAge(health.ingestion_lag_seconds)}`;
      ovwSetChip("ovw-chip-ingest", health.stale ? "warn" : "ok",
        `${lag}${health.alerts_per_minute != null ? ` · ${Number(health.alerts_per_minute).toFixed(1)}/min` : ""}`);
    } else {
      ovwSetChip("ovw-chip-ingest", "unknown", "Ingestão: sem alertas recentes");
    }
  }

  // Tempo real: lê o WebSocket que app.js já gere (ws, inRealtimeFallback).
  const live = typeof ws !== "undefined" && ws && ws.readyState === WebSocket.OPEN;
  const fallback = typeof inRealtimeFallback !== "undefined" && inRealtimeFallback;
  ovwSetChip("ovw-chip-realtime", live ? "ok" : (fallback ? "warn" : "unknown"),
    live ? "Tempo real ativo" : (fallback ? "Tempo real indisponível (30 s)" : "Tempo real: a ligar…"));
  ovwText("ovw-updated", `Atualizado às ${new Date().toLocaleTimeString("pt-PT")}`);
}

// ----- KPIs -----

function ovwKpi(valueId, subId, value, sub, level) {
  const valueEl = document.getElementById(valueId);
  valueEl.textContent = value;
  valueEl.parentElement.dataset.level = level || "";
  ovwText(subId, sub);
}

function ovwRenderIncidentKpi(incidents, error) {
  if (!incidents) {
    ovwKpi("ovw-kpi-incidents", "ovw-kpi-incidents-sub", "—", error ? "Fonte indisponível" : "A carregar…", "");
    return;
  }
  const s = incidents.summary || {};
  const open = Number(s.open) || 0;
  const hot = Number(s.high_or_critical_open) || 0;
  ovwKpi("ovw-kpi-incidents", "ovw-kpi-incidents-sub", String(open),
    open === 0 ? "Nenhum incidente aberto" : `${hot} alta/crítica`, hot > 0 ? "bad" : (open > 0 ? "warn" : "ok"));
}

function ovwRenderMttdKpi(metrics, error) {
  if (!metrics) {
    ovwKpi("ovw-kpi-mttd", "ovw-kpi-mttd-sub", "—", error ? "Fonte indisponível" : "A carregar…", "");
    return;
  }
  const m = metrics.mttd || {};
  if (m.available === false) {
    ovwKpi("ovw-kpi-mttd", "ovw-kpi-mttd-sub", "—", m.reason === "source_unavailable" ? "Fonte indisponível" : "Sem dados", "");
    return;
  }
  ovwKpi("ovw-kpi-mttd", "ovw-kpi-mttd-sub", ovwFormatSeconds(m.median_s),
    `mediana · n=${m.n}${m.small_sample ? " · amostra pequena" : ""}`, "");
}

function ovwRenderRateKpi(metrics, error) {
  if (!metrics) {
    ovwKpi("ovw-kpi-rate", "ovw-kpi-rate-sub", "—", error ? "Fonte indisponível" : "A carregar…", "");
    return;
  }
  const r = metrics.rate || {};
  if (r.available === false) {
    ovwKpi("ovw-kpi-rate", "ovw-kpi-rate-sub", "—", r.reason === "source_unavailable" ? "Fonte indisponível" : "Sem ataques lançados", "");
    return;
  }
  const pct = r.detection_pct;
  const level = pct === null || pct === undefined ? "" : (pct >= 80 ? "ok" : (pct >= 50 ? "warn" : "bad"));
  const truncated = metrics.alerts_truncated ? " · limite inferior (alertas truncados)" : "";
  ovwKpi("ovw-kpi-rate", "ovw-kpi-rate-sub", pct === null || pct === undefined ? "—" : `${pct}%`,
    `${r.detected}/${r.launched} detetados${r.small_sample ? " · amostra pequena" : ""}${truncated}`, level);
}

// ----- Requer atenção -----

// Cada item: { sev (0 = mais grave), level, title, detail, tab }. A ordem final
// é por gravidade e depois pela ordem em que foram juntados (estável).
function ovwBuildAttention(health, healthErr, incidents, incErr, vaccines, vacErr) {
  const items = [];
  const unavailable = [];

  if (health) {
    if (health.status === "down") {
      items.push({ sev: 0, level: "bad", title: "SIEM em baixo", detail: "Manager e Indexer não respondem — não há alertas novos.", tab: "live-soc" });
    } else if (health.status === "degraded") {
      const parts = [];
      if (health.manager.status !== "ok") parts.push("Manager");
      if (health.indexer.status !== "ok") parts.push("Indexer");
      if (health.stale) parts.push("ingestão desatualizada");
      items.push({ sev: 1, level: "warn", title: "SIEM degradado", detail: parts.length ? `Problema: ${parts.join(", ")}.` : "Estado degradado.", tab: "live-soc" });
    }
    if (health.truncated) {
      items.push({ sev: 3, level: "warn", title: "Alertas truncados no Indexer", detail: "Atingido o limite de alertas: métricas e deteções podem ser limites inferiores.", tab: "live-soc" });
    }
    if (health.agents) {
      const offline = health.agents.disconnected + health.agents.never_connected;
      if (offline > 0) {
        items.push({ sev: 2, level: "warn", title: `${offline} agente(s) sem ligação`,
          detail: `${health.agents.disconnected} desligado(s), ${health.agents.never_connected} nunca ligado(s).`, tab: "agents" });
      }
    }
  } else {
    unavailable.push("estado do SIEM");
  }

  if (incidents) {
    const now = Date.now();
    for (const inc of incidents.incidents || []) {
      if (!OVW_OPEN_STATUSES.includes(inc.status)) continue;
      if (!(inc.severity === "critical" || inc.severity === "high")) continue;
      const deadline = inc.sla_deadline ? ovwParseDate(inc.sla_deadline).getTime() : NaN;
      const slaBreached = Number.isFinite(deadline) && deadline < now;
      const age = inc.last_evidence_at ? Math.max(0, (now - ovwParseDate(inc.last_evidence_at).getTime()) / 1000) : null;
      items.push({
        sev: (inc.severity === "critical" ? 0 : 1) + (slaBreached ? -0.5 : 0),
        level: inc.severity === "critical" ? "bad" : "warn",
        title: `Incidente #${inc.id} · ${OVW_SEV_LABEL[inc.severity] || inc.severity}`,
        detail: `${inc.asset || "ativo desconhecido"} · ${inc.status}${slaBreached ? " · SLA ultrapassado" : ""}${age !== null ? ` · evidência há ${ovwFormatAge(age)}` : ""}`,
        tab: "incidents",
      });
    }
  } else {
    unavailable.push("incidentes");
  }

  if (vaccines) {
    if (vaccines.total > 0) {
      items.push({ sev: 4, level: "info", title: `${vaccines.total} vaccine(s) proposta(s) por rever`,
        detail: "Propostas de deteção geradas para ataques não (totalmente) detetados.", tab: "vaccines" });
    }
  } else {
    unavailable.push("vaccines");
  }

  items.sort((a, b) => a.sev - b.sev);
  return { items, unavailable };
}

function ovwRenderAttention(result) {
  const list = document.getElementById("ovw-attention-list");
  const { items, unavailable } = result;
  const shown = items.slice(0, OVW_MAX_ATTENTION);
  const rows = shown.map((it) => htmlT`<li><button type="button" class="ovw-attn ovw-${it.level}" data-tab="${it.tab}"><span class="ovw-attn-title">${it.title}</span><span class="ovw-attn-detail">${it.detail}</span></button></li>`);
  const more = items.length > shown.length
    ? htmlT`<li class="ovw-attn-more">+ ${items.length - shown.length} mais — ver a aba respetiva.</li>`
    : "";
  // Nunca "tudo em ordem" quando uma fonte falhou: não sabemos se está.
  const clear = !items.length && !unavailable.length
    ? htmlT`<li class="ovw-attn-clear">✓ Nada a exigir atenção neste momento.</li>`
    : "";
  const missing = unavailable.length
    ? htmlT`<li class="ovw-attn-unavailable">⚠ Sem dados de: ${unavailable.join(", ")} — esta lista pode estar incompleta.</li>`
    : "";
  htmRender(list, clear ? htmlT`${clear}${missing}` : htmlT`${rows}${more}${missing}`);
  ovwText("ovw-attention-count", items.length ? String(items.length) : "");
}

// ----- Ciclo de atualização -----

async function ovwRefresh() {
  if (ovwRefreshing) return;
  ovwRefreshing = true;
  try {
    const [h, i, m, v] = await Promise.allSettled([
      ovwRequest("/api/siem/health"),
      ovwRequest(`/api/incidents?hours=${OVW_WINDOW_HOURS}&limit=100`),
      ovwRequest(`/api/metrics?hours=${OVW_WINDOW_HOURS}`),
      ovwRequest("/api/vaccines?limit=1"),
    ]);
    const val = (r) => (r.status === "fulfilled" ? r.value : null);
    const err = (r) => r.status === "rejected";
    ovwRenderStatus(val(h), err(h));
    ovwRenderIncidentKpi(val(i), err(i));
    ovwRenderMttdKpi(val(m), err(m));
    ovwRenderRateKpi(val(m), err(m));
    ovwRenderAttention(ovwBuildAttention(val(h), err(h), val(i), err(i), val(v), err(v)));
  } finally {
    ovwRefreshing = false;
  }
}

function ovwOnShow() {
  if (!ovwIsActive()) return;
  ovwLoadedOnce = true;
  ovwRefresh();
}

document.getElementById("ovw-attention-list").addEventListener("click", (event) => {
  const btn = event.target.closest("button[data-tab]");
  if (btn) activateTab(btn.dataset.tab);
});

new MutationObserver(ovwOnShow).observe(ovwTab, { attributes: true, attributeFilter: ["class"] });
document.addEventListener("visibilitychange", ovwOnShow);
setInterval(() => { if (ovwIsActive() && ovwLoadedOnce) ovwRefresh(); }, OVW_REFRESH_MS);

ovwOnShow();
