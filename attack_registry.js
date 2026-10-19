// Abas "Attack Registry" e "Attack Timeline" (Roadmap v2, R4). Carregado depois
// de app.js: reutiliza os seus globais (API_BASE, API_KEY,
// severityBadge, formatTimestamp, renderPanelError, windowSelect) — não
// redeclarar nenhum aqui. As duas abas partilham o mesmo pedido a
// GET /api/attacks; só mostram dados reais, sem dados -> estado vazio. Só
// trabalha com uma das abas ativa e o separador visível (sem refresh em
// segundo plano) e não abre WebSockets. Todo o texto dinâmico (operador,
// ferramenta, alvo, cenário...) é escapado pelo htmlT.

const ATK_REFRESH_MS = 30000;
const ATK_VERDICT_LABELS = {
  detected: "Detetado", partial: "Parcial", not_detected: "Não detetado", unknown: "Desconhecido",
};
const ATK_SOURCE_LABELS = { rule: "Regra", ml: "ML", network: "Rede" };
const ATK_ERROR_LABELS = {
  indexer_unavailable: "o Wazuh Indexer não respondeu",
  ml_model_unavailable: "o modelo de ML não está disponível",
  attack_outside_alert_window: "o ataque é anterior à janela de alertas suportada (30 dias)",
};
const ATK_TECHNIQUE_RE = /^T\d{4}(\.\d{3})?$/;

const atkTabs = [document.getElementById("tab-attack-registry"), document.getElementById("tab-attack-timeline")];
let atkAttacks = [];
let atkSelectedId = null;
let atkRefreshing = false;
let atkSeq = 0;
let atkPending = false;

function atkIsActive() {
  return atkTabs.some((t) => t.classList.contains("active")) && document.visibilityState === "visible";
}

// Texto simples: o htmlT escapa na interpolação.
function atkCell(value) {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
}

function atkSetText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function atkSources(list) {
  return list && list.length ? list.map((s) => ATK_SOURCE_LABELS[s] || s).join(", ") : "—";
}

function atkVerdictBadge(verdict) {
  const label = ATK_VERDICT_LABELS[verdict] || verdict;
  return htmlT`<span class="atk-verdict atk-verdict-${verdict}">${label}</span>`;
}

function atkFormatSeconds(seconds) {
  if (seconds === null || seconds === undefined) return "—";
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  return `${Math.floor(seconds / 60)} min ${Math.round(seconds % 60)} s`;
}

function atkRequest(path) {
  return apiRequest(path);
}

function atkQuery() {
  // O endpoint aceita no máximo 720 h (30 dias); a nota da aba diz o recorte.
  const params = new URLSearchParams({ hours: String(slEffectiveWindow(windowSelect.value, 720).hours), limit: "500" });
  const status = document.getElementById("atk-status-filter").value;
  const technique = document.getElementById("atk-technique-filter").value.trim().toUpperCase();
  if (status) params.set("status", status);
  if (technique) params.set("technique", technique);
  return params;
}

function atkTechniqueValid() {
  const technique = document.getElementById("atk-technique-filter").value.trim().toUpperCase();
  return technique === "" || ATK_TECHNIQUE_RE.test(technique);
}

function atkCorrelationNote(data) {
  const c = data.correlation || {};
  const parts = [];
  if (!c.available) {
    parts.push(`⚠️ Correlação indisponível (${ATK_ERROR_LABELS[c.error_code] || "erro interno"}): o veredito fica «Desconhecido».`);
  }
  if (c.alerts_truncated) {
    parts.push("⚠️ Atingido o teto de alertas pedidos ao Indexer: ataques sem correspondência ficam «Desconhecido» (os alertas mais antigos foram cortados).");
  }
  if (data.incidents_available === false) parts.push("⚠️ Base de incidentes indisponível: a coluna «Incidentes» está incompleta.");
  const sk = data.skipped || {};
  const skipped = (sk.not_executed || 0) + (sk.unknown_scenario || 0) + (sk.invalid || 0);
  if (skipped) {
    parts.push(`${skipped} entrada(s) do log fora do registo (não lançadas, cenário desconhecido ou inválidas).`);
  }
  return parts.join(" ");
}

function renderAttackKpis(summary) {
  atkSetText("kpi-atk-total", summary.total);
  atkSetText("kpi-atk-detected", summary.detected);
  atkSetText("kpi-atk-partial", summary.partial);
  atkSetText("kpi-atk-missed", summary.not_detected);
}

function renderAttacksTable(attacks) {
  const body = document.getElementById("attacks-body");
  if (!attacks.length) {
    htmRender(body, htmlT`<tr><td colspan="10" class="empty-state">Sem dados — nenhum ataque lançado nesta janela.</td></tr>`);
    return;
  }
  htmRender(body, htmlT`${attacks.map((a) => {
    const clickable = a.id !== null;
    const incidents = a.incidents.length ? a.incidents.map((i) => i.id).join(", ") : "—";
    const rowAttrs = clickable ? htmlT` data-id="${String(a.id)}" tabindex="0"` : "";
    return htmlT`<tr class="${clickable ? "atk-row" : ""}${a.id === atkSelectedId ? " selected" : ""}"${rowAttrs}>
      <td>${a.id === null ? "—" : String(a.id)}${a.duplicate_id ? " ⚠️" : ""}</td>
      <td>${formatTimestamp(a.timestamp)}</td>
      <td>${atkCell(a.scenario)}</td>
      <td>${atkCell(a.mitre_technique)}</td>
      <td>${atkCell(a.tool)}</td>
      <td>${atkCell(a.target)}</td>
      <td>${atkCell(a.operator)}</td>
      <td>${atkSources(a.expected.detection)}</td>
      <td>${atkVerdictBadge(a.actual.verdict)}</td>
      <td>${a.id === null ? "—" : atkCell(incidents === "—" ? "" : incidents)}</td>
    </tr>`;
  })}`);
}

// Faixa ataque -> deteção (W6.5), SVG à mão: uma linha por ataque, losango no lançamento,
// um ponto por sensor à distância do MTTD. Sem deteção: só o losango e «não detetado».
const ATK_STRIP = { labelW: 190, plotW: 520, rowH: 28, top: 26, right: 24 };

function renderAttackStrip(attacks) {
  const box = document.getElementById("atk-strip");
  const details = document.getElementById("atk-strip-details");
  const { rows, maxSeconds } = slAttackStrip(attacks);
  if (!rows.length) {
    box.textContent = "Sem dados — nenhum ataque lançado nesta janela.";
    box.setAttribute("aria-label", "Faixa ataque → deteção: sem dados nesta janela");
    details.hidden = true;
    return;
  }
  const { labelW, plotW, rowH, top, right } = ATK_STRIP;
  const width = labelW + plotW + right;
  const height = top + rows.length * rowH + 8;
  const x = (sec) => labelW + (sec / maxSeconds) * plotW;
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => f * maxSeconds);
  const cy = (i) => top + i * rowH + rowH / 2;
  const dy = { rule: -4, ml: 4, network: 0 };
  const svg = htmlT`<svg class="atk-strip-svg" viewBox="0 0 ${width} ${height}" width="${width}" aria-hidden="true" focusable="false">
    ${ticks.map((t) => htmlT`<line class="atk-strip-grid" x1="${x(t)}" x2="${x(t)}" y1="${top - 6}" y2="${height - 8}"/><text class="atk-strip-tick" x="${x(t)}" y="${top - 12}" text-anchor="middle">${fmtDuration(t)}</text>`)}
    ${rows.map((r, i) => htmlT`<g>
      <text class="atk-strip-label" x="${labelW - 10}" y="${cy(i) + 4}" text-anchor="end">${slTruncate(r.label, 26)}<title>${r.label}</title></text>
      ${r.points.length ? htmlT`<line class="atk-strip-link" x1="${x(0)}" x2="${x(Math.max(...r.points.map((p) => p.seconds)))}" y1="${cy(i)}" y2="${cy(i)}"/>` : ""}
      <polygon class="atk-strip-launch" points="${x(0)},${cy(i) - 6} ${x(0) + 6},${cy(i)} ${x(0)},${cy(i) + 6} ${x(0) - 6},${cy(i)}"><title>Lançamento</title></polygon>
      ${r.points.map((p) => htmlT`<circle class="atk-strip-dot atk-strip-${p.sensor}" cx="${x(p.seconds)}" cy="${cy(i) + dy[p.sensor]}" r="5"><title>${SL_SENSOR_LABELS[p.sensor]}: ${fmtDuration(p.seconds)}</title></circle>`)}
      ${r.detected ? "" : htmlT`<text class="atk-strip-miss" x="${x(0) + 14}" y="${cy(i) + 4}">${r.verdict === "unknown" ? "sem correlação" : "não detetado"}</text>`}
    </g>`)}
  </svg>`;
  const legend = htmlT`<p class="atk-strip-legend"><span class="atk-key atk-strip-rule"></span> Regra <span class="atk-key atk-strip-ml"></span> ML <span class="atk-key atk-strip-network"></span> Rede <span class="atk-key-diamond"></span> Lançamento · a distância ao losango é o MTTD (regra e ML partilham o mesmo valor)</p>`;
  htmRender(box, htmlT`${svg}${legend}`);
  const detected = rows.filter((r) => r.detected).length;
  box.setAttribute("aria-label", `Faixa ataque → deteção: ${rows.length} ataques, ${detected} detetados, ${rows.length - detected} sem deteção`);
  details.hidden = false;
  const cell = (r, s) => fmtDuration((r.points.find((p) => p.sensor === s) || {}).seconds);
  chartFillTable(document.getElementById("atk-strip-data"), ["Ataque", "Veredito", "Regra", "ML", "Rede"],
    rows.map((r) => [r.label, r.verdict, cell(r, "rule"), cell(r, "ml"), cell(r, "network")]));
}

function renderAttackTimeline(attacks) {
  renderAttackStrip(attacks);
  const list = document.getElementById("atk-timeline");
  if (!attacks.length) {
    htmRender(list, htmlT`<li class="empty-state">Sem dados — nenhum ataque lançado nesta janela.</li>`);
    return;
  }
  htmRender(list, htmlT`${[...attacks].reverse().map((a) => htmlT`<li>
    <time>${formatTimestamp(a.timestamp)}</time>
    ${a.id === null ? "" : `#${String(a.id)} `}<strong>${atkCell(a.scenario)}</strong>
    (${atkCell(a.mitre_technique)} / ${atkCell(a.tool)}) → ${atkCell(a.target)} · ${atkCell(a.operator)}
    ${atkVerdictBadge(a.actual.verdict)}
    <span class="panel-note">esperado: ${atkSources(a.expected.detection)}; observado: ${atkSources(a.actual.achieved)}${a.incidents.length ? `; incidentes: ${a.incidents.map((i) => i.id).join(", ")}` : ""}</span>
  </li>`)}`);
}

function renderAttackDetail(payload) {
  const a = payload.attack;
  const panel = document.getElementById("attack-detail-panel");
  panel.hidden = false;
  atkSetText("atk-detail-title", `Ataque #${a.id}`);
  htmRender(document.getElementById("atk-detail-meta"), htmlT`
    <span>${atkVerdictBadge(a.actual.verdict)}</span>
    <span>Hora: ${formatTimestamp(a.timestamp)}</span>
    <span>Cenário: <strong>${atkCell(a.scenario)}</strong></span>
    <span>MITRE: ${atkCell(a.mitre_technique)} (${atkCell(a.mitre_tactic)})</span>
    <span>Ferramenta: ${atkCell(a.tool)}</span>
    <span>Origem: ${atkCell(a.source)}</span>
    <span>Alvo: ${atkCell(a.target)}</span>
    <span>Operador: ${atkCell(a.operator)}</span>
    <span>MTTD: ${atkFormatSeconds(a.actual.mttd_seconds)}</span>
    ${a.actual.coverage_gap ? htmlT`<span>⚠️ Só a rede detetou (ponto cego Wazuh)</span>` : ""}`);

  const achieved = a.actual.achieved || [];
  const known = payload.correlation && payload.correlation.available;
  htmRender(document.getElementById("atk-detail-compare"), htmlT`${["rule", "ml", "network"].map((src) => {
    const expected = a.expected.detection.includes(src);
    const seen = known ? (achieved.includes(src) ? "Sim" : "Não") : "Desconhecido";
    return htmlT`<tr><td>${ATK_SOURCE_LABELS[src]}</td><td>${expected ? "Sim" : "—"}</td><td>${seen}</td></tr>`;
  })}`);

  const ev = a.evidence;
  const items = [
    `Esperado definido por: ${a.expected.source === "log" ? "o log do ataque" : "o cenário (por omissão)"}; Event IDs do cenário: ${a.expected.event_ids.join(", ")}`,
    `Alertas correlacionados: ${ev.matched_alert_count === null ? "desconhecido" : ev.matched_alert_count} (Event IDs: ${ev.matched_event_ids.length ? ev.matched_event_ids.join(", ") : "—"})`,
    `Deteções de rede: ${ev.network_detection_types.length ? ev.network_detection_types.join(", ") : "—"}`,
    `Incidentes ligados: ${a.incidents.length ? a.incidents.map((i) => `${i.id} (${i.status}, ${i.severity})`).join("; ") : "nenhum"}`,
  ];
  const note = known ? "" : atkCorrelationNote(payload);
  if (note) items.push(note);
  htmRender(document.getElementById("atk-detail-evidence"), htmlT`${items.map((t) => htmlT`<li>${t}</li>`)}`);
}

function atkShowDetailError(message) {
  const el = document.getElementById("atk-detail-error");
  el.hidden = !message;
  el.textContent = message ? `⚠️ ${message}` : "";
}

let atkSelectSeq = 0;
async function selectAttack(id) {
  const seq = ++atkSelectSeq;
  atkSelectedId = Number(id);
  atkShowDetailError("");
  document.querySelectorAll("#attacks-body tr[data-id]").forEach((tr) =>
    tr.classList.toggle("selected", tr.dataset.id === String(id)));
  try {
    const detail = await atkRequest(`/api/attacks/${encodeURIComponent(id)}`);
    if (seq !== atkSelectSeq) return;
    renderAttackDetail(detail);
  } catch (err) {
    if (seq !== atkSelectSeq) return;
    atkShowDetailError(apiErrorMessage(err));
  }
}

async function refreshAttacks() {
  if (atkRefreshing) { atkPending = true; return; }
  if (!atkTechniqueValid()) {
    atkSetText("atk-notice", "Técnica inválida: usa o formato T1110 ou T1110.003.");
    return;
  }
  atkRefreshing = true;
  const seq = ++atkSeq;
  try {
    const data = await atkRequest(`/api/attacks?${atkQuery()}`);
    if (seq !== atkSeq) return;
    renderPanelError("#attack-registry-panel", "");
    renderPanelError("#attack-timeline-panel", "");
    atkAttacks = data.attacks;
    atkSetText("atk-notice", atkCorrelationNote(data));
    renderAttackKpis(data.summary);
    renderAttacksTable(atkAttacks);
    renderAttackTimeline(atkAttacks);
  } catch (err) {
    const message = `Não foi possível carregar os ataques: ${apiErrorMessage(err)}`;
    renderPanelError("#attack-registry-panel", message);
    renderPanelError("#attack-timeline-panel", message);
    htmRender(document.getElementById("attacks-body"), htmlT`<tr><td colspan="10" class="empty-state">Indisponível.</td></tr>`);
    htmRender(document.getElementById("atk-timeline"), htmlT`<li class="empty-state">Indisponível.</li>`);
  } finally {
    atkRefreshing = false;
    if (atkPending) { atkPending = false; refreshAttacks(); }
  }
}

document.getElementById("attacks-body").addEventListener("click", (event) => {
  const tr = event.target.closest("tr[data-id]");
  if (tr) selectAttack(tr.dataset.id);
});
document.getElementById("attacks-body").addEventListener("keydown", (event) => {
  const tr = event.target.closest("tr[data-id]");
  if (tr && (event.key === "Enter" || event.key === " ")) {
    event.preventDefault();
    selectAttack(tr.dataset.id);
  }
});
document.getElementById("atk-status-filter").addEventListener("change", () => { if (atkIsActive()) refreshAttacks(); });
let atkTechniqueTimer = null;
document.getElementById("atk-technique-filter").addEventListener("input", () => {
  clearTimeout(atkTechniqueTimer);
  atkTechniqueTimer = setTimeout(() => { if (atkIsActive()) refreshAttacks(); }, 250);
});
windowSelect.addEventListener("change", () => { if (atkIsActive()) refreshAttacks(); });

// Ciclo de vida: só pede dados com uma das abas ativa e o separador visível.
let atkLoadedOnce = false;
function atkOnShow() {
  if (!atkIsActive()) return;
  refreshAttacks().then(() => { atkLoadedOnce = true; });
}
const atkObserver = new MutationObserver(atkOnShow);
atkTabs.forEach((t) => atkObserver.observe(t, { attributes: true, attributeFilter: ["class"] }));
document.addEventListener("visibilitychange", atkOnShow);
setInterval(() => { if (atkIsActive() && atkLoadedOnce) refreshAttacks(); }, ATK_REFRESH_MS);
atkOnShow();
