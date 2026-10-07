// Abas "Attack Registry" e "Attack Timeline" (Roadmap v2, R4). Carregado depois
// de app.js: reutiliza os seus globais (API_BASE, API_KEY, escapeHtml,
// severityBadge, formatTimestamp, renderPanelError, periodSelect) — não
// redeclarar nenhum aqui. As duas abas partilham o mesmo pedido a
// GET /api/attacks; só mostram dados reais, sem dados -> estado vazio. Só
// trabalha com uma das abas ativa e o separador visível (sem refresh em
// segundo plano) e não abre WebSockets. Todo o texto dinâmico (operador,
// ferramenta, alvo, cenário...) passa por escapeHtml.

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

function atkCell(value) {
  if (value === null || value === undefined || value === "") return "—";
  return escapeHtml(String(value));
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
  return `<span class="atk-verdict atk-verdict-${escapeHtml(verdict)}">${escapeHtml(label)}</span>`;
}

function atkFormatSeconds(seconds) {
  if (seconds === null || seconds === undefined) return "—";
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  return `${Math.floor(seconds / 60)} min ${Math.round(seconds % 60)} s`;
}

async function atkRequest(path) {
  const response = await fetch(`${API_BASE}${path}`, { headers: { "X-API-Key": API_KEY } });
  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    try {
      const data = await response.json();
      if (data && typeof data.detail === "string") detail = data.detail;
    } catch (_) { /* corpo não-JSON: fica o código HTTP */ }
    throw new Error(detail);
  }
  return response.json();
}

function atkQuery() {
  // period-select está em dias; o endpoint aceita no máximo 720 h (30 dias).
  const params = new URLSearchParams({ hours: String(Math.min(Number(periodSelect.value) * 24, 720)), limit: "500" });
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
    parts.push("⚠️ Atingido o teto de alertas pedidos ao Indexer: ataques antigos podem aparecer como não detetados por truncagem.");
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
    body.innerHTML = `<tr><td colspan="10" class="empty-state">Sem dados — nenhum ataque lançado nesta janela.</td></tr>`;
    return;
  }
  body.innerHTML = attacks.map((a) => {
    const clickable = a.id !== null;
    const incidents = a.incidents.length ? a.incidents.map((i) => i.id).join(", ") : "—";
    return `<tr class="${clickable ? "atk-row" : ""}${a.id === atkSelectedId ? " selected" : ""}"${clickable ? ` data-id="${escapeHtml(String(a.id))}" tabindex="0"` : ""}>
      <td>${a.id === null ? "—" : escapeHtml(String(a.id))}${a.duplicate_id ? " ⚠️" : ""}</td>
      <td>${escapeHtml(formatTimestamp(a.timestamp))}</td>
      <td>${atkCell(a.scenario)}</td>
      <td>${atkCell(a.mitre_technique)}</td>
      <td>${atkCell(a.tool)}</td>
      <td>${atkCell(a.target)}</td>
      <td>${atkCell(a.operator)}</td>
      <td>${escapeHtml(atkSources(a.expected.detection))}</td>
      <td>${atkVerdictBadge(a.actual.verdict)}</td>
      <td>${a.id === null ? "—" : atkCell(incidents === "—" ? "" : incidents)}</td>
    </tr>`;
  }).join("");
}

function renderAttackTimeline(attacks) {
  const list = document.getElementById("atk-timeline");
  if (!attacks.length) {
    list.innerHTML = `<li class="empty-state">Sem dados — nenhum ataque lançado nesta janela.</li>`;
    return;
  }
  list.innerHTML = [...attacks].reverse().map((a) => `<li>
    <time>${escapeHtml(formatTimestamp(a.timestamp))}</time>
    ${a.id === null ? "" : `#${escapeHtml(String(a.id))} `}<strong>${atkCell(a.scenario)}</strong>
    (${atkCell(a.mitre_technique)} / ${atkCell(a.tool)}) → ${atkCell(a.target)} · ${atkCell(a.operator)}
    ${atkVerdictBadge(a.actual.verdict)}
    <span class="panel-note">esperado: ${escapeHtml(atkSources(a.expected.detection))}; observado: ${escapeHtml(atkSources(a.actual.achieved))}${a.incidents.length ? `; incidentes: ${escapeHtml(a.incidents.map((i) => i.id).join(", "))}` : ""}</span>
  </li>`).join("");
}

function renderAttackDetail(payload) {
  const a = payload.attack;
  const panel = document.getElementById("attack-detail-panel");
  panel.hidden = false;
  atkSetText("atk-detail-title", `Ataque #${a.id}`);
  document.getElementById("atk-detail-meta").innerHTML = `
    <span>${atkVerdictBadge(a.actual.verdict)}</span>
    <span>Hora: ${escapeHtml(formatTimestamp(a.timestamp))}</span>
    <span>Cenário: <strong>${atkCell(a.scenario)}</strong></span>
    <span>MITRE: ${atkCell(a.mitre_technique)} (${atkCell(a.mitre_tactic)})</span>
    <span>Ferramenta: ${atkCell(a.tool)}</span>
    <span>Origem: ${atkCell(a.source)}</span>
    <span>Alvo: ${atkCell(a.target)}</span>
    <span>Operador: ${atkCell(a.operator)}</span>
    <span>MTTD: ${escapeHtml(atkFormatSeconds(a.actual.mttd_seconds))}</span>
    ${a.actual.coverage_gap ? "<span>⚠️ Só a rede detetou (ponto cego Wazuh)</span>" : ""}`;

  const achieved = a.actual.achieved || [];
  const known = payload.correlation && payload.correlation.available;
  document.getElementById("atk-detail-compare").innerHTML = ["rule", "ml", "network"].map((src) => {
    const expected = a.expected.detection.includes(src);
    const seen = known ? (achieved.includes(src) ? "Sim" : "Não") : "Desconhecido";
    return `<tr><td>${escapeHtml(ATK_SOURCE_LABELS[src])}</td><td>${expected ? "Sim" : "—"}</td><td>${escapeHtml(seen)}</td></tr>`;
  }).join("");

  const ev = a.evidence;
  const items = [
    `Esperado definido por: ${a.expected.source === "log" ? "o log do ataque" : "o cenário (por omissão)"}; Event IDs do cenário: ${a.expected.event_ids.join(", ")}`,
    `Alertas correlacionados: ${ev.matched_alert_count === null ? "desconhecido" : ev.matched_alert_count} (Event IDs: ${ev.matched_event_ids.length ? ev.matched_event_ids.join(", ") : "—"})`,
    `Deteções de rede: ${ev.network_detection_types.length ? ev.network_detection_types.join(", ") : "—"}`,
    `Incidentes ligados: ${a.incidents.length ? a.incidents.map((i) => `${i.id} (${i.status}, ${i.severity})`).join("; ") : "nenhum"}`,
  ];
  document.getElementById("atk-detail-evidence").innerHTML = items.map((t) => `<li>${escapeHtml(t)}</li>`).join("");
  if (!known) {
    const note = atkCorrelationNote(payload);
    if (note) document.getElementById("atk-detail-evidence").innerHTML += `<li>${escapeHtml(note)}</li>`;
  }
}

function atkShowDetailError(message) {
  const el = document.getElementById("atk-detail-error");
  el.hidden = !message;
  el.textContent = message ? `⚠️ ${message}` : "";
}

async function selectAttack(id) {
  atkSelectedId = Number(id);
  atkShowDetailError("");
  document.querySelectorAll("#attacks-body tr[data-id]").forEach((tr) =>
    tr.classList.toggle("selected", tr.dataset.id === String(id)));
  try {
    renderAttackDetail(await atkRequest(`/api/attacks/${encodeURIComponent(id)}`));
  } catch (err) {
    atkShowDetailError(err.message);
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
    const message = `Não foi possível carregar os ataques: ${err.message}`;
    renderPanelError("#attack-registry-panel", message);
    renderPanelError("#attack-timeline-panel", message);
    document.getElementById("attacks-body").innerHTML = `<tr><td colspan="10" class="empty-state">Indisponível.</td></tr>`;
    document.getElementById("atk-timeline").innerHTML = `<li class="empty-state">Indisponível.</li>`;
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
document.getElementById("atk-technique-filter").addEventListener("input", () => { if (atkIsActive()) refreshAttacks(); });
periodSelect.addEventListener("change", () => { if (atkIsActive()) refreshAttacks(); });

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
