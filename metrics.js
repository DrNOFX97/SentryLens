// Abas "MTTD / MTTR", "Detection Coverage" e "Detection Rate" (Roadmap v2, R8).
// Carregado depois de app.js: reutiliza os seus globais (API_BASE, API_KEY,
// escapeHtml, renderPanelError) — não redeclarar nenhum aqui. Consome só
// GET /api/metrics (um único pedido serve as 3 abas). Só pede dados com uma
// das abas ativa e o separador visível. Só mostra dados reais: sem amostra ->
// "Sem dados"; amostra pequena -> aviso. Todo o texto dinâmico passa por
// escapeHtml.

const MET_REFRESH_MS = 30000;
const MET_TAB_IDS = ["tab-mttd-mttr", "tab-detection-coverage", "tab-detection-rate"];
const MET_SOURCE_LABELS = { rule: "Regra", ml: "ML", network: "Rede", multiple: "Várias fontes" };

const metTabs = MET_TAB_IDS.map((id) => document.getElementById(id));

function metIsActive() {
  return metTabs.some((tab) => tab.classList.contains("active")) && document.visibilityState === "visible";
}

function metFormatSeconds(value) {
  if (value === null || value === undefined) return "—";
  const s = Number(value);
  if (!Number.isFinite(s)) return "—";
  if (s < 60) return `${s.toFixed(1)} s`;
  if (s < 3600) return `${Math.floor(s / 60)} min ${Math.round(s % 60)} s`;
  return `${Math.floor(s / 3600)} h ${Math.round((s % 3600) / 60)} min`;
}

function metPct(value) {
  return value === null || value === undefined ? "—" : `${value}%`;
}

function metText(id, text) {
  document.getElementById(id).textContent = text;
}

function metNote(id, block, label) {
  if (!block || block.available === false) {
    const down = block && block.reason === "source_unavailable";
    metText(id, down ? `${label}: fonte indisponível.` : `${label}: sem dados.`);
    return;
  }
  metText(id, block.small_sample ? `${label}: amostra pequena (n=${block.n}).` : `${label}: n=${block.n}.`);
}

async function metRequest(path) {
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

function metRenderMttd(data) {
  const mttd = data.mttd || {};
  const mttr = data.mttr || {};
  metText("met-mttd-median", metFormatSeconds(mttd.median_s));
  metText("met-mttd-p90", metFormatSeconds(mttd.p90_s));
  metText("met-mttr-median", metFormatSeconds(mttr.median_s));
  metText("met-mttr-p90", metFormatSeconds(mttr.p90_s));
  metText("met-first-response", metFormatSeconds(mttr.first_response && mttr.first_response.median_s));
  metText("met-open-count", mttr.open_count === null || mttr.open_count === undefined ? "—" : String(mttr.open_count));
  metNote("met-mttd-note", mttd, "MTTD");
  metNote("met-mttr-note", mttr, "MTTR");
  metText("met-mttd-def", `${(data.definitions || {}).mttd || ""} ${(data.definitions || {}).mttr || ""}`);

  const rows = Object.entries(mttd.by_scenario || {});
  document.getElementById("met-mttd-body").innerHTML = rows.length
    ? rows.map(([name, b]) => `<tr>
        <td>${escapeHtml(name)}</td>
        <td>${b.n}</td>
        <td>${metFormatSeconds(b.median_s)}</td>
        <td>${metFormatSeconds(b.p90_s)}</td>
        <td>${metFormatSeconds(b.avg_s)}</td>
      </tr>`).join("")
    : `<tr><td colspan="5" class="empty-state">Sem dados.</td></tr>`;
}

function metGapList(id, items, available) {
  // Sem dados != sem lacunas: só afirma "Nenhuma lacuna" se a cobertura foi calculada.
  document.getElementById(id).innerHTML = items && items.length
    ? items.map((x) => `<li>${escapeHtml(x)}</li>`).join("")
    : `<li class="empty-state">${available === false ? "Sem dados." : "Nenhuma lacuna."}</li>`;
}

function metRenderCoverage(data) {
  const cov = data.coverage || {};
  const sc = cov.scenarios;
  const te = cov.techniques;
  metText("met-cov-scenarios", sc && sc.total ? `${sc.covered}/${sc.total} (${metPct(sc.pct)})` : "—");
  metText("met-cov-techniques", te && te.total ? `${te.covered}/${te.total} (${metPct(te.pct)})` : "—");
  metText("met-cov-note", cov.available === false
    ? (cov.reason === "source_unavailable" ? "Fonte indisponível." : "Sem dados: nenhum ataque lançado na janela.")
    : `Janela de ${data.window_hours} h.`);
  metText("met-cov-def", (data.definitions || {}).coverage || "");
  metGapList("met-gaps-scenarios", cov.gaps && cov.gaps.scenarios, cov.available);
  metGapList("met-gaps-techniques", cov.gaps && cov.gaps.techniques, cov.available);
}

function metRenderRate(data) {
  const rate = data.rate || {};
  const fp = rate.false_positives || {};
  const num = (v) => (v === null || v === undefined ? "—" : String(v));
  metText("met-rate-launched", num(rate.launched));
  metText("met-rate-detected", num(rate.detected));
  metText("met-rate-pct", metPct(rate.detection_pct));
  metText("met-rate-fn", num(rate.false_negatives));
  metText("met-rate-fp", fp.available === false ? "—"
    : (fp.pct === null || fp.pct === undefined ? `${fp.n}/${fp.closed_total} (amostra pequena)` : `${fp.n}/${fp.closed_total} (${fp.pct}%)`));
  metText("met-rate-note", rate.available === false
    ? (rate.reason === "source_unavailable" ? "Fonte indisponível." : "Sem dados: nenhum ataque lançado na janela.")
    : (rate.small_sample ? `Amostra pequena (n=${rate.launched}).` : `Janela de ${data.window_hours} h.`));
  const ex = rate.excluded;
  metText("met-rate-excluded", ex
    ? `Fora do cálculo: ${ex.not_executed} não executado(s), ${ex.unknown_scenario} de cenário desconhecido, ${ex.invalid_entries} entrada(s) inválida(s).`
    : "");
  metText("met-rate-def", `${(data.definitions || {}).rate || ""} ${(data.definitions || {}).fn || ""} ${(data.definitions || {}).fp || ""}`);

  const by = rate.by_source;
  document.getElementById("met-rate-body").innerHTML = by
    ? Object.keys(MET_SOURCE_LABELS).map((k) => `<tr><td>${escapeHtml(MET_SOURCE_LABELS[k])}</td><td>${by[k]}</td></tr>`).join("")
    : `<tr><td colspan="2" class="empty-state">Sem dados.</td></tr>`;
}

async function refreshMetrics() {
  try {
    const data = await metRequest("/api/metrics?hours=168");
    for (const id of ["#mttd-mttr-panel", "#detection-coverage-panel", "#detection-rate-panel"]) renderPanelError(id, null);
    metRenderMttd(data);
    metRenderCoverage(data);
    metRenderRate(data);
    if (data.alerts_truncated) {
      // O Indexer devolveu o teto de alertas: ataques antigos podem ficar sem os
      // seus alertas e parecer não detetados — os valores são limites inferiores.
      const warn = " ⚠ Alertas truncados no limite do Indexer (1000): ataques antigos podem aparecer como não detetados; estes valores são limites inferiores.";
      for (const id of ["met-mttd-note", "met-cov-note", "met-rate-note"]) {
        document.getElementById(id).textContent += warn;
      }
    }
  } catch (err) {
    for (const id of ["#mttd-mttr-panel", "#detection-coverage-panel", "#detection-rate-panel"]) {
      renderPanelError(id, `Não foi possível carregar as métricas: ${err.message}`);
    }
  }
}

let metLoadedOnce = false;

function metOnShow() {
  if (!metIsActive()) return;
  metLoadedOnce = true;
  refreshMetrics();
}

metTabs.forEach((tab) => new MutationObserver(metOnShow).observe(tab, { attributes: true, attributeFilter: ["class"] }));
document.addEventListener("visibilitychange", metOnShow);
setInterval(() => { if (metIsActive() && metLoadedOnce) refreshMetrics(); }, MET_REFRESH_MS);

metOnShow();
