// Aba "Detections" (Roadmap v2, R7 — Detection Engine). Carregado depois de
// app.js: reutiliza os seus globais (
// formatTimestamp, severityBadge, renderPanelError) — não redeclarar nenhum
// aqui. Consome só GET /api/detections (vista unificada regra/ML/rede via
// DetectionEvent); o dado bruto de origem nunca chega ao cliente. Só pede
// dados com a aba ativa e o separador visível (nunca em segundo plano). Só
// mostra dados reais; fonte em baixo -> "indisponível". Todo o texto
// dinâmico é escapado pelo htmlT. O filtro de fonte é feito no cliente
// (a rota já devolve as 3 fontes, capadas a `limit`).

const DET_REFRESH_MS = 30000;
const DET_LIMIT = 200;
const DET_SOURCE_LABELS = { rule: "Regra", ml: "ML", network: "Rede" };

const detTab = document.getElementById("tab-detections");

function detIsActive() {
  return detTab.classList.contains("active") && document.visibilityState === "visible";
}

// Texto simples: o htmlT escapa na interpolação.
function detCell(value) {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
}

function detSourceCount(sources, name) {
  const s = sources && sources[name];
  if (!s) return "—";
  return s.available ? String(s.count) : "indisponível";
}

async function refreshDetections() {
  const hours = document.getElementById("det-hours-filter").value || "24";
  const source = document.getElementById("det-source-filter").value;
  try {
    const data = await apiRequest(`/api/detections?hours=${encodeURIComponent(hours)}&limit=${DET_LIMIT}`);
    renderPanelError("#detections-panel", null);
    const sources = data.sources || {};
    const down = Object.keys(DET_SOURCE_LABELS).filter((n) => sources[n] && !sources[n].available);
    document.getElementById("det-note").textContent = down.length
      ? `Fonte(s) indisponível(is): ${down.map((n) => DET_SOURCE_LABELS[n]).join(", ")}. As restantes continuam a responder.`
      : `Janela de ${data.window_hours} h.` + (data.truncated ? ` Mostrando os ${DET_LIMIT} mais recentes.` : "");
    document.getElementById("det-total").textContent = data.total ?? 0;
    for (const name of Object.keys(DET_SOURCE_LABELS)) {
      document.getElementById(`det-count-${name}`).textContent = detSourceCount(sources, name);
    }

    const events = (data.events || []).filter((e) => !source || e.source === source);
    htmRender(document.getElementById("det-body"), events.length
      ? htmlT`${events.map((e) => htmlT`<tr>
          <td>${detCell(e.ts ? formatTimestamp(e.ts) : null)}</td>
          <td>${detCell(DET_SOURCE_LABELS[e.source] || e.source)}</td>
          <td>${htmlRaw(severityBadge(e.severity || "info"))}</td>
          <td>${detCell(e.asset)}</td>
          <td>${detCell(e.label)}</td>
          <td>${detCell(e.description)}</td>
        </tr>`)}`
      : htmlT`<tr><td colspan="6" class="empty-state">Sem dados.</td></tr>`);
  } catch (err) {
    renderPanelError("#detections-panel", `Não foi possível carregar as deteções: ${apiErrorMessage(err)}`);
    document.getElementById("det-note").textContent = "Sem dados.";
    htmRender(document.getElementById("det-body"), htmlT`<tr><td colspan="6" class="empty-state">Sem dados — ${apiErrorMessage(err)}</td></tr>`);
  }
}

document.getElementById("det-hours-filter").addEventListener("change", () => { if (detIsActive()) refreshDetections(); });
document.getElementById("det-source-filter").addEventListener("change", () => { if (detIsActive()) refreshDetections(); });

let detLoadedOnce = false;

function detOnShow() {
  if (!detIsActive()) return;
  detLoadedOnce = true;
  refreshDetections();
}

new MutationObserver(detOnShow).observe(detTab, { attributes: true, attributeFilter: ["class"] });
document.addEventListener("visibilitychange", detOnShow);
setInterval(() => { if (detIsActive() && detLoadedOnce) refreshDetections(); }, DET_REFRESH_MS);

detOnShow();
