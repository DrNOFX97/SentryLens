// Aba "Detections" (Roadmap v2, R7 — Detection Engine). Carregado depois de
// app.js: reutiliza os seus globais (API_BASE, API_KEY, escapeHtml,
// formatTimestamp, severityBadge, renderPanelError) — não redeclarar nenhum
// aqui. Consome só GET /api/detections (vista unificada regra/ML/rede via
// DetectionEvent); o dado bruto de origem nunca chega ao cliente. Só pede
// dados com a aba ativa e o separador visível (nunca em segundo plano). Só
// mostra dados reais; fonte em baixo -> "indisponível". Todo o texto
// dinâmico passa por escapeHtml. O filtro de fonte é feito no cliente
// (a rota já devolve as 3 fontes, capadas a `limit`).

const DET_REFRESH_MS = 30000;
const DET_LIMIT = 200;
const DET_SOURCE_LABELS = { rule: "Regra", ml: "ML", network: "Rede" };

const detTab = document.getElementById("tab-detections");

function detIsActive() {
  return detTab.classList.contains("active") && document.visibilityState === "visible";
}

function detCell(value) {
  if (value === null || value === undefined || value === "") return "—";
  return escapeHtml(String(value));
}

async function detRequest(path) {
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

function detSourceCount(sources, name) {
  const s = sources && sources[name];
  if (!s) return "—";
  return s.available ? String(s.count) : "indisponível";
}

async function refreshDetections() {
  const hours = document.getElementById("det-hours-filter").value || "24";
  const source = document.getElementById("det-source-filter").value;
  try {
    const data = await detRequest(`/api/detections?hours=${encodeURIComponent(hours)}&limit=${DET_LIMIT}`);
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
    document.getElementById("det-body").innerHTML = events.length
      ? events.map((e) => `<tr>
          <td>${detCell(e.ts ? formatTimestamp(e.ts) : null)}</td>
          <td>${detCell(DET_SOURCE_LABELS[e.source] || e.source)}</td>
          <td>${severityBadge(e.severity || "info")}</td>
          <td>${detCell(e.asset)}</td>
          <td>${detCell(e.label)}</td>
          <td>${detCell(e.description)}</td>
        </tr>`).join("")
      : `<tr><td colspan="6" class="empty-state">Sem dados.</td></tr>`;
  } catch (err) {
    renderPanelError("#detections-panel", `Não foi possível carregar as deteções: ${err.message}`);
    document.getElementById("det-note").textContent = "Sem dados.";
    document.getElementById("det-body").innerHTML = `<tr><td colspan="6" class="empty-state">Sem dados — ${escapeHtml(err.message)}.</td></tr>`;
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
