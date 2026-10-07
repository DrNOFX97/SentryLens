// Abas "Live Traffic", "Network Detections" e "PCAP / Evidence" (Roadmap v2,
// R6 — Network SOC). Carregado depois de app.js: reutiliza os seus globais
// (API_BASE, API_KEY, escapeHtml, formatTimestamp, renderPanelError) — não
// redeclarar nenhum aqui. Reaproveita os dados já recolhidos por
// network_monitor.py/network_detections.py (mesma fonte do painel de rede
// da aba Red vs Blue, redblue.js) através de 3 rotas dedicadas
// (/api/network/live-traffic, /api/network/detections,
// /api/network/evidence) — não abre um 2º WebSocket (o /ws/network já é
// exclusivo da aba Red vs Blue). Cada painel só pede dados com a sua aba
// ativa e o separador visível (nunca em segundo plano). Só mostra dados
// reais; sem dados -> "Sem dados". Todo o texto dinâmico passa por
// escapeHtml.

const NS_REFRESH_MS = 30000;
const NS_DETECTION_TYPE_LABELS = { port_scan: "Port scan", brute_force: "Força bruta", volume_spike: "Pico de volume" };

const nsLiveTab = document.getElementById("tab-live-traffic");
const nsDetTab = document.getElementById("tab-network-detections");
const nsEvTab = document.getElementById("tab-pcap-evidence");

function nsIsActive(tabEl) {
  return tabEl.classList.contains("active") && document.visibilityState === "visible";
}

function nsCell(value) {
  if (value === null || value === undefined || value === "") return "—";
  return escapeHtml(String(value));
}

function nsDetail(detail) {
  if (!detail || typeof detail !== "object" || Object.keys(detail).length === 0) return "—";
  return escapeHtml(JSON.stringify(detail));
}

function nsTypeLabel(type) {
  return NS_DETECTION_TYPE_LABELS[type] || type || "—";
}

async function nsRequest(path) {
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

// ===== Live Traffic =====

function nsRenderCountTable(bodyId, rows, labelKey, countKey, colspan) {
  const body = document.getElementById(bodyId);
  if (!rows.length) {
    body.innerHTML = `<tr><td colspan="${colspan}" class="empty-state">Sem dados.</td></tr>`;
    return;
  }
  body.innerHTML = rows.map((r) => `<tr><td>${nsCell(r[labelKey])}</td><td>${nsCell(r[countKey])}</td></tr>`).join("");
}

async function refreshLiveTraffic() {
  try {
    const data = await nsRequest("/api/network/live-traffic");
    renderPanelError("#live-traffic-panel", null);
    document.getElementById("nst-note").textContent = data.configured
      ? `Captura de rede configurada — ${data.total} pacote(s) no buffer.`
      : "Sem dados — captura de rede não configurada (VM_SSH_HOST).";
    document.getElementById("nst-total").textContent = data.total ?? 0;
    document.getElementById("nst-window-start").textContent = data.window_start ? formatTimestamp(data.window_start) : "—";
    document.getElementById("nst-window-end").textContent = data.window_end ? formatTimestamp(data.window_end) : "—";

    const protocolRows = Object.entries(data.by_protocol || {}).map(([protocol, packets]) => ({ protocol, packets }));
    nsRenderCountTable("nst-protocol-body", protocolRows, "protocol", "packets", 2);

    const talkers = (data.top_talkers || []).map((t) => ({ src_ip: t.src_ip, packets: t.packets }));
    nsRenderCountTable("nst-talkers-body", talkers, "src_ip", "packets", 2);

    const ports = (data.top_ports || []).map((p) => ({ port: p.port, packets: p.packets }));
    nsRenderCountTable("nst-ports-body", ports, "port", "packets", 2);
  } catch (err) {
    const message = `Não foi possível carregar o Live Traffic: ${err.message}`;
    renderPanelError("#live-traffic-panel", message);
    document.getElementById("nst-note").textContent = "Sem dados.";
    ["nst-protocol-body", "nst-talkers-body", "nst-ports-body"].forEach((id) => {
      document.getElementById(id).innerHTML = `<tr><td colspan="2" class="empty-state">Sem dados — ${escapeHtml(err.message)}.</td></tr>`;
    });
  }
}

// ===== Network Detections =====

async function refreshNetworkDetections() {
  try {
    const data = await nsRequest("/api/network/detections");
    renderPanelError("#network-detections-panel", null);
    document.getElementById("nsd-note").textContent = data.configured
      ? "Captura de rede configurada."
      : "Sem dados — captura de rede não configurada (VM_SSH_HOST).";
    document.getElementById("nsd-live-count").textContent = data.live_count ?? 0;
    document.getElementById("nsd-history-count").textContent = data.history_count ?? 0;

    const byType = Object.entries(data.by_type || {}).map(([type, count]) => ({ type: nsTypeLabel(type), count }));
    nsRenderCountTable("nsd-bytype-body", byType, "type", "count", 2);

    const body = document.getElementById("nsd-recent-body");
    const recent = data.recent || [];
    body.innerHTML = recent.length
      ? recent.map((d) => `<tr>
          <td>${d.timestamp ? formatTimestamp(d.timestamp) : "—"}</td>
          <td>${nsCell(nsTypeLabel(d.type))}</td>
          <td>${nsCell(d.src_ip)}</td>
          <td>${nsCell(d.dst_ip)}</td>
          <td>${nsDetail(d.detail)}</td>
        </tr>`).join("")
      : `<tr><td colspan="5" class="empty-state">Sem dados.</td></tr>`;
  } catch (err) {
    const message = `Não foi possível carregar as Network Detections: ${err.message}`;
    renderPanelError("#network-detections-panel", message);
    document.getElementById("nsd-note").textContent = "Sem dados.";
    document.getElementById("nsd-bytype-body").innerHTML = `<tr><td colspan="2" class="empty-state">Sem dados — ${escapeHtml(err.message)}.</td></tr>`;
    document.getElementById("nsd-recent-body").innerHTML = `<tr><td colspan="5" class="empty-state">Sem dados — ${escapeHtml(err.message)}.</td></tr>`;
  }
}

// ===== PCAP / Evidence =====

function nsEvidenceQuery() {
  const limit = document.getElementById("nse-limit-filter").value || "100";
  const dateRaw = document.getElementById("nse-date-filter").value.trim();
  const params = new URLSearchParams({ limit });
  if (dateRaw) params.set("date", dateRaw);
  return params.toString();
}

async function refreshPcapEvidence() {
  try {
    const data = await nsRequest(`/api/network/evidence?${nsEvidenceQuery()}`);
    renderPanelError("#pcap-evidence-panel", null);
    document.getElementById("nse-disclaimer").textContent = data.note || "";
    document.getElementById("nse-notice").textContent = data.total
      ? `${data.total} entrada(s) de evidência (metadados, sem payload/PCAP real).`
      : "";

    const body = document.getElementById("nse-body");
    const entries = data.entries || [];
    body.innerHTML = entries.length
      ? entries.map((e) => `<tr>
          <td>${nsCell(e.date)}</td>
          <td>${nsCell(e.time)}</td>
          <td>${nsCell(nsTypeLabel(e.type))}</td>
          <td>${nsCell(e.src_ip)}</td>
          <td>${nsCell(e.dst_ip)}</td>
          <td>${nsDetail(e.detail)}</td>
        </tr>`).join("")
      : `<tr><td colspan="6" class="empty-state">Sem dados para este dia.</td></tr>`;
  } catch (err) {
    const message = `Não foi possível carregar a evidência: ${err.message}`;
    renderPanelError("#pcap-evidence-panel", message);
    document.getElementById("nse-notice").textContent = "";
    document.getElementById("nse-body").innerHTML = `<tr><td colspan="6" class="empty-state">Sem dados — ${escapeHtml(err.message)}.</td></tr>`;
  }
}

document.getElementById("nse-reload-btn").addEventListener("click", () => { if (nsIsActive(nsEvTab)) refreshPcapEvidence(); });
document.getElementById("nse-limit-filter").addEventListener("change", () => { if (nsIsActive(nsEvTab)) refreshPcapEvidence(); });
document.getElementById("nse-date-filter").addEventListener("keydown", (event) => {
  if (event.key === "Enter" && nsIsActive(nsEvTab)) refreshPcapEvidence();
});

// Ciclo de vida: cada painel só pede dados com a sua aba ativa e o
// separador visível — nunca em segundo plano. setInterval condicional,
// mesmo padrão de attack_registry.js/attack_library.js.
let nsLiveLoadedOnce = false;
let nsDetLoadedOnce = false;
let nsEvLoadedOnce = false;

function nsLiveOnShow() {
  if (!nsIsActive(nsLiveTab)) return;
  nsLiveLoadedOnce = true;
  refreshLiveTraffic();
}
function nsDetOnShow() {
  if (!nsIsActive(nsDetTab)) return;
  nsDetLoadedOnce = true;
  refreshNetworkDetections();
}
function nsEvOnShow() {
  if (!nsIsActive(nsEvTab)) return;
  nsEvLoadedOnce = true;
  refreshPcapEvidence();
}

const nsLiveObserver = new MutationObserver(nsLiveOnShow);
nsLiveObserver.observe(nsLiveTab, { attributes: true, attributeFilter: ["class"] });
const nsDetObserver = new MutationObserver(nsDetOnShow);
nsDetObserver.observe(nsDetTab, { attributes: true, attributeFilter: ["class"] });
const nsEvObserver = new MutationObserver(nsEvOnShow);
nsEvObserver.observe(nsEvTab, { attributes: true, attributeFilter: ["class"] });

document.addEventListener("visibilitychange", () => {
  nsLiveOnShow();
  nsDetOnShow();
  nsEvOnShow();
});

setInterval(() => { if (nsIsActive(nsLiveTab) && nsLiveLoadedOnce) refreshLiveTraffic(); }, NS_REFRESH_MS);
setInterval(() => { if (nsIsActive(nsDetTab) && nsDetLoadedOnce) refreshNetworkDetections(); }, NS_REFRESH_MS);
setInterval(() => { if (nsIsActive(nsEvTab) && nsEvLoadedOnce) refreshPcapEvidence(); }, NS_REFRESH_MS);

nsLiveOnShow();
nsDetOnShow();
nsEvOnShow();
