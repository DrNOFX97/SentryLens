// Dashboard de Cibersegurança — globais partilhados (escapeHtml, fetchJSON,
// renderPanelError, formatTimestamp, API_BASE/API_KEY, panelErrorText, ...).
// A lógica de cada domínio vive nos ficheiros ao lado (overview-alerts.js,
// system.js, iam.js, ml-anomalies.js, compliance.js, realtime.js, shell.js);
// o arranque (primeiro refresh, WebSocket, ativação da aba) está no fim de
// shell.js, que é o último a carregar antes dos módulos de aba.

const API_BASE = "http://localhost:8001";
// A chave vem de /config.js, gerado por scripts/serve_frontend.py a partir de
// SENTRYLENS_API_KEY em scripts/.env (nunca vai para o repositório). Esse
// endpoint só responde ao próprio origin do dashboard (ver serve_frontend.py).
// Se config.js não existir (outro servidor estático), fica vazia e a API
// responde 401 — o dashboard mostra "sem ligação", não falha em silêncio.
const API_KEY = (window.SENTRYLENS_CONFIG && window.SENTRYLENS_CONFIG.apiKey) || "";


// Dados do Wazuh (nomes de agente, descrições de regra, username de logons
// falhados, etc.) podem conter texto controlado por um atacante — escapamos
// tudo antes de o meter em HTML para evitar XSS armazenado.
function escapeHtml(value) {
  if (value === null || value === undefined) return "";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function severityBadge(severity) {
  const labels = {
    critical: "Crítico",
    high: "Alto",
    medium: "Médio",
    low: "Baixo",
    info: "Info",
  };
  const label = labels[severity] || severity;
  return `<span class="severity-badge ${escapeHtml(severity)}">${escapeHtml(label)}</span>`;
}

// O backend dos painéis novos (ciclo de vida, privilégios, contas admin)
// devolve severidade em slugs PT ("critico"/"alto"/"medio"/"baixo"); a app
// usa classes em inglês (severityBadge, .detection-item, .alert-row, etc.)
// — traduz aqui, num único sítio, para os 3 painéis novos.
function mapSeverity(sev) {
  const map = { critico: "critical", alto: "high", medio: "medium", baixo: "low" };
  return map[sev] || sev;
}

function formatTimestamp(ts) {
  return slFormatTimestamp(ts);
}

// Invólucro fino sobre apiRequest (api.js): mesma assinatura (path -> JSON).
// O erro lançado é um ApiError (status numérico + mensagem fixa em PT).
async function fetchJSON(path) {
  return apiRequest(path);
}

// Texto seguro para mostrar num painel: só mensagens de ApiError (fixas, em
// PT, com ação sugerida); qualquer outro erro (ex.: bug de renderização)
// cai no texto de reserva, nunca no texto da exceção.
function panelErrorText(err, fallback) {
  return err instanceof ApiError ? err.message : fallback;
}

// --- Helpers partilhados pelos painéis novos (ciclo de vida, privilégios,
// contas admin) — reutilizáveis pelos 3, ver docs/README ou o comentário
// de refreshNewPanels() mais abaixo para a estrutura esperada. ---

// Renderiza uma lista de deteções de risco ({name, severity, explanation})
// dentro do container indicado. severity vem em slugs PT do backend e é
// traduzida com mapSeverity() antes de aplicar a classe .level-<...>.
function renderDetections(containerId, detections) {
  const container = document.getElementById(containerId);
  if (!container) return;

  if (!detections || detections.length === 0) {
    sttShowEmpty(container, "Sem deteções neste período");
    return;
  }

  htmRender(container, htmlT`${detections.map((d) => htmlT`
        <div class="detection-item level-${mapSeverity(d.severity)}">
          <strong>${d.name}</strong>
          <span>${d.explanation}</span>
        </div>
      `)}`);
}

// Mostra (ou, com message vazio/null, esconde) um banner de erro dentro do
// painel indicado por panelSelector (ex: "#lifecycle-panel").
//
// Decisão de paleta: o estilo vem de .panel-error-banner (tokens --sev-critical-*
// do style.css, que mudam com o tema), e não da paleta de .status-error, pensada
// para o indicador de estado sobre o fundo do header.
function renderPanelError(panelSelector, message) {
  const panel = document.querySelector(panelSelector);
  if (!panel) return;

  let banner = panel.querySelector(".panel-error-banner");
  if (!message) {
    if (banner) banner.remove();
    return;
  }

  if (!banner) {
    banner = document.createElement("div");
    banner.className = "panel-error-banner";
    const heading = panel.querySelector("h2");
    if (heading) {
      heading.insertAdjacentElement("afterend", banner);
    } else {
      panel.insertBefore(banner, panel.firstChild);
    }
  }
  sttShowError(banner, `⚠️ ${message}`);
}

