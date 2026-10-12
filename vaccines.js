// Aba "Vaccines" (Roadmap v2, R11). Carregado depois de app.js: reutiliza os
// seus globais (API_BASE, API_KEY, escapeHtml, renderPanelError) e nunca os
// redeclara. Só leitura: um único pedido GET a /api/vaccines com o cabeçalho
// X-API-Key; nenhuma ação altera uma vaccine nem o Wazuh (as vaccines são
// regras PROPOSTAS, nunca aplicadas).
//
// Todos os identificadores de topo começam por vac ou VAC_: os scripts
// clássicos partilham um só escopo global e um nome repetido rebenta o
// script inteiro. Todo o texto dinâmico passa por escapeHtml (ou por um
// helper vac* que o devolve já escapado). O backend nunca envia texto de erro
// para o ecrã: o campo detail só serve de chave de lookup em VAC_ERROR_TEXT
// e nunca entra no DOM.
//
// Ciclo de vida: carrega a cada passagem a ativa (aba e separador visíveis),
// sem polling e sem canal em tempo real; pedidos concorrentes são ignorados.

const VAC_VERDICT_LABELS = { not_detected: "Não detetado", partial: "Parcial" };
const VAC_SENSOR_LABELS = { rule: "Regra", ml: "ML", network: "Rede" };
const VAC_STATE_LABELS = { proposed: "Proposta" };

// Os dois textos de lista sem linhas são DISTINTOS de propósito: o primeiro é
// o store sem nada (reason no_data), o segundo é um filtro sem resultados.
const VAC_NO_DATA_TEXT = "Sem dados — ainda não há vaccines propostas (nenhum ataque não detetado ou parcial já assente).";
const VAC_FILTER_EMPTY_TEXT = "Nenhuma vaccine corresponde aos filtros.";
const VAC_GENERIC_ERROR = "Erro inesperado ao ler as vaccines.";

// Só isto é aceite como código vindo do detalhe da resposta; qualquer outra
// coisa (HTML, caminho, texto de exceção) cai no código HTTP.
const VAC_CODE_RE = /^[a-z_]{1,64}$/;

// Frases acionáveis em PT-PT, uma chave por linha. Nenhuma diz que não há
// dados: um erro nunca se desenha como ausência de vaccines.
const VAC_ERROR_TEXT = {
  unauthorized: "API key inválida ou em falta — confirma SENTRYLENS_API_KEY em scripts/.env e recarrega a página.",
  network_error: "Sem ligação ao backend (localhost:8001) — confirma que está a correr com scripts/start-backend.ps1.",
  store_unavailable: "O store de vaccines (scripts/vaccines.sqlite3) não pôde ser lido nem escrito — vê o backend.log.",
  // Códigos do gerador (vaccine_ingest.GENERATOR_ERROR_CODES); store_unavailable serve os dois casos.
  indexer_unavailable: "O Wazuh Indexer não respondeu — sem alertas não é possível avaliar os ataques.",
  ml_model_unavailable: "O modelo de ML não está disponível — o veredito por ML não pôde ser medido.",
  attack_outside_alert_window: "Há ataques mais antigos do que a janela de alertas consultada.",
  source_unavailable: "Uma fonte de dados do Red vs Blue esteve indisponível.",
  attack_log_unreadable: "O attack log (attack_log.jsonl) não pôde ser lido.",
  incidents_unavailable: "A base de incidentes não pôde ser lida — nada foi gravado para não perder a ligação aos incidentes.",
  unexpected_error: "Erro inesperado no gerador — vê o backend.log.",
  entry_not_found: "Esta vaccine não existe no store (o ficheiro pode ter sido trocado ou apagado).",
  http_404: "O backend não tem a rota de vaccines — reinicia-o com a versão atual.",
  http_422: "Filtro recusado pelo backend (valor fora do formato aceite).",
  http_502: "O backend devolveu 502 (erro de gateway) — tenta Atualizar daqui a pouco.",
  http_503: "O backend está indisponível (503) — tenta Atualizar daqui a pouco.",
};

// Os mesmos formatos que a rota GET /api/vaccines aceita (a rota volta a validar).
const VAC_ATTACK_ID_RE = /^[1-9]\d{0,8}$/;
const VAC_TECHNIQUE_RE = /^T\d{4}(\.\d{3})?$/;
const VAC_INVALID_ATTACK_TEXT = "ID de ataque inválido: usa um número inteiro de 1 a 999999999.";

const vacTab = document.getElementById("tab-vaccines");
let vacLoading = false;
let vacWasActive = false;
// União das técnicas MITRE vistas nas respostas da sessão: alimenta o select
// sem nunca encolher por causa do próprio filtro.
const vacTechniques = new Set();

function vacIsActive() {
  return vacTab.classList.contains("active") && document.visibilityState === "visible";
}

function vacCell(value) {
  if (value === null || value === undefined || value === "") return "—";
  return escapeHtml(String(value));
}

// Texto cru: quem o mete em HTML passa-o por vacCell.
function vacSensors(list) {
  return list && list.length ? list.map((s) => VAC_SENSOR_LABELS[s] || s).join(", ") : "—";
}

function vacDate(iso) {
  const ms = Date.parse(iso);
  if (Number.isNaN(ms)) return "—";
  return new Date(ms).toLocaleString("pt-PT");
}

function vacCodeFromResponse(status, body) {
  if (status === 401) return "unauthorized";
  const detail = body ? body.detail : null;
  if (typeof detail === "string" && VAC_CODE_RE.test(detail)) return detail;
  return "http_" + status;
}

function vacErrorText(code) {
  if (typeof code !== "string") return VAC_GENERIC_ERROR;
  if (Object.prototype.hasOwnProperty.call(VAC_ERROR_TEXT, code)) return VAC_ERROR_TEXT[code];
  if (/^http_\d{3}$/.test(code)) return VAC_GENERIC_ERROR + " (HTTP " + code.slice(5) + ")";
  return VAC_GENERIC_ERROR;
}

// A mensagem do erro lançado é sempre um código, nunca texto do servidor.
async function vacRequest(path) {
  let response;
  try {
    response = await fetch(API_BASE + path, { headers: { "X-API-Key": API_KEY } });
  } catch (_) {
    throw new Error("network_error");
  }
  if (!response.ok) {
    let body = null;
    try {
      body = await response.json();
    } catch (_) { /* corpo não-JSON: fica o código HTTP */ }
    throw new Error(vacCodeFromResponse(response.status, body));
  }
  return response.json();
}

// Veredito em badge: classe pelo valor escapado, rótulo escapado (ou o valor).
function vacVerdictBadge(verdict) {
  const label = VAC_VERDICT_LABELS[verdict] || verdict;
  return '<span class="vac-verdict vac-verdict-' + escapeHtml(String(verdict)) + '">' +
    escapeHtml(String(label)) + "</span>";
}

// A condição fica em helpers: cada interpolação do template começa por vac*.
function vacRowClass(vaccine) {
  return vaccine.superseded_by === null || vaccine.superseded_by === undefined ? "" : " vac-row-superseded";
}

function vacSupersededNote(vaccine) {
  if (vaccine.superseded_by === null || vaccine.superseded_by === undefined) return "";
  return '<span class="vac-superseded-note">Substituída por ' + vacCell(vaccine.superseded_by) + "</span>";
}

function vacRowsHtml(vaccines) {
  return vaccines.map((vaccine) => {
    const origin = vaccine.origin || {};
    const attack = origin.attack_id === null || origin.attack_id === undefined ? "" : "#" + origin.attack_id;
    return `<tr class="atk-row${vacRowClass(vaccine)}" data-id="${escapeHtml(vaccine.id)}" tabindex="0">
    <td>${vacCell(vaccine.id)}${vacSupersededNote(vaccine)}</td>
    <td>${vacCell(attack)}</td>
    <td>${vacCell(origin.scenario)}</td>
    <td>${vacCell(origin.mitre_technique)}</td>
    <td>${vacVerdictBadge(vaccine.verdict)}</td>
    <td>${vacCell(vacSensors(vaccine.missing_sensors))}</td>
    <td>${vacCell(VAC_STATE_LABELS[vaccine.state] || vaccine.state)}</td>
    <td>${vacCell(vacDate(vaccine.created_at))}</td>
  </tr>`;
  }).join("");
}

function vacRenderList(envelope) {
  const body = document.getElementById("vac-body");
  const notice = document.getElementById("vac-notice");
  if (envelope.reason === "no_data") {
    body.innerHTML = `<tr><td colspan="8" class="empty-state">${escapeHtml(VAC_NO_DATA_TEXT)}</td></tr>`;
    notice.textContent = "";
    return;
  }
  const vaccines = envelope.vaccines || [];
  if (!vaccines.length) {
    body.innerHTML = `<tr><td colspan="8" class="empty-state">${escapeHtml(VAC_FILTER_EMPTY_TEXT)}</td></tr>`;
    notice.textContent = "";
    return;
  }
  body.innerHTML = vacRowsHtml(vaccines);
  let text = vaccines.length + " vaccine(s)";
  if (envelope.total > vaccines.length) text += " — a mostrar as primeiras " + vaccines.length;
  notice.textContent = text;
}

function vacRenderError(code) {
  const text = vacErrorText(code);
  renderPanelError("#vaccines-panel", text);
  document.getElementById("vac-body").innerHTML =
    `<tr><td colspan="8" class="vac-error-state">${escapeHtml(text)}</td></tr>`;
  document.getElementById("vac-notice").textContent = "";
}

// Há quanto tempo, em texto simples (vai para textContent).
function vacAgo(iso, nowMs) {
  const ms = Date.parse(iso);
  if (Number.isNaN(ms)) return "em data desconhecida";
  const minutes = Math.floor((nowMs - ms) / 60000);
  if (minutes < 1) return "há menos de 1 min";
  if (minutes < 60) return "há " + minutes + " min";
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return "há " + hours + " h";
  return "há " + Math.floor(hours / 24) + " dias";
}

// Linha de estado do gerador, em texto simples. O código de erro do servidor
// só serve de chave de vacErrorText; nunca é desenhado como veio.
function vacGeneratorText(generator, nowMs) {
  if (!generator || typeof generator !== "object") {
    return { text: "Estado do gerador indisponível.", isError: true };
  }
  if (generator.status === "never_run") {
    return { text: "O gerador de vaccines ainda não correu desde o arranque do backend.", isError: false };
  }
  if (generator.status !== "error" && generator.status !== "ok" && generator.status !== "no_data") {
    return { text: "Estado do gerador desconhecido.", isError: true };
  }
  let text = "Última execução " + vacAgo(generator.last_run_at, nowMs);
  let isError = false;
  if (generator.status === "error") {
    isError = true;
    text += ": falhou — " + vacErrorText(generator.error_code);
    if (generator.last_success_at) text += " Último sucesso " + vacAgo(generator.last_success_at, nowMs) + ".";
  } else {
    text += ".";
    if (generator.status === "no_data") text += " Sem ataques no attack log.";
  }
  const counts = generator.counts;
  if (counts && counts.pending_settle > 0) {
    text += " " + counts.pending_settle + " ataque(s) recente(s) ainda a assentar — a vaccine só é proposta depois do tempo de estabilização.";
  }
  if (generator.alerts_truncated === true) {
    text += " Aviso: a última execução atingiu o teto de 1000 alertas; ataques sem correspondência ficam por avaliar.";
  }
  return { text, isError };
}

function vacRenderGenerator(generator) {
  const line = document.getElementById("vac-generator");
  const state = vacGeneratorText(generator, Date.now());
  line.textContent = state.text;
  line.classList.toggle("vac-generator-error", state.isError);
}

// Query string dos filtros visíveis: "" sem filtros, "?..." com filtros, ou
// null quando o id de ataque escrito é inválido (nesse caso não há pedido).
function vacBuildQuery() {
  const attackId = document.getElementById("vac-attack-filter").value.trim();
  const technique = document.getElementById("vac-technique-filter").value;
  const superseded = document.getElementById("vac-superseded-filter").checked;
  if (attackId !== "" && !VAC_ATTACK_ID_RE.test(attackId)) return null;
  const params = new URLSearchParams();
  if (attackId !== "") params.set("attack_id", attackId);
  if (VAC_TECHNIQUE_RE.test(technique)) params.set("technique", technique);
  if (superseded) params.set("include_superseded", "true");
  const text = params.toString();
  return text ? "?" + text : "";
}

// Cada option é escapada; só entram técnicas que casam VAC_TECHNIQUE_RE.
function vacTechniqueOptionsHtml() {
  const options = ['<option value="">Todas</option>'];
  for (const technique of Array.from(vacTechniques).sort()) {
    options.push(`<option value="${escapeHtml(technique)}">${escapeHtml(technique)}</option>`);
  }
  return options.join("");
}

function vacAddTechniques(vaccines) {
  const select = document.getElementById("vac-technique-filter");
  const selected = select.value;
  for (const vaccine of vaccines) {
    const origin = vaccine.origin || {};
    if (typeof origin.mitre_technique === "string" && VAC_TECHNIQUE_RE.test(origin.mitre_technique)) {
      vacTechniques.add(origin.mitre_technique);
    }
  }
  select.innerHTML = vacTechniqueOptionsHtml();
  select.value = selected;
}

async function vacRefresh() {
  if (vacLoading) return;
  const query = vacBuildQuery();
  if (query === null) {
    document.getElementById("vac-notice").textContent = VAC_INVALID_ATTACK_TEXT;
    return;
  }
  vacLoading = true;
  try {
    const envelope = await vacRequest("/api/vaccines" + query);
    renderPanelError("#vaccines-panel", "");
    vacRenderList(envelope);
    vacAddTechniques(envelope.vaccines || []);
    vacRenderGenerator(envelope.generator);
  } catch (err) {
    vacRenderError(err.message);
    const line = document.getElementById("vac-generator");
    line.textContent = "";
    line.classList.remove("vac-generator-error");
  } finally {
    vacLoading = false;
    // Filtros mudados a meio do pedido: um (e só um) novo pedido, depois deste.
    const current = vacBuildQuery();
    if (current !== null && current !== query) vacRefresh();
  }
}

for (const id of ["vac-attack-filter", "vac-technique-filter", "vac-superseded-filter"]) {
  document.getElementById(id).addEventListener("change", vacRefresh);
}
document.getElementById("vac-refresh-btn").addEventListener("click", vacRefresh);

// Ciclo de vida: recarrega só na passagem de inativa a ativa.
function vacOnShow() {
  const active = vacIsActive();
  if (active && !vacWasActive) vacRefresh();
  vacWasActive = active;
}
const vacObserver = new MutationObserver(vacOnShow);
vacObserver.observe(vacTab, { attributes: true, attributeFilter: ["class"] });
document.addEventListener("visibilitychange", vacOnShow);
vacOnShow();
