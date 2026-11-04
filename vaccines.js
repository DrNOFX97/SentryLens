// Aba "Vaccines" (Roadmap v2, R11/R12). Carregado depois de app.js: reutiliza os seus globais
// (API_BASE, API_KEY, htmlT/htmRender de html.js, renderPanelError) e nunca os redeclara. Lê por GET
// de /api/vaccines com o cabeçalho X-API-Key e tem uma única escrita: o POST da decisão (vacDecide),
// em que o analista pode aprovar ou rejeitar uma vaccine proposta. A decisão é final; aprovada
// significa só aceite pelo analista e nada é aplicado no Wazuh (as vaccines são regras PROPOSTAS).
//
// Todos os identificadores de topo começam por vac ou VAC_: os scripts clássicos partilham um só
// escopo global e um nome repetido rebenta o script inteiro. Todo o texto dinâmico é interpolado
// em htmlT (escapado por omissão) e desenhado com htmRender; nunca se atribui HTML à mão. O backend
// nunca envia texto de erro para o ecrã: o campo detail só serve de chave de lookup em
// VAC_ERROR_TEXT e nunca entra no DOM.
//
// Ciclo de vida: carrega a cada passagem a ativa (aba e separador visíveis), sem polling e sem canal
// em tempo real; um refresco pedido durante outro fica em fila e faz uma só volta extra.

const VAC_VERDICT_LABELS = { not_detected: "Não detetado", partial: "Parcial" };
const VAC_SENSOR_LABELS = { rule: "Regra", ml: "ML", network: "Rede" };
const VAC_STATE_LABELS = { proposed: "Proposta", approved: "Aprovada", rejected: "Rejeitada" };
// Estados que o filtro pode enviar como ?state= (iguais a main.VaccineState; a rota recusa o resto com 422).
const VAC_STATES = ["proposed", "approved", "rejected"];
const VAC_EXPECTED_SOURCE_LABELS = { log: "attack log", scenario_default: "omissão do cenário (Attack Library)" };

// Mesmo formato que a rota de detalhe aceita (a rota volta a validar).
const VAC_ID_RE = /^vac-[0-9a-f]{12}$/;

// Os dois textos de lista sem linhas são DISTINTOS de propósito: o primeiro é
// o store sem nada (reason no_data), o segundo é um filtro sem resultados.
const VAC_NO_DATA_TEXT = "Sem dados — ainda não há vaccines propostas (nenhum ataque não detetado ou parcial já assente).";
const VAC_FILTER_EMPTY_TEXT = "Nenhuma vaccine corresponde aos filtros.";
// Texto do bloco Decisão quando não há botões a mostrar (D-03): nunca se esconde o bloco.
const VAC_NO_ANALYSTS_TEXT = "Sem analistas ativos na Equipa SOC — cria ou reativa um analista na aba Equipa SOC para poder decidir.";
const VAC_DECISION_LOADING_TEXT = "A carregar os analistas da Equipa SOC…";
const VAC_GENERIC_ERROR = "Erro inesperado no pedido de vaccines — vê o backend.log.";

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
  // Serve o gerador e a decisão: em ambos a base de incidentes e da Equipa SOC não pôde ser lida.
  incidents_unavailable: "A base de incidentes e da Equipa SOC (scripts/incidents.sqlite3) não pôde ser lida — nada foi gravado; vê o backend.log.",
  unexpected_error: "Erro inesperado no gerador — vê o backend.log.",
  entry_not_found: "Esta vaccine não existe no store (o ficheiro pode ter sido trocado ou apagado).",
  // Validação local da decisão (slVacDecisionBody): nenhum pedido é enviado.
  analyst_required: "Escolhe o analista que decide antes de Aprovar ou Rejeitar.",
  invalid_decision: "A escolha tem de ser Aprovar ou Rejeitar.",
  reason_required: "Rejeitar exige um motivo — escreve porque é que a proposta não serve.",
  invalid_reason: "O motivo tem no máximo 500 caracteres, numa só linha, sem caracteres de controlo.",
  // Recusas da rota de decisão (vaccine_decision.ERROR_CODES e main.VACCINE_DECISION_ROUTE_CODES).
  // O nome do analista (ou o seu identificador) tem caracteres fora do aceite, como o apóstrofo (F16 D-07).
  invalid_author: "O nome do analista tem caracteres fora do aceite (por exemplo um apóstrofo) — corrige-o na Equipa SOC e recarrega a página.",
  invalid_vaccine_id: "O identificador da vaccine está mal formado — escolhe a vaccine outra vez na tabela.",
  invalid_decided_at: "O backend recusou a data da decisão (erro do servidor, não do pedido) — vê o backend.log.",
  invalid_body: "O pedido foi recusado por estar fora do contrato do backend — recarrega a página para teres a versão atual do dashboard.",
  analyst_not_found: "Esse analista já não existe na Equipa SOC — escolhe outro analista na lista (é atualizada ao recarregar).",
  analyst_inactive: "Esse analista está desativado na Equipa SOC — escolhe outro analista na lista (é atualizada ao recarregar).",
  already_decided: "Esta vaccine já foi decidida — outra pessoa ou outro separador decidiu primeiro; a vista é atualizada.",
  vaccine_superseded: "Esta vaccine foi substituída por uma mais recente — a vista é atualizada e decide-se a atual.",
  // Transporte e HTTP sem código estável: servem a leitura e a decisão.
  timeout: "O backend não respondeu em 15 s — o pedido pode ter chegado ao backend; se estavas a decidir, a decisão pode ter ficado gravada e a vista é atualizada para o mostrar.",
  invalid_response: "O backend devolveu uma resposta ilegível — o pedido pode ter chegado ao backend; se estavas a decidir, a vista é atualizada para mostrar se a decisão ficou gravada (vê o backend.log).",
  http_403: "Acesso recusado pelo backend — confirma a API key e a origem do dashboard.",
  http_404: "O backend não tem a rota de vaccines — reinicia-o com a versão atual.",
  http_405: "O backend não aceita este método na rota de decisão — reinicia-o com a versão atual.",
  http_409: "Conflito: a vaccine mudou entretanto — a vista é atualizada.",
  http_422: "O backend recusou o pedido (valor fora do formato aceite) — recarrega a página e tenta de novo.",
  http_500: "Erro interno do backend — vê o backend.log.",
  http_502: "O backend devolveu 502 (erro de gateway) — tenta Atualizar daqui a pouco.",
  http_503: "O backend está indisponível (503) — tenta Atualizar daqui a pouco.",
  http_504: "O backend demorou demasiado a responder — tenta de novo; se estavas a decidir, a vista é atualizada.",
};

// Os mesmos formatos que a rota GET /api/vaccines aceita (a rota volta a validar).
const VAC_ATTACK_ID_RE = /^[1-9]\d{0,8}$/;
const VAC_TECHNIQUE_RE = /^T\d{4}(\.\d{3})?$/;
const VAC_INVALID_ATTACK_TEXT = "ID de ataque inválido: usa um número inteiro de 1 a 999999999.";

const vacTab = document.getElementById("tab-vaccines");
let vacLoading = false;
// Um refresco pedido enquanto outro está no ar (por exemplo depois de uma decisão) não se perde.
let vacRefreshQueued = false;
let vacWasActive = false;
// Vaccine aberta no detalhe e contador que descarta respostas fora de ordem.
let vacSelectedId = null;
let vacSelectSeq = 0;
// Decisão: vaccine desenhada no detalhe, pedido em curso e analistas ativos
// (null até carregar; vacAnalystsError guarda o código se falhou). Nada disto
// vai para o armazenamento do browser: recarregar a página volta a "Escolher…".
let vacDetailVaccine = null;
let vacDeciding = false;
let vacAnalysts = null;
let vacAnalystsError = null;
let vacAnalystsSeq = 0;
// União das técnicas MITRE vistas nas respostas da sessão: alimenta o select
// sem nunca encolher por causa do próprio filtro.
const vacTechniques = new Set();

function vacIsActive() {
  return vacTab.classList.contains("active") && document.visibilityState === "visible";
}

function vacCell(value) {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
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
  if ((code === "timeout" || code === "invalid_response") && typeof ApiError === "function"
      && typeof apiErrorMessage === "function") {
    return apiErrorMessage(new ApiError(code, 0));
  }
  if (/^http_\d{3}$/.test(code)) return VAC_GENERIC_ERROR + " (HTTP " + code.slice(5) + ")";
  return VAC_GENERIC_ERROR;
}

// A mensagem do erro lançado é sempre um código, nunca texto do servidor.
// O transporte (fetch, chave, timeout) é do apiRequest em api.js.
async function vacRequest(path, options) {
  try {
    return await apiRequest(path, options);
  } catch (err) {
    throw new Error(vacCodeFromApiError(err));
  }
}

// ApiError -> a chave de lookup de VAC_ERROR_TEXT (403/422 sem slug ficam
// http_403/http_422, como em vacCodeFromResponse).
function vacCodeFromApiError(err) {
  if (!err || err.name !== "ApiError") return "unexpected_error";
  if (err.code === "validation_error" || err.code === "forbidden") return "http_" + (err.status || 422);
  return err.code;
}

// Texto cru de uma lista, ou o travessão quando está vazia.
function vacList(list) {
  return list && list.length ? list.join(", ") : "—";
}

// Rótulo de um mapa fixo; uma chave desconhecida (ou herdada) fica como veio.
function vacLabel(labels, key) {
  return Object.prototype.hasOwnProperty.call(labels, key) ? labels[key] : key;
}

// Veredito em badge: classe pelo valor e rótulo (ou o valor), ambos escapados pelo htmlT.
function vacVerdictBadge(verdict) {
  const label = VAC_VERDICT_LABELS[verdict] || verdict;
  return htmlT`<span class="vac-verdict vac-verdict-${String(verdict)}">${String(label)}</span>`;
}

// Estado em badge com texto (D-07): a cor nunca é a única pista. O modificador de classe só
// aceita os três estados conhecidos (T-17-12); qualquer outro texto fica como veio, escapado
// pelo htmlT, com a classe vac-state-unknown. Ausente ou não-string é o travessão.
function vacStateBadge(state) {
  if (typeof state !== "string" || state === "") return htmlT`${vacCell(null)}`;
  const modifier = Object.prototype.hasOwnProperty.call(VAC_STATE_LABELS, state) ? state : "unknown";
  return htmlT`<span class="vac-state vac-state-${modifier}">${vacLabel(VAC_STATE_LABELS, state)}</span>`;
}

// A condição fica em helpers: cada interpolação do template começa por vac*.
function vacRowClass(vaccine) {
  let classes = vaccine.superseded_by === null || vaccine.superseded_by === undefined ? "" : " vac-row-superseded";
  if (vaccine.id === vacSelectedId) classes += " selected";
  return classes;
}

function vacSupersededNote(vaccine) {
  if (vaccine.superseded_by === null || vaccine.superseded_by === undefined) return "";
  return htmlT`<span class="vac-superseded-note">Substituída por ${vacCell(vaccine.superseded_by)}</span>`;
}

function vacRowsHtml(vaccines) {
  return htmlT`${vaccines.map((vaccine) => {
    const origin = vaccine.origin || {};
    const attack = origin.attack_id === null || origin.attack_id === undefined ? "" : "#" + origin.attack_id;
    return htmlT`<tr class="atk-row${vacRowClass(vaccine)}" data-id="${vaccine.id}" tabindex="0">
    <td>${vacCell(vaccine.id)}${vacSupersededNote(vaccine)}</td>
    <td>${vacCell(attack)}</td>
    <td>${vacCell(origin.scenario)}</td>
    <td>${vacCell(origin.mitre_technique)}</td>
    <td>${vacVerdictBadge(vaccine.verdict)}</td>
    <td>${vacCell(vacSensors(vaccine.missing_sensors))}</td>
    <td>${vacStateBadge(vaccine.state)}</td>
    <td>${vacCell(vacDate(vaccine.created_at))}</td>
  </tr>`;
  })}`;
}

function vacRenderList(envelope) {
  const body = document.getElementById("vac-body");
  const notice = document.getElementById("vac-notice");
  if (envelope.reason === "no_data") {
    htmRender(body, htmlT`<tr><td colspan="8" class="empty-state">${VAC_NO_DATA_TEXT}</td></tr>`);
    notice.textContent = "";
    return;
  }
  const vaccines = envelope.vaccines || [];
  if (!vaccines.length) {
    htmRender(body, htmlT`<tr><td colspan="8" class="empty-state">${VAC_FILTER_EMPTY_TEXT}</td></tr>`);
    notice.textContent = "";
    return;
  }
  htmRender(body, vacRowsHtml(vaccines));
  let text = vaccines.length + " vaccine(s)";
  if (envelope.total > vaccines.length) text += " — a mostrar as primeiras " + vaccines.length;
  notice.textContent = text;
}

function vacRenderError(code) {
  const text = vacErrorText(code);
  renderPanelError("#vaccines-panel", text);
  const tbody = document.getElementById("vac-body");
  const tr = document.createElement("tr");
  const td = document.createElement("td");
  td.colSpan = 8;
  td.className = "vac-error-state";
  tr.appendChild(td);
  tbody.replaceChildren(tr);
  sttShowError(td, text);
  document.getElementById("vac-notice").textContent = "";
}

// Contadores das vaccines atuais por estado (D-08). Vêm do envelope e não dependem dos filtros;
// sem amostra, erro ou valor inválido o cartão mostra — (kpiRender), nunca 0.
function vacRenderCounts(stateCounts) {
  const view = slVacStateCounts(stateCounts);
  kpiRender(document.getElementById("vac-count-proposed"), { label: "Propostas", value: view.proposed });
  kpiRender(document.getElementById("vac-count-approved"), { label: "Aprovadas", value: view.approved });
  kpiRender(document.getElementById("vac-count-rejected"), { label: "Rejeitadas", value: view.rejected });
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
  const state = document.getElementById("vac-state-filter").value;
  const superseded = document.getElementById("vac-superseded-filter").checked;
  if (attackId !== "" && !VAC_ATTACK_ID_RE.test(attackId)) return null;
  const params = new URLSearchParams();
  if (attackId !== "") params.set("attack_id", attackId);
  if (VAC_TECHNIQUE_RE.test(technique)) params.set("technique", technique);
  if (VAC_STATES.includes(state)) params.set("state", state);
  if (superseded) params.set("include_superseded", "true");
  const text = params.toString();
  return text ? "?" + text : "";
}

// Cada option é escapada (htmlT); só entram técnicas que casam VAC_TECHNIQUE_RE.
function vacTechniqueOptionsHtml() {
  const options = [htmlT`<option value="">Todas</option>`];
  for (const technique of Array.from(vacTechniques).sort()) {
    options.push(htmlT`<option value="${technique}">${technique}</option>`);
  }
  return htmlT`${options}`;
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
  htmRender(select, vacTechniqueOptionsHtml());
  select.value = selected;
}

// Linha "A carregar" (só quando a tabela ainda não tem vaccines).
function vacShowLoadingRow() {
  const tr = document.createElement("tr");
  const td = document.createElement("td");
  td.colSpan = 8;
  tr.appendChild(td);
  document.getElementById("vac-body").replaceChildren(tr);
  sttShowLoading(td, "A carregar as vaccines…");
}

async function vacRefresh() {
  if (vacLoading) {
    vacRefreshQueued = true;
    return;
  }
  const query = vacBuildQuery();
  if (query === null) {
    document.getElementById("vac-notice").textContent = VAC_INVALID_ATTACK_TEXT;
    return;
  }
  vacLoading = true;
  if (!document.querySelector("#vac-body tr[data-id]")) vacShowLoadingRow();
  try {
    const envelope = await vacRequest("/api/vaccines" + query);
    renderPanelError("#vaccines-panel", "");
    vacRenderList(envelope);
    vacAddTechniques(envelope.vaccines || []);
    vacRenderGenerator(envelope.generator);
    vacRenderCounts(envelope.state_counts);
  } catch (err) {
    vacRenderError(err.message);
    vacRenderCounts(null);
    const line = document.getElementById("vac-generator");
    line.textContent = "";
    line.classList.remove("vac-generator-error");
  } finally {
    vacLoading = false;
    // Refresco pedido ou filtros mudados a meio do pedido: um (e só um) novo pedido, depois deste.
    const queued = vacRefreshQueued;
    vacRefreshQueued = false;
    const current = vacBuildQuery();
    if (current !== null && (queued || current !== query)) vacRefresh();
  }
}

// Detalhe da vaccine (D-06): Origem, Propostas e Cadeia. Só texto: sem
// ligações para outras abas (D-07). Cada valor passa por vacCell.
function vacAttackLabel(attackId) {
  return attackId === null || attackId === undefined ? "" : "#" + attackId;
}

function vacSourceNote(source) {
  if (typeof source !== "string") return htmlT``;
  return htmlT` (fonte: ${vacCell(vacLabel(VAC_EXPECTED_SOURCE_LABELS, source))})`;
}

function vacOriginHtml(vaccine) {
  const origin = vaccine.origin;
  const evidence = origin.evidence || {};
  const incidents = origin.incident_ids && origin.incident_ids.length ? vacList(origin.incident_ids) : "nenhum incidente ligado";
  return htmlT`<span>Veredito: ${vacVerdictBadge(vaccine.verdict)}</span>
    <span>Ataque: <strong>${vacCell(vacAttackLabel(origin.attack_id))}</strong></span>
    <span>Cenário: <strong>${vacCell(origin.scenario)}</strong></span>
    <span>MITRE: ${vacCell(origin.mitre_technique)} (${vacCell(origin.mitre_tactic)})</span>
    <span>Incidentes: ${vacCell(incidents)}</span>
    <span>Sensores esperados: ${vacCell(vacSensors(vaccine.expected))}${vacSourceNote(vaccine.expected_source)}</span>
    <span>Sensores alcançados: ${vacCell(vacSensors(vaccine.achieved))}</span>
    <span>Evidência (por referência): Event IDs ${vacCell(vacList(evidence.matched_event_ids))};
      alertas correspondentes ${vacCell(evidence.matched_alert_count)};
      deteções de rede ${vacCell(vacList(evidence.network_detection_types))}</span>`;
}

function vacEventRowsHtml(events) {
  return htmlT`${(events || []).map((catalogEvent) => htmlT`<tr>
    <td>${vacCell(catalogEvent.event_id)}</td>
    <td>${vacCell(catalogEvent.name)}</td>
    <td>${vacCell(catalogEvent.severity)}</td>
  </tr>`)}`;
}

function vacRuleHtml(proposal) {
  const rule = proposal.rule;
  if (!rule) return htmlT``;
  return htmlT`<p>Regra proposta: Event IDs <strong>${vacCell(vacList(rule.event_ids))}</strong> — pelo menos
    ${vacCell(rule.min_count)} ocorrência(s) em ${vacCell(rule.window_seconds)} s</p>
    <table><thead><tr><th>Event ID</th><th>Nome</th><th>Severidade</th></tr></thead>
    <tbody>${vacEventRowsHtml(proposal.events)}</tbody></table>`;
}

function vacRecommendationHtml(proposal) {
  if (!proposal.recommendation) return htmlT``;
  return htmlT`<p>Recomendação: ${vacCell(proposal.recommendation)}</p>`;
}

function vacProposalsHtml(vaccine) {
  const proposals = vaccine.proposals || [];
  if (!proposals.length) return htmlT`<p>Nenhuma proposta registada.</p>`;
  return htmlT`${proposals.map((proposal) => htmlT`<div class="vac-proposal">
    <h4>${vacCell(vacLabel(VAC_SENSOR_LABELS, proposal.sensor))}</h4>
    ${vacRuleHtml(proposal)}
    ${vacRecommendationHtml(proposal)}
  </div>`)}`;
}

// O que a própria vaccine já diz da cadeia, em texto simples.
function vacChainLead(vaccine) {
  if (vaccine.superseded_by) return "Substituída por " + vaccine.superseded_by + ".";
  return "Atual — é a proposta em vigor para este ataque.";
}

// replacedIds é a lista calculada a partir do segundo pedido; sem ela (ainda
// por chegar) só se desenha a linha que a própria vaccine permite afirmar.
function vacChainHtml(vaccine, replacedIds) {
  let extra = htmlT``;
  if (Array.isArray(replacedIds)) {
    extra = replacedIds.length
      ? htmlT`<p>Substitui: ${vacCell(replacedIds.join(", "))}</p>`
      : htmlT`<p>Não substitui nenhuma vaccine anterior deste ataque.</p>`;
  }
  return htmlT`<p>${vacCell(vacChainLead(vaccine))}</p>${extra}`;
}

// Ids (por ordem) das vaccines da lista que esta vaccine substituiu.
function vacReplacedIds(vaccines, id) {
  return vaccines.filter((vaccine) => vaccine.superseded_by === id).map((vaccine) => vaccine.id);
}

// Segundo pedido de leitura: as vaccines do mesmo ataque, incluindo as
// substituídas. Um erro nunca se apresenta como "não substitui nenhuma".
async function vacLoadChain(vaccine, seq) {
  const chain = document.getElementById("vac-detail-chain");
  sttShowLoading(chain, "A carregar a cadeia…");
  const params = new URLSearchParams();
  params.set("attack_id", String(vaccine.origin.attack_id));
  params.set("include_superseded", "true");
  params.set("limit", "500");
  try {
    const envelope = await vacRequest("/api/vaccines?" + params.toString());
    if (seq !== vacSelectSeq) return;
    htmRender(chain, vacChainHtml(vaccine, vacReplacedIds(envelope.vaccines || [], vaccine.id)));
  } catch (err) {
    if (seq !== vacSelectSeq) return;
    sttShowError(chain, vacChainLead(vaccine) + " Cadeia indisponível: " + vacErrorText(err.message));
  }
}

function vacRenderDetail(vaccine) {
  document.getElementById("vaccine-detail-panel").hidden = false;
  document.getElementById("vac-detail-title").textContent = vaccine.id;
  htmRender(document.getElementById("vac-detail-origin"), vacOriginHtml(vaccine));
  htmRender(document.getElementById("vac-detail-proposals"), vacProposalsHtml(vaccine));
  htmRender(document.getElementById("vac-detail-chain"), vacChainHtml(vaccine));
  document.getElementById("vac-detail-warning").textContent = slVacWarningText(vaccine.state, VAC_STATE_LABELS);
  vacDetailVaccine = vaccine;
  vacRenderDecision();
}

function vacRenderDetailError(code) {
  document.getElementById("vaccine-detail-panel").hidden = false;
  renderPanelError("#vaccine-detail-panel", vacErrorText(code));
  document.getElementById("vac-detail-title").textContent = "Vaccine";
  document.getElementById("vac-detail-origin").replaceChildren();
  document.getElementById("vac-detail-proposals").replaceChildren();
  document.getElementById("vac-detail-chain").replaceChildren();
  document.getElementById("vac-detail-warning").textContent = slVacWarningText(null, VAC_STATE_LABELS);
  vacDetailVaccine = null;
  vacRenderDecision();
}

// Linhas do bloco Decisão: texto simples (escapado pelo htmlT) ou um htmlT já seguro (badge de estado).
function vacShowDecisionLines(lines) {
  htmRender(document.getElementById("vac-decision-state"),
    htmlT`${lines.map((line) => htmlT`<span>${line}</span><br>`)}`);
}

// Decisão do analista (D-03, D-06, D-09). O que se mostra decide-se só por slVacDecisionView:
// os botões só existem para uma vaccine proposta, atual e com analistas ativos; nos outros casos
// o bloco explica porquê (decidida, substituída, estado desconhecido, analistas por carregar,
// em falta ou indisponíveis) e nunca se esconde nem se desenha como ausência de dados.
function vacRenderDecision() {
  const form = document.getElementById("vac-decision-form");
  const view = slVacDecisionView(vacDetailVaccine, vacAnalysts, vacAnalystsError);
  const proposed = htmlT`Estado: ${vacStateBadge("proposed")}`;
  let showForm = false;
  switch (view.mode) {
    case "decided":
      vacShowDecisionLines([
        htmlT`Estado: ${vacStateBadge(view.state)} · por ${vacCell(view.author)} · em ${vacCell(vacDate(view.decidedAt))}`,
        "Motivo: " + vacCell(view.reason),
      ]);
      break;
    case "superseded":
      vacShowDecisionLines(["Substituída por " + vacCell(view.supersededBy)
        + " — já não pode ser decidida; decide a vaccine atual deste ataque."]);
      break;
    case "unknown_state":
      vacShowDecisionLines(["Estado " + vacCell(view.state) + " — sem decisão possível neste painel."]);
      break;
    case "analysts_error":
      vacShowDecisionLines([proposed, vacErrorText(view.code)]);
      break;
    case "no_analysts":
      vacShowDecisionLines([proposed, VAC_NO_ANALYSTS_TEXT]);
      break;
    case "loading":
      vacShowDecisionLines([proposed, VAC_DECISION_LOADING_TEXT]);
      break;
    case "controls":
      vacShowDecisionLines([proposed]);
      showForm = true;
      break;
    case "none":
    default:
      vacShowDecisionLines([]);
  }
  form.hidden = !showForm;
  vacSyncDecisionControls();
}

// Nova vaccine aberta: o analista e o motivo nunca passam de uma vaccine para outra (D-01).
function vacResetDecisionForm() {
  document.getElementById("vac-decision-analyst").value = "";
  document.getElementById("vac-decision-reason").value = "";
  document.getElementById("vac-decision-count").textContent = slVacReasonCounter("");
  vacSetDecisionStatus("", false);
  vacSyncDecisionControls();
}

// Botões desativados durante o pedido e enquanto não há analista escolhido.
function vacSyncDecisionControls() {
  const select = document.getElementById("vac-decision-analyst");
  const blocked = vacDeciding || select.value === "";
  document.querySelectorAll("#vac-detail-decision button[data-action]").forEach((button) => {
    button.disabled = blocked;
  });
  select.disabled = vacDeciding;
  document.getElementById("vac-decision-reason").disabled = vacDeciding;
}

function vacSetDecisionStatus(text, isError) {
  const status = document.getElementById("vac-decision-status");
  status.textContent = text;
  status.classList.toggle("vac-decision-error", isError);
}

// O código do erro só serve de chave de vacErrorText e do seguimento (D-13). Quando o servidor pode
// ter gravado, ou outra pessoa decidiu primeiro, refaz-se o detalhe (o id não muda, por isso a frase
// fica) e a lista com os contadores; com um analista entretanto inexistente recarregam-se os analistas.
// O seguimento só faz pedidos GET: nunca há um novo POST automático.
function vacRenderDecisionError(code) {
  vacSetDecisionStatus(vacErrorText(code), true);
  const followUp = slVacErrorFollowUp(code);
  if (followUp === "refresh") {
    vacSelect(vacSelectedId);
    vacRefresh();
  } else if (followUp === "reload_analysts") {
    vacLoadAnalysts();
  }
}

// Guarda a falha ao ler os analistas (código estável, nunca texto do servidor).
function vacSetAnalystsError(code) {
  vacAnalystsError = code;
  vacAnalysts = null;
}

// Redesenha as options do select, mantendo a escolha só se o analista ainda existir.
function vacRenderAnalystOptions() {
  const select = document.getElementById("vac-decision-analyst");
  const chosen = select.value;
  const options = Array.isArray(vacAnalysts) ? vacAnalysts : [];
  htmRender(select, htmlT`<option value="">Escolher…</option>${options.map((analyst) =>
    htmlT`<option value="${analyst.id}">${analyst.name}</option>`)}`);
  select.value = options.some((analyst) => analyst.id === chosen) ? chosen : "";
}

async function vacLoadAnalysts() {
  const seq = ++vacAnalystsSeq;
  try {
    const envelope = await vacRequest("/api/soc/analysts?active_only=true");
    if (seq !== vacAnalystsSeq) return;
    vacAnalysts = slVacAnalystOptions(envelope);
    vacAnalystsError = null;
  } catch (err) {
    if (seq !== vacAnalystsSeq) return;
    vacSetAnalystsError(err.message);
  }
  vacRenderAnalystOptions();
  vacRenderDecision();
}

// Único POST do ficheiro. A validação local (slVacDecisionBody) não envia
// nada; um segundo clique durante o pedido é ignorado (vacDeciding).
async function vacDecide(choice) {
  if (vacDeciding) return;
  const vaccine = vacDetailVaccine;
  if (!vaccine || vaccine.id !== vacSelectedId) return;
  const check = slVacDecisionBody(
    document.getElementById("vac-decision-analyst").value, choice,
    document.getElementById("vac-decision-reason").value);
  if (check.code) {
    vacRenderDecisionError(check.code);
    return;
  }
  vacDeciding = true;
  vacSyncDecisionControls();
  vacSetDecisionStatus("A registar a decisão…", false);
  const seq = vacSelectSeq;
  try {
    const envelope = await vacRequest("/api/vaccines/" + encodeURIComponent(vaccine.id) + "/decision",
      { method: "POST", body: check.body });
    if (seq === vacSelectSeq) {
      vacDetailVaccine = envelope.vaccine;
      document.getElementById("vac-detail-warning").textContent = slVacWarningText(envelope.vaccine.state, VAC_STATE_LABELS);
      vacRenderDecision();
      vacSetDecisionStatus(envelope.notice, false);
    }
    vacRefresh();
  } catch (err) {
    if (seq === vacSelectSeq) vacRenderDecisionError(err.message);
    else if (slVacErrorFollowUp(err.message) === "refresh") vacRefresh();
  } finally {
    vacDeciding = false;
    vacSyncDecisionControls();
  }
}

async function vacSelect(id) {
  if (!VAC_ID_RE.test(id)) return;
  if (id !== vacSelectedId) vacResetDecisionForm();
  const seq = ++vacSelectSeq;
  vacSelectedId = id;
  document.querySelectorAll("#vac-body tr[data-id]").forEach((tr) =>
    tr.classList.toggle("selected", tr.dataset.id === id));
  try {
    const envelope = await vacRequest("/api/vaccines/" + encodeURIComponent(id));
    if (seq !== vacSelectSeq) return;
    renderPanelError("#vaccine-detail-panel", "");
    vacRenderDetail(envelope.vaccine);
    vacLoadChain(envelope.vaccine, seq);
  } catch (err) {
    if (seq !== vacSelectSeq) return;
    vacRenderDetailError(err.message);
  }
}

document.getElementById("vac-body").addEventListener("click", (event) => {
  const tr = event.target.closest("tr[data-id]");
  if (tr) vacSelect(tr.dataset.id);
});
document.getElementById("vac-body").addEventListener("keydown", (event) => {
  const tr = event.target.closest("tr[data-id]");
  if (tr && (event.key === "Enter" || event.key === " ")) {
    event.preventDefault();
    vacSelect(tr.dataset.id);
  }
});

for (const id of ["vac-attack-filter", "vac-technique-filter", "vac-state-filter", "vac-superseded-filter"]) {
  document.getElementById(id).addEventListener("change", vacRefresh);
}
document.getElementById("vac-refresh-btn").addEventListener("click", vacRefresh);

document.getElementById("vac-detail-decision").addEventListener("click", (event) => {
  const button = event.target.closest("[data-action]");
  if (!button) return;
  if (button.dataset.action === "vac-approve") vacDecide("approved");
  else if (button.dataset.action === "vac-reject") vacDecide("rejected");
});
document.getElementById("vac-decision-analyst").addEventListener("change", vacSyncDecisionControls);
document.getElementById("vac-decision-reason").addEventListener("input", (event) => {
  document.getElementById("vac-decision-count").textContent = slVacReasonCounter(event.target.value);
});

// Ciclo de vida: recarrega só na passagem de inativa a ativa.
function vacOnShow() {
  const active = vacIsActive();
  if (active && !vacWasActive) {
    vacRefresh();
    vacLoadAnalysts();
  }
  vacWasActive = active;
}
const vacObserver = new MutationObserver(vacOnShow);
vacObserver.observe(vacTab, { attributes: true, attributeFilter: ["class"] });
document.addEventListener("visibilitychange", vacOnShow);
vacOnShow();
