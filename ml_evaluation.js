// Aba "📐 Evaluation" (marco R9, Fase 2 — avaliação ligada à versão; R11: comparação vN vs vN−1).
// Carregado DEPOIS de app.js e de ml_models.js: reutiliza os globais de
// app.js (API_BASE, API_KEY, htmlT/htmRender de html.js, renderPanelError) e os helpers puros
// de ml_models.js (mlmErrorText, mlmCodeFromResponse) — não redeclara nenhum
// deles, porque os scripts clássicos partilham um só escopo global.
//
// TODOS os identificadores de topo começam por mle/MLE_ (Pitfall 9): um nome
// repetido com ml_models.js (mlm/MLM_) ou com app.js rebentava o script
// inteiro no browser. O teste node:vm carrega os DOIS ficheiros no mesmo
// contexto de propósito, para que essa colisão fosse um teste vermelho.
//
// Duas camadas, como ml_models.js, para a lógica ser testável sem browser
// (test_ml_models_ui.py + test_ml_models_ui.cjs carregam este ficheiro num
// node:vm sem document):
//
//   1. camada pura — sem DOM, sem fetch, devolve strings (mlePercent,
//      mleMetricCell, mleBuildEvalRows, mleEvalNoticeText, mleOriginHtml,
//      mleSmallSampleNotice, mleBuildLiveAgreement, mleLiveErrorHtml,
//      mleEmptyState, mleVersionNumber, mleNumeradas, mleDeltaPontos,
//      mleDeltaTexto, mleVeredicto, mleComparePairs, mleCompareRows,
//      mleCompareNoticeText, mleFeatureStatsNotice, mleLiveModelText);
//   2. camada DOM — só chamada a partir de mleInit().
//
// Nenhuma linha de topo toca em `document`: é o que permite ao teste Node
// carregar o ficheiro. O arranque é a ÚLTIMA instrução, com a guarda
// `typeof document !== "undefined"`.
//
// Cada linha lê o `evaluation` da SUA PRÓPRIA entrada: nunca um valor global.
// Com duas versões com avaliações diferentes, a linha de cada uma tem de
// trazer as métricas dela (Pitfall 1 — o critério 2 do ROADMAP). Todo o texto
// que vem do metadata.json do utilizador é interpolado em htmlT (escapado).
//
// O bloco de concordância ao vivo faz o SEGUNDO pedido desta aba, a
// /api/ml-anomalies (D-10). Os dois pedidos são independentes: uma falha de um
// não apaga o que o outro já mostrou.
//
// A comparação vN vs vN−1 (R11) é derivada NO BROWSER do que GET /api/ml/models
// já traz (cada versão já vem com a sua `evaluation`). Nenhum endpoint novo,
// nenhuma chamada extra, nenhum segundo pedido — mleRefresh continua a fazer
// exactamente os mesmos dois pedidos de antes (D-07).

// ======================= camada pura (sem DOM) ==============================

const MLE_EMPTY_TEXT = "Sem dados — ainda não há modelos registados.";
const MLE_SEM_AVALIACAO =
  'Sem avaliação — corre "python model_registry.py evaluate vN --events <ficheiro>"';

// Quantas colunas a tabela desenha. Uma linha de aviso ou de "Sem avaliação"
// ocupa a largura toda, por isso o colspan é o mesmo número da tabela.
const MLE_COLUNAS = 6;

// --- Comparação vN vs vN-1 (R11) -----------------------------------------------
//
// A comparação é derivada NO BROWSER do que GET /api/ml/models já traz
// (cada versão já vem com a sua `evaluation`). Nenhum endpoint novo,
// nenhuma chamada extra, nenhum segundo pedido — mleRefresh continua
// a fazer exactamente os mesmos dois pedidos de antes (D-07).
//
// O par comparado é sempre (vN, vN-1) por NÚMERO de versão, nunca por
// ordem da lista nem por "as duas últimas": uma lista reordenada pelo
// backend dá a mesma comparação, e uma versão sem avaliação interrompe
// a cadeia em vez de ser saltada em silêncio.
//
// A palavra de veredicto é uma de três: "melhorou", "piorou", "estável" —
// e sai de um limiar NOMEADO em pontos percentuais (MLE_DELTA_LIMIAR_PP),
// ao jeito dos MIN_EVENTS/MIN_ATTACKS da Fase 2. Um delta abaixo do
// limiar é "estável", nunca "melhorou".
//
// Uma métrica ausente num dos lados NÃO é "piorou": a célula fica "—",
// o delta fica "—" e a leitura fica "—". Nunca se compara com um valor
// inventado.
//
// D-03: quando metadata.dataset.feature_stats existe, a Evaluation mostra,
// por feature, a média e o desvio **do lote de treino** e diz por escrito
// que um evento pode mudar de feature — e de veredicto — conforme o lote.
// Honestidade como funcionalidade; a forma do objecto que o backend
// escrever tem de ser lida, não adivinhada.

const MLE_DELTA_LIMIAR_PP = 0.5;   // limiar em pontos percentuais (ex.: 0.5 pp)

function mleVersionNumber(id) {
  if (typeof id !== "string") return null;
  const m = id.match(/^v(\d+)$/);
  return m ? parseInt(m[1], 10) : null;
}

function mleNumeradas(versions) {
  return (versions || [])
    .filter((e) => e && e.kind !== "legacy" && mleVersionNumber(e.id) !== null)
    .sort((a, b) => mleVersionNumber(b.id) - mleVersionNumber(a.id));
}

function mleDeltaPontos(a, b) {
  if (a === null || b === null) return null;
  return Math.round((b - a) * 1000) / 10; // b - a em pontos percentuais, 1 casa
}

function mleDeltaTexto(delta) {
  if (delta === null) return "—";
  const sinal = delta > 0 ? "+" : "";
  return `${sinal}${delta.toFixed(1).replace(".", ",")} pp`;
}

function mleVeredicto(delta) {
  if (delta === null) return "—";
  if (Math.abs(delta) < MLE_DELTA_LIMIAR_PP) return "estável";
  return delta > 0 ? "melhorou" : "piorou";
}

function mleComparePairs(versions) {
  const num = mleNumeradas(versions);
  const pares = [];
  for (let i = 0; i < num.length - 1; i++) {
    const maisNova = num[i];
    const maisVelha = num[i + 1];
    if (mleVersionNumber(maisNova.id) - mleVersionNumber(maisVelha.id) !== 1) continue;
    const evN = maisNova.evaluation;
    const evV = maisVelha.evaluation;
    if (!evN || !evV) continue;
    pares.push({ maisNova, maisVelha });
  }
  return pares;
}

function mleCompareRows(pares) {
  const metricas = ["precision", "recall", "f1"];
  const lados = ["ml", "rules"];
  return pares.map((par) => {
    const n = par.maisNova;
    const v = par.maisVelha;
    const linhas = [];
    for (const lado of lados) {
      for (const metrica of metricas) {
        const a = mleNumero(par.maisVelha.evaluation?.[lado]?.[metrica]);
        const b = mleNumero(par.maisNova.evaluation?.[lado]?.[metrica]);
        const delta = mleDeltaPontos(a, b);
        const veredicto = mleVeredicto(delta);
        linhas.push({
          versaoNova: mleVersionNumber(n.id),
          versaoVelha: mleVersionNumber(v.id),
          lado,
          metrica,
          antes: mlePercent(a),
          depois: mlePercent(b),
          delta: mleDeltaTexto(delta),
          veredicto,
          veredictoClass:
            delta === null ? "" : (delta > 0 ? "mle-delta-up" : delta < 0 ? "mle-delta-down" : "mle-delta-flat"),
        });
      }
    }
    return linhas;
  }).flat();
}

function mleCompareNoticeText(versions) {
  const num = mleNumeradas(versions);
  const pares = mleComparePairs(versions);
  const semPar = num.length - pares.length;
  let txt = `${pares.length} par(es) comparado(s) (vN vs vN−1).`;
  if (semPar > 0) {
    txt += ` ${semPar} versão(ões) avaliada(s) sem par para comparar.`;
  }
  return txt;
}

// --- feature_stats notice (D-03) -----------------------------------------------
//
// Quando metadata.dataset.feature_stats existe, mostra a média e o desvio
// por feature no lote de treino, e avisa que estes números descrevem o
// lote, não o comportamento do modelo. O mesmo evento pode mudar de
// feature (e de veredicto) conforme o lote — 9,6 % dos casos mudam de
// feature, 8,7 % dos eventos mudam de veredicto anómalo/normal só por
// isso. A resposta do projecto não é corrigir o skew — é declará-lo.
function mleFeatureStatsNotice(entry) {
  const meta = entry?.metadata;
  const stats = meta?.dataset?.feature_stats;
  if (!stats || typeof stats !== "object") return "";
  const chaves = Object.keys(stats);
  if (!chaves.length) return "";
  const linhas = chaves.map((k) => {
    const v = stats[k];
    if (!v || typeof v !== "object" || typeof v.mean !== "number" || typeof v.std !== "number") return null;
    return `${k}: mean ${v.mean.toFixed(3).replace(".", ",")}, std ${v.std.toFixed(3).replace(".", ",")}`;
  }).filter(Boolean).join("; ");
  if (!linhas) return "";
  return `⚠ Feature stats do lote de treino: ${linhas}. Estes números descrevem o lote de treino (média e desvio populacional de cada feature no lote), não o comportamento do modelo. O mesmo evento pode mudar de feature — e de veredicto — conforme o lote que o acompanha (medido: ~9,6 % dos eventos mudam de feature, ~8,7 % mudam de veredicto só por isso).`;
}

// --- live model_version (D-06) -------------------------------------------------
//
// Durante e depois de um reset_cache, um relatório pode ser de uma
// versão que já não é a activa. Sem model_version o painel diz "o modelo"
// e não diz qual. "legacy" é uma resposta honesta (o modelo sem metadados),
// None é "nada carregado".
function mleLiveModelText(mlReport) {
  const v = mlReport?.model_version;
  if (v === "legacy") return "Modelo: legado (sem metadados nem verificação SHA-256).";
  if (v === null || v === undefined) return "Modelo: (não carregado / indeterminado).";
  if (typeof v === "string") return `Modelo: ${v} (versão que mediu esta janela).`;
  return `Modelo: ${String(v)} (versão que mediu esta janela).`;
}

// ======================= camada pura (sem DOM) ==============================

// --- concordância ao vivo (D-10) ----------------------------------------------
//
// MLE_LIVE_SEM_DADOS é uma DECISÃO de frontend, não um valor ausente: a rota
// devolve total = 0 (inteiro, nunca None) numa janela sem eventos, e 0 ÷ 0
// desenhado como "0,0 %" seria lido como concordância perfeita (Pitfall 3).
const MLE_LIVE_SEM_DADOS =
  "Sem dados — nenhum evento com timestamp e Event ID válidos na janela.";

// O tecto de 1000 alertas é do Indexer, não do painel: um acordo calculado
// sobre uma janela truncada não é um acordo completo, e o valor mostrado
// continua a ser o agree/total que a rota calculou.
const MLE_LIVE_TRUNCADO =
  "A janela foi truncada pelo tecto de 1000 alertas do Indexer: a concordância abaixo só "
  + "cobre os alertas mais recentes e pode estar a subestimar a divergência.";

// --- origem dos dados (D-06, D-08) --------------------------------------------
//
// A origem é DECLARADA pelo comando (`--dataset-origin`), nunca adivinhada
// pelo caminho do ficheiro. O valor cru nunca é desenhado: um valor fora dos
// três cai no badge de "não declarada", que é o que um `evaluate` sem
// --dataset-origin produz.
const MLE_ORIGEM_REAL = "dados reais";
const MLE_ORIGEM_SINTETICOS = "dados sintéticos";
const MLE_ORIGEM_NAO_DECLARADA = "origem não declarada";
const MLE_ORIGEM_DESCONHECIDA = "origem desconhecida";
const MLE_ORIGIN_AVISO =
  "a origem do dataset não foi declarada no comando — não assumimos que são reais";

// Um número para desenhar, ou "—": um valor em falta nunca vira 0 nem "NaN".
function mleNumero(valor) {
  if (typeof valor === "boolean" || valor === null || valor === undefined || valor === "") return null;
  const numero = Number(valor);
  return Number.isFinite(numero) ? numero : null;
}

function mleContagem(valor) {
  const numero = mleNumero(valor);
  return numero === null ? "—" : String(numero);
}

// "Etiqueta 12" para as contagens da concordância ao vivo.
function mleMetrica(rotulo, valor) {
  return htmlT`<span class="mle-metric"><span class="mle-metric-label">${rotulo}</span> ${valor}</span>`;
}

// A percentagem pt-PT, com uma casa. Um valor em falta nunca é desenhado
// como 0 %: sem amostra é "—", não um número inventado (D-10/Pitfall 3).
function mlePercent(value) {
  if (typeof value !== "number" && typeof value !== "string") return "—";
  if (typeof value === "string" && value.trim() === "") return "—";
  const numero = Number(value);
  if (!Number.isFinite(numero)) return "—";
  return `${(numero * 100).toFixed(1).replace(".", ",")} %`;
}

// As três métricas de um lado (ML ou regras) numa célula. Sem objeto, "—".
function mleMetricCell(metrics) {
  if (!metrics || typeof metrics !== "object") return "—";
  return htmlT`${[
    ["P", metrics.precision],
    ["R", metrics.recall],
    ["F", metrics.f1],
  ].map(([sigla, valor], i) =>
    htmlT`${i ? " " : ""}<span class="mle-metric"><span class="mle-metric-label">${sigla}</span> ${mlePercent(valor)}</span>`
  )}`;
}

function mleEmptyState(colspan, texto) {
  const col = Number(colspan) > 0 ? Number(colspan) : 1;
  return htmlT`<tr><td colspan="${col}" class="empty-state">${texto}</td></tr>`;
}

// O badge da origem DECLARADA do dataset da avaliação. Só existem três
// origens; qualquer outra cai em "origem desconhecida" (o valor cru nunca é
// desenhado, T-02-28), e o badge de "não declarada" carrega sempre o aviso
// que diz o que isso significa.
function mleOriginHtml(dataset_origin) {
  if (dataset_origin === "real") {
    return htmlT`<span class="mle-origin mle-origin-real">${MLE_ORIGEM_REAL}</span>`;
  }
  if (dataset_origin === "synthetic") {
    return htmlT`<span class="mle-origin mle-origin-synthetic">${MLE_ORIGEM_SINTETICOS}</span>`;
  }
  if (dataset_origin === "unknown") {
    return htmlT`<span class="mle-origin mle-origin-unknown" title="${MLE_ORIGIN_AVISO}">${MLE_ORIGEM_NAO_DECLARADA}</span>`;
  }
  return htmlT`<span class="mle-origin mle-origin-unknown" title="${MLE_ORIGIN_AVISO}">${MLE_ORIGEM_DESCONHECIDA}</span>`;
}

// O aviso de amostra pequena (D-05): dois limiares nomeados, eventos E
// ataques, e os números REAIS do dataset. Os limiares vêm no payload
// (min_events/min_attacks gravados pelo motor) — o frontend nunca os
// recalcula. Sem small_sample === true não há aviso, e um número em falta
// é "—" em vez de um inteiro inventado.
function mleSmallSampleNotice(evaluation) {
  if (!evaluation || typeof evaluation !== "object") return "";
  if (evaluation.small_sample !== true) return "";
  return `⚠ Amostra pequena: ${mleContagem(evaluation.total_events)} eventos `
    + `(mínimo ${mleContagem(evaluation.min_events)}) e `
    + `${mleContagem(evaluation.attacks_in_dataset)} ataques `
    + `(mínimo ${mleContagem(evaluation.min_attacks)}) — com uma amostra assim as métricas `
    + `acima são pouco fiáveis.`;
}

// Uma linha por versão: Versão | Ativa | Dataset | Origem | ML | Regras. Quando
// a versão não tem avaliação, uma linha extra diz "Sem avaliação" — a
// distinção tem de ser VISÍVEL, não um "—" que se lê como zero (EVAL-03). Com
// avaliação e amostra pequena, a linha de aviso entra logo a seguir, com os
// dois limiares.
function mleBuildEvalRows(report) {
  const versions = (report && report.versions) || [];
  if (!versions.length) return mleEmptyState(MLE_COLUNAS, MLE_EMPTY_TEXT);
  return htmlT`${versions.map((entry) => {
    const ativa = entry.active ? htmlT`<span class="mlm-badge mlm-badge-active">ativa</span>` : "—";
    const versao = entry.id || entry.label || "";
    const avaliacao = entry.evaluation;
    const semAvaliacao = avaliacao === null || avaliacao === undefined;
    const dataset = semAvaliacao
      ? "—"
      : `${mleContagem(avaliacao.total_events)} eventos · `
        + `${mleContagem(avaliacao.attacks_in_dataset)} ataques`;
    const linha = htmlT`<tr>
      <td>${versao}</td>
      <td>${ativa}</td>
      <td>${dataset}</td>
      <td>${mleOriginHtml(semAvaliacao ? null : avaliacao.dataset_origin)}</td>
      <td>${mleMetricCell(avaliacao && avaliacao.ml)}</td>
      <td>${mleMetricCell(avaliacao && avaliacao.rules)}</td>
    </tr>`;
    if (semAvaliacao) return htmlT`${linha}${mleEmptyState(MLE_COLUNAS, MLE_SEM_AVALIACAO)}`;
    const aviso = mleSmallSampleNotice(avaliacao);
    if (!aviso) return linha;
    return htmlT`${linha}<tr><td colspan="${MLE_COLUNAS}" class="mle-warning">${aviso}</td></tr>`;
  })}`;
}

// Uma frase com as contagens que o analista precisa antes de ler números:
// quantas versões há e quantas ainda não foram avaliadas.
function mleEvalNoticeText(report) {
  const versions = (report && report.versions) || [];
  const semAvaliacao = versions.filter(
    (v) => v.evaluation === null || v.evaluation === undefined).length;
  return `${versions.length} versão(ões). ${semAvaliacao} sem avaliação.`;
}

// A concordância ao vivo: SÓ o que /api/ml-anomalies já devolve (D-10). Nada
// é recalculado no browser para além da divisão agree/total — as contagens
// vêm todas da rota, calculadas pelo mesmo motor que corre a deteção.
//
// Devolve {state, html} com state em "ok" | "sem_dados":
//   - resposta ausente, `total` não numérico ou `total === 0` ⇒ "sem_dados"
//     (nunca "0,0 %": 0 ÷ 0 não é concordância, é falta de amostra);
//   - `alerts_truncated === true` acrescenta o aviso de truncagem e NUNCA
//     um valor diferente — o valor continua a ser agree_count/total.
function mleBuildLiveAgreement(mlReport) {
  const semDados = {
    state: "sem_dados",
    html: htmlT`<div class="empty-state">${MLE_LIVE_SEM_DADOS}</div>`,
  };
  if (!mlReport || typeof mlReport !== "object" || Array.isArray(mlReport)) return semDados;
  const total = mleNumero(mlReport.total);
  const concordes = mleNumero(mlReport.agree_count);
  if (total === null || concordes === null || total <= 0) return semDados;

  const linhas = [
    mleMetrica("Concordância", mlePercent(concordes / total)),
    mleMetrica("Eventos", mleContagem(mlReport.total)),
    mleMetrica("Marcados pelo ML", mleContagem(mlReport.ml_anomalies_count)),
    mleMetrica("Marcados pelas regras", mleContagem(mlReport.rule_flagged_count)),
    mleMetrica("Divergentes", mleContagem(mlReport.diverge_count)),
    mleMetrica("Modelo que mediu", mleLiveModelText(mlReport)),
  ];
  if (mlReport.alerts_truncated === true) {
    linhas.push(htmlT`<div class="mle-warning">${MLE_LIVE_TRUNCADO}</div>`);
  }
  return { state: "ok", html: htmlT`${linhas.map((l, i) => htmlT`${i ? " " : ""}${l}`)}` };
}

// Um ERRO no pedido à concordância nunca é desenhado como "Sem dados" (D-10):
// o `detail` da resposta entra só como CHAVE de lookup — o texto de exceção do
// Indexer nunca chega ao DOM (T-02-23). Os códigos do registo (D-06) são
// traduzidos por mlmErrorText; os genéricos de HTTP têm uma frase própria,
// porque a do registo ("não foi possível ler a pasta de modelos") mentiria
// aqui.
const MLE_LIVE_ERROR_TEXT = {
  http_502: "O Wazuh Indexer não respondeu — a concordância ao vivo não pôde ser calculada. "
    + "Confirma que a VM do laboratório está ligada (o detalhe da falha fica no backend.log).",
  http_503: "O modelo de deteção não está carregado no backend, ou o registo recusou a versão "
    + "ativa. Retoma o modelo com 'python model_registry.py adopt' em scripts/ e reinicia o "
    + "backend.",
  http_500: "O backend deu um erro interno ao calcular a concordância. Olha no backend.log.",
};

function mleLiveErrorMessage(code) {
  if (typeof code === "string" && Object.prototype.hasOwnProperty.call(MLE_LIVE_ERROR_TEXT, code)) {
    return MLE_LIVE_ERROR_TEXT[code];
  }
  return mlmErrorText(code);
}

function mleLiveErrorHtml(code) {
  return htmlT`<div class="empty-state mle-live-error">${mleLiveErrorMessage(code)}</div>`;
}

// ======================= camada DOM (só via mleInit) ========================

let mleEvalTab = null;
let mleEvalWasShown = false;
let mleLoading = false;
let mleLoadingLive = false;
let mleLastReport = null;

// Pedido próprio (nome próprio, `mlmRequest` é de ml_models.js): a resposta é
// a mesma, mas o ciclo de dados desta aba é independente — ml_models.js só
// redesenha a aba Models.
async function mleRequest(path) {
  return mlmApiCall(path);
}

// A janela escolhida. O select só oferece 1/24/72/168 (o ge=1, le=168 da
// rota), mas o valor lido ainda é validado: um select ausente ou adulterado
// cai no default em vez de fazer um pedido que a rota recusa com 422.
function mleLiveHours() {
  const select = document.getElementById("mle-live-hours");
  const valor = Number(select && select.value);
  if (!Number.isInteger(valor) || valor < 1 || valor > 168) return 24;
  return valor;
}

// Um pedido só ao bloco ao vivo — é o que o change do select chama, sem
// tocar na tabela de versões (que não muda quando muda a janela).
async function mleRefreshLive() {
  if (mleLoadingLive) return;
  const corpo = document.getElementById("mle-live-body");
  const aviso = document.getElementById("mle-live-notice");
  if (!corpo || !aviso) return;
  mleLoadingLive = true;
  const horas = mleLiveHours();
  sttShowLoading(corpo, "A carregar a concordância ao vivo…");
  try {
    const relatorio = await mleRequest(`/api/ml-anomalies?hours=${horas}`);
    const resultado = mleBuildLiveAgreement(relatorio);
    htmRender(corpo, resultado.html);
    aviso.textContent = resultado.state === "sem_dados"
      ? `Janela de ${horas} h: ${MLE_LIVE_SEM_DADOS}`
      : `Janela de ${horas} h: o ML e as regras comparados em cada evento processado.`;
  } catch (err) {
    // Um erro NUNCA é desenhado como "Sem dados": a diferença entre "não há
    // eventos na janela" e "o Indexer não respondeu" é toda a informação.
    sttShowError(corpo, mleLiveErrorMessage(err.message));
    aviso.textContent = "Não foi possível ler a concordância ao vivo: " + mleLiveErrorMessage(err.message);
  } finally {
    mleLoadingLive = false;
  }
}

async function mleRefresh() {
  if (mleLoading) return;
  mleLoading = true;
  if (!mleLastReport) mlmShowTableState(document.getElementById("mlm-eval-body"), MLE_COLUNAS, "loading", "A carregar as avaliações…");
  try {
    const report = await mleRequest("/api/ml/models");
    renderPanelError("#ml-evaluation-panel", "");
    mleLastReport = report;
    mleRenderEvaluation(report);
  } catch (err) {
    // O `detail` da resposta nunca entra no DOM: entra como chave de lookup
    // em mlmErrorText e sai já traduzido.
    const texto = mlmErrorText(err.message);
    mleLastReport = null;
    renderPanelError("#ml-evaluation-panel", "Não foi possível carregar as avaliações: " + texto);
    mlmShowTableState(document.getElementById("mlm-eval-body"), MLE_COLUNAS, "error", texto);
  } finally {
    mleLoading = false;
  }
  // Os dois pedidos são independentes: um registo ilegível não apaga a
  // concordância ao vivo, e um Indexer em baixo não apaga a tabela.
  mleRefreshLive();
}

function mleRenderCompare(report) {
  const versions = (report && report.versions) || [];
  const pares = mleComparePairs(versions);
  const corpo = document.getElementById("mle-compare-body");
  const aviso = document.getElementById("mle-compare-notice");
  if (!corpo || !aviso) return;

  aviso.textContent = mleCompareNoticeText((report && report.versions) || []);

  if (!pares.length) {
    htmRender(corpo, htmlT`<tr><td colspan="8" class="empty-state">Sem pares para comparar — cada versão precisa de avaliação, e o par exige números consecutivos (vN vs vN−1).</td></tr>`);
    return;
  }

  const linhas = mleCompareRows(mleComparePairs((report && report.versions) || []));
  htmRender(corpo, htmlT`${linhas.map((l) =>
    htmlT`<tr>
      <td>${l.versaoNova}</td>
      <td>${l.versaoVelha}</td>
      <td>${l.lado === "ml" ? "ML" : "Regras"}</td>
      <td>${l.metrica === "precision" ? "Precisão" : l.metrica === "recall" ? "Recall" : "F1"}</td>
      <td>${l.antes}</td>
      <td>${l.depois}</td>
      <td>${l.delta}</td>
      <td class="${l.veredictoClass}">${l.veredicto}</td>
    </tr>`
  )}`);
}

function mleRenderFeatureStats(report) {
  const versions = (report && report.versions) || [];
  const container = document.getElementById("mle-feature-stats");
  if (!container) return;
  const avisos = [];
  for (const entry of (report && report.versions) || []) {
    const notice = mleFeatureStatsNotice(entry);
    if (notice) {
      avisos.push(htmlT`<div class="mle-warning" style="margin-bottom: 8px;">${entry.id || entry.label}: ${notice}</div>`);
    }
  }
  if (!avisos.length) {
    sttShowEmpty(container, "Nenhuma feature_stats disponível nas versões avaliadas.");
  } else {
    htmRender(container, htmlT`${avisos}`);
  }
}

function mleRenderEvaluation(report) {
  htmRender(document.getElementById("mlm-eval-body"), mleBuildEvalRows(report));
  document.getElementById("mlm-eval-notice").textContent = mleEvalNoticeText(report);
  mleRenderCompare(report);
  mleRenderFeatureStats(report);
}

// Mesma regra que mlmIsShown em ml_models.js: aba ativa e página visível.
function mleIsShown(tab) {
  return tab.classList.contains("active") && document.visibilityState === "visible";
}

// Recarrega SEMPRE que a aba passa de escondida a visível, como ml_models.js
// faz com a Models: um `evaluate` pode ter corrido entretanto e o backend
// só passa a usar a versão nova depois de reiniciado.
function mleOnTabChange() {
  const shown = mleEvalTab ? mleIsShown(mleEvalTab) : false;
  if (shown && !mleEvalWasShown) mleRefresh();
  mleEvalWasShown = shown;
}

function mleInit() {
  mleEvalTab = document.getElementById("tab-ml-evaluation");
  if (mleEvalTab) {
    const observer = new MutationObserver(mleOnTabChange);
    observer.observe(mleEvalTab, { attributes: true, attributeFilter: ["class"] });
  }
  document.addEventListener("visibilitychange", mleOnTabChange);
  const reload = document.getElementById("mlm-eval-reload");
  if (reload) reload.addEventListener("click", () => mleRefresh());
  // Mudar a janela recarrega SÓ o bloco ao vivo: a avaliação por versão não
  // depende da janela, por isso não justifica um pedido ao registo.
  const janela = document.getElementById("mle-live-hours");
  if (janela) janela.addEventListener("change", () => mleRefreshLive());
  // Deep link #ml-evaluation: o applyHash de app.js corre antes deste script.
  mleOnTabChange();
}

if (typeof document !== "undefined") { mleInit(); }