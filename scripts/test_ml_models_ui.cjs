"use strict";
// Teste Node da camada pura de ml_models.js E de ml_evaluation.js (marco R9).
// Corre os dois ficheiros REAIS num contexto node:vm sem document/window/fetch
// e exercita só os helpers que devolvem strings — a camada DOM não é testada
// aqui, é o que o <human-check> no browser de cada fase cobre.
//
// Os dois ficheiros são carregados no MESMO contexto, porque em produção
// partilham um só escopo global: um identificador repetido entre eles
// rebentaria o script inteiro no browser (D-09/Pitfall 9).
//
// Os relatórios de report_v1.json / report_empty.json / report_legacy.json /
// report_evaluated.json são reais: vêm do wrapper test_ml_models_ui.py, que os
// obtém de GET /api/ml/models com TestClient sobre um registo temporário — e
// no caso do report_evaluated.json, depois de correr o `evaluate` a sério. Por
// isso este ficheiro nunca é corrido sozinho (sem argumentos sai com
// [FALHOU]).
//
// Uso: node test_ml_models_ui.cjs <pasta-com-os-json>

const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const failures = [];

function check(label, condition) {
  console.log(`[${condition ? "OK   " : "FALHOU"}] ${label}`);
  if (!condition) failures.push(label);
}

// Cópia exacta do corpo de escapeHtml em app.js (linhas 40-48). O contexto
// do vm tem de trazer os globais que nenhum dos dois ficheiros redeclara.
function escapeHtml(value) {
  if (value === null || value === undefined) return "";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const D06_CODES = [
  "invalid_version_id",
  "active_not_found",
  "metadata_missing",
  "metadata_invalid",
  "artifact_missing",
  "hash_mismatch",
  "already_adopted",
  "no_legacy_model",
  "registry_unavailable",
];

// --- carregar os ficheiros reais sem DOM ---------------------------------------

const mlSource = fs.readFileSync(path.join(__dirname, "..", "ml_models.js"), "utf8");
const mleSource = fs.readFileSync(path.join(__dirname, "..", "ml_evaluation.js"), "utf8");
// Transporte único (W2): mlmPost/mlmRequest passam por apiRequest de api.js.
const apiSource = fs.readFileSync(path.join(__dirname, "..", "api.js"), "utf8");
const apiGlobals = { setTimeout, clearTimeout, AbortController, JSON, Promise };
function loadApi(ctx) { vm.runInContext(apiSource, ctx, { filename: "api.js" }); }
const htmlSource = fs.readFileSync(path.join(__dirname, "..", "html.js"), "utf8");
const ctx = vm.createContext({ escapeHtml, console });
try {
  vm.runInContext(htmlSource, ctx, { filename: "html.js" });
  vm.runInContext(mlSource, ctx, { filename: "ml_models.js" });
  vm.runInContext(mleSource, ctx, { filename: "ml_evaluation.js" });
} catch (err) {
  console.log("[FALHOU] ml_models.js e ml_evaluation.js carregam no MESMO contexto sem DOM "
    + "(nenhuma linha de topo toca em document, nenhum identificador colide)");
  console.log(String(err && err.stack ? err.stack : err));
  process.exit(1);
}
check("ml_models.js e ml_evaluation.js carregam no MESMO contexto sem DOM "
  + "(nenhuma linha de topo toca em document, nenhum identificador colide)", true);

// Os construtores de HTML devolvem SafeHtml (htmlT, de html.js); os testes
// inspecionam o texto final, por isso desembrulham-no (a escapagem já foi feita
// na interpolação do htmlT, que é exatamente o que se verifica).
function unsafe(valor) {
  if (valor && valor.htmSafe === true) return String(valor);
  if (valor && typeof valor === "object" && !Array.isArray(valor)) {
    const copia = {};
    for (const k of Object.keys(valor)) copia[k] = unsafe(valor[k]);
    return copia;
  }
  return valor;
}
function desembrulha(fn) { return (...args) => unsafe(fn(...args)); }

const helpers = vm.runInContext(
  "({ MLM_ERROR_TEXT, MLM_GENERIC_ERROR, mlmErrorText, mlmCodeFromResponse, mlmCell,"
  + "   mlmStatusText, mlmFormatDate, mlmOriginHtml, mlmTrainedAtText,"
  + "   mlmEntryKey, mlmFindEntryIndex, mlmRowIndexFromEvent, mlmIsSelectKey,"
  + "   mlmHandleRowKey, mlmBuildDetail,"
  + "   mlmBuildModelsRows, mlmModelsNoticeText })",
  ctx
);
const {
  MLM_ERROR_TEXT,
  MLM_GENERIC_ERROR,
  mlmErrorText,
  mlmCodeFromResponse,
  mlmCell,
  mlmStatusText,
  mlmFormatDate,
  mlmTrainedAtText,
  mlmEntryKey,
  mlmFindEntryIndex,
  mlmRowIndexFromEvent,
  mlmIsSelectKey,
  mlmHandleRowKey,
  mlmModelsNoticeText,
} = helpers;
const mlmOriginHtml = desembrulha(helpers.mlmOriginHtml);
const mlmBuildDetail = desembrulha(helpers.mlmBuildDetail);
const mlmBuildModelsRows = desembrulha(helpers.mlmBuildModelsRows);

// Os helpers da Evaluation vivem agora em ml_evaluation.js (D-09): saem do
// MESMO contexto, depois de o segundo ficheiro ter carregado.
const helpersEval = vm.runInContext(
  "({ mleEmptyState, mlePercent, mleMetricCell, mleBuildEvalRows, mleEvalNoticeText,"
  + "   mleOriginHtml, mleSmallSampleNotice, mleBuildLiveAgreement, mleLiveErrorHtml,"
  + "   mleLiveErrorMessage, MLE_LIVE_SEM_DADOS, MLE_LIVE_TRUNCADO, MLE_ORIGIN_AVISO,"
  + "   mleFeatureStatsNotice, mleLiveModelText, mleComparePairs, mleCompareRows,"
  + "   mleCompareNoticeText, mleVersionNumber, mleNumeradas, mleDeltaPontos,"
  + "   mleDeltaTexto, mleVeredicto })",
  ctx
);
const {
  mlePercent,
  mleEvalNoticeText,
  mleSmallSampleNotice,
  mleLiveErrorMessage,
  MLE_LIVE_SEM_DADOS,
  MLE_LIVE_TRUNCADO,
  MLE_ORIGIN_AVISO,
  mleFeatureStatsNotice,
  mleLiveModelText,
  mleComparePairs,
  mleCompareRows,
  mleCompareNoticeText,
  mleVersionNumber,
  mleNumeradas,
  mleDeltaPontos,
  mleDeltaTexto,
  mleVeredicto,
} = helpersEval;
const mleEmptyState = desembrulha(helpersEval.mleEmptyState);
const mleMetricCell = desembrulha(helpersEval.mleMetricCell);
const mleBuildEvalRows = desembrulha(helpersEval.mleBuildEvalRows);
const mleOriginHtml = desembrulha(helpersEval.mleOriginHtml);
const mleBuildLiveAgreement = desembrulha(helpersEval.mleBuildLiveAgreement);
const mleLiveErrorHtml = desembrulha(helpersEval.mleLiveErrorHtml);

// --- relatórios reais gerados pelo wrapper ------------------------------------

const fixturesDir = process.argv[2];
if (!fixturesDir) {
  console.log("[FALHOU] pasta de fixtures em falta — corre via test_ml_models_ui.py");
  process.exit(1);
}
check("pasta de fixtures recebida", true);
const reportV1 = JSON.parse(fs.readFileSync(path.join(fixturesDir, "report_v1.json"), "utf8"));
const reportLegacy = JSON.parse(fs.readFileSync(path.join(fixturesDir, "report_legacy.json"), "utf8"));
const reportEmpty = JSON.parse(fs.readFileSync(path.join(fixturesDir, "report_empty.json"), "utf8"));
const reportEvaluated = JSON.parse(
  fs.readFileSync(path.join(fixturesDir, "report_evaluated.json"), "utf8"));
const evaluateStdout = fs.readFileSync(path.join(fixturesDir, "evaluate_stdout.txt"), "utf8");

// As três janelas de /api/ml-anomalies, reais (o Indexer mockado, no wrapper).
// Uma falta aqui é um wrapper desatualizado, não um teste a falhar por outra
// coisa: mensagem explícita e saída 1, para não se testar um ficheiro vazio.
const LIVE_FIXTURES = ["ml_report_ok.json", "ml_report_vazio.json", "ml_report_truncado.json"];
for (const nome of LIVE_FIXTURES) {
  const caminho = path.join(fixturesDir, nome);
  if (!fs.existsSync(caminho)) {
    console.log(`[FALHOU] fixture ${nome} em falta — regenera com test_ml_models_ui.py`);
    process.exit(1);
  }
}
check("as três janelas de /api/ml-anomalies chegaram do wrapper", true);
const mlReportOk = JSON.parse(fs.readFileSync(path.join(fixturesDir, "ml_report_ok.json"), "utf8"));
const mlReportVazio = JSON.parse(
  fs.readFileSync(path.join(fixturesDir, "ml_report_vazio.json"), "utf8"));
const mlReportTruncado = JSON.parse(
  fs.readFileSync(path.join(fixturesDir, "ml_report_truncado.json"), "utf8"));

// --- Fixtures de treino (R10, 11-03) -----------------------------------------
//
// report_treinado.json: resposta de GET /api/ml/models depois de um treino real
// pelo POST /api/ml/train, com dataset.feature_stats no metadata.json.
// Só existe se o backend tiver gravado feature_stats; caso contrário o wrapper
// não o escreve e os casos abaixo usam o ramo fail-closed (sem números).
let reportTreinado = null;
try {
  const caminhoTreinado = path.join(fixturesDir, "report_treinado.json");
  if (fs.existsSync(caminhoTreinado)) {
    reportTreinado = JSON.parse(fs.readFileSync(caminhoTreinado, "utf8"));
    check("report_treinado.json carregado do wrapper (com feature_stats)", true);
  } else {
    check("report_treinado.json não existe (sem feature_stats — ramo fail-closed)", true);
  }
} catch (e) {
  check("report_treinado.json falhou ao carregar", false);
}

// --- mlmErrorText: cada código de D-06 traduzido, nunca em bruto -------------

check("MLM_ERROR_TEXT tem os 10 códigos (9 de D-06 + unauthorized)",
  D06_CODES.concat("unauthorized").every((c) => typeof MLM_ERROR_TEXT[c] === "string"));

const seen = new Set();
for (const code of D06_CODES.concat("unauthorized")) {
  const text = mlmErrorText(code);
  check(`${code}: mensagem não vazia`, typeof text === "string" && text.trim().length > 0);
  check(`${code}: a mensagem não é a genérica`, text !== MLM_GENERIC_ERROR);
  check(`${code}: a mensagem não repete o código`, text !== code && !text.includes(code));
  seen.add(text);
}
check("cada código tem a sua própria mensagem", seen.size === D06_CODES.length + 1);
check("código desconhecido -> mensagem genérica", mlmErrorText("codigo_inventado") === MLM_GENERIC_ERROR);
check("código ausente -> mensagem genérica", mlmErrorText(undefined) === MLM_GENERIC_ERROR);
check("código que é uma chave herdada -> mensagem genérica", mlmErrorText("constructor") === MLM_GENERIC_ERROR);

// --- mlmCodeFromResponse: o detail só serve de chave de lookup ---------------

check("401 com detail de código -> unauthorized",
  mlmCodeFromResponse(401, { detail: "hash_mismatch" }) === "unauthorized");
check("503 com detail de código -> o próprio código",
  mlmCodeFromResponse(503, { detail: "hash_mismatch" }) === "hash_mismatch");
check("503 com detail que não é um código -> http_503",
  mlmCodeFromResponse(503, { detail: "<img src=x>" }) === "http_503");
check("500 sem corpo -> http_500", mlmCodeFromResponse(500, null) === "http_500");
check("503 com detail que é objeto -> http_503",
  mlmCodeFromResponse(503, { detail: { a: 1 } }) === "http_503");

// --- mlmCell -----------------------------------------------------------------

check("mlmCell(null) -> desconhecido", mlmCell(null) === "desconhecido");
check("mlmCell(undefined) -> desconhecido", mlmCell(undefined) === "desconhecido");
check("mlmCell('') -> desconhecido", mlmCell("") === "desconhecido");
check("mlmCell devolve texto simples (o escape é do htmlT, na interpolação)", mlmCell("<b>") === "<b>");

// --- fixtures inline segundo o contrato do SKELETON.md -----------------------
//
// Nada aqui é inventado: são as duas entradas do contrato de
// GET /api/ml/models (uma versionada completa, a do legado com kind/status
// no_metadata e `files` com size_bytes/modified_at).

const SHA_MODEL = "a".repeat(64);
const SHA_SCALER = "b".repeat(64);

function versioned(over) {
  return Object.assign({
    id: "v1",
    kind: "versioned",
    label: "v1",
    active: true,
    status: "ok",
    error_code: null,
    metadata: {
      schema_version: 1,
      version: "v1",
      origin: "adopted",
      adopted: true,
      created_at: "2026-10-09T21:00:00+00:00",
      trained_at: "2026-09-14T15:40:00+00:00",
      trained_at_estimated: true,
      model_type: "IsolationForest",
      parameters: null,
      dataset: { name: null, size: null, attacks: null, synthetic: null },
      library_versions: null,
      artifacts: {
        "isolation_forest.pkl": { sha256: SHA_MODEL, size_bytes: 539673 },
        "scaler.pkl": { sha256: SHA_SCALER, size_bytes: 767 },
      },
    },
    evaluation: null,
  }, over);
}

function legacy(over) {
  return Object.assign({
    id: null,
    kind: "legacy",
    label: "legado, sem metadados",
    active: true,
    status: "no_metadata",
    error_code: null,
    metadata: null,
    evaluation: null,
    files: {
      "isolation_forest.pkl": { size_bytes: 539673, modified_at: "2026-09-14T15:40:00+00:00" },
      "scaler.pkl": { size_bytes: 767, modified_at: "2026-09-14T15:40:00+00:00" },
    },
  }, over);
}

// --- mlmStatusText: os 8 estados + o desconhecido ----------------------------

check("mlmStatusText: 'ok' diz que o SHA-256 foi verificado",
  mlmStatusText({ status: "ok" }) === "Íntegra (SHA-256 verificado)");
check("mlmStatusText: 'no_metadata' diz que carrega sem verificação",
  mlmStatusText({ status: "no_metadata" })
    === "Sem metadados nem hash — carrega sem verificação até ser adotado");

const CODES_UI = [
  "hash_mismatch",
  "artifact_missing",
  "metadata_missing",
  "metadata_invalid",
  "invalid_version_id",
  "registry_unavailable",
];
for (const code of CODES_UI) {
  check(`mlmStatusText: ${code} dá exactamente a mensagem de MLM_ERROR_TEXT`,
    mlmStatusText({ status: code, error_code: code }) === MLM_ERROR_TEXT[code]);
}
check("mlmStatusText: código inventado cai na mensagem genérica",
  mlmStatusText({ status: "codigo_inventado", error_code: "codigo_inventado" })
    === MLM_GENERIC_ERROR);
check("mlmStatusText: estado sem código não dá a genérica (o legado carrega)",
  mlmStatusText({ status: "no_metadata", error_code: null }) !== MLM_GENERIC_ERROR);

// --- mlmFormatDate ------------------------------------------------------------

check("mlmFormatDate formata uma data ISO em pt-PT",
  mlmFormatDate("2026-09-14T15:40:00+00:00").includes("2026"));
check("mlmFormatDate sem data -> desconhecido", mlmFormatDate(null) === "desconhecido");
check("mlmFormatDate(undefined) -> desconhecido", mlmFormatDate(undefined) === "desconhecido");
check("mlmFormatDate que não é data devolve o texto como veio",
  mlmFormatDate("nao-e-data") === "nao-e-data");
check("mlmFormatDate devolve texto simples (o escape é do htmlT)",
  mlmFormatDate("<b>x") === "<b>x");

// --- mlmOriginHtml / mlmTrainedAtText -----------------------------------------

check("mlmOriginHtml: metadata.adopted true -> badge 'adotado'",
  mlmOriginHtml(versioned()).includes("mlm-badge-adopted")
  && mlmOriginHtml(versioned()).includes("adotado"));
check("mlmOriginHtml: origin 'trained' -> 'treinado'",
  mlmOriginHtml(versioned({ metadata: Object.assign(versioned().metadata, { adopted: false, origin: "trained" }) }))
    .includes("treinado"));
check("mlmOriginHtml: legado -> 'legado'", mlmOriginHtml(legacy()).includes("mlm-badge-legacy"));
check("mlmOriginHtml: sem metadados -> desconhecido",
  mlmOriginHtml(versioned({ metadata: null })).includes("desconhecido"));

const metaBase = versioned().metadata;
check("mlmCell: o htmlT escapa o valor", String(helpers.mlmBuildDetail(versioned({ metadata: Object.assign({}, versioned().metadata, { model_type: "<b>" }) })).metaHtml).includes("&lt;b&gt;"));
const treadoEstimada = mlmTrainedAtText(versioned());
const treadoReal = mlmTrainedAtText(versioned({
  metadata: Object.assign({}, metaBase, { trained_at_estimated: false }),
}));
check("mlmTrainedAtText: data estimada fica marcada como tal", treadoEstimada.includes("(estimada)"));
check("mlmTrainedAtText: data real não é marcada como estimada", !treadoReal.includes("(estimada)"));
check("mlmTrainedAtText: ambos mostram a data", treadoEstimada.includes("2026") && treadoReal.includes("2026"));
check("mlmTrainedAtText: sem data de treino -> desconhecido",
  mlmTrainedAtText(versioned({ metadata: Object.assign({}, metaBase, { trained_at: null }) }))
    === "desconhecido");
check("mlmTrainedAtText: legado usa a data do ficheiro",
  mlmTrainedAtText(legacy()).includes("(data do ficheiro)"));

// --- linhas: uma por estado de erro, com mensagem PT e nunca o código --------

const entriesErro = CODES_UI.map((code, i) => versioned({
  id: `v${i + 1}`,
  label: `v${i + 1}`,
  active: false,
  status: code,
  error_code: code,
  metadata: (code === "metadata_missing" || code === "metadata_invalid") ? null : metaBase,
}));
const rowsErro = mlmBuildModelsRows({
  active: null, active_error: null, loaded: null, total: entriesErro.length, versions: entriesErro,
});
for (const code of CODES_UI) {
  check(`${code}: a linha mostra o badge de erro e a mensagem PT`,
    rowsErro.includes("mlm-badge-error") && rowsErro.includes(escapeHtml(MLM_ERROR_TEXT[code])));
  check(`${code}: o código em bruto nunca chega ao HTML`, !rowsErro.includes(code));
}

// --- a linha do legado (REG-02) ----------------------------------------------

const rowsLegacyInline = mlmBuildModelsRows({
  active: "legacy", active_error: null, loaded: "legacy", total: 1, versions: [legacy()],
});
check("legado (fixture do contrato): badge 'legado, sem metadados'",
  rowsLegacyInline.includes("mlm-badge-legacy")
  && rowsLegacyInline.includes("legado, sem metadados"));
check("legado (fixture do contrato): badge 'ativa'", rowsLegacyInline.includes("mlm-badge-active"));
check("legado (fixture do contrato): a data vem do ficheiro",
  rowsLegacyInline.includes("(data do ficheiro)"));
check("legado (fixture do contrato): estado diz que carrega sem verificação",
  rowsLegacyInline.includes("carrega sem verificação"));
check("legado (fixture do contrato): sem avaliação", rowsLegacyInline.includes("Sem avaliação"));
check("legado (fixture do contrato): não é pintado como erro",
  !rowsLegacyInline.includes("mlm-badge-error"));

// --- linhas selecionáveis (seleção em detalhe é da Task 2) --------------------

const rowsTres = mlmBuildModelsRows({
  versions: [
    versioned({ id: "v3", label: "v3" }),
    versioned({ id: "v2", label: "v2", active: false }),
    legacy({ active: false }),
  ],
});
const indices = (rowsTres.match(/data-index="(\d+)"/g) || []).map((s) => s.slice(12, -1));
check("cada linha leva data-index com a sua posição",
  JSON.stringify(indices) === JSON.stringify(["0", "1", "2"]));
check("cada linha é clicável", (rowsTres.match(/class="atk-row"/g) || []).length === 3);
check("cada linha é focável pelo teclado", (rowsTres.match(/tabindex="0"/g) || []).length === 3);

// --- XSS em todos os campos dinâmicos da linha -------------------------------

const rowsXss2 = mlmBuildModelsRows({
  versions: [{
    id: null,
    kind: "legacy",
    label: "<script>alert(1)</script>",
    active: false,
    status: "no_metadata",
    error_code: null,
    metadata: null,
    evaluation: null,
    files: {
      "isolation_forest.pkl": { size_bytes: 1, modified_at: "<img src=x onerror=1>" },
      "scaler.pkl": { size_bytes: 1, modified_at: "<img src=x onerror=1>" },
    },
  }],
});
check("XSS: <script> no label nunca chega ao DOM", !rowsXss2.includes("<script"));
check("XSS: <img> na data do ficheiro nunca chega ao DOM", !rowsXss2.includes("<img"));
check("XSS: escapado continua legível como texto", rowsXss2.includes("&lt;script"));

// --- os cinco avisos ----------------------------------------------------------

const avisoActiveError = mlmModelsNoticeText({
  active: null, active_error: "invalid_version_id", loaded: null, total: 0, versions: [],
});
check("aviso: ACTIVE inválido traduz o código e aponta para models/ACTIVE",
  avisoActiveError.includes(MLM_ERROR_TEXT.invalid_version_id)
  && avisoActiveError.includes("models/ACTIVE"));

const avisoAtivoLegado = mlmModelsNoticeText({
  active: "legacy", active_error: null, loaded: "legacy", total: 1, versions: [legacy()],
});
check("aviso: com o legado ativo sugere o adopt",
  avisoAtivoLegado.includes("python model_registry.py adopt"));

const avisoSemAtiva = mlmModelsNoticeText({
  active: null, active_error: null, loaded: null, total: 1, versions: [versioned()],
});
check("aviso: sem versão ativa diz o que fazer (adopt interrompido)",
  avisoSemAtiva.includes("Nenhuma versão ativa") && avisoSemAtiva.includes("volta a correr"));

const avisoLoadedDiff = mlmModelsNoticeText({
  active: "v1", active_error: null, loaded: "legacy", total: 2,
  versions: [versioned(), legacy({ active: false })],
});
check("aviso: loaded != active manda reiniciar o backend e diz os dois nomes (D-02)",
  avisoLoadedDiff.includes("reinicia o backend")
  && avisoLoadedDiff.includes("«legacy»") && avisoLoadedDiff.includes("«v1»"));

const avisoTudoCerto = mlmModelsNoticeText({
  active: "v1", active_error: null, loaded: "v1", total: 1, versions: [versioned()],
});
check("aviso: loaded == active não pede para reiniciar",
  !avisoTudoCerto.includes("reinicia o backend"));

const avisoSemLoaded = mlmModelsNoticeText({
  active: "v1", active_error: null, loaded: null, total: 1, versions: [versioned()],
});
check("aviso: sem modelo carregado diz que ainda não carregou",
  avisoSemLoaded.includes("ainda não carregou"));

check("aviso: conta sempre as versões registadas",
  avisoTudoCerto.includes("1 versão(ões) registada(s)."));

// --- painel de detalhe -------------------------------------------------------

const META_BASE = versioned().metadata;

const entryCompleta = versioned({
  metadata: Object.assign({}, META_BASE, {
    parameters: { n_estimators: 100 },
    library_versions: { "scikit-learn": "1.5.2" },
    dataset: { name: "lab", size: 120, attacks: 7, synthetic: true },
  }),
});
const detalheCompleto = mlmBuildDetail(entryCompleta);
check("detalhe: o título é o id da versão", detalheCompleto.title === "v1");
check("detalhe: o SHA-256 do modelo vai dentro de <code>",
  detalheCompleto.artifactsHtml.includes("<code>" + SHA_MODEL + "</code>"));
check("detalhe: o SHA-256 do scaler vai dentro de <code>",
  detalheCompleto.artifactsHtml.includes("<code>" + SHA_SCALER + "</code>"));
check("detalhe: o tamanho do modelo aparece em bytes",
  detalheCompleto.artifactsHtml.includes("539673 bytes"));
check("detalhe: o tamanho do scaler aparece em bytes",
  detalheCompleto.artifactsHtml.includes("767 bytes"));
check("detalhe: os parâmetros aparecem como 'chave = valor'",
  detalheCompleto.paramsHtml.includes("n_estimators = 100"));
check("detalhe: as versões das bibliotecas aparecem",
  detalheCompleto.metaHtml.includes("scikit-learn=1.5.2"));
check("detalhe: a data de treino estimada é marcada", detalheCompleto.metaHtml.includes("(estimada)"));
check("detalhe: o nome do dataset", detalheCompleto.datasetHtml.includes("lab"));
check("detalhe: o tamanho do dataset", detalheCompleto.datasetHtml.includes("120"));
check("detalhe: o número de ataques do dataset", detalheCompleto.datasetHtml.includes("7"));
check("detalhe: dataset sintético -> Sim", detalheCompleto.datasetHtml.includes("Sim"));
check("detalhe: sem avaliação nesta fase (D-05)", detalheCompleto.evalText === "Sem avaliação");

// Uma versão adotada real: parameters/library_versions/dataset são null
// (nada é desserializado no adopt e não se inventa o dataset).
const detalheVazio = mlmBuildDetail(versioned());
check("detalhe: sem parâmetros -> desconhecido", detalheVazio.paramsHtml.includes("desconhecido"));
check("detalhe: sem versões de bibliotecas -> desconhecido",
  detalheVazio.metaHtml.includes("desconhecido"));
check("detalhe: dataset com os quatro campos null -> desconhecido quatro vezes",
  (detalheVazio.datasetHtml.match(/desconhecido/g) || []).length === 4);

const detalheLegado = mlmBuildDetail(legacy());
check("detalhe do legado: o título é o label",
  detalheLegado.title === "legado, sem metadados");
check("detalhe do legado: diz que não há hash registado",
  detalheLegado.artifactsHtml.includes("sem hash registado"));
check("detalhe do legado: tamanho do modelo",
  detalheLegado.artifactsHtml.includes("539673 bytes"));
check("detalhe do legado: tamanho do scaler",
  detalheLegado.artifactsHtml.includes("767 bytes"));
check("detalhe do legado: a data vem do ficheiro",
  detalheLegado.metaHtml.includes("(data do ficheiro)"));
check("detalhe do legado: sem parâmetros registados",
  detalheLegado.paramsHtml.includes("desconhecido"));
check("detalhe do legado: sem avaliação", detalheLegado.evalText === "Sem avaliação");

// Detalhe do legado REAL (resposta da rota com os .pkl soltos).
const legadoReal = (reportLegacy.versions || [])[0];
const detalheLegadoReal = mlmBuildDetail(legadoReal);
check("detalhe do legado real: título e estado honestos",
  detalheLegadoReal.title === "legado, sem metadados"
  && detalheLegadoReal.artifactsHtml.includes("sem hash registado"));
check("detalhe do legado real: os dois tamanhos reais aparecem",
  detalheLegadoReal.artifactsHtml.includes(`${legadoReal.files["isolation_forest.pkl"].size_bytes} bytes`)
  && detalheLegadoReal.artifactsHtml.includes(`${legadoReal.files["scaler.pkl"].size_bytes} bytes`));
check("detalhe do legado real: nenhum caminho do disco",
  !detalheLegadoReal.artifactsHtml.includes("\\") && !detalheLegadoReal.metaHtml.includes("scripts/"));

// Versão sem metadata.json utilizável: não há hashes para mostrar, mas a
// mensagem do código ainda é a acção a fazer (API-02).
const entryQuebrada = versioned({
  metadata: null, status: "metadata_invalid", error_code: "metadata_invalid",
});
const detalheQuebrado = mlmBuildDetail(entryQuebrada);
check("detalhe sem metadata.json: estado vazio com a mensagem do código",
  detalheQuebrado.artifactsHtml.includes("empty-state")
  && detalheQuebrado.artifactsHtml.includes(escapeHtml(MLM_ERROR_TEXT.metadata_invalid))
  && !detalheQuebrado.artifactsHtml.includes("metadata_invalid"));
check("detalhe sem metadata.json: o estado traduz o código também",
  detalheQuebrado.metaHtml.includes(escapeHtml(MLM_ERROR_TEXT.metadata_invalid)));

// --- XSS no detalhe ----------------------------------------------------------

const detalheXss = mlmBuildDetail(versioned({
  metadata: Object.assign({}, META_BASE, {
    parameters: { "<b>k": "<img src=x>" },
    library_versions: { "<b>k": "<img src=x>" },
    dataset: { name: "<img src=x>", size: null, attacks: null, synthetic: null },
  }),
}));
check("XSS no detalhe: chave e valor dos parâmetros escapados",
  !detalheXss.paramsHtml.includes("<b>") && !detalheXss.paramsHtml.includes("<img"));
check("XSS no detalhe: biblioteca escapada",
  !detalheXss.metaHtml.includes("<b>") && !detalheXss.metaHtml.includes("<img"));
check("XSS no detalhe: nome do dataset escapado", !detalheXss.datasetHtml.includes("<img"));

// --- chaves e selecção por índice --------------------------------------------

const RELATORIO = {
  versions: [
    versioned({ id: "v2", label: "v2" }),
    versioned({ id: "v1", label: "v1", active: false }),
    legacy({ active: false }),
  ],
};
check("mlmEntryKey: versionada dá o id", mlmEntryKey(RELATORIO.versions[0]) === "v2");
check("mlmEntryKey: o legado dá 'legacy'", mlmEntryKey(RELATORIO.versions[2]) === "legacy");
check("mlmFindEntryIndex acha a v1", mlmFindEntryIndex(RELATORIO, "v1") === 1);
check("mlmFindEntryIndex acha o legado", mlmFindEntryIndex(RELATORIO, "legacy") === 2);
check("mlmFindEntryIndex com chave ausente -> -1", mlmFindEntryIndex(RELATORIO, "v9") === -1);

// Depois de um adopt o legado deixa de estar na lista (D-03): o detalhe da
// seleção que apontava para ele tem de desaparecer, não ficar a apontar
// para a versão que ficou no mesmo lugar.
const APOS_ADOPT = { versions: [versioned({ id: "v1" })] };
check("mlmFindEntryIndex: legado depois do adopt -> -1",
  mlmFindEntryIndex(APOS_ADOPT, "legacy") === -1);

// A seleção segue a CHAVE, não a posição: um refresh que reordene a lista
// tem de continuar a mostrar a mesma versão no detalhe.
const REORDENADO = {
  versions: [legacy({ active: false }), versioned({ id: "v1" }), versioned({ id: "v2", active: false })],
};
check("mlmFindEntryIndex: a seleção acompanha uma reordenação",
  mlmFindEntryIndex(REORDENADO, "v1") === 1
  && mlmFindEntryIndex(RELATORIO, "v1") === 1);

// --- teclado: Enter e Espaço selecionam, o resto não --------------------------

function fakeEvent(key, indice) {
  const chamadas = { preventDefault: 0, onSelect: [] };
  const evento = {
    key,
    target: {
      closest(seletor) {
        if (indice === null) return null;
        return seletor === "tr[data-index]" ? { dataset: { index: String(indice) } } : null;
      },
    },
    preventDefault() { chamadas.preventDefault += 1; },
  };
  const selecionar = (i) => { chamadas.onSelect.push(i); };
  return { evento, chamadas, selecionar };
}

for (const key of ["Enter", " ", "Spacebar"]) {
  check(`mlmIsSelectKey: ${JSON.stringify(key)} é tecla de seleção`, mlmIsSelectKey({ key }) === true);
}
for (const key of ["a", "Tab", "ArrowDown", "Escape"]) {
  check(`mlmIsSelectKey: ${JSON.stringify(key)} não é tecla de seleção`, mlmIsSelectKey({ key }) === false);
}

const enter = fakeEvent("Enter", 1);
check("mlmHandleRowKey: Enter na linha 1 devolve true",
  mlmHandleRowKey(enter.evento, enter.selecionar) === true);
check("mlmHandleRowKey: Enter chama preventDefault uma vez", enter.chamadas.preventDefault === 1);
check("mlmHandleRowKey: Enter seleciona o índice 1",
  JSON.stringify(enter.chamadas.onSelect) === "[1]");

const espaco = fakeEvent(" ", 1);
check("mlmHandleRowKey: Espaço na linha 1 devolve true",
  mlmHandleRowKey(espaco.evento, espaco.selecionar) === true);
check("mlmHandleRowKey: Espaço chama preventDefault uma vez", espaco.chamadas.preventDefault === 1);
check("mlmHandleRowKey: Espaço seleciona o índice 1",
  JSON.stringify(espaco.chamadas.onSelect) === "[1]");

for (const key of ["a", "Tab"]) {
  const outra = fakeEvent(key, 1);
  check(`mlmHandleRowKey: ${JSON.stringify(key)} devolve false`,
    mlmHandleRowKey(outra.evento, outra.selecionar) === false);
  check(`mlmHandleRowKey: ${JSON.stringify(key)} não faz nada`, outra.chamadas.preventDefault === 0
    && outra.chamadas.onSelect.length === 0);
}

const semLinha = fakeEvent("Enter", null);
check("mlmHandleRowKey: Enter fora de uma linha devolve false",
  mlmHandleRowKey(semLinha.evento, semLinha.selecionar) === false);
check("mlmHandleRowKey: Enter fora de uma linha não seleciona nada",
  semLinha.chamadas.preventDefault === 0 && semLinha.chamadas.onSelect.length === 0);

const indiceLixo = fakeEvent("Enter", "abc");
check("mlmRowIndexFromEvent com data-index inválido -> -1",
  mlmRowIndexFromEvent(indiceLixo.evento) === -1);
check("mlmRowIndexFromEvent devolve a posição da linha",
  mlmRowIndexFromEvent(fakeEvent("Enter", 2).evento) === 2);
check("mlmRowIndexFromEvent sem linha -> -1",
  mlmRowIndexFromEvent(fakeEvent("Enter", null).evento) === -1);

// --- mlmBuildModelsRows sobre o relatório real ------------------------------

const rowsEmpty = mlmBuildModelsRows(reportEmpty);
check("relatório vazio: diz que ainda não há modelos registados",
  rowsEmpty.includes("Sem dados — ainda não há modelos registados."));

const rowsV1 = mlmBuildModelsRows(reportV1);
check("relatório com v1 ativa: exactamente uma linha",
  (rowsV1.match(/<tr/g) || []).length === 1);
check("relatório com v1 ativa: mostra o id da versão", rowsV1.includes("v1"));
check("relatório com v1 ativa: marca a versão ativa", rowsV1.includes("mlm-badge-active"));
check("relatório com v1 ativa: diz que ainda não há avaliação", rowsV1.includes("Sem avaliação"));

const rowsXss = mlmBuildModelsRows({
  versions: [{
    id: "<img src=x onerror=alert(1)>",
    label: "<img src=x onerror=alert(1)>",
    kind: "versioned",
    active: false,
    status: "metadata_invalid",
    error_code: "metadata_invalid",
    metadata: { origin: "<script>alert(1)</script>", trained_at: null },
    evaluation: null,
  }],
});
check("HTML numa versão nunca chega ao DOM", !rowsXss.includes("<img"));
check("HTML nos metadados nunca chega ao DOM", !rowsXss.includes("<script"));
check("HTML escapado continua visível como texto", rowsXss.includes("&lt;img"));
check("erro de uma versão traduzido pela tabela",
  rowsXss.includes("metadata.json") && !rowsXss.includes("metadata_invalid"));

// --- a entrada do legado NÃO é um erro (REG-02, 01-02) ------------------------
//
// O relatório real com só os dois .pkl soltos tem status "no_metadata" e
// error_code null: o modelo está a ser usado. Pinta-lo com o badge de erro
// (que cai no texto genérico, porque não há código) seria mentir ao analista.

const rowsLegacy = mlmBuildModelsRows(reportLegacy);
check("legado: exactamente uma linha",
  (rowsLegacy.match(/<tr/g) || []).length === 1);
check("legado: mostra o label 'legado, sem metadados'",
  rowsLegacy.includes("legado, sem metadados"));
check("legado: marcado como ativo", rowsLegacy.includes("mlm-badge-active"));
check("legado: sem badge de erro (o modelo carrega, não está avariado)",
  !rowsLegacy.includes("mlm-badge-error"));
check("legado: sem mensagem genérica de erro",
  !rowsLegacy.includes(MLM_GENERIC_ERROR));
check("legado: sem avaliação", rowsLegacy.includes("Sem avaliação"));

// --- mlmModelsNoticeText -----------------------------------------------------

const noticeV1 = mlmModelsNoticeText(reportV1);
check("aviso com v1 ativa menciona a v1", noticeV1.includes("v1"));
check("aviso sem versão ativa diz 'nenhuma'", mlmModelsNoticeText(reportEmpty).includes("nenhuma"));
check("aviso com active_error traduz o código",
  mlmModelsNoticeText({ active: null, active_error: "active_not_found", versions: [] })
    .includes(mlmErrorText("active_not_found")));

// --- Evaluation: os helpers puros de ml_evaluation.js (D-09, D-11) ------------

// Avaliação de exemplo segundo o contrato: as 14 chaves de EVALUATION_KEYS,
// como as que o `evaluate` grava e a API sub-projeta.
function avaliacao(over) {
  return Object.assign({
    evaluated_at: "2026-10-10T09:30:00+00:00",
    events_file: "eventos.json",
    attack_log: "attack_log.jsonl",
    label_window_seconds: 120,
    total_events: 35,
    attacks_in_dataset: 20,
    ml: { precision: 0.987, recall: 0.5, f1: 0.62 },
    rules: { precision: 0.875, recall: 0.4, f1: 0.33 },
    comparison: { both_flagged: 8, ml_only: 2, rules_only: 4, neither: 21 },
    min_events: 50,
    min_attacks: 10,
    small_sample: true,
    caveat: "Dataset pequeno (35 eventos, 20 ataques).",
    dataset_origin: "real",
  }, over);
}

function versaoAvaliada(id, active, ev) {
  return versioned(Object.assign({ id, label: id, active }, ev ? { evaluation: ev } : {}));
}

// mlePercent: uma percentagem pt-PT; um valor em falta NUNCA é 0 (D-10).

check("mlePercent(0.987) -> '98,7 %'", mlePercent(0.987) === "98,7 %");
check("mlePercent(1) -> '100,0 %'", mlePercent(1) === "100,0 %");
check("mlePercent(0) -> '0,0 %'", mlePercent(0) === "0,0 %");
check("mlePercent(0.5) -> '50,0 %'", mlePercent(0.5) === "50,0 %");
check("mlePercent(null) -> '—' (nunca '0 %')", mlePercent(null) === "—");
check("mlePercent(undefined) -> '—'", mlePercent(undefined) === "—");
check("mlePercent('x') -> '—' (nunca 'NaN %')", mlePercent("x") === "—");
check("mlePercent('') -> '—'", mlePercent("") === "—");
check("mlePercent(NaN) -> '—'", mlePercent(NaN) === "—");

// mleMetricCell

const celula = mleMetricCell(avaliacao().ml);
check("mleMetricCell: as três métricas em percentagem com vírgula",
  celula.includes("98,7 %") && celula.includes("50,0 %") && celula.includes("62,0 %"));
check("mleMetricCell: identifica P, R e F",
  celula.includes(">P<") && celula.includes(">R<") && celula.includes(">F<"));
check("mleMetricCell(null) -> '—'", mleMetricCell(null) === "—");
check("mleMetricCell(undefined) -> '—'", mleMetricCell(undefined) === "—");
check("mleMetricCell({}) -> três '—' e nenhum '0 %'",
  (mleMetricCell({}).match(/—/g) || []).length === 3 && !mleMetricCell({}).includes("0,0 %"));

// mleBuildEvalRows: uma linha por versão com SEIS células, e "Sem avaliação"
// é visível (EVAL-03).

const evalV1 = mleBuildEvalRows(reportV1);
check("Evaluation com v1 sem avaliação: diz 'Sem avaliação'", evalV1.includes("Sem avaliação"));
check("Evaluation com v1 sem avaliação: marca a versão ativa", evalV1.includes("mlm-badge-active"));
check("Evaluation sem versões: diz que ainda não há modelos registados",
  mleBuildEvalRows(reportEmpty).includes("Sem dados — ainda não há modelos registados."));
check("Evaluation sem versões: colspan=6", mleBuildEvalRows(reportEmpty).includes('colspan="6"'));
check("Evaluation sem versões: a linha vazia tem as seis colunas",
  mleBuildEvalRows(reportEmpty).includes('colspan="6" class="empty-state"'));
check("Evaluation sem versões: o valor 4 nunca fica no colspan",
  !mleBuildEvalRows(reportEmpty).includes('colspan="4"'));

// Seis <td> na linha da versão: Versão | Ativa | Dataset | Origem | ML | Regras.
const seisCelulas = (html, id) => {
  const linha = (html.split("<tr").find((p) => p.includes(`>${id}<`)) || "");
  return (linha.match(/<td/g) || []).length;
};
check("Evaluation: a linha da versão tem seis <td>",
  seisCelulas(mleBuildEvalRows({
    versions: [versaoAvaliada("v9", true, avaliacao())],
  }), "v9") === 6);
check("Evaluation: a coluna Dataset traz eventos e ataques",
  mleBuildEvalRows({ versions: [versaoAvaliada("v9", false, avaliacao())] })
    .includes("35 eventos") && mleBuildEvalRows({ versions: [versaoAvaliada("v9", false, avaliacao())] })
    .includes("20 ataques"));

// [INVERSÃO D-11] A Fase 1 fixava que NENHUM número era mostrado. A Fase 2
// precisa do contrário: a precisão do ML e a das regras aparecem, em
// percentagem com vírgula, e o valor cru nunca aparece. O teste foi
// invertido, não contornado nem saltado.
const evalComNumeros = mleBuildEvalRows({
  versions: [versaoAvaliada("v9", false, avaliacao())],
});
check("Evaluation com objeto: mostra a precisão do ML (D-11)",
  evalComNumeros.includes("98,7 %"));
check("Evaluation com objeto: mostra a precisão das regras (D-11)",
  evalComNumeros.includes("87,5 %"));
check("Evaluation com objeto: mostra o recall e o F1 do ML",
  evalComNumeros.includes("50,0 %") && evalComNumeros.includes("62,0 %"));
check("Evaluation com objeto: mostra o recall e o F1 das regras",
  evalComNumeros.includes("40,0 %") && evalComNumeros.includes("33,0 %"));
check("Evaluation com objeto: o valor cru (0.987) NUNCA aparece",
  !evalComNumeros.includes("0.987") && !evalComNumeros.includes("0.875"));
check("Evaluation com objeto: não volta a dizer que a apresentação chega na Fase 2",
  !evalComNumeros.includes("Fase 2"));

// Pitfall 1 — o critério 2 do ROADMAP: duas versões com avaliações DIFERENTES,
// cada linha com as SUAS métricas. É o teste que fecha esse critério.
const duasAvaliadas = mleBuildEvalRows({
  versions: [
    versaoAvaliada("v2", true, avaliacao({
      ml: { precision: 0.1111, recall: 0.2222, f1: 0.3333 },
      rules: { precision: 0.4444, recall: 0.5555, f1: 0.6666 },
    })),
    versaoAvaliada("v1", false, avaliacao()),
  ],
});
const linhaDe = (html, id) => (html.split("<tr").find((p) => p.includes(`>${id}<`)) || "");
const linhaV1 = linhaDe(duasAvaliadas, "v1");
const linhaV2 = linhaDe(duasAvaliadas, "v2");
check("Pitfall 1: a linha da v1 tem as métricas da v1",
  linhaV1.includes("98,7 %") && linhaV1.includes("87,5 %"));
check("Pitfall 1: a linha da v1 NÃO tem as métricas da v2",
  !linhaV1.includes("11,1 %") && !linhaV1.includes("44,4 %"));
check("Pitfall 1: a linha da v2 tem as métricas da v2",
  linhaV2.includes("11,1 %") && linhaV2.includes("44,4 %"));
check("Pitfall 1: a linha da v2 NÃO tem as métricas da v1",
  !linhaV2.includes("98,7 %") && !linhaV2.includes("87,5 %"));
check("Pitfall 1: a badge de ativa só aparece na linha da v2",
  linhaV1.includes("—") && linhaV2.includes("mlm-badge-active"));

// Uma versão com avaliação e outra sem, na mesma resposta.
const mista = mleBuildEvalRows({
  versions: [versaoAvaliada("v2", false, null), versaoAvaliada("v1", true, avaliacao())],
});
check("mista: a versão sem avaliação diz 'Sem avaliação'", mista.includes("Sem avaliação"));
check("mista: a linha com avaliação mostra os números",
  linhaDe(mista, "v1").includes("98,7 %"));
check("mista: a linha sem avaliação não mostra números",
  !linhaDe(mista, "v2").includes("98,7 %"));
check("mista: o id da versão aparece sempre",
  mista.includes(">v1<") && mista.includes(">v2<"));

// Tudo o que vem do metadata.json do utilizador passa por escapeHtml.
const xss = mleBuildEvalRows({
  versions: [versioned({
    id: "<img src=x onerror=alert(1)>",
    label: "<img src=x onerror=alert(1)>",
    active: false,
    status: "ok",
    error_code: null,
    metadata: null,
    evaluation: avaliacao({ caveat: "<img src=x onerror=alert(1)>", events_file: "<script>x</script>" }),
  })],
});
check("XSS na Evaluation: o id nunca chega ao DOM", !xss.includes("<img"));
check("XSS na Evaluation: escapado continua legível como texto", xss.includes("&lt;img"));

// mleEvalNoticeText

const noticeDuas = mleEvalNoticeText({
  versions: [versaoAvaliada("v1", true, avaliacao()), versaoAvaliada("v2", false, null)],
});
check("aviso da Evaluation: conta as versões", noticeDuas.includes("2 versão"));
check("aviso da Evaluation: conta as sem avaliação", noticeDuas.includes("1 sem avaliação"));
check("aviso da Evaluation: zero versões -> '0'",
  mleEvalNoticeText(reportEmpty).includes("0 versão") && mleEvalNoticeText(reportEmpty).includes("0 sem"));
check("aviso da Evaluation: com todas avaliadas -> '0 sem avaliação'",
  mleEvalNoticeText({ versions: [versaoAvaliada("v1", true, avaliacao())] }).includes("0 sem avaliação"));

// --- fecho do tracer: o que o comando mediu é o que a tabela mostra ----------
//
// O report_evaluated.json é a resposta VERDADEIRA de GET /api/ml/models a um
// registo onde `model_registry.py evaluate` foi corrido a sério (o wrapper
// gravou também o stdout do comando em evaluate_stdout.txt). A linha da v1
// tem de trazer as mesmas três percentagens de ML e as três de regras que o
// CLI imprimiu — é isto que liga as duas pontas do caminho.

const avaliacoes = ((reportEvaluated.versions || []).filter((v) => v.evaluation) || []);
check("fecho do tracer: o relatório avaliado tem pelo menos uma versão com avaliação",
  avaliacoes.length >= 1);

const linhaReal = linhaDe(mleBuildEvalRows(reportEvaluated), "v1");
function percentagensDaLinha(texto) {
  const achados = texto.match(/\d+,\d %/g) || [];
  return achados;
}
function percentagensDoCli(rotulo) {
  const linha = (evaluateStdout.split("\n").find((l) => l.trim().startsWith(rotulo)) || "");
  return percentagensDaLinha(linha);
}

const cliML = percentagensDoCli("ML");
const cliRegras = percentagensDoCli("Regras");
check("fecho do tracer: o stdout do CLI traz as três percentagens do ML",
  cliML.length === 3);
check("fecho do tracer: o stdout do CLI traz as três percentagens das regras",
  cliRegras.length === 3);
check("fecho do tracer: a linha da v1 mostra as MESMAS percentagens de ML que o CLI imprimiu",
  cliML.every((p) => linhaReal.includes(p)));
check("fecho do tracer: a linha da v1 mostra as MESMAS percentagens de regras que o CLI imprimiu",
  cliRegras.every((p) => linhaReal.includes(p)));
check("fecho do tracer: a linha da v1 não mostra nenhum valor cru do metadata.json",
  !linhaReal.includes("0.9") && !linhaReal.includes("NaN"));

// A v2 (registada sem avaliação) não pode herdar os números da v1.
const v2DoRelatorio = ((reportEvaluated.versions || []).find((v) => v.id === "v2") || null);
if (v2DoRelatorio) {
  const linhasReais = mleBuildEvalRows(reportEvaluated);
  check("fecho do tracer: a v2 sem avaliação diz 'Sem avaliação'",
    linhasReais.includes("Sem avaliação"));
  check("fecho do tracer: a linha da v2 não mostra percentagem nenhuma",
    !linhaDe(linhasReais, "v2").includes("%"));
}

// --- mleOriginHtml: a origem DECLARADA dos dados (D-06, D-08) ---------------
//
// A origem nunca é adivinhada pelo caminho nem pelo número: o backend só
// projecta "real" | "synthetic" | "unknown", e um valor fora desses três cai
// no badge cinza em vez de ser desenhado em bruto (D-08, T-02-28).

const origemReal = mleOriginHtml("real");
check("origem 'real': badge verde com 'dados reais'",
  origemReal.includes("mle-origin-real") && origemReal.includes("dados reais"));
const origemSintetica = mleOriginHtml("synthetic");
check("origem 'synthetic': badge âmbar com 'dados sintéticos'",
  origemSintetica.includes("mle-origin-synthetic") && origemSintetica.includes("dados sintéticos"));
const origemNaoDeclarada = mleOriginHtml("unknown");
check("origem 'unknown': badge cinza com 'origem não declarada'",
  origemNaoDeclarada.includes("mle-origin-unknown")
  && origemNaoDeclarada.includes("origem não declarada"));
check("origem 'unknown': o badge diz sempre o que 'não declarada' significa",
  origemNaoDeclarada.includes(MLE_ORIGIN_AVISO));
check("MLE_ORIGIN_AVISO diz que não se assume que são reais",
  MLE_ORIGIN_AVISO.includes("não foi declarada") && MLE_ORIGIN_AVISO.includes("não assumimos"));
for (const valor of [null, undefined, "", "inventada", "<img src=x onerror=alert(1)>"]) {
  const badge = mleOriginHtml(valor);
  check(`origem fora do contrato (${JSON.stringify(valor)}) -> badge cinza 'origem desconhecida'`,
    badge.includes("mle-origin-unknown") && badge.includes("origem desconhecida"));
  // A string vazia não é desenhada em bruto por definição (includes("")
  // é sempre verdadeiro), por isso o teste só vale para valores não vazios.
  if (String(valor) !== "") {
    check(`origem fora do contrato (${JSON.stringify(valor)}) nunca é desenhada em bruto`,
      !badge.includes(String(valor)));
  }
}
check("origem fora do contrato: '<img' nunca chega ao HTML",
  !mleOriginHtml("<img src=x onerror=alert(1)>").includes("<img"));

// --- mleSmallSampleNotice: os DOIS limiares nomeados (D-05) -------------------
//
// Os limiares vêm no payload (min_events/min_attacks gravados pelo motor): o
// frontend nunca os recalcula nem os adivinha. Sem small_sample === true não
// há aviso — e nunca há um número inventado.

const avisoAmostra = mleSmallSampleNotice({
  total_events: 35, attacks_in_dataset: 20, min_events: 50, min_attacks: 10, small_sample: true,
});
check("aviso de amostra pequena: traz os números reais E os dois limiares",
  ["35", "20", "50", "10"].every((n) => avisoAmostra.includes(n)));
check("aviso de amostra pequena: nomeia os dois limiares",
  avisoAmostra.includes("eventos") && avisoAmostra.includes("ataques"));
check("aviso de amostra pequena: small_sample false -> nada",
  mleSmallSampleNotice(avaliacao({ small_sample: false })) === "");
check("aviso de amostra pequena: sem avaliação -> nada",
  mleSmallSampleNotice(null) === "" && mleSmallSampleNotice(undefined) === "");
check("aviso de amostra pequena: payload sem chaves -> nada (nunca inventa)",
  mleSmallSampleNotice({}) === "");
const avisoSemLimiares = mleSmallSampleNotice({
  total_events: 35, attacks_in_dataset: 2, small_sample: true,
});
check("aviso de amostra pequena: limiar em falta -> '—', não um número inventado",
  avisoSemLimiares.includes("35") && avisoSemLimiares.includes("—")
  && !avisoSemLimiares.includes("50"));
check("aviso de amostra pequena: o valor cru nunca aparece (texto simples; o htmlT escapa ao desenhar)",
  !mleSmallSampleNotice({ total_events: "<img src=x>", attacks_in_dataset: 1, small_sample: true })
    .includes("<img"));

// O aviso entra na MESMA linha da versão (colspan), e só quando small_sample
// é true — uma linha de aviso que aparece sempre seria ruído.
const comAmostraPequena = mleBuildEvalRows({
  versions: [versaoAvaliada("v1", true, avaliacao())],
});
check("linha da versão com amostra pequena traz a linha de aviso",
  comAmostraPequena.includes('class="mle-warning"')
  && comAmostraPequena.includes(escapeHtml(mleSmallSampleNotice(avaliacao()))));
const semAmostraPequena = mleBuildEvalRows({
  versions: [versaoAvaliada("v1", true, avaliacao({ small_sample: false }))],
});
check("linha da versão sem amostra pequena NÃO traz a linha de aviso",
  !semAmostraPequena.includes("mle-warning"));

// --- mleBuildLiveAgreement: a concordância ao vivo (D-10) ---------------------
//
// Só o que /api/ml-anomalies já dá. Nada é calculado no browser para além da
// divisão agree/total, e uma janela sem amostra é "Sem dados", nunca "0,0 %"
// (Pitfall 3). Um ERRO nunca é desenhado como "Sem dados" — esse é um caso
// separado, com a sua própria mensagem.

const liveOk = mleBuildLiveAgreement({
  total: 10, agree_count: 8, diverge_count: 2, ml_anomalies_count: 4, rule_flagged_count: 6,
  alerts_truncated: false,
});
check("concordância ao vivo com amostra: state 'ok'", liveOk.state === "ok");
check("concordância ao vivo com amostra: a percentagem é agree/total em pt-PT",
  liveOk.html.includes("80,0 %"));
check("concordância ao vivo com amostra: as quatro contagens vêm da rota",
  ["10", "4", "6", "2"].every((n) => liveOk.html.includes(n)));
check("concordância ao vivo: nenhuma contagem é recalculada no browser",
  !liveOk.html.includes("agree_count") && !liveOk.html.includes("diverge_count"));

const liveVazio = mleBuildLiveAgreement({ total: 0, agree_count: 0, diverge_count: 0 });
check("concordância ao vivo sem amostra: state 'sem_dados'", liveVazio.state === "sem_dados");
check("concordância ao vivo sem amostra: escreve 'Sem dados'", liveVazio.html.includes("Sem dados"));
check("concordância ao vivo sem amostra: NUNCA '0,0 %' (Pitfall 3)",
  !liveVazio.html.includes("%") && !liveVazio.html.includes("0,0 %"));
for (const resposta of [null, undefined, {}, "texto", 42]) {
  const semDados = mleBuildLiveAgreement(resposta);
  check(`concordância ao vivo com resposta ausente/inválida (${JSON.stringify(resposta)}): 'sem_dados'`,
    semDados.state === "sem_dados" && semDados.html.includes("Sem dados")
    && !semDados.html.includes("%"));
}

// Janela truncada: o aviso é obrigatório, o valor é o MESMO de sempre.
const liveTruncado = mleBuildLiveAgreement({
  total: 10, agree_count: 8, diverge_count: 2, ml_anomalies_count: 4, rule_flagged_count: 6,
  alerts_truncated: true,
});
check("janela truncada: a linha de aviso entra", liveTruncado.html.includes("mle-warning"));
check("janela truncada: o aviso diz o tecto de 1000 alertas",
  liveTruncado.html.includes(escapeHtml(MLE_LIVE_TRUNCADO)) && liveTruncado.html.includes("1000"));
check("janela truncada: a percentagem continua a ser agree/total",
  liveTruncado.html.includes("80,0 %") && liveTruncado.state === "ok");

// Valores que não são números: nada de "NaN %" nem de excepção.
for (const mlReport of [
  { total: "abc", agree_count: 8 },
  { total: 10, agree_count: "abc" },
  { total: 10, agree_count: null },
  { total: null, agree_count: 8 },
  { total: 10 },
]) {
  let resultado = null;
  let levantou = false;
  try {
    resultado = mleBuildLiveAgreement(mlReport);
  } catch (_) { levantou = true; }
  check(`concordância ao vivo com ${JSON.stringify(mlReport)} não levanta nem escreve NaN`,
    !levantou && resultado !== null
    && !resultado.html.includes("NaN") && !resultado.html.includes("undefined"));
}

// As três janelas REAIS da rota (Indexer mockado no wrapper).
const liveRealOk = mleBuildLiveAgreement(mlReportOk);
check("rota real com amostra: state 'ok' e percentagem calculada a partir dela",
  liveRealOk.state === "ok" && liveRealOk.html.includes(mlReportOk.total)
  && !liveRealOk.html.includes("NaN"));
check("rota real com amostra: a percentagem bate com agree/total",
  liveRealOk.html.includes(`${((mlReportOk.agree_count / mlReportOk.total) * 100).toFixed(1)
    .replace(".", ",")} %`));
const liveRealVazio = mleBuildLiveAgreement(mlReportVazio);
check("rota real com a janela vazia: 'Sem dados', nunca '0,0 %'",
  liveRealVazio.state === "sem_dados" && liveRealVazio.html.includes("Sem dados")
  && !liveRealVazio.html.includes("%"));
const liveRealTruncado = mleBuildLiveAgreement(mlReportTruncado);
check("rota real truncada: o aviso de truncagem entra e o valor mantém-se",
  liveRealTruncado.html.includes("mle-warning")
  && liveRealTruncado.html.includes(`${((mlReportTruncado.agree_count / mlReportTruncado.total) * 100)
    .toFixed(1).replace(".", ",")} %`));

// Contagens com HTML: nada disso entra no DOM. As contagens do bloco ao vivo
// são NÚMEROS — um valor que não seja número é "—", nunca o texto que vinha
// no payload (T-02-24).
const liveXss = mleBuildLiveAgreement({
  total: 10, agree_count: 8, diverge_count: 2,
  ml_anomalies_count: "<img src=x onerror=alert(1)>", rule_flagged_count: 6, alerts_truncated: false,
});
check("XSS na concordância ao vivo: <img> nunca chega ao HTML",
  !liveXss.html.includes("<img") && !liveXss.html.includes("onerror"));
check("XSS na concordância ao vivo: uma contagem não numérica vira '—', não texto cru",
  liveXss.html.includes("—") && liveXss.state === "ok");
const liveXssTotal = mleBuildLiveAgreement({
  total: "<img src=x onerror=alert(1)>", agree_count: 8, ml_anomalies_count: 4,
});
check("XSS num total não numérico: 'Sem dados' e nunca o HTML",
  liveXssTotal.state === "sem_dados" && !liveXssTotal.html.includes("<img"));

// --- mleLiveErrorHtml: um erro NUNCA é "Sem dados" e nunca mostra o código ----
//
// A rota devolve um `detail` que pode trazer texto de exceção (o da 502 traz a
// excepção do httpx). Entra como CHAVE de lookup em mlmErrorText e sai já
// traduzido — o código nunca chega ao DOM (T-02-23).

const erroHash = mleLiveErrorHtml("hash_mismatch");
check("erro live: hash_mismatch dá a mensagem de mlmErrorText",
  erroHash.includes(escapeHtml(mlmErrorText("hash_mismatch"))));
check("erro live: o código em bruto nunca aparece no HTML", !erroHash.includes("hash_mismatch"));
const erro502 = mleLiveErrorHtml("http_502");
check("erro live: 502 fala do Wazuh Indexer", erro502.toLowerCase().includes("indexer"));
check("erro live: 502 não mostra o código", !erro502.includes("http_502"));
check("erro live: 502 NÃO é desenhado como 'Sem dados'", !erro502.includes("Sem dados"));
const erro503 = mleLiveErrorHtml("http_503");
check("erro live: 503 diz que o modelo não está carregado",
  erro503.includes("modelo") && !erro503.includes("http_503"));
const erro401 = mleLiveErrorHtml("unauthorized");
check("erro live: 401 dá a mensagem da API key",
  erro401.includes(escapeHtml(mlmErrorText("unauthorized"))) && !erro401.includes("unauthorized"));
for (const codigo of ["codigo_inventado", undefined, "<img src=x>", ""]) {
  const html = mleLiveErrorHtml(codigo);
  check(`erro live com código ${JSON.stringify(codigo)}: mensagem traduzida, sem HTML cru`,
    typeof html === "string" && !html.includes("<img") && html.length > 0);
}
check("mleLiveErrorHtml nunca devolve a mensagem de erro em cru",
  mleLiveErrorMessage("http_502") !== "<div></div>"
  && !mleLiveErrorMessage("http_502").includes("<"));

// --- feature_stats real (R10, 11-03) -----------------------------------------
// Se report_treinado.json existe (o wrapper gravou com feature_stats),
// provamos o aviso de D-03 com números REAIS do lote.
// Se não existe, testamos o ramo fail-closed (sem números).
if (reportTreinado) {
  check("report_treinado.json tem feature_stats no metadata", 
    (reportTreinado.versions || []).some(v => 
      v.metadata && v.metadata.dataset && typeof v.metadata.dataset.feature_stats === "object"
    ));
  const entryComStats = reportTreinado.versions.find(v => 
    v.metadata && v.metadata.dataset && typeof v.metadata.dataset.feature_stats === "object"
  );
  if (entryComStats) {
    const aviso = mleFeatureStatsNotice(entryComStats);
    check("mleFeatureStatsNotice com feature_stats real -> aviso com números",
      typeof aviso === "string" && aviso.length > 0 && aviso.includes("mean") && aviso.includes("std"));
    check("mleFeatureStatsNotice avisa que números são do lote, não do modelo",
      aviso.includes("lote de treino") && aviso.includes("não o comportamento do modelo"));
  }
} else {
  // Ramo fail-closed: feature_stats ausente ou forma desconhecida
  const entrySemStats = versioned({ metadata: { dataset: {} } });
  const avisoVazio = mleFeatureStatsNotice(entrySemStats);
  check("mleFeatureStatsNotice sem feature_stats -> aviso vazio",
    avisoVazio === "");
  const entryFormaInvalida = versioned({ metadata: { dataset: { feature_stats: "não-é-objecto" } } });
  const avisoInvalido = mleFeatureStatsNotice(entryFormaInvalida);
  check("mleFeatureStatsNotice com feature_stats inválida -> aviso vazio",
    avisoInvalido === "");
}

// --- model_version real no bloco ao vivo (D-06, 11-03) ------------------------
// O ml_report_ok.json real (vindo do wrapper com o treino a sério) deve trazer
// model_version. O bloco ao vivo deve mostrá-lo via mleLiveModelText.
if (typeof mlReportOk.model_version === "string" && mlReportOk.model_version.trim() !== "") {
  check("ml_report_ok.json real tem model_version",
    typeof mlReportOk.model_version === "string" && mlReportOk.model_version.trim().length > 0);
  const texto = mleLiveModelText(mlReportOk);
  check("mleLiveModelText com model_version real -> texto inclui a versão",
    texto.includes(mlReportOk.model_version));
  check("mleLiveModelText não contém HTML cru",
    !texto.includes("<") && !texto.includes(">"));
} else {
  check("ml_report_ok.json NÃO tem model_version (bloqueio D-06)",
    !mlReportOk.hasOwnProperty("model_version") || mlReportOk.model_version === null || mlReportOk.model_version === "");
}

// --- Treino (R10) - mlmTrainBody / mlmTrainButtonState / mlmTrainResult /
//     mlmTrainErrorText / mlmPost --------------------------------------------
//
// Um fetch stubado no contexto para exercitar mlmPost sem rede. O stub regista
// (url, options) e devolve um Response-like já feito. Só mlmPost o usa;
// mlmRequest e ml_evaluation.js continuam intactos.
const fetchCalls = [];
const mlmFakeFetch = async (url, options) => {
  fetchCalls.push({ url, options: JSON.parse(JSON.stringify(options)) });
  // Devolve um Response-like mínimo com ok, status, json() assíncrona
  return {
    ok: true,
    status: 200,
    json: async () => ({ version: "v3", active: "v3", loaded: "v3" }),
  };
};
vm.runInContext("({})", vm.createContext({ fetch: mlmFakeFetch, console }), { filename: "stub.js" });

// Re-carregar o contexto com o fetch stubado para mlmPost poder usá-lo
const ctxTrain = vm.createContext({ ...apiGlobals, escapeHtml, console, fetch: mlmFakeFetch });
loadApi(ctxTrain);
vm.runInContext(mlSource, ctxTrain, { filename: "ml_models.js" });
vm.runInContext(mleSource, ctxTrain, { filename: "ml_evaluation.js" });

const helpersTrain = vm.runInContext(
  "({ MLM_TRAIN_DATASETS, MLM_TRAIN_ORIGINS, MLM_TRAIN_ERROR_TEXT,"
  + " MLM_TRAIN_HTTP_TEXT, MLM_TRAIN_GENERIC_ERROR, mlmTrainBody, mlmTrainButtonState,"
  + " mlmTrainResult, mlmTrainErrorText, mlmPost })",
  ctxTrain
);
const {
  MLM_TRAIN_DATASETS,
  MLM_TRAIN_ORIGINS,
  MLM_TRAIN_ERROR_TEXT,
  MLM_TRAIN_HTTP_TEXT,
  MLM_TRAIN_GENERIC_ERROR,
  mlmTrainBody,
  mlmTrainButtonState,
  mlmTrainResult,
  mlmTrainErrorText,
  mlmPost,
} = helpersTrain;

// --- mlmTrainBody: DUAS chaves, listas fechadas, omissões do servidor --------
check("mlmTrainBody: dataset válido + origin válido -> duas chaves exatas",
  JSON.stringify(mlmTrainBody("latest_export", "real")) === '{"dataset":"latest_export","dataset_origin":"real"}');
check("mlmTrainBody: dataset inválido -> omissão latest_export",
  mlmTrainBody("inventado", "real").dataset === "latest_export");
check("mlmTrainBody: origin inválido -> omissão unknown",
  mlmTrainBody("latest_export", "inventado").dataset_origin === "unknown");
check("mlmTrainBody: null/undefined -> omissões",
  JSON.stringify(mlmTrainBody(null, undefined)) === '{"dataset":"latest_export","dataset_origin":"unknown"}');
check("mlmTrainBody: sample_fixture força origem synthetic",
  mlmTrainBody("sample_fixture", "real").dataset_origin === "synthetic");
check("mlmTrainBody: sample_fixture sem origem -> synthetic",
  mlmTrainBody("sample_fixture", undefined).dataset_origin === "synthetic");
check("mlmTrainBody: latest_export mantém origem declarada",
  mlmTrainBody("latest_export", "real").dataset_origin === "real");
check("mlmTrainBody: nunca contém contamination/random_state/n_estimators",
  !JSON.stringify(mlmTrainBody("latest_export", "real")).includes("contamination")
  && !JSON.stringify(mlmTrainBody("latest_export", "real")).includes("random_state")
  && !JSON.stringify(mlmTrainBody("latest_export", "real")).includes("n_estimators"));

// --- mlmTrainButtonState: estado do botão sem DOM ----------------------------
check("mlmTrainButtonState(true) -> {text:'A treinar…', disabled:true}",
  JSON.stringify(mlmTrainButtonState(true)) === '{"text":"A treinar…","disabled":true}');
check("mlmTrainButtonState(false) -> {text:'Treinar', disabled:false}",
  JSON.stringify(mlmTrainButtonState(false)) === '{"text":"Treinar","disabled":false}');

// --- mlmTrainResult: quatro estados, texto simples nunca HTML ----------------
check("mlmTrainResult: ok (loaded===active)",
  JSON.stringify(mlmTrainResult({ version: "v3", active: "v3", loaded: "v3" }))
    .includes("foi criada, está ativa e é a versão que o backend está a usar"));
check("mlmTrainResult: reiniciar (loaded!==active)",
  JSON.stringify(mlmTrainResult({ version: "v3", active: "v3", loaded: "v1" }))
    .includes("reiniciar o backend")
    && JSON.stringify(mlmTrainResult({ version: "v3", active: "v3", loaded: "v1" })).includes("v3")
    && JSON.stringify(mlmTrainResult({ version: "v3", active: "v3", loaded: "v1" })).includes("v1"));
check("mlmTrainResult: nao_ativa (loaded null/undefined, active presente)",
  JSON.stringify(mlmTrainResult({ version: "v3", active: "v1", loaded: null }))
    .includes("versão ativa continua a ser"));
check("mlmTrainResult: incompleto (sem version string)",
  JSON.stringify(mlmTrainResult({})).includes("não há forma de dizer o que foi treinado"));
check("mlmTrainResult: incompleto (version não string)",
  JSON.stringify(mlmTrainResult({ version: 42 })).includes("não há forma de dizer o que foi treinado"));
check("mlmTrainResult: devolve object com estado e texto (escape feito no DOM)",
  typeof mlmTrainResult({ version: "<script>", active: "v1", loaded: "v1" }).texto === "string"
  && mlmTrainResult({ version: "<script>", active: "v1", loaded: "v1" }).texto.includes("<script>"));

// --- mlmTrainErrorText: códigos de treino + HTTP + delegação ao registo ------
check("mlmTrainErrorText: training_in_progress -> frase completa sem o código",
  mlmTrainErrorText("training_in_progress") === "Já há um treino a correr — o servidor só aceita um de cada vez (D-01.2). Espera que o primeiro termine e volta a carregar em «Treinar».");
check("mlmTrainErrorText: dataset_unavailable -> frase completa",
  mlmTrainErrorText("dataset_unavailable") === "O conjunto de dados pedido não está disponível no servidor: o export do Indexer falhou ou não há eventos na janela. Confirma que o Wazuh Indexer está ligado e olha o backend.log.");
check("mlmTrainErrorText: training_failed -> frase completa",
  mlmTrainErrorText("training_failed") === "O treino falhou a meio e nenhuma versão nova ficou registada. O motivo está no backend.log.");
check("mlmTrainErrorText: models_dir_unavailable -> frase completa",
  mlmTrainErrorText("models_dir_unavailable") === "Não foi possível escrever em scripts/models/ (permissões ou disco cheio). Corrige as permissões e olha o backend.log.");
check("mlmTrainErrorText: http_422 -> frase de MLM_TRAIN_HTTP_TEXT",
  mlmTrainErrorText("http_422") === "O servidor recusou o pedido — um dos parâmetros está fora dos valores aceites. Volta a carregar em «Treinar» sem alterar os campos.");
check("mlmTrainErrorText: http_409 -> mesma frase de training_in_progress",
  mlmTrainErrorText("http_409") === "Já há um treino a correr — o servidor só aceita um de cada vez (D-01.2). Espera que o primeiro termine e volta a carregar em «Treinar».");
check("mlmTrainErrorText: código do registo (unauthorized) -> delega a mlmErrorText",
  mlmTrainErrorText("unauthorized") !== MLM_TRAIN_GENERIC_ERROR
  && mlmTrainErrorText("unauthorized") === mlmErrorText("unauthorized"));
check("mlmTrainErrorText: código do registo (registry_unavailable) -> delega a mlmErrorText",
  mlmTrainErrorText("registry_unavailable") !== MLM_TRAIN_GENERIC_ERROR
  && mlmTrainErrorText("registry_unavailable") === mlmErrorText("registry_unavailable"));
check("mlmTrainErrorText: código inventado -> genérica",
  mlmTrainErrorText("codigo_inventado") === MLM_TRAIN_GENERIC_ERROR);
check("mlmTrainErrorText: null/undefined -> genérica",
  mlmTrainErrorText(null) === MLM_TRAIN_GENERIC_ERROR
  && mlmTrainErrorText(undefined) === MLM_TRAIN_GENERIC_ERROR);

// --- mlmPost: mesmo tratamento de erro de mlmRequest -------------------------
fetchCalls.length = 0;
const fakeFetch200 = async (url, options) => {
  fetchCalls.push({ url, options: JSON.parse(JSON.stringify(options)) });
  return {
    ok: true,
    status: 200,
    json: async () => ({ version: "v3", active: "v3", loaded: "v3" }),
  };
};
vm.runInContext("({})", vm.createContext({ fetch: fakeFetch200, console }), { filename: "stub2.js" });
const ctxPost = vm.createContext({ ...apiGlobals, escapeHtml, console, fetch: fakeFetch200, API_BASE: "/api", API_KEY: "test-key" });
loadApi(ctxPost);
vm.runInContext(mlSource, ctxPost, { filename: "ml_models.js" });
// Usar mlmPost e mlmCodeFromResponse do contexto novo (evita redeclarar no mesmo scope)
const { mlmPost: mlmPost2, mlmCodeFromResponse: mlmCodeFromResponse2 } = vm.runInContext(
  "({ mlmPost, mlmCodeFromResponse })",
  ctxPost
);

check("mlmPost 200 -> devolve JSON parseado",
  (async () => {
    const r = await mlmPost2("/api/ml/train", { dataset: "latest_export", dataset_origin: "real" });
    return r.version === "v3" && r.active === "v3" && r.loaded === "v3";
  })());

check("mlmPost: url, method POST, headers X-API-Key + Content-Type, body JSON",
  (async () => {
    fetchCalls.length = 0;
    await mlmPost2("/api/ml/train", { dataset: "latest_export", dataset_origin: "real" });
    const c = fetchCalls[0];
    return c.url === "/api/ml/train"
      && c.options.method === "POST"
      && c.options.headers["X-API-Key"] === "test-key"
      && c.options.headers["Content-Type"] === "application/json"
      && c.options.body === '{"dataset":"latest_export","dataset_origin":"real"}';
  })());

check("mlmPost 409 -> rejeita Error('training_in_progress')",
  (async () => {
    fetchCalls.length = 0;
    const fakeFetch409 = async (url, options) => {
      fetchCalls.push({ url, options: JSON.parse(JSON.stringify(options)) });
      return { ok: false, status: 409, json: async () => ({ detail: "training_in_progress" }) };
    };
    const ctx409 = vm.createContext({ ...apiGlobals, escapeHtml, console, fetch: fakeFetch409, API_BASE: "/api", API_KEY: "test-key" });
    loadApi(ctx409);
vm.runInContext(mlSource, ctx409, { filename: "ml_models.js" });
    const { mlmPost: mlmPost409 } = vm.runInContext("({ mlmPost })", ctx409);
    try { await mlmPost409("/api/ml/train", {}); return false; }
    catch (e) { return e.message === "training_in_progress"; }
  })());

check("mlmPost corpo não-JSON -> rejeita Error('http_500')",
  (async () => {
    fetchCalls.length = 0;
    const fakeFetch500 = async (url, options) => {
      fetchCalls.push({ url, options: JSON.parse(JSON.stringify(options)) });
      return { ok: false, status: 500, json: async () => { throw new Error("não é JSON"); } };
    };
    const ctx500 = vm.createContext({ ...apiGlobals, escapeHtml, console, fetch: fakeFetch500, API_BASE: "/api", API_KEY: "test-key" });
    loadApi(ctx500);
vm.runInContext(mlSource, ctx500, { filename: "ml_models.js" });
    const { mlmPost: mlmPost500 } = vm.runInContext("({ mlmPost })", ctx500);
    try { await mlmPost500("/api/ml/train", {}); return false; }
    catch (e) { return e.message === "http_500"; }
  })());

check("mlmPost 422 com detail lista -> rejeita Error('http_422')",
  (async () => {
    fetchCalls.length = 0;
    const fakeFetch422 = async (url, options) => {
      fetchCalls.push({ url, options: JSON.parse(JSON.stringify(options)) });
      return { ok: false, status: 422, json: async () => ({ detail: [{ loc: ["body", "dataset"] }] }) };
    };
    const ctx422 = vm.createContext({ ...apiGlobals, escapeHtml, console, fetch: fakeFetch422, API_BASE: "/api", API_KEY: "test-key" });
    loadApi(ctx422);
vm.runInContext(mlSource, ctx422, { filename: "ml_models.js" });
    const { mlmPost: mlmPost422 } = vm.runInContext("({ mlmPost })", ctx422);
    try { await mlmPost422("/api/ml/train", {}); return false; }
    catch (e) { return e.message === "http_422"; }
  })());

// --- fim ---------------------------------------------------------------------

if (failures.length > 0) {
  process.exitCode = 1;
} else {
  console.log("\n[OK] Todos os testes Node passaram");
}