"use strict";
// Teste Node da camada pura de ml_models.js (marco R9). Corre o ficheiro
// real num contexto node:vm sem document/window/fetch e exercita só os
// helpers que devolvem strings — a camada DOM não é testada aqui, é o que
// o <human-check> no browser de cada fase.
//
// Os relatórios de report_v1.json / report_empty.json são reais: vêm do
// wrapper test_ml_models_ui.py, que os obtém de GET /api/ml/models com
// TestClient sobre um registo temporário. Por isso este ficheiro nunca é
// corrido sozinho (sem argumentos sai com [FALHOU]).
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
// do vm tem de trazer os globais que ml_models.js NÃO redeclara.
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

// --- carregar o ficheiro real sem DOM ----------------------------------------

const mlSource = fs.readFileSync(path.join(__dirname, "..", "ml_models.js"), "utf8");
const ctx = vm.createContext({ escapeHtml, console });
try {
  vm.runInContext(mlSource, ctx, { filename: "ml_models.js" });
} catch (err) {
  console.log("[FALHOU] ml_models.js carrega sem DOM (nenhuma linha de topo toca em document)");
  console.log(String(err && err.stack ? err.stack : err));
  process.exit(1);
}
check("ml_models.js carrega sem DOM (nenhuma linha de topo toca em document)", true);

const helpers = vm.runInContext(
  "({ MLM_ERROR_TEXT, MLM_GENERIC_ERROR, mlmErrorText, mlmCodeFromResponse, mlmCell," +
  "   mlmStatusText, mlmFormatDate, mlmOriginHtml, mlmTrainedAtText," +
  "   mlmEntryKey, mlmFindEntryIndex, mlmRowIndexFromEvent, mlmIsSelectKey," +
  "   mlmHandleRowKey, mlmBuildDetail," +
  "   mlmBuildModelsRows, mlmModelsNoticeText, mlmBuildEvalRows })",
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
  mlmOriginHtml,
  mlmTrainedAtText,
  mlmEntryKey,
  mlmFindEntryIndex,
  mlmRowIndexFromEvent,
  mlmIsSelectKey,
  mlmHandleRowKey,
  mlmBuildDetail,
  mlmBuildModelsRows,
  mlmModelsNoticeText,
  mlmBuildEvalRows,
} = helpers;

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
check("mlmCell escapa HTML", mlmCell("<b>") === "&lt;b&gt;");

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
check("mlmFormatDate que não é data devolve o texto escapado",
  mlmFormatDate("nao-e-data") === "nao-e-data");
check("mlmFormatDate escapa texto que não é data",
  mlmFormatDate("<b>x") === "&lt;b&gt;x");

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

// --- mlmBuildEvalRows (aba Evaluation, D-05) --------------------------------

const evalV1 = mlmBuildEvalRows(reportV1);
check("Evaluation com v1: uma linha por versão",
  (evalV1.match(/<tr/g) || []).length === 1);
check("Evaluation com v1: diz que não há avaliação", evalV1.includes("Sem avaliação"));
check("Evaluation com v1: marca a versão ativa", evalV1.includes("mlm-badge-active"));
check("Evaluation sem versões: diz que ainda não há modelos registados",
  mlmBuildEvalRows(reportEmpty).includes("Sem dados — ainda não há modelos registados."));

// D-05: a Fase 1 não mostra métricas — só diz que existe uma avaliação.
const evalComNumeros = mlmBuildEvalRows({
  versions: [{
    id: "v9",
    label: "v9",
    kind: "versioned",
    active: false,
    status: "ok",
    error_code: null,
    metadata: null,
    evaluation: { precision: 0.987, recall: 0.5 },
  }],
});
check("Evaluation com objeto: diz que está registada no metadata.json",
  evalComNumeros.includes("Avaliação registada no metadata.json"));
check("Evaluation com objeto: nenhum número é mostrado (D-05)",
  !evalComNumeros.includes("0.987") && !evalComNumeros.includes("0.5"));

// --- fim ---------------------------------------------------------------------

if (failures.length > 0) {
  process.exitCode = 1;
} else {
  console.log("\n[OK] Todos os testes Node passaram");
}