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