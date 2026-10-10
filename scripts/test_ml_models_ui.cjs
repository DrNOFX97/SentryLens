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
  "   mlmBuildModelsRows, mlmModelsNoticeText, mlmBuildEvalRows })",
  ctx
);
const {
  MLM_ERROR_TEXT,
  MLM_GENERIC_ERROR,
  mlmErrorText,
  mlmCodeFromResponse,
  mlmCell,
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