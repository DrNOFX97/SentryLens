"use strict";
// Teste Node dos helpers puros de ui_helpers.js. Carrega o ficheiro REAL num
// contexto node:vm sem document/window/fetch: se o ficheiro tocar no DOM no
// topo, o carregamento falha e isso fica registado como [FALHOU].
// As tarefas seguintes acrescentam check(...) no fim, antes do resumo.
//
// Uso: node test_ui_helpers.cjs <caminho-de-ui_helpers.js>

const fs = require("node:fs");
const vm = require("node:vm");

const failures = [];

function check(label, condition) {
  console.log(`[${condition ? "OK   " : "FALHOU"}] ${label}`);
  if (!condition) failures.push(label);
}

function finish() {
  if (failures.length) {
    console.log(`\n[FALHOU] ${failures.length} teste(s) falharam`);
    process.exit(1);
  }
  console.log("\n[OK] Todos os testes passaram");
}

const helpersPath = process.argv[2];
if (!helpersPath) {
  check("caminho de ui_helpers.js passado como argumento", false);
  finish();
}

// Emula o Firefox/Safari: rejeita ±HHMM sem dois pontos (o V8 aceita-o), para
// o teste de datas falhar se a reescrita ±HHMM -> ±HH:MM for removida.
const RealDate = Date;
function StrictDate(...args) {
  if (!new.target) return RealDate(...args);
  if (typeof args[0] === "string" && /[+-]\d{4}$/.test(args[0])) return new RealDate(NaN);
  return new RealDate(...args);
}
StrictDate.prototype = RealDate.prototype;
StrictDate.now = RealDate.now;
StrictDate.parse = RealDate.parse;
StrictDate.UTC = RealDate.UTC;

const iso = (d) => (d ? d.toISOString() : null);

const ctx = vm.createContext({ console, Date: StrictDate });
try {
  vm.runInContext(fs.readFileSync(helpersPath, "utf8"), ctx, { filename: helpersPath });
  check("ui_helpers.js carrega sem DOM (sem document no contexto)", true);
} catch (e) {
  check(`ui_helpers.js carrega sem DOM: ${e && e.message}`, false);
  finish();
}

check("o Date emulado rejeita +0000 (sensibilidade do teste)",
  Number.isNaN(vm.runInContext('new Date("2026-10-16T10:00:00.000+0000").getTime()', ctx)));
check("slParseDate aceita +0000 do Wazuh",
  iso(ctx.slParseDate("2026-10-16T10:00:00.000+0000")) === "2026-10-16T10:00:00.000Z");
check("slParseDate aceita -0300", iso(ctx.slParseDate("2026-10-16T10:00:00-0300")) === "2026-10-16T13:00:00.000Z");
check("slParseDate aceita Z", iso(ctx.slParseDate("2026-10-16T10:00:00Z")) === "2026-10-16T10:00:00.000Z");
check("slParseDate aceita só data", iso(ctx.slParseDate("2026-10-16")) === "2026-10-16T00:00:00.000Z");
check("slParseDate aceita sem fuso", ctx.slParseDate("2026-10-16T10:00:00") !== null);
check("slParseDate aceita +01:00", iso(ctx.slParseDate("2026-10-16T11:00:00+01:00")) === "2026-10-16T10:00:00.000Z");
check("slParseDate inválido -> null", ctx.slParseDate("não é data") === null);
check("slParseDate vazio -> null", ctx.slParseDate("") === null && ctx.slParseDate(null) === null && ctx.slParseDate(undefined) === null);
check("slFormatTimestamp inválido -> travessão", ctx.slFormatTimestamp("xyz") === "—");
check("slFormatTimestamp válido não é Invalid Date",
  !/Invalid/.test(ctx.slFormatTimestamp("2026-10-16T10:00:00.000+0000")) && ctx.slFormatTimestamp("2026-10-16T10:00:00.000+0000") !== "—");

const hs = (h, f) => JSON.stringify(ctx.slHeaderStatus(h, f));
const hsEq = (h, f, text, cls) => hs(h, f) === JSON.stringify({ text, cls });
check("slHeaderStatus(null, true) -> sem ligação", hsEq(null, true, "● sem ligação ao backend", "status-error"));
check("slHeaderStatus(null, false) -> a verificar", hsEq(null, false, "● a verificar", "status-unknown"));
check("slHeaderStatus ok", hsEq({ status: "ok" }, false, "● Wazuh operacional", "status-ok"));
check("slHeaderStatus degraded", hsEq({ status: "degraded" }, false, "● Wazuh degradado", "status-warn"));
check("slHeaderStatus down", hsEq({ status: "down" }, false, "● Wazuh em baixo", "status-error"));
check("slHeaderStatus outro estado -> desconhecido", hsEq({ status: "xpto" }, false, "● estado do Wazuh desconhecido", "status-unknown"));
check("slHeaderStatus({}, false).cls é status-unknown", ctx.slHeaderStatus({}, false).cls === "status-unknown");
check("slHeaderStatus com resposta ignora failed", ctx.slHeaderStatus({ status: "ok" }, true).text === "● Wazuh operacional");

const hes = (e) => JSON.stringify(ctx.slHeaderErrorStatus(e));
check("slHeaderErrorStatus 401 -> chave inválida",
  hes({ status: 401 }) === JSON.stringify({ text: "● chave da API inválida", cls: "status-error" }));
check("slHeaderErrorStatus outro erro -> sem ligação",
  hes({ status: 502 }) === hs(null, true) && hes(new Error("x")) === hs(null, true) && hes(null) === hs(null, true));

check("slFmtPct(null) -> —", ctx.slFmtPct(null) === "—");
check("slFmtPct(12.34,1) -> 12.3%", ctx.slFmtPct(12.34, 1) === "12.3%");
check("slFmtPct(true) -> —", ctx.slFmtPct(true) === "—");
check("slProgressWidth(null) -> 0%", ctx.slProgressWidth(null) === "0%");
check("slProgressWidth(150) -> 100%", ctx.slProgressWidth(150) === "100%");
check("slProgressWidth(-5) -> 0%", ctx.slProgressWidth(-5) === "0%");
check("slNumberOrNull vazio/NaN/bool -> null", ctx.slNumberOrNull("") === null && ctx.slNumberOrNull(NaN) === null && ctx.slNumberOrNull(false) === null && ctx.slNumberOrNull(Infinity) === null);
check("slNumberOrNull(0) -> 0", ctx.slNumberOrNull(0) === 0);

check("concordância sem eventos -> —", ctx.slAgreementText(0, 0) === "—");
check("concordância total null -> —", ctx.slAgreementText(3, null) === "—");
check("concordância 3/4 -> 75%", ctx.slAgreementText(3, 4) === "75%");

const ap = ctx.slComplianceVerdict({ estado: "aplicavel", justificacao: "Dados pessoais" });
check("aplicável + justificação", ap.label === "✅ Aplicável" && ap.title === "Dados pessoais");
check("não aplicável", ctx.slComplianceVerdict({ estado: "verificado_e_nao_aplicavel" }).label === "➖ Não aplicável");
check("estado desconhecido -> Indeterminado", ctx.slComplianceVerdict({ estado: "xpto" }).label === "❔ Indeterminado");
const miss = ctx.slComplianceVerdict(undefined);
check("sem veredito -> Indeterminado com motivo", miss.label === "❔ Indeterminado" && miss.title === "Sem veredito do motor de conformidade");
check("veredito null -> Indeterminado", ctx.slComplianceVerdict(null).label === "❔ Indeterminado");

const af = (v) => JSON.stringify(ctx.slAnalystActiveFilter(v));
check("Ativos", af("1") === '{"activeOnly":true,"onlyInactive":false}');
check("Inativos", af("0") === '{"activeOnly":false,"onlyInactive":true}');
check("Todos", af("") === '{"activeOnly":false,"onlyInactive":false}');
check("filtro desconhecido -> Todos", af("x") === '{"activeOnly":false,"onlyInactive":false}');

// Janela global (W5.3): horas selecionadas, teto por fonte, nota «A mostrar».
check("slWindowHours: valor válido passa", ctx.slWindowHours("24") === 24 && ctx.slWindowHours(2160) === 2160);
check("slWindowHours: inválido/zero/negativo/Infinity -> 168", [undefined, "abc", 0, -3, Infinity].every((v) => ctx.slWindowHours(v) === 168));
const ew = (s, m) => JSON.stringify(ctx.slEffectiveWindow(s, m));
check("janela abaixo do teto não recorta", ew(24, 168) === '{"hours":24,"clamped":false}');
check("janela igual ao teto não recorta", ew(168, 168) === '{"hours":168,"clamped":false}');
check("90 dias numa fonte de 168 h recorta", ew(2160, 168) === '{"hours":168,"clamped":true}');
check("90 dias numa fonte de 720 h recorta", ew(2160, 720) === '{"hours":720,"clamped":true}');
check("inválido usa 168 h", ew("abc", 720) === '{"hours":168,"clamped":false}');
check("slWindowDays arredonda para cima e tem mínimo 1", ctx.slWindowDays(1) === 1 && ctx.slWindowDays(24) === 1 && ctx.slWindowDays(25) === 2 && ctx.slWindowDays(2160) === 90);
check("rótulos da janela", ctx.slWindowLabel(1) === "última hora" && ctx.slWindowLabel(6) === "últimas 6 horas" && ctx.slWindowLabel(24) === "últimas 24 horas" && ctx.slWindowLabel(168) === "últimos 7 dias" && ctx.slWindowLabel(720) === "últimos 30 dias" && ctx.slWindowLabel(2160) === "últimos 90 dias");
check("nota sem recorte", ctx.slWindowNote(168, 720) === "A mostrar: últimos 7 dias");
check("nota com recorte diz o máximo da fonte", ctx.slWindowNote(2160, 168) === "A mostrar: últimos 7 dias (máximo desta fonte)");

// slVacDecisionBody (R12, aba Vaccines): valida o que o analista escreveu e constrói o corpo do POST de decisão.
const vdb = (a, c, r) => ctx.slVacDecisionBody(a, c, r);
const vdbJson = (a, c, r) => JSON.stringify(vdb(a, c, r));
check("slVacDecisionBody: aprovar sem motivo -> corpo com reason null",
  vdbJson("analyst-eddie", "approved", "") === '{"code":null,"body":{"decision":"approved","analyst_id":"analyst-eddie","reason":null}}');
check("slVacDecisionBody: o corpo tem exatamente as chaves decision, analyst_id, reason (por esta ordem)",
  JSON.stringify(Object.keys(vdb("analyst-eddie", "approved", "").body)) === '["decision","analyst_id","reason"]');
check("slVacDecisionBody: o motivo vai aparado",
  vdb("analyst-jeremy", "rejected", "  Regra ruidosa  ").body.reason === "Regra ruidosa");
check("slVacDecisionBody: analista vazio, null e undefined -> analyst_required, sem corpo",
  ["", null, undefined].every((a) => { const r = vdb(a, "approved", ""); return r.code === "analyst_required" && r.body === null; }));
check("slVacDecisionBody: analista fora do formato -> invalid_author", vdb("Eddie", "approved", "").code === "invalid_author");
check("slVacDecisionBody: escolha fora de approved/rejected -> invalid_decision", vdb("analyst-eddie", "applied", "").code === "invalid_decision");
check("slVacDecisionBody: rejeitar com motivo só de espaços -> reason_required", vdb("analyst-eddie", "rejected", "   ").code === "reason_required");
check("slVacDecisionBody: motivo com 501 caracteres -> invalid_reason", vdb("analyst-eddie", "rejected", "x".repeat(501)).code === "invalid_reason");
check("slVacDecisionBody: motivo com quebra de linha -> invalid_reason", vdb("analyst-eddie", "rejected", "a\nb").code === "invalid_reason");
check("slVacDecisionBody: analista com maiúscula (analyst-A) -> invalid_author", vdb("analyst-A", "approved", "").code === "invalid_author");
check("slVacDecisionBody: APPROVED e vazio -> invalid_decision", vdb("analyst-eddie", "APPROVED", "").code === "invalid_decision" && vdb("analyst-eddie", "", "").code === "invalid_decision");
check("slVacDecisionBody: rejeitar com motivo vazio ou null -> reason_required", vdb("analyst-eddie", "rejected", "").code === "reason_required" && vdb("analyst-eddie", "rejected", null).code === "reason_required");
check("slVacDecisionBody: aprovar com motivo só de espaços -> reason null", vdb("analyst-eddie", "approved", "  ").body.reason === null);
check("slVacDecisionBody: 500 caracteres é válido", vdb("analyst-eddie", "rejected", "x".repeat(500)).code === null);
check("slVacDecisionBody: 500 emoji (1000 unidades UTF-16) é válido; 501 emoji -> invalid_reason",
  vdb("analyst-eddie", "rejected", "😀".repeat(500)).code === null && vdb("analyst-eddie", "rejected", "😀".repeat(501)).code === "invalid_reason");
check("slVacDecisionBody: tabulação, U+202E e U+2028 no motivo -> invalid_reason",
  ["a\tb", "a‮b", "a b"].every((r) => vdb("analyst-eddie", "rejected", r).code === "invalid_reason"));

// slVacAnalystOptions: só analistas ativos, com id válido e nome não vazio.
const vao = (e) => JSON.stringify(ctx.slVacAnalystOptions(e));
check("slVacAnalystOptions: filtra inativos (0), ids inválidos, nomes vazios e itens nulos; aceita active true",
  vao({ analysts: [
    { id: "analyst-eddie", name: "Eddie", active: 1 }, { id: "analyst-x", name: "X", active: 0 },
    { id: "bad id", name: "Y", active: 1 }, { id: "analyst-z", name: "  ", active: 1 }, null,
    { id: "analyst-t", name: "Tom", active: true }] }) === '[{"id":"analyst-eddie","name":"Eddie"},{"id":"analyst-t","name":"Tom"}]');
check("slVacAnalystOptions: null, {} e analysts não-array -> []",
  vao(null) === "[]" && vao({}) === "[]" && vao({ analysts: "x" }) === "[]");

// slVacDecisionView: o que o bloco Decisão pode afirmar (modos avaliados por ordem, forma fixa).
const VIEW_KEYS = '["mode","state","author","decidedAt","reason","supersededBy","code"]';
const dv = (v, a, e) => ctx.slVacDecisionView(v, a, e);
const dvs = (v, a, e) => JSON.stringify(dv(v, a, e));
const EDDIE = [{ id: "analyst-eddie", name: "Eddie" }];
const decidida = { state: "approved", superseded_by: null,
  decision: { decided_by_name: "Eddie", decided_at: "2026-10-30T10:00:00+00:00", reason: null } };
check("slVacDecisionView: vaccine null/undefined -> none",
  dv(null, EDDIE, null).mode === "none" && dv(undefined, null, null).mode === "none");
check("slVacDecisionView: approved com decisão -> decided, com autor e data, motivo null",
  dvs(decidida, EDDIE, null) === JSON.stringify({ mode: "decided", state: "approved", author: "Eddie",
    decidedAt: "2026-10-30T10:00:00+00:00", reason: null, supersededBy: null, code: null }));
const rejeitadaSubstituida = { state: "rejected", superseded_by: "vac-0123456789ab",
  decision: { decided_by_name: "Jeremy", decided_at: "2026-10-30T11:00:00+00:00", reason: "Regra ruidosa" } };
check("slVacDecisionView: rejected e substituída continua decided e preserva o motivo",
  dv(rejeitadaSubstituida, EDDIE, null).mode === "decided" && dv(rejeitadaSubstituida, EDDIE, null).reason === "Regra ruidosa");
check("slVacDecisionView: decided não depende dos analistas (null, erro ou vazio)",
  dv(decidida, null, "http_500").mode === "decided" && dv(decidida, [], null).mode === "decided"
  && dv(decidida, null, null).mode === "decided");
check("slVacDecisionView: approved sem decision -> decided com autor, data e motivo null",
  dvs({ state: "approved", decision: null }, EDDIE, null) === JSON.stringify({ mode: "decided", state: "approved",
    author: null, decidedAt: null, reason: null, supersededBy: null, code: null }));
check("slVacDecisionView: estado desconhecido e estado ausente -> unknown_state",
  dv({ state: "xpto" }, EDDIE, null).mode === "unknown_state" && dv({ state: "xpto" }, EDDIE, null).state === "xpto"
  && dv({}, EDDIE, null).mode === "unknown_state" && dv({}, EDDIE, null).state === null
  && dv({ state: 7 }, EDDIE, null).mode === "unknown_state");
check("slVacDecisionView: proposed com superseded_by -> superseded, sem analistas à mistura",
  dvs({ state: "proposed", superseded_by: "vac-aaaaaaaaaaaa" }, null, "http_500") === JSON.stringify({ mode: "superseded",
    state: "proposed", author: null, decidedAt: null, reason: null, supersededBy: "vac-aaaaaaaaaaaa", code: null }));
check("slVacDecisionView: proposed atual + analistas por carregar -> loading",
  dv({ state: "proposed", superseded_by: null }, null, null).mode === "loading");
const atual = { state: "proposed", superseded_by: null };
check("slVacDecisionView: erro http_500 e http_503 -> analysts_error com incidents_unavailable",
  ["http_500", "http_503"].every((c) => dv(atual, null, c).mode === "analysts_error" && dv(atual, null, c).code === "incidents_unavailable"));
check("slVacDecisionView: network_error e unauthorized ficam como vieram",
  dv(atual, null, "network_error").code === "network_error" && dv(atual, null, "unauthorized").code === "unauthorized");
check("slVacDecisionView: o erro ganha à lista quando os dois vêm preenchidos",
  dv(atual, EDDIE, "network_error").mode === "analysts_error");
check("slVacDecisionView: lista vazia -> no_analysts; lista com analistas -> controls",
  dv(atual, [], null).mode === "no_analysts" && dv(atual, EDDIE, null).mode === "controls");
check("slVacDecisionView: todos os resultados têm exatamente as 7 chaves, pela mesma ordem",
  [dv(null, null, null), dv(decidida, null, null), dv({ state: "x" }, null, null), dv(atual, null, null),
   dv(atual, null, "http_500"), dv(atual, [], null), dv(atual, EDDIE, null),
   dv({ state: "proposed", superseded_by: "vac-a" }, null, null)].every((v) => JSON.stringify(Object.keys(v)) === VIEW_KEYS));

// slVacWarningText: o aviso do detalhe depende sempre do estado e diz sempre "não aplicada no Wazuh".
const LABELS = { proposed: "Proposta", approved: "Aprovada", rejected: "Rejeitada" };
const wt = (s) => ctx.slVacWarningText(s, LABELS);
check("slVacWarningText: proposed", wt("proposed") === "Proposta — não aplicada no Wazuh");
check("slVacWarningText: approved diz aceite pelo analista", wt("approved") === "Aprovada — aceite pelo analista, não aplicada no Wazuh");
check("slVacWarningText: rejected", wt("rejected") === "Rejeitada — não aplicada no Wazuh");
check("slVacWarningText: estado desconhecido aparece como veio", wt("xpto") === "xpto — não aplicada no Wazuh");
check("slVacWarningText: null, undefined, número e vazio -> Estado desconhecido",
  [null, undefined, 7, ""].every((s) => wt(s) === "Estado desconhecido — não aplicada no Wazuh"));
check("slVacWarningText: toString/constructor não usam o protótipo dos labels",
  wt("toString") === "toString — não aplicada no Wazuh" && wt("constructor") === "constructor — não aplicada no Wazuh");
check("slVacWarningText: todas as variantes contêm 'não aplicada no Wazuh'",
  ["proposed", "approved", "rejected", "xpto", null, 7].every((s) => wt(s).includes("não aplicada no Wazuh")));
check("slVacWarningText: sem labels não rebenta", ctx.slVacWarningText("proposed", null) === "proposed — não aplicada no Wazuh");

// slVacReasonCounter: pontos de código sobre 500.
const rc = (r) => ctx.slVacReasonCounter(r);
check("slVacReasonCounter: null, undefined e vazio -> 0/500", rc(null) === "0/500" && rc(undefined) === "0/500" && rc("") === "0/500");
check("slVacReasonCounter: 'ab' -> 2/500 e um emoji conta 1", rc("ab") === "2/500" && rc("😀") === "1/500");
check("slVacReasonCounter: 500 caracteres -> 500/500", rc("x".repeat(500)) === "500/500");

finish();
