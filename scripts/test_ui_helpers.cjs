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

finish();
