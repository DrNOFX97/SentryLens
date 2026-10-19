"use strict";
// Teste Node de fmt.js em node:vm. Uso: node test_fmt.cjs <fmt.js>
const fs = require("node:fs");
const vm = require("node:vm");
const failures = [];
function check(label, cond) { console.log(`[${cond ? "OK   " : "FALHOU"}] ${label}`); if (!cond) failures.push(label); }
const NB = " ";

const ctx = vm.createContext({ console, Date, Number, Math });
try {
  vm.runInContext(fs.readFileSync(process.argv[2], "utf8"), ctx, { filename: process.argv[2] });
  check("fmt.js carrega sem window nem DOM", true);
} catch (e) { check(`carregamento: ${e && e.message}`, false); process.exit(1); }
const call = (expr) => vm.runInContext(expr, ctx);

// fmtNumber
check("fmtNumber(0) = 0 (medição real)", call("fmtNumber(0)") === "0");
check("fmtNumber 1234 sem agrupar (pt-PT)", call("fmtNumber(1234)") === "1234");
check("fmtNumber 12345,6 com espaço fixo e vírgula", call("fmtNumber(12345.6, {decimals:1})") === `12${NB}345,6`);
check("fmtNumber 1234567", call("fmtNumber(1234567)") === `1${NB}234${NB}567`);
check("fmtNumber negativo", call("fmtNumber(-12345)") === `-12${NB}345`);
check("fmtNumber -0.001 sem sinal", call("fmtNumber(-0.001)") === "0");
check("fmtNumber string numérica", call('fmtNumber("42")') === "42");
for (const bad of ["null", "undefined", "NaN", "Infinity", '""', '"  "', '"abc"', "true", "{}", "[]"])
  check(`fmtNumber(${bad}) = —`, call(`fmtNumber(${bad})`) === "—");

// fmtPct
check("fmtPct(12.5) = 12,5%", call("fmtPct(12.5)") === "12,5%");
check("fmtPct(0) = 0,0% (medição)", call("fmtPct(0)") === "0,0%");
check("fmtPct ratio", call("fmtPct(0.256, {ratio:true})") === "25,6%");
check("fmtPct decimals 0", call("fmtPct(99.6, {decimals:0})") === "100%");
check("fmtPct(null/NaN/undefined/'') = — (sem '%')", ["null", "NaN", "undefined", '""'].every((b) => call(`fmtPct(${b})`) === "—"));

// fmtDuration
check("fmtDuration(0) = 0 s", call("fmtDuration(0)") === "0 s");
check("fmtDuration(0.4) = < 1 s", call("fmtDuration(0.4)") === "< 1 s");
check("fmtDuration(45)", call("fmtDuration(45)") === "45 s");
check("fmtDuration(200)", call("fmtDuration(200)") === "3 min 20 s");
check("fmtDuration(180)", call("fmtDuration(180)") === "3 min");
check("fmtDuration(7500)", call("fmtDuration(7500)") === "2 h 5 min");
check("fmtDuration(7200)", call("fmtDuration(7200)") === "2 h");
check("fmtDuration(97200)", call("fmtDuration(97200)") === "1 d 3 h");
check("fmtDuration(86400)", call("fmtDuration(86400)") === "1 d");
check("fmtDuration arredonda 59.6 -> 1 min", call("fmtDuration(59.6)") === "1 min");
for (const bad of ["null", "undefined", "NaN", "-5", '""', '"x"', "Infinity", "false"])
  check(`fmtDuration(${bad}) = —`, call(`fmtDuration(${bad})`) === "—");

// fmtDate (hora local: construímos o Date em local para ser independente do fuso)
check("fmtDate com hora", call("fmtDate(new Date(2026, 9, 7, 14, 5, 9))") === "07/10/2026 14:05:09");
check("fmtDate time:false", call("fmtDate(new Date(2026, 9, 7, 14, 5, 9), {time:false})") === "07/10/2026");
check("fmtDate aceita +0000 do Wazuh", call('fmtDate("2026-10-16T10:00:00.000+0000", {time:false})') !== "—");
check("fmtDate +0000 == +00:00", call('fmtDate("2026-10-16T10:00:00.000+0000")') === call('fmtDate("2026-10-16T10:00:00.000+00:00")'));
check("fmtDate epoch ms", call("fmtDate(1760000000000)") !== "—");
for (const bad of ["null", "undefined", '""', '"não é data"', "NaN", "true", "new Date('x')"])
  check(`fmtDate(${bad}) = —`, call(`fmtDate(${bad})`) === "—");

process.exit(failures.length ? 1 : 0);
