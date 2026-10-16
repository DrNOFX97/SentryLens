"use strict";
// Teste Node de kpi.js (com fmt.js) em node:vm. Uso: node test_kpi.cjs <fmt.js> <kpi.js>
const fs = require("node:fs");
const vm = require("node:vm");
const { FakeEl, fakeDocument } = require("./_fake_dom.cjs");
const failures = [];
function check(label, cond) { console.log(`[${cond ? "OK   " : "FALHOU"}] ${label}`); if (!cond) failures.push(label); }

function load(files) {
  const ctx = vm.createContext({ console, document: fakeDocument });
  for (const f of files) vm.runInContext(fs.readFileSync(f, "utf8"), ctx, { filename: f });
  return ctx;
}
let ctx;
try {
  ctx = load([process.argv[3]]);
  check("kpi.js carrega sozinho, sem window e sem tocar no DOM no topo", true);
} catch (e) { check(`carregamento: ${e && e.message}`, false); process.exit(1); }
const withFmt = load(process.argv.slice(2));

function render(c, opts) {
  const el = new FakeEl("div");
  c.opts = opts; c.el = el;
  vm.runInContext("kpiRender(el, opts)", c);
  return el;
}
const valueOf = (el) => el.children[1].textContent;

let el = render(ctx, { label: "MTTD", value: "3 min", sub: "últimos 7 dias", level: "high" });
check("label em h3", el.children[0].tag === "h3" && el.children[0].textContent === "MTTD");
check("valor em .value", el.children[1].className === "value" && valueOf(el) === "3 min");
check("sub em small", el.children[2] && el.children[2].tag === "small" && el.children[2].textContent === "últimos 7 dias");
check("classe card + nível", el.className === "card high");

el = render(ctx, { label: "X", value: "5", unit: "alertas", level: "critical" });
check("unit junta-se ao valor", valueOf(el) === "5 alertas");
check("sem sub não cria small", el.children.length === 2);

for (const [lbl, v] of [["null", null], ["undefined", undefined], ['""', ""], ["NaN", NaN], ["Infinity", Infinity], ['"  "', "  "], ["objeto", {}], ["true", true]]) {
  el = render(ctx, { label: "X", value: v, unit: "ms", level: "critical", sub: "s" });
  check(`value ${lbl} -> «—», sem unidade e sem nível`, valueOf(el) === "—" && el.className === "card kpi-empty");
}
el = render(ctx, { label: "X", value: 0 });
check("value 0 é uma medição: mostra 0 (não «—»)", valueOf(el) === "0" && !el.className.includes("kpi-empty"));
el = render(ctx, { label: "X", value: "0", level: "low" });
check("value '0' (texto) mantém-se", valueOf(el) === "0" && el.className === "card low");
el = render(ctx, { label: "X", value: "1", level: "bogus" });
check("nível desconhecido ignorado", el.className === "card");
el = render(ctx, { label: "<b>x</b>", value: "<i>1</i>", sub: "<u>" });
check("texto vai por textContent (nada interpretado)", el.children[0].textContent === "<b>x</b>" && valueOf(el) === "<i>1</i>" && el.innerHTML === "");
ctx.el2 = new FakeEl("div");
vm.runInContext("kpiRender(el2)", ctx);
check("sem opts não rebenta", ctx.el2.children[1].textContent === "—");
check("el nulo -> null", vm.runInContext("kpiRender(null, {value: 1})", ctx) === null);
ctx.el = render(ctx, { label: "A", value: "1" });
ctx.opts = { label: "B", value: "2" };
vm.runInContext("kpiRender(el, opts)", ctx);
check("re-render substitui (não acumula)", ctx.el.children.length === 2 && ctx.el.children[0].textContent === "B");

el = render(withFmt, { label: "N", value: 12345 });
check("número usa fmtNumber (pt-PT)", valueOf(el) === "12 345");
el = render(withFmt, { label: "N", value: 2.4 });
check("decimal com vírgula", valueOf(el) === "2,4");
check("kpiModel é puro e expõe empty", vm.runInContext("kpiModel({value:null}).empty === true && kpiModel({value:1}).empty === false", ctx));

process.exit(failures.length ? 1 : 0);
