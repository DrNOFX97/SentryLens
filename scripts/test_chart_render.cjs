"use strict";
// Teste node:vm de renderChart (W6.3): estado vazio, aria-label e tabela «Ver dados».
// Uso: node test_chart_render.cjs <raiz-do-repo>
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const root = process.argv[2];
const failures = [];
function check(l, c) { console.log(`[${c ? "OK   " : "FALHOU"}] ${l}`); if (!c) failures.push(l); }

class El {
  constructor(tag) {
    this.tag = tag; this.id = ""; this.className = ""; this.hidden = false; this.textContent = "";
    this.attrs = {}; this.next = null; this.parent = null; this._html = ""; this.body = null;
  }
  setAttribute(k, v) { this.attrs[k] = v; }
  after(el) { el.parent = this.parent; this.next = el; registry.set(el.id, el); }
  set innerHTML(v) { this._html = v; if (/chart-data-body/.test(v) && !this.body) { this.body = new El("div"); } }
  get innerHTML() { return this._html; }
  querySelector() { return this.body; }
  getContext() { return {}; }
}
const registry = new Map();
const wrap = new El("div");
const canvas = new El("canvas"); canvas.id = "chart-x"; canvas.parentElement = wrap;
wrap.parent = null;
registry.set("chart-x", canvas);

let created = 0, destroyed = 0, updated = 0;
class FakeChart {
  constructor() { created++; this.data = null; this.options = null; }
  update() { updated++; }
  destroy() { destroyed++; }
}
FakeChart.defaults = { font: {}, color: "", borderColor: "" };

const document = {
  getElementById: (id) => registry.get(id) || null,
  createElement: (tag) => new El(tag),
  documentElement: {}, addEventListener() {},
};
const ctx = vm.createContext({
  console, Math, Number, String, Array, Object, Map, WeakMap, Date,
  document, Chart: FakeChart,
  getComputedStyle: () => ({ getPropertyValue: () => "#000000" }),
  window: { matchMedia: () => ({ addEventListener() {} }) },
  MutationObserver: class { observe() {} },
});
for (const f of ["html.js", "fmt.js", "ui_helpers.js", "overview-alerts.js"]) {
  vm.runInContext(fs.readFileSync(path.join(root, f), "utf8"), ctx, { filename: f });
}
vm.runInContext("this.__render = renderChart; this.__charts = charts;", ctx);
const render = ctx.__render;
const cfg = () => ({ type: "bar", data: { labels: ["a"], datasets: [{ data: [1] }] }, options: {} });

render("chart-x", cfg(), { title: "Teste: a 1", empty: false, columns: ["Nome", "Valor"], rows: [["<b>a</b>", "1"]] });
const empty = registry.get("chart-x-empty");
const details = registry.get("chart-x-data");
check("aria-label e role=img no canvas", canvas.attrs["aria-label"] === "Teste: a 1" && canvas.attrs.role === "img");
check("com dados: gráfico criado e visível", created === 1 && wrap.hidden === false);
check("com dados: mensagem de vazio escondida", empty && empty.hidden === true);
check("com dados: tabela «Ver dados» visível", details && details.hidden === false);
check("tabela tem cabeçalhos e a linha", /<th scope="col">Nome<\/th>/.test(details.body.innerHTML) && /<th scope="row">/.test(details.body.innerHTML));
check("texto dinâmico da tabela escapado", !/<b>a<\/b>/.test(details.body.innerHTML) && /&lt;b&gt;/.test(details.body.innerHTML));

render("chart-x", cfg(), { title: "Teste: a 2", empty: false, columns: ["Nome", "Valor"], rows: [["a", "2"]] });
check("segundo desenho atualiza em vez de recriar", created === 1 && updated === 1);

render("chart-x", cfg(), { title: "Teste: sem dados nesta janela", empty: true });
check("vazio: gráfico destruído", destroyed === 1 && !("chart-x" in ctx.__charts));
check("vazio: área do gráfico escondida", wrap.hidden === true);
check("vazio: mensagem «Sem dados nesta janela»", empty.hidden === false && empty.textContent === "Sem dados nesta janela");
check("vazio: sem tabela", details.hidden === true);
check("vazio: aria-label diz que não há dados", /sem dados/.test(canvas.attrs["aria-label"]));

render("chart-x", cfg(), { title: "Teste: a 3", empty: false, columns: ["Nome", "Valor"], rows: [["a", "3"]] });
check("volta a ter dados: gráfico recriado e visível", created === 2 && wrap.hidden === false && empty.hidden === true);

render("chart-x", cfg(), { empty: true, emptyText: "Nada aqui" });
check("texto de vazio personalizável", empty.textContent === "Nada aqui");
render("chart-x", cfg());
check("sem meta: aria-label por omissão, nunca vazio", canvas.attrs["aria-label"] === "Gráfico");

if (failures.length) process.exit(1);
