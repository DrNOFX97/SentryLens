"use strict";
// Teste Node de table.js (com state.js e html.js) em node:vm.
// Uso: node test_table.cjs <state.js> <html.js> <table.js>
const fs = require("node:fs");
const vm = require("node:vm");
const { FakeEl, fakeDocument } = require("./_fake_dom.cjs");
const failures = [];
function check(label, cond) { console.log(`[${cond ? "OK   " : "FALHOU"}] ${label}`); if (!cond) failures.push(label); }

const ctx = vm.createContext({ console, document: fakeDocument, Map, WeakMap, Number, String, Array });
try {
  for (const f of process.argv.slice(2)) vm.runInContext(fs.readFileSync(f, "utf8"), ctx, { filename: f });
  check("table.js (+state.js, html.js) carrega sem window e sem tocar no DOM no topo", true);
} catch (e) { check(`carregamento: ${e && e.message}`, false); process.exit(1); }

const run = (opts, el) => { ctx.opts = opts; ctx.el = el; vm.runInContext("tblRender(el, opts)", ctx); return el; };
const body = (el) => el.querySelectorAll("tr[data-id]");
const cell = (tr, i) => tr.children[i].textContent;
const ids = (el) => body(el).map((tr) => tr.getAttribute("data-id"));
const th = (el, key) => el.querySelectorAll("th[data-sort-key]").find((t) => t.getAttribute("data-sort-key") === key);
const count = (el) => el.children.find((c) => c.className === "table-count").textContent;
const selected = (el) => body(el).filter((tr) => tr.getAttribute("aria-selected") === "true").map((tr) => tr.getAttribute("data-id")).join();

const columns = [
  { key: "name", label: "Nome" },
  { key: "n", label: "Nº", align: "right" },
  { key: "note", label: "Nota", sortable: false },
];
const rows = [
  { id: "a", name: "Zé", n: 10, note: "x" },
  { id: "b", name: "Ana", n: 2, note: "<img src=x onerror=alert(1)>" },
  { id: "c", name: "Rui", n: null, note: null },
  { id: "d", name: "Bia", n: 7, note: "" },
];

// Render básico
let el = run({ columns, rows }, new FakeEl("div"));
check("cria 4 linhas com data-id", ids(el).join() === "a,b,c,d");
check("cabeçalhos com scope=col", el.querySelectorAll("th").every((t) => t.getAttribute("scope") === "col"));
check("«A mostrar 4 de 4»", count(el) === "A mostrar 4 de 4");
check("célula nula -> —", cell(body(el)[2], 1) === "—" && cell(body(el)[2], 2) === "—");
check("HTML em célula é texto (textContent, innerHTML vazio)", cell(body(el)[1], 2) === "<img src=x onerror=alert(1)>" && body(el)[1].children[2].innerHTML === "");
check("coluna sortable:false sem data-sort-key", th(el, "note") === undefined && th(el, "name") !== undefined);
check("aria-sort=none inicial", th(el, "name").getAttribute("aria-sort") === "none");
check("sem inline: nenhum atributo on*", [...el.querySelectorAll("tr"), ...el.querySelectorAll("th"), ...el.querySelectorAll("td")].every((n) => Object.keys(n.attrs).every((k) => !k.startsWith("on"))));
check("sem onSelect: linhas não focáveis", body(el)[0].getAttribute("tabindex") === null);

// Ordenação por clique
th(el, "name").dispatch("click", {});
check("clique ordena asc por nome (pt)", ids(el).join() === "b,d,c,a");
check("aria-sort ascending", th(el, "name").getAttribute("aria-sort") === "ascending");
th(el, "name").dispatch("click", {});
check("segundo clique -> desc", ids(el).join() === "a,c,d,b" && th(el, "name").getAttribute("aria-sort") === "descending");
th(el, "n").dispatch("click", {});
check("outra coluna recomeça em asc, numérico, vazios no fim", ids(el).join() === "b,d,a,c");
th(el, "n").dispatch("click", {});
check("desc numérico mantém vazios no fim", ids(el).join() === "a,d,b,c");
check("coluna anterior volta a none", th(el, "name").getAttribute("aria-sort") === "none");
check("ordenar não muta o array de entrada", rows.map((r) => r.id).join() === "a,b,c,d");

// Teclado nos cabeçalhos
const e1 = th(el, "name").dispatch("keydown", { key: "Enter" });
check("Enter no cabeçalho ordena e previne default", ids(el).join() === "b,d,c,a" && e1.prevented === true);
th(el, "name").dispatch("keydown", { key: " " });
check("Espaço no cabeçalho ordena", ids(el).join() === "a,c,d,b");
const e2 = th(el, "name").dispatch("keydown", { key: "a" });
check("outra tecla ignorada", ids(el).join() === "a,c,d,b" && !e2.prevented);
check("cabeçalhos ordenáveis são focáveis", th(el, "name").getAttribute("tabindex") === "0");

// Ordenação sobrevive a re-render com dados novos
run({ columns, rows: rows.slice(0, 3) }, el);
check("re-render mantém ordenação escolhida (name desc)", ids(el).join() === "a,c,b");
check("listeners não duplicados após re-render", el.listeners.click.length === 1 && el.listeners.keydown.length === 1);

// Seleção
const picked = [];
el = run({ columns, rows, onSelect: (r, id) => picked.push([r.name, id]) }, new FakeEl("div"));
check("com onSelect: linhas focáveis (tabindex 0)", body(el).every((tr) => tr.getAttribute("tabindex") === "0"));
body(el)[1].children[0].dispatch("click", {});
check("clique numa célula seleciona a linha (delegado)", picked.length === 1 && picked[0][0] === "Ana" && picked[0][1] === "b");
check("aria-selected só na escolhida", selected(el) === "b");
body(el)[3].dispatch("keydown", { key: "Enter" });
check("Enter na linha seleciona", picked.length === 2 && picked[1][1] === "d");
const e3 = body(el)[0].dispatch("keydown", { key: " " });
check("Espaço na linha seleciona e previne scroll", picked.length === 3 && picked[2][1] === "a" && e3.prevented === true);
body(el)[0].dispatch("keydown", { key: "Tab" });
check("Tab não seleciona", picked.length === 3);
el.dispatch("click", {});
check("clique fora de linha/cabeçalho é ignorado", picked.length === 3);
th(el, "n").dispatch("click", {});
check("seleção persiste após reordenar", selected(el) === "a");
body(el)[0].dispatch("click", {});
check("onSelect devolve a linha visível após ordenar", picked[3][1] === body(el)[0].getAttribute("data-id"));

// rowId, limit/total
el = run({ columns, rows, rowId: (r) => "r-" + r.name, limit: 2, total: 50 }, new FakeEl("div"));
check("rowId personalizado", ids(el).join() === "r-Zé,r-Ana");
check("limit + total -> «A mostrar 2 de 50»", count(el) === "A mostrar 2 de 50");
el = run({ columns, rows: [{ name: "sem id" }, { name: "outro" }] }, new FakeEl("div"));
check("sem id usa o índice", ids(el).join() === "0,1");
el = run({ columns, rows, sortKey: "n", sortDir: "desc" }, new FakeEl("div"));
check("ordenação inicial por opção", ids(el).join() === "a,d,b,c");
el = run({ columns, rows, sortable: false }, new FakeEl("div"));
check("sortable:false global desliga ordenação", el.querySelectorAll("th[data-sort-key]").length === 0);

// Vazio / erro via state.js
el = run({ columns, rows: [], empty: "Nenhum incidente" }, new FakeEl("div"));
check("vazio -> empty-state com texto", el.children.length === 1 && el.children[0].className === "empty-state" && el.children[0].textContent === "Nenhum incidente");
el = run({ columns, rows: [] }, new FakeEl("div"));
check("vazio sem texto -> «Sem dados», nunca 0", el.children[0].textContent === "Sem dados");
el = run({ columns, rows: null }, new FakeEl("div"));
check("rows null -> estado vazio", el.children[0].className === "empty-state");
el = run({ columns, rows, error: "Falhou" }, new FakeEl("div"));
check("erro tem prioridade sobre rows, role=alert", el.children[0].className === "error-state" && el.children[0].textContent === "Falhou" && el.children[0].getAttribute("role") === "alert");
check("erro: sem linhas nem contagem", body(el).length === 0);
const same = new FakeEl("div");
run({ columns, rows: [], empty: "x" }, same);
run({ columns, rows }, same);
check("passa de vazio a dados no mesmo elemento", ids(same).length === 4);
run({ columns, rows, onSelect: (r) => picked.push(r) }, same);
const before = picked.length;
body(same)[0].dispatch("click", {});
check("onSelect atualizado em re-render é o usado", picked.length === before + 1);

// Células: render() e SafeHtml
const cols2 = [
  { key: "name", label: "N", render: (r) => r.name.toUpperCase() },
  { key: "x", label: "X", render: () => vm.runInContext("htmlRaw('<b>ok</b>')", ctx) },
  { key: "y", label: "Y", render: () => "<b>não</b>" },
];
el = run({ columns: cols2, rows: [{ id: "1", name: "ana" }] }, new FakeEl("div"));
const tr0 = body(el)[0];
check("render() devolve texto", cell(tr0, 0) === "ANA");
check("render() com htmlRaw usa innerHTML", tr0.children[1].innerHTML === "<b>ok</b>");
check("render() com string não-segura fica texto", tr0.children[2].innerHTML === "" && cell(tr0, 2) === "<b>não</b>");
check("el nulo -> null", vm.runInContext("tblRender(null, {})", ctx) === null);
check("tblSortRows é estável", vm.runInContext("tblSortRows([{k:1,i:0},{k:1,i:1},{k:0,i:2}], {key:'k'}, 'asc').map(r=>r.i).join()", ctx) === "2,0,1");

process.exit(failures.length ? 1 : 0);
