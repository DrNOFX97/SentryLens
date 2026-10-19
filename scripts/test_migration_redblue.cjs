"use strict";
// Com fetch a rejeitar, o painel Red vs Blue não fica em «A carregar» nem
// mostra «Failed to fetch». Uso: node test_migration_redblue.cjs <api.js> <state.js> <redblue.js>
const fs = require("node:fs");
const vm = require("node:vm");
const failures = [];
function check(l, c) { console.log(`[${c ? "OK   " : "FALHOU"}] ${l}`); if (!c) failures.push(l); }

function makeEl() {
  const el = {
    children: [], attrs: {}, className: "", textContent: "", _html: "", colSpan: 0,
    setAttribute(k, v) { this.attrs[k] = v; },
    appendChild(c) { this.children.push(c); return c; },
    replaceChildren(...c) { this.children = c; },
    insertAdjacentElement() {}, remove() {}, querySelector() { return null; },
    get innerHTML() { return this._html; }, set innerHTML(v) { this._html = v; this.children = []; },
  };
  return el;
}
const els = {};
const doc = {
  getElementById: (id) => (els[id] = els[id] || makeEl()),
  querySelector: () => makeEl(),
  createElement: () => makeEl(),
};
function dump(el) {
  return [el.textContent, el._html, ...el.children.map(dump)].join(" ");
}
const ctx = vm.createContext({
  console: { log() {}, error() {}, warn() {} }, setTimeout, clearTimeout, AbortController, JSON, Promise, Date, Math, Number, String, Array, Object,
  document: doc,
  setInterval: () => 0,
  WebSocket: function () {},
  fetch: () => Promise.reject(new TypeError("Failed to fetch")),
});
vm.runInContext(`const API_BASE = "http://x:1"; const API_KEY = "k";
const WS_RECONNECT_DELAYS_MS = [1];
function escapeHtml(s){return String(s).replace(/[&<>"']/g,c=>"&#"+c.charCodeAt(0)+";");}
function formatTimestamp(t){return String(t);}
const __panelErrors = {};
function renderPanelError(sel, msg){ __panelErrors[sel] = msg; }`, ctx);
const [api, state, rb] = process.argv.slice(2);
const htmlJs = require("node:path").join(require("node:path").dirname(rb), "html.js");
for (const f of [htmlJs, api, state, rb]) vm.runInContext(fs.readFileSync(f, "utf8"), ctx, { filename: f });

(async () => {
  await vm.runInContext("refreshRedBlueTab()", ctx);
  const errs = vm.runInContext("JSON.stringify(__panelErrors)", ctx);
  check("nenhum painel mostra «Failed to fetch»", !/Failed to fetch/i.test(errs) && !/Failed to fetch/i.test(Object.values(els).map(dump).join(" ")));
  check("painéis mostram erro em PT com ação (backend.log/start-backend)", /start-backend/.test(errs));
  const agents = els["redblue-agents-body"];
  const txt = dump(agents);
  check("tabela de agentes saiu de «A carregar»", !/A carregar/.test(txt));
  check("tabela de agentes mostra estado de erro", /Sem ligação ao backend/.test(txt));
  check("tabela do log de ataques saiu de «A carregar»", !/A carregar/.test(dump(els["redblue-attack-body"])));
  ["kpi-rb-attempts", "kpi-rb-coverage", "kpi-rb-mttd"].forEach((id) =>
    check(`${id} mostra «—» sem dados`, els[id] && els[id].textContent === "—"));
  const src = fs.readFileSync(rb, "utf8");
  check("redblue.js já não usa fetchJSON", !/fetchJSON\(/.test(src));
  check("redblue.js não mostra err.message em bruto", !/err\.message/.test(src));
  if (failures.length) { console.log(`\n${failures.length} falha(s)`); process.exit(1); }
})();
