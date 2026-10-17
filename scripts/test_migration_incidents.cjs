"use strict";
// Com fetch a rejeitar, o painel de incidentes não fica em «A carregar» nem
// mostra «Failed to fetch». Uso: node test_migration_incidents.cjs <api.js> <state.js> <incidents.js>
const fs = require("node:fs");
const vm = require("node:vm");
const failures = [];
function check(l, c) { console.log(`[${c ? "OK   " : "FALHOU"}] ${l}`); if (!c) failures.push(l); }

function makeEl(id) {
  const el = {
    id, children: [], attrs: {}, className: "", textContent: "", innerHTML: "", value: "", hidden: false,
    dataset: {}, classList: { toggle() {}, add() {}, remove() {} },
    setAttribute(k, v) { this.attrs[k] = v; },
    appendChild(c) { this.children.push(c); },
    replaceChildren(...c) { this.children = c; },
    addEventListener() {}, querySelector() { return null; }, querySelectorAll() { return []; },
  };
  return el;
}
const els = {};
const doc = {
  createElement: () => makeEl("new"),
  getElementById: (id) => (els[id] = els[id] || makeEl(id)),
  querySelector: () => null, querySelectorAll: () => [],
  addEventListener() {},
};
const panelErrors = [];
function text(el) {
  return [el.textContent, el.innerHTML, ...el.children.map(text)].join(" ");
}
const ctx = vm.createContext({
  console, clearTimeout, setTimeout, AbortController, JSON, Promise, URLSearchParams, Math, Number, String, Map,
  setInterval() {}, confirm: () => true, document: doc,
  fetch: () => Promise.reject(new TypeError("Failed to fetch")),
});
vm.runInContext(`const API_BASE="http://x:1"; const API_KEY="k";
const windowSelect={value:"168",addEventListener(){}};
function escapeHtml(s){return String(s)}; function severityBadge(s){return s};
function formatTimestamp(s){return s};
function rtRegisterTab(){return {id:"incidents",refresh(){}}}; // router.js (W3.2) não é carregado aqui
var __pe=[]; function renderPanelError(sel,msg){__pe.push(String(msg))};`, ctx);
vm.runInContext(fs.readFileSync(require("node:path").join(__dirname, "..", "ui_helpers.js"), "utf8"), ctx, { filename: "ui_helpers.js" });
for (const f of process.argv.slice(2)) vm.runInContext(fs.readFileSync(f, "utf8"), ctx, { filename: f });

(async () => {
  // o ficheiro já dispara um refresh ao carregar: esperar que termine
  await new Promise((r) => setTimeout(r, 100));
  await vm.runInContext("refreshIncidentsTab()", ctx);
  const body = els["incidents-body"];
  const t = text(body);
  const pe = vm.runInContext("__pe.join('|')", ctx);
  check("tabela sai de «A carregar»", !/A carregar/.test(t));
  check("tabela mostra erro em PT (role=alert, error-state)", /Sem ligação ao backend/.test(t));
  check("sem «Failed to fetch» na tabela nem no banner", !/Failed to fetch/.test(t + pe));
  check("banner do painel com mensagem PT", /Sem ligação ao backend/.test(pe));
  await vm.runInContext("backfillIncidents()", ctx);
  check("backfill: aviso em PT sem texto de exceção", /Sem ligação/.test(els["inc-notice"].textContent) && !/Failed to fetch/.test(els["inc-notice"].textContent));
  await vm.runInContext("selectIncident('x')", ctx);
  check("detalhe: erro em PT", /Sem ligação/.test(els["inc-detail-error"].textContent) && !/Failed to fetch/.test(els["inc-detail-error"].textContent));
  check("refreshing libertado (pode voltar a tentar)", vm.runInContext("incRefreshing", ctx) === false);
  if (failures.length) process.exit(1);
})().catch((e) => { console.log("FALHOU", e); process.exit(1); });
