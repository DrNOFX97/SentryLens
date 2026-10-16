"use strict";
// Teste Node de soc_team.js em node:vm: com fetch a rejeitar, nenhum painel
// fica em «A carregar» nem mostra «Failed to fetch».
// Uso: node test_migration_soc_team.cjs <api.js> <state.js> <soc_team.js>
const fs = require("node:fs");
const vm = require("node:vm");

const failures = [];
function check(label, cond) {
  console.log(`[${cond ? "OK   " : "FALHOU"}] ${label}`);
  if (!cond) failures.push(label);
}

const els = {};
function makeEl(id) {
  const el = {
    id, children: [], attrs: {}, className: "", _text: "", value: "", hidden: false, disabled: false,
    dataset: {}, classList: { contains: () => false },
    set textContent(v) { this._text = String(v); this.children = []; },
    get textContent() { return this._text + this.children.map((c) => c.textContent).join(""); },
    set innerHTML(v) { this._html = String(v); this.children = []; this._text = ""; },
    get innerHTML() { return (this._html || "") + this.children.map((c) => c.innerHTML || "").join(""); },
    setAttribute(k, v) { this.attrs[k] = v; },
    appendChild(c) { this.children.push(c); return c; },
    replaceChildren(...c) { this.children = c; this._text = ""; this._html = ""; },
    addEventListener() {}, querySelector: () => null, closest: () => null,
    querySelectorAll: () => [], focus() {}, observe() {}, reset() {},
  };
  return el;
}
const fakeDocument = {
  readyState: "complete",
  getElementById(id) { return els[id] || (els[id] = makeEl(id)); },
  createElement(tag) { const e = makeEl(""); e.tagName = tag.toUpperCase(); return e; },
  querySelector: () => null, addEventListener() {}, contains: () => true, activeElement: null,
};
fakeDocument.getElementById("analyst-tier-filter").value = "";
fakeDocument.getElementById("analyst-active-filter").value = "";
fakeDocument.getElementById("oncall-tier-filter").value = "1";
fakeDocument.getElementById("analysts-body").tagName = "TBODY";
for (const id of ["shifts-body", "escalation-body", "sla-breaches-body", "tier-summary-body"]) fakeDocument.getElementById(id).tagName = "TBODY";
for (const id of ["oncall-list", "primary-list"]) fakeDocument.getElementById(id).tagName = "UL";

const panelErrors = [];
const ctx = vm.createContext({
  console, setTimeout, clearTimeout, setInterval: () => 0, AbortController, JSON, Promise,
  URLSearchParams, Number, parseInt, Date, Object, String, Array,
  document: fakeDocument,
  MutationObserver: class { observe() {} },
  fetch: () => Promise.reject(new TypeError("Failed to fetch")),
  confirm: () => true,
});
try {
  vm.runInContext(`const API_BASE = "http://x:1"; const API_KEY = "k";
    const periodSelect = { value: "7" };
    function escapeHtml(s) { return String(s); }
    function severityBadge(s) { return String(s); }
    function renderPanelError(sel, msg) { __errs.push([sel, msg]); }
    function slAnalystActiveFilter() { return { activeOnly: true, onlyInactive: false }; }
    function slTierWindowHours(d) { return d * 24; }`, Object.assign(ctx, { __errs: panelErrors }));
  for (const f of process.argv.slice(2)) vm.runInContext(fs.readFileSync(f, "utf8"), ctx, { filename: f });
  check("api.js, state.js e soc_team.js carregam", true);
} catch (e) {
  check(`carregamento: ${e && e.stack}`, false);
  process.exit(1);
}

const flush = () => new Promise((r) => setTimeout(r, 20));
(async () => {
  await flush();
  const bodies = ["analysts-body", "shifts-body", "escalation-body", "sla-breaches-body", "tier-summary-body", "oncall-list", "primary-list"];
  for (const id of bodies) {
    const txt = els[id].textContent;
    check(`${id}: não fica em «A carregar»`, !/A carregar/.test(txt));
    check(`${id}: sem «Failed to fetch»`, !/Failed to fetch/i.test(txt));
    check(`${id}: mostra o erro em PT com ação`, /Sem ligação ao backend/.test(txt));
  }
  const notices = ["analyst-notice", "shift-notice", "escalation-notice", "oncall-notice", "sla-breaches-notice", "tier-summary-notice"];
  for (const id of notices) {
    const t = els[id].textContent;
    check(`${id}: sem «A carregar» nem «Failed to fetch»`, !/A carregar|Failed to fetch/i.test(t) && /Sem ligação/.test(t));
  }
  check("banners de erro sem texto de exceção", panelErrors.length >= 3 && panelErrors.every((e) => !/Failed to fetch/i.test(e[1])));

  // 2xx vazio -> estado vazio, nunca «0»
  ctx.fetch = () => Promise.resolve({ ok: true, status: 200, json: async () => ({ shifts: [] }) });
  await ctx.loadShifts();
  check("sem turnos -> «Sem turnos.»", /Sem turnos\./.test(els["shifts-body"].textContent));
  // mutação a falhar: aviso em PT
  ctx.fetch = () => Promise.reject(new TypeError("Failed to fetch"));
  await ctx.deactivateAnalyst("a1", "Ana");
  check("desativar a falhar -> aviso seguro", /❌ Sem ligação/.test(els["analyst-notice"].textContent) && !/Failed to fetch/.test(els["analyst-notice"].textContent));

  if (failures.length) { console.log(`\n${failures.length} falha(s)`); process.exit(1); }
  console.log("\ntudo OK");
})().catch((e) => { console.log(`FALHOU: ${e && e.stack}`); process.exit(1); });
