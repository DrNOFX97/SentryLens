"use strict";
// Migração para apiRequest (attack_registry, attack_library, live_soc, overview):
// com fetch a rejeitar, nenhum painel fica em «A carregar» nem mostra «Failed to fetch».
// Uso: node test_migration_core.cjs <raiz do repo>
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const root = process.argv[2];
const failures = [];
const check = (l, c) => { console.log(`[${c ? "OK   " : "FALHOU"}] ${l}`); if (!c) failures.push(l); };

const out = []; // tudo o que chega ao DOM como texto/HTML
function makeEl() {
  const store = { classList: { contains: () => false, toggle() {}, add() {}, remove() {} }, dataset: {}, value: "", className: "", style: {}, children: [] };
  return new Proxy(store, {
    get(t, k) {
      if (k in t) return t[k];
      if (k === "querySelector") return () => null;
      if (k === "querySelectorAll") return () => [];
      if (k === "closest") return () => null;
      if (k === "parentElement") return (t.parentElement = makeEl());
      return () => {};
    },
    set(t, k, v) { t[k] = v; if (k === "textContent" || k === "innerHTML") out.push(String(v)); return true; },
  });
}
const els = {};
const document = {
  getElementById: (id) => (els[id] = els[id] || makeEl()),
  querySelector: () => null, querySelectorAll: () => [],
  createElement: () => makeEl(), addEventListener() {}, visibilityState: "hidden",
};
const ctx = vm.createContext({
  console, setTimeout, clearTimeout, setInterval: () => 0, AbortController, JSON, Promise, URLSearchParams, Date, Math, Number, String, Array, Object,
  document, MutationObserver: class { observe() {} },
  fetch: () => Promise.reject(new TypeError("Failed to fetch")),
  activateTab() {}, windowSelect: (() => { const e = makeEl(); e.value = "168"; return e; })(),
});
vm.runInContext(`const API_BASE = "http://x:1"; const API_KEY = "k";
function escapeHtml(v){return String(v).replace(/[&<>"']/g,c=>"&#"+c.charCodeAt(0)+";");}
function renderPanelError(sel,msg){ __out(msg); }
function formatTimestamp(v){return String(v);}`, Object.assign(ctx, { __out: (m) => out.push(String(m)) }));
for (const f of ["html.js", "ui_helpers.js", "api.js", "state.js", "attack_registry.js", "attack_library.js", "live_soc.js", "overview.js"]) {
  try { vm.runInContext(fs.readFileSync(path.join(root, f), "utf8"), ctx, { filename: f }); }
  catch (e) { check(`carrega ${f}: ${e && e.message}`, false); process.exit(1); }
}
check("os 4 ficheiros carregam", true);

for (const f of ["attack_registry.js", "attack_library.js", "live_soc.js", "overview.js"]) {
  const src = fs.readFileSync(path.join(root, f), "utf8");
  check(`${f} não usa fetch próprio`, !/\bfetch\(/.test(src));
  check(`${f} não mostra err.message em bruto`, !/err\.message/.test(src));
}

(async () => {
  const calls = {
    refreshAttacks: () => ctx.refreshAttacks(),
    refreshAttackLibrary: () => ctx.refreshAttackLibrary(),
    lsRefreshHealth: () => ctx.lsRefreshHealth(),
    lsLoadInitialFeed: () => ctx.lsLoadInitialFeed(),
    ovwRefresh: () => ctx.ovwRefresh(),
    selectAttack: () => ctx.selectAttack(1),
    selectAttackLibraryEntry: () => ctx.selectAttackLibraryEntry("x"),
  };
  for (const [name, fn] of Object.entries(calls)) {
    out.length = 0;
    let threw = null;
    try { await fn(); } catch (e) { threw = e; }
    const text = out.join("\n");
    check(`${name}: não rebenta com fetch a rejeitar`, !threw);
    check(`${name}: sem «Failed to fetch» no DOM`, !/Failed to fetch/i.test(text));
    check(`${name}: não fica em «A carregar»`, !/A carregar/.test(text) || name === "ovwRefresh");
    if (name !== "ovwRefresh") check(`${name}: mostra mensagem em PT do backend`, /Sem ligação ao backend/.test(text));
  }
  // overview: KPIs mostram «Fonte indisponível» e «—», nunca 0
  out.length = 0; await ctx.ovwRefresh();
  const t = out.join("\n");
  check("overview: erro -> «Fonte indisponível» e sem «A carregar…»", /Fonte indisponível/.test(t) && !/A carregar…/.test(t));
  if (failures.length) { console.log(`\n[FALHOU] ${failures.length}`); process.exit(1); }
  console.log("\n[OK] Todos os testes passaram");
})();
