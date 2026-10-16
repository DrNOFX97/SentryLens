"use strict";
// Teste Node de incidents.js (W3.2 + W3.4): router.js + incidents.js REAIS em
// node:vm, DOM mínimo e relógio/timers falsos.
// Uso: node test_lifecycle_incidents.cjs <router.js> <incidents.js>

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

const [routerPath, incPath] = process.argv.slice(2);

function makeEnv() {
  let t = 1000000;
  let nextId = 1;
  const timers = new Map(); // id -> {fn, ms, next, repeat}
  const listeners = {};
  const requests = [];
  const els = {};
  function makeEl() {
    return {
      value: "", textContent: "", innerHTML: "", hidden: false, disabled: false,
      dataset: {}, style: {}, children: [],
      classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
      addEventListener() {}, appendChild() {}, replaceChildren() {},
      setAttribute() {}, removeAttribute() {}, closest: () => null,
    };
  }
  const doc = {
    visibilityState: "visible",
    addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
    dispatch(type) { (listeners[type] || []).slice().forEach((fn) => fn({ type })); },
    createElement() { return makeEl(); },
    querySelector() { return null; },
    querySelectorAll() { return []; },
    getElementById(id) { return (els[id] = els[id] || makeEl()); },
  };
  els["period-select"] = Object.assign(makeEl(), { value: "7" });

  function add(fn, ms, repeat) {
    const id = nextId++;
    timers.set(id, { fn, ms, next: t + ms, repeat });
    return id;
  }
  const sandbox = {
    console,
    document: doc,
    Date: { now: () => t },
    URLSearchParams,
    setInterval: (fn, ms) => add(fn, ms, true),
    clearInterval: (id) => timers.delete(id),
    setTimeout: (fn, ms) => add(fn, ms, false),
    clearTimeout: (id) => timers.delete(id),
    apiRequest: async (path) => {
      requests.push(path);
      return { summary: {}, incidents: [], analysts: [] };
    },
    apiErrorMessage: (e) => String((e && e.message) || e),
    escapeHtml: (s) => String(s),
    severityBadge: (s) => String(s),
    formatTimestamp: (s) => String(s),
    renderPanelError() {},
    sttShowLoading() {}, sttShowError() {}, sttShowEmpty() {},
    periodSelect: els["period-select"],
  };
  return {
    sandbox, doc, requests,
    async advance(ms) {
      const end = t + ms;
      for (;;) {
        let due = null;
        for (const [id, tm] of timers) {
          if (tm.next <= end && (due === null || tm.next < timers.get(due).next)) due = id;
        }
        if (due === null) break;
        const tm = timers.get(due);
        t = tm.next;
        if (tm.repeat) tm.next += tm.ms; else timers.delete(due);
        tm.fn();
        for (let i = 0; i < 10; i++) await Promise.resolve();
      }
      t = end;
      for (let i = 0; i < 10; i++) await Promise.resolve();
    },
  };
}

function boot(visibility) {
  const env = makeEnv();
  env.doc.visibilityState = visibility;
  const ctx = vm.createContext(env.sandbox);
  try {
    vm.runInContext(fs.readFileSync(routerPath, "utf8"), ctx, { filename: "router.js" });
    vm.runInContext(fs.readFileSync(incPath, "utf8"), ctx, { filename: "incidents.js" });
  } catch (err) {
    check("router.js + incidents.js carregam: " + err.message, false);
    finish();
  }
  return { env, ctx };
}

const incReqs = (env) => env.requests.filter((p) => p.startsWith("/api/incidents?")).length;

(async () => {
  // 1. Nada corre ao carregar nem com a aba inativa; ativar carrega e faz polling.
  {
    const { env, ctx } = boot("visible");
    check("carregar o script não faz pedidos (aba não ativa)", env.requests.length === 0);
    await env.advance(120000);
    check("aba não ativa: 0 pedidos em 120 s", env.requests.length === 0);
    vm.runInContext('rtActivate("incidents")', ctx);
    await env.advance(0);
    check("rtActivate('incidents') carrega a lista", incReqs(env) === 1);
    await env.advance(31000);
    check("polling a cada 30 s com a aba ativa", incReqs(env) >= 2);
  }

  // 2. Documento escondido: 0 pedidos em 120 s, mesmo com aba ativa e alertas.
  {
    const { env, ctx } = boot("hidden");
    vm.runInContext('rtActivate("incidents")', ctx);
    await env.advance(120000);
    check("documento escondido: 0 pedidos em 120 s", env.requests.length === 0);
    for (let i = 0; i < 20; i++) env.doc.dispatch("sentrylens:new-alert");
    await env.advance(20000);
    check("documento escondido + alertas: 0 pedidos", env.requests.length === 0);
  }

  // 3. Aba desativada: sem pedidos por polling nem por alertas.
  {
    const { env, ctx } = boot("visible");
    vm.runInContext('rtActivate("incidents")', ctx);
    await env.advance(0);
    vm.runInContext("rtDeactivate()", ctx);
    const n = env.requests.length;
    for (let i = 0; i < 20; i++) env.doc.dispatch("sentrylens:new-alert");
    await env.advance(120000);
    check("aba desativada: 0 pedidos novos (polling e alertas)", env.requests.length === n);
  }

  // 4. 50 alertas em 2 s -> no máximo 1 a 2 refreshes.
  {
    const { env, ctx } = boot("visible");
    vm.runInContext('rtActivate("incidents")', ctx);
    await env.advance(1000);
    const base = incReqs(env);
    for (let i = 0; i < 50; i++) {
      env.doc.dispatch("sentrylens:new-alert");
      await env.advance(40); // 50 x 40 ms = 2 s
    }
    await env.advance(6000); // deixa o trailing correr (abaixo dos 30 s do polling)
    const extra = incReqs(env) - base;
    check(`50 alertas em 2 s -> 1 a 2 refreshes (houve ${extra})`, extra >= 1 && extra <= 2);
    const n = env.requests.length;
    await env.advance(5000);
    check("sem alertas novos, não há refresh extra", env.requests.length === n);
  }

  finish();
})();
