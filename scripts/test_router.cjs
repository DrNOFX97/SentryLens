"use strict";
// Teste Node de router.js (W3.1): carrega o ficheiro REAL em node:vm, sem DOM,
// com relógio e timers falsos. Uso: node test_router.cjs <caminho-de-router.js>

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

const routerPath = process.argv[2];
if (!routerPath) {
  check("caminho de router.js passado como argumento", false);
  finish();
}

// Relógio e timers falsos.
function makeEnv() {
  let t = 0;
  let nextId = 1;
  const timers = new Map(); // id -> {fn, ms, next}
  const listeners = [];
  const doc = {
    visibilityState: "visible",
    addEventListener(type, fn) { if (type === "visibilitychange") listeners.push(fn); },
  };
  const env = {
    doc,
    now: () => t,
    setIntervalFn: (fn, ms) => { const id = nextId++; timers.set(id, { fn, ms, next: t + ms }); return id; },
    clearIntervalFn: (id) => { timers.delete(id); },
    activeTimers: () => timers.size,
    setVisibility(v) {
      doc.visibilityState = v;
      listeners.forEach((fn) => fn());
    },
    advance(ms) {
      const end = t + ms;
      for (;;) {
        let due = null;
        for (const [id, tm] of timers) {
          if (tm.next <= end && (due === null || tm.next < timers.get(due).next)) due = id;
        }
        if (due === null) break;
        const tm = timers.get(due);
        t = tm.next;
        tm.next += tm.ms;
        tm.fn();
      }
      t = end;
    },
  };
  return env;
}

function loadRouter() {
  const ctx = vm.createContext({ console });
  let code;
  try {
    code = fs.readFileSync(routerPath, "utf8");
    vm.runInContext(code, ctx, { filename: "router.js" });
    check("router.js carrega sem DOM no topo", true);
  } catch (err) {
    check("router.js carrega sem DOM no topo: " + err.message, false);
    finish();
  }
  return ctx;
}

const ctx = loadRouter();
check("expõe rtCreateRouter", typeof ctx.rtCreateRouter === "function");
check("expõe rtRegisterTab/rtActivate/rtDeactivate",
  typeof ctx.rtRegisterTab === "function" && typeof ctx.rtActivate === "function" && typeof ctx.rtDeactivate === "function");

function setup(visibility) {
  const env = makeEnv();
  if (visibility) env.doc.visibilityState = visibility;
  const r = ctx.rtCreateRouter(env);
  let calls = 0;
  let hides = 0;
  r.registerTab({ id: "a", load: () => { calls++; }, refreshMs: 10000, onHide: () => { hides++; } });
  let callsB = 0;
  r.registerTab({ id: "b", load: () => { callsB++; }, refreshMs: 10000 });
  return { env, r, calls: () => calls, callsB: () => callsB, hides: () => hides };
}

// 1. Documento escondido: 0 pedidos em 120 s.
{
  const s = setup("hidden");
  s.r.activate("a");
  s.env.advance(120000);
  check("hidden: 0 pedidos em 120 s", s.calls() === 0);
  check("hidden: nenhum intervalo ativo", s.env.activeTimers() === 0);
}

// 2. Visível, refreshMs=10000: no máximo 4 pedidos em 30 s.
{
  const s = setup();
  s.r.activate("a");
  s.env.advance(30000);
  check("visível: <= 4 pedidos em 30 s (obtido " + s.calls() + ")", s.calls() >= 1 && s.calls() <= 4);
  check("visível: 1 load imediato + 1 por intervalo (4)", s.calls() === 4);
}

// 3. Aba inativa não corre.
{
  const s = setup();
  s.r.activate("a");
  s.env.advance(30000);
  check("aba inativa b: 0 pedidos", s.callsB() === 0);
  s.r.activate("b");
  s.env.advance(30000);
  const aAfter = s.calls();
  s.env.advance(60000);
  check("trocar de aba pára a anterior (onHide chamado, sem mais loads)", s.hides() === 1 && s.calls() === aAfter);
  check("a nova aba corre", s.callsB() >= 4);
  check("só um intervalo ativo", s.env.activeTimers() === 1);
}

// 4. Esconder pára, voltar visível retoma.
{
  const s = setup();
  s.r.activate("a");
  s.env.advance(10000);
  const before = s.calls();
  s.env.setVisibility("hidden");
  check("esconder pára o intervalo e chama onHide", s.env.activeTimers() === 0 && s.hides() === 1);
  s.env.advance(120000);
  check("0 pedidos adicionais enquanto escondido", s.calls() === before);
  s.env.setVisibility("visible");
  check("voltar visível após >= refreshMs: refresh imediato", s.calls() === before + 1);
  s.env.advance(10000);
  check("e retoma o intervalo", s.calls() === before + 2 && s.env.activeTimers() === 1);
}

// 5. Voltar visível cedo (< refreshMs) não faz refresh imediato.
{
  const s = setup();
  s.r.activate("a");
  const before = s.calls();
  s.env.advance(3000);
  s.env.setVisibility("hidden");
  s.env.advance(2000);
  s.env.setVisibility("visible");
  check("visível < refreshMs desde o último load: sem refresh imediato", s.calls() === before);
}

// 6. Ativar com documento escondido e depois mostrar: carrega ao ficar visível.
{
  const s = setup("hidden");
  s.r.activate("a");
  s.env.advance(5000);
  s.env.setVisibility("visible");
  check("ativada escondida: load ao ficar visível", s.calls() === 1);
}

// 7. Load assíncrono pendente não se sobrepõe; erros não matam o intervalo.
{
  const env = makeEnv();
  const errors = [];
  const r = ctx.rtCreateRouter(Object.assign({}, env, { onError: (e) => errors.push(e) }));
  let n = 0;
  let release = null;
  r.registerTab({ id: "slow", refreshMs: 1000, load: () => { n++; return new Promise((res) => { release = res; }); } });
  r.activate("slow");
  env.advance(5000);
  check("load pendente não se sobrepõe", n === 1);
  let m = 0;
  r.registerTab({ id: "bad", refreshMs: 1000, load: () => { m++; throw new Error("x"); } });
  r.activate("bad");
  env.advance(3000);
  check("load que lança é reportado e o intervalo continua", errors.length === m && m === 4);
}

// 8. Validação de registerTab.
{
  const r = ctx.rtCreateRouter(makeEnv());
  let threw = 0;
  try { r.registerTab({ load: () => {} }); } catch (e) { threw++; }
  try { r.registerTab({ id: "x" }); } catch (e) { threw++; }
  r.registerTab({ id: "dup", load: () => {} });
  try { r.registerTab({ id: "dup", load: () => {} }); } catch (e) { threw++; }
  check("registerTab rejeita id em falta, load em falta e id repetido", threw === 3);
}

finish();
