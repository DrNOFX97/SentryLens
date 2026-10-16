"use strict";
// Teste node:vm do ciclo de vida das abas em shell.js (W3.2): router.js REAL +
// o bloco "Ciclo de vida das abas" do shell.js REAL, com timers/relógio falsos.
// Uso: node test_lifecycle_app.cjs <raiz-do-repo>
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const root = process.argv[2];
const failures = [];
function check(l, c) { console.log(`[${c ? "OK   " : "FALHOU"}] ${l}`); if (!c) failures.push(l); }
const read = (f) => fs.readFileSync(path.join(root, f), "utf8").split(String.fromCharCode(13)).join("");

const app = read("shell.js");
const m = app.match(/\/\/ --- Ciclo de vida das abas \(W3\.2\) ---[\s\S]*?\/\/ --- fim do ciclo de vida das abas ---/);
check("shell.js tem o bloco de ciclo de vida delimitado", !!m);
if (!m) { process.exit(1); }

function makeEnv(visibility) {
  let t = 0, nextId = 1;
  const timers = new Map();
  const listeners = [];
  const requests = [];
  const document = {
    visibilityState: visibility,
    addEventListener(type, fn) { if (type === "visibilitychange") listeners.push(fn); },
  };
  const rec = (name) => () => { requests.push(name); return Promise.resolve(); };
  const ctx = {
    console, Promise, Math, Number, document,
    Date: { now: () => t },
    setInterval: (fn, ms) => { const id = nextId++; timers.set(id, { fn, ms, next: t + ms }); return id; },
    clearInterval: (id) => { timers.delete(id); },
    periodSelect: { value: "7" }, windowSelect: { value: "24" }, severityFilter: { value: "" },
    refreshHeaderStatus: rec("header"),
    loadAlerts: rec("alerts"), loadAgents: rec("agents"), loadSystemPanel: rec("system"),
    loadLifecyclePanel: rec("lifecycle"), loadPrivilegesPanel: rec("privileges"),
    loadAdminActivityPanel: rec("admin-activity"), loadMlAnomaliesPanel: rec("ml-anomalies"),
    loadCompliancePanel: rec("compliance"),
  };
  vm.createContext(ctx);
  vm.runInContext(read("router.js") + "\nthis.rtRouter=rtRouter;this.rtActivate=rtActivate;this.rtDeactivate=rtDeactivate;this.rtRegisterTab=rtRegisterTab;", ctx);
  vm.runInContext(m[0] + "\nthis.appCurrentTabId=appCurrentTabId;", ctx);
  return {
    ctx, requests,
    setVisibility(v) { document.visibilityState = v; listeners.forEach((fn) => fn()); },
    advance(ms) {
      const end = t + ms;
      for (;;) {
        let due = null;
        for (const [id, tm] of timers) if (tm.next <= end && (due === null || tm.next < timers.get(due).next)) due = id;
        if (due === null) break;
        const tm = timers.get(due); t = tm.next; tm.next += tm.ms; tm.fn();
      }
      t = end;
    },
  };
}

// 1) Página escondida: 0 pedidos em 120 s, mesmo com uma aba ativada.
{
  const e = makeEnv("hidden");
  e.ctx.rtActivate("lifecycle");
  e.ctx.rtActivate("alerts");
  e.advance(120000);
  check("hidden: 0 pedidos em 120 s", e.requests.length === 0);
}

// 2) Overview visível (nenhuma aba de shell.js ativa): só o cabeçalho, <= 4 pedidos / 30 s.
{
  const e = makeEnv("visible");
  e.ctx.rtActivate("overview");
  e.advance(30000);
  check(`overview visível: <= 4 pedidos em 30 s (${e.requests.length})`, e.requests.length <= 4);
  check("overview visível: o cabeçalho corre", e.requests.includes("header"));
}

// 3) Aba de shell.js ativa: só os pedidos dessa aba; trocar pára a anterior.
{
  const e = makeEnv("visible");
  e.ctx.rtActivate("lifecycle");
  e.advance(30000);
  check("lifecycle ativa: carrega só lifecycle (+ cabeçalho)", e.requests.filter((r) => r !== "header").every((r) => r === "lifecycle") && e.requests.includes("lifecycle"));
  check(`lifecycle ativa: <= 4 pedidos em 30 s (${e.requests.length})`, e.requests.length <= 4);
  e.requests.length = 0;
  e.ctx.rtActivate("privileges");
  e.advance(30000);
  check("trocar de aba pára a anterior", !e.requests.includes("lifecycle") && e.requests.includes("privileges"));
  e.requests.length = 0;
  e.ctx.rtDeactivate();
  e.advance(60000);
  check("rtDeactivate: só o cabeçalho continua", e.requests.every((r) => r === "header"));
}

// 4) Cabeçalho pára ao esconder e retoma com refresh imediato ao voltar.
{
  const e = makeEnv("visible");
  e.setVisibility("hidden");
  e.advance(120000);
  check("cabeçalho pára com a página escondida", e.requests.length === 0);
  e.setVisibility("visible");
  check("voltar a visível: refresh imediato do cabeçalho", e.requests.filter((r) => r === "header").length === 1);
  e.advance(30000);
  check("voltar a visível: retoma o intervalo", e.requests.filter((r) => r === "header").length === 2);
}

// 5) Todos os ids registados existem como data-tab no index.html; shell.js não deixa setIntervals soltos de painéis.
{
  const html = read("index.html");
  const ids = [...m[0].matchAll(/id: "([a-z-]+)"/g)].map((x) => x[1]);
  check("8 abas registadas", ids.length === 8);
  check("ids = data-tab do nav", ids.every((id) => html.includes(`data-tab="${id}"`)));
  check("overview não é registado em shell.js", !ids.includes("overview"));
  check("refreshNewPanels já não tem setInterval", !/setInterval\(refreshNewPanels/.test(["app.js", "shell.js", "iam.js", "ml-anomalies.js", "compliance.js", "overview-alerts.js", "system.js", "realtime.js"].map(read).join("\n")));
}

if (failures.length) { console.log(`\n[FALHOU] ${failures.length} teste(s) falharam`); process.exit(1); }
console.log("\n[OK] Todos os testes passaram");
