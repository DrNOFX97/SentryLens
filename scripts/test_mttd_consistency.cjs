"use strict";
// Prova que Overview, Incidentes, Red vs Blue e Métricas renderizam o MESMO MTTD
// (valor, rótulo e sub) para os mesmos dados de GET /api/metrics, e que os 4
// pedem a mesma janela. Carrega os módulos REAIS num node:vm com um DOM falso.
//
// Uso: node test_mttd_consistency.cjs <raiz-do-frontend>

const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const failures = [];
function check(label, condition) {
  console.log(`[${condition ? "OK   " : "FALHOU"}] ${label}`);
  if (!condition) failures.push(label);
}

const root = process.argv[2];

class El {
  constructor(id, parent) {
    this.id = id; this.parentElement = parent || null; this.textContent = ""; this.children = [];
    this.dataset = {}; this.hidden = false; this.value = ""; this.className = "";
    this.classList = { contains: () => false, add() {}, remove() {}, toggle() {} };
    this._h3 = null;
  }
  addEventListener() {}
  appendChild(c) { c.parentElement = this; this.children.push(c); return c; }
  replaceChildren() {}
  querySelector(sel) {
    if (sel === "h3") { this._h3 = this._h3 || new El("h3", this); return this._h3; }
    if (sel === ".ovw-kpi-sub") return this.children.find((c) => c.className === "ovw-kpi-sub") || null;
    return null;
  }
  querySelectorAll() { return []; }
  closest() { return null; }
}

const els = new Map();
function getEl(id) {
  if (!els.has(id)) els.set(id, new El(id, new El(id + "-card", null)));
  return els.get(id);
}

const requested = [];
const fixtures = {};
const sandbox = {
  console, URLSearchParams, Date, Math, Number, String, Object, Array, Promise, JSON, encodeURIComponent, Map,
  document: {
    getElementById: getEl, addEventListener() {}, visibilityState: "hidden",
    querySelector: () => null, querySelectorAll: () => [],
    createElement: (tag) => new El(tag, null),
  },
  MutationObserver: class { observe() {} },
  setInterval() {}, setTimeout() {}, clearTimeout() {},
  WebSocket: { OPEN: 1 },
  API_BASE: "http://127.0.0.1:8001", API_KEY: "k",
  periodSelect: { value: "7", addEventListener() {} },
  apiRequest: async (p) => {
    requested.push(p);
    const key = Object.keys(fixtures).find((k) => p.startsWith(k));
    if (!key) throw new Error("sem fixture para " + p);
    const v = fixtures[key];
    if (v instanceof Error) throw v;
    return v;
  },
  apiErrorMessage: (e) => String(e && e.message),
  renderPanelError() {}, severityBadge: () => "", formatTimestamp: (t) => String(t),
  htmlT: (s, ...v) => s.reduce((a, x, i) => a + x + (i < v.length ? v[i] : ""), ""),
  htmlRaw: (x) => x, htmRender() {},
  sttShowLoading() {}, sttShowError() {}, sttShowEmpty() {},
  activateTab() {}, renderBluePanel() {}, renderRedPanel() {},
  rtRegisterTab: () => ({ isActive: () => false, isVisible: () => false, refresh() {} }),
};
sandbox.window = sandbox;
vm.createContext(sandbox);

for (const f of ["ui_helpers.js", "overview.js", "redblue.js", "incidents.js", "metrics.js"]) {
  try {
    vm.runInContext(fs.readFileSync(path.join(root, f), "utf-8"), sandbox, { filename: f });
    check(`${f} carrega sem erro`, true);
  } catch (e) {
    check(`${f} carrega sem erro (${e.message})`, false);
  }
}
const run = (code) => vm.runInContext(code, sandbox);

function cardLabel(id) {
  return getEl(id).parentElement.querySelector("h3").textContent;
}
function cardSub(id) {
  const s = getEl(id).parentElement.querySelector(".ovw-kpi-sub");
  return s ? s.textContent : null;
}

function panels(metrics, error) {
  const val = (id) => getEl(id).textContent;
  sandbox.__m = metrics; sandbox.__e = error;
  run("ovwRenderMttdKpi(__m, __e)");
  run("incRenderMttdKpi(__m, __e)");
  run("rbRenderMttdKpi(__m, __e)");
  if (metrics) run("metRenderMttd(__m)");
  const out = {
    overview: { v: val("ovw-kpi-mttd"), l: cardLabel("ovw-kpi-mttd"), s: val("ovw-kpi-mttd-sub") },
    incidents: { v: val("kpi-inc-mttd"), l: cardLabel("kpi-inc-mttd"), s: cardSub("kpi-inc-mttd") },
    redblue: { v: val("kpi-rb-mttd"), l: cardLabel("kpi-rb-mttd"), s: cardSub("kpi-rb-mttd") },
  };
  if (metrics) out.metrics = { v: val("met-mttd-median"), l: cardLabel("met-mttd-median"), s: null };
  return out;
}

function sameAll(out, label) {
  const names = Object.keys(out);
  const ref = out[names[0]];
  for (const n of names) {
    check(`${label}: valor igual em ${n} (${out[n].v})`, out[n].v === ref.v);
    check(`${label}: rótulo igual em ${n} (${out[n].l})`, out[n].l === ref.l);
    if (out[n].s !== null && n !== "metrics") check(`${label}: sub igual em ${n}`, out[n].s === ref.s);
  }
}

const base = { window_hours: 168, alerts_truncated: false, mttr: {}, coverage: {}, rate: {}, definitions: {} };

// 1) Com amostra: mediana 20 s (n=3), não a média das tentativas.
let out = panels({ ...base, mttd: { available: true, n: 3, small_sample: true, median_s: 20, p90_s: 90, avg_s: 36.7, by_scenario: {} } }, false);
sameAll(out, "com amostra");
check("com amostra: mostra 20.0 s", out.overview.v === "20.0 s");
check("com amostra: rótulo diz mediana e 7 dias", out.overview.l === "MTTD (mediana, 7 dias)");

// 2) Duração longa: mesmo formato nos 4 (antes havia 3 formatadores diferentes).
out = panels({ ...base, mttd: { available: true, n: 9, small_sample: false, median_s: 4500, p90_s: 5000, avg_s: 4500, by_scenario: {} } }, false);
sameAll(out, "75 min");
check("75 min formatado como 1 h 15 min nos 4", Object.values(out).every((p) => p.v === "1 h 15 min"));

// 3) Sem amostra: "—" nos 4, nunca 0.
out = panels({ ...base, mttd: { available: false, reason: "no_data", n: 0, median_s: null, by_scenario: {} } }, false);
sameAll(out, "sem amostra");
check("sem amostra: «—» e nunca 0", Object.values(out).every((p) => p.v === "—"));

// 4) Fonte indisponível e pedido falhado.
out = panels({ ...base, mttd: { available: false, reason: "source_unavailable", n: 0, median_s: null, by_scenario: {} } }, false);
sameAll(out, "fonte indisponível");
out = panels(null, true);
check("pedido falhado: «—» nos 3 painéis com estado de erro", ["overview", "incidents", "redblue"].every((k) => out[k].v === "—"));

// 5) Alertas truncados: aviso igual.
out = panels({ ...base, alerts_truncated: true, mttd: { available: true, n: 6, small_sample: false, median_s: 12, by_scenario: {} } }, false);
sameAll(out, "truncado");
check("truncado: sub avisa limite inferior", /limite inferior/.test(out.incidents.s));

// 6) Os 4 pedem a MESMA janela de /api/metrics, via os fluxos reais.
fixtures["/api/metrics"] = { ...base, mttd: { available: true, n: 3, small_sample: true, median_s: 20, by_scenario: {} },
  coverage: { available: false }, rate: { available: false } };
fixtures["/api/redblue/metrics"] = { overall: { total_attempts: 0 }, attempts: [], by_scenario: {}, alerts_fetched: 0 };
fixtures["/api/incidents"] = { summary: { open: 0, high_or_critical_open: 0, total: 0, avg_mttd_seconds: 999 }, incidents: [] };
fixtures["/api/siem/health"] = new Error("n/a");
fixtures["/api/vaccines"] = new Error("n/a");
requested.length = 0;
(async () => {
  try {
    await run("loadRedBlueMetrics()");
    await run("incLoadMttd()");
    await run("refreshMetrics()");
    await run("ovwRefresh()");
  } catch (e) {
    check("fluxos de carregamento correram (" + e.message + ")", false);
  }
  const metricCalls = requested.filter((p) => p.startsWith("/api/metrics"));
  check(`4 painéis pedem /api/metrics (${metricCalls.length})`, metricCalls.length >= 4);
  check("todos com a mesma janela hours=168", metricCalls.every((p) => p === "/api/metrics?hours=168"));
  check("Incidentes não usa o avg_mttd_seconds do resumo (999)", getEl("kpi-inc-mttd").textContent === "20.0 s");
  check("Red vs Blue após o fluxo real mostra 20.0 s", getEl("kpi-rb-mttd").textContent === "20.0 s");
  check("Métricas após o fluxo real mostra 20.0 s", getEl("met-mttd-median").textContent === "20.0 s");
  check("Overview após o fluxo real mostra 20.0 s", getEl("ovw-kpi-mttd").textContent === "20.0 s");

  if (failures.length) {
    console.log(`\n[FALHOU] ${failures.length} teste(s) falharam`);
    process.exit(1);
  }
  console.log("\n[OK] Todos os testes passaram");
})();
