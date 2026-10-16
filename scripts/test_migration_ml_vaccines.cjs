"use strict";
// Migração W2 de ml_models.js, ml_evaluation.js e vaccines.js para apiRequest
// e state.js. Com fetch a rejeitar (backend em baixo) ou a devolver erro, o
// painel não pode ficar em «A carregar» nem mostrar «Failed to fetch».
// Uso: node test_migration_ml_vaccines.cjs <pasta-da-raiz-do-frontend>
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const root = process.argv[2];
const read = (f) => fs.readFileSync(path.join(root, f), "utf8");
const failures = [];
function check(label, cond) {
  console.log(`[${cond ? "OK   " : "FALHOU"}] ${label}`);
  if (!cond) failures.push(label);
}

function makeEl(id) {
  const el = {
    id, children: [], _text: "", _html: "", className: "", value: "", checked: false,
    hidden: false, dataset: {}, style: {}, attrs: {}, colSpan: 0,
    classList: { contains: () => false, add() {}, remove() {}, toggle() {} },
    setAttribute(k, v) { this.attrs[k] = v; },
    addEventListener() {}, appendChild(c) { this.children.push(c); return c; },
    replaceChildren(...c) { this.children = c; this._html = ""; this._text = ""; },
    querySelector: () => null, querySelectorAll: () => [], closest: () => null, remove() {},
    get textContent() { return this._text; }, set textContent(v) { this._text = String(v); this.children = []; },
    get innerHTML() { return this._html; }, set innerHTML(v) { this._html = String(v); this.children = []; },
  };
  return el;
}
function allText(el) {
  return [el._text, el._html, ...el.children.map(allText)].join(" ");
}
function classes(el) {
  return [el.className, ...el.children.map(classes)].join(" ");
}

function makeCtx(fetchImpl) {
  const els = {};
  const doc = {
    visibilityState: "visible",
    getElementById: (id) => (els[id] = els[id] || makeEl(id)),
    querySelector: () => null, querySelectorAll: () => [],
    createElement: () => makeEl("new"), addEventListener() {},
  };
  const ctx = vm.createContext({
    console, setTimeout, clearTimeout, AbortController, JSON, Promise, Set, URLSearchParams,
    MutationObserver: class { observe() {} },
    document: doc, fetch: fetchImpl,
    escapeHtml: (v) => String(v == null ? "" : v).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"),
    renderPanelError: () => {},
  });
  vm.runInContext('const API_BASE = "http://x:1"; const API_KEY = "k";', ctx);
  for (const f of ["api.js", "state.js", "ml_models.js", "ml_evaluation.js"]) {
    vm.runInContext(read(f), ctx, { filename: f });
  }
  return { ctx, els };
}

const BAD = [
  ["fetch rejeita (TypeError: Failed to fetch)", () => Promise.reject(new TypeError("Failed to fetch"))],
  ["HTTP 502 com detail em texto livre", async () => ({ ok: false, status: 502, json: async () => ({ detail: "Boom: Traceback /etc/x" }) })],
];

(async () => {
  for (const [nome, impl] of BAD) {
    const { ctx, els } = makeCtx(impl);
    await vm.runInContext("mlmRefresh(true)", ctx);
    const body = els["mlm-models-body"];
    const txt = allText(body);
    check(`Models, ${nome}: sai de «A carregar»`, !/A carregar/.test(txt) && vm.runInContext("mlmLoading", ctx) === false);
    check(`Models, ${nome}: sem «Failed to fetch» nem texto de exceção`, !/Failed to fetch|Traceback|Boom/.test(txt));
    check(`Models, ${nome}: error-state com ação em PT`, /error-state/.test(classes(body)) && /backend|Wazuh|API key/i.test(txt));

    await vm.runInContext("mleRefresh()", ctx);
    await new Promise((r) => setTimeout(r, 5));
    const eb = allText(els["mlm-eval-body"]) + allText(els["mle-live-body"]) + els["mle-live-notice"].textContent;
    check(`Evaluation, ${nome}: sem «A carregar», «Failed to fetch» nem exceção`, !/A carregar|Failed to fetch|Traceback|Boom/.test(eb));
    check(`Evaluation, ${nome}: erro visível nas duas zonas`,
      /error-state/.test(classes(els["mlm-eval-body"])) && /error-state/.test(classes(els["mle-live-body"])));

    await vm.runInContext("mlmDoTrain()", ctx);
    const tr = els["mlm-train-result"].textContent;
    check(`Treino, ${nome}: mensagem PT sem «Failed to fetch»`, /Não foi possível treinar/.test(tr) && !/Failed to fetch|Traceback|Boom/.test(tr));
    check(`Treino, ${nome}: botão volta a ficar ativo`, els["mlm-train-button"].disabled === false);
  }

  // Vaccines: carrega o ficheiro inteiro (liga listeners no topo).
  for (const [nome, impl] of BAD) {
    const { ctx, els } = makeCtx(impl);
    vm.runInContext(read("vaccines.js"), ctx, { filename: "vaccines.js" });
    await vm.runInContext("vacRefresh()", ctx);
    await new Promise((r) => setTimeout(r, 5));
    const txt = allText(els["vac-body"]);
    check(`Vaccines, ${nome}: sem «A carregar», «Failed to fetch» nem exceção`, !/A carregar|Failed to fetch|Traceback|Boom/.test(txt));
    check(`Vaccines, ${nome}: linha vac-error-state com mensagem`, /vac-error-state/.test(classes(els["vac-body"].children[0] || makeEl())) && txt.trim().length > 20);
    check(`Vaccines, ${nome}: vacLoading volta a false`, vm.runInContext("vacLoading", ctx) === false);
  }

  // Caminho feliz continua a funcionar e põe a chave.
  let seen = null;
  const ok = async (url, opt) => { seen = { url, opt }; return { ok: true, status: 200, json: async () => ({ versions: [], active: null, loaded: null }) }; };
  const { ctx } = makeCtx(ok);
  const r = await vm.runInContext('mlmRequest("/api/ml/models")', ctx);
  check("mlmRequest feliz: URL e X-API-Key via apiRequest", seen.url === "http://x:1/api/ml/models" && seen.opt.headers["X-API-Key"] === "k" && Array.isArray(r.versions));

  if (failures.length) process.exitCode = 1;
  else console.log("\n[OK] Todos os testes Node passaram");
})();
