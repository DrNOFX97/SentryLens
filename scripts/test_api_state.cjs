"use strict";
// Teste Node de api.js e state.js em node:vm (sem browser).
// Uso: node test_api_state.cjs <api.js> <state.js>
const fs = require("node:fs");
const vm = require("node:vm");

const failures = [];
function check(label, cond) {
  console.log(`[${cond ? "OK   " : "FALHOU"}] ${label}`);
  if (!cond) failures.push(label);
}

// DOM falso mínimo
function makeEl() {
  return {
    children: [], attrs: {}, className: "", textContent: "",
    setAttribute(k, v) { this.attrs[k] = v; },
    replaceChildren(...c) { this.children = c; },
  };
}
const fakeDocument = { createElement: () => makeEl() };

let fetchImpl;
const ctx = vm.createContext({
  console, setTimeout, clearTimeout, AbortController, JSON, Promise,
  document: fakeDocument,
  fetch: (...a) => fetchImpl(...a),
});
try {
  vm.runInContext('const API_BASE = "http://x:1"; const API_KEY = "k1";', ctx);
  for (const f of process.argv.slice(2)) vm.runInContext(fs.readFileSync(f, "utf8"), ctx, { filename: f });
  check("api.js e state.js carregam sem window e sem tocar no DOM no topo", true);
} catch (e) {
  check(`carregamento: ${e && e.message}`, false);
  process.exit(1);
}

ctx.ApiError = vm.runInContext("ApiError", ctx);
const jsonRes = (status, data) => ({
  ok: status >= 200 && status < 300, status,
  json: async () => { if (data === undefined) throw new Error("sem corpo"); return data; },
});
async function errOf(p) { try { await p; return null; } catch (e) { return e; } }

(async () => {
  let seen;
  fetchImpl = async (url, init) => { seen = { url, init }; return jsonRes(200, { a: 1 }); };
  const ok = await ctx.apiRequest("/api/x");
  check("sucesso devolve o JSON", ok.a === 1);
  check("URL = API_BASE + path (lido em runtime)", seen.url === "http://x:1/api/x");
  check("envia X-API-Key", seen.init.headers["X-API-Key"] === "k1");
  check("GET sem body não manda Content-Type", !("Content-Type" in seen.init.headers) && seen.init.body === undefined);
  await ctx.apiRequest("/api/y", { method: "POST", body: { n: 2 } });
  check("POST com body JSON", seen.init.method === "POST" && seen.init.body === '{"n":2}' && seen.init.headers["Content-Type"] === "application/json");

  fetchImpl = async () => jsonRes(204);
  check("204 -> null", (await ctx.apiRequest("/z")) === null);
  fetchImpl = async () => jsonRes(200, undefined);
  let e = await errOf(ctx.apiRequest("/z"));
  check("200 com corpo ilegível -> invalid_response", e && e.code === "invalid_response");

  fetchImpl = async () => { throw new TypeError("Failed to fetch"); };
  e = await errOf(ctx.apiRequest("/z"));
  check("rede -> network_error, status 0, ApiError", e && e.code === "network_error" && e.status === 0 && e.name === "ApiError" && e instanceof ctx.ApiError);
  check("mensagem de rede em PT com ação", /start-backend/.test(e.message));

  fetchImpl = (url, init) => new Promise((_, rej) => init.signal.addEventListener("abort", () => rej({ name: "AbortError" })));
  e = await errOf(ctx.apiRequest("/z", { timeoutMs: 20 }));
  check("timeout (abort pelo temporizador) -> timeout", e && e.code === "timeout" && e.status === 0);
  check("mensagem de timeout menciona 15 s", /15 s/.test(e.message));
  fetchImpl = async () => { const x = new Error("t"); x.name = "TimeoutError"; throw x; };
  e = await errOf(ctx.apiRequest("/z"));
  check("TimeoutError nativo -> timeout", e && e.code === "timeout");

  fetchImpl = async () => jsonRes(401, { detail: "Invalid API key <script>" });
  e = await errOf(ctx.apiRequest("/z"));
  check("401 -> unauthorized", e && e.code === "unauthorized" && e.status === 401 && /SENTRYLENS_API_KEY/.test(e.message));
  check("401 não mostra o detail em bruto", !/<script|Invalid API/.test(e.message));

  fetchImpl = async () => jsonRes(422, { detail: [{ loc: ["query", "hours"], msg: "<img onerror=x>", type: "int" }] });
  e = await errOf(ctx.apiRequest("/z"));
  check("422 com array -> validation_error", e && e.code === "validation_error" && e.status === 422);
  check("422 não vaza msg do array", !/img|onerror|hours/.test(e.message));

  fetchImpl = async () => jsonRes(422, { detail: "texto livre inseguro" });
  e = await errOf(ctx.apiRequest("/z"));
  check("422 com string insegura -> validation_error", e && e.code === "validation_error" && !/inseguro/.test(e.message));

  fetchImpl = async () => jsonRes(502, { detail: "Erro ao ligar ao Wazuh: https://10.0.0.5:9200 refused" });
  e = await errOf(ctx.apiRequest("/z"));
  check("502 com detail inseguro -> http_502", e && e.code === "http_502" && e.status === 502);
  check("502 não vaza o detail", !/10\.0\.0\.5|refused/.test(e.message) && /Wazuh/.test(e.message));

  fetchImpl = async () => jsonRes(503, { detail: "store_unavailable" });
  e = await errOf(ctx.apiRequest("/z"));
  check("503 com detail slug seguro -> usa o slug", e && e.code === "store_unavailable" && e.status === 503);
  fetchImpl = async () => jsonRes(503, undefined);
  e = await errOf(ctx.apiRequest("/z"));
  check("503 sem corpo JSON -> http_503", e && e.code === "http_503" && /backend.log/.test(e.message));

  fetchImpl = async () => jsonRes(404, { detail: "entry_not_found" });
  e = await errOf(ctx.apiRequest("/z"));
  check("404 com slug -> entry_not_found", e && e.code === "entry_not_found");

  fetchImpl = async () => jsonRes(500, { detail: { x: 1 } });
  e = await errOf(ctx.apiRequest("/z"));
  check("500 com detail objeto -> http_500, mensagem genérica", e && e.code === "http_500" && /http_500/.test(e.message));

  fetchImpl = async () => jsonRes(418, { detail: "Slug_Com_Maiusculas" });
  e = await errOf(ctx.apiRequest("/z"));
  check("slug com maiúsculas rejeitado -> http_418", e && e.code === "http_418");
  fetchImpl = async () => jsonRes(400, { detail: "a".repeat(65) });
  e = await errOf(ctx.apiRequest("/z"));
  check("slug com mais de 64 chars rejeitado", e && e.code === "http_400");

  const t = new ctx.ApiError("timeout", 0);
  check("apiErrorMessage(ApiError) = message", ctx.apiErrorMessage(t) === t.message);
  check("apiErrorMessage(Error qualquer) é genérica", !/segredo/.test(ctx.apiErrorMessage(new Error("segredo"))));

  // state.js
  const el = makeEl();
  let p = ctx.sttShowLoading(el);
  check("showLoading: texto por defeito e role=status", el.children.length === 1 && p.textContent === "A carregar…" && p.attrs.role === "status");
  p = ctx.sttShowEmpty(el);
  check("showEmpty: 'Sem dados' por defeito, substitui o conteúdo", el.children.length === 1 && p.textContent === "Sem dados" && p.className === "empty-state");
  p = ctx.sttShowEmpty(el, "—");
  check("showEmpty aceita texto próprio", p.textContent === "—");
  p = ctx.sttShowError(el, new ctx.ApiError("network_error", 0));
  check("showError(ApiError): role=alert e mensagem PT", p.attrs.role === "alert" && p.className === "error-state" && /backend/.test(p.textContent));
  p = ctx.sttShowError(el, "<b>x</b>");
  check("showError(string) usa textContent (sem HTML)", p.textContent === "<b>x</b>" && !("innerHTML" in p));
  p = ctx.sttShowError(el, new Error("segredo"));
  check("showError(Error genérico) não vaza a mensagem", !/segredo/.test(p.textContent) && p.attrs.role === "alert");
  p = ctx.sttShowError(el, undefined);
  check("showError(undefined) mostra mensagem genérica", p.textContent.length > 0);
  check("el nulo não rebenta", ctx.sttShowLoading(null) === null && ctx.sttShowEmpty(null) === null && ctx.sttShowError(null, "x") === null);

  const src = fs.readFileSync(process.argv[3], "utf8");
  check("state.js sem innerHTML nem handlers inline", !/\.innerHTML|insertAdjacentHTML|onclick\s*=/.test(src));

  if (failures.length) { console.log(`\n[FALHOU] ${failures.length} teste(s) falharam`); process.exit(1); }
  console.log("\n[OK] Todos os testes passaram");
})();
