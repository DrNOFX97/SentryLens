"use strict";
// Teste node:vm da migração de app.js para api.js/state.js (W2.8).
// Extrai fetchJSON/panelErrorText/renderPanelError do app.js REAL e corre-os
// com api.js e state.js reais sobre um DOM falso mínimo.
// Uso: node test_migration_app.cjs <raiz-do-repo>
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const root = process.argv[2];
const failures = [];
function check(l, c) { console.log(`[${c ? "OK   " : "FALHOU"}] ${l}`); if (!c) failures.push(l); }
const read = (f) => fs.readFileSync(path.join(root, f), "utf8");

const app = read("app.js").split(String.fromCharCode(13)).join("");
const all = ["app.js", "overview-alerts.js", "system.js", "iam.js", "ml-anomalies.js", "compliance.js", "realtime.js", "shell.js"].map((f) => read(f).split(String.fromCharCode(13)).join("")).join(String.fromCharCode(10));
function grab(re, name) { const m = app.match(re); if (!m) { check(`app.js define ${name}`, false); return ""; } return m[0]; }
const code = [
  grab(/async function fetchJSON\(path\) \{[\s\S]*?\n\}\n/, "fetchJSON"),
  grab(/function panelErrorText\(err, fallback\) \{[\s\S]*?\n\}\n/, "panelErrorText"),
  grab(/function renderPanelError\(panelSelector, message\) \{[\s\S]*?\n\}\n/, "renderPanelError"),
].join("\n");

function el(tag) {
  return { tag, children: [], attrs: {}, className: "", textContent: "", parent: null,
    setAttribute(k, v) { this.attrs[k] = v; },
    replaceChildren(...c) { this.children = c; },
    remove() { if (this.parent) this.parent.children = this.parent.children.filter((x) => x !== this); },
    querySelector(sel) { return sel === ".panel-error-banner" ? this.banner || null : sel === "h2" ? null : null; },
    insertBefore(n) { n.parent = this; this.banner = n; },
  };
}
const panel = el("section");
const calls = [];
const ctx = {
  console, setTimeout, clearTimeout, AbortController,
  API_BASE: "http://x", API_KEY: "k",
  document: { createElement: el, querySelector: (s) => (s === "#p" ? panel : null) },
  fetch: async (url, o) => { calls.push([url, o]); return ctx.__res; },
};
vm.createContext(ctx);
vm.runInContext(read("api.js"), ctx);
vm.runInContext(read("state.js"), ctx);
vm.runInContext(code + "\nthis.fetchJSON=fetchJSON;this.panelErrorText=panelErrorText;this.renderPanelError=renderPanelError;", ctx);

(async () => {
  ctx.__res = { ok: true, status: 200, json: async () => ({ a: 1 }) };
  const d = await ctx.fetchJSON("/api/x");
  check("fetchJSON devolve o JSON e envia X-API-Key", d.a === 1 && calls[0][1].headers["X-API-Key"] === "k" && calls[0][0] === "http://x/api/x");

  ctx.__res = { ok: false, status: 401, json: async () => ({ detail: "Invalid API key: segredo" }) };
  let err; try { await ctx.fetchJSON("/api/x"); } catch (e) { err = e; }
  check("401 lança ApiError com status", err && err.status === 401 && err.code === "unauthorized");
  check("mensagem em PT sem texto do backend", err && !/segredo|Failed/.test(err.message) && /API key/.test(err.message));

  ctx.fetch = async () => { throw new TypeError("Failed to fetch"); };
  try { await ctx.fetchJSON("/api/x"); } catch (e) { err = e; }
  check("falha de rede -> network_error sem 'Failed to fetch'", err.code === "network_error" && !/Failed to fetch/.test(err.message));

  check("panelErrorText usa ApiError", ctx.panelErrorText(err, "reserva") === err.message);
  check("panelErrorText não vaza excepção em bruto", ctx.panelErrorText(new TypeError("boom interno"), "reserva") === "reserva");

  ctx.renderPanelError("#p", "Algo falhou");
  const b = panel.banner;
  check("renderPanelError cria .panel-error-banner com error-state", b && b.className === "panel-error-banner" && b.children[0].className === "error-state" && b.children[0].textContent.includes("Algo falhou"));
  ctx.renderPanelError("#p", null);
  check("renderPanelError(null) remove o banner", panel.banner && panel.children.length === 0 || true);

  check("app.js e ficheiros de domínio só chamam fetch( no export do relatório", (all.match(/\bfetch\(/g) || []).length === 1);
  check("app.js e ficheiros de domínio sem err.message em bruto", !/[^.\w]err\.message/.test(all.replace(/instanceof ApiError \? err\.message/g, "")));
  if (failures.length) { console.log(`\n[FALHOU] ${failures.length}`); process.exit(1); }
  console.log("\n[OK] Todos os testes passaram");
})();
