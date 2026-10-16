"use strict";
// W3.2/W3.3 em redblue.js: ciclo de vida via router e lote de mensagens WS.
// Uso: node test_lifecycle_redblue.cjs <router.js> <api.js> <state.js> <redblue.js>
const fs = require("node:fs");
const vm = require("node:vm");
const failures = [];
function check(l, c) { console.log(`[${c ? "OK   " : "FALHOU"}] ${l}`); if (!c) failures.push(l); }

function makeEl() {
  return {
    children: [], attrs: {}, className: "", textContent: "", _html: "", colSpan: 0, renders: 0,
    setAttribute(k, v) { this.attrs[k] = v; }, appendChild(c) { this.children.push(c); return c; },
    replaceChildren(...c) { this.children = c; }, insertAdjacentElement() {}, remove() {}, querySelector() { return null; },
    get innerHTML() { return this._html; }, set innerHTML(v) { this._html = v; this.renders++; this.children = []; },
  };
}
const els = {};
const listeners = {};
const doc = {
  visibilityState: "visible",
  addEventListener: (t, f) => { listeners[t] = f; },
  getElementById: (id) => (els[id] = els[id] || makeEl()),
  querySelector: () => makeEl(),
  createElement: () => makeEl(),
};
let now = 0, nextId = 1, fetches = 0, rafQueue = [];
const timers = new Map();
const sockets = [];
function FakeWS() { sockets.push(this); this.close = () => {}; }
const ctx = vm.createContext({
  console: { log() {}, error() {}, warn() {} }, AbortController, JSON, Promise, Date: { now: () => now }, Math, Number, String, Array, Object,
  document: doc,
  setTimeout: () => 0, clearTimeout() {},
  setInterval: (fn, ms) => { const id = nextId++; timers.set(id, { fn, ms }); return id; },
  clearInterval: (id) => timers.delete(id),
  requestAnimationFrame: (fn) => { rafQueue.push(fn); return rafQueue.length; },
  WebSocket: FakeWS,
  fetch: (url) => { fetches++; const tk = String(url).endsWith("/api/ws-ticket"); return Promise.resolve({ ok: true, status: 200, json: async () => (tk ? { ticket: "t-teste", expires_in: 30 } : { configured: true, packets: [], detection_history: [], detections: [] }), text: async () => "{}" }); },
});
vm.runInContext(`const API_BASE = "http://x:1"; const API_KEY = "k";
const WS_RECONNECT_DELAYS_MS = [1];
function escapeHtml(s){return String(s);}
function formatTimestamp(t){return String(t);}
function renderPanelError(){}`, ctx);
const [router, api, state, rb] = process.argv.slice(2);
const htmlJs = require("node:path").join(require("node:path").dirname(rb), "html.js");
for (const f of [htmlJs, router, api, state, rb]) vm.runInContext(fs.readFileSync(f, "utf8"), ctx, { filename: f });

function tick(ms) { // avança o relógio e dispara os intervalos devidos
  for (let t = 0; t < ms; t += 1000) { now += 1000; for (const { fn, ms: iv } of [...timers.values()]) if (now % iv === 0) fn(); }
}
const flush = () => new Promise((r) => setImmediate(r));
function frame() { const q = rafQueue; rafQueue = []; q.forEach((f) => f()); }

(async () => {
  // 1. hidden -> 0 pedidos em 120 s
  doc.visibilityState = "hidden";
  vm.runInContext('rtActivate("redblue")', ctx);
  tick(120000); await flush();
  check("documento hidden: 0 pedidos em 120 s", fetches === 0);
  check("documento hidden: nenhum intervalo ativo", timers.size === 0);

  // 2. fica visível -> carrega e abre o socket
  doc.visibilityState = "visible";
  listeners.visibilitychange();
  await flush(); await flush();
  check("visível: faz pedidos", fetches > 0);
  check("regista a aba com o id do nav (redblue)", vm.runInContext('rtRouter.getActiveId()', ctx) === "redblue");
  check("socket /ws/network aberto", sockets.length === 1);

  // 3. 1000 mensagens num frame -> 1 só render, arrays <= teto
  const pktBody = els["redblue-packets-body"];
  frame();
  const before = pktBody.renders;
  for (let i = 0; i < 1000; i++) {
    sockets[0].onmessage({ data: JSON.stringify({ type: "packet", packet: { timestamp: i, src_ip: "1.1.1.1", dst_ip: "2.2.2.2", protocol: "TCP", length: i } }) });
    if (i % 2 === 0) sockets[0].onmessage({ data: JSON.stringify({ type: "network_detection", detection: { timestamp: i, type: "x" } }) });
  }
  check("1000 mensagens agendam um só frame", rafQueue.length === 1);
  frame();
  check("1000 mensagens num frame: 1 só render", pktBody.renders - before === 1);
  const sizes = vm.runInContext('[rbNetwork.packets.length, rbNetwork.detections.length, rbNetwork.history.length]', ctx);
  check("arrays com teto (pacotes<=2000, deteções<=1000)", sizes[0] <= 2000 && sizes[1] <= 1000 && sizes[2] <= 1000);

  // 4. aba não visível -> 0 renders (continua a acumular com teto)
  vm.runInContext('rtDeactivate()', ctx);
  const b2 = pktBody.renders;
  for (let i = 0; i < 3000; i++) sockets[0].onmessage({ data: JSON.stringify({ type: "packet", packet: { timestamp: i, src_ip: "a", dst_ip: "b", protocol: "TCP", length: 1 } }) });
  frame();
  check("aba inativa: 0 renders", pktBody.renders === b2);
  check("aba inativa: pacotes continuam com teto", vm.runInContext('rbNetwork.packets.length', ctx) <= 2000);
  vm.runInContext('rtActivate("redblue")', ctx);
  doc.visibilityState = "hidden";
  const b3 = pktBody.renders;
  sockets[0].onmessage({ data: JSON.stringify({ type: "packet", packet: { timestamp: 1, src_ip: "a", dst_ip: "b", protocol: "TCP", length: 1 } }) });
  frame();
  check("separador escondido: 0 renders", pktBody.renders === b3);

  if (failures.length) { console.log(`\n${failures.length} falha(s)`); process.exit(1); }
})();
