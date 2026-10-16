// Prova que metrics.js/detections.js/network_soc.js, com fetch a rejeitar,
// mostram erro PT sem «Failed to fetch» e sem ficar em «A carregar».
const fs = require("fs"), vm = require("vm"), path = require("path");
const root = process.argv[2];
let failed = 0;
const check = (l, c) => { console.log(`[${c ? "OK   " : "FALHOU"}] ${l}`); if (!c) failed++; };

async function run(file, ids) {
  const els = {};
  const mk = () => ({ textContent: "", innerHTML: "", value: "", classList: { contains: () => true }, addEventListener() {} });
  const errors = [];
  const ctx = {
    document: { getElementById: (i) => (els[i] ||= mk()), addEventListener() {}, visibilityState: "visible" },
    MutationObserver: class { observe() {} },
    setInterval() {}, setTimeout, clearTimeout, AbortController, URLSearchParams, encodeURIComponent,
    API_BASE: "http://x", API_KEY: "k",
    escapeHtml: (s) => String(s), formatTimestamp: (s) => s, severityBadge: (s) => s,
    renderPanelError: (sel, msg) => { if (msg) errors.push(msg); },
    fetch: () => Promise.reject(new TypeError("Failed to fetch")),
  };
  vm.createContext(ctx);
  vm.runInContext(fs.readFileSync(path.join(root, "api.js"), "utf8") + "\nthis.apiErrorMessage=apiErrorMessage;this.apiRequest=apiRequest;", ctx);
  vm.runInContext(fs.readFileSync(path.join(root, "ui_helpers.js"), "utf8"), ctx);
  vm.runInContext(fs.readFileSync(path.join(root, "html.js"), "utf8") + ";this.htmlT=htmlT;this.htmlRaw=htmlRaw;this.htmRender=htmRender;", ctx);
  vm.runInContext(fs.readFileSync(path.join(root, file), "utf8"), ctx);
  await new Promise((r) => setTimeout(r, 50));
  const dom = JSON.stringify(Object.values(els).map((e) => [e.textContent, e.innerHTML]));
  check(`${file}: mostra erro PT no painel`, errors.length > 0 && errors.every((m) => m.includes("backend")));
  check(`${file}: sem «Failed to fetch» no DOM`, !dom.includes("Failed to fetch") && !errors.join().includes("Failed to fetch"));
  check(`${file}: sem «A carregar» preso`, !dom.includes("A carregar"));
  check(`${file}: sem fetch directo`, !/\bfetch\(/.test(fs.readFileSync(path.join(root, file), "utf8")));
}

(async () => {
  for (const f of ["metrics.js", "detections.js", "network_soc.js"]) await run(f);
  process.exit(failed ? 1 : 0);
})();
