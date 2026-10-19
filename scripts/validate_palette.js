"use strict";
/**
 * Validador de paletas do SentryLens (W4.2), adaptado do validador da skill
 * dataviz. So usa a stdlib de Node. Duas formas de uso:
 *
 *   node validate_palette.js
 *       Le ../style.css, extrai --cat-1..--cat-8 e --sev-critical..--sev-info
 *       (modo claro em :root, modo escuro no bloco do tema escuro) e valida:
 *         - paleta categorica dos graficos: banda de luminosidade, croma,
 *           separacao CVD (adjacentes), piso de visao normal e contraste;
 *         - rampa de severidade: piso de visao normal, separacao CVD e
 *           contraste com a superficie. A severidade nunca depende so da
 *           cor: o badge leva sempre texto e um glifo (ver style.css).
 *
 *   node validate_palette.js "#hex,#hex,..." [--mode light|dark]
 *                            [--surface #hex] [--pairs adjacent|all]
 *                            [--profile categorical|severity]
 *       Valida uma lista avulsa de cores.
 *
 * Sai com 0 se tudo passa, 1 se alguma verificacao falha, 2 se o uso e invalido.
 * Limiares da skill: dE em OKLab x100; CVD >= 8 (alvo), 6-8 so com codificacao
 * secundaria; visao normal >= 15 (duro); contraste >= 3:1.
 */

const fs = require("node:fs");
const path = require("node:path");

const BAND = { light: [0.43, 0.77], dark: [0.48, 0.67] };
const CHROMA_FLOOR = 0.10;
const CVD_TARGET = 8.0, CVD_FLOOR = 6.0;
const NORMAL_FLOOR = 15.0;
const CONTRAST_MIN = 3.0;

const MACHADO = {
  protan: [[0.152286, 1.052583, -0.204868], [0.114503, 0.786281, 0.099216], [-0.003882, -0.048116, 1.051998]],
  deutan: [[0.367322, 0.860646, -0.227968], [0.280085, 0.672501, 0.047413], [-0.011820, 0.042940, 0.968881]],
  tritan: [[1.255528, -0.076749, -0.178779], [-0.078411, 0.930809, 0.147602], [0.004733, 0.691367, 0.303900]],
};

const isHex = (v) => /^#[0-9a-fA-F]{6}$/.test(v);
const hex2srgb = (h) => [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16) / 255);
const s2lin = (c) => (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
const lin = (h) => hex2srgb(h).map(s2lin);
const relLum = (h) => { const [r, g, b] = lin(h); return 0.2126 * r + 0.7152 * g + 0.0722 * b; };
function contrast(a, b) {
  const [hi, lo] = [relLum(a), relLum(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}
function oklabFromLin([r, g, b]) {
  const l = Math.cbrt(0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b);
  const m = Math.cbrt(0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b);
  const s = Math.cbrt(0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b);
  return [
    0.2104542553 * l + 0.7936177850 * m - 0.0040720468 * s,
    1.9779984951 * l - 2.4285922050 * m + 0.4505937099 * s,
    0.0259040371 * l + 0.7827717662 * m - 0.8086757660 * s,
  ];
}
const oklch = (h) => { const [L, a, b] = oklabFromLin(lin(h)); return [L, Math.hypot(a, b)]; };
function simulate(h, kind) {
  const [r, g, b] = lin(h), M = MACHADO[kind];
  const cl = (c) => Math.max(0, Math.min(1, c));
  return M.map((row) => cl(row[0] * r + row[1] * g + row[2] * b));
}
function deltaE(h1, h2, kind) {
  const a = oklabFromLin(kind ? simulate(h1, kind) : lin(h1));
  const b = oklabFromLin(kind ? simulate(h2, kind) : lin(h2));
  return 100 * Math.hypot(a[0] - b[0], a[1] - b[1], a[2] - b[2]);
}

/**
 * profile "categorical": todas as verificacoes da skill.
 * profile "severity": sem banda de luminosidade nem piso de croma (uma rampa
 * de severidade vai de escuro a claro de proposito); mantem CVD, visao normal
 * e contraste, que decidem se os niveis se distinguem.
 */
function validate(palette, { mode = "light", surface, pairs = "adjacent", profile = "categorical" } = {}) {
  const report = [];
  let ok = true;
  const n = palette.length;
  if (profile === "categorical") {
    const [lo, hi] = BAND[mode];
    const off = palette.filter((c) => { const L = oklch(c)[0]; return L < lo || L > hi; })
      .map((c) => [c, +oklch(c)[0].toFixed(3)]);
    if (off.length) ok = false;
    report.push(["Banda de luminosidade", !off.length,
      off.length ? `fora da banda: ${JSON.stringify(off)}` : `${n} dentro de L ${lo}-${hi}`]);
    const lowc = palette.filter((c) => oklch(c)[1] < CHROMA_FLOOR).map((c) => [c, +oklch(c)[1].toFixed(3)]);
    if (lowc.length) ok = false;
    report.push(["Piso de croma", !lowc.length,
      lowc.length ? `abaixo do piso (le-se cinzento): ${JSON.stringify(lowc)}` : `${n} >= ${CHROMA_FLOOR}`]);
  }
  const pairlist = pairs === "all"
    ? Array.from({ length: n }, (_, i) => Array.from({ length: n - i - 1 }, (_, k) => [i, i + 1 + k])).flat()
    : Array.from({ length: Math.max(0, n - 1) }, (_, i) => [i, i + 1]);
  let worst = null;
  for (const kind of ["protan", "deutan"]) {
    for (const [i, j] of pairlist) {
      const d = deltaE(palette[i], palette[j], kind);
      if (worst === null || d < worst[0]) worst = [d, kind, palette[i], palette[j]];
    }
  }
  const wd = worst ? worst[0] : 99;
  const cvd = wd >= CVD_TARGET ? "pass" : wd >= CVD_FLOOR ? "floor" : "fail";
  if (cvd === "fail") ok = false;
  report.push(["Separacao CVD", cvd, worst ? `pior par ${worst[2]}<->${worst[3]} dE ${wd.toFixed(1)} (${worst[1]})` : "n/a"]);
  let nw = null;
  for (const [i, j] of pairlist) {
    const d = deltaE(palette[i], palette[j]);
    if (nw === null || d < nw[0]) nw = [d, palette[i], palette[j]];
  }
  const nd = nw ? nw[0] : 99;
  const nstate = nd >= NORMAL_FLOOR ? "pass" : "fail";
  if (nstate === "fail") ok = false;
  report.push(["Piso de visao normal", nstate, nw ? `pior par ${nw[1]}<->${nw[2]} dE ${nd.toFixed(1)} (>= ${NORMAL_FLOOR})` : "n/a"]);
  const low = palette.filter((c) => contrast(c, surface) < CONTRAST_MIN).map((c) => [c, +contrast(c, surface).toFixed(2)]);
  if (low.length && profile === "severity") ok = false;
  report.push(["Contraste com a superficie", low.length ? (profile === "severity" ? "fail" : "relief") : "pass",
    low.length ? `abaixo de ${CONTRAST_MIN}:1: ${JSON.stringify(low)}` : `${n} >= ${CONTRAST_MIN}:1`]);
  return { report, ok };
}

// -- leitura dos tokens de style.css ------------------------------------------
function extractBlock(css, header) {
  const start = css.indexOf(header);
  if (start < 0) return null;
  const open = css.indexOf("{", start);
  let depth = 0;
  for (let i = open; i < css.length; i++) {
    if (css[i] === "{") depth++;
    else if (css[i] === "}" && --depth === 0) return css.slice(open + 1, i);
  }
  return null;
}
function parseVars(block) {
  const out = {};
  for (const m of block.matchAll(/(--[a-z0-9-]+)\s*:\s*([^;]+);/gi)) out[m[1]] = m[2].trim();
  return out;
}
/** Devolve {light, dark}: token -> valor (o escuro herda o claro). */
function loadTokens(cssPath) {
  const css = fs.readFileSync(cssPath, "utf8").replace(/\/\*[\s\S]*?\*\//g, "");
  const light = parseVars(extractBlock(css, ":root {") || "");
  const darkBlock = extractBlock(css, ':root[data-theme="dark"]');
  const dark = Object.assign({}, light, parseVars(darkBlock || ""));
  return { light, dark };
}
function resolve(tokens, name, depth = 0) {
  const v = tokens[name];
  const m = v && /^var\((--[a-z0-9-]+)\)$/.exec(v);
  if (m && depth < 8) return resolve(tokens, m[1], depth + 1);
  return v;
}

const GLYPH = { true: "PASS", false: "FAIL", pass: "PASS", floor: "WARN", fail: "FAIL", relief: "WARN" };
function print(title, { report, ok }) {
  console.log(`\n${title}`);
  for (const [name, state, detail] of report) {
    console.log(`  [${(GLYPH[state] || state).padEnd(4)}] ${name.padEnd(28)} ${detail}`);
  }
  console.log(`  -> ${ok ? "TUDO PASSA" : "FALHOU"}`);
}

const SEV = ["critical", "high", "medium", "low", "info"];
const CAT = [1, 2, 3, 4, 5, 6, 7, 8].map((i) => `--cat-${i}`);

function runTokens(cssPath) {
  const t = loadTokens(cssPath);
  let all = true;
  for (const mode of ["light", "dark"]) {
    const tk = t[mode];
    const surface = resolve(tk, "--surface");
    const cat = CAT.map((k) => resolve(tk, k));
    const sev = SEV.map((s) => resolve(tk, `--sev-${s}`));
    const bad = [...cat, ...sev, surface].filter((c) => !c || !isHex(c));
    if (bad.length) { console.error(`tokens em falta ou invalidos (${mode}): ${bad.join(", ")}`); return false; }
    const r1 = validate(cat, { mode, surface, profile: "categorical" });
    const r2 = validate(sev, { mode, surface, profile: "severity" });
    print(`Paleta categorica dos graficos (${mode}, superficie ${surface})`, r1);
    print(`Rampa de severidade critico>alto>medio>baixo>info (${mode}, superficie ${surface})`, r2);
    all = all && r1.ok && r2.ok;
  }
  return all;
}

module.exports = { validate, contrast, deltaE, loadTokens, resolve, isHex, relLum, oklch };

if (require.main === module) {
  const args = process.argv.slice(2);
  const opts = {};
  let positional = null;
  for (let i = 0; i < args.length; i++) {
    let a = args[i], val;
    const eq = a.indexOf("=");
    if (eq > 0) { val = a.slice(eq + 1); a = a.slice(0, eq); }
    if (["--mode", "--surface", "--pairs", "--profile"].includes(a)) opts[a.slice(2)] = val ?? args[++i];
    else if (a.startsWith("--")) { console.error(`flag desconhecida: ${a}`); process.exit(2); }
    else if (positional === null) positional = a;
    else { console.error(`argumento a mais: ${a}`); process.exit(2); }
  }
  if (positional === null) {
    process.exit(runTokens(path.join(__dirname, "..", "style.css")) ? 0 : 1);
  }
  const mode = opts.mode || "light";
  const surface = opts.surface || (mode === "light" ? "#ffffff" : "#0f1f2e");
  const palette = positional.split(",").map((s) => s.trim()).filter(Boolean);
  const badArg = !["light", "dark"].includes(mode) || ![undefined, "adjacent", "all"].includes(opts.pairs)
    || ![undefined, "categorical", "severity"].includes(opts.profile);
  if (!palette.length || badArg || [...palette, surface].some((c) => !isHex(c))) {
    console.error('uso: node validate_palette.js ["#hex,#hex,..."] [--mode light|dark] [--surface #hex] [--pairs adjacent|all] [--profile categorical|severity]');
    process.exit(2);
  }
  const r = validate(palette, { mode, surface, pairs: opts.pairs || "adjacent", profile: opts.profile || "categorical" });
  print(`Paleta (${mode}, superficie ${surface})`, r);
  process.exit(r.ok ? 0 : 1);
}
