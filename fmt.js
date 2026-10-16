// fmt.js — formatadores puros (W7.3, E7): duração, data, número, percentagem.
// Script clássico, prefixo `fmt`. Sem DOM, sem fetch: testável em node:vm
// (scripts/test_fmt.cjs). PT-PT: vírgula decimal, espaço fixo (U+00A0) nos
// milhares a partir de 5 dígitos. Sem valor (null, undefined, "", NaN,
// ±Infinity, booleano, texto não numérico) é sempre «—», nunca 0.

const FMT_EMPTY = "—";

// Converte para número finito, ou null. "" e booleanos NÃO são zero.
function fmtToNumber(v) {
  if (typeof v === "number") return Number.isFinite(v) ? v : null;
  if (typeof v === "string" && v.trim() !== "") {
    const n = Number(v.trim());
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

function fmtClampDecimals(d, fallback) {
  return Number.isInteger(d) && d >= 0 && d <= 10 ? d : fallback;
}

// 1234.5 -> "1234,5"; 12345.6 -> "12 345,6" (espaço fixo). opts.decimals
// (default 0).
function fmtNumber(v, opts) {
  const n = fmtToNumber(v);
  if (n === null) return FMT_EMPTY;
  const decimals = fmtClampDecimals(opts && opts.decimals, 0);
  const fixed = Math.abs(n).toFixed(decimals);
  const neg = n < 0 && Number(fixed) !== 0; // evita «-0»
  const parts = fixed.split(".");
  let int = parts[0];
  if (int.length >= 5) int = int.replace(/\B(?=(\d{3})+(?!\d))/g, " ");
  return (neg ? "-" : "") + int + (parts[1] ? "," + parts[1] : "");
}

// Percentagem. Por omissão `v` já está em 0-100; opts.ratio=true trata 0-1.
// opts.decimals (default 1) -> "12,5%".
function fmtPct(v, opts) {
  const n = fmtToNumber(v);
  if (n === null) return FMT_EMPTY;
  const scaled = opts && opts.ratio ? n * 100 : n;
  return fmtNumber(scaled, { decimals: fmtClampDecimals(opts && opts.decimals, 1) }) + "%";
}

// Duração em segundos -> "45 s", "3 min 20 s", "2 h 5 min", "1 d 3 h".
// Mostra no máximo as duas maiores unidades. Negativo/sem valor -> «—».
// 0 é uma medição real: "0 s". Entre 0 e 1 s: "< 1 s".
function fmtDuration(seconds) {
  const n = fmtToNumber(seconds);
  if (n === null || n < 0) return FMT_EMPTY;
  if (n > 0 && n < 1) return "< 1 s";
  const total = Math.round(n);
  const d = Math.floor(total / 86400);
  const h = Math.floor((total % 86400) / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (d > 0) return h > 0 ? `${d} d ${h} h` : `${d} d`;
  if (h > 0) return m > 0 ? `${h} h ${m} min` : `${h} h`;
  if (m > 0) return s > 0 ? `${m} min ${s} s` : `${m} min`;
  return `${s} s`;
}

// Converte o que o backend envia num Date, ou null. Aceita Date, epoch em ms
// e strings ISO; o Wazuh manda "+0000" sem dois pontos (Firefox/Safari
// rejeitam), por isso normaliza ±HHMM em ±HH:MM.
function fmtParseDate(ts) {
  if (ts === null || ts === undefined || ts === "" || typeof ts === "boolean") return null;
  let valor = ts;
  if (typeof ts === "string") valor = ts.trim().replace(/([+-]\d{2})(\d{2})$/, "$1:$2");
  const data = valor instanceof Date ? valor : new Date(valor);
  return Number.isNaN(data.getTime()) ? null : data;
}

function fmtPad2(n) { return n < 10 ? "0" + n : String(n); }

// "17/10/2026 14:05:09" na hora local; opts.time=false -> só "17/10/2026".
// Inválido ou vazio -> «—».
function fmtDate(ts, opts) {
  const d = fmtParseDate(ts);
  if (!d) return FMT_EMPTY;
  const dia = `${fmtPad2(d.getDate())}/${fmtPad2(d.getMonth() + 1)}/${d.getFullYear()}`;
  if (opts && opts.time === false) return dia;
  return `${dia} ${fmtPad2(d.getHours())}:${fmtPad2(d.getMinutes())}:${fmtPad2(d.getSeconds())}`;
}
