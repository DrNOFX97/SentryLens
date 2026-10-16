// ui_helpers.js — helpers puros do frontend (sem DOM, sem fetch).
//
// Regras deste ficheiro:
//  - Só funções puras: nada toca em document/window no topo, para poderem ser
//    testadas em Node (scripts/test_ui_helpers.cjs, via scripts/test_ui_helpers.py).
//  - Os scripts do dashboard são clássicos e partilham o escopo global, por isso
//    todo o identificador de topo daqui começa por "sl" e nunca repete nomes de app.js.
//  - Carregado em index.html entre config.js e app.js.

// O Wazuh devolve datas como "2026-10-16T10:00:00.000+0000"; Firefox/Safari
// rejeitam o sufixo sem dois pontos. Converte ±HHMM em ±HH:MM e devolve
// um Date, ou null se o valor estiver vazio ou não for uma data válida.
function slParseDate(ts) {
  if (ts === null || ts === undefined || ts === "") return null;
  const valor = typeof ts === "string"
    ? ts.trim().replace(/([+-]\d{2})(\d{2})$/, "$1:$2")
    : ts;
  const data = new Date(valor);
  return Number.isNaN(data.getTime()) ? null : data;
}

// Data/hora legível em pt-PT, ou "—" quando não há valor válido.
function slFormatTimestamp(ts) {
  const data = slParseDate(ts);
  return data ? data.toLocaleString("pt-PT") : "—";
}

// Texto e classe CSS do indicador do cabeçalho, a partir de /api/siem/health.
// `health` é a resposta (ou null); `failed` indica que o pedido falhou.
// Com resposta, `failed` é ignorado.
function slHeaderStatus(health, failed) {
  if (health === null || health === undefined) {
    return failed
      ? { text: "● sem ligação ao backend", cls: "status-error" }
      : { text: "● a verificar", cls: "status-unknown" };
  }
  switch (health.status) {
    case "ok": return { text: "● Wazuh operacional", cls: "status-ok" };
    case "degraded": return { text: "● Wazuh degradado", cls: "status-warn" };
    case "down": return { text: "● Wazuh em baixo", cls: "status-error" };
    default: return { text: "● estado do Wazuh desconhecido", cls: "status-unknown" };
  }
}

// Número finito ou null. Rejeita null/undefined/""/booleanos/NaN/Infinity,
// para que "sem valor" nunca vire 0.
function slNumberOrNull(v) {
  if (v === null || v === undefined || v === "" || typeof v === "boolean") return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

// Percentagem formatada ("12%") ou "—" sem valor.
function slFmtPct(v, digits = 0) {
  const n = slNumberOrNull(v);
  return n === null ? "—" : `${n.toFixed(digits)}%`;
}

// Largura CSS de uma barra de progresso: "0%" sem valor, senão limitada a 0-100.
function slProgressWidth(v) {
  const n = slNumberOrNull(v);
  return n === null ? "0%" : `${Math.min(100, Math.max(0, n))}%`;
}
