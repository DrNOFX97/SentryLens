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
