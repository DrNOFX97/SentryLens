// api.js — único ponto que fala com o backend (W2.1, E1 da auditoria).
// Script clássico (sem módulos ES). Prefixo `api`; ApiError é a excepção.
// API_BASE e API_KEY vêm de app.js/config.js e são lidos em runtime (dentro
// das funções), nunca no topo, para não depender da ordem de carregamento.

const API_TIMEOUT_MS = 15000;

// Mensagens em PT com a ação sugerida. Só texto fixo daqui chega ao DOM:
// o `detail` do backend nunca é mostrado em bruto.
const API_ERROR_TEXT = {
  network_error: "Sem ligação ao backend (localhost:8001) — confirma que correu scripts/start-backend.ps1.",
  timeout: "O backend não respondeu em 15 s — o Wazuh Indexer pode estar lento; tenta de novo daqui a pouco.",
  unauthorized: "API key inválida ou em falta — confirma SENTRYLENS_API_KEY em scripts/.env e reinicia o backend.",
  forbidden: "Acesso recusado pelo backend — confirma a API key e a origem do dashboard.",
  validation_error: "O backend recusou os parâmetros do pedido — ajusta os filtros e tenta de novo.",
  invalid_response: "O backend devolveu uma resposta ilegível — vê o backend.log.",
  entry_not_found: "Não encontrado — o registo pode já não existir.",
  store_unavailable: "O armazenamento do backend está indisponível — vê o backend.log.",
  http_404: "Não encontrado — confirma que o backend está atualizado.",
  http_502: "O backend não conseguiu falar com o Wazuh — confirma que a VM Wazuh está ligada e com disco livre.",
  http_503: "Serviço indisponível no backend — vê o backend.log e tenta de novo.",
  http_504: "O Wazuh demorou demasiado a responder — tenta de novo daqui a pouco.",
};

class ApiError extends Error {
  constructor(code, status) {
    super(API_ERROR_TEXT[code] || (status >= 500
      ? `Erro no backend (${code}) — vê o backend.log.`
      : `Erro inesperado (${code}) — tenta de novo.`));
    this.name = "ApiError";
    this.code = code;
    this.status = status || 0;
  }
}

// `detail` só vira código se for um slug estável (a-z e _); qualquer outra
// coisa (texto livre, array do 422, objeto) é ignorada.
function apiSafeCode(detail) {
  return typeof detail === "string" && /^[a-z_]{1,64}$/.test(detail) ? detail : null;
}

function apiCodeFromResponse(status, data) {
  if (status === 401) return "unauthorized";
  const detail = data && data.detail;
  if (status === 422 && Array.isArray(detail)) return "validation_error";
  if (status === 403 && !apiSafeCode(detail)) return "forbidden";
  return apiSafeCode(detail) || (status === 422 ? "validation_error" : `http_${status}`);
}

// Texto seguro para mostrar ao utilizador, venha o erro de onde vier.
function apiErrorMessage(err) {
  if (err instanceof ApiError) return err.message;
  return "Erro inesperado — tenta de novo.";
}

async function apiRequest(path, options) {
  const opts = options || {};
  const method = opts.method || "GET";
  const timeoutMs = opts.timeoutMs || API_TIMEOUT_MS;
  const base = typeof API_BASE !== "undefined" ? API_BASE : "";
  const key = typeof API_KEY !== "undefined" ? API_KEY : "";
  const hasBody = opts.body !== undefined && opts.body !== null;

  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; controller.abort(); }, timeoutMs);

  let res;
  try {
    res = await fetch(base + path, {
      method,
      signal: controller.signal,
      headers: Object.assign({ "X-API-Key": key }, hasBody ? { "Content-Type": "application/json" } : {}),
      body: hasBody ? JSON.stringify(opts.body) : undefined,
    });
  } catch (e) {
    clearTimeout(timer);
    const isTimeout = timedOut || (e && e.name === "TimeoutError");
    throw new ApiError(isTimeout ? "timeout" : "network_error", 0);
  }

  try {
    if (res.ok) {
      if (res.status === 204) return null;
      try {
        return await res.json();
      } catch (e) {
        throw new ApiError(timedOut ? "timeout" : "invalid_response", res.status);
      }
    }
    const data = await res.json().catch(() => null);
    throw new ApiError(apiCodeFromResponse(res.status, data), res.status);
  } finally {
    clearTimeout(timer);
  }
}
