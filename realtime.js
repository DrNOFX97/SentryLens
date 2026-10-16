// Tempo real: WebSocket /ws/alerts, reconexão com backoff, fallback por polling.

// WebSocket de alertas em tempo real (/ws/alerts) — ver connectWebSocket()
// mais abaixo. Autenticação vai por query param (não header) porque o
// handshake de WebSocket do browser não permite headers HTTP arbitrários.
const WS_URL = `${API_BASE.replace(/^http/, "ws")}/ws/alerts?api_key=${encodeURIComponent(API_KEY)}`;
const WS_RECONNECT_DELAYS_MS = [1000, 2000, 4000, 8000, 16000];
// Depois de esgotar as 5 tentativas iniciais, deixa de fazer backoff
// exponencial (não faz sentido continuar a espaçar mais) e passa a tentar
// uma vez a este ritmo fixo, em paralelo com o próprio polling de fallback
// — mesma cadência de 30s, para o WebSocket poder recuperar sozinho sem
// precisar de recarregar a página.
const WS_RECOVERY_INTERVAL_MS = 30000;

let ws = null;
let wsReconnectAttempts = 0;
let pollFallbackIntervalId = null;
let wsRecoveryIntervalId = null;
let inRealtimeFallback = false;
let realtimeFallbackBannerEl = null;

// Aviso fixo no topo do dashboard quando o WebSocket de tempo real falha
// definitivamente (5 tentativas de reconexão esgotadas) — ver
// connectWebSocket(). Não há classe de banner de página inteira reutilizável
// em style.css (.panel-error-banner é para dentro de um .panel de fundo
// branco), por isso estiliza-se inline aqui; amarelo/laranja de aviso,
// consistente com o resto da paleta (ver .level-aviso em style.css).
function showRealtimeFallbackWarning() {
  if (realtimeFallbackBannerEl) return;
  realtimeFallbackBannerEl = document.createElement("div");
  realtimeFallbackBannerEl.textContent =
    "⚠️ Ligação em tempo real indisponível — a atualizar a cada 30s.";
  realtimeFallbackBannerEl.className = "realtime-fallback-banner";
  document.body.insertBefore(realtimeFallbackBannerEl, document.body.firstChild);
}

function hideRealtimeFallbackWarning() {
  if (realtimeFallbackBannerEl) {
    realtimeFallbackBannerEl.remove();
    realtimeFallbackBannerEl = null;
  }
}

// Único sítio onde o polling fixo de 30s ainda existe — só arranca quando o
// WebSocket falha definitivamente (ver connectWebSocket()/onclose abaixo).
function startPollFallback() {
  if (pollFallbackIntervalId) return;
  pollFallbackIntervalId = setInterval(refreshDashboard, 30000);
}

// Enquanto em fallback, tenta recuperar o WebSocket a cada
// WS_RECOVERY_INTERVAL_MS — cada tentativa é uma ligação nova e única (não
// volta a encadear o backoff exponencial, já esgotado). Se conseguir,
// ws.onopen trata de limpar este intervalo e sair do fallback; se falhar,
// ws.onclose vê inRealtimeFallback=true e não faz nada mais (deixa o
// próprio intervalo tentar outra vez no próximo tick).
function startWsRecovery() {
  if (wsRecoveryIntervalId) return;
  wsRecoveryIntervalId = setInterval(connectWebSocket, WS_RECOVERY_INTERVAL_MS);
}

// Cada alerta novo chega por WebSocket e, antes, chamava refreshDashboard()
// diretamente — uma rajada de alertas (ex.: um ataque) redesenhava os gráficos
// e repetia 5 pedidos várias vezes por segundo. Agora agrupa-se: o primeiro
// alerta atualiza logo (se passou o intervalo mínimo) e os seguintes dentro
// da janela viram UM único refresh no fim dela.
const REALTIME_REFRESH_MIN_MS = 15000;
let lastRealtimeRefreshAt = 0;
let realtimeRefreshTimerId = null;

function scheduleRealtimeRefresh() {
  if (realtimeRefreshTimerId) return; // já há um refresh agendado para cobrir este alerta
  const wait = Math.max(0, lastRealtimeRefreshAt + REALTIME_REFRESH_MIN_MS - Date.now());
  realtimeRefreshTimerId = setTimeout(() => {
    realtimeRefreshTimerId = null;
    lastRealtimeRefreshAt = Date.now();
    refreshDashboard();
  }, wait);
}

// Liga o WebSocket de alertas em tempo real (/ws/alerts). Ao receber
// {"type":"new_alert"} agenda refreshDashboard() (ver scheduleRealtimeRefresh) em vez de inserir a linha
// manualmente — refreshDashboard() já busca/filtra tudo (severidade/janela
// temporal selecionadas) e não vale a pena duplicar essa lógica aqui.
// Reconecta com backoff exponencial (1s..16s, 5 tentativas); depois disso
// entra em fallback de polling (startPollFallback + showRealtimeFallbackWarning)
// mas continua a tentar recuperar sozinho a cada 30s (startWsRecovery) — só
// esta função chama new WebSocket(...), tanto nas tentativas iniciais como
// nas de recuperação, por isso toda a lógica de estado vive só aqui.
function connectWebSocket() {
  ws = new WebSocket(WS_URL);

  ws.onopen = () => {
    wsReconnectAttempts = 0;
    inRealtimeFallback = false;
    hideRealtimeFallbackWarning();
    if (pollFallbackIntervalId) {
      clearInterval(pollFallbackIntervalId);
      pollFallbackIntervalId = null;
    }
    if (wsRecoveryIntervalId) {
      clearInterval(wsRecoveryIntervalId);
      wsRecoveryIntervalId = null;
    }
  };

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      if (msg && msg.type === "new_alert") {
        scheduleRealtimeRefresh();
        document.dispatchEvent(new CustomEvent("sentrylens:new-alert", { detail: msg.alert }));
      }
    } catch (err) {
      console.error("Mensagem WebSocket inválida:", err);
    }
  };

  ws.onerror = () => {
    ws.close();
  };

  ws.onclose = () => {
    if (inRealtimeFallback) {
      // Foi só uma tentativa de recuperação a falhar — startWsRecovery()
      // já está a correr e tenta outra vez no próximo tick, sem repetir o
      // aviso nem duplicar o polling (já ativos).
      return;
    }
    if (wsReconnectAttempts < WS_RECONNECT_DELAYS_MS.length) {
      const delay = WS_RECONNECT_DELAYS_MS[wsReconnectAttempts];
      wsReconnectAttempts++;
      setTimeout(connectWebSocket, delay);
    } else {
      inRealtimeFallback = true;
      showRealtimeFallbackWarning();
      startPollFallback();
      startWsRecovery();
    }
  };
}

