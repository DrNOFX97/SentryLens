# R2 — Live SOC: design

Data: 2026-10-07. Fase R2 do Roadmap v2 ("Reutiliza /api/stats, /api/alerts, /ws/alerts").

## Âmbito

Um único painel na sidebar, grupo "Wazuh", que substitui o item planeado
"SIEM Health" (badge R2): **"📡 Live SOC"** (`data-tab="live-soc"`), com duas
secções: (1) feed de alertas ao vivo; (2) saúde do SIEM. Um painel em vez de
dois itens porque as duas coisas respondem à mesma pergunta ("o SIEM está a
receber e a mostrar alertas agora?") e a sidebar R1 já tem muitos itens.

## 1. Feed ao vivo

- Alimentado pelo WebSocket já existente de `app.js`. **Não abre 2.º WebSocket.**
- `app.js` (mudança mínima): o dispatch `sentrylens:new-alert` passa a levar
  `detail: msg.alert` (alerta já enriquecido por `_enrich_alert`).
- `live_soc.js` guarda os últimos N=50 (mais recente em cima), de-duplicados por
  timestamp+regra+agente, e renderiza a tabela (hora, severidade, agente, evento).
  Carga inicial: `GET /api/alerts?hours=1` (últimos 50) ao abrir a aba.
- Botão Pausar/Retomar: em pausa, os alertas novos ficam em buffer e o contador
  "N novos em pausa" sobe; ao retomar, são fundidos no feed.
- Indicador de ligação: lê o estado de `app.js` (`ws.readyState`,
  `inRealtimeFallback`): "Tempo real" / "Fallback (polling 30 s)" / "A ligar...".
- Sem polling próprio do feed; todo o texto dinâmico via `escapeHtml()`.

## 2. Saúde do SIEM

Dados que já existem: `/api/agents` (resumo de agentes), `/api/alerts`. Faltam
estado Manager/Indexer e idade do último alerta (`/api/health` não testa o
Wazuh). Uma rota nova mínima:

`GET /api/siem/health` (`dependencies=_REQUIRE_API_KEY`) — chama
`get_agents_summary()` (Manager) e `get_recent_alerts(hours=1, size=500)`
(Indexer) **em separado**, cada um com try/except, e passa os resultados à
função pura `siem_health.build_siem_health_report(...)` (módulo novo,
testável sem Wazuh). Resposta (HTTP 200 mesmo com componentes em baixo):

```
{ "generated_at", "status": "ok|degraded|down", "stale": bool, "truncated": bool, "manager": {"status": "ok|unavailable", "error"?},
  "indexer": {"status": ..., "error"?},
  "agents": {"active","disconnected","never_connected","pending","total"} | null,
  "last_alert_at": iso|null, "ingestion_lag_seconds": float|null,
  "alerts_per_minute": float|null, "window_minutes": 5, "alerts_in_window": int|null }
```

Regras de honestidade: componente em baixo -> campos dependentes `null` e a UI
mostra "Indisponível"; Indexer ok mas sem alertas na última hora ->
`last_alert_at=null` e a UI mostra "Sem alertas na última hora" (não 0 s);
taxa = alertas na janela de 5 min / 5 (`null` se o Indexer está em baixo).
Atraso de ingestão = agora − timestamp do alerta mais recente (limitado à
última hora, porque só essa janela é pesquisada).

Revisão de segurança (correções):
- `error` de cada componente é um **código estável** (`timeout`/`unreachable`),
  nunca texto de exceção (podia expor host/URL/portas); o detalhe só vai para o log.
- Campo agregado `status`: `ok` | `degraded` (um componente em baixo ou
  `stale`) | `down` (ambos). HTTP 200 não significa saudável. `stale: true`
  quando o Indexer está ok mas o último alerta tem > 300 s (ou não há nenhum na
  última hora). A UI mostra `status` num banner proeminente.
- `truncated: true` quando o Indexer devolveu o limite pedido (500, os mais
  recentes por `@timestamp` desc): a taxa é um mínimo e a UI mostra "≥" e aviso.

Refresh: ao abrir a aba e depois a cada 30 s, **só se a aba Live SOC estiver
ativa e o documento visível** (`document.visibilityState`).

## Ficheiros

`scripts/siem_health.py` (+ `test_siem_health.py`), rota em `main.py`,
`live_soc.js`, `index.html`, `style.css` (reutiliza tokens/`.card`/`.panel`),
whitelist em `serve_frontend.py` + caso em `test_serve_frontend.py`, docs.

## Fora de âmbito

Gráficos históricos de ingestão, alertas sonoros, estado detalhado dos
serviços internos do Manager (`/manager/status`).
