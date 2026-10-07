# R6 — Network SOC (design)

Data: 2026-10-07 · Branch: `roadmap-v2-r6-network-soc` (a partir de
`roadmap-v2-r5-attack-library`, HEAD `e2c5e89`) · Base: R0/Fase 11 Onda 2.

## Objetivo

`docs/ROADMAP_STATUS.md` marca R6 como 🟡: `network_monitor.py` (captura de
metadados via tshark/SSH) e `network_detections.py` (deteção de padrões —
port scan, força bruta, pico de volume) já existem, mas só são consumidos
dentro da aba Red vs Blue (`redblue.js`, painel "🌐 Rede em Tempo Real",
`GET /api/redblue/network`). A sidebar já tem 3 itens planeados no grupo
"Network" (`index.html`, "Live Traffic"/"Network Detections"/"PCAP /
Evidence", todos `data-planned="R6"`) sem dados próprios. A dívida
registada em R0 é explícita: "deteções de rede só existem em memória
(ficam fora do backfill)".

A R6 **não reimplementa a captura**. Expõe-na em painéis dedicados e
resolve a dívida concreta de persistência das deteções.

## Rulings (decididos, não em aberto)

1. **Três painéis reais, dados já existentes.** "Live Traffic" e "Network
   Detections" tornam-se abas ativas, alimentadas por 2 rotas `GET` novas
   (`/api/network/live-traffic`, `/api/network/detections`) que reaproveitam
   `packet_buffer`/`network_detection_buffer`/`detect_network_anomalies` já
   geridos em `main.py` — a mesma fonte de `/api/redblue/network`, resumida
   por um módulo novo e puro (`network_soc.py`), não um 2º poller nem uma
   2ª ligação SSH.
2. **"PCAP / Evidence" resolve a dívida com persistência leve, não PCAP
   real — opção (a).** `network_monitor.py` só lê 11 campos de cabeçalho
   exportados pelo tshark (`-T fields`: timestamps, IPs, portas,
   protocolo, flags TCP) — nunca o payload do pacote (confirmado em
   `_parse_fields_line`). Por isso não há payload nenhum para exportar
   como `.pcap` real; "Evidence" é o registo persistido das **deteções**
   (não dos pacotes crus, que continuam efémeros em `packet_buffer` — o
   volume seria desproporcionado para o valor de auditoria). Mecanismo:
   `history_store.append_network_detection_history`, mesmo padrão JSONL
   append-only de `append_alert_history`
   (`historico/AAAA/MM-mês/AAAA-MM-DD-network-detections.jsonl`), ligado ao
   callback `on_new_detections` que `network_poll_loop` já chama — sem
   segundo poller. Rota nova `GET /api/network/evidence` lê esse ficheiro.
   A UI e a API deixam explícito, sempre, que isto é evidência de
   metadados, nunca uma captura PCAP/payload real (`payload_capture:
   false` na resposta + nota fixa no painel).
3. **Sem mocks.** Sem `VM_SSH_HOST` configurado, as 3 rotas devolvem 200
   com `configured: false` e listas/contagens vazias (mesmo padrão de
   `/api/redblue/network`) — nunca inventam pacotes/deteções.
4. **Segurança:** as 3 rotas são `GET` com `dependencies=_REQUIRE_API_KEY`;
   não expõem nada que `/api/redblue/network` já não exponha (IPs/portas
   dos pacotes capturados já são públicos a quem tem a API key, decisão
   herdada da Fase 11). `GET /api/network/evidence` pagina com `limit`
   (`Query(..., ge=1, le=NETWORK_EVIDENCE_MAX_LIMIT=500)`) e `date`
   (`AAAA-MM-DD`, validado por regex antes de tocar no filesystem) — nunca
   um `limit` sem teto, e `history_store.read_network_detection_history`
   capa `limit` outra vez no próprio módulo (não confia só no parâmetro
   HTTP) e nunca lança por data malformada/ficheiro ausente.
5. **Frontend:** `network_soc.js` novo (padrão `incidents.js`/
   `attack_registry.js`): 3 painéis, cada um só pede dados com a sua aba
   ativa e o separador visível (`MutationObserver` + `visibilitychange` +
   `setInterval` condicional — nunca em segundo plano), sem abrir um 2º
   WebSocket (o `/ws/network` já existe e é exclusivo da aba Red vs Blue).
   `escapeHtml` em todo o texto dinâmico. `serve_frontend.py` ganha
   `/network_soc.js` na whitelist + caso em `test_serve_frontend.py`.
   **Relação com o painel de rede já existente em `redblue.js`**: fica
   como está (é a vista "correlação viva" dentro do contexto Red vs Blue —
   pacotes do buffer + deteções recomputadas, para alimentar
   `/api/redblue/metrics`); o painel ganha uma nota com link cruzado
   ("ver também as abas Network → Live Traffic / Network Detections /
   PCAP Evidence para o histórico persistido e resumos dedicados"). Não há
   duplicação de lógica — `redblue.js` lê `/api/redblue/network`, as abas
   novas leem as 3 rotas novas; ambas as rotas partilham os mesmos dados
   de origem em `main.py`, não há 2 fontes de verdade.

## Módulo novo — `scripts/network_soc.py` (puro)

- `summarize_packets(packets) -> dict`: total, janela temporal
  (`window_start`/`window_end`), contagem por protocolo, top 10
  "talkers" (`src_ip`) e top 10 portas de destino — nunca a lista
  completa de pacotes (painel "Live Traffic").
- `summarize_detections(live, history) -> dict`: contagem "agora"
  (`live_count`, recomputada sobre a janela curta, mesma fonte que
  `/api/redblue/network`) vs `history_count` acumulado desde o arranque,
  por tipo, e os 50 mais recentes (`recent`, mais recente primeiro) —
  painel "Network Detections".
- `build_evidence_report(entries, configured) -> dict`: envolve as
  entradas já lidas do JSONL com `payload_capture: false` e a nota fixa
  de que é metadados, nunca PCAP real — painel "PCAP / Evidence".

Todas puras (recebem listas já obtidas), nunca lançam sobre dados
malformados, sempre limitam o tamanho da resposta (top-N / `recent`
capeado) mesmo que o buffer de origem seja grande.

## `history_store.py` — persistência das deteções (resolve a dívida R0)

- `append_network_detection_history(detection, base_dir) -> (path, offset)`
  e `append_network_detections_history(detections, base_dir)` — mesmo
  padrão de `append_alert_history`/`append_alerts_history`, ficheiro
  `AAAA-MM-DD-network-detections.jsonl`, reaproveita `_alert_datetime`
  para extrair data/hora do campo `timestamp` da deteção.
- `read_network_detection_history(base_dir, date_str=None, limit=100) ->
  list[dict]`: lê o ficheiro de um dia (padrão: hoje, UTC), devolve as
  últimas `limit` entradas (mais recente primeiro). `limit` sempre capeado
  a `NETWORK_EVIDENCE_MAX_LIMIT`; `date_str` inválido, ficheiro ausente ou
  linha malformada → `[]`/linha ignorada, nunca excepção.

`main.py`: `_ingest_incident_detections` (já ligado como `on_new_detections`
de `network_poll_loop`) passa a chamar também
`append_network_detections_history` — mesmas deteções, sem segundo
poller, sem segunda fonte.

## API (`main.py`, todas `GET`, `dependencies=_REQUIRE_API_KEY`)

| Rota | Parâmetros | Resposta |
|---|---|---|
| `GET /api/network/live-traffic` | — | `{configured, total, window_start, window_end, by_protocol, top_talkers[], top_ports[]}` |
| `GET /api/network/detections` | — | `{configured, live_count, history_count, by_type, recent[]}` |
| `GET /api/network/evidence` | `date` (`AAAA-MM-DD`, opcional), `limit` (1–500, padrão 100) | `{configured, entries[], total, payload_capture: false, note}` |

`configured: false` (sem `VM_SSH_HOST`) devolve 200 com zeros/listas
vazias nas duas primeiras — nunca 500. `evidence` não depende de
`VM_SSH_HOST` (lê ficheiro persistido, pode ter dados de uma sessão
anterior mesmo que a captura esteja desligada agora).

## Fora de âmbito, riscos, dívida

**Fora de âmbito**: exportação de `.pcap` real (não há payload capturado);
reimplementar captura/deteção (reaproveitadas tal como estão); indexação
SQLite da evidência (fica em JSONL simples, como o histórico de alertas —
se o volume justificar um índice de consulta, é trabalho de uma fase
futura, mesmo princípio de `history_index.py` para alertas); retenção/
purga automática do JSONL de deteções (mesma política — ou ausência dela —
de `historico/` hoje).

**Dívida**: o ficheiro de evidência cresce sem rotação/purga automática
(mitigado por já ser append-only por dia, como o resto de `historico/`);
sem paginação por offset (só "últimas N de um dia"), suficiente para o
objetivo de laboratório mas não para consultar meses de histórico de uma
vez — candidato a usar `history_index.py` como padrão se isso vier a ser
necessário.

**Critérios de aceitação**:
- [ ] As 3 rotas nunca devolvem 500 por falta de `VM_SSH_HOST`.
- [ ] `GET /api/network/evidence` sobrevive a um restart do backend com
      dados reais (teste: persistir, "reiniciar" o estado em memória,
      reler do ficheiro).
- [ ] `limit` nunca devolve mais de 500 entradas mesmo pedindo mais.
- [ ] `payload_capture` é sempre `false` na resposta de `evidence`.
- [ ] Testes novos e todos os `scripts/test_*.py` existentes passam.
- [ ] Docs atualizadas (`API.md`, `DATA_MODEL.md`, `ARCHITECTURE.md`,
      `SECURITY.md`, `ROADMAP_STATUS.md`, `README.md`).
