# R3 — Gestão de incidentes (design)

Roadmap v2, fase R3 (ver `docs/ROADMAP_STATUS.md`). Estado: spec para revisão.

## Objetivo

Introduzir o **incidente**: o agrupamento de deteções relacionadas (alertas
Wazuh e deteções de rede, com anotação ML) sobre o mesmo ativo, ligado ao
ataque que as originou quando existe, com estado e timeline. É a entidade de
que dependem MTTR (R8), DetectionEvent (R7) e Vaccine Lab (R11–R14).

Princípio do projeto: **dados reais primeiro**. Nenhum incidente é inventado;
sem fonte de dados o painel mostra "Sem dados".

## Decisões (acordadas)

| Tema | Decisão |
|---|---|
| Criação | Automática a partir de deteções. Ataques sem nenhuma deteção **não** viram incidente; continuam visíveis como `detected=false` no Red vs Blue (sem endpoint novo — o R12 trata-os como candidatos a vaccine). |
| Persistência | SQLite novo `scripts/incidents.sqlite3`, fora do git, separado de `historico/index.sqlite3` (cache reconstruível). |
| Evidências | `wazuh_alert` e `network_detection`. O ML não é um tipo: aparece como resumo ao nível do incidente (ver §2, "Derivados"). |
| Quando agrupa | Híbrido: uma função pura, chamada pelo ingest em tempo real e por um backfill manual sobre os alertas do Wazuh Indexer. |

> **Emenda (descoberta ao planear, 2026-10-06).** `historico/*.jsonl` só guarda `date/time/event_id/severity/friendly_name/agent_name/rule_id` — sem `agent_ip` nem timestamp completo —, por isso o backfill e a chave de deduplicação usam o alerta bruto do Indexer (`_id`), e o ML passou de anotação por alerta a resumo por incidente (as features do ML dependem da janela de alertas à volta e `extract_features` reordena/descarta alertas; um score por alerta calculado no ingest seria enganador).

## Fora de âmbito

Merge/split manual, atribuição a pessoas (a API só tem uma chave global:
autor fixo `analyst`), MTTR formal (R8), evidência ML como tipo próprio, aba
"Investigações" (continua planeada), PCAP.

## 1. Modelo e regras de agrupamento (`incident_engine.py`, puro)

Sem I/O. Recebe evidências normalizadas e o estado atual, devolve decisões.

**Evidência normalizada**: `{kind, key, ts, asset, severity, payload}`.

- `wazuh_alert`: parte do alerta **bruto** do Indexer (`_source` + `_id`, como
  devolve `WazuhIndexerClient.get_recent_alerts`). `asset = agent.ip`,
  `severity = event_catalog.classify_alert(windows_event_id)["severity"]`
  (`info < low < medium < high < critical`; alertas sem Event ID Windows são
  `info`), `ts = @timestamp`, `key = "alert:<_id>"`, `payload` = o alerta bruto.
- `network_detection`: `asset = dst_ip or src_ip` (o `volume_spike` tem
  `dst_ip=None`), severidade fixa por tipo (`port_scan`/`brute_force` =
  `medium`, `volume_spike` = `low`; constante `NETWORK_SEVERITY`),
  `key = "net:<tipo>:<src>:<dst>:<ts[:16]>"` — a mesma granularidade (minuto)
  com que `network_monitor._poll_once` já deduplica.

**Constantes** (módulo, com override por variável de ambiente):
`INCIDENT_GAP_SECONDS = 600`, `INCIDENT_OPEN_MIN_SEVERITY = "medium"`.

**Atribuição** `assign_evidence(evidence, open_incidents) -> Decision`:

1. Se `evidence.key` já existe → `duplicate` (idempotência).
2. Procura incidente do mesmo `asset` com estado fora de `RESOLVED`/`CLOSED`
   e `evidence.ts - last_evidence_ts <= gap` → `attach`.
3. Senão, se `evidence.kind == network_detection` ou
   `severity >= INCIDENT_OPEN_MIN_SEVERITY` → `open` (novo incidente).
4. Senão (alerta `info`/`low` sem incidente aberto) → `ignore`. Alertas abaixo
   do limiar nunca abrem incidentes; só se anexam a um já aberto.

Evidências de um lote são processadas por ordem de `ts`. Severidade do
incidente = máximo das suas evidências (um aumento gera evento
`severity_changed`).

**Ataques ligados**: ao anexar/abrir, procura no `attack_log` ataques
`status == "launched"` com `target == asset` e `attack_ts <= evidence.ts <=
window_end` (janela de 300 s cortada pelo ataque seguinte, a mesma de
`redblue_correlator`). Para não duplicar a regra, `redblue_correlator` passa a
expor `attack_windows(parsed_attacks, window_seconds)` (comportamento
inalterado, coberto por `test_redblue.py`). Os campos `id`, `technique` e `tool`
do log (R0) são guardados no evento `attack_linked`. Técnicas MITRE do
incidente = as dos ataques ligados; sem ataque ligado, vazio ("—"), nunca
inferidas.

**Máquina de estados** `can_transition(from, to, note)`:

```
NEW           -> INVESTIGATING | CLOSED (nota obrigatória: falso positivo)
INVESTIGATING -> CONTAINED | RESOLVED
CONTAINED     -> RESOLVED | INVESTIGATING
RESOLVED      -> CLOSED | INVESTIGATING
CLOSED        -> (final)
```

## 2. Persistência (`incident_store.py`)

`INCIDENTS_DB_PATH` (default `scripts/incidents.sqlite3`; adicionar ao
`.gitignore`). Uma ligação por operação (`sqlite3.connect(timeout=10)`) e um
`threading.Lock` de módulo em torno de "ler abertos → decidir → gravar", porque
o ingest corre numa thread de executor e o backfill/API noutra.

```sql
incidents(
  id TEXT PRIMARY KEY,            -- INC-AAAAMMDD-NNN (data da criação, sequência diária)
  status TEXT NOT NULL,           -- NEW|INVESTIGATING|CONTAINED|RESOLVED|CLOSED
  severity TEXT NOT NULL,
  asset TEXT NOT NULL,
  created_at TEXT NOT NULL,       -- ISO-8601 UTC
  first_evidence_at TEXT NOT NULL,
  last_evidence_at TEXT NOT NULL,
  updated_at TEXT NOT NULL)
incident_evidence(
  incident_id TEXT NOT NULL REFERENCES incidents(id),
  key TEXT NOT NULL UNIQUE,       -- chave de deduplicação
  kind TEXT NOT NULL,             -- wazuh_alert|network_detection
  ts TEXT NOT NULL,
  severity TEXT NOT NULL,
  payload TEXT NOT NULL)          -- JSON: alerta bruto do Wazuh ou deteção de rede
incident_events(                  -- append-only: nunca UPDATE/DELETE
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id TEXT NOT NULL REFERENCES incidents(id),
  ts TEXT NOT NULL,
  kind TEXT NOT NULL,             -- created|evidence_added|attack_linked|severity_changed|status_changed|note_added
  actor TEXT NOT NULL,            -- 'system' | 'analyst'
  data TEXT NOT NULL)             -- JSON
```

Índices em `incidents(status)`, `incidents(asset, last_evidence_at)` e
`incident_evidence(incident_id)`.

**Derivados (não guardados)**: `ml_summary` = `{scored, ml_anomalies, rule_flagged}`
calculado em `GET /api/incidents/{id}` com `ml_anomalies.build_ml_anomalies_report`
sobre os alertas brutos do próprio incidente (a janela certa para as features;
`null` se o modelo não existir, sem falhar o pedido); MTTD do incidente = `first_evidence_at −
timestamp do ataque ligado mais antigo` (None sem ataque); tempo até à primeira
resposta = primeiro `status_changed → INVESTIGATING` menos `created_at` (entrada
para o MTTR do R8).

## 3. API (`main.py`, todas com `dependencies=_REQUIRE_API_KEY`)

| Método | Rota | Descrição |
|---|---|---|
| GET | `/api/incidents` | `status`, `severity`, `hours` (1–720, default 168), `limit`/`offset`. Devolve `incidents[]` com `evidence_count`, `techniques`, `attack_ids`, `mttd_seconds` + `summary` (contagens por estado/severidade, abertos, críticos abertos, MTTD médio). |
| GET | `/api/incidents/{id}` | Incidente + `evidence[]` + `timeline[]`. 404 se não existir. |
| POST | `/api/incidents/{id}/status` | `{status, note?}`. 409 se a transição for inválida; 422 se faltar a nota obrigatória. |
| POST | `/api/incidents/{id}/notes` | `{text}` (1–2000 chars) → evento `note_added`. |
| POST | `/api/incidents/backfill` | `{days}` (1–90): reprocessa os alertas do Wazuh Indexer (retenção de 90 dias; máx. 5000, `truncated` sinalizado) com a função pura; idempotente; devolve `{fetched, opened, attached, duplicate, ignored, truncated}`. 502 se o Indexer falhar. |

Validação por modelos Pydantic (limites de tamanho, enum de estados). Erros de
base de dados → 500 com mensagem genérica (sem caminhos nem SQL).
O CORS não muda (`GET`/`POST` já permitidos).

## 4. Integração com o ingest

- **Alertas**: `websocket_alerts._poll_once`/`alert_poll_loop` ganham o parâmetro
  opcional `on_new_raw_alerts` (síncrono, corre em executor, erros isolados), que
  recebe os alertas **brutos** novos (o `on_new_alerts` existente continua a
  receber os enriquecidos, sem mudança). `main.py` liga-o a
  `incident_ingest.ingest_raw_alerts`. Falha no incidente nunca impede a
  persistência do histórico nem o broadcast.
- **Rede**: `network_monitor._poll_once`/`network_poll_loop` ganham o parâmetro
  opcional `on_new_detections` (síncrono, corre em executor, erros isolados),
  espelhando `on_new_alerts`. `main.py` liga-o a `ingest_network_detections`.
  Sem `VM_SSH_HOST` nada muda (a rede continua opcional).
- **ML**: só na leitura do detalhe (ver §2). Se o modelo não existir, o incidente
  funciona na mesma, com `ml_summary = null`.
- **Backfill**: `indexer_client.get_recent_alerts(hours=days*24, size=5000)` e a
  mesma função de ingest (ordenada por tempo). Deteções de rede só existem em
  memória, por isso o backfill cobre apenas alertas Wazuh (documentado na
  resposta e na UI).

## 5. Frontend (`incidents.js`, não edita `app.js`)

- Na sidebar, "Incidentes" passa de `data-planned="R3"` a `data-tab="incidents"`
  e ganha `#tab-incidents`; "Investigações" mantém-se planeada. `index.html`
  carrega `incidents.js` depois de `redblue.js`; reutiliza os globais de
  `app.js` (`fetchJSON`, `escapeHtml`, `severityBadge`, `renderPanelError`).
- **Lista**: KPIs (abertos, críticos abertos, MTTD médio, por estado), filtros
  de estado/severidade, tabela (id, severidade, estado, ativo, primeira/última
  evidência, nº evidências, técnicas MITRE, ataque ligado).
- **Detalhe** (ao selecionar uma linha): evidências, timeline, botões das
  transições **válidas** a partir do estado atual, e caixa de nota. Para
  CLOSED a partir de NEW a nota é obrigatória na UI.
- Estados explícitos de loading/erro/vazio; vazio distingue "sem incidentes" de
  "ainda não correu o backfill" (botão "Importar histórico"). Todo o texto
  dinâmico (notas, payloads) passa por `escapeHtml`; nunca `innerHTML` direto.
- Atualiza com `refreshNewPanels`-style (30 s) e ao receber `new_alert` no
  WebSocket existente.

## 6. Testes (standalone, estilo atual; sem Wazuh)

- `test_incident_engine.py` — duplicado, attach dentro/fora do gap, abre ≥
  limiar, `info` ignorado sem aberto e anexado com aberto, rede abre sempre,
  `volume_spike` sem `dst_ip`, severidade = máximo, ataque ligado
  (janela/target/corte pelo seguinte), todas as transições válidas e inválidas.
- `test_incident_store.py` — schema, IDs diários sequenciais, deduplicação por
  `key`, timeline append-only (UPDATE/DELETE em `incident_events` não existe na
  API), concorrência com 2 threads sem duplicar incidentes.
- `test_incidents_api.py` — `TestClient` como os restantes: 401 sem chave, filtros,
  404, 409 transição inválida, 422 nota em falta, backfill idempotente com um Indexer falso (duas
  corridas dão o mesmo número de incidentes), 502 quando o Indexer falha, sem caminhos/SQL em erros 500.
- `test_redblue.py` — `attack_windows` não altera nenhum resultado existente.
- `test_network_monitor.py` / `test_websocket_alerts.py` — `on_new_detections` e
  `on_new_raw_alerts` chamados só com itens novos e um erro no callback não
  derruba o polling; `on_new_alerts` mantém o comportamento atual.

## 7. Riscos e mitigações

- **Ruído**: 467/500 alertas atuais são `info`; o limiar `medium` evita
  incidentes inúteis. Constantes configuráveis se o limiar não servir.
- **Retenção do backfill**: limitada aos 90 dias do Indexer e a 5000 alertas por corrida (truncagem sinalizada, não silenciosa).
- **Rede só em memória**: deteções de rede pré-existentes ao arranque não entram
  no backfill. Registado como limitação, não escondido.
- **Janela de 10 min**: pode fundir ataques distintos ao mesmo ativo. Aceite no
  R3; refinar com `attack_id` propagado no R4/R7.
- **Sem identidade de utilizador**: `actor` é `analyst` para todas as ações
  manuais. Autorização por papéis é R22.
- **Dados de laboratório**: o `incidents.sqlite3` pode conter IPs e texto de
  alertas; fica fora do git e não é servido pelo `serve_frontend.py` (whitelist).

## 8. Critérios de aceitação

- [ ] Backfill sobre os alertas reais do Indexer cria incidentes sem duplicar numa 2.ª corrida.
- [ ] Um alerta `high` novo no ingest abre/anexa incidente em < 15 s (ciclo de poll de 10 s).
- [ ] Mudar estado e adicionar nota aparece na timeline; transição inválida é recusada.
- [ ] Painel mostra dados reais e estados loading/erro/vazio; sem dados inventados.
- [ ] Todos os testes existentes (18 ficheiros) e os novos passam; sem secrets; docs atualizados
      (`API.md`, `DATA_MODEL.md`, `ARCHITECTURE.md`, `ROADMAP_STATUS.md`, README).
