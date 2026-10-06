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
| Evidências | `wazuh_alert` e `network_detection`; ML é anotação do alerta, não um tipo. |
| Quando agrupa | Híbrido: uma função pura, chamada pelo ingest em tempo real e por um backfill manual sobre o histórico. |

## Fora de âmbito

Merge/split manual, atribuição a pessoas (a API só tem uma chave global:
autor fixo `analyst`), MTTR formal (R8), evidência ML como tipo próprio, aba
"Investigações" (continua planeada), PCAP.

## 1. Modelo e regras de agrupamento (`incident_engine.py`, puro)

Sem I/O. Recebe evidências normalizadas e o estado atual, devolve decisões.

**Evidência normalizada**: `{kind, key, ts, asset, severity, payload, ml}`.

- `wazuh_alert`: `asset = alert.agent_ip`, `severity = alert.severity`
  (`info < low < medium < high < critical`), `key = "alert:<ficheiro relativo
  a historico/>:<offset>"` (o par que `history_store.append_alert_history`
  devolve; relativo para não depender do caminho absoluto). `ml` =
  `{ml_is_anomaly, ml_score}` quando o modelo está carregado, senão `None`.
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
  payload TEXT NOT NULL,          -- JSON compacto (alerta enriquecido ou deteção)
  ml TEXT)                        -- JSON {ml_is_anomaly, ml_score} ou NULL
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

**Derivados (não guardados)**: MTTD do incidente = `first_evidence_at −
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
| POST | `/api/incidents/backfill` | `{days}` (1–90): reprocessa o histórico (`historico/**.jsonl`) com a função pura; idempotente; devolve `{processed, opened, attached, duplicate, ignored}`. |

Validação por modelos Pydantic (limites de tamanho, enum de estados). Erros de
base de dados → 500 com mensagem genérica (sem caminhos nem SQL).
O CORS não muda (`GET`/`POST` já permitidos).

## 4. Integração com o ingest

- **Alertas**: `_persist_new_alerts` (já chamado por `alert_poll_loop`) passa a
  chamar `incident_ingest.ingest_alerts(alerts_with_refs)` depois de gravar o
  histórico — reutiliza o `(path, offset)` já devolvido por
  `append_alert_history`. Falha no incidente **nunca** impede a persistência do
  histórico (try/except + `logger.exception`, padrão do módulo).
- **Rede**: `network_monitor._poll_once`/`network_poll_loop` ganham o parâmetro
  opcional `on_new_detections` (síncrono, corre em executor, erros isolados),
  espelhando `on_new_alerts`. `main.py` liga-o a `ingest_network_detections`.
  Sem `VM_SSH_HOST` nada muda (a rede continua opcional).
- **ML**: a anotação usa o modelo já carregado por `ml_anomalies.load_model`; se
  não existir/falhar, `ml = None` e o incidente cria-se na mesma.
- **Backfill**: percorre `historico/AAAA/MM-mês/*-alerts.jsonl` dos últimos N
  dias, reconstrói a evidência e o `key` (ficheiro relativo + offset) e chama a
  mesma função de ingest. Deteções de rede só existem em memória, por isso o
  backfill cobre apenas alertas Wazuh (documentado na resposta e na UI).

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
  404, 409 transição inválida, 422 nota em falta, backfill idempotente (duas
  corridas dão o mesmo número de incidentes), sem caminhos/SQL em erros 500.
- `test_redblue.py` — `attack_windows` não altera nenhum resultado existente.
- `test_network_monitor.py` — `on_new_detections` chamado só com deteções novas e
  um erro no callback não derruba o polling.

## 7. Riscos e mitigações

- **Ruído**: 467/500 alertas atuais são `info`; o limiar `medium` evita
  incidentes inúteis. Constantes configuráveis se o limiar não servir.
- **Rede só em memória**: deteções de rede pré-existentes ao arranque não entram
  no backfill. Registado como limitação, não escondido.
- **Janela de 10 min**: pode fundir ataques distintos ao mesmo ativo. Aceite no
  R3; refinar com `attack_id` propagado no R4/R7.
- **Sem identidade de utilizador**: `actor` é `analyst` para todas as ações
  manuais. Autorização por papéis é R22.
- **Dados de laboratório**: o `incidents.sqlite3` pode conter IPs e texto de
  alertas; fica fora do git e não é servido pelo `serve_frontend.py` (whitelist).

## 8. Critérios de aceitação

- [ ] Backfill sobre o histórico real cria incidentes sem duplicar numa 2.ª corrida.
- [ ] Um alerta `high` novo no ingest abre/anexa incidente em < 15 s (ciclo de poll de 10 s).
- [ ] Mudar estado e adicionar nota aparece na timeline; transição inválida é recusada.
- [ ] Painel mostra dados reais e estados loading/erro/vazio; sem dados inventados.
- [ ] Todos os testes existentes (18 ficheiros) e os novos passam; sem secrets; docs atualizados
      (`API.md`, `DATA_MODEL.md`, `ARCHITECTURE.md`, `ROADMAP_STATUS.md`, README).
