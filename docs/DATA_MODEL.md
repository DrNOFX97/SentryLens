# Modelo de dados (estado em 2026-10-12)

Só o que já existe. Entidades do Roadmap v2 já definidas: `DetectionEvent`
(R7), o registo de modelo (R9) e a Vaccine (R11), todas abaixo; o Replay
(R13) ainda não existe.

## `DetectionEvent` (R7) — `scripts/detection_event.py`

Tipo comum que normaliza os 3 detetores independentes (regra/Wazuh, ML,
rede) para a mesma forma. Não é persistido — calculado a pedido por
`GET /api/detections` e usado internamente por `incident_engine.py`/
`redblue_correlator.py` como base de construção (ver
[ARCHITECTURE.md](ARCHITECTURE.md)).

```
{source, severity, asset, ts, technique, confidence, ref, label, description}
  source       "rule" | "ml" | "network"
  severity     info|low|medium|high|critical (rule/network) — o próprio
               campo "severity" do resultado ML (ver ml_anomalies.py), para network
  asset        IP do ativo afetado; None se não aplicável
  ts           ISO-8601 com fuso
  technique    sempre None nos 3 construtores por agora (ruling 2 da spec —
               nenhuma das 3 fontes liga uma técnica MITRE a uma deteção
               individual; isso só existe ao nível da tentativa de ataque,
               em redblue_correlator)
  confidence   sempre None nos 3 construtores por agora (ruling 2 — o
               ml_score do Isolation Forest não é uma probabilidade
               calibrada; inventar uma normalização seria um número com
               aparência de rigor que não tem)
  ref          apontador para o dado original (alerta bruto do Indexer /
               item de ml_anomalies.results / deteção de rede), NUNCA cópia
  label        rótulo curto (nome amigável do Event ID / "Anomalia ML
               (Isolation Forest)" / tipo de deteção de rede)
  description  texto mais longo opcional (recomendação / ml_score em bruto /
               src_ip -> dst_ip)
```

Três construtores puros, nunca lançam exceção, entrada inválida → `None`:
`from_rule_alert(raw)` (mesmo critério de validade que
`incident_engine.evidence_from_raw_alert` usava: `@timestamp` válido +
`agent.ip`), `from_ml_anomaly(result)` (só `ml_is_anomaly=True` vira
evento — uma linha "normal" não é uma deteção), `from_network_detection(det)`
(mesmo critério que `incident_engine.evidence_from_network_detection`
usava: `timestamp`/`type` válidos, `dst_ip` ou `src_ip` como asset).

`incident_engine.py` e `redblue_correlator.py` **não migraram** para expor
`DetectionEvent` como o seu contrato externo — continuam com as suas
formas próprias (evidência de incidente, "attempt" de correlação); usam
`detection_event.py` só como base de construção interna, sem mudar nada
observável de fora (ver
`docs/superpowers/specs/2026-10-07-r7-detection-engine-design.md`).

## Registo de modelo (R9)

Layout em disco:
```
scripts/models/ACTIVE                           uma linha UTF-8, p.ex. "v1"
scripts/models/vN/isolation_forest.pkl
scripts/models/vN/scaler.pkl
scripts/models/vN/metadata.json                   schema 1 (15 chaves)
scripts/models/{isolation_forest,scaler}.pkl     o "legado": nunca movidos nem apagados
```

Schema do `metadata.json` (15 chaves: 13 públicas + `evaluation` + `feature_stats`):
- `schema_version`: 1
- `version`: nome da pasta (ex.: "v1")
- `origin`: "trained" | "adopted"
- `adopted`: booleano, True se for adoptado
- `created_at`: ISO-8601, momento em que a versão foi criada no registo
- `trained_at`: ISO-8601 data do treino. Escrita **nos dois** casos: no
  `origin="trained"` a data é a do treino real; no `origin="adopted"` é
  *estimada* a partir do mtime do `.pkl` legado (o `adopt` não desserializa o
  pickle para a descobrir) — daí `trained_at_estimated: True`
- `trained_at_estimated`: booleano, True só quando `trained_at` foi estimada
- `model_type`: "IsolationForest"
- `parameters`: {contamination, random_state, n_estimators} — `None` no `adopt`
- `dataset`: {name (só `Path(...).name`), size, attacks, synthetic,
  documents, processable, truncated, window_first, window_last} —
  `size` são as linhas **processáveis**; `documents` é quantos documentos
  brutos entraram e `truncated` diz se bateram o tecto, para que "35 eventos"
  seja distinguível de "os 35 que couberam de 500". `synthetic` é
  **tri-estado**: `true`, `false` ou `null` (= origem não declarada)
- `library_versions`: {python, scikit-learn, joblib, numpy} — `None` no `adopt`
- `artifacts`: {`isolation_forest.pkl`: {"sha256": "...", "size_bytes": N},
  `scaler.pkl`: {"sha256": "...", "size_bytes": N}} — ambos obrigatórios
- `catalog_sha256`: hash de `event_catalog.CRITICAL_EVENTS` no momento do
  treino. `event_id_encoded` é o **índice posicional** no catálogo ordenado,
  por isso acrescentar um Event ID desloca todos os índices seguintes e
  invalida em silêncio qualquer `.pkl` antigo — o hash é o que transforma
  "não sei" em "sei que é incompatível"
- `evaluation`: `null` ou objeto (preenchido após `model_registry.py evaluate vN`)
- `feature_stats`: por feature, {mean, std} do **lote de treino**. Aviso
  importante: `is_new_source_ip` e `failed_attempts_last_hour` acumulam dentro
  do lote, por isso estes números descrevem o lote e não o comportamento —
  em serviço os lotes são de 1000. É por isso que se registam em vez de se
  esconderem
- `METADATA_PUBLIC_KEYS`: **13** chaves projectadas para a API — as 12
  originais mais `catalog_sha256`. `evaluation` e `feature_stats` **não**
  entram: são campos de nível superior projectados à parte
- `EVALUATION_PUBLIC_KEYS`: **14** chaves — a sub-projeção de `evaluation`,
  a mesma lista que `ml_evaluation.EVALUATION_KEYS` (igualdade verificada por
  `scripts/test_ml_models_api.py`)

**Regras de validade:** teto de 64 KB, `schema_version == 1`, `version` igual ao nome da pasta, `artifacts` com uma entrada por nome de `ARTIFACT_FILES` com `sha256` a casar `[0-9a-fA-F]{64}` e `size_bytes` int ≥ 0, `evaluation` `null` ou objeto.

**ArtifactSource:** `resolve_version_artifacts(models_dir, version_id)` lê e VERIFICA os dois `.pkl` de uma versão pedida. `ArtifactSource(version, verified, model_bytes, scaler_bytes)`.

**Resposta de `GET /api/ml/models`:**
- Versão ativa: devolve a versão apontada por `models/ACTIVE` com todos os metadados e estado de avaliação.
- Histórico: lista todas as versões `vN` em `models/`, cada uma com o seu `metadata.json`.
- Legado: enquanto só existirem os `.pkl` soltos (sem `v1/` e sem `ACTIVE`),
  a lista acrescenta uma entrada `kind: "legacy"` com `id: null`,
  `metadata: null`, `evaluation: null`, `status: "no_metadata"` e `files`
  (tamanho e mtime de cada `.pkl`, nunca os bytes) — **sem** `origin`, porque
  ainda não foi registada. O `active` de topo é `"legacy"` (é daqui que o
  modelo carrega, sem verificação de hash) ou `null` se nem isso existir.
  Depois de `model_registry.py adopt`, o `origin: "adopted"` passa a viver no
  `metadata.json` da `v1` — e a entrada de legado deixa de aparecer, porque a
  `v1` já existe.
- O `evaluation` só existe depois de `model_registry.py evaluate vN` — a versão treinada **nasce sem avaliação**.

Desde que existe o registo, o `Model` do Roadmap já não está "por definir".

## Ataque — linha de `scripts/attack_log.jsonl`

```json
{"scenario":"brute_force_rdp","target":"192.0.2.10","timestamp":"2026-10-06T10:24:08Z",
 "status":"launched","id":3,"technique":"T1110","tool":"hydra"}
```

- Obrigatórios para o correlator: `scenario` (chave de `SCENARIOS`), `target`,
  `timestamp` (ISO-8601, UTC se sem fuso), `status` (só `launched` conta).
- Opcionais (R0): `id` (→ `attack_id`), `technique` e `tool` — quando presentes
  prevalecem sobre os do cenário ao reportar MITRE/ferramenta.
- `scenario` só determina os `event_ids` esperados para a correspondência.
- Opcionais (R4): `operator` (≤64 car., default `unknown`), `source` (origem,
  default `null`) e `expected` (lista ⊂ `rule|ml|network`), gravados por
  `attack_scenarios.py --operator/--source/--expect`. Ficheiros antigos sem estes
  campos continuam a ler-se. `details` (comando) nunca é exposto pela API.
- Os registos podem não estar por ordem de tempo; o correlator ordena.

## Tentativa correlacionada — `build_redblue_report().attempts[]`

`attack_id, scenario, target, tool, timestamp, mitre_tactic, mitre_technique,
detected, detected_by (rule|ml|both|none), mttd_seconds, matched_event_ids,
detected_by_network, network_detection_types, mttd_network_seconds,
coverage_gap, matched_alert_count` (R4, aditivo).

## Registo de ataque (R4)

`attack_registry.build_attack_registry()` (puro) junta cada tentativa lançada
(`parse_launched_attacks`) com `build_redblue_report` e com os incidentes cujo
evento `attack_linked` tem o mesmo `attack_id`. Não é persistido: calcula-se a
cada pedido. Campos em [API.md](API.md#️-attack-registry-r4). Regras:
`expected.detection` vem do log ou, sem ele, `["rule","ml"]`; `actual.verdict`
é `detected` (todas as fontes esperadas viram), `partial`, `not_detected` ou
`unknown` (correlação indisponível, ou sem correspondência com alertas truncados:
`actual.correlation_reason = "alerts_truncated"`). Ataques sem `id` têm `id: null` e não
ligam a incidentes; ids duplicados levam `duplicate_id: true`. Desde a R5,
`expected.detection` sem `expected` no log vem de
`attack_library.get_expected_sensors(scenario)` (a biblioteca, ver abaixo);
`["rule","ml"]` fica como rede de segurança só para um cenário sem entrada lá.

## Biblioteca de ataques (R5)

`scripts/attack_library.yaml` (versionado, editorial) — uma entrada por
`scenario_name` de `attack_scenarios.SCENARIOS`:

```yaml
brute_force_rdp:
  name: "Força bruta de RDP"
  description: "Tentativas de autenticação RDP com dicionário de passwords contra o alvo."
  risk: medium
  prerequisites: "Alvo com RDP exposto; sem credenciais prévias; wordlist disponível na máquina atacante."
  expected_sensors: [rule, ml]
  cleanup_steps:
    - "Desbloquear a conta atacada se a política de bloqueio a tiver bloqueado."
  replayable: true
  replayable_reason: "Não altera estado persistente; cada corrida é independente (...)."
  duration_estimate: minutes
```

Campos obrigatórios por entrada: `name, description, risk (low|medium|high),
prerequisites, expected_sensors[] (⊂ rule|ml|network), cleanup_steps[]
(frases descritivas, nunca comandos/argv), replayable (bool),
replayable_reason, duration_estimate (seconds|minutes)`.
`attack_library.load_attack_library()` junta cada entrada com os campos já
existentes em `SCENARIOS` (`event_ids`, `mitre_tactic`, `mitre_technique`,
`tool`) — o YAML não os repete. Resposta de `GET /api/attack-library[/{id}]`
= a entrada combinada + `id` (= `scenario_name`). Nunca expõe
`build_command`/argv.

**Validação (fail-fast, síncrona, no arranque do backend)**: campo
obrigatório em falta, `risk`/`duration_estimate` fora da taxonomia,
`expected_sensors` fora de `rule|ml|network`, técnica MITRE (herdada de
`SCENARIOS`) fora do formato `Txxxx`/`Txxxx.xxx`, entrada no YAML sem par em
`SCENARIOS` → erro, processo não arranca. Cenário em `SCENARIOS` sem entrada
no YAML → aviso não-bloqueante (stderr), o arranque continua. Incoerências
risco/replayable/cleanup (decisão do utilizador, R5): `risk: low` com
`replayable: false`, ou `risk: low` com `cleanup_steps` vazio, são erros de
validação — o risco em si continua decidido à mão por entrada, não calculado.

## Vaccine (R11) — `vaccine_engine.py` + `vaccine_store.py` + `vaccine_ingest.py`

Uma vaccine é uma **proposta** de regra de deteção, gerada a partir de um ataque
do Red vs Blue que ficou `not_detected` ou `partial`. Nunca é aplicada no Wazuh,
nunca traz comandos e o estado é sempre `proposed` (aprovar ou rejeitar é o R12).
Persistida em SQLite (`scripts/vaccines.sqlite3`), gerada em segundo plano pelo
backend, servida só por leitura (`GET /api/vaccines[/{id}]`, ver
[API.md](API.md) (secção Vaccines (R11))). Exemplo de `GET /api/vaccines/{id}` (a vaccine
não guarda IPs, ferramentas nem alvos, só referências ao ataque):

```json
{"vaccine": {
  "id": "vac-bd617cce8054", "verdict": "partial",
  "expected": ["rule", "ml"], "expected_source": "scenario_default",
  "achieved": ["rule"], "missing_sensors": ["ml"],
  "proposals": [{"sensor": "ml", "rule": null, "events": null,
    "recommendation": "Rever o treino do modelo de anomalias: incluir este ataque e eventos semelhantes no conjunto de treino e reavaliar a versão antes de a ativar."}],
  "origin": {"attack_id": 3, "scenario": "lateral_movement_schtasks",
    "mitre_tactic": "Lateral Movement", "mitre_technique": "T1053",
    "incident_ids": ["INC-20261012-1"],
    "evidence": {"matched_event_ids": [4672, 4698], "matched_alert_count": 2, "network_detection_types": []}},
  "state": "proposed", "superseded_by": null, "created_at": "2026-10-12T10:41:07+00:00"}}
```

### Campos

Contrato fechado (`validate_vaccine` recusa chaves a mais ou a menos) e cada
texto vem de uma allowlist, por isso nenhum campo pode transportar um comando.

- **Vaccine** (`VACCINE_KEYS`): `id` (regra abaixo); `verdict` (`not_detected` ou
  `partial`); `expected` (sensores esperados, subconjunto de `rule|ml|network`);
  `expected_source` (`log` ou `scenario_default`, ou `null`); `achieved`
  (sensores que viram o ataque); `missing_sensors` (esperados menos
  alcançados, pela ordem `rule`, `ml`, `network`); `proposals` (uma por sensor
  em falta); `origin`.
- **`origin`** (`ORIGIN_KEYS`): `attack_id`; `scenario`; `mitre_tactic` e
  `mitre_technique` (podem ser `null`); `incident_ids` (só os ids `INC-AAAAMMDD-n`,
  nunca os incidentes completos); `evidence`.
- **`origin.evidence`** (`EVIDENCE_KEYS`): `matched_event_ids` (Event IDs que
  casaram); `matched_alert_count` (pode ser `null`); `network_detection_types`.
- **Proposta** (`PROPOSAL_KEYS`): `sensor`; `rule` (só na proposta `rule`,
  `null` nas outras); `events` (só na proposta `rule`, `null` nas outras);
  `recommendation` (texto em PT-PT nas propostas `ml` e `network`, `null` na `rule`).
- **`rule`** (`RULE_KEYS`): `event_ids` (os do cenário); `min_count` (sempre 1);
  `window_seconds` (300, a janela de correlação do Red vs Blue).
- **Evento** (`EVENT_KEYS`, em `events[]`): `event_id`; `name` e `severity`
  vêm de `event_catalog.classify_alert`.
- **Campos do store** (`STORE_FIELDS`, acrescentados ao ler): `state` (sempre
  `proposed`); `superseded_by` (id da vaccine que a substituiu, ou `null`);
  `created_at` (ISO-8601, quando o ciclo a gravou).

### Regras

- **Quem gera:** só ataques `not_detected` ou `partial`. `detected` e `unknown`
  nunca geram, incluindo o `unknown` por alertas truncados (nada falhou, só
  não se sabe) e o `unknown` por fonte indisponível. Sem id de ataque, id
  duplicado, sensores em falta vazios ou sem Event IDs numa proposta `rule`: não
  gera e conta em `skipped`.
- **Uma vaccine por ataque**, com uma proposta por sensor em falta. Só a
  proposta `rule` tem regra: `{event_ids do cenário, min_count 1, window_seconds 300}`.
  As propostas `ml` e `network` só têm a recomendação em texto.
- **O id** é `vac-` mais 12 hex de sha256 de `<attack_id>:<sensores em falta
  pela ordem rule, ml, network, unidos por vírgula>`. É determinístico:
  reprocessar o mesmo ataque com o mesmo veredito não duplica. Deteta troca ou
  duplicação mas **não autentica**: quem consegue editar o `attack_log` ou o
  ficheiro SQLite também consegue forjar um id coerente.
- **`superseded_by`:** a vaccine atual de um ataque é a última que o motor emitiu.
  Quando o veredito muda, a anterior fica guardada com `superseded_by` a apontar
  para a nova (vaivém A, B, A repõe A). Um ataque que passa a `detected` não mexe
  nas suas vaccines. A lista só mostra as atuais; as substituídas aparecem com
  `include_superseded=true` e no detalhe.
- **O store impõe as regras no próprio ficheiro:** `CHECK (state = 'proposed')`,
  `CHECK (json_valid(payload))`, trigger que recusa DELETE e trigger que recusa
  UPDATE de tudo menos `superseded_by`. A escrita é `INSERT ... ON CONFLICT(id)
  DO NOTHING` e não `INSERT OR IGNORE`: este também engole em silêncio uma
  violação de CHECK (sem erro), o que anularia a garantia do estado; o
  `ON CONFLICT` só ignora a chave repetida e deixa um CHECK violado levantar erro.
- **O GET nunca escreve:** abre o ficheiro em modo só-leitura e, se ele ainda não
  existir, não o cria (responde vazio). Só o ciclo do gerador escreve. Caminho
  em `SENTRYLENS_VACCINES_DB_PATH` (relativo resolve-se contra a pasta do
  módulo, nunca contra o cwd); o ficheiro e o `-journal` estão no `.gitignore`.

### Gerador

O backend corre um ciclo no arranque e depois a cada
`SENTRYLENS_VACCINE_INTERVAL_SECONDS` (omissão 300; aceita 30 a 86400).
Cada ciclo olha para os ataques dos últimos `SENTRYLENS_VACCINE_WINDOW_HOURS`
(omissão 168; 1 a 720) e só grava vaccines de ataques mais velhos que
`SENTRYLENS_VACCINE_SETTLE_SECONDS` (omissão 600; 300 a 86400): um ataque
avaliado segundos depois de lançado sai `not_detected` só porque os alertas
ainda não chegaram, e essa vaccine falsa ficaria para sempre. Um valor inválido
volta à omissão com aviso. Na prática, uma vaccine só aparece cerca de 10 min
depois do ataque, mais até 5 min do intervalo. Com a base de incidentes
indisponível nada é gravado. Com alertas truncados (teto de 8000 do Indexer, `ATTACK_ALERTS_SIZE` em `main.py`; paliativo, volta a truncar quando o ruído crescer)
grava na mesma e sinaliza em `alerts_truncated`.

Contagens por ciclo (`COUNT_KEYS`): `inserted` (novas), `existing` (já existiam),
`rejected` (recusadas por `validate_vaccine`), `pending_settle` (ataques ainda a
assentar), `outside_window` (mais velhos que a janela).

O bloco `generator` do envelope (`GENERATOR_KEYS`): `status`, `error_code`,
`last_run_at`, `last_success_at` (preservado quando um ciclo falha),
`alerts_truncated` (`null` em erro e antes do 1.º ciclo) e `counts` (`null` se
nunca correu). `status` (`GENERATOR_STATUSES`): `never_run` (ainda sem ciclo,
incluindo depois de reiniciar), `ok`, `no_data` (attack log vazio, sem chamar o
Indexer) e `error`. `error_code` (`GENERATOR_ERROR_CODES`, ou `null`):

| `error_code` | Falha |
|---|---|
| `indexer_unavailable` | Wazuh Indexer em baixo |
| `ml_model_unavailable` | modelo ML em falta ou corrompido |
| `attack_outside_alert_window` | a correlação não cobre os ataques do log (mais antigos que os alertas obtidos) |
| `source_unavailable` | o motor não conseguiu confirmar a fonte e a correlação não deu um código mais específico |
| `attack_log_unreadable` | attack log ilegível |
| `incidents_unavailable` | base de incidentes em baixo (nada gravado) |
| `store_unavailable` | escrita no store falhou |
| `unexpected_error` | qualquer outra exceção |

O estado do gerador vive em memória: depois de reiniciar o backend volta a
`never_run` até ao primeiro ciclo. Nunca leva texto de exceção, só o código.

### Envelope de `GET /api/vaccines`

`{available, reason, total, limit, offset, vaccines[], generator}`. `reason:
"no_data"` (e `available: false`) só quando o store não tem nenhuma linha; um
filtro sem resultados com o store não vazio dá `reason: null`, `available: true`
e lista vazia. `GET /api/vaccines/{id}` dá 404 `entry_not_found` para um id
válido que não existe. Falha a ler o store dá 503 `store_unavailable`, sem texto
de exceção nem caminho. Qualquer escrita (POST, PUT, PATCH, DELETE) dá 405: não
há rota de escrita.

### Limites conhecidos

- **A7:** a leitura não volta a correr `validate_vaccine`; uma linha adulterada
  diretamente no ficheiro seria servida (o mesmo limite dos `.pkl`).
- **A8:** as deteções de rede estão em memória e ficam vazias depois de um
  reinício; um ataque com `network` esperado, avaliado logo a seguir, pode gerar
  uma proposta `network` falsa.
- **A3:** com alertas truncados as vaccines gravam-se na mesma; o risco fica
  sinalizado em `generator.alerts_truncated`.
- **A5:** o estado do gerador é em memória (ver acima).
- O id não autentica (ver Regras). Uma vaccine é só uma proposta: nunca aplicada,
  aprovada nem validada; escrever, aprovar e rejeitar é o R12.

## Alerta enriquecido — `main._enrich_alert`

`timestamp, agent_name, agent_ip, rule_id, rule_description, wazuh_level,
windows_event_id, friendly_name, severity, category, recommendation, full_log`.

## Deteção de rede — `network_detections.detect_network_anomalies`

`type (port_scan|brute_force|volume_spike), src_ip, dst_ip, timestamp, detail`.

## Network SOC (R6) — `network_soc.py` + persistência de deteções

Três resumos puros sobre os mesmos dados de `network_monitor.py`/
`network_detections.py` (pacotes capturados via tshark/SSH, deteções de
padrão), sem reimplementar captura nem deteção:

- `summarize_packets(packets)` → `{total, window_start, window_end,
  by_protocol{}, top_talkers[{src_ip, packets}] (top 10), top_ports[{port,
  packets}] (top 10)}` — painel "Live Traffic".
- `summarize_detections(live, history)` → `{live_count, history_count,
  by_type{}, recent[] (até 50, mais recente primeiro)}` — painel "Network
  Detections".
- `build_evidence_report(entries, configured)` → `{configured, entries[],
  total, payload_capture: false, note}` — painel "PCAP / Evidence".

**Persistência das deteções** (`history_store.py`, resolve a dívida de R0
"deteções de rede só existem em memória"):
`historico/AAAA/MM-mês/AAAA-MM-DD-network-detections.jsonl`, JSONL
append-only, mesmo padrão de `AAAA-MM-DD-alerts.jsonl`. Cada linha:
`{date, time, type, src_ip, dst_ip, detail}` — metadados só, nunca payload.
Escrita por `append_network_detection(s)_history`, ligada ao callback
`on_new_detections` que `network_poll_loop` já chama (sem segundo poller).
Leitura por `read_network_detection_history(base_dir, date_str=None,
limit=100)` — `limit` sempre capeado a `NETWORK_EVIDENCE_MAX_LIMIT` (500),
dia inválido/ficheiro ausente/linha malformada → `[]`/ignorada, nunca
exceção. **Nunca é uma captura PCAP real**: `network_monitor._parse_fields_line`
só lê 11 campos de cabeçalho exportados pelo tshark (timestamps, IPs,
portas, protocolo, flags TCP) — não há payload capturado para exportar.

## Incidente (R3)

Base `scripts/incidents.sqlite3` (`INCIDENTS_DB_PATH`, fora do git). Três tabelas:

```
incidents(id PK, status, severity, asset,
          created_at, first_evidence_at, last_evidence_at, updated_at)
incident_evidence(rowid_ PK AUTOINCREMENT, incident_id FK, key UNIQUE,
                  kind, ts, severity, payload)
incident_events(id PK AUTOINCREMENT, incident_id FK, ts, kind, actor, data)
```

- `status`: `NEW|INVESTIGATING|CONTAINED|RESOLVED|CLOSED`. `severity`: máximo das
  evidências (`info < low < medium < high < critical`). `asset`: IP (`agent.ip`
  nos alertas; `dst_ip` ou `src_ip` nas deteções de rede). Datas em ISO-8601 UTC.
- `incident_evidence.kind`: `wazuh_alert` (payload = alerta bruto do Indexer) ou
  `network_detection` (payload = deteção de rede). `payload` e `data` são JSON.
- **ID** `INC-AAAAMMDD-NNN`: `AAAAMMDD` é o dia da **1.ª evidência** (não da
  criação, para o backfill dar IDs com sentido) e `NNN` a sequência diária.
- **Chaves de deduplicação** (`incident_evidence.key`, UNIQUE):
  `alert:<_id do documento no Indexer>` e
  `net:<tipo>:<src_ip>:<dst_ip>:<timestamp[:16]>` (granularidade ao minuto).
- **Tipos de evento** (`incident_events.kind`): `created`, `evidence_added`,
  `attack_linked`, `severity_changed`, `status_changed`, `note_added`.
  `actor` é `system` (automático) ou `analyst` (estado/notas; autor fixo).
  Dados: `status_changed` → `{from, to, note?}`; `note_added` → `{text}`;
  `attack_linked` → `{ref, attack_id, scenario, technique, tool, attack_timestamp}`.
- **`incident_events` é append-only**: triggers SQLite abortam qualquer
  `UPDATE`/`DELETE`.
- **Derivados (não guardados)**: `attack_ids`/`techniques` (dos eventos
  `attack_linked`); `mttd_seconds` = `first_evidence_at` − ataque ligado mais
  antigo (`null` sem ataque); `time_to_first_response_seconds` = 1.º
  `status_changed → INVESTIGATING` − `first_evidence_at` (`created_at` no
  backfill é a hora da importação, por isso não serve); `ml_summary`
  (`{scored, ml_anomalies, rule_flagged}` ou `null`) calculado no detalhe.
- **Regras de agrupamento**: mesma evidência (`key`) → duplicada; mesmo `asset`
  com incidente aberto (`NEW|INVESTIGATING|CONTAINED`) e gap ≤
  `INCIDENT_GAP_SECONDS` (600) → anexa; senão abre se for deteção de rede ou
  severidade ≥ `INCIDENT_OPEN_MIN_SEVERITY` (`medium`); senão ignora.

## Definição de MTTD em vigor

`mttd_seconds = timestamp do 1º alerta correspondente − timestamp do ataque`,
dentro da janela (`window_seconds`, cortada pelo ataque seguinte). Campos
`detected`/`mttd_seconds` auto-declarados em `attack_log_round3.jsonl` **não**
são usados.

## Definições de métricas em vigor (R8, `soc_metrics.py`)

- **MTTD** = tempo entre o ataque lançado e a 1.ª deteção *sinalizada* (regra, ML
  ou rede; a mais cedo). Um alerta correspondente mas não sinalizado não conta.
- **MTTR** = `first_evidence_at` do incidente → a sua **última** passagem a
  `RESOLVED`; só incidentes que chegaram a `RESOLVED` (ou `CLOSED` depois de
  resolvidos). Os abertos contam-se à parte (`open_count`).
- **FN** = ataque lançado sem qualquer deteção sinalizada.
- **FP** = incidente fechado de `NEW` para `CLOSED` (a nota é obrigatória).
  Taxa = FP / incidentes fechados, só com amostra ≥ `METRICS_MIN_SAMPLE`.
- **Cobertura** = cenários/técnicas lançados na janela com pelo menos uma
  deteção; lacuna = lançado e nunca detetado.
- Sem amostra o valor é `null` (nunca 0). `alerts_truncated` = o teto de 1000
  alertas do Indexer foi atingido (os valores são limites inferiores).
