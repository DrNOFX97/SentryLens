# Modelo de dados (estado em 2026-10-07)

Só o que já existe. Entidades do Roadmap v2 (Incident, Detection, Vaccine,
Replay, Model…) estão por definir nas fases R3–R14.

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

## Alerta enriquecido — `main._enrich_alert`

`timestamp, agent_name, agent_ip, rule_id, rule_description, wazuh_level,
windows_event_id, friendly_name, severity, category, recommendation, full_log`.

## Deteção de rede — `network_detections.detect_network_anomalies`

`type (port_scan|brute_force|volume_spike), src_ip, dst_ip, timestamp, detail`.

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
são usados. MTTR ainda não existe (R8).
