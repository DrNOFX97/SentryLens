# Modelo de dados (estado em 2026-10-06)

Só o que já existe. Entidades do Roadmap v2 (Incident, Detection, Vaccine,
Replay, Model…) estão por definir nas fases R3–R14.

## Ataque — linha de `scripts/attack_log.jsonl`

```json
{"scenario":"brute_force_rdp","target":"192.168.1.169","timestamp":"2026-10-06T10:24:08Z",
 "status":"launched","id":3,"technique":"T1110","tool":"hydra"}
```

- Obrigatórios para o correlator: `scenario` (chave de `SCENARIOS`), `target`,
  `timestamp` (ISO-8601, UTC se sem fuso), `status` (só `launched` conta).
- Opcionais (R0): `id` (→ `attack_id`), `technique` e `tool` — quando presentes
  prevalecem sobre os do cenário ao reportar MITRE/ferramenta.
- `scenario` só determina os `event_ids` esperados para a correspondência.
- Os registos podem não estar por ordem de tempo; o correlator ordena.

## Tentativa correlacionada — `build_redblue_report().attempts[]`

`attack_id, scenario, target, tool, timestamp, mitre_tactic, mitre_technique,
detected, detected_by (rule|ml|both|none), mttd_seconds, matched_event_ids,
detected_by_network, network_detection_types, mttd_network_seconds,
coverage_gap`.

## Alerta enriquecido — `main._enrich_alert`

`timestamp, agent_name, agent_ip, rule_id, rule_description, wazuh_level,
windows_event_id, friendly_name, severity, category, recommendation, full_log`.

## Deteção de rede — `network_detections.detect_network_anomalies`

`type (port_scan|brute_force|volume_spike), src_ip, dst_ip, timestamp, detail`.

## Definição de MTTD em vigor

`mttd_seconds = timestamp do 1º alerta correspondente − timestamp do ataque`,
dentro da janela (`window_seconds`, cortada pelo ataque seguinte). Campos
`detected`/`mttd_seconds` auto-declarados em `attack_log_round3.jsonl` **não**
são usados. MTTR ainda não existe (R8).
