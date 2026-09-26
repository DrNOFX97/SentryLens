# Deteção de anomalias por Machine Learning

> ⚠️ Os números abaixo (fixture sintético) provam que o *pipeline*
> funciona de ponta a ponta — não são uma estimativa de taxa de deteção
> em produção. Um primeiro ciclo com dados **reais** do laboratório já
> aconteceu (2026-09-14) — ver [Ciclo de validação com dados
> reais](#ciclo-de-validação-com-dados-reais) abaixo — mas a amostra
> continua pequena; os resultados sintéticos ficam como referência de
> metodologia.

O painel **🧠 ML Anomalias** usa um `IsolationForest` (scikit-learn)
lado a lado com a classificação por regras já existente
(`scripts/event_catalog.py`) — um segundo ponto de vista, nunca um
substituto.

## Features (`scripts/feature_extractor.py`)

Módulo único, partilhado entre treino e inferência, para que a lógica
nunca divirja. 7 features por alerta: `hour_of_day`, `day_of_week`,
`event_id_encoded`, `failed_attempts_last_hour`,
`has_special_privileges`, `is_new_source_ip`, `severity_encoded`.

## Retreinar

```bash
cd scripts
python train_anomaly_model.py
```

Lê `sample_events_real.json` + `sample_attack_log.jsonl` por default
(aceita `--events`/`--attack-log` para outros ficheiros, ex. um
snapshot exportado do laboratório real), treina `IsolationForest` +
`StandardScaler`, e escreve:

- `scripts/models/isolation_forest.pkl` + `scaler.pkl` — não
  versionados (`.gitignore`); o endpoint `/api/ml-anomalies` devolve
  `503` até estes existirem.
- `scripts/ml_training_report.json` — este é committed.

## Resultados no fixture sintético (36 eventos, 5 ataques rotulados)

| | Precisão | Recall | F1 |
|---|---|---|---|
| ML (Isolation Forest) | 0,4286 | 0,6 | 0,5 |
| Regras (`event_catalog.py`) | 0,625 | 1,0 | 0,7692 |

3 alertas sinalizados por ambas as abordagens, 4 só pelo ML, 5 só pelas
regras, 24 por nenhuma — uma divergência genuína, é esse contraste que
é o ponto do exercício.

## Ciclo de validação com dados reais

`scripts/attack_scenarios.py` corre-se manualmente na VM Kali contra o
agente Windows do laboratório (`--list` mostra os cenários
disponíveis), e regista cada um em `scripts/attack_log.jsonl`, que o
`feature_extractor.py` usa para atribuir o rótulo `is_attack` por
correspondência de timestamp.

`scripts/export_snapshot.py` exporta `/api/alerts` + `/api/stats` +
`attack_log.jsonl` para `scripts/snapshots/AAAA-MM-DD_HH-MM.json`
(nunca sobrescreve — acrescenta `_2`, `_3`, ... se já houver um para o
mesmo minuto); autentica-se com `--api-key` (default: env
`SENTRYLENS_API_KEY`).

### Primeiro ciclo real (2026-09-14)

5 cenários lançados a partir da VM `Kali-Atacante` contra o agente
Windows alvo (`smb_enum`, `blank_password_check`,
`account_lockout_spray`, `lateral_movement_schtasks`,
`brute_force_rdp`) capturaram **500 alertas reais** no Wazuh Indexer.
Como `export_snapshot.py` exporta o formato já classificado de
`/api/alerts` (incompatível com o formato bruto que
`feature_extractor.py` espera), os 500 documentos brutos foram obtidos
diretamente do Indexer para este treino — gap registado para uma
sessão futura, se o export também precisar de alimentar retreinos.

De 500 alertas, **35 eventos eram processáveis** (timestamp + Event ID
válidos), **20 rotulados `is_attack`** por correspondência de janela
temporal. Resultado (`scripts/ml_training_report.json`, `caveat`
dinâmico consoante o ficheiro de eventos usado — ver
`train_anomaly_model.py`):

| | Precisão | Recall | F1 |
|---|---|---|---|
| ML (Isolation Forest) | 0,8571 | 0,3 | 0,4444 |
| Regras (`event_catalog.py`) | 0,875 | 0,35 | 0,5 |

5 alertas sinalizados por ambas as abordagens, 2 só pelo ML, 3 só pelas
regras, 25 por nenhuma. Amostra ainda pequena (35 eventos) — próximo
passo natural: repetir `attack_scenarios.py --all` ao longo de vários
dias e re-exportar/retreinar para uma amostra mais robusta.

## 🥊 Correlação Red vs Blue (`GET /api/redblue/metrics`, Fase 11)

Fase 11 (Onda 1): cruza o log de ataques da VM Kali
(`scripts/attack_log.jsonl`, `attack_scenarios.py`) com os alertas já
classificados por regra + ML (`ml_anomalies.build_ml_anomalies_report`,
acima), por cenário de ataque — cobertura, MTTD (tempo até à primeira
deteção) e se foi apanhado por regra, por ML, por ambos ou por nenhum.
Frontend (10ª aba) ainda não implementado — Onda 2.

Função pura `scripts/redblue_correlator.py::build_redblue_report()`:
um alerta só conta como deteção de um ataque se o IP do agente bater
com o alvo do ataque **e** o Event ID estiver na lista de
`event_ids` desse cenário, dentro da janela `[timestamp,
min(timestamp + window_seconds, timestamp da tentativa seguinte)]`.

| Parâmetro | Tipo | Default | Descrição |
|---|---|---|---|
| `hours` | int (1–168) | 168 | Janela temporal para buscar alertas ao Indexer |
| `window_seconds` | int (30–3600) | 300 | Janela de correlação por tentativa de ataque, cortada pela tentativa seguinte no log |

```json
{
  "attempts": [
    {
      "scenario": "brute_force_rdp",
      "target": "192.168.1.169",
      "timestamp": "2026-09-14T15:34:27.258872+00:00",
      "mitre_tactic": "Credential Access",
      "mitre_technique": "T1110",
      "detected": true,
      "detected_by": "rule",
      "mttd_seconds": 8.4,
      "matched_event_ids": [4625]
    }
  ],
  "by_scenario": {
    "brute_force_rdp": {
      "attempts": 1, "detected": 1, "detected_by_rule": 1, "detected_by_ml": 0,
      "detected_by_both": 0, "detected_by_none": 0, "coverage_rate": 1.0, "avg_mttd_seconds": 8.4
    }
  },
  "overall": {"total_attempts": 5, "detected": 4, "coverage_rate": 0.8, "avg_mttd_seconds": 12.1},
  "not_executed": [],
  "unknown_scenario": [],
  "invalid_entries": [],
  "window_hours": 168,
  "alerts_fetched": 372,
  "alerts_truncated": false
}
```

Erro → `503` se o modelo ML ainda não foi treinado, `502` se o Wazuh
Indexer não responder. Ataques com `status` diferente de `launched`
(skipped/failed) entram em `not_executed`, nunca contam para as
métricas de cobertura. Entradas malformadas do log (não-dict ou
timestamp impossível de parsear) são desviadas para `invalid_entries`
— nunca descartadas em silêncio nem contadas como tentativa. Em cada
cenário, `detected_by_rule + detected_by_ml + detected_by_both +
detected_by_none == attempts`.

O fetch de alertas ao Indexer está limitado a 1000 (mais recentes
primeiro): `alerts_fetched` diz quantos vieram e `alerts_truncated`
fica `true` quando esse teto é atingido — nessa situação tentativas
antigas podem cair fora da janela e aparecer como não detetadas por
truncagem, não por falha real de deteção.

> **Nota sobre `--target` / correspondência:** a correlação faz um
> *exact string compare* contra o `agent.ip` do Wazuh, por isso o
> `--target` dos cenários de ataque tem de ser o **IP do agente** (não
> um hostname). Um hostname como alvo produz silenciosamente 0% de
> cobertura.

> ⚠️ **Nota histórica:** até 2026-09-26, `attack_scenarios.py` gravava
> o timestamp de cada tentativa **no fim** do ataque (depois do
> `subprocess.run` retornar), não no início — desalinhava ligeiramente
> as janelas de correlação nos ataques mais lentos. Corrigido: o
> timestamp passa a ser capturado antes do lançamento, e o tempo
> decorrido fica registado em `details.duration_seconds` no
> `attack_log.jsonl`. Timeouts (ex: hydra a esgotar `--timeout`) também
> passaram a contar como `status="launched"` (com `details.timed_out`),
> em vez de caírem em `not_executed` apesar de terem gerado tráfego
> real.

**Testes:** `scripts/test_redblue.py`.

## Nota sobre o seletor de período no painel ML

O seletor de período partilhado do dashboard (7/30/90 dias) é
convertido para horas e limitado a 168h (7 dias) só neste painel —
escolher "30" ou "90 dias" continua a mostrar só os últimos 7 dias de
análise de ML (`refreshNewPanels()` em `app.js`).
