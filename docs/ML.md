# Deteção de anomalias por Machine Learning

> ⚠️ **Nada disto foi treinado ou validado com dados reais do
> laboratório.** O modelo é treinado sobre um fixture sintético; os
> números abaixo provam que o *pipeline* funciona de ponta a ponta —
> não são uma estimativa de taxa de deteção em produção. Validação real
> requer correr `attack_scenarios.py` contra o laboratório, exportar
> com `export_snapshot.py`, e retreinar. Ainda não aconteceu.

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
mesmo minuto). É esse par export/retreino que falta para passar de
"pipeline validado" a "deteção validada".

## Nota sobre o seletor de período no painel ML

O seletor de período partilhado do dashboard (7/30/90 dias) é
convertido para horas e limitado a 168h (7 dias) só neste painel —
escolher "30" ou "90 dias" continua a mostrar só os últimos 7 dias de
análise de ML (`refreshNewPanels()` em `app.js`).
