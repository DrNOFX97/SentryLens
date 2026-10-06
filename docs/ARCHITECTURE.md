# Arquitetura (estado em 2026-10-06)

```
Kali (attack_scenarios.py) ──► attack_log.jsonl ─┐
                                                 ▼
Alvos Windows ─► agente Wazuh ─► Manager/Indexer ─► main.py (FastAPI :8001)
VM Wazuh ─► tshark (SSH) ─► network_monitor ──────►   │  REST /api/*  (X-API-Key)
                                                      │  WS /ws/alerts, /ws/network
                                                      ▼
                       index.html + app.js + redblue.js  (sidebar R1, :5500)
```

## Backend (`scripts/`)

`main.py` é só a camada HTTP + loops de background; a lógica de cada painel
vive em módulos puros que recebem dados já obtidos (testáveis sem Wazuh):

| Domínio | Módulos |
|---|---|
| Ingestão Wazuh | `wazuh_client.py`, `event_catalog.py` |
| Painéis | `lifecycle.py`, `rbac.py`, `admin_activity.py`, `compliance_evaluator.py` |
| Red/Blue | `attack_scenarios.py`, `redblue_correlator.py` |
| Rede | `network_monitor.py`, `network_detections.py` |
| ML | `feature_extractor.py` (partilhado treino/inferência), `ml_anomalies.py`, `train_anomaly_model.py` |
| Persistência | `history_store.py` (JSONL), `history_index.py` (SQLite) |
| Relatórios | `report_generator.py`, `export_snapshot.py` |

Detetores independentes hoje: **regra** (Wazuh/`event_catalog`), **ML**
(Isolation Forest) e **rede** (`network_detections`). Só o correlator os une,
por janela temporal + IP alvo — não há `DetectionEvent` comum (R7).

## Frontend

Estático, sem build. `index.html` tem a sidebar (grupos → itens). Cada item
com `data-tab="x"` mostra `#tab-x`; itens `is-planned` (`data-planned="R<n>"`)
mostram `#tab-planned` com "Sem dados". `app.js` expõe `activateTab(name)` e
usa o hash da URL para deep links. `redblue.js` reutiliza os globais de `app.js`.

## Persistência (fontes de verdade atuais)

| Dado | Onde | Versionado |
|---|---|---|
| Alertas + conformidade (histórico) | `scripts/historico/**.jsonl` + `index.sqlite3` | não |
| Log de ataques | `scripts/attack_log.jsonl` | não (`.gitignore`) |
| Modelo ML | `scripts/models/*.pkl` | não |
| Snapshots de treino | `scripts/snapshots/` | não |
| Deteções de rede | memória (`deque` 5000) | não — perde-se no restart |
