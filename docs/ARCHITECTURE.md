# Arquitetura (estado em 2026-10-07)

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
| Red/Blue | `attack_scenarios.py`, `redblue_correlator.py`, `attack_registry.py` (R4, puro) |
| Rede | `network_monitor.py`, `network_detections.py` |
| ML | `feature_extractor.py` (partilhado treino/inferência), `ml_anomalies.py`, `train_anomaly_model.py` |
| Persistência | `history_store.py` (JSONL), `history_index.py` (SQLite) |
| Incidentes | `incident_engine.py` (puro), `incident_store.py`, `incident_ingest.py` |
| Relatórios | `report_generator.py`, `export_snapshot.py` |

Detetores independentes hoje: **regra** (Wazuh/`event_catalog`), **ML**
(Isolation Forest) e **rede** (`network_detections`). O correlator une-os por janela
temporal + IP alvo e, desde o R3, os **incidentes** agrupam as três fontes por
ativo (alertas Wazuh e deteções de rede como evidências, ML como resumo) — mas
não há `DetectionEvent` comum (R7).

## Frontend

Estático, sem build. `index.html` tem a sidebar (grupos → itens). Cada item
com `data-tab="x"` mostra `#tab-x`; itens `is-planned` (`data-planned="R<n>"`)
mostram `#tab-planned` com "Sem dados". `app.js` expõe `activateTab(name)` e
usa o hash da URL para deep links. `attack_registry.js` (R4) serve os itens Attack Registry e Attack Timeline (um só pedido a `/api/attacks`, só com a aba visível). `redblue.js` reutiliza os globais de `app.js`.

## Persistência (fontes de verdade atuais)

| Dado | Onde | Versionado |
|---|---|---|
| Alertas + conformidade (histórico) | `scripts/historico/**.jsonl` + `index.sqlite3` | não |
| Log de ataques | `scripts/attack_log.jsonl` (lido por `/api/attacks`, só leitura; mantém-se no `.gitignore` por poder ter IPs do lab) | não (`.gitignore`) |
| Modelo ML | `scripts/models/*.pkl` | não |
| Snapshots de treino | `scripts/snapshots/` | não |
| Incidentes (R3) | `scripts/incidents.sqlite3` (evidências + timeline append-only) | não (`.gitignore`) |
| Deteções de rede | memória (`deque` 5000) | não — perde-se no restart |
