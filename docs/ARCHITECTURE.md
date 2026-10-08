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
| Red/Blue | `attack_scenarios.py`, `redblue_correlator.py`, `attack_registry.py` (R4, puro), `attack_library.py` (R5, catálogo só-leitura) |
| Rede | `network_monitor.py`, `network_detections.py`, `network_soc.py` (R6, resumos puros para os painéis dedicados) |
| ML | `feature_extractor.py` (partilhado treino/inferência), `ml_anomalies.py`, `train_anomaly_model.py` |
| Persistência | `history_store.py` (JSONL), `history_index.py` (SQLite) |
| Incidentes | `incident_engine.py` (puro), `incident_store.py`, `incident_ingest.py` |
| Deteção (R7) | `detection_event.py` (puro, tipo `DetectionEvent` comum) |
| Relatórios | `report_generator.py`, `export_snapshot.py` |

Detetores independentes hoje: **regra** (Wazuh/`event_catalog`), **ML**
(Isolation Forest) e **rede** (`network_detections`). O correlator une-os por janela
temporal + IP alvo e, desde o R3, os **incidentes** agrupam as três fontes por
ativo (alertas Wazuh e deteções de rede como evidências, ML como resumo).
Desde o R7 há um `DetectionEvent` comum (`detection_event.py`, puro, 3
construtores: `from_rule_alert`/`from_ml_anomaly`/`from_network_detection`) —
`incident_engine.py` constrói as suas evidências sobre ele por dentro (sem
mudar o shape externo) e `redblue_correlator.py` usa-o para rotular
`network_detection_types` de forma partilhada; o algoritmo de
janelas/correspondência do correlator não foi tocado (risco demasiado alto
para esta fase — ver spec R7). `GET /api/detections` é o primeiro consumidor
direto do tipo comum: vista unificada recente das 3 fontes, sem painel
frontend ainda (dívida documentada, ver `docs/ROADMAP_STATUS.md`).

## Frontend

Estático, sem build. `index.html` tem a sidebar (grupos → itens). Cada item
com `data-tab="x"` mostra `#tab-x`; itens `is-planned` (`data-planned="R<n>"`)
mostram `#tab-planned` com "Sem dados". `app.js` expõe `activateTab(name)` e
usa o hash da URL para deep links. `attack_registry.js` (R4) serve os itens Attack Registry e Attack Timeline (um só pedido a `/api/attacks`, só com a aba visível). `attack_library.js` (R5) serve o item Attack Library: um só pedido a `/api/attack-library` por ativação da aba (catálogo estático, não depende do período selecionado), filtros por risco/sensor aplicados em memória. `network_soc.js` (R6) serve os 3 itens "Network" (Live Traffic/Network Detections/PCAP Evidence): cada painel só pede dados com a sua aba ativa e o separador visível, reaproveita os dados de `network_monitor.py`/`network_detections.py` já expostos a `redblue.js` (que mantém o seu próprio painel de rede, com nota de link cruzado para estas abas) — sem abrir um 2º WebSocket. `redblue.js` reutiliza os globais de `app.js`.

## Persistência (fontes de verdade atuais)

| Dado | Onde | Versionado |
|---|---|---|
| Alertas + conformidade (histórico) | `scripts/historico/**.jsonl` + `index.sqlite3` | não |
| Log de ataques | `scripts/attack_log.jsonl` (lido por `/api/attacks`, só leitura; mantém-se no `.gitignore` por poder ter IPs do lab) | não (`.gitignore`) |
| Modelo ML | `scripts/models/*.pkl` | não |
| Snapshots de treino | `scripts/snapshots/` | não |
| Incidentes (R3) | `scripts/incidents.sqlite3` (evidências + timeline append-only) | não (`.gitignore`) |
| Deteções de rede | memória (`deque` 5000) | não — perde-se no restart |
