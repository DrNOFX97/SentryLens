# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# SentryLens — CET

Projeto do CET (curso de cibersegurança) com duas fases que partilham a mesma
lógica de classificação de Event IDs:

- **Fase 1** — `log_analyzer.py` (raiz): analisa ficheiros de log estáticos
  (JSON/CSV) e gera um relatório HTML autónomo. Sem dependências externas
  (só stdlib).
- **Fase 2** *(o essencial deste repo)* — `scripts/` tem o backend FastAPI
  (`main.py` + módulos de domínio) que liga às APIs do Wazuh (Manager API
  porta 55000, Indexer API porta 9200) e expõe dados prontos para o
  dashboard. `index.html`/`style.css`/`app.js`/`ui_helpers.js` e um `*.js` por aba
  (raiz) são o frontend estático que consome esse backend (ver "Frontend (raiz)"). Desde a sessão de 2026-09-13/14 o backend também
  tem autenticação por API key, push em tempo real via WebSocket,
  persistência de histórico própria, exportação de relatório HTML e uma
  camada de conformidade regulatória (RGPD/NIS2/AI Act) — ver secções
  próprias abaixo.

`README.md` na raiz é a fonte de verdade sobre arquitetura, endpoints e
troubleshooting — está em português e é mantido atualizado a cada sessão de
trabalho. `docs/README.md` está desatualizado (descreve uma estrutura
`backend/`/`frontend/` antiga) — não confiar nele para a estrutura atual.

## Início rápido

**A forma mais fácil de ter tudo a correr:**

```bash
# 1. Setup inicial (só uma vez)
cd scripts
python -m venv .venv
# Ativar o venv (Git Bash):
source .venv/Scripts/activate
# Ou PowerShell:
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
cp .env.example .env          # depois editar com credenciais reais do Wazuh

# 2. Todos os dias — a partir da raiz do repo:
# (Assume que o laboratório Wazuh já está ligado)
.\scripts\start-backend.ps1      # arranca backend em background, redirecionado para backend.log
.\scripts\start-frontend.ps1     # arranca frontend em background e abre o browser
```

Se preferir manual:
```bash
# Backend (a partir de `scripts/`):
uvicorn main:app --reload --port 8001   # NUNCA 8000 — ocupada por serviço de terceiros neste PC

# Frontend (a partir da raiz do repo):
python -m http.server 5500
# Depois abrir http://localhost:5500/index.html no browser
```

### Scripts de arranque automático

Dois scripts PowerShell fornecem uma forma mais cómoda (e segura) de iniciar:

- **`scripts/start-backend.ps1`** — Arranca o backend em background (sem janela de
  consola), com stdout/stderr redirecionados para `scripts/backend.log`. Verificações:
  venv existe, `uvicorn` está instalado. Pensado para ser chamado por tarefa agendada
  Windows (ou manualmente todas as manhãs).

- **`scripts/start-frontend.ps1`** — Arranca o servidor estático (via
  `scripts/serve_frontend.py`, não `python -m http.server`) em background e abre
  o dashboard no browser. **Importante:** não usa `python -m http.server` porque
  esse expõe a raiz inteira do projeto (incluindo `scripts/.env` com passwords Wazuh).
  `serve_frontend.py` é uma whitelist fixa (só `index.html` + recursos estáticos),
  ligado só a `127.0.0.1` — foi uma correção de segurança (auditoria 2026-08-31).
  Redirecionado para `scripts/frontend.log`. Nota técnica: passa o caminho entre
  aspas devido a um bug do PowerShell 5.1 com espaços em paths.

**Sem estes scripts:** precisavas de abrir `index.html` por duplo-clique (`file://`),
mas isso deixou de funcionar depois do CORS ficar restrito a `localhost`/`127.0.0.1`
— `file://` envia `Origin: null`, que essa restrição não reconhece de propósito.

## Testes do backend

48 ficheiros standalone (`run_all_tests.py` corre-os todos), todos sem precisar do laboratório Wazuh ligado (tudo mockado).
Correm todos a partir de `scripts/`:

```bash
python run_all_tests.py            # todos em paralelo (~13s), só PASS/FAIL; mostra o output só dos que falham
python run_all_tests.py incident   # filtra por parte do nome (ex.: test_incident_*.py)
python test_incident_engine.py     # ou um ficheiro isolado
```

Lista completa de testes e o que cobre cada um: `README.md` (secção Testes).

**Particularidades dos testes:**
- Nenhum usa pytest — são scripts standalone que imprimem `[OK]`/`[FALHOU]` por caso
- Saem com `sys.exit(1)` se algo falhar (para CI/automação)
- Todos usam `TestClient(main.app)` + `main.app.router.on_startup.clear()` (não dispara loops de background)
- Definem `SENTRYLENS_API_KEY` em `os.environ` **antes** de `import main` (autenticação é lida a nível de módulo)
- Mockam `WazuhIndexerClient` e `WazuhManagerClient` com `AsyncMock`
- Os testes do frontend não abrem browser: `test_frontend_static.py` lê os ficheiros servidos (contratos de texto: sem handlers inline, `.modal[hidden]`, CSS, `.gitignore`) e `test_ui_helpers.py` corre `test_ui_helpers.cjs` em `node:vm` sobre `ui_helpers.js` (mesmo padrão de `test_ml_models_ui.py`). Sem `node` no PATH falham de propósito.
- **Em worktrees** `test_export_raw_events.py` e `test_ml_training.py` falham sempre: precisam de `scripts/models/` e `scripts/snapshots/`, que estão no `.gitignore` e só existem no checkout principal. `test_attack_log_ids.py` e `test_attack_targets.py` falham às vezes em paralelo e passam isolados (flake conhecido, ver `docs/ROADMAP_STATUS.md`).
- Se um teste rebenta na consola do Windows por um emoji no label (cp1252), corre com `PYTHONIOENCODING=utf-8`.

**Ambiente:**
- Correr num `.venv` já criado em `scripts/.venv`
- Ativar: `source scripts/.venv/Scripts/activate` (Git Bash) ou `.\.venv\Scripts\Activate.ps1` (PowerShell)
- Python global desta máquina não tem `scikit-learn`/`joblib`/`PyYAML` — sempre usar o venv

## Fase 1 (log_analyzer, independente)

Analisa ficheiros de log estáticos sem precisar do backend Wazuh:
```bash
python log_analyzer.py --input sample_events.json --output report.html
```

## Arquitetura do backend (`scripts/`)

`main.py` é só a camada HTTP (endpoints FastAPI + CORS + loop de background
de monitorização do sistema); a lógica de negócio de cada painel vive num
módulo próprio que `main.py` importa e chama com os alertas já obtidos do
Wazuh:

- `wazuh_client.py` — `WazuhManagerClient` (JWT, porta 55000) e
  `WazuhIndexerClient` (Basic Auth, porta 9200). Único ponto que fala HTTP
  com o Wazuh.
- `event_catalog.py` — `CRITICAL_EVENTS`/`RECOMMENDATIONS`/`classify_alert()`.
  Fonte única de verdade para Event ID → nome amigável/severidade/categoria/
  recomendação, partilhada entre Fase 1 e Fase 2. Adicionar um Event ID novo
  só requer uma entrada aqui — nunca é preciso tocar em `main.py`.
- `lifecycle.py` — painel de ciclo de vida de contas (`build_lifecycle_report`):
  contagens, timeline e deteções de risco (offboarding falhado, conta
  descartável, criação fora de horário, escalada imediata).
- `rbac.py` — painel de desvios RBAC (`build_privileges_report` +
  `load_rbac_baseline`): compara grupos atribuídos com um baseline
  cargo→grupos permitidos/proibidos em `rbac_baseline.example.json`
  (caminho configurável via `RBAC_BASELINE_PATH`, sempre resolvido
  relativamente ao próprio ficheiro, nunca ao cwd).
- `admin_activity.py` — painel de atividade de contas administrativas
  (`build_admin_activity_report`): privilégios especiais, tarefas agendadas
  e deteções de risco, identificando contas admin por prefixo
  (`ADMIN_ACCOUNT_PREFIX`, default `adm.`).
- `system_monitor.py` — specs/saúde da **máquina local** (CPU/RAM/disco/rede
  via WMI/PowerShell, Windows-only), independente do Wazuh; alimenta um loop
  de background em `main.py` (amostra a cada 30s, rede a cada 20min) com
  histórico em memória + `system_alerts_history.json` para violações de
  threshold resolvidas.
- `serve_frontend.py` — servidor estático dedicado para o frontend
  (whitelist fixa de ficheiros, só `127.0.0.1`) — ver nota de segurança
  abaixo; **não** usar `python -m http.server` a partir da raiz do repo em
  produção porque expõe `scripts/.env`.
- `websocket_alerts.py` — `ConnectionManager` + `alert_poll_loop`/`_poll_once`
  para o endpoint `/ws/alerts`: faz polling interno ao Wazuh Indexer a cada
  10s, deduplica por `_id` do documento OpenSearch (campo que
  `wazuh_client.get_recent_alerts` passou a incluir só para isto), e faz
  broadcast `{"type": "new_alert", "alert": ...}` aos clientes ligados.
  Aceita um callback opcional `on_new_alerts` — é aí que `main.py` liga a
  persistência de histórico e conformidade (ver a seguir), reaproveitando a
  mesma deteção de "alerta novo" em vez de um segundo poller.
- `history_store.py` — persistência própria de histórico em JSONL
  append-only, `scripts/historico/AAAA/MM-mês/AAAA-MM-DD-{alerts,compliance}.jsonl`
  (configurável via `SENTRYLENS_HISTORY_DIR`, gitignored), para além dos 90
  dias que o Wazuh Indexer guarda. Não confundir com `export_snapshot.py`
  (Fase 6, snapshots de treino de ML — mecanismo separado).
- `report_generator.py` — `generate_html_report()`, função pura que gera um
  relatório HTML autónomo (CSS embutido, zero recursos externos, paleta
  navy+ciano do dashboard) a partir de dados já recolhidos pelos endpoints
  existentes; expõe também `render_compliance_section()` para a secção de
  conformidade. Todo o texto dinâmico passa por `html.escape()` — este
  ficheiro é gravado em disco e reaberto fora do dashboard, sem a
  sanitização do `escapeHtml()` de `app.js`.
- `compliance_evaluator.py` + `compliance_rules.yaml` + `org_profile.py` —
  motor de conformidade regulatória (RGPD/NIS2/AI Act, Fase 7):
  `evaluate_alert_compliance(alert, org_profile, rules)` é pura, nunca omite
  um veredito em silêncio. Perfil da organização fixo por agora (o CET não é
  uma empresa real) — sempre lido via `get_org_profile()` (devolve cópia),
  nunca do dict interno.
- `attack_registry.py` — registo de ataques (R4), puro: `build_attack_registry` junta `parse_launched_attacks` + `build_redblue_report` + incidentes (`attack_ids`) e calcula esperado vs real (veredito detected/partial/not_detected/unknown). Alimenta `GET /api/attacks[/{id}]` (só leitura, sem POST). Frontend: `attack_registry.js` (abas Attack Registry e Attack Timeline). Desde a R5, `expected_detection()` usa `attack_library.get_expected_sensors(scenario)` como default por cenário em vez de um `DEFAULT_EXPECTED` fixo (que fica como rede de segurança para um cenário sem entrada na biblioteca) — única exceção à regra "módulo puro, sem I/O" do ficheiro, porque lê um YAML já cacheado em memória por `load_attack_library()` no arranque do backend.
- `attack_library.py` — biblioteca de referência de ataques (R5), catálogo só-leitura: nunca executa nada, nenhum campo contém um comando executável. `load_attack_library()` lê `attack_library.yaml` (novo, versionado: risco, pré-requisitos, sensores esperados, cleanup em texto, replayable+motivo, duração estimada) e junta com `attack_scenarios.SCENARIOS` (event_ids/MITRE/ferramenta, não duplicados no YAML) por `scenario_name`. Cache em memória (não relê a cada pedido); validação fail-fast e síncrona chamada a nível de módulo em `main.py` — um YAML inválido/incoerente (campo em falta, risk/duration_estimate fora da taxonomia, incoerência risk=low com replayable=false ou cleanup_steps vazio, entrada no YAML sem par em SCENARIOS) impede o backend de arrancar; cenário em SCENARIOS sem entrada no YAML é só aviso (stderr), não bloqueia. Alimenta `GET /api/attack-library[/{id}]` (`id` = scenario_name, `^[a-z_]{1,64}$`, 404 com código estável `entry_not_found`). Frontend: `attack_library.js` (aba Attack Library) — um só pedido por ativação da aba (catálogo estático), filtros por risco/sensor em memória.
- `vaccine_engine.py` — motor puro do R11 (Vaccine Engine): `build_vaccine_candidates(registry, correlation=None)` gera uma vaccine por ataque `not_detected`/`partial` (`detected` e `unknown`, incluindo o unknown por alertas truncados, nunca geram), com `proposals[]` por sensor em falta (só a proposta `rule` leva `rule` = {event_ids, `min_count` 1, `window_seconds` 300}; `ml`/`network` só uma recomendação em texto) e `origin` por referência (nunca copia tool/target/operator). O id é `vac-` + 12 hex de sha256 de `<attack_id>:<sensores em falta>` (ordem de `EXPECTED_SOURCES`): deteta troca/duplicação, **não autentica**. `validate_vaccine` é a segunda barreira (contrato fechado, nenhum comando, tudo por allowlist); `reason` no_data/source_unavailable, fail-closed. Uma vaccine é só uma proposta: nunca aplicada no Wazuh.
- `vaccine_store.py` — store SQLite `scripts/vaccines.sqlite3` (`SENTRYLENS_VACCINES_DB_PATH`; relativo resolve-se contra a pasta do módulo, nunca o cwd; gitignored com o `-journal`). O estado `proposed` é imposto no ficheiro (`CHECK (state = 'proposed')`, `CHECK (json_valid(payload))`, triggers que recusam DELETE e qualquer UPDATE fora de `superseded_by`). Escrita com `INSERT ... ON CONFLICT(id) DO NOTHING` e não `INSERT OR IGNORE`, porque este engole em silêncio uma violação de CHECK. `superseded_by`: a vaccine atual de um ataque é a última emitida, a anterior fica guardada. A leitura abre em modo só-leitura e nunca cria o ficheiro; os argumentos de filtro são só por nome.
- `vaccine_ingest.py` — liga o motor ao store: `select_attack_ids`, `persist_vaccines`, `VaccineLoopState` (estado do gerador em memória, `GENERATOR_KEYS`). `main._vaccine_loop` corre no arranque e a cada `SENTRYLENS_VACCINE_INTERVAL_SECONDS` (300), janela `SENTRYLENS_VACCINE_WINDOW_HOURS` (168), e só grava vaccines de ataques mais velhos que `SENTRYLENS_VACCINE_SETTLE_SECONDS` (600). Rotas `GET /api/vaccines` e `GET /api/vaccines/{id}`: só GET com API key por rota (`dependencies=_REQUIRE_API_KEY`), 404 `entry_not_found`, 503 `store_unavailable`, 405 a qualquer escrita; o envelope traz o bloco `generator`. Frontend: `vaccines.js` (aba Vaccines -> Candidates, não edita `app.js`); `test_vaccines_frontend.py` fixa o contrato estático (sem browser). Limites e campos em `docs/DATA_MODEL.md`.
- `redblue_correlator.py` — motor de correlação Red vs Blue (Fase 11,
  Onda 1): cruza `attack_log.jsonl` (`attack_scenarios.py`) com os
  alertas já classificados por `ml_anomalies.build_ml_anomalies_report`
  (regra + ML), por cenário de ataque — cobertura, MTTD, detetado por
  regra/ML/ambos/nenhum. Função pura `build_redblue_report`, alimenta
  `GET /api/redblue/metrics`. Frontend (10ª aba, `redblue.js`) implementado
  na Onda 3 — não edita `app.js`, reutiliza os seus globais.
- `attack_scenarios.py` — definições de cenários de ataque para teste Red vs Blue
  (scanning, brute-force, privilege escalation, etc.), persiste timestamp/tipo/origem
  para correlação com alertas reais. Allowlist de alvos (R5), fail-closed: por omissão
  só loopback e os blocos de documentação (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`, `2001:db8::/32`); allowlist real via `ATTACK_TARGETS_PATH` ou
  `scripts/attack_targets.json` (gitignored, a partir de `attack_targets.example.json`);
  `--allow-any-target` é o override explícito. Isto é uma mudança de comportamento:
  qualquer `--target` apontado a um IP real do laboratório passa a ser recusado por
  omissão a partir desta versão.
- `network_monitor.py` — captura de metadados de tráfego de rede via SSH +
  tshark na VM Wazuh (não WMI local — essa era a ideia original da Fase 11,
  substituída na Onda 2), alimenta `packet_buffer`/`network_detection_buffer`
  em `main.py` (consumidos por `/api/redblue/network` e pelas rotas `/api/
  network/*` da R6). Polling a cada 5s (`network_poll_loop`), só ativo com
  `VM_SSH_HOST` configurado.
- `network_detections.py` — análise de padrões de rede (port scan, força
  bruta, pico de volume) a partir dos pacotes capturados. Integra-se com
  `redblue_correlator.py` para marcar alertas como detetados por rede.
- `network_soc.py` (R6) — resumos puros para os 3 painéis dedicados de rede
  (Live Traffic/Network Detections/PCAP Evidence): `summarize_packets`,
  `summarize_detections`, `build_evidence_report`. Não reimplementa captura
  nem deteção — só sumariza os dados de `network_monitor.py`/
  `network_detections.py`, a mesma fonte do painel de rede dentro da aba
  Red vs Blue (`redblue.js`). "PCAP/Evidence" é evidência de metadados
  persistida em JSONL (`history_store.append_network_detection_history`),
  nunca uma exportação PCAP/payload real — não há payload capturado para
  exportar (`network_monitor.py` só lê cabeçalhos tshark). Ver
  `docs/superpowers/specs/2026-10-07-r6-network-soc-design.md`.
- `nis2_lookup.py` — lookup de classificação NIS2 sugerida (Fase 8): dado um CAE
  (código de atividade económica), colaboradores contratados, endereço e
  faturação, sugere um nível de criticidade NIS2 sem pesquisa online — apenas
  com dados já conhecidos da organização (`get_org_profile()`).
- `incident_engine.py` / `incident_store.py` / `incident_ingest.py` — gestão de
  incidentes (R3): o engine é puro (evidência normalizada, regras de agrupamento,
  máquina de estados, ligação a ataques); o store é SQLite (`incidents.sqlite3`,
  `incident_events` append-only); o ingest liga os pollers (`on_new_raw_alerts`,
  `on_new_detections`) e o backfill ao engine. Frontend em `incidents.js`
  (11ª aba, não edita `app.js`). Rotas `/api/incidents/*`.
- `detection_event.py` / `GET /api/detections` — Detection Engine (R7): tipo comum `DetectionEvent` (TypedDict, `Literal` em source/severity) com 3 construtores puros; `incident_engine.py` e `redblue_correlator.py` constroem sobre ele por dentro sem mudar o contrato externo. Painel Detections em `detections.js`; `confidence`/`technique` ficam `None`.
- `soc_metrics.py` / `GET /api/metrics` — Métricas SOC (R8): `build_metrics_report` pura (MTTD, MTTR, cobertura, taxa de deteção, FN/FP) sobre o relatório Red vs Blue + `IncidentStore.list_for_metrics`; fontes isoladas na rota (`source_unavailable`), nunca 0 sem amostra, `alerts_truncated` quando o Indexer atinge o teto de 1000 alertas. Frontend: `metrics.js` (3 abas: MTTD / MTTR, Detection Coverage, Detection Rate). Definições em `docs/DATA_MODEL.md`.
- `jev_client.py` — triagem EXPERIMENTAL de incidentes via JEV (TypeSafe AI), `POST /api/incidents/{id}/triage`. Opt-in fail-closed (`SENTRYLENS_JEV_ENABLED` + `TYPESAFE_API_KEY`); única rota que envia dados para fora (api.typesafe.ai); `build_state` só envia agregados anonimizados. `confidence` do JEV = concentração da distribuição, não probabilidade de acerto.
- `siem_health.py` — saúde do SIEM (R2): `build_siem_health_report` pura (status ok/degraded/down, stale, truncated; erros como códigos estáveis, nunca texto de exceção). Rota `/api/siem/health`; frontend em `live_soc.js` (aba Live SOC, reutiliza o WebSocket de `app.js` via evento `sentrylens:new-alert` com `detail`).
- `history_index.py` — índice SQLite a partir de `history_store.py` para
  consultas rápidas (Fase 9): query builder, filtros por data/severidade/tipo,
  paginação. Criado incremental a partir de JSONL, reconstruído se
  `historico/` for modificado manualmente.
- `feature_extractor.py` — extração de features numéricas dos alertas brutos
  (Fase 6): `hour_of_day`, `day_of_week`, `event_id_encoded`, `failed_attempts_last_hour`,
  `has_special_privileges`, `is_new_source_ip`, `severity_encoded`. Usado por
  `ml_anomalies.py` para treino/predição (Isolation Forest). As 7 features reais
  estão em `feature_extractor.FEATURE_NAMES`, linhas 40-48.
- `ssh_client.py` — cliente SSH para operações em máquinas remotas monitoradas
  (Fase 6+): ligação com chave privada, execução de comandos, transfer de ficheiros.
  Nunca é chamado automaticamente — apenas se uma ação manual a invocar no backend.
- `export_snapshot.py` — exportação de dados brutos para treino de ML externo
  (snapshots de época/tipo/severidade). Separado de `report_generator.py`
  (que faz relatórios HTML para utilizador final).
- `_generate_sample_ml_data.py` — gera dados sintéticos de treino para Isolation
  Forest se não houver histórico real. Nunca executado em produção — só em
  `train_anomaly_model.py` ou em testes.
- `train_anomaly_model.py` — script standalone de treino de modelos ML. Lê
  eventos e attack log, extrai features via `feature_extractor.py`, treina
  `IsolationForest` e grava os dois `.pkl` na pasta indicada em
  `--models-dir` (`save_model()`). **Não toca no registo**: importa
  `model_registry` mas nunca chama `register_trained_version()` — quem cria
  e activa `models/vN/` com `metadata.json` + SHA-256 é o subcomando
  `model_registry.py train` (REG-04), que reutiliza `load_dataset()`/
  `train_model()` daqui. CLI: `--events`, `--attack-log`, `--models-dir`
  (**obrigatório**, tem de ser uma pasta já existente), `--contamination`,
  `--dataset-origin {synthetic,real,unknown}`, `--report <ficheiro>`
  (opt-in; sem ele o relatório só é impresso). Nada disto vai para o
  `metadata.json`. Executado off-line, nunca por HTTP.

- `model_registry.py` — registo versionado em disco: `next_version_id()`, `build_trained_metadata()`, `register_trained_version()`, `adopt`, `evaluate`, `ACTIVE`, SHA-256 antes do `joblib.load`, stdlib puro por contrato (gate por AST — scikit-learn e `train_anomaly_model` só entram por `importlib` dentro de `evaluate`/`train`). CLI com **três** subcomandos: `adopt`, `evaluate vN` e `train vN` (REG-04; o `version_id` do `train` é um rótulo pedido, não o id final — quem decide é `next_version_id`, e `--contamination`/`--random-state`/`--n-estimators` ficam registados no `metadata.json`). É o único ponto que escreve em `models/vN/` e gerencia o ciclo de vida das versões. O `metadata.json` tem **13** chaves: as 12 de `METADATA_PUBLIC_KEYS` (projeção que a API expõe, `evaluation` de fora) mais a `evaluation`; as **14** são as de `EVALUATION_PUBLIC_KEYS`, a mesma lista escrita à mão em `ml_evaluation.EVALUATION_KEYS` (igualdade verificada por `test_ml_models_api.py`). `origin` é um campo do `metadata.json`: `"trained"` no treino, `"adopted"` no `adopt` — que também escreve `trained_at`, estimado a partir do mtime dos `.pkl` com `trained_at_estimated: True`.
- `ml_evaluation.py` — motor de avaliação de UMA versão: `build_evaluation_report()` e `validate_evaluation()`, contrato de 14 chaves fechadas em `EVALUATION_KEYS`, limiares nomeados `MIN_EVENTS`/`MIN_ATTACKS` com aviso de amostra pequena, e `--dataset-origin {real,synthetic,unknown}` declarado pelo utilizador. Mede a versão pedida, não a ativa (D-02). `evaluate_alert_compliance()` **não** é aqui — vive em `compliance_evaluator.py` (conformidade RGPD/NIS2/AI Act) — e `origin` também não: é campo do `metadata.json` escrito pelo registo. É o único módulo que importa scikit-learn além de `train_anomaly_model.py`.

Todos os painéis Wazuh (alerts/stats/brute-force/lifecycle/privileges/
admin-activity) seguem o mesmo padrão: `indexer_client.get_recent_alerts(...)`
busca alertas crus → módulo de domínio puro transforma-os em relatório → erro
de rede vira `HTTPException(502)`. As funções `build_*_report()` são puras
(recebem a lista de alertas já obtida), o que é o que torna possível testá-las
com mocks sem o laboratório ligado.

## Frontend (raiz)

Sem build step: scripts clássicos carregados por `index.html`, servidos por `scripts/serve_frontend.py` (whitelist fixa — **um ficheiro novo tem de entrar em `ALLOWED_FILES`** e em `test_serve_frontend.py`).

- **Escopo global partilhado.** Todos os `*.js` partilham um só escopo; um identificador repetido rebenta o script inteiro. Cada ficheiro usa o seu prefixo (`ovw`, `rb`, `inc`, `st`, `ls`, `atk`, `alib`, `det`, `ns`, `met`, `mlm`, `mle`, `vac` e `sl` para `ui_helpers.js`). `app.js` define os globais que os outros reutilizam (`escapeHtml`, `fetchJSON`, `renderPanelError`, `formatTimestamp`, `API_BASE`, `API_KEY`).
- **`ui_helpers.js`** (carregado antes de `app.js`): só funções puras `sl*`, sem DOM no topo, é o que se consegue testar em `node:vm`. Lógica nova com decisões (formatar, escolher estado, filtrar) vai para aqui, não para `app.js`.
- **Nenhum handler inline** (`onclick=` etc.), nunca: `escapeHtml` não protege dentro de um atributo `on*`, porque o browser decodifica `&#39;` antes de correr o JS (XSS confirmada na Equipa SOC com um nome de analista). Usar `data-action`/`data-id` e um listener delegado que vai buscar o objeto à cache pelo id.
- **Sem dados é `—` ou `Sem dados`**, nunca `0`, `0%` nem uma barra cheia. `.progress-fill` começa vazio e só ganha cor com `level-*`.
- **O cabeçalho lê `/api/siem/health`** (`slHeaderStatus`), não infere nada de outros pedidos: os loaders apanham os seus erros e um `Promise.all` que não falha não prova que o Wazuh está ligado.
- `.modal { display:flex }` anula o atributo `hidden`; por isso existe `.modal[hidden] { display:none }`. Qualquer elemento novo com `hidden` e `display` próprio precisa da mesma regra.
- **A chave da API** vem de `/config.js` (gerado por `serve_frontend.py` a partir de `scripts/.env`, só same-origin). O WebSocket manda-a em `?api_key=` e o uvicorn grava-a **em claro** no access log (`scripts/backend.log.err`) até a Onda 5 tirar a chave do URL. Os logs não vão para o git, mas existem em disco e no OneDrive. Rodar a chave: editar `SENTRYLENS_API_KEY` em `scripts/.env` e reiniciar o backend (`.\scripts\start-backend.ps1 -SkipVMs` — sem `-SkipVMs` arranca também as 3 VMs); o frontend lê-a a cada pedido e não reinicia.
- **Plano de melhorias do frontend:** `docs/AUDITORIA_FRONTEND.md` (relatório e estado, secção 9). Ondas 0 e 1 no PR #3; Ondas 2 a 7 e Onda 8 parcial (W8.1, W8.3) no PR #4 — já em `main`. Falta só W8.2 (gravação da demo) e W8.4 (ensaio por outra pessoa), que dependem de um ataque de teste real no laboratório.

## Coisas não óbvias a partir do código

- **Todos os endpoints REST `/api/*` exigem API key** (header `X-API-Key`,
  variável `SENTRYLENS_API_KEY`, fail-closed — sem a variável definida,
  tudo devolve 401). A dependency `require_api_key` está aplicada
  **individualmente a cada rota** (`dependencies=_REQUIRE_API_KEY` em cada
  `@app.get`/`@app.post`), **nunca a nível de app** — uma rota REST nova tem
  de lembrar de a incluir, não fica protegida por omissão. Duas armadilhas
  do FastAPI já mordidas por causa disto: (1) `dependencies=[Depends(...)]`
  no construtor `FastAPI(...)` nunca protege `/docs`/`/redoc`/`/openapi.json`
  (são `add_route()`, não `add_api_route()`) — por isso estão desligadas de
  vez (`docs_url=None` etc.); (2) esse mesmo `dependencies=[...]` a nível de
  app **aplica-se também a `@app.websocket`**, e como um browser real nunca
  envia `X-API-Key` no handshake de WebSocket, isso deixava `/ws/alerts`
  pendurado para sempre em vez de recusar a ligação — por isso a
  autenticação REST teve de sair do construtor do `FastAPI(...)` e passar a
  ser por rota. `/ws/alerts` autentica-se à parte, por query param
  (`?api_key=...`), verificado manualmente dentro do próprio endpoint.
- **CORS está deliberadamente restrito** a `localhost`/`127.0.0.1` (qualquer
  porta) via `allow_origin_regex` em `main.py` — não voltar a abrir para
  `["*"]`; foi uma correção de segurança (auditoria 2026-08-31) porque não
  havia autenticação nenhuma nos endpoints (entretanto fechada, ver acima) —
  CORS continua a ser uma camada adicional, não uma substituição da API key.
- **`WAZUH_VERIFY_SSL=false` é o default intencional**, não um bug — o
  laboratório usa o certificado autoassinado gerado pelo `wazuh-install.sh`.
- O Windows força o stdout/stderr para o codepage da consola por omissão, o
  que corrompe acentos em logs redirecionados para ficheiro — por isso
  `main.py` e `log_analyzer.py` fazem `reconfigure(encoding="utf-8")` no
  arranque. Scripts `.ps1` novos devem ser gravados **com BOM UTF-8** —
  ficheiros sem BOM com acentos/travessões partem o parser do Windows
  PowerShell 5.1 (já aconteceu, ver histórico do git).
- O laboratório Wazuh (VM) corre atualmente em **VirtualBox** neste PC, não
  Hyper-V, apesar do nome dos scripts (`setup-hyperv-lab.ps1`) e da
  documentação em `docs/LAB_WAZUH_HYPERV.md` — as duas coisas não coexistem
  facilmente na mesma máquina. Endpoints/portas/credenciais são iguais; só o
  arranque automático da VM usa `VBoxManage`, não `Set-VM`. Os ficheiros da
  VM (disco virtual, snapshots) vivem em `D:\VMs\SentryLens` — foi para lá
  que a VM foi migrada para libertar espaço no `C:`.
- Os 3 scripts em `scripts/*.ps1`/`*.sh` de automação do laboratório
  correm-se **manualmente, nesta ordem** (nunca automaticamente — envolvem
  reiniciar o PC e mexer em virtualização): `setup-hyperv-lab.ps1` →
  (instalação manual do Ubuntu) → `install-wazuh.sh` → (login manual no
  dashboard) → `install-wazuh-agent.ps1` → (validação manual). Ver
  `scripts/README.md` para o que cada um propositadamente não automatiza.
- Commits com prefixo `gauntlet(sentrylens):` vêm de um exercício de
  desenvolvimento multi-agente (checkpoints/rondas com aprovação/reprovação)
  — histórico de processo, não terminologia do produto em si.

- **O SHA-256 dos `.pkl` detecta corrupção e troca acidental; não autentica.** Quem consegue escrever em `scripts/models/` reescreve também o `metadata.json`. Para uma versão treinada o hash é uma auto-atestação do próprio processo de treino: garante que o `.pkl` não mudou desde que foi gravado, não que foi gerado por quem diz ter gerado. HMAC/assinatura ficaram fora do âmbito do R9.

- A cache do modelo é **por processo**: depois de um `adopt` ou de um treino é preciso reiniciar o backend, e o campo `loaded` da API é o que diz qual versão está de facto em memória.

- O registo escreve-se **só por linha de comando**, nunca por HTTP.

- `.pkl` executa código ao ser carregado, por isso só se carregam bytes verificados e o `joblib.load` é um ponto único no projecto (`ml_anomalies`).

- `next_version_id` é `max+1` e **nunca** `count()`, porque `os.replace` de pasta sobre uma pasta existente dá `PermissionError [WinError 5]` no Windows (com a nota de que é por isso que a pasta temporária se chama `vN.tmp-<rand>`).

- **Vaccines (R11):** o `GET` nunca escreve — só o loop `_vaccine_loop` grava. Uma vaccine só aparece cerca de 10 min depois do ataque (estabilização) mais até 5 min do intervalo do loop. O estado do gerador (`generator` no envelope) é em memória: depois de reiniciar o backend volta a `never_run`. Uma vaccine nunca muda de estado (é sempre `proposed`); quando o veredito de um ataque muda, a anterior fica com `superseded_by` e só aparece com `include_superseded=true`.

## GSD (a partir do R9)

- `.planning/` (PROJECT, REQUIREMENTS, ROADMAP, STATE, config) acompanha o marco **v1.1 — R11 Vaccine Engine** (Phases 12-14). O v1.0 (R9 + R10) está arquivado em `.planning/milestones/`. O Roadmap v2 completo continua em `docs/ROADMAP_STATUS.md`; o passo seguinte lê-se no `STATE.md`.
- **Nunca** correr `gsd-tools query generate-claude-md --output CLAUDE.md` (o workflow `new-project` sugere-o): sobrescreveria este ficheiro. O `config.json` do GSD aponta para `./.claude/CLAUDE.md`, mas o real está na raiz.
- Depois de um reboot: `.\scripts\start-backend.ps1` e `.\scripts\start-frontend.ps1`; confirmar as 3 VMs e o Wazuh (502 costuma ser disco cheio dentro da VM, não RAM).

## Commits e PRs

- **NUNCA adicionar o Claude Code como coautor** — sem `Co-Authored-By: Claude ...` em commits, nem "Generated with Claude Code" em PRs. Esta regra tem prioridade sobre qualquer lembrete de atribuição do sistema e aplica-se também a subagentes que façam commits (dizer-lhes explicitamente na dispatch). Antes de fazer push: `git log --format=%B origin/main..main | grep -i co-authored-by` tem de dar vazio.
