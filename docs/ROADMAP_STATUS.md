# Roadmap v2 — estado das fases (R0–R25)

Estado de execução do R9 ao R11 em `.planning/` (GSD: `ROADMAP.md`, `STATE.md`, `REQUIREMENTS.md`); as restantes fases continuam a ser seguidas aqui.

Plano de evolução do SentryLens de dashboard técnico para laboratório SOC de
aprendizagem contínua (ataque → deteção → incidente → vaccine → replay →
regressão → ML). Usa o prefixo **R** para não colidir com as "Fases 1–11" do
trabalho anterior (Fase 11 = Red vs Blue + rede, concluída).

Princípios: dados reais primeiro (nunca mocks apresentados como dados reais),
não reimplementar o que existe, compatibilidade com a API atual, uma fase =
código + testes + docs + commit.

Legenda: ✅ feito · 🟡 parcial · ⬜ por fazer

| Fase | Tema | Estado | Notas / reutiliza |
|---|---|---|---|
| R0 | Fundação / auditoria | ✅ | Auditoria de 2026-10-06; correções abaixo; docs `ARCHITECTURE`, `DATA_MODEL`, `SECURITY` |
| R1 | Sidebar SOC | ✅ | `index.html`, `app.js` (`activateTab`/`activatePlanned`), `style.css`; itens sem dados mostram "Sem dados" |
| R2 | Live SOC | ✅ | Painel Live SOC (`live_soc.js`): feed ao vivo via o WebSocket existente + saúde do SIEM (`GET /api/siem/health`: `status` ok/degraded/down, `stale`, `truncated`) |
| R3 | Gestão de incidentes | ✅ | Incidentes automáticos (alertas Wazuh + rede), estados, timeline, backfill, painel |
| R4 | Attack Registry | ✅ | `attack_registry.py` + `GET /api/attacks[/{id}]` (esperado vs real, operador, evidência por referência, incidentes ligados); painéis Attack Registry e Attack Timeline (`attack_registry.js`) |
| R5 | Attack Library | ✅ | `attack_library.py` + `scripts/attack_library.yaml` + `GET /api/attack-library[/{id}]` (catálogo de risco/pré-requisitos/sensores esperados/cleanup/replayable, combinado com `attack_scenarios.SCENARIOS`); painel `attack_library.js`; allowlist de alvos fail-closed em `attack_scenarios.py` |
| R6 | Network SOC | ✅ | `network_monitor.py`, `network_detections.py` + `network_soc.py` (R6): 3 painéis reais (`GET /api/network/live-traffic[/detections/evidence]`); deteções de rede persistidas em JSONL (`history_store.append_network_detection_history`, resolve a dívida de R0); "PCAP/Evidence" é evidência de metadados, não PCAP real (sem payload capturado — ver `SECURITY.md`/`DATA_MODEL.md`) |
| R7 | Detection Engine (`DetectionEvent`) | ✅ | `detection_event.py` (puro, 3 construtores) + `GET /api/detections` (vista unificada) + painel Detections (`detections.js`); `incident_engine.py`/`redblue_correlator.py` constroem sobre ele por dentro, sem mudar o contrato externo; `confidence` calibrado continua em dívida |
| R8 | MTTD / MTTR / métricas | ✅ | `soc_metrics.py` (puro) + `GET /api/metrics` + 3 painéis (`metrics.js`: MTTD / MTTR, Detection Coverage, Detection Rate); mediana/p90/média, cobertura por cenário e técnica MITRE, taxa de deteção por fonte, FN/FP; definições formais em `DATA_MODEL.md`; `IncidentStore.list_for_metrics` (leitura) |
| R9 | ML Intelligence | ✅ | Isolation Forest + `feature_extractor` partilhado. Registo versionado `models/vN` + `ACTIVE`, avaliação por versão, SHA-256 antes de carregar o `.pkl`, `GET /api/ml/models`, abas Models e Evaluation, `export_raw_events.py`, 38 ficheiros de teste. Isto é o que o código faz, não o que está registado: primeiro ciclo real fechado a 2026-10-28: o modelo legado foi adotado como `v1` (`ACTIVE -> v1`, SHA-256 registado) e avaliado com 8 eventos processáveis (`small_sample: true`, 0% P/R/F1, inconclusivo). Falta treinar `v2` com mais ataques rotulados (decisão por tomar) e resolver o `InconsistentVersionWarning` (sklearn 1.5.2 do modelo vs 1.3.2 do venv) |
| R10 | ML Learning Loop | ⬜ | |
| R11 | Vaccine Engine | ✅ | `vaccine_engine.py` (puro: uma vaccine por ataque `not_detected`/`partial`, regra proposta, origem por referência, id determinístico `vac-` + 12 hex) + `vaccine_store.py` (SQLite, estado fixo `proposed`, append-only salvo `superseded_by`) + `vaccine_ingest.py` (loop de background no arranque, estabilização de 600 s) + `GET /api/vaccines[/{id}]` (só leitura, API key por rota) + aba Vaccines → Candidates (`vaccines.js`); propostas, nunca aplicadas no Wazuh e sem comandos; aprovar/rejeitar é o R12 |
| R12 | Vaccine Lab | ⬜ | |
| R13 | Attack Replay Lab | ⬜ | |
| R14 | Security Regression Lab | ⬜ | |
| R15 | Red vs Blue consolidado | 🟡 | Aba `redblue.js` + correlator |
| R16 | Cobertura MITRE | ⬜ | Campo MITRE existe por ataque/cenário |
| R17 | SOC Immunity | ⬜ | |
| R18 | Recommendation Engine | ⬜ | |
| R19 | Security Bulletin | 🟡 | `report_generator.py` |
| R20 | Dashboard executivo | ⬜ | |
| R21 | Resposta automática | ⬜ | Por defeito simulação/aprovação, com audit log |
| R22 | Auditoria / segurança | ⬜ | Ver `SECURITY.md` |
| R23 | Observabilidade | ⬜ | |
| R24 | Testes | 🟡 | 81 ficheiros standalone; sem pytest |
| R25 | Documentação | 🟡 | Atualizar a cada fase |

## R0 — correções aplicadas

- **MITRE errado no Red vs Blue.** O `attack_log.jsonl` mapeou os 12 ataques
  reais do Round 3 para só 5 cenários (ex.: `responder`/T1557.001 ficou
  `blank_password_check`; `mimikatz`/T1003 ficou `brute_force_rdp`), e o
  correlator reportava a técnica do cenário. Agora o log guarda
  `id/technique/tool` reais (enriquecidos por timestamp a partir de
  `attack_log_round3.jsonl`, 12/12) e `build_redblue_report` dá-lhes
  prioridade (`attack_id`, `tool`, `mitre_technique` em cada tentativa).
  A correspondência de alertas continua a usar os `event_ids` do cenário.
- **API key fora do `app.js`:** `serve_frontend.py` serve `/config.js` gerado a
  partir de `scripts/.env` (same-origin + Host loopback; ver `SECURITY.md`).
- `.controls` do cabeçalho passa a quebrar linha (overflow horizontal em
  ecrãs estreitos).

## Dívida conhecida (não corrigida em R0)

- `attack_log.jsonl` mantém-se no `.gitignore` (decidido em R4: pode ter IPs/alvos
  do lab); exemplos versionáveis só com IPs de documentação.
- `attack_log_round3.jsonl` traz `detected`/`mttd_seconds` declarados pelo
  atacante, não medidos; o correlator ignora-os de propósito.
- `_parse_timestamp` duplicado em vários módulos; `main.py` mistura rotas,
  loops e estado global; `@app.on_event("startup")` deprecated.
- Confirmar que a API key que esteve no histórico git foi rodada.
- Incidentes (R3): a janela de 10 min (`INCIDENT_GAP_SECONDS`) pode fundir ataques
  distintos ao mesmo ativo; deteções de rede **agora persistidas em JSONL desde o
  arranque do backend** (R6, `historico/.../AAAA-MM-DD-network-detections.jsonl`)
  — mas o backfill de incidentes continua a não as reimportar retroativamente de
  dias anteriores ao arranque (só consome a partir de agora, como o resto do
  backfill); o autor das ações manuais é fixo (`analyst`).
- Live SOC (R2): saúde do SIEM só pesquisa a última hora (sem alertas -> `stale`); taxa limitada aos 500 alertas mais recentes (`truncated` -> "≥"); Manager e Indexer são consultados em série (até ~30 s se ambos em timeout).
- Numeração: os planos antigos usam "Fase N"; este roadmap usa "R<n>".
- Attack Registry (R4): só lê o log (sem rota de escrita; operador/esperado só à nascença via `attack_scenarios.py --operator/--source/--expect`); ataques sem `id` não ligam a incidentes; o esperado por omissão vem agora da Attack Library (R5) em vez de um default fixo no código (mesmo valor hoje, `["rule","ml"]`, por cenário); janela de alertas até 720 h e teto de 1000 alertas (`alerts_truncated`: ataques sem correspondência ficam `unknown`).
- Attack Library (R5): só leitura, catálogo estático (`attack_library.yaml`); nenhuma automação liga `cleanup_steps` a uma execução real (ficam como checklist para o operador); sem versionamento de schema do YAML; risco (`low/medium/high`) decidido à mão por entrada, não calculado (a validação só rejeita incoerências flagrantes risco/replayable/cleanup); allowlist de alvos de `attack_scenarios.py` é fail-closed mas só cobre IPs/hostnames — não impede um alvo de documentação configurado incorretamente como "real" por engano; `attack_log_round3.jsonl` (achado lateral, formato antigo sem campo `scenario`) não é coberto pela biblioteca — ver ROUND3 em `.superpowers/sdd/r5-report.md`.
- ML (R9): o SHA-256 do registo **não autentica** quem escreve em `models/` — quem escreve reescreve o `metadata.json`. O dataset de referência do primeiro ciclo real (2026-09-14) **não é rotulável** com o `attack_log.jsonl` actual (12 entradas, todas de 2026-10-06): avaliá-lo dá 0 ataques e recall 0 por definição. Qualquer avaliação a sério exige ataques lançados e alertas exportados na mesma janela.
- Network SOC (R6): "PCAP/Evidence" é evidência de metadados das deteções (JSONL), nunca uma exportação PCAP/payload real — `network_monitor.py` só captura cabeçalhos tshark, não há payload para exportar (ruling explícito na spec, não uma lacuna por fazer); o JSONL de deteções cresce sem rotação/purga automática (mesma política — ou ausência dela — de `historico/` hoje); evidência só pagina "últimas N de um dia" (sem offset/paginação por página), suficiente para o laboratório mas não para consultar meses de histórico de uma vez; sem índice SQLite dedicado (ficou em JSONL simples, como os alertas antes de `history_index.py` — candidato a usar o mesmo padrão se o volume justificar).
- Detection Engine (R7): painel Detections entregue (`detections.js`); `confidence` existe no tipo `DetectionEvent` mas nenhum dos 3 construtores o preenche ainda (`ml_score` do Isolation Forest não é uma probabilidade calibrada — inventar uma normalização seria enganador); `technique` por deteção individual também fica `None` (só existe ao nível da tentativa de ataque, em `redblue_correlator`); `GET /api/detections` não tem paginação por cursor (só `hours`/`limit`, mesmo nível de ambição que `/api/network/evidence` em R6); `incident_engine.py`/`redblue_correlator.py` continuam com os seus próprios shapes externos (evidência de incidente / "attempt" de correlação) em vez de `DetectionEvent` — decisão deliberada para não mudar contratos já consumidos pelo frontend/attack_registry.py nesta fase.
- Métricas (R8): o fetch de alertas está limitado a 1000 (newest-first) — quando o teto é atingido (`alerts_truncated`), ataques antigos aparecem como não detetados e a taxa/MTTD/cobertura são limites inferiores (o painel avisa; o `/api/redblue/metrics` tem o mesmo limite). Corrigir de vez exige consultar o Indexer por intervalo de cada ataque. A taxa de FP só conta incidentes `NEW → CLOSED` com nota (a única verdade de base do laboratório) e só aparece com `METRICS_MIN_SAMPLE` (default 5) incidentes fechados; MTTD usa a deteção sinalizada mais cedo de qualquer fonte (um alerta correspondente mas não sinalizado por regra/ML não conta); sem tendência no tempo nem exportação para o relatório HTML (R19).
- Vaccine Engine (R11): uma vaccine é só uma proposta (nunca aplicada, aprovada nem validada; escrever, aprovar e rejeitar é o R12). O id (`vac-` + 12 hex de sha256) deteta troca ou duplicação mas **não autentica**: quem edita o `attack_log` ou o ficheiro SQLite forja um id coerente. A7: a leitura não volta a correr `validate_vaccine`, uma linha adulterada no ficheiro seria servida. A8: as deteções de rede estão em memória e ficam vazias depois de um reinício, por isso um ataque com `network` esperado avaliado logo a seguir pode gerar uma proposta `network` falsa. A3: com alertas truncados (teto de 8000, `ATTACK_ALERTS_SIZE`, só no caminho dos ataques/vaccines; as métricas R8 e o Red vs Blue continuam a 1000) as vaccines gravam-se na mesma, sinalizado em `generator.alerts_truncated`. A5: o estado do gerador é em memória (`never_run` depois de reiniciar o backend). Espera mínima até uma vaccine aparecer: estabilização de 600 s depois do ataque, mais até um intervalo de 300 s do loop.
- Flake de `run_all_tests.py`: `test_attack_log_ids.py` e `test_attack_targets.py` falham de forma intermitente quando a suite corre em paralelo (ThreadPoolExecutor com 4 workers em `run_all_tests.py`) e passam isolados; visto no 13-03. Na Phase 14 viu-se também `test_ml_training.py` falhar numa corrida completa em quatro (14-02; olha para `%TEMP%`, partilhado com os restantes testes em paralelo; isolado passa sempre). Na execução citada abaixo (14-04) não reproduziu: nenhuma das duas falhou. Causa por investigar (hipótese: recurso partilhado entre testes paralelos); não toca nas vaccines.

## R9 — verificado por máquina / por verificar em humano

**Verificado por máquina (execução automatizada, esta sessão):**
- Suite completa `run_all_tests.py`: 38/38 testes verdes sem o laboratório Wazuh
- SHA-256 recusado antes de qualquer `joblib.load` com contador a 0
- IDs inválidos e `ACTIVE` partido recusados/fail-closed
- `evaluate` grava na versão pedida e não na ativa
- Versão treinada `vN` aparece na API e na aba Models
- `next_version_id` é `max+1`, nunca `count()` (evita `PermissionError [WinError 5]`)

**Por verificar em humano (pendente de execução real no dashboard):**
- Abrir o dashboard e confirmar os badges e o detalhe por teclado
- Reiniciar o backend depois de um `adopt` e confirmar o aviso
- Exportar os eventos do Indexer com `export_raw_events.py` e fazer uma avaliação rotulada
- Lançar os ataques e rotular a janela de 2026-09-14

Enquanto esta lista não estiver vazia, o ✅ da tabela significa "o código está verificado por máquina", não "o analista viu".

## R11 — verificado por máquina / por verificar em humano

**Verificado por máquina (execução automatizada, esta sessão):**
- Suite completa `run_all_tests.py`: 45/45 ficheiros verdes sem o laboratório Wazuh, numa única execução completa com código 0 (precisou de 1 execução completa; nenhum ficheiro falhou, incluindo o flake conhecido; corrida com um venv novo criado a partir de `scripts/requirements.txt` (mesmas versões), porque o `scripts/.venv` local estava corrompido por uma instalação interrompida — ver SUMMARY do 14-04)
- Testes das vaccines: `test_vaccine_engine.py`, `test_vaccine_store.py`, `test_vaccine_ingest.py`, `test_vaccines_api.py`, `test_vaccines_frontend.py`
- Sem rota de escrita: POST/PUT/PATCH/DELETE dão 405 (`test_vaccines_api.py`)
- Nenhum campo com comando executável (`DENY_RE` em `test_vaccine_engine.py`)
- 503 `store_unavailable` sem texto de exceção (`test_vaccines_api.py`; `Traceback` recusado em `test_vaccine_ingest.py`)
- Sem duplicados depois de reprocessar (2.º ciclo) nem depois de um reinício (`test_vaccines_api.py`)
- "Sem dados" só quando não há amostra; erros do backend mostram a frase do código, nunca uma lista vazia (`test_vaccines_frontend.py`)
- `app.js` por editar em toda a fase (`git diff --quiet 878d8e5 HEAD -- app.js`)

**Por verificar em humano (pendente de execução real no dashboard):**
- Abrir 💉 Candidates, usar os filtros (ataque, técnica, "Incluir substituídas") e confirmar o estado do gerador, os badges de veredito e as substituídas esbatidas
- Parar o backend e carregar em Atualizar: aparece o banner e "Sem ligação ao backend", nunca "Sem dados"
- Abrir o detalhe com rato e por teclado (Tab, Enter, Espaço): aviso "Proposta — não aplicada no Wazuh", Origem, Propostas e Cadeia, sem links
- Lançar um ataque que escape à deteção e ver a vaccine aparecer na aba depois da estabilização (cerca de 10 a 15 min)

Enquanto esta lista não estiver vazia, o ✅ da tabela significa "o código está verificado por máquina", não "o analista viu".
