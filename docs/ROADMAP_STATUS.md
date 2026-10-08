# Roadmap v2 — estado das fases (R0–R25)

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
| R7 | Detection Engine (`DetectionEvent`) | 🟡 | `detection_event.py` (puro, 3 construtores) + `GET /api/detections` (vista unificada); `incident_engine.py`/`redblue_correlator.py` já constroem sobre ele por dentro, sem mudar o contrato externo; falta o painel frontend (sidebar continua `data-planned="R7"`) e `confidence` calibrado |
| R8 | MTTD / MTTR / métricas | 🟡 | MTTD existe em `redblue_correlator`; falta MTTR, FP/FN, definição formal; tempo até à 1.ª resposta já calculado nos incidentes |
| R9 | ML Intelligence | 🟡 | Isolation Forest + `feature_extractor` partilhado; falta model registry e avaliação |
| R10 | ML Learning Loop | ⬜ | |
| R11 | Vaccine Engine | ⬜ | |
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
| R24 | Testes | 🟡 | 17 ficheiros standalone existentes; sem pytest |
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
- Network SOC (R6): "PCAP/Evidence" é evidência de metadados das deteções (JSONL), nunca uma exportação PCAP/payload real — `network_monitor.py` só captura cabeçalhos tshark, não há payload para exportar (ruling explícito na spec, não uma lacuna por fazer); o JSONL de deteções cresce sem rotação/purga automática (mesma política — ou ausência dela — de `historico/` hoje); evidência só pagina "últimas N de um dia" (sem offset/paginação por página), suficiente para o laboratório mas não para consultar meses de histórico de uma vez; sem índice SQLite dedicado (ficou em JSONL simples, como os alertas antes de `history_index.py` — candidato a usar o mesmo padrão se o volume justificar).
- Detection Engine (R7): sem painel frontend — a sidebar mantém "Detections" como `data-planned="R7"` (decisão deliberada, ver `docs/superpowers/specs/2026-10-07-r7-detection-engine-design.md`, ruling 6 — o backend/API já existe, falta só o consumidor de UI, que fica para uma fase seguinte); `confidence` existe no tipo `DetectionEvent` mas nenhum dos 3 construtores o preenche ainda (`ml_score` do Isolation Forest não é uma probabilidade calibrada — inventar uma normalização seria enganador); `technique` por deteção individual também fica `None` (só existe ao nível da tentativa de ataque, em `redblue_correlator`); `GET /api/detections` não tem paginação por cursor (só `hours`/`limit`, mesmo nível de ambição que `/api/network/evidence` em R6); `incident_engine.py`/`redblue_correlator.py` continuam com os seus próprios shapes externos (evidência de incidente / "attempt" de correlação) em vez de `DetectionEvent` — decisão deliberada para não mudar contratos já consumidos pelo frontend/attack_registry.py nesta fase.
