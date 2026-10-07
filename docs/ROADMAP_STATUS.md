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
| R4 | Attack Registry | 🟡 | `attack_log.jsonl` já tem `id/technique/tool` (ver R0); faltam operador, evidência, esperado vs real; usa `attack_id` em `incident_events` |
| R5 | Attack Library | 🟡 | `attack_scenarios.SCENARIOS`; faltam cleanup, risco, sensores, replayable |
| R6 | Network SOC | 🟡 | `network_monitor.py`, `network_detections.py`; falta PCAP/evidência |
| R7 | Detection Engine (`DetectionEvent`) | ⬜ | Hoje 3 detetores independentes unidos só no correlator; base para `DetectionEvent` nos incidentes (R3) |
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

- `attack_log.jsonl` está no `.gitignore` (estado de runtime) — o registo de
  ataques não é versionado. Decisão a tomar em R4 (Attack Registry).
- `attack_log_round3.jsonl` traz `detected`/`mttd_seconds` declarados pelo
  atacante, não medidos; o correlator ignora-os de propósito.
- `_parse_timestamp` duplicado em vários módulos; `main.py` mistura rotas,
  loops e estado global; `@app.on_event("startup")` deprecated.
- Confirmar que a API key que esteve no histórico git foi rodada.
- Incidentes (R3): a janela de 10 min (`INCIDENT_GAP_SECONDS`) pode fundir ataques
  distintos ao mesmo ativo; deteções de rede só existem em memória (ficam fora do
  backfill); o autor das ações manuais é fixo (`analyst`).
- Live SOC (R2): saúde do SIEM só pesquisa a última hora (sem alertas -> `stale`); taxa limitada aos 500 alertas mais recentes (`truncated` -> "≥"); Manager e Indexer são consultados em série (até ~30 s se ambos em timeout).
- Numeração: os planos antigos usam "Fase N"; este roadmap usa "R<n>".
