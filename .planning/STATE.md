---
gsd_state_version: "1.0"
milestone: v1.2
milestone_name: R12 Vaccine Lab
current_phase: 17
current_phase_name: Aba, testes e documentação
status: executing
stopped_at: Completed 17-01-PLAN.md
last_updated: "2026-10-30T16:50:00.356Z"
last_activity: 2026-10-30
last_activity_desc: Phase 17 execution started
state_head: 4c995f44cc2d068fc88e1c7bae635d9aeeb2ebff
progress:
  total_phases: 3
  completed_phases: 2
  total_plans: 12
  completed_plans: 7
  percent: 58
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-10-29)

**Core value:** Medir de forma honesta, com dados reais, quão bem o laboratório deteta e responde a ataques — nunca apresentar como real um valor inventado ou sem amostra.
**Current focus:** Phase 17 — Aba, testes e documentação

## Current Position

Phase: 17 (Aba, testes e documentação) — EXECUTING
Plan: 2 of 6
Status: Ready to execute
Last activity: 2026-10-30 — Phase 17 execution started

Progress: [██████░░░░] 58%

## Performance Metrics

**Velocity:**
- Total plans completed (v1.2): 0
- v1.1 (referência): 10 planos em 3 fases; v1.0: 17 planos em 5 fases

*Updated after each plan completion*
**Per-Plan Metrics:**

| Plan | Duration | Tasks | Files |
|------|----------|-------|-------|
| Phase 15 P01 | 25min | 3 tasks | 5 files |
| Phase 15 P02 | 15min | 2 tasks | 1 files |
| Phase 15 P03 | 20min | 2 tasks | 2 files |
| Phase 16 P01 | 10 min | 2 tasks | 3 files |
| Phase 16 P02 | 15 min | 2 tasks | 5 files |
| Phase 16 P03 | 8 min | 2 tasks | 2 files |
| Phase 17 P01 | 25min | 2 tasks | 5 files |

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- [v1.2 roadmap]: 3 fases em fatias verticais (store de decisões → API → dashboard+docs); numeração continua (15, 16, 17).
- [R12]: as decisões vivem numa tabela nova só de acréscimo (`vaccine_decisions`); a tabela `vaccines` do R11 não muda (estado fixo `proposed`, triggers intactos); o estado atual é derivado da última decisão.
- [R12]: aprovar não aplica nada no Wazuh (aplicar é R21); qualquer analista pode decidir (só há uma API key) e o autor fica registado.
- [R11 carry-over]: `ATTACK_ALERTS_SIZE=8000` é paliativo; truncagem por ataque (não por lote) por decidir.
- [Phase 15]: DDL de vaccine_decisions confirmado pelo utilizador; VaccineDecisionError nao deriva de ValueError; ordem fixa de validacao antes de tocar no disco
- [Phase 16]: Phase 16-01: teto do corpo 8192 bytes, excedido dá 422 invalid_body (não 413)
- [Phase 16]: Phase 16-01: vaccine_id mal formado dá 422 invalid_vaccine_id por handler de RequestValidationError só da rota de decisão
- [Phase 16]: Phase 16-01: autoria da decisão autodeclarada (analyst_id no corpo, validado no incident_store), não autenticada
- [Phase 16]: 16-02: state_counts (envelope) e count_by_state (store); zeros explícitos com amostra, None sem amostra
- [Phase 16]: 16-02: count_by_state corre depois de list_vaccines no mesmo try; estado desconhecido no ficheiro dá ValueError e 503
- [Phase 16]: 16-03: o varrimento AST do fecho local segue referências a nomes e proíbe acesso por atributo a manager_client/vm_ssh_client/subprocess; allow_methods do CORS fixado por teste sem mudar main.py
- [Phase 17]: 17-01: secção Decisão como markup estático; validação local analista, escolha, motivo; motivo conta pontos de código; só analistas com active 1/true

### Pending Todos

None yet.

### Blockers/Concerns

None.

## Deferred Items

Items acknowledged and deferred at milestone close, most recent first:

| Category | Item | Status | Deferred At | Milestone |
|----------|------|--------|-------------|-----------|
| verification | Verificação humana do R9/R10 no dashboard (badges, aviso após `adopt`, avaliação rotulada) | Pending | 2026-10-11 | v1.0 |
| data | Primeiro ciclo de treino real: `v1` adotado e avaliado (inconclusivo, 8 eventos); falta treinar `v2` com mais ataques rotulados | Pending | 2026-10-11 | v1.0 |
| verification | 01-VERIFICATION.md e 02-VERIFICATION.md (v1.0): verificações humanas do R9/R10 por fazer; `status` corrigido de `complete-with-open-human-checks` para `human_needed` | acknowledged | 2026-10-29 | v1.1 |
| deferred_items | 12/deferred-items.md: falha de `test_attack_registry` por chamada posicional a `list_incidents`; já resolvida (`limit=`/`offset=` por palavra-chave) | acknowledged | 2026-10-29 | v1.1 |
| verification | Vaccine substituída na aba Vaccines (linha esbatida e cadeia) sem prova num browser real | Pending | 2026-10-29 | v1.1 |

## Session Continuity

Last session: 2026-10-30T16:50:00.214Z
Stopped at: Completed 17-01-PLAN.md
Resume file: None

## Operator Next Steps

- Planear a primeira fase: `/gsd-plan-phase 15` (ou discuti-la antes com `/gsd-discuss-phase 15`).
