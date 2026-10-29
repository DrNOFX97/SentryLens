---
gsd_state_version: "1.0"
milestone: v1.2
milestone_name: R12 Vaccine Lab
status: Ready to plan
stopped_at: Milestone v1.2 defined - roadmap approved
last_updated: "2026-10-29T12:00:00.000Z"
last_activity: 2026-10-29
last_activity_desc: Milestone v1.2 (R12 Vaccine Lab) started
progress:
  total_phases: 3
  completed_phases: 0
  total_plans: 0
  completed_plans: 0
  percent: 0
current_phase: 15
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-10-29)

**Core value:** Medir de forma honesta, com dados reais, quão bem o laboratório deteta e responde a ataques — nunca apresentar como real um valor inventado ou sem amostra.
**Current focus:** Phase 15 — Store de decisões

## Current Position

Phase: 15 (Store de decisões) — por planear
Plan: —
Status: Ready to plan
Last activity: 2026-10-29 — Milestone v1.2 (R12 Vaccine Lab) started

Progress: [░░░░░░░░░░] 0%

## Performance Metrics

**Velocity:**
- Total plans completed (v1.2): 0
- v1.1 (referência): 10 planos em 3 fases; v1.0: 17 planos em 5 fases

*Updated after each plan completion*

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- [v1.2 roadmap]: 3 fases em fatias verticais (store de decisões → API → dashboard+docs); numeração continua (15, 16, 17).
- [R12]: as decisões vivem numa tabela nova só de acréscimo (`vaccine_decisions`); a tabela `vaccines` do R11 não muda (estado fixo `proposed`, triggers intactos); o estado atual é derivado da última decisão.
- [R12]: aprovar não aplica nada no Wazuh (aplicar é R21); qualquer analista pode decidir (só há uma API key) e o autor fica registado.
- [R11 carry-over]: `ATTACK_ALERTS_SIZE=8000` é paliativo; truncagem por ataque (não por lote) por decidir.

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

Last session: 2026-10-29T12:00:00.000Z
Stopped at: Milestone v1.2 defined - roadmap approved
Resume file: None

## Operator Next Steps

- Planear a primeira fase: `/gsd-plan-phase 15` (ou discuti-la antes com `/gsd-discuss-phase 15`).
