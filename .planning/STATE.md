---
gsd_state_version: "1.0"
milestone: v1.3
milestone_name: R16 MITRE ATT&CK
status: planning
last_updated: "2026-11-09T12:00:00.000Z"
last_activity: 2026-11-09
progress:
  total_phases: 3
  completed_phases: 0
  total_plans: 0
  completed_plans: 0
  percent: 0
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-11-09)

**Core value:** Medir de forma honesta, com dados reais, quão bem o laboratório deteta e responde a ataques — nunca apresentar como real um valor inventado ou sem amostra.
**Current focus:** Phase 18 — Técnica e tática por alerta

## Current Position

Phase: 18 of 20 (v1.3: fase 1 de 3) — Técnica e tática por alerta
Plan: —
Status: Ready to plan
Last activity: 2026-11-09 — Roadmap do v1.3 criado (Phases 18-20, 10/10 requisitos mapeados)

Progress: [░░░░░░░░░░] 0%

## Performance Metrics

**Velocity:**
- Total plans completed (v1.3): 0
- Referência: v1.2 12 planos em 3 fases; v1.1 10 planos em 3 fases; v1.0 17 planos em 5 fases

*Updated after each plan completion*
**Per-Plan Metrics:**

| Plan | Duration | Tasks | Files |
|------|----------|-------|-------|

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- [v1.3 roadmap]: 3 fases em fatias verticais (técnica/tática por alerta → API de cobertura → aba+testes+docs); numeração continua (18, 19, 20). Cada fase traz os seus testes; TST-01 e DOC-01 fecham na Phase 20.
- [R16]: técnica MITRE vem de `rule.mitre` do alerta Wazuh primeiro e de `event_catalog.py` (`technique_id`) só como fallback; origem sempre marcada (`wazuh` | `catalog`); nunca forçar nem inventar um mapeamento.
- [R16]: o `rule.mitre` do Wazuh traz listas `id[]` e `tactic[]` sem emparelhamento, por isso a tática vem de uma tabela técnica→tática versionada no repo (ficheiro, não base de dados), validada fail-fast no arranque como o `attack_library.yaml`.
- [R16]: o `DetectionEvent` só ganha campos de forma aditiva (`techniques`, `technique_source`; `technique` deixa de ser sempre `None`); nenhum campo de `GET /api/detections` muda.
- [R16]: "ataques lançados" vêm do `attack_log`/attack_registry; o Caldera fica fora (não está instalado no lab).
- [R12 carry-over]: aprovar uma vaccine não aplica nada no Wazuh (R21); autoria autodeclarada (só há uma API key). Detalhe das decisões de fase do v1.2 em `.planning/milestones/v1.2-phases/`.
- [R11 carry-over]: `ATTACK_ALERTS_SIZE=8000` é paliativo; truncagem por ataque (não por lote) por decidir — relevante para `alerts_truncated` da rota de cobertura.

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

Last session: 2026-11-09
Stopped at: roadmap do v1.3 escrito (ROADMAP.md, STATE.md, rastreabilidade em REQUIREMENTS.md); por aprovar e fazer commit
Resume file: None

## Operator Next Steps

- Rever o roadmap do v1.3 e depois `/gsd-discuss-phase 18` (ou `/gsd-plan-phase 18`)
