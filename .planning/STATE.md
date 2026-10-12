---
gsd_state_version: "1.0"
milestone: v1.1
milestone_name: R11 Vaccine Engine
current_phase: 14
current_phase_name: aba-vaccines-testes-e-documenta-o
status: executing
stopped_at: Phase 14 context gathered
last_updated: "2026-10-12T09:34:10.713Z"
last_activity: 2026-10-12
last_activity_desc: Phase 13 complete, transitioned to Phase 14
state_head: 878d8e5b7f6cbfcb9ce25fa7a18497c4c88ad884
progress:
  total_phases: 3
  completed_phases: 2
  total_plans: 10
  completed_plans: 6
  percent: 60
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-10-11)

**Core value:** Medir de forma honesta, com dados reais, quão bem o laboratório deteta e responde a ataques — nunca apresentar como real um valor inventado ou sem amostra.
**Current focus:** Phase 13 — Store e API de leitura

## Current Position

Phase: 14 (aba-vaccines-testes-e-documenta-o) — READY TO EXECUTE
Plan: Not started
Status: Ready to execute
Last activity: 2026-10-12 — Phase 13 complete, transitioned to Phase 14

Progress: [██████░░░░] 60%

## Performance Metrics

**Velocity:**
- Total plans completed (v1.1): 0
- v1.0 (referência): 17 planos em 5 fases

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 12 | 3 | - | - |
| 13 | 3 | - | - |

*Updated after each plan completion*
**Per-Plan Metrics:**

| Plan | Duration | Tasks | Files |
|------|----------|-------|-------|
| Phase 12 P01 | 4 min | 2 tasks | 2 files |
| Phase 12 P02 | 5 min | 2 tasks | 2 files |
| Phase 12 P03 | 6 min | 2 tasks | 2 files |
| Phase 13 P01 | 7min | 2 tasks | 6 files |
| Phase 13 P02 | 12min | 2 tasks | 4 files |
| Phase 13 P03 | 10min | 2 tasks | 2 files |

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- [v1.1 roadmap]: 3 fases em fatias verticais (motor → store/API → dashboard+docs); a numeração continua a do v1.0 (12, 13, 14).
- [v1.1 roadmap]: VAC-08 (testes + docs) mapeia à Phase 14; os testes de cada fase escrevem-se com o respetivo código, como no v1.0.
- [R11]: uma vaccine só propõe — nunca é aplicada no Wazuh, nunca tem comandos executáveis, estado fixo `proposed` (escrita por HTTP é R12).
- [Phase 12]: D-03 fixado: vaccine id = vac- + 12 hex sha256('<attack_id>:<sensores em falta>'), literais golden no teste
- [Phase 12]: D-07 refinado: uma vaccine por ataque com proposals[] por sensor em falta; so a proposta rule traz regra {event_ids,min_count=1,window_seconds=300}
- [Phase 12]: 12-02: regex da origem com fullmatch; correlation sem available=True e source_unavailable (fail-closed); considered/skipped/alerts_truncated None quando nada foi medido
- [Phase 12]: 12-03: id do attack log = int 1..999_999_999, max+1 sobre ids validos de qualquer status (nunca contagem+1); AttackIdUnavailable fail-closed antes de lancar e de escrever; sem backfill
- [Phase 13]: A1: INSERT ... ON CONFLICT(id) DO NOTHING em vez de INSERT OR IGNORE (emenda a D-04, provada por teste)
- [Phase 13]: A2: vaccines so gravadas para ataques mais velhos que SENTRYLENS_VACCINE_SETTLE_SECONDS (omissao 600)
- [Phase 13]: GET /api/vaccines abre o SQLite so-leitura e nunca cria o ficheiro (no_data com store inexistente)
- [Phase 13]: 13-02: em erro alerts_truncated fica None (ciclo falhado nao mediu); A3 e A5 mantidas
- [Phase 13]: 13-03: filtro sem resultados com store nao vazio da 200 com reason null; reason no_data so com store sem linhas (D-09)

### Pending Todos

None yet.

### Blockers/Concerns

- [Phase 13] Por decidir no discuss-phase: quem escreve no store e quando (o `GET` tem de ficar sem efeitos secundários, por isso a geração/persistência corre fora do pedido).
- [Phase 12] A regra proposta para um ataque `partial` (o sensor em falta vs o conjunto esperado) não está especificada nos requisitos — decidir no discuss-phase.

## Deferred Items

Items acknowledged and deferred at milestone close, most recent first:

| Category | Item | Status | Deferred At | Milestone |
|----------|------|--------|-------------|-----------|
| verification | Verificação humana do R9/R10 no dashboard (badges, aviso após `adopt`, avaliação rotulada) | Pending | 2026-10-11 | v1.0 |
| data | Primeiro ciclo de treino real (lançar ataques, exportar na mesma janela, treinar `v1`) | Pending | 2026-10-11 | v1.0 |

## Session Continuity

Last session: 2026-10-12T08:38:40.033Z
Stopped at: Phase 14 context gathered
Resume file: .planning/phases/14-aba-vaccines-testes-e-documenta-o/14-CONTEXT.md

## Operator Next Steps

- Discutir a primeira fase com `/gsd-discuss-phase 12` (ou planear já com `/gsd-plan-phase 12`).
