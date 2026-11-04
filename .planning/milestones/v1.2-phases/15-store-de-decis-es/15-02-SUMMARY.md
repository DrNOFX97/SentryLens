---
phase: 15-store-de-decis-es
plan: 02
subsystem: backend/vaccines
tags: [sqlite, begin-immediate, concurrency, append-only, vaccine-decisions, tests]
requires:
  - phase: 15-store-de-decis-es
    provides: decide_vaccine, vaccine_decisions e vaccine_decision.py (plano 15-01)
provides:
  - run_refusals: quatro recusas estáveis sem gravar nada, decisão que sobrevive à substituição (D-09) e a reinícios
  - run_concurrency: ordem das instruções (set_trace_callback), 8 threads e corrida com o gerador
affects: [16-api-de-decisao]
tech-stack:
  added: []
  patterns:
    - "prova da ordem das instruções por set_trace_callback numa subclasse de teste que sobrescreve _connect"
    - "corrida determinística com uma ligação direta que segura o lock de escrita"
key-files:
  created: []
  modified:
    - scripts/test_vaccine_decision_store.py
key-decisions:
  - "decide_vaccine nao precisou de nenhuma correção: a forma da transação fixada no 15-01 passou todos os testes à primeira"
requirements-completed: [VLB-02, VLB-03]
status: complete
duration: ~15 min
completed: 2026-10-29
commits: 2
plan_head_before: cfe6928
plan_head_after: f88afe3
estimate:
  tokens: 50000
actuals:
  tokens: 9500
  tasks: 2
  commits: 2
---

# Phase 15 Plan 02: Recusas e corrida (BEGIN IMMEDIATE) Summary

**A decisão é final e a corrida está fechada: quatro códigos de recusa distintos não gravam nada, uma vaccine aprovada continua aprovada depois de substituída pelo gerador, e a verificação e o INSERT vivem na mesma transação BEGIN IMMEDIATE, provado pela ordem das instruções e por concorrência real.**

## Tasks

| Task | Nome | Commit |
|------|------|--------|
| 1 | Tracer: recusas ponta a ponta e interação com o gerador (`run_refusals`) | 7c45250 |
| 2 | Corrida com o gerador e entre decisões (`run_concurrency`) | f88afe3 |

## Códigos observados (Task 1)

`already_decided`, `vaccine_superseded`, `entry_not_found`, `reason_required` (conjunto exato, todos em `ERROR_CODES`; os dois primeiros em `CONFLICT_CODES`, `entry_not_found` em `NOT_FOUND_CODES`). Em cada recusa as linhas de `vaccines` e `vaccine_decisions` ficaram iguais; o ficheiro inexistente continua a não existir.

- Decidir de novo uma vaccine decidida (mesma decisão ou outra): `already_decided`; também depois de substituída (nunca `vaccine_superseded`).
- D-09: A aprovada e substituída por B mantém `approved` e o bloco `decision` (Eddie), `superseded_by` = B; B nasce `proposed` com `decision` None. No vaivém A-B-A, A volta a ser a atual com o mesmo bloco e B (por decidir) responde `vaccine_superseded`.
- Uma `VaccineStore` nova sobre o mesmo ficheiro responde `already_decided` e lê a mesma decisão.
- `reason_required` não deixa nada pendurado: a decisão seguinte com motivo é aceite.

## Traço de instruções (Task 2)

Decisão aceite:
`PRAGMA foreign_keys = ON`, `BEGIN IMMEDIATE`, `SELECT superseded_by FROM vaccines WHERE id = ...`, `SELECT decision FROM vaccine_decisions WHERE vaccine_id = ...`, `INSERT INTO vaccine_decisions (...) VALUES (...)`, `COMMIT`. Sem UPDATE.

Recusa no ficheiro (`already_decided`): as mesmas até ao segundo SELECT e depois `ROLLBACK` (sem INSERT nem COMMIT).

Recusa de validação (`decision` "applied"): traço vazio, nenhuma ligação aberta. `upsert_batch` (gerador) sem `BEGIN IMMEDIATE` nem `PRAGMA foreign_keys = ON`: o R11 escreve como antes.

## Concorrência

| Cenário | Resultado |
|---------|-----------|
| 8 threads, instâncias separadas, `Barrier(8)` | 1 sucesso, 7 `already_decided`, 0 outras exceções, 1 linha (do vencedor), ~0,02 s |
| 8 threads, mesma instância | idem, ~0,01 s |
| Gerador segura `BEGIN IMMEDIATE` + marca `superseded_by`, depois COMMIT | decisão à espera (thread viva 0,3 s depois), depois `vaccine_superseded`, nada gravado |
| Gerador segura `BEGIN IMMEDIATE` sem mudar nada, depois ROLLBACK | decisão passa, 1 linha |

`test_vaccine_decision_store.py` correu três vezes seguidas, sempre com saída 0 e sem `[FALHOU]`.

## Verificação

- `run_all_tests.py vaccine`: 8/8 ficheiros passaram (após cada task).
- `git diff --quiet 7b7fd25 -- scripts/test_vaccine_store.py scripts/main.py`: sai 0.
- Nenhum commit com `Co-Authored-By`.

## Deviations from Plan

None - plan executed exactly as written. `scripts/vaccine_store.py` não foi tocado (o plano previa-o só se um teste revelasse um defeito).

## Known Stubs

None.

## Threat Flags

None. T-15-08 e T-15-09 mitigados e provados (ordem das instruções, corrida com o gerador, 8 threads).

## Self-Check: PASSED

- `scripts/test_vaccine_decision_store.py` contém `def run_refusals`, `def run_concurrency`, `set_trace_callback` e `Barrier(8)`.
- Commits `7c45250` e `f88afe3` existem em `main`.
