---
phase: 15-store-de-decis-es
plan: 03
subsystem: backend/vaccines
tags: [sqlite, state-filter, append-only, audit, vaccine-decisions, tests]
requires:
  - phase: 15-store-de-decis-es
    provides: decide_vaccine, vaccine_decisions, TracingStore e helpers de teste (planos 15-01 e 15-02)
provides:
  - list_vaccines(state=...) por estado derivado, com e sem a tabela vaccine_decisions
  - run_state_filter: filtro nas duas variantes, valores hostis, ficheiro antigo byte a byte
  - run_file_guarantees: triggers, CHECK, UNIQUE, FK, vaccines do R11 intacta, API fechada, traço sem UPDATE/DELETE
affects: [16-api-de-decisao, 17-frontend-de-decisao]
tech-stack:
  added: []
  patterns:
    - "colunas, FROM e expressão de estado escolhidos juntos pela mesma verificação de sqlite_master"
    - "garantias provadas por SQL direto e sqlite_master, não só pelo código do store"
key-files:
  created: []
  modified:
    - scripts/vaccine_store.py
    - scripts/test_vaccine_decision_store.py
key-decisions:
  - "O filtro por estado entra no store nesta fase; a validação do valor (Query pattern) fica na rota da Phase 16"
  - "O store não valida state: um valor desconhecido ou hostil vai por ? e não casa com nada"
requirements-completed: [VLB-02, VLB-03]
status: complete
duration: ~20 min
completed: 2026-10-29
commits: 2
plan_head_before: b4cbba01952e4c21ed9ce5f80e79d00d32285da8
plan_head_after: 5fdbf06b756476c6ce8615fa4a24e915aa5e28df
estimate:
  tokens: 55000
actuals:
  tokens: 5500
  tasks: 2
  commits: 2
---

# Phase 15 Plan 03: Filtro por estado e provas no ficheiro Summary

**`list_vaccines(state=...)` filtra pelo estado derivado (proposed, approved, rejected) com e sem a tabela de decisões, e o próprio ficheiro SQLite prova que recusa editar, apagar, duplicar ou gravar fora do contrato uma decisão, com a tabela `vaccines` do R11 igual byte a byte.**

## Tasks

| Task | Nome | Commit |
|------|------|--------|
| 1 | Tracer: filtrar por estado derivado, também num ficheiro antigo (`run_state_filter`) | e7f3f0f |
| 2 | Provas no ficheiro: auditoria só de acréscimo, vaccines do R11 intactas, API fechada (`run_file_guarantees`) | 5fdbf06 |

## Filtro por estado (Task 1)

`list_vaccines` ganhou o parâmetro `state` só por nome (default `None`: comportamento de antes). `_read_fragments` passou a devolver `(colunas, FROM, expressão de estado)` escolhidos juntos pela mesma verificação de `sqlite_master`: `COALESCE(d.decision, 'proposed')` com a tabela, o literal `'proposed'` sem ela. A cláusula é `<expressão> = ?` com o valor nos parâmetros; `total` usa o mesmo FROM e WHERE, `store_total` continua sem filtros. `get_vaccine`, `decide_vaccine`, `upsert_batch` e o esquema não mudaram.

| Caso (ficheiro com A rejeitada e substituída por B, B proposed, C approved) | Resultado |
|---|---|
| sem `state` | [C, B], total 2, store_total 3 (igual a antes) |
| `approved` | ([C], 1, 3) |
| `proposed` | ([B], 1, 3) |
| `rejected` | ([], 0, 3); com `include_superseded` [A] |
| `attack_id=2` + `rejected` + `include_superseded` | [A] |
| `attack_id=3` + `proposed` | ([], 0, 3) |
| `limit=1` com `approved` | 1 linha, total 1 |
| `approved' OR '1'='1`, `""`, `APPROVED`, `proposed; DROP TABLE vaccines`, `applied` | ([], 0, 3), sem exceção; as duas tabelas ficam iguais |
| ficheiro antigo (R11): `proposed` | [C, A], total 2; `approved`/`rejected`/hostil -> ([], 0, 2) |

Em todas as linhas devolvidas, `v["state"]` é igual ao filtro. No ficheiro antigo, depois de `list_vaccines` (com e sem filtro) e `get_vaccine`, `vaccine_decisions` continua inexistente e os bytes do ficheiro são idênticos.

## Tentativas recusadas pelo ficheiro (Task 2)

Todas por SQL direto (ligação nova por tentativa) e com o conteúdo das duas tabelas igual ao snapshot no fim:

- **Triggers:** UPDATE de cada uma das 7 colunas (`decision`, `decided_by`, `decided_by_name`, `decided_at`, `reason`, `previous_state`, `vaccine_id`); DELETE com WHERE e DELETE sem WHERE.
- **UNIQUE:** segundo INSERT simples para uma vaccine já decidida.
- **CHECK** (cada tentativa com uma só coisa errada; duas cópias de controlo provam que as linhas válidas seriam aceites): `decision` 'applied'; `previous_state` 'approved'; rejected sem motivo; motivo vazio; motivo só espaços; motivo com 501 caracteres; `decided_by` 'Eddie', 'analyst-A' e 'analyst-'; `decided_by_name` vazio e com 129 caracteres; `vaccine_id` 'abc'.
- **FK:** com `PRAGMA foreign_keys = ON`, `vaccine_id` inexistente.
- **Contraste:** numa base em memória, `INSERT OR IGNORE` com `decision` 'applied' dá rowcount 0 sem erro (razão do INSERT simples, como a emenda A1 do R11).

## Comparação de `sqlite_master` (vaccines do R11 intacta)

- `VACCINES_SCHEMA == R11_VACCINES_DDL`; `SCHEMA == VACCINES_SCHEMA + DECISIONS_SCHEMA`; `vaccine_decisions` não aparece em `VACCINES_SCHEMA`; o comando git sobre o literal de `7b7fd25` sai 0.
- As entradas de `sqlite_master` com `tbl_name = 'vaccines'` (6: tabela, `sqlite_autoindex_vaccines_1` com sql NULL, 2 índices, 2 triggers) são iguais em três bases: só o DDL do R11 em memória, um ficheiro novo depois de `upsert_batch` e `decide_vaccine`, e um ficheiro antigo (`make_r11_file`) depois da primeira decisão (que criou `vaccine_decisions`).
- `UPDATE vaccines SET state = 'approved'` e `DELETE FROM vaccines` continuam a falhar numa vaccine aprovada; `state` é `proposed` em todas as linhas.

## API fechada e traço (D-03)

`VaccineStore` tem exatamente `decide_vaccine`, `get_vaccine`, `list_vaccines` e `upsert_batch` como API pública; o código do store não contém `UPDATE vaccine_decisions` nem `DELETE FROM vaccine_decisions`; `_INSERT_DECISION` não tem `OR IGNORE`, `OR REPLACE` nem `ON CONFLICT`. O traço de `upsert_batch` + decisão aceite + recusada (`already_decided`) + inválida (`invalid_decision`) + id inexistente (`entry_not_found`) não tem nenhum UPDATE sobre decisões nem DELETE; os UPDATE vêm só de `upsert_batch`; a decisão aceite tem exatamente um `INSERT INTO vaccine_decisions (`.

## Verificação

- `test_vaccine_decision_store.py`: saída 0, 181 linhas `[OK]`, nenhuma `[FALHOU]`.
- `run_all_tests.py vaccine`: 8/8 (após a Task 1); `run_all_tests.py`: **83/83 ficheiros passaram** (sem o flake conhecido de `test_attack_log_ids.py`/`test_attack_targets.py` nesta corrida).
- `test_vaccine_store.py` (R11, inalterado) verde; `git diff --quiet 7b7fd25 -- scripts/test_vaccine_store.py scripts/main.py` sai 0.
- Nenhum commit com `Co-Authored-By`.

## Deviations from Plan

**1. [Rule 3 - Blocking] `raises_integrity` não existia em `test_vaccine_decision_store.py`**
- **Found during:** Task 2
- **Issue:** o plano listava `raises_integrity` entre os helpers dos planos 15-01/15-02, mas só existe em `test_vaccine_store.py` (que não se pode alterar).
- **Fix:** helper equivalente acrescentado ao ficheiro de teste, com um argumento opcional `foreign_keys` para o caso do PRAGMA.
- **Files modified:** `scripts/test_vaccine_decision_store.py`
- **Commit:** 5fdbf06

Fora isso, o plano foi executado como escrito. A Task 2 não precisou de nenhuma correção em `scripts/vaccine_store.py`: o esquema do 15-01 passou todas as provas à primeira (as provas de ficheiro já eram satisfeitas pelo DDL confirmado).

## Known Stubs

None.

## Threat Flags

None. T-15-11, T-15-12, T-15-13, T-15-14 e T-15-16 mitigados e provados por teste; T-15-15 aceite (mesmo limite do R11).

## Known follow-ups

- Phase 16: expor `state` em `GET /api/vaccines` com `Query(pattern=r"^(proposed|approved|rejected)$")` e passá-lo por nome a `list_vaccines`; o store não valida o valor.
- Phase 17: documentar a tabela `vaccine_decisions`, os triggers, os códigos de erro e a contagem de 83 ficheiros de teste (`CLAUDE.md`, `README.md`, `DATA_MODEL.md`, `API.md`).

## Self-Check: PASSED

- `scripts/vaccine_store.py` contém `COALESCE(d.decision, 'proposed')`; `scripts/test_vaccine_decision_store.py` contém `def run_state_filter` e `def run_file_guarantees`.
- Commits `e7f3f0f` e `5fdbf06` existem em `main`.
