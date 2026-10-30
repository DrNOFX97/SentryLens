---
phase: 16-api-de-decisao
plan: 02
subsystem: api
tags: [fastapi, vaccines, state-filter, state-counts, read-only, sqlite]

requires:
  - phase: 15-store-de-decisoes
    provides: list_vaccines(state=...), get_vaccine com state e decision, _read_fragments, vaccine_decision.DERIVED_STATES
  - phase: 16-api-de-decisao
    provides: POST /api/vaccines/{id}/decision (usada pelos testes para decidir por HTTP)
provides:
  - "GET /api/vaccines?state=proposed|approved|rejected validado pelo FastAPI (VaccineState), 422 fora do conjunto"
  - "state_counts no envelope de GET /api/vaccines: {proposed, approved, rejected} das vaccines atuais, None sem amostra"
  - "VaccineStore.count_by_state(): leitura aditiva, mode=ro, sem tocar no esquema"
affects: [16-03, 17-frontend-de-decisao]

plan_head_before: ce649ea
plan_head_after: 2d405710ee26cb5b1db65387b7628d33161cee66
commits: 2

actuals:
  tokens: 9000
  tasks: 2
  commits: 2

tech-stack:
  added: []
  patterns:
    - "Contagem de KPI sobre o universo fixo das vaccines atuais, independente dos filtros do pedido; None sem amostra"
    - "Leitura nova no store reutiliza _read_fragments: expressão de estado fixa, nenhum valor interpolado"

key-files:
  created: []
  modified:
    - scripts/main.py
    - scripts/vaccine_store.py
    - scripts/test_vaccines_api.py
    - scripts/test_vaccine_decision_store.py
    - scripts/test_vaccines_frontend.py

key-decisions:
  - "O campo do envelope chama-se state_counts (o envelope já tem generator.counts, do gerador) e o método do store count_by_state"
  - "Com amostra as contagens levam zeros explícitos nos estados sem vaccines (medido 0 é dado); só a falta de amostra é None"
  - "count_by_state corre depois de list_vaccines no mesmo try, para um store partido continuar a dar 503 pelo primeiro"
  - "Um estado lido fora de DERIVED_STATES levanta ValueError (linha corrompida) e a rota dá 503 store_unavailable"

patterns-established:
  - "Filtro de estado: Literal na assinatura da rota (422 do FastAPI) e valor por ? no store"

requirements-completed: [VLB-05]

coverage:
  - id: D1
    description: "GET /api/vaccines?state= filtra pelo estado derivado, 422 fora do conjunto, filtro sem resultado não é no_data, aprovada substituída só com include_superseded"
    requirement: "VLB-05"
    verification:
      - kind: unit
        ref: "scripts/test_vaccines_api.py#run_state_read"
        status: pass
    human_judgment: false
  - id: D2
    description: "Lista e detalhe trazem state e decision (autor, data, motivo) depois de decidir por HTTP"
    requirement: "VLB-05"
    verification:
      - kind: unit
        ref: "scripts/test_vaccines_api.py#run_state_read"
        status: pass
    human_judgment: false
  - id: D3
    description: "state_counts das vaccines atuais, igual com e sem filtros, None sem amostra, 503 estável se count_by_state falha"
    requirement: "VLB-05"
    verification:
      - kind: unit
        ref: "scripts/test_vaccine_decision_store.py#run_state_counts"
        status: pass
      - kind: unit
        ref: "scripts/test_vaccines_api.py#run_state_counts_api"
        status: pass
    human_judgment: false
  - id: D4
    description: "Os GET não alteram bytes nem st_mtime_ns do ficheiro e não o criam; o frontend desenha approved/rejected pelo próprio texto"
    requirement: "VLB-05"
    verification:
      - kind: unit
        ref: "scripts/test_vaccines_api.py#run_state_counts_api"
        status: pass
      - kind: unit
        ref: "scripts/test_vaccines_frontend.py#run_states"
        status: pass
    human_judgment: false

duration: 15min
completed: 2026-10-30
status: complete
---

# Phase 16 Plan 02: Leitura por estado Summary

**GET /api/vaccines ganha `?state=` validado como Literal (422 fora de proposed/approved/rejected) e `state_counts` das vaccines atuais, calculado por uma leitura nova só de leitura no store e `None` sem amostra, nunca 0.**

## Performance

- **Duration:** ~15 min
- **Tasks:** 2 (tracer + contagens)
- **Files:** 5 alterados, nenhum criado, nenhum ficheiro de frontend

## Accomplishments

- `VaccineState = Literal["proposed", "approved", "rejected"]` em `main.py` e parâmetro `state` em `list_vaccines`, passado por nome ao store; um teste prova `typing.get_args(main.VaccineState) == vaccine_decision.DERIVED_STATES`.
- `VaccineStore.count_by_state()`: `None` se o ficheiro não existe ou `vaccines` tem 0 linhas; senão `GROUP BY` da expressão de estado de `_read_fragments` sobre `superseded_by IS NULL`, com as três chaves de `DERIVED_STATES` e zeros explícitos.
- Envelope com `state_counts`, igual com `state`, `attack_id`, `technique` e `include_superseded` (testado com oito consultas).
- `GET /api/vaccines/{id}` sem alteração de código (D-13): só ganhou testes.

## Casos do filtro (run_state_read)

Montagem por HTTP: `vac-bd617cce8054` aprovada por Eddie, `vac-5fe3861aa2a3` rejeitada por Jeremy ("Regra ruidosa"), depois um segundo ciclo cria `vac-3eb8018acb1c`, que substitui a aprovada.

- Sem filtro: `[vac-3eb8018acb1c, vac-5fe3861aa2a3]`, estados `[proposed, rejected]`.
- `?state=rejected`: só `vac-5fe3861aa2a3`, total 1, `decision.reason` e `decided_by_name` corretos.
- `?state=proposed`: só `vac-3eb8018acb1c`, `decision` None.
- `?state=approved`: `vaccines []`, total 0, `reason` None, `available` True (filtro sem resultado não é `no_data`).
- `?state=approved&include_superseded=true` (D-12): `vac-bd617cce8054`, `approved`, `decided_by_name` Eddie, `superseded_by` preenchido; nenhum campo novo no envelope.
- 422 para `applied`, `APPROVED`, vazio, `proposed;DROP` e `approved'`.
- Detalhe: a aprovada substituída tem `set(decision) == set(DECISION_FIELDS)`; a atual tem `decision` None.

## Contagens (run_state_counts e run_state_counts_api)

- Ficheiro inexistente: `None`, ficheiro não criado. Só esquema e 0 linhas: `None`.
- Ficheiro antigo sem `vaccine_decisions`: `{proposed: 2, approved: 0, rejected: 0}`, sem criar a tabela, bytes e mtime iguais.
- Aprovada e substituída não conta: `{2, 0, 0}`; depois de decidir C e B: `{0, 1, 1}`; soma igual ao total de `list_vaccines()` sem filtros.
- Rota: `{proposed: 1, approved: 0, rejected: 1}` em todas as consultas; store inexistente ou sem linhas dá `state_counts` None e `no_data`.
- `sqlite3.OperationalError` ou `ValueError` em `count_by_state` dá 503 `{"detail": "store_unavailable"}` sem texto de exceção.
- GET sem efeitos: bytes e `st_mtime_ns` do `v.sqlite3` iguais depois de lista (sem filtro, com cada estado, com `include_superseded`) e de três detalhes.
- API pública do store fixada em `count_by_state, decide_vaccine, get_vaccine, list_vaccines, upsert_batch`.
- Frontend: `vacRowsHtml` contém `vacCell(VAC_STATE_LABELS[vaccine.state] || vaccine.state)`; `approved`/`rejected` aparecem como o próprio texto (escapado pelo `htmlT`), nunca `undefined`. A Phase 17 acrescenta os rótulos.

## Verificação

- `test_vaccine_decision_store.py`, `test_vaccines_api.py`, `test_vaccines_frontend.py` e `test_vaccine_decision_api.py`: todos verdes.
- `run_all_tests.py vaccine`: 9/9 ficheiros passaram.
- `run_all_tests.py` completo: 84/84.
- `VACCINES_SCHEMA` igual ao `SCHEMA` de `ad488f2`; `git diff ad488f2` sem diferenças em `vaccine_decision.py`, `vaccine_engine.py`, `vaccine_ingest.py`, `vaccines.js`, `index.html`, `app.js`, `api.js`, `style.css`.

## Task Commits

1. **Task 1 (tracer): filtro por estado** - `9d3c5e1` (feat)
2. **Task 2: contagens por estado no envelope** - `2d40571` (feat)

## Deviations from Plan

None - plan executed exactly as written. Nota de processo: o plano pedia testes primeiro; ambas as tarefas foram confirmadas em vermelho (`AttributeError` em `main.VaccineState`; `KeyError: 'state_counts'` e `count_by_state` em falta) antes da implementação. O check do fallback do estado em `vacRowsHtml` já passava no frontend atual (é um contrato de texto que fixa o comportamento existente).

## Issues Encountered

None.

## Known Stubs

None.

## Threat Flags

None. T-16-07 (`state` por Literal, 422 testado com `;` e `'`), T-16-08 (`None` sem amostra, soma igual ao total, estado desconhecido dá 503) e T-16-09 (bytes e mtime iguais, ficheiro inexistente não criado) cobertos por testes.

## Next Phase Readiness

Pronto para o 16-03 (varrimento AST e CORS). Para a Phase 17: `state_counts` serve os KPIs (None mostra "Sem dados") e `?state=` serve o filtro da tabela; faltam os rótulos de `approved`/`rejected` em `VAC_STATE_LABELS`.

## Self-Check: PASSED

- `scripts/main.py`, `scripts/vaccine_store.py`, `scripts/test_vaccines_api.py`, `scripts/test_vaccine_decision_store.py`, `scripts/test_vaccines_frontend.py` existem.
- Commits `9d3c5e1` e `2d40571` são antecessores de HEAD.
