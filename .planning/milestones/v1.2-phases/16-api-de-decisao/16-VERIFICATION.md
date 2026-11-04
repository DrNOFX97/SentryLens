---
phase: 16-api-de-decisao
verified: 2026-10-30T11:30:00Z
status: passed
score: 4/4 must-haves verified
covered_files:
  - ".planning/phases/16-api-de-decisao/16-01-PLAN.md"
  - ".planning/phases/16-api-de-decisao/16-01-SUMMARY.md"
  - ".planning/phases/16-api-de-decisao/16-02-PLAN.md"
  - ".planning/phases/16-api-de-decisao/16-02-SUMMARY.md"
  - ".planning/phases/16-api-de-decisao/16-03-PLAN.md"
  - ".planning/phases/16-api-de-decisao/16-03-SUMMARY.md"
  - "scripts/main.py"
  - "scripts/test_cors.py"
  - "scripts/test_vaccine_decision_api.py"
  - "scripts/test_vaccines_api.py"
  - "scripts/vaccine_store.py"
covered_digest: "v3:sha256:4ff2b7c0da9994c76fbe4cd52d447febc4a2d545c33ff0ea82f75d88993c07ec"
behavior_unverified: 0
overrides_applied: 0
---

# Phase 16: API de decisão - Verification Report

**Phase Goal:** O analista decide por HTTP e lê o resultado, com as garantias de segurança do R11 mantidas.
**Verified:** 2026-10-30
**Status:** passed
**Re-verification:** No (initial verification)

## Observable Truths (ROADMAP success criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | `POST /api/vaccines/{id}/decision` exige API key (401), valida corpo fechado, devolve 404/409/422/503 com códigos estáveis; GET sem efeitos | VERIFIED | `main.py` l.2103: `@app.post(..., dependencies=_REQUIRE_API_KEY)` (por rota). Corpo lido à mão com teto de 8192 bytes, `object_pairs_hook` contra chaves repetidas, chaves fechadas `decision/analyst_id/reason`. Tabela `VACCINE_DECISION_HTTP_STATUS` mapeia códigos para 422/404/409/503, `detail` sempre string. Spot-check próprio (TestClient, DB temporária): sem key 401; analista inexistente 422 `analyst_not_found`; PUT/DELETE 405; GET e recusas não criaram ficheiro (diretório vazio). Escrita via `decide_vaccine` (BEGIN IMMEDIATE) sem "ler antes de decidir". |
| 2 | `GET /api/vaccines[/{id}]` traz `state` e `decision`, filtra por estado, sem amostra "Sem dados" nunca 0 | VERIFIED | `state: VaccineState` na lista (valor fora do conjunto: 422, confirmado `?state=applied`). `state_counts` via `VaccineStore.count_by_state` (ligação `mode=ro`, só vaccines atuais, `None` sem amostra, medido: store vazio devolve `state_counts: None` e `reason: no_data`). Detalhe usa `_to_vaccine` (state/decision da Phase 15). O texto "Sem dados" é da UI (Phase 17); o contrato do backend (`no_data`/`None`) está cumprido. |
| 3 | Nenhuma rota/módulo aplica ou executa; texto diz aprovada != aplicada | VERIFIED | `run_no_apply` em `test_vaccine_decision_api.py` (varrimento AST de `vaccine_*.py` e funções de vaccines de `main.py`, provado contra violações plantadas). Handler só chama `incident_store.get_analyst`, `vaccine_store.decide_vaccine`, `vaccine_store.get_vaccine`. `VACCINE_DECISION_NOTICE`: "aprovada significa só aceite pelo analista... não aplicada no Wazuh". Sem campo `applied`/`active`. |
| 4 | `allow_methods` do CORS e `test_cors.py` cobrem o método novo | VERIFIED | Corrida de `test_cors.py`: preflight POST da rota de decisão 200, PUT/DELETE recusados (400), origens externas sem ACAO, `allow_methods == ['GET','POST','PATCH']` fixado. Nenhuma alteração a `main.py` era necessária (POST já permitido). |

**Score:** 4/4

## Requirements Coverage

| Requisito | Estado | Evidência |
|-----------|--------|-----------|
| VLB-01 (POST com API key por rota, CORS coerente) | SATISFIED | rota + `test_cors.py` |
| VLB-02 (final, 409 `already_decided`/`vaccine_superseded`, mapeamento HTTP) | SATISFIED | tabela de status + `run_refusals`; lógica de transição herdada da Phase 15 |
| VLB-04 (nada aplica, teste varre) | SATISFIED | `run_no_apply` |
| VLB-05 (GET com estado/decisão/filtro, sem amostra nunca 0) | SATISFIED | `list_vaccines`, `count_by_state`, `get_vaccine` |
| VLB-03 (Phase 15) | n/a nesta fase | schema não alterado |
| VLB-06/07 | Phase 17 | pendentes por desenho |

Sem requisitos órfãos: REQUIREMENTS.md mapeia VLB-01/02/04/05 a esta fase e os três planos reclamam-nos.

## Behavioral Spot-Checks / Testes executados

| Comando (a partir de `scripts/`, venv) | Resultado |
|---------|-----------|
| `python run_all_tests.py vaccine` | 9/9 PASS (inclui `test_vaccine_decision_api.py`, `test_vaccines_api.py`, `test_vaccine_decision_store.py`, `test_vaccines_frontend.py`) |
| `python test_cors.py` | todos `[OK]`, "Todos os testes passaram" |
| Script próprio com `TestClient` (401, 422, 405, state 422, GET sem criar ficheiro) | como esperado |

Não corri a suite completa (84/84 reclamada em 16-03-SUMMARY); está fora do pedido e é critério da Phase 17.

## Anti-Patterns

Nenhum marcador TBD/FIXME/XXX nem stubs nos ficheiros da fase inspecionados (rota, helpers, `count_by_state`). Sem handlers inline ou código de aplicação.

## Observações (não bloqueantes)

- A autoria do analista é autodeclarada (só existe uma API key); está documentado no docstring da rota e em CONTEXT D-03. É um limite aceite, não um gap.
- `invalid_author` para nomes de analista com caracteres fora do charset (ex. apóstrofo) é aceite e documentado (D-07); a frase fica para a Phase 17.
- Documentação (`API.md`, `DATA_MODEL.md`, README, CLAUDE.md) ainda não descreve o R12 — pertence à Phase 17 (VLB-07).

## Human Verification Required

Nenhuma. Nada na fase é visual nem depende de serviços externos.

## Gaps Summary

Sem lacunas. O objetivo da fase (decidir por HTTP e ler o resultado com as garantias do R11) está atingido no código e provado por testes que passam.

---

_Verified: 2026-10-30_
_Verifier: Claude (gsd-verifier)_
