---
phase: 15-store-de-decis-es
plan: 01
subsystem: backend/vaccines
tags: [sqlite, append-only, audit, vaccine-decisions, pure-domain-module]
requires:
  - phase: 13-store-e-api-de-leitura
    provides: vaccine_store.py (VACCINES schema, VaccineStore, STORE_FIELDS) e GET /api/vaccines
provides:
  - tabela vaccine_decisions (append-only, UNIQUE por vaccine) no mesmo vaccines.sqlite3
  - VaccineStore.decide_vaccine (keyword-only, BEGIN IMMEDIATE)
  - leitura com state derivado e bloco decision
  - scripts/vaccine_decision.py (regra pura, codigos de erro estaveis, validate_request)
affects: [16-api-de-decisao, 17-frontend-de-decisao]
tech-stack:
  added: []
  patterns:
    - "regra de dominio pura + store que a aplica dentro da transacao"
    - "imutabilidade imposta no ficheiro (UNIQUE, CHECK, triggers RAISE ABORT)"
key-files:
  created:
    - scripts/vaccine_decision.py
    - scripts/test_vaccine_decision.py
    - scripts/test_vaccine_decision_store.py
  modified:
    - scripts/vaccine_store.py
    - scripts/test_vaccines_api.py
key-decisions:
  - "DDL de vaccine_decisions confirmado pelo utilizador (Task 1: confirm), usado tal como esta no plano"
  - "VaccineDecisionError nao deriva de ValueError (as rotas GET mapeiam ValueError para 503)"
  - "Ordem fixa de validacao: vaccine_id, decision, autor, decided_at, motivo; depois no ficheiro: entry_not_found, already_decided, vaccine_superseded"
requirements-completed: [VLB-02, VLB-03]
status: complete
duration: ~25 min
completed: 2026-10-29
commits: 2
plan_head_before: 6b8a1efd0f0d43818448d0e62894fefc51375b07
plan_head_after: f66679fbf23b048ee34840b9f22a50d5a318a7db
estimate:
  tokens: 70000
actuals:
  tokens: 12700
  tasks: 3
  commits: 2
---

# Phase 15 Plan 01: Store de decisoes (tracer + validacao) Summary

**Uma vaccine proposta pode ser aprovada ou rejeitada (com motivo) pelo store: a decisao fica numa tabela `vaccine_decisions` so de acrescimo no mesmo `vaccines.sqlite3`, a leitura devolve `state` derivado e o bloco `decision`, e a tabela `vaccines` do R11 fica intacta byte a byte.**

## Checkpoint da Task 1 (DDL)

Resposta do utilizador: **confirm**. O DDL de `vaccine_decisions` e dos dois triggers entrou em `DECISIONS_SCHEMA` exatamente como na secao "DDL a fixar" do plano. Nada foi escrito antes da confirmacao.

## Tasks

| Task | Nome | Commit |
|------|------|--------|
| 1 | Confirmar o DDL (checkpoint:decision) | sem commit (resposta: confirm) |
| 2 | Tracer: regra pura -> vaccine_decisions -> decide_vaccine -> leitura derivada | e7db8fc |
| 3 | Regra pura completa: todos os codigos de entrada por ordem fixa | f66679f |

## O que ficou fixado

- **Codigos de erro (9, conjunto fechado)**: `INVALID_INPUT_CODES` = `invalid_vaccine_id`, `invalid_decision`, `invalid_author`, `invalid_decided_at`, `reason_required`, `invalid_reason` (Phase 16: 422); `NOT_FOUND_CODES` = `entry_not_found` (404); `CONFLICT_CODES` = `already_decided`, `vaccine_superseded` (409).
- **Ordem das verificacoes**: entrada (`vaccine_id`, `decision`, autor, `decided_at`, motivo) antes de qualquer acesso ao disco; depois, dentro de `BEGIN IMMEDIATE`: `entry_not_found`, `already_decided`, `vaccine_superseded`. Uma vaccine ja decidida e entretanto substituida responde `already_decided`.
- **Esquema**: `SCHEMA = VACCINES_SCHEMA + DECISIONS_SCHEMA`. `VACCINES_SCHEMA` e o literal do R11 sem um byte alterado; confirmado com o comando git de aceitacao (`git show 7b7fd25:scripts/vaccine_store.py` cortado entre `SCHEMA = """` e o `"""` seguinte e igual a `vaccine_store.VACCINES_SCHEMA`, saida 0).
- **Leitura**: LEFT JOIN a `vaccine_decisions` so se a tabela existir em `sqlite_master`; ficheiro antigo do R11 le-se como "sem decisoes" (`state` proposed, `decision` None) e a leitura nao cria a tabela.
- **Autor**: so formato (id `^analyst-[a-z0-9-]{1,64}$`, nome 1-128 sem `< > & " '` nem controlo); o store nao importa `incident_store`/`incident_engine`/`incident_ingest` (provado por AST).
- **Motivo**: uma linha, maximo 500 caracteres depois do `strip`, sem categorias Unicode Cc/Cf/Cs/Co/Cn/Zl/Zp; guardado verbatim (texto com `<script>` ou com aspeto de instrucao e dado).
- `STORE_FIELDS = ("state", "superseded_by", "created_at", "decision")`.

## Verificacao

- `run_all_tests.py vaccine`: **8/8 ficheiros passaram** (6 de base + `test_vaccine_decision.py` + `test_vaccine_decision_store.py`; no fim da Task 2 estava 7/7).
- Suite completa: 83/83.
- `git diff --quiet 7b7fd25 -- scripts/test_vaccine_store.py scripts/main.py`: sai 0 (teste do R11 e app nao mudaram).
- Nenhum commit com `Co-Authored-By`.

## Deviations from Plan

None - plan executed exactly as written.

Notas sem impacto: `test_vaccines_api.py` e `vaccine_store.py` estao em CRLF no working tree (git normaliza com autocrlf); os ficheiros novos foram criados em LF e o git avisa que passarao a CRLF no proximo toque. A pureza do modulo e provada por AST (`re`, `unicodedata`, `datetime`).

## Known Stubs

None.

## Threat Flags

None - nenhuma superficie nova alem da prevista no `<threat_model>` do plano (sem rota HTTP nesta fase).

## Known follow-ups (para as proximas fases)

- Phase 16: mapear `INVALID_INPUT_CODES` -> 422, `NOT_FOUND_CODES` -> 404, `CONFLICT_CODES` -> 409 e `sqlite3.Error` -> 503 `store_unavailable`; verificar que o analista existe e esta ativo (`incident_store.list_analysts`) e passar o nome atual como `decided_by_name`; gerar `now_iso` no servidor.
- `GET /api/vaccines[/{id}]` ja devolve `decision: null` (D-11); a documentacao do contrato e da Phase 17 (VLB-07).
- Um analista com nome fora do conjunto aceite (por exemplo com apostrofo) nao consegue decidir (`invalid_author`, falha fechada): a Phase 16 decide a mensagem.
- Planos 15-02 (recusas e corrida) e 15-03 (filtro por estado e provas ao nivel do ficheiro) acrescentam funcoes `run_*` a `test_vaccine_decision_store.py`.

## Self-Check: PASSED

- Ficheiros: `scripts/vaccine_decision.py`, `scripts/test_vaccine_decision.py`, `scripts/test_vaccine_decision_store.py` existem; `scripts/vaccine_store.py` e `scripts/test_vaccines_api.py` alterados.
- Commits `e7db8fc` e `f66679f` existem em `main`.
