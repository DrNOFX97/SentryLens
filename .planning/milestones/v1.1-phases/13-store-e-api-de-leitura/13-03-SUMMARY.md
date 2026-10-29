---
phase: 13-store-e-api-de-leitura
plan: 03
subsystem: api
tags: [fastapi, vaccines, filters, read-only, stable-error-codes]

requires:
  - phase: 13-store-e-api-de-leitura
    provides: "13-01: VaccineStore.list_vaccines keyword-only, rotas GET; 13-02: loop e bloco generator"
provides:
  - "GET /api/vaccines com attack_id, technique e include_superseded passados por nome ao store"
  - "test_vaccines_api.py: run_history (D-06/D-07/filtros sobre ciclos reais) e run_guarantees (405, introspecao de rotas, 503 sem fuga, 422/401)"
affects: [14 aba Vaccines]

plan_head_before: 272a8e6ca1d21aadd4c7aab1629981208bfe79f1
plan_head_after: 6d66912e085505bda7d790dd086d051f65be3d43

actuals:
  tokens: 9000
  tasks: 2
  commits: 2

tech-stack:
  added: []
  patterns:
    - "Garantia negativa por introspecao de main.app.routes (metodos e dependencia require_api_key por rota)"
    - "Ciclos reais com o resultado ML trocado entre ciclos para exercitar superseded_by por HTTP"

key-files:
  created: []
  modified:
    - scripts/main.py
    - scripts/test_vaccines_api.py

key-decisions:
  - "O envelope nao mudou: reason so e no_data quando store_total == 0; um filtro sem resultados da 200 com reason null (D-09)"
  - "Nenhuma alteracao de main.py na Task 2: o mapeamento (sqlite3.Error, ValueError) -> 503 ja cobria o ficheiro nao-SQLite (sqlite3.DatabaseError)"

requirements-completed: [VAC-05, VAC-06]

coverage:
  - id: D1
    description: "Filtros por ataque e tecnica MITRE e include_superseded por HTTP; por omissao so a vaccine atual de cada ataque (D-06), vaivem e ataque detetado (D-07)"
    requirement: VAC-06
    verification:
      - kind: integration
        ref: "scripts/test_vaccines_api.py (run_history)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Nenhuma rota de escrita (405, store inalterado), so duas rotas GET com require_api_key na propria rota, estado servido sempre proposed"
    requirement: VAC-05
    verification:
      - kind: integration
        ref: "scripts/test_vaccines_api.py (run_guarantees)"
        status: pass
    human_judgment: false
  - id: D3
    description: "Erros de leitura como 503 store_unavailable sem texto de excecao, traceback nem caminho; 422 e 401"
    requirement: VAC-06
    verification:
      - kind: integration
        ref: "scripts/test_vaccines_api.py (run_guarantees: mock sqlite3.OperationalError, ValueError e ficheiro nao-SQLite)"
        status: pass
    human_judgment: false

duration: 10min
completed: 2026-10-12
status: complete
---

# Phase 13 Plan 03: Filtros, historico de substituidas e garantias negativas Summary

**GET /api/vaccines filtra por ataque, tecnica MITRE e include_superseded, e as garantias negativas do ROADMAP (sem escrita, API key por rota, estado proposed, 503 sem fuga) ficam presas por teste.**

## Accomplishments

- **Filtros (D-08):** `list_vaccines` em `main.py` aceita `attack_id` (1..999999999), `technique` (`^T\d{4}(\.\d{3})?$`, igual a `/api/attacks`) e `include_superseded` (omissao false) e passa-os por nome, com `limit`/`offset`, a `vaccine_store.list_vaccines`. Valores fora dos limites dao 422 antes de chegar ao store.
- **D-06 por HTTP:** com o ataque 3 a passar de partial (`vac-bd617cce8054`) a not_detected (`vac-3eb8018acb1c`), a lista por omissao mostra so a atual; com `include_superseded=true` aparecem as duas e a antiga traz `superseded_by` e `state proposed`; o detalhe da substituida continua a dar 200. O vaivem (ataque volta a partial) repoe `vac-bd617cce8054` como atual.
- **D-07 por HTTP:** quando o ataque 2 passa a detected, `vac-5fe3861aa2a3` fica na lista por omissao, igual byte a byte, `superseded_by` null.
- **D-09:** filtro sem resultados com store nao vazio -> 200, `vaccines []`, `total 0`, `reason null`, `available true`.
- **D-10 / criterio 3 do ROADMAP:** POST/PUT/PATCH/DELETE as duas rotas -> 405 (com e sem chave), store igual antes/depois (linhas, payloads, estados, COUNT); `main.app.routes` tem exatamente duas rotas `/api/vaccines*`, so GET/HEAD, ambas com `require_api_key` nas dependencies da propria rota; todas as vaccines servidas tem `state proposed`.
- **Criterio 4 do ROADMAP:** `sqlite3.OperationalError`, `ValueError` e um ficheiro que nao e SQLite dao 503 `{"detail": "store_unavailable"}` nas duas rotas, sem "Traceback", ".sqlite3", texto da excecao nem caminho; id malformado 422, sem chave 401 (mesmo com filtros), sub-caminho 404.
- **Verificacao:** `test_vaccines_api.py` 93 verificacoes OK; `run_all_tests.py` 44/44.

## Contrato final para a Phase 14

### `GET /api/vaccines`

| Parametro | Tipo / limites | Omissao |
|-----------|----------------|---------|
| `attack_id` | int 1..999999999 | sem filtro |
| `technique` | `^T\d{4}(\.\d{3})?$` | sem filtro |
| `include_superseded` | bool | `false` (so a vaccine atual de cada ataque) |
| `limit` | int 1..500 | 200 |
| `offset` | int >= 0 | 0 |

Envelope: `{available, reason, total, limit, offset, vaccines, generator}`. `total` conta com os mesmos filtros. `available` e `reason` dependem so do store (`reason "no_data"` e `available false` apenas se o store nao tem linhas). Ordem: `attack_id` descendente, depois `created_at` descendente. Cada vaccine = vaccine do motor + `state` (sempre `proposed`), `superseded_by` (id ou null), `created_at`. `generator`: ver 13-02-SUMMARY.

### `GET /api/vaccines/{vaccine_id}`

`{vaccine: {...}}`; devolve tambem as substituidas.

### Codigos

| Codigo | Quando |
|--------|--------|
| 200 | sucesso (incl. filtro sem resultados e store vazio) |
| 401 | sem chave ou chave errada (verificado antes dos parametros) |
| 404 | `entry_not_found` (id valido que nao existe); caminho inexistente |
| 405 | POST/PUT/PATCH/DELETE |
| 422 | `limit`/`offset`/`attack_id`/`technique`/`include_superseded` fora dos limites; `vaccine_id` fora de `^vac-[0-9a-f]{12}$` |
| 503 | `{"detail": "store_unavailable"}` (nunca texto de excecao nem caminho) |

## Task Commits

1. **Task 1 (tracer): filtros e historico por HTTP** - `beb41f5` (feat)
2. **Task 2: garantias negativas** - `6d66912` (test)

## Deviations from Plan

None - plan executed exactly as written. Na Task 2 todos os checks passaram a primeira, por isso `main.py` nao foi tocado (so o teste foi commitado).

Notas de execucao:
- Procedimento C na Task 1: backup `.git/main.py.before-13-03-t1`, patch `.git/main-13-03-t1.patch` (1 hunk), `git apply --cached`; o commit nao arrasta `class AnalystCreate` nem `scripts/incident_store.py`. `main.py` continua CRLF; `git diff -- scripts/main.py` restante tem 0 ocorrencias de "vaccine".
- O teste da Task 1 foi corrido antes de editar `main.py` e falhou por conteudo (a rota ignorava os parametros), como previsto.
- `run_all_tests.py` teve uma execucao com 2 falhas intermitentes (`test_attack_log_ids.py`, `test_attack_targets.py`) que passam isoladas e em 3 execucoes seguidas da suite; nao tocam nas vaccines (provavel contencao entre testes paralelos, pre-existente).

## Known Follow-ups (fora do ambito)

- **A7 / T-13-19:** a leitura nao volta a correr `validate_vaccine`; uma linha adulterada diretamente no ficheiro seria servida (mesmo limite dos `.pkl`, aceite).
- **A8 (13-02):** deteccoes de rede em memoria, vazias depois de um reinicio.
- Flake intermitente de `test_attack_log_ids.py`/`test_attack_targets.py` em execucao paralela (nao investigado; fora do ambito).

## Known Stubs

None.

## Threat Flags

None - sem superficie nova; T-13-14 a T-13-18 mitigados e testados.

## Self-Check: PASSED

- FOUND: scripts/test_vaccines_api.py (run_history, run_guarantees), scripts/main.py (include_superseded=include_superseded)
- FOUND: commits beb41f5, 6d66912
- `run_all_tests.py`: 44/44; `grep -cE '@app\.(post|put|patch|delete)\("/api/vaccines' scripts/main.py` = 0
