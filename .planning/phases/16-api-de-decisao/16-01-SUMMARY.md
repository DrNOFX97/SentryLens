---
phase: 16-api-de-decisao
plan: 01
subsystem: api
tags: [fastapi, vaccines, decision, api-key, closed-contract, sqlite]

requires:
  - phase: 15-store-de-decisoes
    provides: VaccineStore.decide_vaccine (BEGIN IMMEDIATE), get_vaccine com state derivado, vaccine_decision (códigos e validate_request)
provides:
  - "POST /api/vaccines/{vaccine_id}/decision com API key por rota, corpo fechado lido à mão e resposta {vaccine, notice}"
  - "Tabela fixa de códigos HTTP (VACCINE_DECISION_HTTP_STATUS) com 422/404/409/503 estáveis em string"
  - "test_vaccine_decision_api.py (run_tracer, run_refusals) e pin de três rotas em test_vaccines_api.py"
affects: [16-02, 16-03, 17-frontend-de-decisao]

plan_head_before: 149e8395fd3da95a801877ad458a97b84294b6be
plan_head_after: 745f4277bb7f12799f0314a1fb1ef9f800097421
commits: 2

actuals:
  tokens: 8600
  tasks: 2
  commits: 2

tech-stack:
  added: []
  patterns:
    - "Corpo JSON lido à mão com teto de bytes (Content-Length e stream) e object_pairs_hook contra chaves repetidas"
    - "Handler de RequestValidationError com âmbito de uma só rota (request.scope['endpoint']), a delegar no handler por omissão"

key-files:
  created:
    - scripts/test_vaccine_decision_api.py
  modified:
    - scripts/main.py
    - scripts/test_vaccines_api.py

key-decisions:
  - "Teto do corpo 8192 bytes, excedido dá 422 invalid_body (não 413); o corpo válido mais longo (motivo de 500 caracteres em pares de escapes de 12 bytes) fica abaixo de 6200 bytes"
  - "analyst_id mal formado dá 422 invalid_author sem consultar a base; chave em falta ou repetida dá invalid_body"
  - "vaccine_id mal formado dá 422 {detail: invalid_vaccine_id} por um handler de RequestValidationError só desta rota; as outras rotas ficam com o detail em lista do FastAPI"
  - "Releitura falhada depois de decidir dá 503 store_unavailable (a decisão fica gravada; um novo POST dá 409)"
  - "Autoria autodeclarada: só existe uma API key, o registo diz quem o cliente disse ser (D-03)"

patterns-established:
  - "Rota de escrita de vaccines: validar corpo, validar analista no incident_store, decidir no store (sem ler antes), reler só depois"
  - "Todo o detail de erro desta rota é um código ^[a-z_]{1,64}$, nunca texto de exceção"

requirements-completed: [VLB-01, VLB-02]

coverage:
  - id: D1
    description: "POST /api/vaccines/{id}/decision aprova e rejeita com API key por rota, devolve a vaccine com state e decision (nome do incident_store, instante do servidor) e o aviso de que nada foi aplicado no Wazuh"
    requirement: "VLB-01"
    verification:
      - kind: unit
        ref: "scripts/test_vaccine_decision_api.py#run_tracer"
        status: pass
    human_judgment: false
  - id: D2
    description: "Segunda decisão (igual ou diferente) dá 409 already_decided e vaccine substituída dá 409 vaccine_superseded, sem gravar nada"
    requirement: "VLB-02"
    verification:
      - kind: unit
        ref: "scripts/test_vaccine_decision_api.py#run_refusals"
        status: pass
    human_judgment: false
  - id: D3
    description: "Todas as recusas (401, 405, 422, 404, 409, 503) têm código estável em string, sem texto de exceção, e deixam vaccines e vaccine_decisions iguais"
    requirement: "VLB-01"
    verification:
      - kind: unit
        ref: "scripts/test_vaccine_decision_api.py#run_refusals"
        status: pass
    human_judgment: false

duration: 10min
completed: 2026-10-30
status: complete
---

# Phase 16 Plan 01: Rota de decisão Summary

**POST /api/vaccines/{id}/decision: API key por rota, corpo fechado lido à mão com teto de 8192 bytes, analista validado no incident_store, decisão por decide_vaccine e resposta com o estado derivado e o aviso "aceite pelo analista, não aplicada no Wazuh".**

## Performance

- **Duration:** ~10 min
- **Tasks:** 2 (tracer + recusas)
- **Files:** 1 criado, 2 alterados (`scripts/main.py`, `scripts/test_vaccine_decision_api.py`, `scripts/test_vaccines_api.py`)

## Accomplishments

- Rota `decide_vaccine_route` com `dependencies=_REQUIRE_API_KEY` na própria rota; `vaccine_id` mantém `Path(pattern=VACCINE_ID_RE)`.
- Corpo de contrato fechado `{decision, analyst_id, reason?}`; o nome do analista vem do `incident_store` e `decided_at` de `_now_iso()` no servidor.
- Teto do corpo sem o ler todo: Content-Length acima do teto (ou não numérico) recusa sem ler; sem Content-Length a leitura por `request.stream()` pára ao passar do teto.
- Handler de `RequestValidationError` com âmbito da rota para o 422 `invalid_vaccine_id` em string; os restantes 422 da app não mudam.
- `test_vaccines_api.py::run_guarantees` passou a fixar três rotas `/api/vaccines*`, a de decisão só POST, as três com `require_api_key`.

## Ordem fixa da rota

1. `_read_vaccine_decision_body` (teto) -> `_parse_vaccine_decision_body` (corpo e formato do `analyst_id`)
2. `incident_store.get_analyst` (existe, ativo; `sqlite3.Error` -> 503 `incidents_unavailable`)
3. `vaccine_store.decide_vaccine` (validação F15, `BEGIN IMMEDIATE`; `VaccineDecisionError` primeiro, depois `sqlite3.Error`/`ValueError` -> 503 `store_unavailable`)
4. `vaccine_store.get_vaccine` (releitura; erro ou `None` -> 503 `store_unavailable`)
5. `{"vaccine", "notice"}`

Nenhuma leitura da vaccine antes de decidir (a corrida está fechada no store), nenhum WebSocket nem escrita no histórico JSONL.

## Tabela de códigos final

| Código | HTTP |
|---|---|
| `invalid_vaccine_id`, `invalid_decision`, `invalid_author`, `invalid_decided_at`, `reason_required`, `invalid_reason` | 422 |
| `invalid_body`, `analyst_not_found`, `analyst_inactive` | 422 |
| `entry_not_found` | 404 |
| `already_decided`, `vaccine_superseded` | 409 |
| `store_unavailable`, `incidents_unavailable` | 503 |
| sem/errada API key | 401 |
| GET/PUT/PATCH/DELETE na rota | 405 |

## Teto do corpo

`VACCINE_DECISION_BODY_MAX_BYTES = 8192`. O corpo válido mais longo possível é um motivo de 500 caracteres cada um escrito como par de escapes `\uXXXX\uXXXX` (12 bytes), abaixo de 6200 bytes, por isso o teto nunca recusa um corpo válido (provado com 500 emoji em `ensure_ascii`). Um corpo acolchoado até exatamente 8192 bytes é aceite; 8193 é recusado.

## Texto do notice

"Decisão registada: aprovada significa só aceite pelo analista. Vaccine não aplicada no Wazuh: nada foi aplicado nem executado."

## Recusas provadas (sempre com vaccines e vaccine_decisions iguais)

- 401: sem chave e chave errada.
- 422 `invalid_body`: corpo vazio, `null`, lista, string, número, JSON partido, UTF-8 inválido, chave repetida (também aninhada), 7 chaves extra (`decided_by_name`, `decided_by`, `decided_at`, `state`, `vaccine_id`, `previous_state`, `applied`), chave em falta, tipos errados, aninhamento profundo (`RecursionError`), teto + 1 byte, 100 KB com e sem Content-Length.
- 422 `invalid_author`: `analyst_id` mal formado (sem consultar a base) e nome fora do charset (O'Brien).
- 422 `invalid_decision`, `reason_required`, `invalid_reason` (501 caracteres, quebra de linha, override bidi).
- 422 `analyst_not_found`, `analyst_inactive`.
- 422 `invalid_vaccine_id` (cinco ids malformados, com corpo válido e inválido); sem chave dá 401.
- 404 `entry_not_found` (id inexistente e store inexistente, sem criar o ficheiro).
- 409 `already_decided` (igual e diferente), `vaccine_superseded`.
- 503 `store_unavailable` (decisão com `sqlite3.Error`/`ValueError`, releitura com erro ou `None`) e `incidents_unavailable` (sem chamar `decide_vaccine`), sem texto de exceção, caminho, `.sqlite3` nem `Traceback`.
- 405: GET, PUT, PATCH, DELETE.

## Verificação

- `test_vaccine_decision_api.py`: 245 verificações, todas OK.
- `run_all_tests.py vaccine`: 9/9 ficheiros passaram.
- `run_all_tests.py` completo: 84/84 (a suite passou de 83 para 84 ficheiros).
- `git diff ad488f2 -- scripts/vaccine_store.py scripts/vaccine_decision.py vaccines.js index.html app.js api.js style.css`: vazio.

## Task Commits

1. **Task 1 (tracer): rota POST de decisão** - `6755cb5` (feat)
2. **Task 2: teto do corpo e recusas estáveis** - `745f427` (feat)

## Deviations from Plan

None - plan executed exactly as written. Nota de processo: o plano pedia os testes primeiro e a rota depois; a Task 1 foi confirmada em vermelho (19 falhas, 404/405) antes de a rota existir, e na Task 2 só falhava a chave repetida antes do teto/`object_pairs_hook`. Um acrescento menor dentro do âmbito da Task 2: `Content-Length` só aceita dígitos ASCII (`isascii() and isdigit()`), porque `isdigit()` aceita `²` e `int()` rebentaria.

## Issues Encountered

`test_ml_training.py` falhou numa corrida completa em paralelo e passou isolado e na repetição (84/84): é o flake de paralelismo já conhecido, sem relação com este plano.

## Known Stubs

None.

## Threat Flags

None. A superfície nova (um POST) está coberta pelo threat model do plano (T-16-01 a T-16-06).

## Next Phase Readiness

Pronto para o 16-02 (`?state=`, contagens por estado) e 16-03 (varrimento AST, CORS). O contrato de códigos acima é o que a Phase 17 mapeia para frases.

## Self-Check: PASSED

- `scripts/test_vaccine_decision_api.py`, `scripts/main.py`, `scripts/test_vaccines_api.py` existem.
- Commits `6755cb5` e `745f427` são antecessores de HEAD.
