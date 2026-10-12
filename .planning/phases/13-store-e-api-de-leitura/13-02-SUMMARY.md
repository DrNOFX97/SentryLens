---
phase: 13-store-e-api-de-leitura
plan: 02
subsystem: api
tags: [fastapi, background-loop, vaccines, resilience, stable-error-codes]

requires:
  - phase: 13-store-e-api-de-leitura
    provides: "13-01: VaccineStore, vaccine_ingest (env_int, select_attack_ids, persist_vaccines), main._run_vaccine_cycle, GET /api/vaccines"
provides:
  - "Loop de background _vaccine_loop registado no arranque (app.state.vaccine_task)"
  - "VaccineLoopState (record/snapshot) e constantes GENERATOR_* em vaccine_ingest"
  - "Bloco generator em GET /api/vaccines com estado da ultima execucao e codigos estaveis"
affects: [13-03 filtros HTTP e garantias, 14 aba Vaccines]

plan_head_before: 373d0d8
plan_head_after: edffe8d5d4ff378f3b984fc3f0415ad4f8940697

actuals:
  tokens: 7300
  tasks: 2
  commits: 3

tech-stack:
  added: []
  patterns:
    - "Loop de background com except Exception por iteracao e no ciclo; CancelledError propaga"
    - "Estado em memoria que so aceita codigos de uma lista fechada (texto livre vira unexpected_error)"

key-files:
  created:
    - scripts/test_vaccine_ingest.py
  modified:
    - scripts/vaccine_ingest.py
    - scripts/main.py
    - scripts/test_vaccines_api.py

key-decisions:
  - "A3 mantida: grava-se mesmo com alertas truncados; so sai partial, not_detected sem correspondencia vira unknown e nao gera; o risco fica em generator.alerts_truncated"
  - "A5 mantida: o estado do loop vive em memoria e e exposto no envelope da lista (generator); depois de um reinicio comeca em never_run"
  - "Em erro, alerts_truncated fica None (nao False): num ciclo falhado nao houve medicao, afirmar False seria inventar"

requirements-completed: [VAC-05, VAC-06]

coverage:
  - id: D1
    description: "Loop de arranque gera vaccines logo e a cada intervalo (omissao 300 s, 30..86400), sobrevive a excecoes e termina ao cancelar"
    requirement: VAC-05
    verification:
      - kind: integration
        ref: "scripts/test_vaccine_ingest.py (run_tracer: arranque real, cancelamento, resiliencia)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Indexer indisponivel chega ao analista como generator.error_code indexer_unavailable, sem alterar a lista nem vazar texto de excecao"
    requirement: VAC-06
    verification:
      - kind: integration
        ref: "scripts/test_vaccine_ingest.py (run_tracer: Indexer em baixo)"
        status: pass
    human_judgment: false
  - id: D3
    description: "Matriz de falhas com codigos estaveis, store intacto, truncagem, janela, estabilizacao e vaccine adulterada rejeitada"
    requirement: VAC-05
    verification:
      - kind: unit
        ref: "scripts/test_vaccine_ingest.py (run_failures, run_selection)"
        status: pass
    human_judgment: false

duration: 12min
completed: 2026-10-12
status: complete
---

# Phase 13 Plan 02: Loop de background e estado do gerador Summary

**O backend gera vaccines sozinho num loop registado no arranque, e GET /api/vaccines expoe no bloco `generator` o estado da ultima execucao com codigos estaveis, para que "Indexer indisponivel" chegue ao analista como codigo e nao como lista vazia.**

## Accomplishments

- **Loop (D-01, D-02):** `_start_vaccine_loop` (segundo `@app.on_event("startup")`, `_start_system_monitor` intocado) cria `app.state.vaccine_task = asyncio.create_task(_vaccine_loop())`. Primeiro ciclo logo no arranque, depois um a cada `SENTRYLENS_VACCINE_INTERVAL_SECONDS` (omissao 300, aceita 30..86400, invalido -> omissao via `env_int`). `except Exception` por iteracao e dentro do ciclo; `CancelledError` propaga (a task fica `cancelled()`).
- **Estado (D-03):** `vaccine_ingest.VaccineLoopState` (lock, `record`, `snapshot` devolve copia). `error_code` so pode ser um de `GENERATOR_ERROR_CODES` (resto vira `unexpected_error`), `counts` so com `COUNT_KEYS`, `alerts_truncated` so bool/None; em erro `last_success_at` nao muda e `counts` fica None.
- **A5 / criterio 4 do ROADMAP:** `GET /api/vaccines` traz `generator` com exatamente `GENERATOR_KEYS`. Com o Indexer em baixo: `status "error"`, `error_code "indexer_unavailable"`, lista de vaccines igual, `last_success_at` preservado, resposta sem o texto da excecao, caminho nem traceback.
- **Matriz de falhas -> codigos:** cada cenario parte de um ciclo feliz com 2 linhas e confirma que, depois da falha, as 2 linhas continuam identicas (ids e payload) e nenhuma nova aparece.
- **Truncagem (A3), janela/estabilizacao (A2/A4), VAC-05:** cobertos pelos testes (ver abaixo).
- **Verificacao:** `test_vaccine_ingest.py` verde (73+ verificacoes); `run_all_tests.py` 44/44 ficheiros passaram.

### Contrato final de `generator`

| Chave | Valores |
|-------|---------|
| `status` | `never_run` / `ok` / `no_data` / `error` |
| `error_code` | um de `indexer_unavailable`, `ml_model_unavailable`, `attack_outside_alert_window`, `source_unavailable`, `attack_log_unreadable`, `incidents_unavailable`, `store_unavailable`, `unexpected_error`; ou `null` |
| `last_run_at` | ISO-8601 da ultima execucao, ou `null` |
| `last_success_at` | ISO-8601 da ultima execucao `ok`/`no_data`, ou `null` |
| `alerts_truncated` | `true` / `false` / `null` (null em erro e antes da 1.a execucao) |
| `counts` | `{inserted, existing, rejected, pending_settle, outside_window}` ou `null` |

### Matriz de falhas -> codigo

| Falha | `error_code` |
|-------|--------------|
| Wazuh Indexer em baixo | `indexer_unavailable` (de `correlation["error_code"]`) |
| Modelo ML em falta/corrompido | `ml_model_unavailable` |
| Attack log ilegivel (`OSError`, `UnicodeDecodeError`) | `attack_log_unreadable` |
| Base de incidentes em baixo (`sqlite3.Error`) | `incidents_unavailable`, nada gravado |
| Escrita no store falha (`sqlite3.Error`) | `store_unavailable` |
| Qualquer outra excecao | `unexpected_error` |
| Attack log vazio | `status no_data`, sem chamar o Indexer |

## Task Commits

1. **Task 1 (tracer): loop, estado e generator** - `6fbd110` (feat); correcao do teste do 13-01 em `cfa244e` (test)
2. **Task 2: falhas com codigos estaveis, truncagem e janela** - `edffe8d` (feat)

## Deviations from Plan

**1. [Rule 1 - Bug] `test_vaccines_api.py` partia com o bloco `generator`**
- **Found during:** Task 1
- **Issue:** o teste de "reinicio" do 13-01 compara o JSON completo antes/depois do 2.o ciclo; o `generator` (estado em memoria) muda entre as duas leituras.
- **Fix:** a comparacao exclui a chave `generator` (e estado do loop, nao do ficheiro).
- **Files modified:** scripts/test_vaccines_api.py
- **Commit:** `cfa244e`

**2. [Detalhe de implementacao] Em erro, `alerts_truncated` fica None** em vez do `False` que o ciclo do 13-01 devolvia: num ciclo falhado nao houve medicao. Os resultados `ok` continuam a trazer o valor real.

**3. Ledger de commits (#3968):** o ficheiro `gsd-plan-head-before-13-02` nao foi criado antes do 1.o commit; `plan_head_before` e `commits` foram medidos com `git rev-list --count 373d0d8..HEAD` (= 3), onde 373d0d8 era o HEAD no inicio do plano.

Notas de execucao: Procedimento C aplicado a `scripts/main.py` nas duas tarefas (backups `.git/main.py.before-13-02-t1/t2`, patches `.git/main-13-02-t1/t2.patch`, `git apply --cached`; 3 + 2 hunks). `git diff -- scripts/main.py` restante tem 0 ocorrencias de "vaccine": so ficou o trabalho alheio. Linhas CRLF preservadas.

## Known Follow-ups (fora do ambito)

- **A8:** as deteccoes de rede usadas pelo registo vem do buffer em memoria (`network_detection_buffer`), vazio depois de um reinicio; um ataque com `network` esperado (so com `--expect network`) avaliado pela 1.a vez depois de um reinicio pode gerar uma proposta `network` falsa (T-13-13, aceite).
- Com o Indexer em baixo, `_build_attack_registry` faz `logger.exception` a cada ciclo (5 min); e o comportamento ja existente de `/api/attacks`, agora periodico em `backend.log`.
- A3/T-13-12 (gravar com alertas truncados) aceite, a confirmar na revisao.
- Os logs do `main.py` usam o logger `sentrylens.system_monitor` (herdado); as mensagens `Vaccines: ...` aparecem la.

## Known Stubs

None.

## Threat Flags

None - sem superficie nova; o `generator` so leva codigos estaveis (T-13-10 mitigado e testado).

## Self-Check: PASSED

- FOUND: scripts/test_vaccine_ingest.py, scripts/vaccine_ingest.py (VaccineLoopState), scripts/main.py (_vaccine_loop)
- FOUND: commits 6fbd110, cfa244e, edffe8d
- `run_all_tests.py`: 44/44
