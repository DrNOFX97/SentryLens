---
phase: 13-store-e-api-de-leitura
verified: 2026-10-12T09:10:00Z
status: passed
score: 4/4 must-haves verified
covered_files:
  - scripts/main.py
  - scripts/test_vaccine_ingest.py
  - scripts/test_vaccine_store.py
  - scripts/test_vaccines_api.py
  - scripts/vaccine_ingest.py
  - scripts/vaccine_store.py
covered_digest: "v2:sha256:d6f785e1043057531ebb92239d8d5240ec813c96c1cda720b44c2285dd0cb862"
behavior_unverified: 0
overrides_applied: 0
---

# Phase 13: Store e API de leitura Verification Report

**Phase Goal:** O analista consulta por HTTP as vaccines propostas, que sobrevivem a um reinicio do backend sem duplicados e nunca mudam de estado.
**Verified:** 2026-10-12
**Status:** passed
**Re-verification:** No (initial verification)

## Goal Achievement

### Observable Truths (ROADMAP success criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Vaccines persistem num store escrito so pelo backend, todas `proposed`; reinicio devolve a mesma lista; reprocessar nao acrescenta linhas | VERIFIED | `scripts/vaccine_store.py`: SQLite com `CHECK (state='proposed')`, `CHECK (json_valid(payload))`, triggers que recusam DELETE e UPDATE de qualquer coluna exceto `superseded_by`; escrita `ON CONFLICT(id) DO NOTHING`. Unica escrita: `upsert_batch`, chamada so por `vaccine_ingest.persist_vaccines` <- `main._run_vaccine_cycle` (loop de background, `@app.on_event("startup")`). Sonda propria: 2o `upsert_batch` do mesmo id -> `{inserted:0, existing:1}`; INSERT com state='accepted', UPDATE state/payload e DELETE -> `IntegrityError` (todos bloqueados). `test_vaccines_api.py` cobre ciclo real -> reprocessar -> nova instancia sobre o mesmo ficheiro com JSON identico (linhas 185-195). |
| 2 | `GET /api/vaccines` (API key) lista, vazia com 200 sem amostra, 401 sem key; `GET /api/vaccines/{id}` detalhe; id inexistente 404 `entry_not_found` | VERIFIED | `main.py` 1940-1985. Sonda propria com TestClient: sem key 401/401; com key lista 200 `available:false, reason:no_data`, e o ficheiro NAO e criado pelo GET (leitura `mode=ro`); id inexistente -> `{'detail': 'entry_not_found'}` 404. Detalhe devolve payload do motor (regra + origem) + `state/superseded_by/created_at`. |
| 3 | Nao existe rota de escrita; POST/PUT/PATCH/DELETE nao altera nada; estado so `proposed` | VERIFIED | Apenas dois `@app.get` para `/api/vaccines*`. Sonda propria: POST/PUT/PATCH/DELETE nas duas rotas -> 405. `test_vaccines_api.py` 333-355 repete a garantia e verifica que o store nao muda. Estado `proposed` imposto pelo CHECK/trigger no proprio ficheiro. |
| 4 | Falhas de leitura chegam como codigos estaveis, sem excecao/traceback/caminho; API key aplicada individualmente por rota | VERIFIED | Ambas as rotas: `dependencies=_REQUIRE_API_KEY`; `sqlite3.Error/ValueError` -> `HTTPException(503, "store_unavailable")` (detalhe so no log). Falhas do gerador (Indexer, attack log, store, ML, incidentes) vao para `vaccine_loop_state` apenas como codigos de `GENERATOR_ERROR_CODES` (`indexer_unavailable`, `store_unavailable`, ...), expostos em `generator` na listagem. `test_vaccines_api.py` verifica "sem fuga" (sem caminho nem `.sqlite3`) para store corrompido (ficheiro nao-SQLite) e ValueError, nas duas rotas. |

**Score:** 4/4 truths verified.

### Required Artifacts

| Artifact | Status | Details |
|----------|--------|---------|
| `scripts/vaccine_store.py` (185 linhas) | VERIFIED | Substantivo, importado em `main.py` (`VaccineStore`, `resolve_db_path`), dados fluem (testes com store real). |
| `scripts/vaccine_ingest.py` (139 linhas) | VERIFIED | `persist_vaccines` valida com `validate_vaccine` antes de gravar; `select_attack_ids` (janela + assentamento); `VaccineLoopState` guarda so codigos estaveis. Usado por `main.py`. |
| `main.py` rotas e loop de vaccines | VERIFIED | Codigo de vaccines ja commitado (`git diff main.py` sem linhas de vaccine; as alteracoes nao commitadas sao de outro ambito, ignoradas). |
| Testes `test_vaccine_store.py`, `test_vaccine_ingest.py`, `test_vaccines_api.py` | VERIFIED | Os tres passam; fazem parte do `run_all_tests.py`. |

### Key Link Verification

| From | To | Status | Details |
|------|----|--------|---------|
| startup -> `_vaccine_loop` -> `_run_vaccine_cycle` | `persist_vaccines` -> `VaccineStore.upsert_batch` | WIRED | Cadeia lida em `main.py` 1874-1937. |
| `_vaccine_cycle_body` | `_build_attack_registry` + `build_vaccine_candidates` | WIRED | Reutiliza o motor da Phase 12; recusa gravar com `source_unavailable` / `incidents_unavailable`. |
| `GET /api/vaccines*` | `vaccine_store.list_vaccines/get_vaccine` (so-leitura) | WIRED | Via `run_in_threadpool`, ligacao `mode=ro`. |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| 401 sem key, 200 vazio, 404 estavel, 405 em escrita | script proprio com TestClient | 401/401, 200 no_data, `entry_not_found`, 405 x8 | PASS |
| Store recusa estado != proposed, DELETE, UPDATE de payload; idempotencia | script proprio sobre o SQLite | todos bloqueados por `IntegrityError`; reinserir -> existing | PASS |
| Suite completa | `python run_all_tests.py` (venv) | 44/44 ficheiros passaram (incl. 4 de vaccines) | PASS |

### Requirements Coverage

| Requirement | Description | Status | Evidence |
|-------------|-------------|--------|----------|
| VAC-05 | Store escrito so pelo backend, `proposed`, sem perda/duplicado no reinicio | SATISFIED | Truth 1 |
| VAC-06 | GET lista/detalhe, API key por rota, 404 `entry_not_found`, erros sem excecao/caminhos | SATISFIED | Truths 2, 3, 4 |

Sem requisitos orfaos: REQUIREMENTS.md mapeia apenas VAC-05 e VAC-06 a Phase 13, ambos reclamados pelos planos.

### Anti-Patterns Found

Nenhum `TBD/FIXME/XXX/TODO/HACK` nos ficheiros da fase. Nenhum stub; nenhum retorno estatico.

### Notas (informativas, nao bloqueantes)

- Num primeiro `run_all_tests.py`, `test_attack_targets.py` mostrou uma falha pontual em "CLI: --self-check continua a passar"; numa segunda corrida completa passou (44/44). Teste da Phase anterior (R5), nao relacionado com vaccines; aparenta ser intermitente sob execucao paralela. Vale acompanhar.
- Um id mal formado em `/api/vaccines/{id}` (fora de `VACCINE_ID_RE`) devolve 422 do FastAPI, coerente com as restantes rotas; "id inexistente" (bem formado) da 404 `entry_not_found` como exigido.

### Human Verification Required

Nenhuma. Fase de backend sem superficie visual (UI chega na Phase 14).

### Gaps Summary

Sem gaps. O objetivo da fase foi alcancado no codigo: store imutavel por esquema, escrita so pelo ciclo de background, leitura so por GET com API key por rota e erros como codigos estaveis.

---

_Verified: 2026-10-12_
_Verifier: Claude (gsd-verifier)_
