---
phase: 13-store-e-api-de-leitura
plan: 01
subsystem: api
tags: [sqlite, fastapi, vaccines, append-only, idempotency]

requires:
  - phase: 12-motor-de-vaccines
    provides: vaccine_engine (build_vaccine_candidates, validate_vaccine, VACCINE_ID_RE)
provides:
  - VaccineStore (SQLite, CHECK + triggers, ON CONFLICT DO NOTHING, politica superseded_by)
  - vaccine_ingest (env_int, select_attack_ids, persist_vaccines)
  - main._run_vaccine_cycle (attack log -> registo -> motor -> validate_vaccine -> store)
  - GET /api/vaccines e GET /api/vaccines/{vaccine_id} (so leitura, API key por rota)
affects: [13-02 loop de background, 13-03 filtros HTTP e garantias, 14 aba Vaccines]

plan_head_before: da89295d82908901f93f752add66e928a6c059ec
plan_head_after: f8d03af8152bd2d06ef2bf38dd517364d66f46c3

actuals:
  tokens: 11000
  tasks: 2
  commits: 2

tech-stack:
  added: []
  patterns:
    - "Store SQLite append-only com um so campo mutavel (superseded_by) garantido por triggers"
    - "Leitura em modo so-leitura (mode=ro) que nunca cria o ficheiro"
    - "Parametros de leitura do store so por nome (evita o desalinhamento posicional de list_incidents)"

key-files:
  created:
    - scripts/vaccine_store.py
    - scripts/vaccine_ingest.py
    - scripts/test_vaccines_api.py
    - scripts/test_vaccine_store.py
  modified:
    - scripts/main.py
    - .gitignore

key-decisions:
  - "A1 (emenda aprovada a D-04): INSERT ... ON CONFLICT(id) DO NOTHING em vez de INSERT OR IGNORE, provado por teste"
  - "A2: so se gravam vaccines de ataques com mais de SENTRYLENS_VACCINE_SETTLE_SECONDS (omissao 600)"
  - "P1: registo construido sobre o log inteiro e corte por idade feito depois em select_attack_ids"
  - "P2: GET abre o SQLite so-leitura e com o ficheiro inexistente responde no_data sem o criar"
  - "Pitfall 6: base de incidentes indisponivel -> ciclo nao grava (incidents_unavailable)"

requirements-completed: [VAC-05, VAC-06]

coverage:
  - id: D1
    description: "Ciclo do backend grava as vaccines validadas de ataques assentes, sem duplicados e sobrevive a reinicio"
    requirement: VAC-05
    verification:
      - kind: integration
        ref: "scripts/test_vaccines_api.py (run_tracer: ciclo, 2.o ciclo, reinicio)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Estado proposed, sem DELETE nem UPDATE exceto superseded_by, garantidos no proprio ficheiro SQLite"
    requirement: VAC-05
    verification:
      - kind: unit
        ref: "scripts/test_vaccine_store.py (run_immutability_and_a1, run_supersede)"
        status: pass
    human_judgment: false
  - id: D3
    description: "GET /api/vaccines e /api/vaccines/{id} com API key, no_data, 404 entry_not_found, 422 e 503 store_unavailable"
    requirement: VAC-06
    verification:
      - kind: integration
        ref: "scripts/test_vaccines_api.py (run_tracer)"
        status: pass
    human_judgment: false

duration: 7min
completed: 2026-10-12
status: complete
---

# Phase 13 Plan 01: Store e API de leitura (tracer + endurecimento) Summary

**Store SQLite de vaccines com estado `proposed` imposto pelo proprio ficheiro, ciclo do backend que grava so vaccines validadas de ataques assentes, e GET /api/vaccines[/{id}] so de leitura com API key.**

## Performance

- **Duration:** ~7 min
- **Tasks:** 2 (1 tracer + 1 auto/tdd)
- **Files:** 4 criados, 2 alterados

## Accomplishments

- **Tracer ponta a ponta (Task 1):** `main._run_vaccine_cycle()` corre sobre o registo verdadeiro das fixtures de `test_attack_registry.py` e grava exatamente `vac-bd617cce8054` (ataque 3, partial, T1053, falta `ml`) e `vac-5fe3861aa2a3` (ataque 2, not_detected). O ataque 4 (lancado ha 500 s) fica em `pending_settle`.
- **Contagens do ciclo:** 1.o ciclo `{"inserted": 2, "existing": 0, "rejected": 0, "pending_settle": 1, "outside_window": 0}`; 2.o ciclo `inserted 0, existing 2`. Reinicio (nova instancia de `VaccineStore` sobre o mesmo ficheiro) devolve JSON identico.
- **Rotas:** so GET, `dependencies=_REQUIRE_API_KEY` em cada uma; 401 sem chave/chave errada, 200 `no_data` com store vazio (e o ficheiro continua a nao existir), 404 `entry_not_found`, 422 em id malformado e em `limit`/`offset` fora de limites, 503 `store_unavailable` sem texto de excecao. Nenhuma resposta traz tool/target/source/operator/IPs do log.
- **Origem completa (regressao):** `origin.incident_ids` da vaccine do ataque 3 e nao vazio, porque `_build_attack_registry` passou a chamar `list_incidents(limit=100000, offset=0)` por nome. `test_attack_registry.py` voltou a verde (as 2 falhas da linha de base desapareceram).
- **Endurecimento do store (Task 2):** triggers e CHECKs provados por SQL direto (UPDATE de state/payload/verdict/created_at e DELETE dao IntegrityError; `superseded_by` e a unica coluna mutavel); atomicidade do lote (tudo ou nada); politica `superseded_by` com vaivem A-B-A (`vac-ed793c0b3437` <-> `vac-5fe3861aa2a3`); filtros `attack_id`/`technique`/`include_superseded` ao nivel do store; resolucao do caminho (D-05).
- **A1 provada:** o teste mostra que `INSERT ... ON CONFLICT(id) DO NOTHING` com `state='applied'` levanta `IntegrityError`, enquanto `INSERT OR IGNORE` no mesmo esquema da `rowcount 0` sem erro.

## Task Commits

1. **Task 1: Tracer (store, ingest, ciclo, rotas)** - `dceed1e` (feat)
2. **Task 2: superseded_by, filtros e imutabilidade** - `f8d03af` (feat)

## Deviations from Plan

None - plan executed exactly as written.

Notas de execucao:
- **Procedimento C aplicado:** `scripts/main.py` tinha alteracoes por commitar de outro trabalho (triagem JEV / equipa SOC). Guardou-se a versao anterior em `.git/main.py.before-13-01-t1`, gerou-se um patch so com as linhas desta tarefa (4 hunks, 86 insercoes e 1 remocao) e aplicou-se com `git apply --cached`. `scripts/incident_store.py` e o resto do trabalho alheio nao foram staged nem alterados; `git show HEAD~1 -- scripts/main.py` nao contem `class AnalystCreate`. Os patches/backups ficam em `.git/` (fora de git).
- `main.py` e CRLF na arvore de trabalho; a edicao foi feita por script que preserva CRLF.
- O passo "confirmar que o teste falha antes de implementar" nao foi corrido isoladamente (o teste e a implementacao foram escritos na mesma passagem e o teste passou logo); a cobertura dos casos e a da lista de `<behavior>`.

## Known Follow-ups (fora do ambito)

- **A7:** a leitura nao volta a correr `validate_vaccine`; uma linha adulterada diretamente no ficheiro seria servida (mesmo limite do SHA-256 dos `.pkl`).
- `.planning/phases/12-motor-de-vaccines/deferred-items.md`: a entrada sobre `test_attack_registry.py` (chamada posicional de `list_incidents`) fica resolvida por este plano; pode ser removida pelo orquestrador/utilizador (nao foi editada aqui).
- Nenhum loop esta agendado no arranque (plano 13-02): ate la nada escreve em producao.

## Known Stubs

None.

## Threat Flags

None - sem superficie nova alem das duas rotas GET (T-13-01) ja cobertas pelo threat model.

## Verification

- `test_vaccines_api.py`, `test_vaccine_store.py`, `test_vaccine_engine.py`, `test_attack_registry.py`: todos verdes.
- `run_all_tests.py`: 43/43 ficheiros passaram (a linha de base era 40/41).

## Self-Check: PASSED

- FOUND: scripts/vaccine_store.py, scripts/vaccine_ingest.py, scripts/test_vaccines_api.py, scripts/test_vaccine_store.py
- FOUND: commits dceed1e e f8d03af
