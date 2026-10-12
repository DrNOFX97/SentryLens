---
phase: 14-aba-vaccines-testes-e-documenta-o
plan: 01
subsystem: frontend
tags: [vaccines, dashboard, read-only, static-contract, escapeHtml, serve_frontend]

requires:
  - phase: 13-store-e-api-de-leitura
    provides: "GET /api/vaccines e GET /api/vaccines/{id}, envelope {available, reason, total, limit, offset, vaccines, generator}, codigos estaveis 401/404/503"
provides:
  - "Aba Vaccines (vaccines.js): Candidates abre #tab-vaccines e lista GET /api/vaccines em 8 colunas, com X-API-Key, so leitura"
  - "Entrada /vaccines.js na whitelist do serve_frontend.py"
  - "test_vaccines_frontend.py: run_tracer (contrato de campos contra a resposta real da rota) e run_guards (escape, erros por codigo, Sem dados honesto, globais, sem polling, app.js intacto)"
affects: [14-02 filtros/gerador/badges, 14-03 detalhe/cadeia, 14-04 documentacao]

status: complete
plan_head_before: a4bbc7203f5068b831d3d4f4bf6be196462e2856
plan_head_after: 382cb2df626d68907d874639e461f1b2a6d4558f

actuals:
  tokens: 9000
  tasks: 2
  commits: 2

tech-stack:
  added: []
  patterns:
    - "Teste estatico sem browser que valida cada campo lido pelo JS contra as chaves da resposta REAL da rota (TestClient sobre store semeado pelo motor)"
    - "Cada varrimento de guarda e corrido tambem sobre uma violacao sintetica (prova de nao-vacuidade)"
    - "Erros so por codigo estavel: detail do servidor so serve de chave de lookup (VAC_CODE_RE) em VAC_ERROR_TEXT, nunca entra no DOM"

key-files:
  created:
    - vaccines.js
    - scripts/test_vaccines_frontend.py
  modified:
    - index.html
    - scripts/serve_frontend.py
    - scripts/test_serve_frontend.py

key-decisions:
  - "Approved passa de planeado R11 a R14 (leitura literal de D-01); index.html fica sem nenhum marcador R11"
  - "A guarda de interpolacoes so aceita helper vac*( como chamada: um identificador que apenas comeca por vac (vaccine) e dado cru e conta como violacao"

requirements-completed: [VAC-07, VAC-08]

coverage:
  - id: D1
    description: "Candidates abre a aba Vaccines, servida pela whitelist, que lista GET /api/vaccines em 8 colunas lendo so campos da resposta real"
    requirement: VAC-07
    verification:
      - kind: unit
        ref: "scripts/test_vaccines_frontend.py (run_tracer)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Texto dinamico por escapeHtml, erros 401/404/422/502/503/rede com a frase do codigo (nunca Sem dados nem lista vazia), sem polling, app.js intacto"
    requirement: VAC-07
    verification:
      - kind: unit
        ref: "scripts/test_vaccines_frontend.py (run_guards)"
        status: pass
    human_judgment: false
---

# Phase 14 Plan 01: Aba Vaccines (tracer + guardas) Summary

**Aba Vaccines ponta a ponta: 💉 Candidates abre `#tab-vaccines`, `vaccines.js` (servido pela whitelist, carregado depois de `app.js`) lista `GET /api/vaccines` em 8 colunas com `X-API-Key`, com "Sem dados" so para `no_data` e erros com a frase do codigo; blindada por um teste estatico ligado as chaves reais da rota.**

## Performance

- **Duration:** ~20 min
- **Tasks:** 2 (1 tracer + 1 auto)
- **Files modified:** 5 (2 criados, 3 alterados)

## Accomplishments

- Tracer verificado de ponta a ponta: sidebar (Candidates ativo; Validation R12, Approved e Regression R14 planeados), markup `#tab-vaccines`/`#vaccines-panel`/`#vac-table`, `serve_frontend.ALLOWED_FILES["/vaccines.js"]`, `<script src="vaccines.js">` depois de `ml_evaluation.js` (logo depois de `app.js`), e a lista a ler so campos que existem na resposta real de `GET /api/vaccines`.
- `vaccines.js` cumpre D-02 (carrega a cada passagem a ativa via `MutationObserver` + `visibilitychange`, guarda `vacLoading`, sem polling nem WebSocket) e D-08 (`reason: no_data` -> "Sem dados"; lista vazia com filtros -> "Nenhuma vaccine corresponde aos filtros."; 401/404/422/502/503/rede -> `renderPanelError` + linha `vac-error-state`).
- `run_guards` fixa o contrato para os planos 14-02/14-03 que acrescentam ao mesmo ficheiro: globais com prefixo `vac`/`VAC_` e sem colisao com os outros `.js` servidos, cada `${` por `escapeHtml(`/`vac*(`/`VAC_*`, cada `innerHTML =` template/helper/vazio, `.message` so como argumento de `vacErrorText`/`vacRenderError`, "Sem dados" uma so vez, `app.js` sem referencias a vaccines.
- `app.js` nao foi editado (`git diff --quiet 878d8e5 HEAD -- app.js` sai 0).

## Task Commits

1. **Task 1: Tracer** — `009f133` (feat(14-01))
2. **Task 2: Guardas do contrato** — `382cb2d` (test(14-01))

## Files Created/Modified

- `vaccines.js` (novo) — `VAC_VERDICT_LABELS`, `VAC_SENSOR_LABELS`, `VAC_STATE_LABELS`, `VAC_NO_DATA_TEXT`, `VAC_FILTER_EMPTY_TEXT`, `VAC_GENERIC_ERROR`, `VAC_CODE_RE`, `VAC_ERROR_TEXT`; `vacTab`, `vacLoading`, `vacWasActive`, `vacObserver`; `vacIsActive`, `vacCell`, `vacSensors`, `vacDate`, `vacCodeFromResponse`, `vacErrorText`, `vacRequest`, `vacRowsHtml`, `vacRenderList`, `vacRenderError`, `vacRefresh`, `vacOnShow`.
- `scripts/test_vaccines_frontend.py` (novo) — helpers `get`, `served`, `function_body`, `data_accesses`, `make_attack`/`engine_vaccine`, `real_api_keys`, `top_level_decls`, `interpolation_violations`, `innerhtml_violations`, `message_violations`; `run_tracer`, `run_guards`.
- `index.html` — botao `data-tab="vaccines"`, Approved com badge R14, bloco `#tab-vaccines` a seguir a `#tab-attack-library`, `<script src="vaccines.js">`.
- `scripts/serve_frontend.py` — entrada `"/vaccines.js": "vaccines.js"`.
- `scripts/test_serve_frontend.py` — check "/vaccines.js é servido como JavaScript".

## Decisions Made

- Approved passa a R14 (D-01, leitura literal); `index.html` fica sem marcador `data-planned="R11"`.
- Identificadores de ids no HTML criados so os do 14-01 (`#vac-notice`, `#vac-table`, `#vac-body`); filtros e `#vac-generator` ficam para o 14-02 e o detalhe para o 14-03.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Guarda de interpolacao deixava passar `${vaccine.id}`**
- **Found during:** Task 2 (a prova com violacao sintetica falhou, como previsto no plano)
- **Issue:** a regex `vac[A-Za-z0-9_$]*` aceitava qualquer identificador que comece por `vac`, incluindo `vaccine`, o dado cru da API; a guarda nunca teria apanhado uma interpolacao sem escape desse objeto.
- **Fix:** so conta como seguro um helper chamado (`vac...(`), `escapeHtml(` ou uma constante `VAC_...`.
- **Files modified:** `scripts/test_vaccines_frontend.py`
- **Commit:** `382cb2d`

**2. [Rule 3 - Blocking] Criterio de aceitacao desatualizado: `data-tab="soc-team"`**
- **Found during:** Task 1 (antes de editar)
- **Issue:** o plano previa que o trabalho alheio da Equipa SOC estivesse por commitar em `index.html` (Procedimento C) e pedia `git show HEAD:index.html | grep -c 'data-tab="soc-team"'` = 0. Entretanto o commit `a4bbc72` ja o integrou: `git diff --quiet -- index.html` saiu 0 antes de qualquer edicao, por isso `index.html` nao tinha trabalho alheio.
- **Fix:** Procedimento C nao foi necessario; `index.html` editado e commitado normalmente (`git add index.html`), so com as linhas da tarefa (31 linhas no diff). Esse criterio daria agora 1 por `a4bbc72`, nao por este plano.
- **Files modified:** nenhum alem dos previstos.

---

**Total deviations:** 2 auto-tratados (1 bug da guarda, 1 criterio de aceitacao desatualizado). **Impact:** nenhum no comportamento entregue.

## Procedimento C aplicado a `index.html`

Nao foi preciso (ver desvio 2). `.planning/config.json`, `.github/`, `packer/`, `.planning/state.json`, `.planning/milestone.lock` e `scripts/setup-boot-lab-entry.ps1` ficaram intocados; apareceu ainda `scripts/.venv2/` nao seguido (nao criado por este plano, nao commitado).

## Verification

- `test_vaccines_frontend.py` (run_tracer + run_guards): verde, 0 `[FALHOU]`.
- `test_serve_frontend.py`: verde. `test_vaccines_api.py`: verde (rota nao mudou).
- `run_all_tests.py vaccine`: 5/5. `run_all_tests.py` (suite completa): **45/45** ficheiros; `git ls-files 'scripts/test_*.py'` mede **45** (para o 14-04: a contagem "38 ficheiros" do `CLAUDE.md` esta desatualizada).
- `git diff --quiet 878d8e5 HEAD -- app.js` -> 0; nenhum `Co-Authored-By` nos commits do plano.

## Known Stubs

Nenhum. A linha inicial "A carregar..." do `<tbody>` e substituida em cada carregamento.

## Known Follow-ups (fora do ambito)

- O contrato estatico nao executa o JavaScript (D-09); a verificacao visual fica no `<human-check>` do 14-02, junto ao UAT.
- A linha `vac-error-state` so ganha estilo proprio no 14-02 (regras `vac-*` em `style.css`).
- A rota nao emite 502 hoje; a frase `http_502` existe porque o criterio 2 do ROADMAP a exige.
- Mensagem de commit do Task 1/2 sem trailer de coautor (regra do utilizador e do projeto).

## Threat Flags

Nenhum: sem superficie nova alem da entrada `/vaccines.js` na whitelist (T-14-03, mitigada e testada: `/scripts/vaccines.sqlite3` e `/vaccines.sqlite3` continuam 404).

## Self-Check: PASSED

- vaccines.js, scripts/test_vaccines_frontend.py: existem; commits `009f133` e `382cb2d` existem.
