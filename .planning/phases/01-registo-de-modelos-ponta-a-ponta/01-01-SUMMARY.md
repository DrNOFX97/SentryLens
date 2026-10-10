---
phase: 01-registo-de-modelos-ponta-a-ponta
plan: 01
subsystem: api
tags: [fastapi, python-stdlib, pathlib, node-vm, vanilla-js, testing]

# Dependency graph
requires:
  - phase: (nenhuma — primeira fatia do R9)
    provides: backend FastAPI em scripts/ com API key por rota; frontend estático servido por serve_frontend.py; convenção de testes standalone
provides:
  - "scripts/model_registry.py: leitura do registo de modelos em disco (ACTIVE + vN/metadata.json), validação de ids à prova de path traversal, lista fechada de 9 códigos de erro"
  - "GET /api/ml/models (só leitura, dependencies=_REQUIRE_API_KEY) com contrato JSON fixado em SKELETON.md"
  - "ml_models.js: abas reais Models e Evaluation, camada pura testável em node:vm + camada DOM"
  - "test_ml_models_api.py, test_ml_models_ui.py + test_ml_models_ui.cjs (wrapper Python → teste Node)"
  - "Regressão da sidebar e da whitelist em test_serve_frontend.py"
affects: [01-02-integridade-e-adopcao, 01-03-estados-de-ui, 01-04-adocao, fase-3-treino, ml_anomalies]

# Actuals — pares com o `estimate` do plano para calibrar estimativas futuras.
actuals:
  tokens: 14863
  tasks: 3
  commits: 3

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Camada pura (devolve strings, sem DOM/fetch) + camada DOM, com o arranque guardado por `if (typeof document !== \"undefined\")` — permite testar a lógica de UI em node:vm sem browser"
    - "Wrapper .py que gera relatórios reais da rota via TestClient e passa-os ao teste .cjs, porque run_all_tests.py só descobre test_*.py"
    - "Erros de domínio com código estável em lista fechada (ModelRegistryError.code), com `str(exc) == código`"

key-files:
  created:
    - scripts/model_registry.py
    - scripts/test_ml_models_api.py
    - scripts/test_ml_models_ui.py
    - scripts/test_ml_models_ui.cjs
    - ml_models.js
  modified:
    - scripts/main.py
    - scripts/serve_frontend.py
    - scripts/test_serve_frontend.py
    - index.html
    - style.css

key-decisions:
  - "Importa-se em model_registry.py só json/re/pathlib — hashlib, hmac, os e datetime só entram na Fase 2, quando a verificação de integridade os usar"
  - "_root() trata string vazia como pasta por omissão (a linha `ML_MODEL_DIR=` do .env.example faz main.ML_MODEL_DIR valer \"\") — nunca resolve para o cwd"
  - "load_metadata valida a forma dos artifacts (sha256 hex64, size_bytes int ≥ 0) mas NÃO compara o hash com o ficheiro — a verificação real é do 01-02, para não se computarem hashes em cada listagem antes de haver modo de os usar"

patterns-established:
  - "Pattern: id de versão validado com VERSION_ID_RE.fullmatch E (root/id).resolve().parent == root — duas camadas, porque o regex não cobre junctions/symlinks"
  - "Pattern: conteúdo de ACTIVE lido em binário com teto de bytes e decodificado em utf-8-sig; decode falhado = invalid_version_id (fail-closed), nunca se adivinha um id"
  - "Pattern: mesmo código de erro dá sempre o mesmo estado HTTP (registry_unavailable = 503 em qualquer ramo), porque a lista de códigos é fechada"
  - "Pattern: numa rota, a mensagem de uma exceção inesperada fica só no log (logger.exception); o detail leva sempre um código"

requirements-completed: [REG-01, SEC-02, API-01, API-02, UI-01, UI-03]

coverage:
  - id: D1
    description: "GET /api/ml/models devolve 200 com active, active_error, loaded, total e versions; cada versão traz os metadados lidos de vN/metadata.json e uma chave evaluation que vale null"
    requirement: API-01
    verification:
      - kind: integration
        ref: "scripts/test_ml_models_api.py#(d) v1 ativa -> 200"
        status: pass
      - kind: integration
        ref: "scripts/test_ml_models_api.py#(e) versões por número decrescente"
        status: pass
    human_judgment: false
  - id: D2
    description: "A rota exige X-API-Key: sem header ou com header errado devolve 401"
    requirement: SEC-02
    verification:
      - kind: integration
        ref: "scripts/test_ml_models_api.py#(a) sem X-API-Key -> 401"
        status: pass
    human_judgment: false
  - id: D3
    description: "models/ vazio ou inexistente devolve 200 com active null, versions [] e total 0"
    requirement: REG-01
    verification:
      - kind: integration
        ref: "scripts/test_ml_models_api.py#(b)/(c) relatório vazio"
        status: pass
    human_judgment: false
  - id: D4
    description: "Um ACTIVE com ../x, em UTF-16, com mais de 64 bytes ou a apontar para uma pasta inexistente nunca resolve fora de models/: active fica null e active_error é um código estável"
    requirement: SEC-02
    verification:
      - kind: integration
        ref: "scripts/test_ml_models_api.py#(g) ACTIVE inválido"
        status: pass
    human_judgment: false
  - id: D5
    description: "Uma versão com metadata.json em falta ou inválido aparece na lista com status/error_code estável e não derruba a resposta"
    requirement: REG-01
    verification:
      - kind: integration
        ref: "scripts/test_ml_models_api.py#(f) versões com problema não derrubam a resposta"
        status: pass
    human_judgment: false
  - id: D6
    description: "Nenhuma resposta contém caminho temporário nem Traceback; registry_unavailable dá 503 tanto vindo de um ModelRegistryError como de uma exceção inesperada"
    requirement: API-02
    verification:
      - kind: integration
        ref: "scripts/test_ml_models_api.py#(h)/(i)"
        status: pass
    human_judgment: false
  - id: D7
    description: "ml_models.js carrega sem DOM e os helpers traduzem cada código de D-06 para uma mensagem PT, nunca o código nem o detail em bruto"
    requirement: API-02
    verification:
      - kind: automated_ui
        ref: "scripts/test_ml_models_ui.cjs#mlmErrorText / mlmCodeFromResponse"
        status: pass
      - kind: integration
        ref: "scripts/test_ml_models_ui.py (wrapper que invoca o .cjs)"
        status: pass
    human_judgment: false
  - id: D8
    description: "A resposta real de GET /api/ml/models (registo temporário com v1 ativa) é renderizada pelos helpers reais de ml_models.js numa linha com v1, o badge 'ativa' e 'Sem avaliação'"
    requirement: UI-01
    verification:
      - kind: automated_ui
        ref: "scripts/test_ml_models_ui.cjs#mlmBuildModelsRows sobre report_v1.json"
        status: pass
    human_judgment: false
  - id: D9
    description: "Models e Evaluation deixam de ser planeados, os dois painéis são abas reais e um único pedido alimenta as duas"
    requirement: UI-03
    verification:
      - kind: unit
        ref: "scripts/test_serve_frontend.py#check_static_frontend"
        status: pass
      - kind: automated_ui
        ref: "scripts/test_ml_models_ui.cjs#mlmBuildEvalRows"
        status: pass
    human_judgment: false
  - id: D10
    description: "As duas abas renderizam e navegam no browser real (aspeto, clique, botão Atualizar)"
    requirement: UI-01
    verification: []
    human_judgment: true
    rationale: "node --check e os testes estáticos provam o HTML/CSS/JS gerado e a lógica dos helpers, mas não provam o clique na sidebar, a abertura do painel nem o aspeto dos badges. Exige o <human-check> da Task 3 (start-backend.ps1 + start-frontend.ps1, http://localhost:5500/index.html), que não foi executado neste ambiente.

# Metrics
duration: 62min
completed: 2026-10-10
status: complete
---

# Phase 1 Plan 01: Registo de modelos ponta a ponta — Summary

**Registo de modelos ML em disco lido por um módulo de domínio stdlib-puro, exposto por `GET /api/ml/models` autenticado por API key, com as abas Models e Evaluation do dashboard a mostrarem as versões e o estado honesto "Sem avaliação".**

## Performance

- **Duration:** ~62 min (inclui a recuperação do `scripts/.venv`, que estava inutilizável)
- **Started:** 2026-10-10T12:35:00+01:00
- **Completed:** 2026-10-10T13:37:00+01:00
- **Tasks:** 3 (Task 1 e Task 2 tracer, Task 3 expansão)
- **Files modified:** 10 (5 criados, 5 alterados) — 1324 linhas, +1322/−2

## Accomplishments

- **Caminho único provado ponta a ponta por teste automático:** registo temporário em disco (`models/v1/` + `ACTIVE`) → `GET /api/ml/models` com X-API-Key → JSON real da rota → linha `v1 / ativa / Sem avaliação` desenhada pelos helpers reais de `ml_models.js` num contexto `node:vm`. É o que o plano chama de tracer (D-07).
- **Contrato JSON do registo fixado e respeitado** (`SKELETON.md`): `active`, `active_error`, `loaded`, `total`, `versions[]`, com `evaluation: null` em todas as entradas e `metadata` projetado só para `METADATA_PUBLIC_KEYS` + os nomes constantes de artefacto.
- **Nada de caminho traversal nem fuga de informação:** ids validados com `fullmatch` **e** com `candidate.parent == root` depois de `resolve()`; ACTIVE lido em binário com teto de 64 bytes e decodificado em `utf-8-sig` (UTF-16 do PowerShell 5.1 falha em vez de ser adivinhado); nenhuma resposta contém caminho nem Traceback.
- **Frontend testável sem browser:** `ml_models.js` separa uma camada pura (devolve strings, não toca em DOM nem em fetch) da camada DOM, e só arranca com `if (typeof document !== "undefined")`. O teste Node carrega o ficheiro real sem DOM — o que prova, por construção, que nenhuma linha de topo toca em `document`.
- **UI-03 fechada:** Models e Evaluation deixaram de ser planeados (nenhum `data-planned="R9"` no index.html), Training continua R10, e `test_serve_frontend.py` passou a proteger a whitelist, a sidebar, o prefixo `mlm`/`MLM_` e a presença dos 9 códigos de D-06 no mapeamento PT.

## Task Commits

Cada task foi commitada atomicamente:

1. **Task 1: Tracer 1/2 (backend)** — registo em disco → `model_registry.py` → `GET /api/ml/models` com API key → `ml_models.js` na whitelist — `36724f6` (feat)
2. **Task 2: Tracer 2/2 (dashboard)** — aba Models a consumir a rota, com verificação ponta a ponta do caminho único — `cbbefd6` (feat)
3. **Task 3: Expansão** — aba Evaluation com "Sem avaliação", sidebar sem marcas de planeado, testes de regressão do frontend — `b9155af` (feat)

_Note: Tasks 2 e 3 têm `tdd="true"` — o teste (.py + .cjs) foi escrito e corrido primeiro, a falhar (`ReferenceError: mlmBuildEvalRows is not defined`, e antes disso `ml_models.js` inexistente), e só depois implementado._

## Files Created/Modified

- `scripts/model_registry.py` — **novo.** Domínio puro (só `json`, `re`, `pathlib`): `ModelRegistryError` com código da lista fechada, `_root`, `validate_version_id`, `resolve_version_dir`, `read_active`, `_active_state`, `load_metadata`, `_public_metadata`, `build_models_report`.
- `scripts/main.py` — `import model_registry` no bloco de imports simples e a rota `GET /api/ml/models` logo a seguir a `get_ml_anomalies`, com `dependencies=_REQUIRE_API_KEY` no próprio decorador e `registry_unavailable` sempre 503.
- `scripts/test_ml_models_api.py` — **novo.** 66 casos standalone sobre a rota (401 sem/ com key errada, pasta inexistente, pasta vazia, v1+v2 ordenadas, versões com metadata em falta/inválido, ACTIVE `../x`/`v9`/UTF-16/>64 bytes, ausência de caminhos e Traceback, mesmo código → mesmo estado).
- `ml_models.js` — **novo.** `MLM_ERROR_TEXT` (10 mensagens PT acionáveis), `MLM_GENERIC_ERROR`, `MLM_CODE_RE`, `mlmErrorText`, `mlmCodeFromResponse`, `mlmCell`, `mlmBuildModelsRows`, `mlmModelsNoticeText`, `mlmBuildEvalRows`, e a camada DOM (`mlmRequest`, `mlmRenderModels`, `mlmRenderEvaluation`, `mlmRefresh`, `mlmOnTabChange`, `mlmInit`).
- `scripts/test_ml_models_ui.cjs` — **novo.** Teste Node em `node:vm` dos helpers puros, com fixtures reais (`report_v1.json`, `report_empty.json`) e fixtures inline de XSS/`active_error`.
- `scripts/test_ml_models_ui.py` — **novo.** Wrapper descoberto pelo `run_all_tests.py`: monta o registo temporário, chama a rota via TestClient, escreve os dois JSON e corre o `.cjs`. Sem `node` no PATH, falha com mensagem explícita.
- `scripts/serve_frontend.py` — `"/ml_models.js": "ml_models.js"` na whitelist, logo a seguir a `/metrics.js`. Nada mais (a pasta `models/` continua por servir).
- `scripts/test_serve_frontend.py` — check de `/ml_models.js` servido como JavaScript e nova função `check_static_frontend()` com as verificações estáticas do index.html e da forma de `ml_models.js`.
- `index.html` — botão Models e botão Evaluation com `data-tab`, painéis `#tab-ml-models` e `#tab-ml-evaluation`, e `<script src="ml_models.js">` depois de `metrics.js`.
- `style.css` — `.mlm-badge` e as variantes `-active`, `-adopted`, `-legacy`, `-error`, com a paleta de `.alib-risk`.

## Decisions Made

- **Importações de `model_registry.py`:** o plano listava `hashlib, hmac, json, os, re, datetime, pathlib` como stdlib admissível; só foram importados `json`, `re` e `pathlib`. `hashlib`/`hmac` são do 01-02 (verificação de hashes) e `os`/`datetime` do 01-03 (adopt) — importar agora seria código morto. A restrição que o plano quer cumprir (só stdlib, nunca `joblib`/`ml_anomalies`/`fastapi`) fica satisfeita na mesma.
- **`load_metadata` valida a *forma*, não compara o hash com o ficheiro.** O plano pedia que um `sha256` sem `fullmatch` de `SHA256_RE` fosse `metadata_invalid` — isso está implementado. A comparação com o SHA-256 real do `.pkl` é do 01-02 (SEC-01), e computá-la em cada listagem antes de existir forma de a usar só custaria CPU a cada pedido. `status` só ganha `hash_mismatch`/`artifact_missing` na Fase 2.
- **Texto exato das mensagens PT** e o nome de dois helpers privados (`_root`, `_public_metadata`) foram escolha do executor dentro do que o plano delegava em "Claude's Discretion".
- **Um teste mais forte do que o mínimo em dois pontos** do `test_ml_models_ui.cjs`: as mensagens de D-06 têm de ser todas distintas entre si (não só diferentes de `MLM_GENERIC_ERROR`), e `mlmErrorText("constructor")` tem de dar o genérico — é o que garante o `hasOwnProperty`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Regra 1 — Blockers] `scripts/.venv` estava inutilizável: tinha de ser recriado antes de correr seja o que for**
- **Found during:** pré-condição da Task 1
- **Issue:** o venv do repo foi criado a partir de `C:\ProgramData\anaconda3\python.exe`, que já não existe nesta máquina — `scripts\.venv\Scripts\python.exe` respondia `No Python at '"C:\ProgramData\anaconda3\python.exe"'` e nada corria.
- **Fix:** recriado com o mesmo `requirements.txt` (`uv venv --clear --python 3.12` + `uv pip install -r requirements.txt`, CPython 3.12.14, uv 0.12.8 já no PATH). O plano previa isto na pré-condição da Task 1; `scripts/.venv/` está no `.gitignore`, por isso não há diff no repositório.
- **Files modified:** nenhum no repositório (só `scripts/.venv/`)
- **Verification:** `run_all_tests.py` verde 33/33 antes de qualquer alteração (baseline), depois 35/35.
- **Committed in:** não aplicável (fora do repositório)

**2. [Regra 5 — Correcção] Uma edição consumiu por engano o decorador `@app.get("/api/redblue/metrics", ...)`**
- **Found during:** Task 1, logo a seguir ao primeiro `run_all_tests.py` (o plano manda correr a suite por task)
- **Issue:** `get_redblue_metrics` deixou de estar registada e passou a ser uma função aninhada inalcançável dentro de `get_ml_models`; `/api/redblue/metrics` devolvia 404 e `test_redblue.py` rebentou com `KeyError: 'overall'`.
- **Fix:** reposto o decorador e as duas linhas em branco antes dele.
- **Files modified:** `scripts/main.py`
- **Verification:** `test_redblue.py` isolado exit 0; suite completa 34/34; `git diff main.py` mostra só as 27 linhas da rota nova.
- **Committed in:** `36724f6` (parte do commit da Task 1)

---

**Total deviations:** 2 auto-fixed (1 blocking de ambiente, 1 correcção)
**Impact on plan:** ambos necessários para conseguir correr a verificação; zero scope creep — nada foi acrescentado ao âmbito do plano.

## Issues Encountered

- **Suite completa a exceder o timeout de 300 s por ficheiro, na primeira execução.** `test_attack_library.py` demorou 188 s sozinho e rebentou o `TimeoutExpired` do `run_all_tests.py`. Causa: arranque a frio (OneDrive + antivírus a trazer as páginas do venv para memória), não o código — as execuções seguintes desse mesmo ficheiro demoram 1,2 s e a suite completa passou a fazer 35 s. Nenhum ficheiro do repo foi alterado por isto; fica registado porque volta a acontecer numa máquina nova.
- **`model_registry.py` tinha de ser lido sem `hmac`/`hashlib`** para o `build_models_report` da listagem não fazer trabalho da Fase 2 (ver Decisions Made).

## Commands Run (resultados reais)

| Comando | Resultado |
|---|---|
| `cd scripts && .venv/Scripts/python test_ml_models_api.py` | **exit 0**, 66 checks `[OK]`, zero `[FALHOU]`, `Todos os testes passaram` |
| `cd scripts && .venv/Scripts/python test_ml_models_ui.py` | **exit 0**, 2 checks do wrapper + 65 checks Node `[OK]`, `Todos os testes Node passaram` / `Todos os testes passaram` |
| `cd scripts && .venv/Scripts/python test_serve_frontend.py` | **exit 0**, 44 checks no total (30 pré-existentes + 14 novos), inclui `/ml_models.js é servido como JavaScript` e as verificações estáticas novas, `Todos os testes passaram` |
| `cd scripts && .venv/Scripts/python run_all_tests.py` | **exit 0**, `35/35 ficheiros passaram` (33 pré-existentes + `test_ml_models_api.py` + `test_ml_models_ui.py`) |
| `node --check ml_models.js` | **exit 0** (Node v24.14.1) |
| AST: `model_registry.py` não importa joblib/ml_anomalies/fastapi | **exit 0**; imports reais = `['json', 'pathlib', 're']` |
| `serve_frontend.ALLOWED_FILES['/ml_models.js'] == 'ml_models.js'` | **exit 0** |
| `grep -c '@app.get("/api/ml/models", dependencies=_REQUIRE_API_KEY)' scripts/main.py` | **1** |
| `grep -c 'VERSION_ID_RE.fullmatch' scripts/model_registry.py` | **3** |
| prefixo `mlm`/`MLM_` em todas as declarações de topo de `ml_models.js` | **exit 0**, lista de nomes fora do prefixo = `[]` |
| `grep -c 'data-planned="R9"' index.html` | **0** |
| `ml_evaluation.js` na raiz | não existe (D-05 respeitada) |
| baseline antes de qualquer alteração: `run_all_tests.py` | 33/33 (a mais lenta, 188 s, foi o arranque a frio descrito acima) |

**Verificação humana por fazer:** o `<human-check>` da Task 3 (abrir o dashboard no browser real e clicar em Models e Evaluation) **não foi executado** — este ambiente não arrancou o backend nem o frontend. É o único ponto do plano não verificado aqui, e está declarado como tal em `coverage.D10`.

## User Setup Required

None - no external service configuration required. (Nenhum serviço novo, nenhuma variável de ambiente nova: a rota lê o `ML_MODEL_DIR` que já existia.)

## Next Phase Readiness

- **01-02 (integridade e adopt)** tem o contrato e as costuras: `_active_state()` já é a função única que decide o que está ativo (o ramo do legado entra aí), `load_metadata` já valida a forma dos `artifacts` que o `read_verified_bytes` vai comparar, e `ModelRegistryError` já tem `hash_mismatch` e `artifact_missing` na lista fechada sem precisar de código novo. `status` de uma versão ainda só pode ser `ok`/`metadata_*`/`invalid_version_id`/`active_not_found`/`registry_unavailable` até lá.
- **Fase 3 (treino)** tem `_root()`, `ARTIFACT_FILES` e `METADATA_PUBLIC_KEYS` como a superfície a reusar na escrita; a pasta temporária `vN.tmp-*` já fica invisível à listagem por não casar `VERSION_ID_RE`.
- **Sem dívida técnica deixada por este plano.** O `loaded` é sempre `null` nesta fase (a rota passa-o por omissão) — o 01-02 liga-o a `ml_anomalies` quando `_active_state` ganhar o ramo do legado.
- **Nota para quem pegar no plano 01-03:** `MLM_ERROR_TEXT` já contém mensagens para os 4 códigos que só a Fase 2/3 produzem (`artifact_missing`, `hash_mismatch`, `already_adopted`, `no_legacy_model`) e o teste de `test_serve_frontend.py` passa a exigir que continuem lá.

---
*Phase: 01-registo-de-modelos-ponta-a-ponta*
*Completed: 2026-10-10*