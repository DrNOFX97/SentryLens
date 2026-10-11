---
phase: 01-registo-de-modelos-ponta-a-ponta
plan: 02
subsystem: api
tags: [python-stdlib, hashlib, hmac, joblib, pickle, fastapi, sha256, testing]

# Dependency graph
requires:
  - phase: (nenhuma — continua a primeira fatia do R9)
    provides: "scripts/model_registry.py com o registo lido de disco (ACTIVE + vN/metadata.json), lista fechada de 9 códigos de erro e contrato JSON fixado no SKELETON.md"
    plan: "01-01 (36724f6, cbbefd6, b9155af, 6703532)"
  - phase: (nenhuma)
    provides: "ml_anomalies.load_model como único ponto com joblib.load; convenção de testes standalone"
provides:
  - "scripts/model_registry.py: sha256_file (streaming), detect_legacy, _verify_artifacts, read_verified_bytes, ArtifactSource, resolve_active_artifacts, NO_MODEL_MESSAGE"
  - "SEC-01 fechado: nada não verificado chega a joblib.load, e o hash é calculado sobre os mesmos bytes que são desserializados (sem TOCTOU)"
  - "REG-02: o modelo legado (.pkl soltos) entra no relatório como 'legado, sem metadados' e continua a carregar sem verificação até ser adotado"
  - "scripts/ml_anomalies.py: load_model delega no registo na cache miss, reset_cache() e loaded_version()"
  - "main.py: /api/ml-anomalies e /api/redblue/metrics devolvem 503 com detail=<código> quando o registo recusa; GET /api/ml/models expõe loaded (D-02)"
  - "scripts/test_model_registry.py (novo, 128 checks) e scripts/test_ml_models_api.py alargado com a secção 'carregamento verificado' (44 checks novos)"
affects: [01-03-estados-de-ui, 01-04-adocao, fase-2-avalicao, fase-3-treino, ml_anomalies, main]

# Actuals — pares com o `estimate` do plano para calibrar estimativas futuras.
actuals:
  tokens: 17772
  tasks: 2
  commits: 2

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Verificar e usar os mesmos bytes: ler uma vez, hashear o buffer, devolver o mesmo buffer — `joblib.load(io.BytesIO(data))` sem segundo open (T-01-08)"
    - "Erro de domínio com código estável (`ModelRegistryError.code`), com `str(exc)` a ser exactamente o código e nunca um caminho"
    - "Verificação negativa como teste: embrulhar `joblib.load` num contador e provar que fica a 0 quando o `.pkl` está adulterado"

key-files:
  created:
    - scripts/test_model_registry.py
  modified:
    - scripts/model_registry.py
    - scripts/ml_anomalies.py
    - scripts/main.py
    - scripts/test_ml_models_api.py
    - scripts/test_ml_models_ui.py
    - scripts/test_ml_models_ui.cjs
    - ml_models.js

key-decisions:
  - "read_verified_bytes recusa um filename fora de ARTIFACT_FILES com `metadata_invalid` — não há código novo na lista fechada (D-06) e o guard fecha a última forma de construir um caminho a partir de texto externo"
  - "A cache só é preenchida depois de os DOIS `joblib.load` terem sucesso: um pickle que exploda ao desserializar deixa a cache vazia em vez de meia carregada"
  - "`_active_state` é a função única que decide o que está ativo, também para o carregamento — o legado nunca é um fallback implícito, é um ramo do mesmo ficheiro"
  - "`loaded` no relatório vem de `ml_anomalies.loaded_version()`, lido dentro da rota; o processo continua a servir o modelo antigo depois de um adopt até reiniciar (D-02)"

patterns-established:
  - "Pattern: uma entrada de estado que não é erro (`error_code` null com status != ok) desenha-se neutra; o badge de erro é para quando há mesmo código de erro"
  - "Pattern: fixture de teste que embute a função perigosa (contador em `joblib.load`) e a restaura num `finally`, para o teste poder correr contra a rota HTTP real"

requirements-completed: [SEC-01, SEC-02, REG-02, API-02]

coverage:
  - id: D1
    description: "Um .pkl de uma versão cujo SHA-256 não bate com o metadata.json é recusado com o código hash_mismatch, e o contador de chamadas a joblib.load fica a 0 (nem no modelo, nem no scaler)"
    requirement: SEC-01
    verification:
      - kind: integration
        ref: "scripts/test_ml_models_api.py#(l)/(m) modelo e scaler adulterados -> ZERO chamadas a joblib.load"
        status: pass
      - kind: integration
        ref: "scripts/test_ml_models_api.py#(l) load_model levanta ModelRegistryError('hash_mismatch') com o contador a 0"
        status: pass
    human_judgment: false
  - id: D2
    description: "O hash é calculado sobre os mesmos bytes que são passados a joblib.load (lidos uma só vez, sem segundo open do ficheiro)"
    requirement: SEC-01
    verification:
      - kind: unit
        ref: "scripts/test_model_registry.py#SEC-01: read_verified_bytes devolve os bytes verificados"
        status: pass
      - kind: unit
        ref: "scripts/test_model_registry.py#SEC-01: resolve_active_artifacts devolve exactamente os bytes do ficheiro do modelo/scaler"
        status: pass
    human_judgment: false
  - id: D3
    description: "Só com os .pkl soltos, o relatório mostra uma entrada 'legado, sem metadados' ativa, /api/ml-anomalies continua a carregar esse modelo e loaded == 'legacy'"
    requirement: REG-02
    verification:
      - kind: unit
        ref: "scripts/test_model_registry.py#REG-02: active == 'legacy' / entrada legacy com files e active True"
        status: pass
      - kind: integration
        ref: "scripts/test_ml_models_api.py#(k) legado -> 200 e loaded == 'legacy' (pickles reais)"
        status: pass
    human_judgment: false
  - id: D4
    description: "Depois de adotado (legado + v1 + ACTIVE v1, ou v1 sem ACTIVE), a entrada legacy desaparece da lista e o ACTIVE inválido não a traz de volta como ativa"
    requirement: REG-02
    verification:
      - kind: unit
        ref: "scripts/test_model_registry.py#D-03: legado desaparece nos três cenários"
        status: pass
    human_judgment: false
  - id: D5
    description: "Nenhum id nem ACTIVE resolve fora de models/, incluindo uma pasta vN que é symlink/junction para fora com metadata.json válido"
    requirement: SEC-02
    verification:
      - kind: unit
        ref: "scripts/test_model_registry.py#SEC-02 (junction/symlink): v7 fora de models/ -> invalid_version_id"
        status: pass
      - kind: unit
        ref: "scripts/test_model_registry.py#SEC-02: ACTIVE com ../x, ..\\x, C:/Windows, v12345, UTF-16, 65 bytes, 'v1\\nlixo' -> invalid_version_id"
        status: pass
    human_judgment: false
  - id: D6
    description: "/api/ml-anomalies e /api/redblue/metrics devolvem 503 com detail igual a um código estável (nunca 500) quando o registo recusa o carregamento, e nenhuma resposta contém caminho nem Traceback"
    requirement: API-02
    verification:
      - kind: integration
        ref: "scripts/test_ml_models_api.py#(l)/(m)/(n) 503 com detail == hash_mismatch / invalid_version_id"
        status: pass
      - kind: integration
        ref: "scripts/test_ml_models_api.py#(o) pasta vazia -> 503 sem caminho temporário cru nem resolvido"
        status: pass
      - kind: unit
        ref: "scripts/test_model_registry.py#Pasta inexistente: a mensagem não contém o caminho"
        status: pass
    human_judgment: false
  - id: D7
    description: "Com _model/_scaler já em memória, load_model devolve-os sem consultar o disco, mesmo com a pasta adulterada em ML_MODEL_DIR, e reset_cache() limpa os três globais"
    requirement: REG-02
    verification:
      - kind: integration
        ref: "scripts/test_ml_models_api.py#(p) cache hit devolve os sentinelas sem levantar / reset_cache limpa"
        status: pass
      - kind: integration
        ref: "scripts/test_ml_anomalies.py + test_redblue.py + test_detections_api.py + test_attack_registry.py + test_metrics_api.py + test_incident_ingest.py + test_incidents_api.py (run_all_tests.py 36/36)"
        status: pass
    human_judgment: false
  - id: D8
    description: "GET /api/ml/models expõe em loaded a versão que o processo tem em memória ('v1' quando carregou da v1, 'legacy' quando carregou os .pkl soltos)"
    requirement: API-02
    verification:
      - kind: integration
        ref: "scripts/test_ml_models_api.py#(j) loaded == 'v1' / (k) loaded == 'legacy'"
        status: pass
    human_judgment: false
  - id: D9
    description: "A entrada do legado desenha-se neutra ('sem metadados') e não com o badge vermelho de erro, contra o relatório real de GET /api/ml/models"
    requirement: UI-01
    verification:
      - kind: automated_ui
        ref: "scripts/test_ml_models_ui.cjs#mlmBuildModelsRows sobre report_legacy.json (sem mlm-badge-error, sem MLM_GENERIC_ERROR)"
        status: pass
    human_judgment: false
  - id: D10
    description: "O painel Models mostra a entrada do legado e as 503 com código no browser real (aspeto dos badges, texto acionável, ausência de caminho)"
    requirement: UI-01
    verification: []
    human_judgment: true
    rationale: "O teste Node prova a string que os helpers devolvem contra o JSON real da rota, mas não prova o clique na sidebar nem o aspeto dos badges. Exige o arranque do backend e do frontend, que não foi executado neste ambiente (o mesmo <human-check> que ficou por fazer no 01-01, ver coverage.D10 de 01-01-SUMMARY.md)."

# Metrics
duration: 22min
completed: 2026-10-10
status: complete
---

# Phase 1 Plan 02: Integridade e adopt — Summary

**SHA-256 conferido sobre os mesmos bytes que chegam ao `joblib.load`, modelo legado reconhecido como "legado, sem metadados" e ativo, e rotas de deteção a devolver 503 com código estável em vez de 500.**

## Performance

- **Duration:** ~22 min
- **Started:** 2026-10-10T13:28:00+01:00
- **Completed:** 2026-10-10T13:50:00+01:00
- **Tasks:** 2 (Task 1 domínio + teste novo; Task 2 carregamento + rotas + teste alargado)
- **Files modified:** 8 (1 criado, 7 alterados) — 1217 linhas, +1217/−40
- **Estimate do plano:** 65 000 tokens / 2 tasks — o real foi 17 772 (chars/4 sobre o diff), porque o grosso do plano era especificação de comportamento e o código dela é curto.

## Accomplishments

- **A propriedade de segurança central está provada por teste, não por argumento:** com um byte trocado em `isolation_forest.pkl` **ou** em `scaler.pkl`, `joblib.load` é chamado **0 vezes**. O teste embrulha `ml_anomalies.joblib.load` num contador e corre contra a rota HTTP real, com pickles verdadeiros (um IsolationForest treinado e dumpado para `BytesIO`), por isso o caminho "bom" também é exercitado a sério — se os bytes não fossem carregáveis, o teste (j) falhava.
- **Sem janela TOCTOU:** `read_verified_bytes` lê o ficheiro uma vez, hashea esse buffer e devolve **o mesmo buffer**; `load_model` faz `joblib.load(io.BytesIO(esse_buffer))`. Não existe um segundo `open` em lado nenhum — nenhum caminho do código passa um caminho de ficheiro ao `joblib.load` (verificado por grep e pelo contador).
- **O legado passou a ser uma primeira classe citizens do relatório, sem deixar de funcionar:** com só os `.pkl` soltos em `scripts/models/`, `/api/ml/models` devolve `active: "legacy"` com a entrada "legado, sem metadados" (tamanho e mtime dos dois ficheiros), e `/api/ml-anomalies` continua a devolver 200 — verificado também contra o **modelo real do repositório**, não só contra fixtures.
- **Um `ACTIVE` inválido deixa de ser um 500 e passa a ser um 503 com código**, em `/api/ml-anomalies` e `/api/redblue/metrics`, e — o ponto de fail-closed — **não cai para o legado** mesmo com `.pkl` soltos presentes em `models/`.
- **`loaded` fecha o ciclo do D-02:** o relatório diz que versão o processo tem de facto em memória, que depois de um `adopt` não é necessariamente a ativa.
- **A cache nunca fica a meio:** os dois `joblib.load` têm de ter sucesso antes de `_model`/`_scaler` serem attribídos, e o curto-circuito continua a ser a primeira instrução de `load_model` (REG-02, sem regressão nos 7 ficheiros de teste que dependem dele).

## Task Commits

Cada task foi commitada atomicamente:

1. **Task 1: Registo verifica SHA-256 e reconhece o legado (domínio + test_model_registry.py)** — `a1e4001` (feat)
2. **Task 2: load_model carrega só bytes verificados; rotas dão 503 com código; loaded no relatório** — `2605b32` (feat)

_Note: ambas as tasks têm `tdd="true"`. O `test_model_registry.py` foi escrito e corrido primeiro (a falhar, com `AttributeError`/`KeyError` por as funções novas não existirem) e só depois o `model_registry.py` foi implementado; a secção "carregamento verificado" do `test_ml_models_api.py` foi escrita antes do `ml_anomalies.py` e do `main.py`, e falhou com `AttributeError: module 'ml_anomalies' has no attribute 'reset_cache'`._

**Commits sem `Co-Authored-By` e sem "Generated with ..."** (D-08): confirmado com `git log --format=%B 6703532..HEAD | grep -i "co-authored-by\|generated with"` → **0 matches**.

## Files Created/Modified

- `scripts/test_model_registry.py` — **novo.** 128 checks standalone (sem `main`, sem `joblib`, sem pipeline) sobre REG-01, REG-02/D-03, SEC-01, SEC-02 e `_root`. Fixtures `make_version` / `make_legacy` / `write_active` / `flip_byte`, todo o disco em `TemporaryDirectory`, e o caso `v7` como symlink para fora de `models/` com remoção explícita do link antes do cleanup (um `rmtree` de uma junction apagaria o alvo).
- `scripts/model_registry.py` — `sha256_file` (streaming, blocos de 1 MiB), `_verify_artifacts`, `read_verified_bytes`, `detect_legacy`, `ArtifactSource` (NamedTuple), `resolve_active_artifacts`, `NO_MODEL_MESSAGE`; `_active_state` com o ramo do legado; `build_models_report` com `status` de integridade e a entrada legacy no fim. Imports: `hashlib`, `hmac`, `datetime`, `typing` a juntar a `json`/`re`/`pathlib` — continua sem `joblib`/`ml_anomalies`/`fastapi` (verificado por AST).
- `scripts/ml_anomalies.py` — `load_model` delega em `model_registry.resolve_active_artifacts` na cache miss e desserializa com `joblib.load(io.BytesIO(...))`; globals `_loaded_from`, `reset_cache()` e `loaded_version()`; a `FileNotFoundError` com a pasta na mensagem foi substituída por `NO_MODEL_MESSAGE` (sem caminhos).
- `scripts/main.py` — `except model_registry.ModelRegistryError` → 503 com `detail=<código>` + `logger.warning` em `get_ml_anomalies` e `get_redblue_metrics`; `get_ml_models` passa `ml_anomalies.loaded_version()`. Nada mais foi tocado nas outras chamadas a `load_model`, que já degradam com `except Exception`.
- `scripts/test_ml_models_api.py` — +277 linhas: `real_model_bytes()` (treina um IsolationForest minúsculo sobre `MOCK_ALERTS` e devolve os bytes de `joblib.dump`), `make_legacy`, `flip_byte`, `no_leaks_pasta`, a classe `ContadorJoblib` e a secção `carregamento_verificado` com os casos (j)..(p). 44 checks novos (110 no total).
- `scripts/test_ml_models_ui.py` / `.cjs` — nova fixture `report_legacy.json` (resposta real da rota com só os `.pkl` soltos) e 6 checks em Node sobre a linha do legado.
- `ml_models.js` — o badge de erro passa a depender de `entry.error_code` em vez de "status != ok" (ver Deviation 1).

## Decisions Made

- **`read_verified_bytes` com nome de ficheiro fora de `ARTIFACT_FILES` levanta `metadata_invalid`.** É um erro de programação, não de dados, e D-06 fecha a lista de códigos — criar um código novo seria pior do que reusar um existente. O guard fecha a última forma de construir um caminho a partir de texto externo, e está testado com `"../../secrets.pkl"`.
- **A cache só é escrita depois dos dois `joblib.load` terem sucesso.** O plano só pedia "nunca uma cache meio preenchida"; a implementação põe `_model`/`_scaler`/`_loaded_from` só no fim, o que também evita que um `pickle.UnpicklingError` deixe `_model` populated e `_scaler` a None.
- **`detect_legacy` devolve `None` se algum dos dois `.pkl` não for ficheiro regular**, e `_active_state` só chama-o no ramo em que o `ACTIVE` não existe — o `ACTIVE` manda sempre.
- **`sha256_file` mapeia ficheiro em falta para `artifact_missing`** (e não para `registry_unavailable`), porque é o código que o analista precisa de ver. `_verify_artifacts` transforma a exceção num `status` para a versão, sem a deixar derrubar a lista.
- **Nome `_winapi.CreateJunction(link, target)`** com os argumentos na ordem real (o plano tinha-os trocados) — ver Deviation 2.
- **Nada foi escrito em `SKELETON.md`.** O contrato JSON não mudou: a entrada legacy e o `status` novo já estavam especificados lá. (Ver "Next Phase Readiness" para a única coisa que o SKELETON ficou ligeiramente atrás.)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 — Missing Critical] A entrada do legado era desenhada com o badge vermelho de erro**
- **Found during:** Task 2, ao fazer o smoke test contra o `scripts/models/` real
- **Issue:** `mlmBuildModelsRows` (01-01) desenhava qualquer `status != "ok"` como `<span class="mlm-badge mlm-badge-error">{mlmErrorText(entry.error_code)}</span>`. A entrada do legado tem `status: "no_metadata"` e `error_code: null`, portanto `mlmErrorText(null)` devolve `MLM_GENERIC_ERROR` — ou seja, o modelo **ativo e a funcionar** aparecia na aba Models com o texto "Erro inesperado ao ler o registo de modelos" num badge vermelho. Antes do 01-02 essa entrada não existia na resposta, por isso o 01-01 não podia ter visto o problema; em `models/` sem v1 — o estado de qualquer máquina que ainda não fez `adopt` — é o estado normal.
- **Fix:** o badge de erro passou a depender de `entry.error_code` (não de `status != "ok"`); um estado não-errado sem código desenha `<span class="mlm-badge mlm-badge-legacy">sem metadados</span>`. Foi escrito primeiro o teste Node (6 checks contra `report_legacy.json`, resposta real da rota) e confirmado que falhava, e só depois o JS.
- **Files modified:** `ml_models.js`, `scripts/test_ml_models_ui.py`, `scripts/test_ml_models_ui.cjs`
- **Verification:** `test_ml_models_ui.py` exit 0 (antes falhava em "sem badge de erro" e "sem mensagem genérica de erro"); `node --check ml_models.js` exit 0; `run_all_tests.py` 36/36
- **Committed in:** `2605b32`
- **Nota de âmbito:** este ficheiro **não** está no `files_modified` do plano (o plano não previa trabalho de frontend). É uma correção de compatibilidade mínima, não o trabalho de estados de UI — esse continua a ser do 01-03, que parte daqui.

**2. [Rule 5 — Correcção] `_winapi.CreateJunction` com os argumentos trocados no plano**
- **Found during:** Task 1, a preparar o caso junction/symlink
- **Issue:** o plano dá `_winapi.CreateJunction(str(alvo), str(root / "v7"))`. A assinatura real (CPython, e a de `CreateJunctionW` na Win32) é `(link_path, target_path)` — com a ordem do plano criava-se a junction **dentro do alvo**, a apontar para `models/`, que não testa nada.
- **Fix:** `_winapi.CreateJunction(str(link), str(alvo))`, só como fallback quando `os.symlink` é recusado.
- **Files modified:** `scripts/test_model_registry.py`
- **Verification:** nesta máquina `os.symlink` foi aceite (Windows Developer Mode), por isso o caminho exercitado é o symlink; o caso tem de se manter para máquinas sem privilégios. O teste corre o mesmo no symlink e na junction e **falha explicitamente** se nenhuma das duas funcionar.
- **Committed in:** `a1e4001`

**3. [Rule 5 — Correcção] Off-by-one na fixture dos 65 bytes**
- **Found during:** Task 1, primeira execução do `test_model_registry.py`
- **Issue:** `b"v1" + b" " * 62` tem **64** bytes, não 65, pelo que o `ACTIVE` era lido e validado como `v1` e a v1 era ativada — o teste falhava, e por outro caminho passaria a ser um falso negativo.
- **Fix:** `b"v1" + b" " * 63`. Aproveitei para trocar os nomes das pastas temporárias (baseados em `hash()`, que é salted por processo) por índices determinísticos.
- **Files modified:** `scripts/test_model_registry.py`
- **Verification:** `test_model_registry.py` exit 0 com 128 checks
- **Committed in:** `a1e4001`

---

**Total deviations:** 3 auto-fixed (1 missing critical de UI, 2 correcções)
**Impact on plan:** os três foram necessários para o resultado estar correto; a Deviation 1 é a única que toca fora do `files_modified` do plano, e existe porque o plano introduz um estado novo na resposta que o renderizador do 01-01 não conhecia. Sem escopo creep: nenhum ficheiro foi criado que o plano não pedisse, nenhuma capacidade nova foi acrescentada.

## Issues Encountered

- **O smoke test contra o modelo real foi o que revelou a Deviation 1.** Nenhum teste do plano toca no `scripts/models/` real (e nenhum deve), e a fixture do wrapper de UI só tinha `report_v1.json` e `report_empty.json`. Correr `resolve_active_artifacts(DEFAULT_MODELS_DIR)` à mão — leitura, nada escrito — foi o que mostrou que `loaded_version()` devolve `legacy` **e** que o badge de erro ia aparecer a toda a gente. A fixture `report_legacy.json` fica agora no wrapper para o teste não voltar a perder essa cobertura.
- **`os.symlink` foi aceite nesta máquina**, pelo que o caminho da junction (`_winapi.CreateJunction`) não foi exercitado — só o do symlink. O teste cobre os dois, mas num SO sem Developer Mode só o segundo correria. Fica declarado: **a variante junction não foi executada neste ambiente**.
- **Ruído de log esperado nos testes:** as rotas registam agora `WARNING ...: registo de modelos recusou o carregamento (hash_mismatch)` nos casos de recusa, e o caso (i) do 01-01 imprime um traceback de propósito (prova que a causa fica no log e não na resposta). É comportamento pretendido, não falha.

## Commands Run (resultados reais)

| Comando | Resultado |
|---|---|
| `cd scripts && .venv/Scripts/python test_model_registry.py` | **exit 0** — 128 checks `[OK]`, zero `[FALHOU]`, zero `[SKIP ]`, `Todos os testes passaram` |
| `cd scripts && .venv/Scripts/python test_ml_models_api.py` | **exit 0** — 110 checks `[OK]` (66 do 01-01 + 44 novos), zero `[FALHOU]` |
| `cd scripts && .venv/Scripts/python test_ml_models_ui.py` | **exit 0** — 3 checks do wrapper + 71 checks Node `[OK]` |
| `cd scripts && .venv/Scripts/python run_all_tests.py` | **exit 0** — `36/36 ficheiros passaram` (35 antes do plano + `test_model_registry.py`) |
| AST: `model_registry.py` não importa `joblib`/`ml_anomalies`/`fastapi` | **exit 0**; imports reais = `['datetime', 'hashlib', 'hmac', 'json', 'pathlib', 're', 'typing']` |
| `grep -c 'def resolve_active_artifacts' scripts/model_registry.py` | `1` (idem `def read_verified_bytes`, `def detect_legacy`, `def sha256_file`) |
| `grep -c 'hmac.compare_digest' scripts/model_registry.py` | `3` (≥ 1 exigido) |
| `grep -c 'except model_registry.ModelRegistryError' scripts/main.py` | `3` (≥ 3 exigido) |
| `grep -c 'ml_anomalies.loaded_version()' scripts/main.py` | `1` |
| `grep -c 'def reset_cache' / 'def loaded_version' scripts/ml_anomalies.py` | `1` / `1` |
| `joblib.load(io.BytesIO` em `ml_anomalies.py` (sem comentários) | `3` (2 chamadas + 1 na docstring); **0** chamadas de `joblib.load` com caminho de ficheiro |
| `node --check ml_models.js` | **exit 0** |
| smoke test real (só leitura) contra `scripts/models/` | `version=legacy`, `verified=False`, `IsolationForest`+`StandardScaler` carregados de `BytesIO`, `active=legacy`, `loaded_version()='legacy'` |
| `git log --format=%B 6703532..HEAD \| grep -i "co-authored-by\|generated with"` | **vazio** (0 matches) |

Baseline antes de qualquer alteração: `run_all_tests.py` **35/35**.

**Verificação humana por fazer:** o `coverage.D10` (aba Models no browser real com a entrada do legado e os estados de erro) **não foi executado** — este ambiente não arrancou o backend nem o frontend. Está declarado como tal, e continua a acumular com o `coverage.D10` do 01-01.

## User Setup Required

None — no external service configuration required. Nenhum serviço novo, nenhuma variável de ambiente nova. Uma nota operacional para quem usá-lo a sério: **depois de `adopt` ou de um treino é preciso reiniciar o backend** (ou chamar `ml_anomalies.reset_cache()`), porque a cache do modelo é por processo — é isso que o campo `loaded` torna visível no dashboard.

## Next Phase Readiness

- **01-03 (estados de UI)** parte de `report_legacy.json` e dos 6 checks que ligei agora: a entrada do legado já desenha-se neutra, mas **não** há ainda a matriz de estados completa (`no_metadata`, `hash_mismatch`, `artifact_missing`, os metadados `null` do legado, o `loaded` vs `active` como aviso de "reinicia o backend"). O badge `mlm-badge-legacy` que este plano passou a usar já existia no `style.css` desde o 01-01.
- **01-04 (adopt)** tem `_root()`, `ARTIFACT_FILES`, `detect_legacy()`, `sha256_file()` e `read_verified_bytes()` prontos a reusar. O único cuidado: `adopt` tem de escrever `ACTIVE` só se não existir (D-01) e, ao ser interrompido, tem de validar a `v1` existente pelos mesmos hashes que `read_verified_bytes` confere.
- **Fase 2 (avaliação)** pode consumir `evaluation` sem mais alteração no contrato.
- **Dívida de segurança registada, tal como o plano mandava:** o SHA-256 deteta corrupção e troca acidental, **não autentica** — quem escreve em `models/` reescreve o `metadata.json` (T-01-09, D-04). E o legado carrega sem verificação até ser adotado (T-01-10). Nenhum texto deste plano diz o contrário; a documentação de `README.md`/`CLAUDE.md` é do 01-04/DOC-01 e tem de manter esta honestidade.
- **Um ponto em que o `SKELETON.md` ficou atrás da implementação** (não corrigido aqui, por decisão — o plano lista o SKELETON como contrato a consumir, não a alterar): a tabela de `status` de uma entrada versionada não inclui `no_metadata`, que é o `status` da entrada **legacy**. Vale a pena uma linha de acerto no 01-03 ou no 01-04.
- **Sem dívida técnica deixada por este plano.**

---
*Phase: 01-registo-de-modelos-ponta-a-ponta*
*Completed: 2026-10-10*
