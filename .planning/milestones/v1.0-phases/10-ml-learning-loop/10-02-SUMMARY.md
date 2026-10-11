---
phase: 10-ml-learning-loop
plan: 02
subsystem: training-engine
tags: [ml, training, single-flight, provenance, rce, n-estimators, security]

# Dependency graph
requires:
  - phase: 10-ml-learning-loop
    plan: 01
    provides: "catalog_sha256(), os sete kwargs de proveniencia em register_trained_version e o compare-and-set de _write_active_atomic(expected=)"
  - phase: 03-treino-gera-versoes-testes-e-documentacao
    provides: "train_anomaly_model.load_dataset/vectorize, ContadorJoblib e o esqueleto check()/secao() dos testes standalone"
provides:
  - "ml_training.train_next_version(...) — treina, regista, activa e recarrega a cache; assinatura SEM nenhum caminho do cliente"
  - "ml_training.activate_version(models_dir, version_id) — activar uma vN com verificacao de integridade e compare-and-set"
  - "ml_training.TRAIN_LOCK / busy() / _slot() — single-flight com threading.Lock (D-01.2)"
  - "ml_training.TRAINING_ERROR_CODES com 4 chaves e TrainingError (molde de ModelRegistryError/EvaluationError)"
  - "resolve_export_path / resolve_attack_log_path — o unico sitio do projecto que decide de onde vem o dataset"
  - "read_events_file / dataset_facts / feature_stats / build_training_rows / dump_artifacts"
  - "train_anomaly_model.train_model ganha n_estimators keyword-only (default N_ESTIMATORS=200); save_model delega em ml_training.dump_artifacts"
  - "test_ml_training.py — 159 checks; gate_seccoes.py — 0 secoes mortas"
affects: [10-03-http-e-frontend, docs/DATA_MODEL.md, docs/SECURITY.md, main.py, ml_models.js]

# Actuals (#2632) — pares com o `estimate` do plano para calibrar os futuros.
actuals:
  tokens: 62000
  tasks: 3
  commits: 4

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "O que o cliente pode escolher (qual dataset) separado do que ele pode dizer (onde esta): um Literal sobre um catalogo fechado, nunca um caminho"
    - "Instrumentacao em vez de introspeccao: a ordem register -> reset -> load prova-se com uma lista de chamadas e uma fotografia do ACTIVE de dentro do load_model substituido"
    - "Substituir um modulo exige guardar a funcao VERDADEIRA antes de a substituir (a versao 1 deste ficheiro chamava a si propria e died num RecursionError)"
    - "Teto de leitura antes do parse: o ficheiro grande nem precisa de ser JSON valido para o teste do teto"

key-files:
  created:
    - "scripts/ml_training.py"
    - "scripts/test_ml_training.py"
    - "scripts/gate_seccoes.py"
  modified:
    - "scripts/train_anomaly_model.py"
    - "scripts/model_registry.py"

key-decisions:
  - "D-01.1 e D-01.2 vivem NO MESMO modulo e no mesmo commit de ficheiro: partir ml_training.py ao meio deixaria um commit com um `train_next_version` sem lock, que e um desenho que ninguem quer. A divisao por task que o plano pede e feita nos commits, com o Task 1 isolado por construcao."
  - "`dump_artifacts` tem UM `joblib.dump` dentro de um ciclo sobre `ARTIFACT_FILES` (e nao dois): e o que faz a contagem por AST dar exactamente 1, e a lista fechada e a do registo em vez de duas strings escritas a mao."
  - "`build_training_rows` e publica de proposito: e a mesma funcao para o CLI e para a API, e duas copias do 'documento vira linha treinavel' seria a divergencia silenciosa que o `feature_extractor` partilhado existe para evitar."
  - "`dataset_facts` nao recebe `attack_log` (o plano passava-o): o rotulo `is_attack` ja esta em cada linha e contar o log outra vez seria um segundo sitio onde o numero do ataque e decidido."
  - "O sufixo do nome de export ordena como INTEIRO, nao como texto: ver 'Deviations from Plan' #1."
  - "O `joblib.dump` do `_cmd_train` tambem migrou para `ml_training.dump_artifacts`: sem isso o gate de 'exactamente 1' nao fechava, porque o CLI tinha o seu proprio."
  - "Nenhum `joblib` novo em `train_anomaly_model.py`: o import foi removido porque a minha alteracao o deixou orfao, e um import orfao de `joblib` num ficheiro que ja nao faz dump convida alguem a acrescentar o segundo."

patterns-established:
  - "Gate por AST para 'nenhuma seccao morta' tem de ler a tupla SECOES, nao procurar Call nodes: o run() chama por iteracao e um gate de Calls reporta 13 seccoes vivas como mortas"
  - "Nome de variavel de loop que nao colida com o prefixo que o gate procura (passo, nao secao_): o gate encontrou o proprio bug ao rodar pela primeira vez"

requirements-completed: [D-01, D-02, D-03, D-05]

# Coverage metadata (#1602)
coverage:
  - id: D1
    description: "D-01.1: train_next_version nao tem sources nem nenhum caminho do cliente; os .pkl nascem num TemporaryDirectory e os nomes vem de ARTIFACT_FILES"
    requirement: D-01
    verification:
      - kind: unit
        ref: "scripts/test_ml_training.py::secao_pin_de_assinatura (assinatura exacta, nomes proibidos, 5 keywords que dao TypeError)"
      - kind: unit
        ref: "scripts/test_ml_training.py::secao_treino_a_serio (nenhum caminho na resposta nem no metadata.json)"
      - kind: unit
        ref: "gate: inspect.signature -> ('models_dir','events_path','attack_log_path','contamination','random_state','n_estimators','dataset_origin')"
      - kind: unit
        ref: "gate por AST: joblib.dump == {'ml_training.py': 1} (era 4 antes)"
    human_judgment: false
  - id: D2
    description: "D-01.2: single-flight com threading.Lock a cobrir a sequencia inteira; o segundo pedido leva training_in_progress e nao escreve nada"
    requirement: D-01
    verification:
      - kind: unit
        ref: "scripts/test_ml_training.py::secao_single_flight (EXACTAMENTE um training_in_progress, models/ fotografado vazio, sem ACTIVE)"
      - kind: unit
        ref: "scripts/test_ml_training.py::secao_ordem_da_cache (sequencia register -> reset -> load por instrumentacao + fotografia do ACTIVE dentro do load)"
      - kind: unit
        ref: "gate: isinstance(TRAIN_LOCK, type(threading.Lock())) e busy() is False"
    human_judgment: false
  - id: D3
    description: "D-02: o metadata.json distingue '35 de 500' de '35 de 35'; cada facto comparado com o calculo independente do proprio teste"
    requirement: D-02
    verification:
      - kind: unit
        ref: "scripts/test_ml_training.py::secao_factos_do_dataset + secao_treino_a_serio (1000 documentos -> truncated True)"
    human_judgment: false
  - id: D4
    description: "D-03: feature_stats com as 7 features de FEATURE_NAMES, media e pstdev recalculados a mao, e o skew declarado como nao corrigido"
    requirement: D-03
    verification:
      - kind: unit
        ref: "scripts/test_ml_training.py::secao_estatisticas_do_lote (comparacao feature a feature com round(x,6))"
      - kind: unit
        ref: "gate: set(feature_stats) == set(FEATURE_NAMES), por ordem, com o docstring a dizer o porque do skew"
    human_judgment: false
  - id: D5
    description: "D-05/T-10-08: n_estimators e random_state usados E registados; o .pkl concorda com os parameters, no CLI e na API"
    requirement: D-05
    verification:
      - kind: unit
        ref: "scripts/test_ml_training.py::secao_treino_a_serio (n_estimators=7 produz 7 arvores e os parameters gravados sao esses)"
      - kind: integration
        ref: "gate do CLI: train v1 --random-state 1234 --n-estimators 77 -> metadata E .pkl dizem 77/1234"
      - kind: unit
        ref: "os 5 ficheiros de teste que importam train_model continuam verdes (assinatura retrocompativel)"
    human_judgment: false
  - id: D6
    description: "TST-01: cobertura real — 159 checks, todas as 13 seccos no SECOES, e o gate que o garante"
    requirement: TST-01
    verification:
      - kind: unit
        ref: "scripts/test_ml_training.py — 159 checks, 0 linhas [FALHOU]"
      - kind: unit
        ref: "scripts/gate_seccoes.py — 13 definidas, 13 no SECOES, 0 mortas, 0 orfas"
    human_judgment: false
  - id: D7
    description: "O disco do utilizador intacto e o registo stdlib puro no topo"
    requirement: SEC-01
    verification:
      - kind: unit
        ref: "gate por AST: topo de ml_training.py e de model_registry.py sem nenhum dos 7 proibidos"
      - kind: unit
        ref: "scripts/test_export_raw_events.py (guard (f): scripts/models/ nunca foi tocado) + SHA-256 e mtime dos dois .pkl"
      - kind: unit
        ref: "prova negativa: sklearn e joblib nao estao em sys.modules quando ml_training e importado"
    human_judgment: false
  - id: D8
    description: "Decisao do agente de frontend: o que o 10-03 tem de saber ler desta resposta"
    verification:
      - kind: manual_procedural
        ref: "ml_models.js / ml_evaluation.js — nenhum bloco novo foi aqui; ver 'Contrato novo para o frontend'"
        status: unknown
    human_judgment: true
    rationale: "Este plano nao toca em frontend. O que a UI faz com `loaded` e com a resposta do treino e do agente de frontend; aqui so se garante que o contrato sai correcto e testado."

# Metrics
duration: 190min
completed: 2026-10-11
status: complete
---

# Phase 10, Plan 02: O motor de treino

**Um `train_next_version` que não aceita nenhum caminho do cliente, treina a sério, regista a proveniência do lote e recarrega a cache do modelo — e um CLI que deixou de mentir sobre os parâmetros com que treinou.**

## Performance

- **Duration:** ~190 min
- **Tasks:** 3 de 3 (Task 3 não escreve `test_model_registry.py` — entra como gate)
- **Files:** 3 criados (`ml_training.py`, `test_ml_training.py`, `gate_seccoes.py`), 2 alterados (`train_anomaly_model.py`, `model_registry.py`)
- **Checks:** `test_ml_training.py` — **159**, 0 `[FALHOU]`, 15–27 s a correr sozinho (variação medida entre execuções; muito abaixo dos 300 s do runner)
- **Suite:** 38/38 -> **39/39** ficheiros

## Accomplishments

- **`train_next_version` sem nenhum caminho do cliente (D-01.1)** — a assinatura é `(models_dir, events_path, attack_log_path, *, contamination, random_state, n_estimators, dataset_origin)` e nada mais. `sources`, `pkl`, `dataset_path`, `url` e `output_dir` são `TypeError`. O `dataset` vem de um conjunto fechado no servidor (`ML_EXPORT_DIR` / `REQUESTED_EXPORT`), o registo de `ML_MODEL_DIR`/`DEFAULT_MODELS_DIR` **nunca** do cwd, e os `.pkl` nascem num `TemporaryDirectory` apagado no `finally` em todos os cinco caminhos testados.
- **Single-flight com `threading.Lock` (D-01.2)** — `TRAIN_LOCK` + `_BUSY` + um contextmanager `_slot()` cujo `finally` é o que garante que o motor abre. O lock cobre treinar → registar → `reset_cache` → `load_model`, e a ordem é provada por **instrumentação**, não por leitura de texto.
- **`activate_version`** — validar o id, confirmar os dois `.pkl` por SHA-256, escrever o `ACTIVE` com compare-and-set, e só então recarregar a cache. Um `.pkl` adulterado dá `hash_mismatch` com **zero** chamadas a `joblib.load`.
- **Proveniência com factos (D-02/D-03)** — `documents`/`processable`/`truncated`/`window_first`/`window_last` e `feature_stats` com as 7 features do lote, comparados check a check com o cálculo independente que o teste faz a partir do ficheiro.
- **T-10-08 fechado** — o `metadata.json` e o `.pkl` dizem agora o mesmo, no CLI e na API.
- **`joblib.dump` tem um dono** — de **4** para **1** (contagem por AST): os de `train_anomaly_model.save_model` e os de `model_registry._cmd_train` foram ambos para `ml_training.dump_artifacts`.

## Task Commits

1. **Task 1 — o motor sem nenhum caminho do cliente** — `d33a44a` (feat): `ml_training.py` (novo), `train_anomaly_model.py`, `test_ml_training.py` (novo, 119 checks)
2. **Task 2 — single-flight e a ordem da cache** — `79320eb` (feat): o mesmo `ml_training.py` e o mesmo `test_ml_training.py` (119 -> 159 checks)
3. **Task 3 — o CLI passa a registar o que treina** — `9c8d248` (fix): `model_registry.py` (`_cmd_train`)
4. **Gate de secções mortas** — `645de48` (test): `gate_seccoes.py` + a variável de loop de `run()`

## Files Created/Modified

- `scripts/ml_training.py` — **novo**: `TRAINING_ERROR_CODES`, `TrainingError`, `read_events_file`, `resolve_export_path`, `resolve_attack_log_path`, `dataset_facts`, `feature_stats`, `dump_artifacts`, `build_training_rows`, `train_next_version`, `activate_version`, `TRAIN_LOCK`, `busy()`, `_claim`/`_release`/`_slot`, `TEMP_PREFIX`, `EXPORT_NAME_RE`, `MAX_EVENTS_BYTES`, `MAX_DOCUMENTS`, `MAX_TIMESTAMP_LEN`, `DEFAULT_EXPORT_DIR`, `DATASET_CHOICES`.
- `scripts/train_anomaly_model.py` — `N_ESTIMATORS = 200`; `train_model(..., *, n_estimators=N_ESTIMATORS)`; `save_model` delega em `ml_training.dump_artifacts`; `import joblib` removido (ficou órfão com a minha alteração).
- `scripts/model_registry.py` — **apenas `_cmd_train`**: `random_state`/`n_estimators` ao `train_model`; leitura por `ml_training.read_events_file` + `build_training_rows`; `dataset_facts`/`feature_stats`/`catalog_sha256` ao registo; `dump_artifacts` em vez de `joblib.dump`; a linha do `catalog_sha256` na mensagem de fim.
- `scripts/test_ml_training.py` — **novo**: 13 secções, 159 checks.
- `scripts/gate_seccoes.py` — **novo**: gate por AST de secções mortas.

**Não tocados:** `main.py`, `ml_anomalies.py`, `feature_extractor.py`, `ml_evaluation.py`, `export_raw_events.py`, `serve_frontend.py`, qualquer ficheiro de frontend, `docs/*`, `README.md`, `CLAUDE.md`, `.planning/*`.

## Verification (tudo medido DEPOIS da última alteração)

| Verificação | Resultado | Número medido |
|---|---|---|
| `test_ml_training.py` | PASS, exit 0, 0 linhas `[FALHOU]` | **159** checks, 27.2 s (medida final) |
| `run_all_tests.py` | PASS, exit 0 | **39/39**, 205.1 s (medida final) |
| Gate AST do topo de `ml_training.py` | PASS | `['contextlib','importlib','json','os','pathlib','re','statistics','tempfile','threading']` |
| Gate AST do topo de `model_registry.py` | PASS | stdlib puro, nenhum dos 7 proibidos |
| Gate `joblib.dump(` em ficheiros não-teste | PASS | `{'ml_training.py': 1}` (era 4) |
| Gate `joblib.load(` | PASS | `{'ml_anomalies.py': 3}` (inalterado) |
| Gate assinatura + lock | PASS | `('models_dir','events_path','attack_log_path','contamination','random_state','n_estimators','dataset_origin')`, `TRAIN_LOCK lock`, `busy False` |
| Gate `TRAINING_ERROR_CODES` / `ERROR_CODES` | PASS | 4 e 9, sem intersecção |
| Gate T-10-08 (pedido) | PASS | metadata `{'contamination':0.2,'random_state':1234,'n_estimators':77}`, `.pkl` `{77, 1234}` |
| Gate T-10-08 (defaults) | PASS | metadata e `.pkl` dizem 200/42 |
| Gate secções mortas | PASS | 13 definidas, 13 no `SECOES`, 0 mortas, 0 órfãs |
| `test_export_raw_events.py` (inclui o guard (f)) | PASS, exit 0 | — |
| `test_ml_anomalies` / `test_redblue` / `test_ml_evaluation` / `test_ml_models_api` / `test_ml_models_ui` | PASS, exit 0 | assinatura retrocompatível |
| `train_anomaly_model.py --help` / `model_registry.py train --help` | PASS, exit 0 | `--contamination`, `--random-state`, `--n-estimators` |
| `node --check ml_models.js` / `ml_evaluation.js` | PASS, exit 0 | v24.14.1, ficheiros não tocados |
| `scripts/models/` | PASS | `['isolation_forest.pkl','scaler.pkl']`, SHA-256 e mtime `2026-09-14T16:40:15` inalterados |
| `Co-Authored-By` / `Generated with` nos commits | PASS | nenhuma ocorrência |

**Sobre o `run_all_tests.py`:** o 10-01 mediu 2 timeouts em 5 execuções em ficheiros alheios. Aqui correu limpo à primeira, depois da última alteração. Não é uma garantia de estabilidade — é uma medição, e a instabilidade de paralelismo desta máquina continua a ser o limite conhecido do número.

## Decisions Made

1. **Nenhum caminho na resposta, e medido por três vias** — a assinatura é exacta (gate), `sources=`/`pkl=`/`url=` são `TypeError` (execução real), e um varrimento recursivo do dict devolvido e do `metadata.json` não encontra `:` de drive nem `/` nem `\`.
2. **`dump_artifacts` com UM `joblib.dump` dentro de um ciclo.** A lista fechada é `model_registry.ARTIFACT_FILES`, e se ela deixar de bater com `{MODEL_FILE, SCALER_FILE}` o resultado é `training_failed` — fail-closed, nunca um `KeyError` a meio de um dump.
3. **A leitura fica fora do lock, o resto dentro.** Ler um ficheiro é rápido e não é o recurso a proteger; o que se protege é `models/`. Por isso o 409 é sobre o treino, não sobre a leitura.
4. **`TRAINING_ERROR_CODES` é uma lista nova**, como `EVALUATION_ERROR_CODES` antes dela. `ERROR_CODES` continua com 9 e o teste da API continua sem uma chave nova.
5. **`dataset_origin` inválido é `ValueError`, não `TrainingError`.** Mesmo contrato de `ml_evaluation.build_evaluation_report` — o erro é de programação da chamada, não um estado do pedido.

## Contrato novo para o frontend (para passar ao agente do 10-03)

Nenhum **código de erro** novo na API de listagem: `ERROR_CODES` continua com as 9 chaves e `D06_CODES.length === 9` fica verde.

`POST /api/ml/train` (a criar no 10-03) deve translating para:

| Código HTTP | Quando | `detail` |
|---|---|---|
| 404 | nenhum export em `ML_EXPORT_DIR` | `"dataset_not_found"` |
| 422 | ficheiro ilegível, não-lista, lista de não-dicts, >8 MB, ou zero linhas treináveis | `"dataset_unusable"` |
| 409 | já há um treino no ar | `"training_in_progress"` |
| 500/503 | `ModelRegistryError` do registo, `training_failed` (compare-and-set perdido), `ValueError` interno | o `code` do registo |

`TrainingError.code` é **exactamente** a chave — `str(exc)` é o código, nunca uma mensagem nem um caminho.

Resposta 200 (o que `train_next_version` devolve, sem o `metadata` completo):

```json
{"version": "v3", "active": "v3", "loaded": "v3",
 "dataset": {"name": "...json", "size": 36, "attacks": 5, "synthetic": true,
             "documents": 36, "processable": 36, "truncated": false,
             "window_first": "...", "window_last": "..."},
 "parameters": {"contamination": 0.2, "random_state": 42, "n_estimators": 200},
 "evaluation": null,
 "catalog_sha256": "<64 hex>"}
```

Pontos para a UI:
- `loaded` é a versão **que este processo tem em memória**. É igual a `active` depois de um treino bemasso, e `null` se o carregamento falhar — o que o backend prefere a mentir.
- `evaluation` é **sempre `null`** num treino novo (EVAL-03). A UI não deve mostrar métricas de um treino sobre si próprio.
- `parameters` são os parâmetros **realmente usados** — o `.pkl` carregado concorda com eles, byte a byte.

## Deviations from Plan

### 1. O sufixo do nome de export NÃO ordena lexicograficamente a partir do décimo

- **Found during:** Task 1, escrita do teste
- **Issue:** o plano diz "ordena lexicograficamente; o último é o mais recente", e justifica com `.` (0x2E) < `_` (0x5F). Isso é verdade para `_2`/`_3` e **falso** a partir de `_10`: em texto, `09-00_10.json` vem **antes** de `09-00_2.json`. Com dez exports no mesmo minuto (o `_10` é o décimo `unique_output_path` do minuto), o motor treinaria sobre o export errado — em silêncio, porque o `metadata.json` registaria honestamente o ficheiro errado.
- **Fix:** o regex passou a capturar o sufixo e a ordenação é por `(carimbo, sufixo como inteiro)`. O carimbo continua a ordenar por texto, que é correcto: `YYYY-MM-DD_HH-MM` com dois dígitos.
- **Files modified:** `scripts/ml_training.py`, `scripts/test_ml_training.py`
- **Verification:** `test_ml_training.py::secao_resolve_export_path` checks (d) e (e) — e o check (d) tem um segundo `check` que **demonstra** que a ordenação textual daria o resultado errado.
- **Committed in:** `d33a44a`

### 2. O `joblib.dump` único obrigava a mexer no `_cmd_train`, que é do Task 3

- **Found during:** Task 1, gate por AST
- **Issue:** o plano diz que a contagem "passa de 1 para 1". **Medido: são 4** — dois em `train_anomaly_model.save_model` e dois em `model_registry._cmd_train:1994-1995`. Deixar o CLI com o seu próprio `dump` não fecha o gate de "exactamente 1".
- **Fix:** `_cmd_train` também passou a usar `ml_training.dump_artifacts`. É a Task 3 a ser antecipada em dois pontos, e a razão está escrita no commit: é o motor que sabe que o destino tem de estar fora do registo.
- **Committed in:** `9c8d248`

### 3. A garantia do `load_model` que falha é "cache vazia", não "nada escrito"

- **Found during:** Task 2
- **Issue:** o plano diz que um `load_model` a levantar deixa "o `metadata.json` gravado **igual** aos bytes de antes (nenhum ACTIVE escrito, nenhuma vN órfã)". Isso é impossível na ordem que o mesmo plano manda: `register_trained_version` é o que escreve o metadata **e** o `ACTIVE`, e ele corre **antes** do `load_model` por outro requirement (é o que impede `active: vN, loaded: v(N-1)`). As duas afirmações não podem ser ambas verdadeiras.
- **Fix:** o que se garante — e o que o teste mede — é a garantia que interessa: **a cache fica vazia**, o erro propaga, e a vN continua registada e listável. O registo é o dono do schema e não se desfaz por o carregamento ter falhado.
- **Verification:** `test_ml_training.py::secao_ordem_da_cache` checks (d), (e), (f) e (g)
- **Committed in:** `79320eb`

### 4. `dataset_facts` recebe dois argumentos, não três

- **Found during:** Task 1
- **Issue:** o plano passa `attack_log`. O rótulo `is_attack` já está em cada linha depois de `label_with_attack_log`; contar o log outra vez seria um segundo sítio onde o número do ataque é decidido — exactamente a divergência silenciosa que D-04 veio eliminar no catálogo.
- **Fix:** `dataset_facts(documentos, rows)`, com `attacks = sum(1 for row in rows if row.get("is_attack"))`. Decidido e escrito no docstring.
- **Committed in:** `d33a44a`

### 5. O plano refere um ficheiro de teste que não existe

- **Found during:** Task 3
- **Issue:** o `<verify>` da Task 1 e o da aceitação chamam `test_train_registry.py`. Esse ficheiro não existe no projecto — os testes do CLI `train` vivem em `test_ml_models_api.py` (`correr_cli_treino`). O comando devolve `rc=2` com "No such file or directory".
- **Fix:** o gate correu `test_ml_models_api.py`, que é onde esses testes vivem. Nenhum ficheiro foi criado para satisfazer um nome de gate.
- **Committed in:** — (é uma inexactidão do plano, não uma alteração)

### 6. `train_anomaly_model` deixou de importar `joblib`

- **Found during:** Task 1
- **Issue:** com o `save_model` a delegar, `import joblib` ficou órfão. Deixá-lo seria um convite: o ficheiro que já não faz `dump` continuaria a ter `joblib` à mão.
- **Fix:** import removido. `platform` e `tempfile`, também órfãos, **não** foram tocados — são anteriores a este plano e mexer neles seria churn alheio.
- **Committed in:** `d33a44a`

**Total deviations:** 6 (1 defeito real do plano, 1 medição errada do plano, 1 requirement internamente inconsistente, 3 decisões de âmbito)
**Impact on plan:** nenhuma mudança de âmbito. As duas primeiras são correcções que fecham os requisitos que o plano mandava fechar; a terceira é a impossibility documentada em vez de uma garantia inventada.

## Issues Encountered

- **O substituto do `train_model` chamava-se a si próprio** e a thread A morreu com `RecursionError`. A causa foi a substituição de `train_anomaly_model.train_model` por uma função que voltava a chamar `train_anomaly_model.train_model` — que já era a substituída. O sintoma foi mais útil que a excepção: apanhou logo que o substituto estava mal escrito. O mesmo aconteceu com `ml_anomalies.reset_cache` na secção 11.
- **O `DRIVE_RE` do teste estava mal escrito** (`^[A-Za-z:]` em vez de `^[A-Za-z]:`) e por isso acusava `v1` de ser um caminho. Uma dependência de teste que é silenciosamente errada é pior do que nenhuma.
- **O ficheiro de teste do teto de 8 MB tinha 680 KB.** O limite só é provado por um ficheiro que o passe; 20 000 documentos não chegam. Agora o teste escreve `MAX_EVENTS_BYTES + 16` bytes, e o check confirma que o ficheiro passou mesmo do teto antes de medir o erro.
- **`scripts/snapshots/` do utilizador NÃO está vazio** (o plano diz que está): tem `2026-09-14_16-37.json` e `real_events_2026-09-14.json`. O primeiro casa o regex do export. Todos os testes deste ficheiro definem `ML_EXPORT_DIR` explicitamente, por isso nenhum deles depende do que está lá — mas um `train_next_version()` sem argumentos na máquina do utilizador treinaria sobre esse export real, não sobre o fixture.

## User Setup Required

None. **`scripts/models/` não foi tocado**: mesmos SHA-256 (`3C2FE308…E3B106`, `007DD505…EB57FF`), mesmo mtime (2026-09-14 16:40:15), sem `v1/`, sem `ACTIVE`, sem temporários.

## Next Phase Readiness

**Pronto para o plano 10-03:**
- `ml_training.train_next_version(...)` com a assinatura já fechada; a rota é que resolve `events_path`/`attack_log_path` com `resolve_export_path(dataset)` a partir de um `Literal` e os passa.
- Os quatro `TRAINING_ERROR_CODES` prontos a traduzir em 404/422/409/500.
- `ml_training.activate_version(models_dir, version_id)` para o `POST` de activação, se o 10-03 o quiser.
- `ml_training.busy()` para um `GET` de estado, se o 10-03 quiser um sem polling (não precisa).

**Para o frontend (10-03):** o contrato está na secção acima. Nenhum código de erro novo na listagem.

**Fica por resolver (não é deste plano):**
- **`main.py:793-795`** continua a dizer que treinar é operação de CLI e nunca por HTTP. D-08 exige reescrever `docs/SECURITY.md`; a redacção de `main.py` é do agente do 10-03.
- **`docs/DATA_MODEL.md:82`** continua a dizer *"METADATA_PUBLIC_KEYS: 12 chaves"* — são 13 desde o 10-01, e o `metadata.json` em disco tem 15.
- **`docs/SECURITY.md:113-117`** ainda descreve o SHA-256 como auto-atestação de disco. Com treino por HTTP passa a ser detector de corrupção. É a reescrita que D-08 manda.

## Next Phase Readiness — o que NÃO foi verificado

- **Nenhum comando foi corrido com o laboratório Wazuh ligado.** Nada nesta mudança toca em rede. O `documents`/`processable`/`truncated`/`window_first`/`window_last` foram medidos contra o **fixture sintético** e contra ficheiros construídos pelo próprio teste — nunca contra um export real do Indexer. Só o laboratório prova que batem certo com o que `export_raw_events` gravou.
- **`POST /api/ml/train` não existe ainda.** Este plano não o cria, e portanto **o 409 nunca foi provado por HTTP** — foi provado com duas threads em Python, que é o mecanismo de que a rota vai depender.
- **A UI não foi tocada nem vista.** Nenhum ficheiro de frontend foi modificado; `node --check` passa nos dois, e é tudo o que se pode dizer sem os abrir.
- **Não se testou atraining com `n_estimators` nos extremos do tecto HTTP (10 e 1000).** O tecto é do 10-03 (`Field(ge=10, le=1000)`); aqui só se provou que um valor não-por-omissão chega ao `.pkl`.
- **O `run_all_tests.py` continua instável sob paralelismo nesta máquina** (o 10-01 mediu 2 timeouts em 5). O 39/39 é de uma execução limpa depois da última alteração, não uma garantia.

---
*Phase: 10-ml-learning-loop*
*Plan: 02*
*Completed: 2026-10-11*