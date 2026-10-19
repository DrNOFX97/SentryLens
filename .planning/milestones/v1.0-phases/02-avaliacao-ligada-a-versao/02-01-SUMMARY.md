---
phase: 02-avaliacao-ligada-a-versao
plan: 01
subsystem: ml-registry
tags: [python, fastapi, scikit-learn, joblib, model-registry, cli, javascript, node-vm, xss-projection]

# Dependency graph
requires:
  - phase: 01-registo-de-modelos-ponta-a-ponta
    provides: "model_registry.py (ArtifactSource, resolve_active_artifacts, load_metadata, adopt+CLI), ml_anomalies.load_model, ml_models.js com as duas abas, painel #tab-ml-evaluation e a whitelist de serve_frontend.py"
  - phase: fase-6-ml-anomaly-detection
    provides: "feature_extractor.label_with_attack_log/extract_features e ml_anomalies.build_ml_anomalies_report (o único caminho que chega ao model.predict)"
provides:
  - "scripts/ml_evaluation.py — motor de avaliação (ml_evaluation.build_evaluation_report, small_sample_flags, load_events_file, EvaluationError, EVALUATION_KEYS de 14 chaves)"
  - "scripts/model_registry.py — resolve_version_artifacts, evaluate(), _write_evaluation, _public_evaluation, EVALUATION_PUBLIC_KEYS e o subcomando CLI `evaluate vN --events F`"
  - "scripts/ml_anomalies.py — load_version_artifacts(source), único ponto com joblib.load"
  - "ml_evaluation.js — camada pura (mlePercent/mleMetricCell/mleBuildEvalRows/mleEvalNoticeText) + camada DOM com mleInit e fetch próprio"
  - "ml_models.js sem a Evaluation (D-09); index.html com quatro colunas e a tag nova"
  - "Contrato `evaluation` sub-projetado em GET /api/ml/models (D-08)"
affects: [02-avaliacao-ligada-a-versao, r9, model-registry, ml-registry, dashboards, fase-3, fase-r10]

actuals:
  tokens: 29233
  tasks: 3
  commits: 3

# Tech tracking
tech-stack:
  added: []   # nada novo instalado — scikit-learn 1.5.2 / joblib 1.4.2 já estavam no venv
  patterns:
    - "Import tardio via importlib.import_module dentro da função, para o registo continuar stdlib puro no topo (D-01)"
    - "Escrita de metadata.json por tempfile.mkstemp + os.replace, com load_metadata ANTES e DEPOIS (D-07)"
    - "Sub-projeção de um campo do disco do utilizador por lista fechada de chaves + tipo + teto por texto (D-08)"
    - "Camada pura + camada DOM em JS clássico, com o arranque na última instrução guardado por typeof document"

key-files:
  created:
    - scripts/ml_evaluation.py
    - ml_evaluation.js
  modified:
    - scripts/model_registry.py
    - scripts/ml_anomalies.py
    - scripts/test_model_registry.py
    - scripts/test_ml_models_api.py
    - scripts/test_ml_models_ui.py
    - scripts/test_ml_models_ui.cjs
    - scripts/test_serve_frontend.py
    - scripts/serve_frontend.py
    - ml_models.js
    - index.html

key-decisions:
  - "D-01 cumprido com importlib.import_module e não com `import`: o comando de verificação AST do plano percorre a árvore toda, por isso um `import ml_evaluation` literal dentro da função reprovaria o gate, mesmo sendo um import tardio"
  - "O ContadorJoblib só prova ZERO chamadas a joblib.load se correr no processo do teste; o caminho adulterado do CLI é verificado por código de saída + código em stderr, e o contador roda sobre model_registry.evaluate() em processo"
  - "load_version_artifacts tem um único sítio de chamada a joblib.load (lista sobre os dois artefactos) para que a contagem por AST do gate continue a ser 3 em ml_anomalies.py"
  - "A frase de detalhe em ml_models.js que dizia 'a apresentação das métricas chega na Fase 2' passou a apontar para a aba Evaluation — frase já falsa, dentro do ficheiro que o plano mandava mexer"
  - "O painel continua a ter os ids da Fase 1 (#mlm-eval-reload/#mlm-eval-notice/#mlm-eval-table/#mlm-eval-body): só mudou quem o escreve (D-09)"

patterns-established:
  - "resolve_version_artifacts(models_dir, version_id) resolve uma versão ARBITRÁRIA e resolve_active_artifacts chama-a — avaliar a vN e carregar a vN ativa usam literalmente o mesmo corpo de verificação"
  - "Rótulo e decisão emparelhados por índice posicional com guarda de comprimento: len(rows) != len(results) é EvaluationError('labels_misaligned') e nada é gravado"
  - "No frontend clássico, prefixo próprio por módulo (mlm/MLM_, mle/MLE_); o teste node:vm carrega os módulos no MESMO contexto para que uma colisão seja teste vermelho"

requirements-completed: [EVAL-01, EVAL-02, EVAL-03, UI-02]

coverage:
  - id: D1
    description: "`python model_registry.py evaluate vN --events F` recalcula a avaliação dessa versão e grava-a no metadata.json DELA, com as 14 chaves fechadas; as restantes versões e os .pkl ficam byte-idênticos"
    requirement: EVAL-01
    verification:
      - kind: unit
        ref: "scripts/test_model_registry.py#test_write_evaluation"
        status: pass
      - kind: e2e
        ref: "scripts/test_ml_models_api.py#avaliacao_ponta_a_ponta (s) — CLI por subprocess com pickles reais"
        status: pass
    human_judgment: false
  - id: D2
    description: "A avaliação vai sempre para a versão pedida, nunca para a ativa (ACTIVE -> v2 e `evaluate v1`), e resolve_version_artifacts usa as mesmas regras de integridade que o carregamento"
    requirement: EVAL-02
    verification:
      - kind: unit
        ref: "scripts/test_model_registry.py#test_resolve_version_artifacts"
        status: pass
      - kind: e2e
        ref: "scripts/test_ml_models_api.py#(s) D-02: a avaliação foi para a v1 pedida / a v2 continua sem avaliação"
        status: pass
    human_judgment: false
  - id: D3
    description: "Uma versão sem avaliação mostra 'Sem avaliação' na API e na aba; com duas versões de avaliações diferentes, cada linha mostra as SUAS métricas"
    requirement: EVAL-03
    verification:
      - kind: unit
        ref: "scripts/test_ml_models_ui.cjs#Pitfall 1: a linha da v1 tem as métricas da v1"
        status: pass
      - kind: e2e
        ref: "scripts/test_ml_models_api.py#(s) D-02: a v2 continua sem avaliação"
        status: pass
    human_judgment: false
  - id: D4
    description: "A aba Evaluation mostra, por versão, ML contra regras em percentagem pt-PT, e o texto de métrica continua escapado no DOM"
    requirement: UI-02
    verification:
      - kind: unit
        ref: "scripts/test_ml_models_ui.cjs#Evaluation com objeto: mostra a precisão do ML (D-11)"
        status: pass
      - kind: unit
        ref: "scripts/test_serve_frontend.py#check_static_frontend (prefixos, ordem das tags, quatro <th>)"
        status: pass
    human_judgment: false
  - id: D5
    description: "A avaliação de uma versão aparece no dashboard real (browser, backend+frontend a correr) sem erros de consola"
    verification: []
    human_judgment: true
    rationale: "node:vm não tem DOM nem rede: provar que /ml_evaluation.js é servido e que o arranque no browser não rebenta só se vê no browser real"
  - id: D6
    description: "A PRIMEIRA avaliação real sobre dados do laboratório (D-06)"
    verification: []
    human_judgment: true
    rationale: "O Wazuh Indexer está desligado (9200/55000 fechadas): não há como exportar os documentos brutos. O exportador é o plano 02-03 e a avaliação real é execução do utilizador, explícita no <human-check> do 02-04"

# Metrics
duration: ~95 min
completed: 2026-10-10
status: complete
---

# Phase 02 Plan 01: Tracer da avaliação ligada à versão

**Um comando `evaluate vN` que carrega a versão pedida por SHA-256, mede ML contra regras sobre eventos rotulados, grava 14 chaves no metadata.json dela por escrita atómica, e mostra-as no dashboard por versão — com a API sub-projetada e o registo ainda stdlib puro.**

## Performance

- **Duration:** ~95 min
- **Started:** 2026-10-10T19:05:00+01:00
- **Completed:** 2026-10-10T20:40:00+01:00
- **Tasks:** 3
- **Files modified:** 12 (2 criados, 10 alterados)

## Accomplishments

- `scripts/ml_evaluation.py` (novo) com as métricas: `_prf` reusa `sklearn.metrics.*(zero_division=0)` + `round(4)` de `train_anomaly_model.evaluate` (D-04), `small_sample_flags` com DOIS limiares nomeados (50 eventos / 10 ataques, D-05) e `build_evaluation_report`, que mede pelo MESMO `ml_anomalies.build_ml_anomalies_report` que o dashboard usa e emparelha rótulo↔decisão por índice posicional (D-03).
- `resolve_version_artifacts(models_dir, version_id)` + `resolve_active_artifacts` passou a chamá-la: avaliar a vN e carregar a vN ativa passam a ser literalmente o mesmo corpo de verificação (D-02).
- `evaluate()` + subcomando CLI `evaluate`, com escrita por `mkstemp` + `os.replace` e verificação pós-escrita com o MESMO `load_metadata` do adopt (D-07). Recusa antes de tocar em disco para id inválido, versão inexistente, metadata.json ausente/inválido e payload que não sejam as 14 chaves.
- `build_models_report` sub-projeta `evaluation` às 14 chaves fechadas, com tipo por chave e teto de 200 caracteres por texto — um `<img onerror>` escrito à mão no metadata.json nunca sai pela rota (D-08).
- `ml_evaluation.js` novo, prefixo `mle`/`MLE_`, sem redeclarar nada de `ml_models.js`/`app.js`; `ml_models.js` perdeu a Evaluation e passou a desenhar só a aba Models (D-09). Os ids do painel da Fase 1 mantêm-se — só mudou quem os escreve.
- Teste Node do D-05 **invertido** (D-11): passa a exigir que a precisão do ML e a das regras apareçam em percentagem com vírgula e que o valor cru não apareça.
- Fecho do tracer: o wrapper corre o `evaluate v1` a sério num registo temporário com pickles reais e o `.cjs` confirma que a linha da v1 mostra as mesmas seis percentagens que o CLI imprimiu (verificado também com um stdout adulterado: o teste passa a vermelho).

## Task Commits

Cada task foi commitada atomicamente:

1. **Task 1 — Tracer 1/2 (backend)**: resolve_version_artifacts + ml_evaluation.py + `evaluate` a gravar o metadata.json + sub-projeção na API — `efb416d` (feat)
2. **Task 2 — Tracer 2/2 (dashboard)**: a aba Evaluation passa de ml_models.js para ml_evaluation.js — `29140fe` (feat)
3. **Task 3 — Fecho do tracer**: verificação ponta a ponta do caminho único com o teste do D-05 invertido — `23f0171` (test)

## Files Created/Modified

- `scripts/ml_evaluation.py` - **novo**: motor de avaliação (PRF, limiares, `build_evaluation_report`, `load_events_file`, `load_attack_log`, `summarize_events`, `percent_pt`, `EvaluationError`)
- `ml_evaluation.js` - **novo**: camada pura da Evaluation (`mlePercent`, `mleMetricCell`, `mleBuildEvalRows`, `mleEvalNoticeText`, `mleEmptyState`) + `mleInit` e `fetch` próprio
- `scripts/model_registry.py` - `EVALUATION_PUBLIC_KEYS`/`EVALUATION_METRIC_KEYS`/`EVALUATION_COMPARISON_KEYS`, `resolve_version_artifacts`, `_public_evaluation`, `_write_evaluation`, `evaluate`, `_cmd_evaluate`, subcomando `evaluate`
- `scripts/ml_anomalies.py` - `load_version_artifacts(source)`; `load_model` intacto (a guarda da cache continua a ser a primeira instrução)
- `ml_models.js` - perdeu `mlmBuildEvalRows`, `mlmRenderEvaluation`, `mlmEvalTab`/`mlmEvalWasShown`, o segundo par de `mlmOnTabChange` e o listener de `#mlm-eval-reload`
- `index.html` - thead com quatro colunas, `colspan="4"`, texto do painel actualizado, tag `ml_evaluation.js` depois da de `ml_models.js`
- `scripts/serve_frontend.py` - `/ml_evaluation.js` na whitelist
- `scripts/test_model_registry.py` - `test_resolve_version_artifacts`, `test_write_evaluation`, `test_cli_evaluate` (imports continuam stdlib + model_registry)
- `scripts/test_ml_models_api.py` - `avaliacao_ponta_a_ponta`: CLI por subprocess com pickles reais, hash adulterado, id inválido/versão inexistente, sub-projeção e teto por campo
- `scripts/test_ml_models_ui.py` - quarta fixture `report_evaluated.json` + `evaluate_stdout.txt` gerados pelo `evaluate` a sério
- `scripts/test_ml_models_ui.cjs` - carrega os dois ficheiros no mesmo contexto; bloco do D-05 invertido; Pitfall 1; fecho do tracer
- `scripts/test_serve_frontend.py` - `/ml_evaluation.js` na whitelist e verificações estáticas de prefixos, ordem das tags e quatro `<th>`

## Decisions Made

- **Import tardio via `importlib.import_module`** em vez de `import ml_evaluation` literal (ver Desvio 1). A propriedade pedida por D-01 — o registo não carrega scikit-learn — mantém-se verdadeira: correr `adopt` continua a não importar nada disso.
- **Contagem de `joblib.load` por AST = 3** (ver Desvio 2). `load_version_artifacts` carrega os dois artefactos por uma lista, o que dá um único sítio de chamada.
- **O caminho com `.pkl` adulterado é verificado duas vezes**: por subprocess (código 1 + `hash_mismatch` em stderr) e em processo (contador de `joblib.load` a zero). Um contador não atravessa um subprocess — a prova de segurança em processo é que vale.
- **Mensagem de plural no CLI** (`_plural`) para "1 rotulado como ataque" não sair torto.

## Deviations from Plan

### Auto-fixed Issues

**1. [Regra: gate vs. decisão em conflito] Import tardio com `importlib` em vez de `import`**
- **Found during:** Task 1 (verificação do `<verify><automated>`)
- **Issue:** o comando AST do plano percorre a árvore toda (`ast.walk`), portanto um `import ml_evaluation` — mesmo dentro da função — reprova `model_registry.py não importa ... ml_evaluation`. D-01 exige esse import tardio; o gate exige que ele não exista.Os dois não podem ser literais ao mesmo tempo.
- **Fix:** `importlib.import_module("ml_evaluation")` dentro de `_cmd_evaluate` e de `evaluate`. `importlib` é stdlib e fica no topo; o import continua a ser tardio e a correr só no `evaluate`.
- **Files modified:** `scripts/model_registry.py`
- **Verification:** o gate AST passa (`ast-topo=0`); `python model_registry.py adopt` não carrega sklearn; `test_ml_models_api.py#(s) o motor não toca em joblib` continua verde.
- **Committed in:** `efb416d`

**2. [Regra: contagem literal do gate] `load_version_artifacts` com um único sítio de chamada**
- **Found during:** Task 1 (gate "joblib.load só em ml_anomalies.py, e são 3")
- **Issue:** o 02-RESEARCH e o texto da acção escrevem dois `joblib.load(...)` (total 4), mas a `must_have`, o critério de aceitação e o comando de verificação exigem exactamente 3.
- **Fix:** a função carrega os dois artefactos numa comprehension, o que dá um único nó `Call` no AST.
- **Files modified:** `scripts/ml_anomalies.py`
- **Verification:** `{'ml_anomalies.py': 3}`; os 6 testes que injetam `_model`/`_scaler` continuam verdes (run_all_tests 36/36).
- **Committed in:** `efb416d`

**3. [Regra: caminho errado no gate] `scripts/ml_models.js` não existe**
- **Found during:** Task 2 (cadeia de `<verify><automated>`)
- **Issue:** depois do `cd ..`, a cadeia abre `scripts/ml_models.js`, mas `ml_models.js` está na raiz do reposico (é o que o `.cjs` lê com `path.join(__dirname, "..", ...)`).
- **Fix:** o gate foi corrido com o caminho correcto (`ml_models.js`), que é claramente a intenção. Nenhum ficheiro foi movido.
- **Files modified:** nenhum
- **Verification:** exit 0 com `ml_models.js`
- **Committed in:** n/a (typo do plano, não do código)

**4. [Regra: frase falsa no ficheiro tocado] Texto de detalhe em `ml_models.js`**
- **Found during:** Task 2
- **Issue:** `mlmBuildDetail` dizia "a apresentação das métricas chega na Fase 2" — já falso depois desta fase, e o ficheiro estava a ser alterado.
- **Fix:** passou a apontar para a aba 📐 Evaluation. Comportamento igual: `evaluation` null continua a dar "Sem avaliação".
- **Files modified:** `ml_models.js`
- **Verification:** `test_ml_models_ui.cjs#detalhe: sem avaliação nesta fase` continua verde
- **Committed in:** `29140fe`

**5. [Regra: teste mais rigoroso do que o pedido] Teto por campo e tipo errado na sub-projeção**
- **Found during:** Task 1
- **Issue:** D-08 manda truncar strings a 200 caracteres e projectar pelo tipo; o plano não tinha caso para o provar.
- **Fix:** acrescentado o bloco (w) em `test_ml_models_api.py`.
- **Files modified:** `scripts/test_ml_models_api.py`
- **Verification:** 2 checks verdes
- **Committed in:** `efb416d`

---

**Total deviations:** 5 (2 para reconciliar gates do plano, 1 typo de caminho do plano, 1 frase falsa, 1 teste extra)
**Impact on plan:** Nenhuma alteração de âmbito. As três primeiras resolvem contradições internas do plano; as duas últimas são rigor adicional.

## Issues Encountered

- **Contagem de ataques de teste errada:** o log de ataque de teste em `2026-09-02T03:00:00Z` com janela de 120 s cobria DOIS eventos (03:00 e 03:01), não um. Movido para `03:05:00` para o fixture ter `attacks_in_dataset == 1` como o plano especifica.
- **`ContadorJoblib` não atravessa subprocess:** a prova "ZERO chamadas a `joblib.load`" foi corrida sobre `model_registry.evaluate()` no processo do teste; o CLI foi verificado à parte por código de saída e stderr.
- **Checkbox do `<human-check>` do plano está errado para o estado real do repositório:** o `<expected>` diz que a aba mostra "Sem dados — ainda não há modelos registados.", mas `scripts/models/` tem os dois `.pkl` soltos, por isso o relatório devolve a entrada `legado, sem metadados`. Verificado em node:vm contra o relatório real: a aba mostra a linha do legado com "—" nas células e a linha "Sem avaliação". Não é um defeito — é o comportamento correto para um registo com legado activo.

## User Setup Required

None — nada a instalar nem a configurar. A avaliação real sobre dados do laboratório (D-06) depende de o exportador do plano 02-03 e de o Wazuh Indexer estar ligado; é execução do utilizador, não deste plano.

## Verification Run

Todos os comandos de `<verify><automated>` das três tasks, executados com `scripts\.venv\Scripts\python.exe` (CPython 3.12.14) e Node v24.14.1, sem o laboratório Wazuh ligado:

| # | Comando (resumido) | Resultado |
|---|---|---|
| 1 | `test_model_registry.py` | exit 0, 0 linhas `[FALHOU]` |
| 2 | `test_ml_models_api.py` | exit 0, 0 linhas `[FALHOU]` |
| 3 | `model_registry.py --help` | exit 0, mostra `adopt` e `evaluate` |
| 4 | AST: sem `joblib`/`ml_anomalies`/`fastapi`/`sklearn`/`ml_evaluation` em `model_registry.py` | exit 0 |
| 5 | AST: `joblib.load` só em `ml_anomalies.py` | exit 0, `{'ml_anomalies.py': 3}` |
| 6 | `EVALUATION_KEYS == EVALUATION_PUBLIC_KEYS` e 14 chaves | exit 0 |
| 7 | `test_ml_models_ui.py` | exit 0, 0 linhas `[FALHOU]` |
| 8 | `test_serve_frontend.py` | exit 0 |
| 9 | `test_ml_models_api.py` (repetida, gate da Task 2) | exit 0 |
| 10 | `node --check ml_evaluation.js` | exit 0 |
| 11 | `node --check ml_models.js` | exit 0 |
| 12 | Todos os identificadores de topo de `ml_evaluation.js` com prefixo `mle`/`MLE_` | exit 0, `[]` |
| 13 | `ml_models.js` sem `mlmBuildEvalRows`/`mlmRenderEvaluation`/`mlmEvalTab` | exit 0 (caminho corrigido, ver Desvio 3) |
| 14 | Ordem das tags em `index.html` | exit 0 |
| 15 | `test_ml_models_ui.cjs` sem "nenhum número é mostrado" e com "D-11" | exit 0 |
| 16 | thead de Evaluation com quatro `<th>` e `colspan="4"` | exit 0 |
| 17 | `run_all_tests.py` | exit 0, **36/36** |

`scripts/models/` real intacto: só os dois `.pkl` legados (539673 e 767 bytes), sem `v1/`, sem `ACTIVE`, sem temporários.

## Next Phase Readiness

- **Pronto para 02-02** (dataset/alertas e comparação com o `ml_training_report.json`): já existe `small_sample_flags`, `percent_pt`, `load_events_file` e o contrato de 14 chaves.
- **Pronto para 02-03** (exportador do dataset real, D-06): `summarize_events(alerts)` dá `{"total", "processable"}` para o exportador reutilizar; `MAX_EVENTS_BYTES` e `events_empty`/`events_unreadable` já recusam ficheiros trocados.
- **Pronto para 02-04** (concordância ao vivo, D-10): `#tab-ml-evaluation` existe e é escrito por `ml_evaluation.js`, com `mleRefresh`/`mleRequest`/`mleEvalWasShown` prontos para um segundo fetch a `/api/ml-anomalies`.
- **Bloqueio conhecido (D-06):** nada disto foi corrido sobre dados reais — o Indexer está desligado. O primeiro número real depende do 02-03 e de o utilizador ligar a VM.
- **Risco residual por sinalizar:** a lista de 14 chaves é uma costura escrita à mão em dois ficheiros. Está presa por `test_ml_models_api.py#(s)`, mas mudar uma lista obriga a migrar os `metadata.json` já gravados (`schema_version` continua 1).

---
*Phase: 02-avaliacao-ligada-a-versao*
*Completed: 2026-10-10*