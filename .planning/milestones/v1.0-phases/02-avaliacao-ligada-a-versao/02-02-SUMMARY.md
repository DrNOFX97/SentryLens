---
phase: 02-avaliacao-ligada-a-versao
plan: 02
subsystem: ml-registry
tags: [python, scikit-learn, sklearn, metrics, precision, recall, f1, dataset-origin, validation, standalone-tests, red-team]

# Dependency graph
requires:
  - phase: 02-avaliacao-ligada-a-versao (02-01)
    provides: "scripts/ml_evaluation.py com _prf/small_sample_flags/build_evaluation_report/load_events_file, os 14 EVALUATION_KEYS, e model_registry.evaluate a gravar por escrita atómica"
  - phase: fase-6-ml-anomaly-detection
    provides: "train_anomaly_model.evaluate (a referência de comparabilidade, D-04) e feature_extractor.label_with_attack_log/extract_features"
provides:
  - "scripts/test_ml_evaluation.py — suite de domínio do motor, 10 secções, sem HTTP nem CLI: números-base, identidade com o evaluate() histórico, limiares D-05 nos dois eixos, guarda labels_misaligned, PRF nos extremos, pureza, leitura de --events, origem declarada e contrato do payload"
  - "scripts/ml_evaluation.py — validate_evaluation(payload) (a segunda barreira antes do disco) e _caveat montada pela origem DECLARADA, com ORIGEM_PT e CAVEAT_TEXT_LIMIT"
  - "scripts/model_registry.py — evaluate() valida o payload antes de _write_evaluation; o except ValueError do CLI passou a evaluation_invalid"
  - "scripts/test_ml_models_api.py — caso (x): payload fora do contrato faz o CLI sair com código 1 e o metadata.json anterior fica byte-idêntico"
affects: [02-avaliacao-ligada-a-versao, r9, model-registry, ml-registry, docs/ML.md, fase-3, fase-r10]

actuals:
  tokens: 12837   # chars/4 sobre o diff real (914 inserções / 34 remoções); o estimate de 55000 era generoso
  tasks: 2
  commits: 2

# Tech tracking
tech-stack:
  added: []   # nada novo instalado — scikit-learn 1.5.2 / joblib 1.4.2 já estavam no venv
  patterns:
    - "Barreira dupla antes de escrever: o motor produz o contrato e validate_evaluation confirma-o antes de _write_evaluation tocar em disco"
    - "Texto de aviso montado por ORIGEM DECLARADA (real/synthetic/unknown), com o NOME do ficheiro e nunca o caminho, e cabendo no mesmo teto que a API aplica"
    - "Teste de subprocesso com motor adulterado por um wrapper temporário + PYTHONPATH, para provar o CLI sem trazer o teste para o processo do CLI"

key-files:
  created:
    - scripts/test_ml_evaluation.py
  modified:
    - scripts/ml_evaluation.py
    - scripts/model_registry.py
    - scripts/test_ml_models_api.py

key-decisions:
  - "Task 1 ficou com 8 das 10 secções: test_origem_declarada e test_validacao_payload testam código que a Task 2 escreve, e commitar a Task 1 com elas a vermelho era o que o plano proibia (ver Desvio 1)"
  - "CAVEAT_TEXT_LIMIT = 200 no motor, o mesmo teto de model_registry.EVALUATION_TEXT_LIMIT: se o validador exige <= 200 e a API corta a 200, o aviso tem de caber inteiro em ambos — um aviso cortado a meio perdia a ressalva que existe para ser lida"
  - "Quando o aviso de log desencontrado dispara, a parte da amostra pequena é omitida: 0 ataques é pequena por definição e a omissão é o que deixa as três origens caberem no aviso sem truncamento no caso normal"
  - "O except ValueError do CLI passou de metadata_invalid para evaluation_invalid: o metadata.json em disco está intacto, dizer que está inválido e mandar re-adotar a versão seria mentira (ver Desvio 3)"
  - "O caso (x) da API tem duas adulterações, não uma: 'falta uma das 14 chaves' passaria sem a barreira nova (o _write_evaluation do 02-01 já contava chaves), por isso a prova discriminante é o payload com as 14 chaves e uma soma que não fecha (ver Desvio 2)"

patterns-established:
  - "Números de avaliação provados por IGUALDADE dita-a-dita com a função de treino (train_anomaly_model.evaluate), não por tolerância — é o que torna a comparação com ml_training_report.json uma subtração"
  - "Guarda de alinhamento provada trocando o produto por uma função que devolve menos elementos (build_ml_anomalies_report), restaurada em finally — qualquer alteração futura ao zip de ml_anomalies.py parte o teste"
  - "Textos gerados pelo motor cortados ao mesmo teto que a API aplica, para que a verdade gravada seja a verdade que o painel mostra"

requirements-completed: [EVAL-01, EVAL-03]

coverage:
  - id: D1
    description: "build_evaluation_report sobre o fixture versionado devolve os números de docs/ML.md: 36 eventos, 5 ataques, ML 0,4286/0,6/0,5, regras 0,625/1,0/0,7692, comparação 3/4/5/24"
    requirement: EVAL-01
    verification:
      - kind: unit
        ref: "scripts/test_ml_evaluation.py#test_numeros_base (14 checks)"
        status: pass
    human_judgment: false
  - id: D2
    description: "As métricas novas são comparáveis com o ml_training_report.json: para o mesmo dataset, modelo e scaler, ml/rules/comparison são idênticos aos de train_anomaly_model.evaluate (D-04)"
    requirement: EVAL-01
    verification:
      - kind: unit
        ref: "scripts/test_ml_evaluation.py#test_comparavel_com_historico (6 checks, comparação dita-a-dita)"
        status: pass
    human_judgment: false
  - id: D3
    description: "O aviso de amostra pequena tem DOIS limiares nomeados (50 eventos OU 10 ataques) e não reusa soc_metrics.DEFAULT_MIN_SAMPLE (D-05)"
    requirement: EVAL-03
    verification:
      - kind: unit
        ref: "scripts/test_ml_evaluation.py#test_limiar_dois_eixos (10 checks, incluindo a ausência de soc_metrics no AST)"
        status: pass
    human_judgment: false
  - id: D4
    description: "A origem do dataset é sempre declarada e nunca adivinhada pelo caminho: real/synthetic/unknown dão três avisos distintos, e nenhum traz caminho (D-06, T-02-13)"
    requirement: EVAL-03
    verification:
      - kind: unit
        ref: "scripts/test_ml_evaluation.py#test_origem_declarada (13 checks)"
        status: pass
    human_judgment: false
  - id: D5
    description: "validate_evaluation fecha o contrato das 14 chaves e recusa cada incoerência (soma da comparação, métrica fora de [0,1], small_sample incoerente, origem inventada, bool como int, texto acima do teto)"
    requirement: EVAL-01
    verification:
      - kind: unit
        ref: "scripts/test_ml_evaluation.py#test_validacao_payload (15 checks)"
        status: pass
    human_judgment: false
  - id: D6
    description: "Um payload fora do contrato faz o `evaluate` sair com código 1 e deixa o metadata.json anterior byte-idêntico, sem tocar nos .pkl (T-02-12)"
    requirement: EVAL-01
    verification:
      - kind: e2e
        ref: "scripts/test_ml_models_api.py#(x) — duas adulterações do motor num processo novo, 19 checks"
        status: pass
    human_judgment: false
  - id: D7
    description: "A guarda labels_misaligned dispara quando as decisões deixam de ser paralelas aos rótulos, e nada é gravado (D-03, T-02-14)"
    requirement: EVAL-01
    verification:
      - kind: unit
        ref: "scripts/test_ml_evaluation.py#test_guarda_de_alinhamento (4 checks, com build_ml_anomalies_report trocado)"
        status: pass
    human_judgment: false
  - id: D8
    description: "O README/docs continuam a descrever o número certo: a tabela de docs/ML.md:83-91 é o dataset REAL de 500 alertas (35 eventos, 20 ataques), não o fixture sintético de 36/5 que este plano fixa como âncora — o texto de docs não foi tocado e não devia ser"
    requirement: EVAL-03
    verification: []
    human_judgment: true
    rationale: "O plano cita 'docs/ML.md:83-91' como se fossem os números sintéticos; essa tabela é a do ciclo real de 2026-09-14. A âncora sintética está correcta e verificada, mas a proveniência dos dois números em docs é decisão editorial do utilizador, não deste plano"

# Metrics
duration: ~24 min
completed: 2026-10-10
status: complete
---

# Phase 02 Plan 02: Suite do motor de avaliação e contrato do payload

**O motor de avaliação deixa de ser código por Covered e passa a ter suite própria com os números-base de `docs/ML.md` reproduzidos e comparados dita-a-dita com o `train_anomaly_model.evaluate`, os dois limiares de D-05 testados um a um, a origem do dataset escrita em três avisos distintos — e um `validate_evaluation` que recusa o payload fora do contrato antes de o registo tocar em disco.**

## Performance

- **Duration:** ~24 min
- **Started:** 2026-10-10T19:55:00+01:00
- **Completed:** 2026-10-10T20:19:00+01:00
- **Tasks:** 2
- **Files modified:** 4 (1 criado, 3 alterados; +914/-34)

## Accomplishments

- `scripts/test_ml_evaluation.py` (novo, 617 linhas): a suite de domínio que o 02-01 não trouxe — porque `test_model_registry.py` corre o registo sem carregar scikit-learn (é a propriedade que garante D-01), e um motor que mede com `sklearn.metrics` precisa de um ficheiro que os importe. Dez secções, 90 checks, sem HTTP, sem CLI, sem rede e sem o laboratório ligado.
- **Números-base provados, não afirmados:** reproduzi primeiro a tabela fora do código (36 eventos / 5 ataques, ML 0,4286/0,6/0,5, regras 0,625/1,0/0,7692, comparação 3/4/5/24) e só depois a escrevi como asserção. Bate certo com a pesquisa e com `docs/ML.md`.
- **Comparabilidade mecânica (D-04):** o mesmo dataset, modelo e scaler dão `ml`, `rules` e `comparison` **idênticos** aos de `train_anomaly_model.evaluate` — comparação dita-a-dita, sem tolerância. É isso que torna a comparação com o `ml_training_report.json` uma subtração.
- **`validate_evaluation(payload)`:** a segunda barreira antes do disco. Recusa com `ValueError` e mensagem PT que nomeia a regra — 14 chaves exactas, inteiros sem `bool`, `attacks_in_dataset <= total_events`, as quatro contagens a somar `total_events`, métricas em [0,1], `small_sample` coerente com os limiares gravados, `dataset_origin` em `DATASET_ORIGINS` e textos não vazios dentro do teto.
- **O aviso passa a dizer de onde vêm os dados (D-06):** `ORIGEM_PT` dá três textos distintos — real, sintético (com "não validados contra o laboratório") e "NÃO declarada" — com o NOME do ficheiro e nunca o caminho. O mesmo ficheiro com três origens dá três avisos, e a origem nunca é adivinhada pelo caminho.
- **Prova de que a barreira é mesmo nova:** o caso (x) da API corre o CLI num processo novo com o motor trocado por duas adulterações — uma sem uma das 14 chaves e outra com as 14 mas com `comparison` a não fechar. Verifiquei que **sem** a chamada nova o segundo caso grava o payload e o teste vai a vermelho; com ela, o CLI sai com código 1 e o `metadata.json` anterior fica byte-idêntico.

## Task Commits

Cada task foi commitada atomicamente:

1. **Task 1 — Suite própria do motor (test_ml_evaluation.py)**: `c130c52` (test)
2. **Task 2 — validate_evaluation e o caveat por origem**: `9a0d33b` (feat)

## Files Created/Modified

- `scripts/test_ml_evaluation.py` - **novo**: 10 secções de domínio, fixtures versionadas em memória com cache por módulo, `SECOES` + `run()` + `sys.exit(1)`
- `scripts/ml_evaluation.py` - `validate_evaluation`, `ORIGEM_PT`, `CAVEAT_TEXT_LIMIT`, `_caveat` reescrito (origem + cobertura + amostra, com o nome do ficheiro)
- `scripts/model_registry.py` - `ml_evaluation.validate_evaluation(evaluation)` antes de `_write_evaluation`; `except ValueError` do CLI passou a `evaluation_invalid`
- `scripts/test_ml_models_api.py` - caso (x) com wrapper temporário num processo novo e `PYTHONPATH`

## Decisions Made

- **Task 1 com 8 secções em vez de 10** (ver Desvio 1): as duas secções que testam código a escrever não podem estar num commit verde.
- **`CAVEAT_TEXT_LIMIT = 200` no motor**: o validador exige `<= 200` e a API corta a 200 (`EVALUATION_TEXT_LIMIT`). Se o motor escrevesse mais, ou o `evaluate` recusaria o seu próprio payload, ou o painel mostraria o aviso cortado a meio — e um aviso cortado a meio perde a ressalva que existe para ser lida. O motor corta com reticências como último recurso; medido: sem o aviso de cobertura, 160 a 184 caracteres para nomes de ficheiro de 23 a 38 caracteres (sem corte); com o aviso de cobertura, 193 a 200 — e aí o corte, quando acontece, só apanha o fim, porque a ordem das partes é cobertura → origem → amostra.
- **A parte da amostra pequena sai quando o aviso de log desencontrado entra**: 0 ataques é amostra pequena por definição, e era a forma de as três origens caberem no caso mais apertado. A informação não se perde: `small_sample`, `min_events` e `min_attacks` são campos.
- **`evaluation_invalid` em vez de `metadata_invalid`** na mensagem do CLI (ver Desvio 3).
- **O caso (x) tem duas adulterações** (ver Desvio 2): a que o plano descreve não distingue a barreira nova da que o 02-01 já tinha.

## Deviations from Plan

### Auto-fixed Issues

**1. [Regra: task tem de ficar verde] Task 1 com 8 das 10 secções de behaviour**
- **Found during:** Task 1 (planeamento do ficheiro de teste)
- **Issue:** o plano põe na Task 1 — que só escreve `test_ml_evaluation.py` e diz explicitamente "este ficheiro é teste, não implementação" — as secções `test_origem_declarada` (que exige três avisos distintos; o `_caveat` do 02-01 não recebe `dataset_origin`) e `test_validacao_payload` (que exige `validate_evaluation`, escrito na Task 2). Com as dez, o primeiro commit ia vermelho, contra o critério de aceitação da própria Task 1 e contra a instrução de não avançar com testes vermelhos.
- **Fix:** a Task 1 traz as oito secções que o motor do 02-01 já satisfaz; as duas restantes entram na Task 2, com o código que as faz passar. O ficheiro acaba com as dez pelo nome, como o plano exige.
- **Files modified:** `scripts/test_ml_evaluation.py`
- **Verification:** Task 1 commitada com exit 0 e 0 linhas `[FALHOU]`; o ficheiro final tem as dez secções e passa com exit 0.
- **Committed in:** `c130c52` (8 secções) + `9a0d33b` (as 2 restantes)

**2. [Regra: teste mais rigoroso do que o pedido] A prova tinha de distinguir a barreira nova**
- **Found during:** Task 2 (caso "payload inválido não grava")
- **Issue:** a adulteração que o plano descreve — um payload sem uma das 14 chaves — já é recusada pelo `_write_evaluation` do 02-01, que contava as chaves. Com essa alteração, o teste passaria com ou sem o `validate_evaluation` novo, ou seja, não provaria nada do que a Task 2 adicionou.
- **Fix:** o wrapper temporário tem dois modos. O segundo devolve as 14 chaves todas com `comparison` a somar 99 em vez de `total_events`: só o validador novo pode recusar. Rodei a suite com a chamada removida e o caso `incoerente` vai a vermelho (6 checks) — a prova é de que a barreira está mesmo a caminho.
- **Files modified:** `scripts/test_ml_models_api.py`
- **Verification:** com a chamada, 19 checks verdes; sem a chamada, `(x/incoerente)` falha a 6 checks e o payload chega a ser gravado.
- **Committed in:** `9a0d33b`

**3. [Regra: mensagem que mente] `evaluation_invalid` em vez de `metadata_invalid`**
- **Found during:** Task 2 (handler de `ValueError` do `_cmd_evaluate`)
- **Issue:** o handler existente imprimia "Erro (metadata_invalid): O metadata.json da versão é inválido ... Volta a registar a versão para o reescrever". Com a validação antes da escrita isso é falso nos dois sentidos: o ficheiro em disco está intacto (é a garantia que acabámos de ganhar) e re-adotar a versão não resolve nada, porque o problema está no payload que o motor calculou.
- **Fix:** imprime `Erro (evaluation_invalid): <a regra que falhou>`. Continua a ser exit 1 e continua a cobrir as `ValueError` do próprio `_write_evaluation` (que são, essas sim, sobre o que ia ser gravado). Nenhum teste dependia do texto antigo.
- **Files modified:** `scripts/model_registry.py`
- **Verification:** `test_model_registry.py` e `test_ml_models_api.py` verdes; o CLI imprime a regra (`caveat` em falta / `comparison` que não fecha).
- **Committed in:** `9a0d33b`

**4. [Regra: referência errada do plano] `docs/ML.md:83-91` é a tabela do dataset real**
- **Found during:** Task 1 (leitura da fonte dos números-base)
- **Issue:** o `must_have` diz que os números de 36 eventos / 5 ataques são "os mesmos números de docs/ML.md:83-91". Essa tabela é a do ciclo real de 2026-09-14 (500 alertas, 35 eventos, 20 ataques, ML 0,8571/0,3/0,4444). A tabela do fixture sintético está em `docs/ML.md:40-49`, como a pesquisa (02-RESEARCH) já dizia correctamente.
- **Fix:** nenhuma. Os números do plano estão certos e reproduzi-os antes de os testar; a referência à linha de docs é que estava errada, e nenhum ficheiro de documentação foi tocado.
- **Files modified:** nenhum
- **Verification:** reprodução verificada na venv antes de escrever o teste; `docs/ML.md` inalterado neste plano.
- **Committed in:** n/a (erro de referência no plano, não no código)

**5. [Regra: caminho errado no gate] O wrapper precisa de `PYTHONPATH`**
- **Found during:** Task 2 (primeira execução do caso (x))
- **Issue:** o wrapper vive na pasta temporária, por isso `sys.path[0]` é essa pasta e não `scripts/` — o subprocesso morria com `ModuleNotFoundError` antes de chegar ao CLI (saída 1 sem a mensagem esperada).
- **Fix:** o `subprocess.run` passa `env={**os.environ, "PYTHONPATH": str(SCRIPT_DIR)}`, o mesmo `scripts/` que o CLI normal tem em `sys.path`.
- **Files modified:** `scripts/test_ml_models_api.py`
- **Verification:** 19 checks verdes no caso (x).
- **Committed in:** `9a0d33b`

---

**Total deviations:** 5 auto-fixed (1 task não podia ficar verde como escrita, 1 teste que não provava o que devia, 1 mensagem que mentia, 1 referência errada do plano, 1 caminho errado no gate)
**Impact on plan:** Nenhuma alteração de âmbito. Nenhum ficheiro fora dos quatro do plano foi tocado, e nada foi decidido à revelia do utilizador — em particular, a lista das 14 chaves NÃO mudou (continua a mesma nos dois ficheiros, com `schema_version` a 1 e sem migração de `metadata.json` já gravados).

## Issues Encountered

- **`numpy.float64` passa como `float`:** as métricas do sklearn são `np.float64`. `validate_evaluation` exige `isinstance(valor, float)` e isso funciona porque `np.float64` é subclasse de `float` (confirmado na venv, numpy do `scikit-learn==1.5.2` do `requirements.txt`) — e o `json.dumps` do payload nunca tinha quebrado, o que já o provava. Fica escrito no docstring para ninguém "endireitar" isto para `type(valor) is float` e partir o `evaluate` em silêncio.
- **O aviso de log desencontrado + origem `unknown`** esgota o orçamento de 200 caracteres com nomes de ficheiro normais: 193 (real) a 200 (synthetic/unknown). O corte, quando há, só apanha o fim — a origem e o nome do ficheiro estão antes da parte da amostra, e a parte da amostra é a única que se sacrifica.
- **A Task 1 não precisou de mexer no motor** — os números-base, a comparabilidade com o histórico, os limiares, a guarda de alinhamento, o PRF, a pureza e a leitura de `--events` já passavam tal e qual o 02-01 os deixou. Só o que é novo (validador e origem) precisou de código, o que é o que a Task 2 trouxe.

## User Setup Required

None — nada a instalar nem a configurar. Continua válido o bloqueio conhecido do D-06: a primeira avaliação **real** precisa do exportador do 02-03 e do Wazuh Indexer ligado.

## Verification Run

Todos os comandos de `<verify><automated>` das duas tasks, com `scripts\.venv\Scripts\python.exe` (CPython 3.12.14, scikit-learn 1.5.2), Node não foi usado, **laboratório Wazuh desligado** (9200 e 55000 fechadas):

| # | Comando | Resultado |
|---|---|---|
| 1 | `test_ml_evaluation.py` (Task 1, no commit `c130c52`) | exit 0, 0 linhas `[FALHOU]`, 8 secções |
| 2 | `run_all_tests.py ml` (Task 1) | exit 0, 4/4 |
| 3 | `test_ml_evaluation.py` (final) | exit 0, 0 linhas `[FALHOU]`, 10 secções / 90 checks |
| 4 | `run_all_tests.py ml` (final) | exit 0, 4/4 |
| 5 | `test_model_registry.py` | exit 0 |
| 6 | `test_ml_models_api.py` | exit 0 |
| 7 | `test_ml_anomalies.py` | exit 0 |
| 8 | `run_all_tests.py` (completo) | exit 0, **37/37** (baseline era 36/36; +1 ficheiro, runner sem edição) |
| 9 | Gate AST: `model_registry.py` sem `joblib`/`ml_anomalies`/`fastapi`/`sklearn`/`ml_evaluation` | exit 0 (`ast-topo` = argparse, datetime, hashlib, hmac, importlib, json, os, pathlib, re, shutil, sys, tempfile, typing) |
| 10 | `def validate_evaluation` aparece 1 vez em `ml_evaluation.py` | 1 |
| 11 | `validate_evaluation` dentro de `evaluate()` em `model_registry.py` | linha 1078 |
| 12 | Mutação: remover a chamada e correr `test_ml_models_api.py` | **FALHOU** em 6 checks do `(x/incoerente)` — a prova é de que a barreira está a caminho (esperado; ficheiro reposto de seguida) |

`scripts/models/` intacto: só `isolation_forest.pkl` (539673 B, sha256 `3C2FE308…`) e `scaler.pkl` (767 B, sha256 `007DD505…`), com a data de modificação original de 2026-09-14. Nenhum `.pkl` novo, nenhum `v1/`, nenhum `ACTIVE`, nenhum temporário.

## Next Phase Readiness

- **Pronto para 02-03** (exportador do dataset real, D-06): o motor já expõe `summarize_events` (total/processáveis), `load_events_file` com `MAX_EVENTS_BYTES`, e o `evaluate` aceita `--dataset-origin` com três valores — o exportador escreve o ficheiro e o comando seginte mede sobre ele sem mais código.
- **Pronto para 02-04** (concordância ao vivo, D-10): sem trabalho novo do meu lado; a aba Evaluation continua a mostrar o `caveat` que agora traz a origem.
- **Risco residual por sinalizar:** a lista das 14 chaves continua escrita à mão em dois ficheiros (motor e registo). **Não a mudei** — mudar obrigaria a migrar os `metadata.json` já gravados, com `schema_version` a 1. `test_ml_models_api.py#(s)` continua a prender a igualdade das duas listas.
- **Aviso de texto para o 02-04:** `EVALUATION_TEXT_LIMIT` (200) é um contrato partilhado com o motor agora. Se algum dia subir, o `CAVEAT_TEXT_LIMIT` do motor tem de subir com ele ou o `evaluate` passa a recusar payloads válidos.
- **Pendente de humano:** nada foi corrido sobre dados reais — o Indexer continua desligado.

---
*Phase: 02-avaliacao-ligada-a-versao*
*Completed: 2026-10-10*
