---
phase: 10-ml-learning-loop
plan: 01
subsystem: testing
tags: [ml, registry, metadata, provenance, catalog-hash, compare-and-set, security]

# Dependency graph
requires:
  - phase: 03-treino-gera-versoes-testes-e-documentacao
    provides: "build_trained_metadata, register_trained_version, _write_active_atomic e a suite de registo (que correria 3 das suas secções mortas)"
  - phase: 02-avaliacao-ligada-a-versao
    provides: "_public_evaluation como molde de sub-projecao, EVALUATION_PUBLIC_KEYS e a costura das listas escritas a mao"
provides:
  - "catalog_sha256() -- SHA-256 do catalogo de features (D-04), com import tardio de event_catalog"
  - "catalog_compatible: true|false|null por versao em build_models_report, sem mexer em status/error_code"
  - "catalog_sha256 gravado no metadata.json (opcional na leitura) e exposto em metadata"
  - "dataset com 9 chaves (D-02): documents/processable/truncated/window_first/window_last"
  - "feature_stats (D-03): media e desvio por feature NO LOTE DE TREINO, gravados e sub-projectados"
  - "_public_dataset e _public_feature_stats -- fecha T-10-01 (o dataset saia CRU desde a Fase 3)"
  - "_write_active_atomic(root, vid, expected=None) -> bool com compare-and-set"
  - "test_catalog_sha256, test_dataset_com_proveniencia e test_write_active_cas; 362 -> 497 checks"
affects: [10-02-motor-de-treino, 10-03-http-e-frontend, ml-training, ml_models.js, DATA_MODEL.md]

# Actuals (#2632) — pares com o `estimate` do plano para calibrar os futuros.
actuals:
  tokens: 18007
  tasks: 2
  commits: 2

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Sub-projecao como barreira de dados nao confiaveis: lista fechada + projecao por tipo + truncagem, com `Nunca levanta` no docstring"
    - "Lista fechada replicada a mao em dois ficheiros, presa por comparacao num teste (EVALUATION_KEYS vs EVALUATION_PUBLIC_KEYS, agora tambem FEATURE_NAMES vs feature_stats)"
    - "Compare-and-set como primitiva que DEVOLVE a decisao e nao a toma -- quem traduz em HTTP e o chamador"
    - "Import de dominio sempre por importlib.import_module dentro da funcao, nunca no topo, verificado por gate por AST"

key-files:
  created: []
  modified:
    - "scripts/model_registry.py"
    - "scripts/test_model_registry.py"

key-decisions:
  - "A incompatibilidade de catalogo publica-se como `catalog_compatible` ADITIVO e nunca como `status` novo: mistura-integridade-vs-senso, obrigaria a um codigo novo em ERROR_CODES e partiria o badge que o frontend ja desenha."
  - "ERROR_CODES fica com as mesmas 9 chaves pela mesma ordem. Os erros do R10 nascem em ml_training.TRAINING_ERROR_CODES (plano 10-02), o mesmo padrao de ml_evaluation.EVALUATION_ERROR_CODES."
  - "METADATA_PUBLIC_KEYS ganha catalog_sha256 (13 chaves); feature_stats fica FORA da tupla e e projectado a parte, para que os dois numeros que o plano fixa em gates (13 e 14) se cumpram. Ver 'Deviations from Plan'."
  - "`expected=None` significa 'nao compares', nao 'tem de estar ausente' -- e o que os quatro chamadores existentes passam, logo o CLI fica byte a byte igual."
  - "`_catalog_compatible(meta, hash_catalogo)` recebe o hash ja calculado: uma pasta vazia nao paga o import de event_catalog e uma pasta com N versoes nao paga N hashes."
  - "O compare-and-set devolve False e nao levanta; um ACTIVE ilegivel e fail-closed (propaga invalid_version_id sem escrever)."

patterns-established:
  - "Sub-projecao por lista fechada: `_public_dataset` e `_public_feature_stats` reusam `_public_evaluation_scalar` em vez de copiar a logica de tipo (DATASET_TEXT_LIMIT == EVALUATION_TEXT_LIMIT)"
  - "Nome novo de dominio em disco e sempre OPCIONAL na leitura; e a sub-projecao que garante a lista fechada, nunca uma exigencia nova em load_metadata"
  - "Medir o limite em vez de o esconder: os NOMES das features nao podem ser fechados (FEATURE_NAMES nao e importavel), e ha um teste que diz isso em voz alta"

requirements-completed: [D-04, SEC-01, API-02, TST-01]

# Coverage metadata (#1602)
coverage:
  - id: D1
    description: "Task 1 (ja estava feita em 61ef024, verificada aqui): run() chama as quatro secoes que nunca corriam e cada caso tem a sua pasta -- 331 -> 362 checks"
    requirement: TST-01
    verification:
      - kind: unit
        ref: "scripts/test_model_registry.py::run (gate 'mortas: []')"
        status: pass
      - kind: unit
        ref: "scripts/test_model_registry.py -- 362 checks, 0 [FALHOU]"
        status: pass
    human_judgment: false
  - id: D2
    description: "D-04: catalog_sha256() mede o _EVENT_ID_ORDER e nada mais; determinismo na sessao e entre processos; adicionar um Event ID muda-o, mudar um nome nao"
    requirement: D-04
    verification:
      - kind: unit
        ref: "scripts/test_model_registry.py::test_catalog_sha256"
        status: pass
    human_judgment: false
  - id: D3
    description: "D-04: build_models_report publica catalog_compatible true/false/null por versao sem mexer em status/error_code; a versao sem a chave continua a listar"
    requirement: D-04
    verification:
      - kind: unit
        ref: "scripts/test_model_registry.py::test_dataset_com_proveniencia (as tres versoes na mesma resposta)"
        status: pass
    human_judgment: false
  - id: D4
    description: "D-02: dataset com 9 chaves distingue '35 de 500' de '35 de 35'; as 4 antigas mantem os mesmos valores"
    requirement: D-02
    verification:
      - kind: unit
        ref: "scripts/test_model_registry.py::test_dataset_com_proveniencia"
        status: pass
      - kind: integration
        ref: "scripts/test_ml_models_api.py (o metadata das fixtures antigas continua a validar)"
        status: pass
    human_judgment: false
  - id: D5
    description: "D-03: feature_stats grava media/desvio das 7 features no lote; recusado antes de qualquer escrita quando malformado"
    requirement: D-03
    verification:
      - kind: unit
        ref: "scripts/test_model_registry.py::test_dataset_com_proveniencia (pins FEATURE_NAMES + 8 recusas)"
        status: pass
    human_judgment: false
  - id: D6
    description: "T-10-01: o dataset e o feature_stats deixam de sair CRU; sub-projecao por lista fechada, por tipo e truncada"
    requirement: SEC-01
    verification:
      - kind: unit
        ref: "scripts/test_model_registry.py::test_dataset_com_proveniencia (o metadata.json escrito a mao com 'rodao')"
        status: pass
    human_judgment: false
  - id: D7
    description: "Retrocompatibilidade: um metadata.json sem as chaves novas continua a validar e a listar, com schema_version ainda a 1 e sem migracao do disco do utilizador"
    requirement: SEC-01
    verification:
      - kind: unit
        ref: "scripts/test_model_registry.py::test_dataset_com_proveniencia (pins 'retro')"
        status: pass
      - kind: integration
        ref: "scripts/run_all_tests.py -- 38/38 medidos depois da ultima alteracao"
        status: pass
    human_judgment: false
  - id: D8
    description: "Compare-and-set em _write_active_atomic: com expected que nao bate nao escreve, nao deixa temporarios e o CLI fica inalterado"
    requirement: SEC-01
    verification:
      - kind: unit
        ref: "scripts/test_model_registry.py::test_write_active_cas (14 casos)"
        status: pass
      - kind: unit
        ref: "gate por AST: adopt/_resume_adoption/register_trained_version sem diferencas de CODIGO contra HEAD"
        status: pass
    human_judgment: false
  - id: D9
    description: "A lista fechada ERROR_CODES nao cresceu: 9 chaves pela mesma ordem, com MESSAGES_PT a cobrir todas, e o teste de contagem do .cjs segue verde"
    requirement: API-02
    verification:
      - kind: unit
        ref: "gate: (9,13,9,2,32) e set(MESSAGES_PT)==set(ERROR_CODES)"
        status: pass
      - kind: automated_ui
        ref: "scripts/test_ml_models_ui.py (D06_CODES.length === 9, sem alteracao)"
        status: pass
    human_judgment: false
  - id: D10
    description: "O registo continua stdlib puro no topo e scripts/models/ intacto (nenhum teste escreve no disco do utilizador)"
    requirement: SEC-01
    verification:
      - kind: unit
        ref: "gate por AST do topo + contagem de joblib.load == {ml_anomalies.py: 3}"
        status: pass
      - kind: unit
        ref: "gate de scripts/models/ == ['isolation_forest.pkl','scaler.pkl'] com SHA-256 e mtime identicos a antes"
        status: pass
    human_judgment: false
  - id: D11
    description: "A decisao sobre quais versoes ficam projectadas para o frontend (o desvio aritmetico do plano) e o que o .cjs tem de saber ler"
    verification:
      - kind: manual_procedural
        ref: "ml_models.js / ml_evaluation.js -- nenhum bloco novo foi aqui; ver 'Contrato novo para o frontend'"
        status: unknown
    human_judgment: true
    rationale: "Este plano nao toca em frontend. O que a UI faz com `catalog_compatible` e com as 5 chaves novas do `dataset` e com o `feature_stats` e do agente do frontend; aqui so se garante que o contrato sai correcto, testado."

# Metrics
duration: 95min
completed: 2026-10-11
status: complete
---

# Phase 10, Plan 01: Registo com proveniencia e compare-and-set

**O registo passa a dizer de onde vieram os dados e com que catalogo de features o modelo foi treinado, e o `ACTIVE` passa a ter escrita condicionada — sem acrescentar um unico codigo a `ERROR_CODES`.**

## Performance

- **Duration:** ~95 min (Task 1 ja estava feita e verificada; Tasks 2 e 3 executadas)
- **Tasks:** 2 de 3 (a Task 1 foi executada e commitada em `61ef024`, antes deste plano correr)
- **Files modified:** 2
- **Checks:** `test_model_registry.py` 331 -> **497** (362 antes da Task 1, 457 depois da Task 2)

## Accomplishments

- **`catalog_sha256()` (D-04)** — o SHA-256 do catalogo de features, gravado com a versao e verificado na listagem. Mede o `_EVENT_ID_ORDER` e o bucket do Event ID desconhecido e **nada mais**: o teste prova que acrescentar um Event ID o muda e que mudar so um `name`/`severity` nao. Determinismo medido na sessao **e entre processos**.
- **`catalog_compatible: true|false|null` em cada `versions[]`** (D-04) — aditivo, e `status`/`error_code` ficam intactos. As tres versoes (bate / nao bate / sem a chave) aparecem na mesma resposta, todas com `status "ok"`.
- **`dataset` de 4 para 9 chaves** (D-02) — `documents`/`processable`/`truncated`/`window_first`/`window_last` distinguem "35 processaveis de 500 documentos" de "35 processaveis de 35". As 4 antigas saem com os mesmos valores, por isso o `ml_models.js` nao se parte.
- **`feature_stats` (D-03)** — media e desvio das 7 features **no lote de treino**, recusado antes de qualquer escrita quando malformado.
- **T-10-01 fechado**: o `dataset` era CRU na API desde a Fase 3. `_public_dataset`/`_public_feature_stats` projectam pelas listas fechadas, por tipo e truncadas. Um `metadata.json` escrito a mao com uma chave `rodao` deixa de a expor.
- **Compare-and-set em `_write_active_atomic`** (T-10-04) — `expected=None` por omissao, os quatro chamadores existentes inalterados (verificado por gate de AST), e o `return False` passa pelo `finally` para nao deixar `ACTIVE.tmp-*` em `models/`.
- **`ERROR_CODES` continua com as mesmas 9 chaves** pela mesma ordem, e `MESSAGES_PT` cobre todas. O `test_ml_models_ui.cjs` (`D06_CODES.length === 9`) fica verde sem o frontend tocar nele.

## Task Commits

1. **Task 1 — ligar as quatro secoes mortas ao `run()`** — `61ef024` (test) — *executada antes deste plano; verificada aqui, nao refeita*
2. **Task 2 — D-04 + D-02 + D-03: proveniencia, `feature_stats` e hash do catalogo** — `0351ef7` (feat)
3. **Task 3 — compare-and-set em `_write_active_atomic`** — `2a1228c` (feat)

## Files Created/Modified

- `scripts/model_registry.py` — `catalog_sha256()`, `_catalog_compatible()`, `DATASET_PUBLIC_KEYS`/`DATASET_KEY_TYPES`/`FEATURE_STATS_KEYS`/`FEATURE_STATS_MAX_ENTRIES`/`DATASET_TEXT_LIMIT`/`METADATA_EXTRA_PROJECTED_KEYS`, `_public_dataset`/`_public_feature_stats`, `catalog_compatible` em `build_models_report`, sete kwargs novos em `build_trained_metadata`/`register_trained_version`, e o compare-and-set.
- `scripts/test_model_registry.py` — `test_catalog_sha256`, `test_dataset_com_proveniencia`, `test_write_active_cas`, e a correcao dos pins de schema.

**Nao tocados** (como o plano exige): `main.py`, `ml_anomalies.py`, `ml_evaluation.py`, `train_anomaly_model.py`, e qualquer ficheiro de frontend, documentacao ou `.planning`.

## Verification (tudo medido DEPOIS da ultima alteracao)

| Verificacao | Resultado | Numero medido |
|---|---|---|
| `test_model_registry.py` | PASS, exit 0, 0 linhas `[FALHOU]` | **497** checks |
| `run_all_tests.py` | PASS, exit 0 | **38/38** ficheiros, 318 s |
| Gate constantes `(9,13,9,2,32)` + `MESSAGES_PT == ERROR_CODES` | PASS, exit 0 | `9 13 9 2 32` |
| Gate AST do topo de `model_registry.py` | PASS, exit 0 | so stdlib |
| `joblib.load` por AST | PASS, exit 0 | `{'ml_anomalies.py': 3}` |
| Gate assinatura de `_write_active_atomic` | PASS, exit 0 | `['root','version_id','expected']`, default `None` |
| Gate dos chamadores (o `<verify>` do plano) | PASS, exit 0 | `[]` |
| Gate por AST dos tres chamadores (codigo, sem docstrings) | PASS, exit 0 | 0 diferencas |
| `scripts/models/` | PASS | `['isolation_forest.pkl','scaler.pkl']` |
| SHA-256 e mtime dos dois `.pkl` | inalterados | `3C2FE308…E3B106` / `007DD505…EB57FF`, 14/09/2026 15:40:15 |
| `test_ml_models_api.py` / `test_ml_models_ui.py` | PASS, exit 0 | frontend semalterado |
| Estabilidade do teste de threads | 15 execucoes seguidas a verde | 15/15 |

**Ressalva honesta sobre o `run_all_tests.py`:** em 5 execucoes, 3 deram 38/38 e 2 deram timeout dos 300 s do runner **em ficheiros diferentes e que não têm nada a ver com o registo** (`test_ml_evaluation.py` e `test_detections_api.py`, ambos a passar sozinhos em 11 s e 17 s). O timeout é do paralelismo nesta máquina, não deste plano — mas é medido e dito aqui.

## Decisions Made

1. **`catalog_compatible` aditivo, nunca `status`.** `status "ok"` é o sinal de que os `.pkl` estão integros; uma versao cujo catalogo ja nao bate continua a carregar. Um `status` novo misturaria as duas coisas, obrigaria a um codigo em `ERROR_CODES` e partiria o badge.
2. **`ERROR_CODES` intacta.** Os quatro codigos do R10 (`dataset_not_found`, `dataset_unusable`, `training_in_progress`, `training_failed`) nascem em `ml_training.TRAINING_ERROR_CODES` no plano 10-02.
3. **`load_metadata` nao ganha exigencias.** A defesa e a sub-projecao. E o que mantem o `scripts/models/` do utilizador e as fixtures dos outros 37 testes validas sem migracao.
4. **`_catalog_compatible` recebe o hash ja calculado** em vez de o calcular por versao: uma pasta vazia nao paga o import de `event_catalog`, e uma pasta com N versoes nao paga N hashes. Se o calculo falhar, degrada para `None`, nunca derruba a listagem.
5. **O compare-and-set devolve, nao decide.** Quem traduz `False` em 409 e o chamador do plano 10-02, com o lock dele por fora.

## Contrato novo para o frontend (para passar ao agente do frontend)

Nenhum **codigo de erro** novo — `ERROR_CODES` continua com as 9 chaves e `D06_CODES.length === 9` fica verde.

O que muda em `/api/ml/models` (`GET`):

| Onde | Chave | Tipo | Nota |
|---|---|---|---|
| `versions[]` | **`catalog_compatible`** | `true \| false \| null` | **NOVA, uma por versao, incluindo a entrada `kind: "legacy"` (`null`).** `null` = "nao sei" (versao antiga, sem a chave); `false` = o `catalog_sha256` gravado nao bate com o catalogo actual. `status`/`error_code` **inalterados**. |
| `versions[].metadata` | **`catalog_sha256`** | `string \| null` | **NOVA.** 64 hex minúsculas ou `null`. Entra em `METADATA_PUBLIC_KEYS` (13 chaves). |
| `versions[].metadata` | **`feature_stats`** | `object \| null` | **NOVA.** `{nome_da_feature: {"mean": float\|null, "std": float\|null}}` ou `null` (nao medido). Sai projectado pelas duas chaves, valores por tipo. |
| `versions[].metadata.dataset` | **`documents`**, **`processable`**, **`truncated`**, **`window_first`**, **`window_last`** | `int \| null`, `int \| null`, `bool \| null`, `str \| null`, `str \| null` | **NOVA**, 5 chaves. As 4 antigas (`name`/`size`/`attacks`/`synthetic`) saem com os mesmos valores, por isso `mlmDatasetHtml` nao se parte. |

Em disco (o que o `metadata.json` gravado passa a ter): 15 chaves de topo — as 13 de `METADATA_PUBLIC_KEYS` + `evaluation` + `feature_stats`.

## Deviations from Plan

### 1. A aritmetica do plano e internamente inconsistente — `METADATA_PUBLIC_KEYS` 13 e `metadata.json` 14 sao impossiveis

- **Found during:** Task 2
- **Issue:** o plano fixa `len(METADATA_PUBLIC_KEYS) == 13` e `len(meta) == 14`, em gates executaveis. Mas D-03 obriga a gravar `feature_stats` **e** D-04 a gravar `catalog_sha256`, e o plano diz que as duas sao chaves **de topo**. Sao 12 + 2 + `evaluation` = **15**. O plano esqueceu-se de contar uma delas — e o seu proprio `set(meta) == set(METADATA_PUBLIC_KEYS) | {"evaluation"}` torna as duas incompativeis com os numeros.
- **Fix:** manteve-se o **13** (que e o numero com codigo de saida no `<verify>`) com `catalog_sha256` dentro da tupla, e `feature_stats` ficou **fora** da tupla e **projectado a parte** em `_public_metadata`, sob a constante nomeada `METADATA_EXTRA_PROJECTED_KEYS = ("feature_stats",)`.
- **Efeito para quem le a API: nenhum.** As duas chaves continuam a sair no bloco `metadata`, como o plano 10-03 (`10-03-PLAN.md:553`) diz ao agente do frontend. O que muda e so a **arregua**.
- **Files modified:** `scripts/model_registry.py`, `scripts/test_model_registry.py`
- **Verification:** o teste mede a diferenca em vez de a esconder — `test_dataset_com_proveniencia` tem um check chamado *"as 14 do plano + a feature_stats que o plano nao contou"* que falha se a aritmetica deixar de bater.
- **Committed in:** `0351ef7`

### 2. A sub-projecao de `feature_stats` nao consegue fechar os NOMES das features

- **Found during:** Task 2
- **Issue:** o plano (T-10-01) diz que `feature_stats` sai com *"exactamente as ... 7 chaves projectadas"*. Nao e possivel: os nomes vivem em `feature_extractor.FEATURE_NAMES`, que o registo **nao pode importar** (D-01, stdlib puro no topo), e copia-lo seria uma segunda lista escrita a mao a divergir em silencio — exactamente o que o plano diz querer evitar.
- **Fix:** a sub-projecao fecha o que e o vector de injecao — os **valores** (`mean`/`std` por tipo, um texto nunca passa) e o **numero** de chaves (teto de 32). Os nomes passam. Documentado no docstring e medido por um teste que diz em voz alta *"um NOME de feature inventado sobrevive (limite conhecido)"*.
- **Verification:** `test_model_registry.py::test_dataset_com_proveniencia` (T-10-01)
- **Committed in:** `0351ef7`

### 3. O teste de duas threads nao devolve "exactamente uma" `True` — e nao pode

- **Found during:** Task 3
- **Issue:** o plano previa que duas threads com `threading.Barrier(2)` a chamar `_write_active_atomic(..., expected="v0")` devolvessem **exactamente uma** `True`. Nao devolvem: se ambas leem `"v0"` antes de qualquer escrita, ambas passam a comparacao e ambas escrevem. E o que o proprio limite do compare-and-set diz — a releitura e o `os.replace` nao sao uma operacao atomica unica. Um teste que exigisse "exactamente uma" seria um teste que passa ou falha conforme a sorte.
- **Fix:** a propriedade *"exactamente uma escreve"* passa a estar provada **sem depender de sorte**, com as duas chamadas a partir da **mesma releitura** (caso `l`). O caso com barreira ficou a medir o que e garantido sempre: nunca ha `ACTIVE.tmp-*`, o `ACTIVE` nunca fica truncado/vazio/parcial, e nenhuma thread levanta uma excepcao inesperada.
- **Verification:** 15 execucoes seguidas a verde.
- **Committed in:** `2a1228c`

### 4. No Windows, `os.replace` em corrida da `PermissionError` — medido como resultado legitimo

- **Found during:** Task 3
- **Issue:** uma thread pode receber `registry_unavailable` em vez de `True`/`False`: o `os.replace` do Windows falha quando outro handle tem o destino aberto, e a releitura tem-no. Com o teste escrito a exigir um `bool`, isto era uma corrida de teste instavel (observada uma vez em ~15 execucoes).
- **Fix:** o resultado `erro:registry_unavailable` passou a ser aceito e **medido** explicitamente, com um check a garantir que nenhuma thread levantou outra coisa inesperada.
- **Committed in:** `2a1228c`

**Total deviations:** 4 (1 aritmetica do plano, 2 limites tecnicos reais medidos, 1 robustez de teste)
**Impact on plan:** nenhuma mudanca de âmbito. As tres ultimas sao limites **medidos e escritos**, nao escondidos. A primeira e um desvio explicito e documentado de um numero do plano, com o efeito no contrato da API medido como nulo.

## Issues Encountered

- **O `run_all_tests.py` deu timeout duas vezes** em cinco execucoes, sempre em ficheiros diferentes e sem ligacao ao registo (`test_ml_evaluation.py`, `test_detections_api.py`), ambos a passar isolados em 11 s / 17 s. Nao se mexeu em nada por causa disto; fica registado.
- **O editor de ficheiros nao preserva acentos de forma confiavel** ao escrever scripts auxiliares. Todos os scripts de verificacao/gate foram escritos com **ancoras ASCII** e, quando precisavam do texto original, tiraram-no de `git show HEAD` em vez de o transcrever. Todos abortam se uma ancora nao bater exactamente uma vez.

## User Setup Required

None — no external service configuration required. **`scripts/models/` nao foi tocado**: mesmos SHA-256, mesmo mtime (14/09/2026 15:40:15), sem `v1/`, sem `ACTIVE`, sem temporarios.

## Next Phase Readiness

**Pronto para o plano 10-02:**
- `model_registry.catalog_sha256()` pronto para o `register_trained_version` do motor.
- Os sete kwargs novos em `register_trained_version` (`dataset_documents`, `dataset_processable`, `dataset_truncated`, `dataset_window_first`, `dataset_window_last`, `feature_stats`, `catalog_sha256`) aceitos e validados.
- `library_versions_pt()` e `build_trained_metadata()` inalterados nos parametros que ja existiam.
- A suite de `register_trained_version` **corre a serio** (era cobertura aparente antes de `61ef024`).

**Para o plano 10-03:**
- `catalog_compatible` por versao, com `status`/`error_code` intactos.
- `catalog_sha256` e `feature_stats` legiveis em `versions[].metadata`.

**Fica por resolver (nao e deste plano):**
- **T-10-08, bug pre-existente medido:** `model_registry.py train v1 --random-state 1234 --n-estimators 77` grava esses valores no `metadata.json` mas treina com `random_state=42, n_estimators=200` (`train_anomaly_model.py:49` esta fixo e `_cmd_train` nao os repassa). O registo **nao** e o sitio certo; e `train_anomaly_model.train_model` ganhar o parametro. O plano 10-02 diz que resolve isto.
- **`docs/DATA_MODEL.md:82`** continua a dizer *"METADATA_PUBLIC_KEYS: **12** chaves"* — passou a 13. A documentacao e do agente de docs; fica registado aqui para ninguem dar por elle.

## Next Phase Readiness — o que NAO foi verificado

- **Nenhum comando foi corrido com o laboratorio Wazuh ligado.** Nada nesta mudanca toca em rede, e o plano proibe esse teste.
- **`POST /api/ml/train` nao existe ainda** — este plano nao o cria.
- **A UI nao foi tocada nem vista.** O que o `ml_models.js` faz com `catalog_compatible` e com as 5 chaves novas do `dataset` e uma decisao do agente de frontend; aqui so se provou que o contrato sai correcto e testado.
- **Nao se testou `catalog_sha256()` contra um `CRITICAL_EVENTS` real que mude** — so contra copias em memoria. A medicao de "acrescentar um Event ID desloca 31 de 31 indices" (D-04) e do plano de pesquisa; aqui mediu-se que o hash muda, que e o que o registo precisa de saber.
- **O `run_all_tests.py` e instavel sob paralelismo nesta maquina** (2 timeouts em 5 execucoes, em ficheiros alheios). A medicao final de 38/38 e de uma execucao limpa pos-alteracao, mas o numero e sensivel a essa instabilidade.

---
*Phase: 10-ml-learning-loop*
*Plan: 01*
*Completed: 2026-10-11*