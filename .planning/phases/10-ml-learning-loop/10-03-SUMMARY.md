---
phase: 10-ml-learning-loop
plan: 03
status: complete
completed: 2026-10-11
requirements: [D-01, D-06, D-07, API-01, API-02, TST-01]
---

# Phase 10, Plan 03: A superfície HTTP do registo

**`POST /api/ml/train` e `POST /api/ml/models/{vN}/activate` existem, e `/api/ml-anomalies` passou a dizer de que versão veio cada número.** O `main.py` deixou de dizer que treinar é operação de CLI — essa frase era verdadeira até agora.

## Performance

| | |
|---|---|
| Ficheiro de teste | `test_ml_models_api.py` a correr sozinho: **26,9 s** (dos quais ~20 s são os seis treinos dentro dos limites e os três `.pkl` reais) |
| Suite completa | **39/39** em ~14 s, depois da última alteração |
| Laboritório Wazuh | desligado — `MOCK_ALERTS` + `AsyncMock`, como sempre |

## Accomplishments

### As duas rotas, com API key no próprio decorador

As quatro rotas ML de `main.py` (`ml-anomalies`, `ml/models`, `ml/train`, `ml/models/{id}/activate`) têm `dependencies=_REQUIRE_API_KEY` **no decorador**, e o construtor `FastAPI(...)` continua com zero `dependencies=` — a armadilha de `/ws/alerts` continua fechada.

### As quatro protecções de D-01, todas medidas

1. **Nenhum caminho vem do corpo.** `MLTrainRequest` tem cinco campos e `extra="forbid"`. Oito chaves de caminho (`events`, `models_dir`, `attack_log`, `sources`, `path`, `url`, `MODEL_DIR`, `models-dir`) dão 422 com o registo byte-idêntico antes e depois. `dataset` e `dataset_origin` são `Literal` **obrigatórios, sem default** — o default natural (`sample_fixture`) treinaria em silêncio sobre o fixture sintético.
2. **Tetos testados pelos dois lados.** `contamination` 0.0/0.51/-1, `random_state` -1/4294967296 e `n_estimators` 9/1001/10⁹ dão 422 sem escrever nada; 0.01/0.5, 0/4294967295 e 10/1000 dão 200 — e **o `.pkl` do POST com `n_estimators=1000` tem mesmo 1000 árvores dentro**, que é o que distingue um tecto de um filtro que nunca deixa passar nada.
3. **Single-flight por HTTP.** Três POSTs em simultâneo dão exactamente `[200, 409, 409]`, com os dois 409 a dizer `training_in_progress` e sem escreverem nada. O registo fica com `['ACTIVE', 'isolation_forest.pkl', 'scaler.pkl', 'v1']` — sem `v1.tmp-*`, sem `ACTIVE.tmp-*`, `total == 1`, e `loaded_version() == 'v1'` **sem reiniciar o backend**. Um quarto pedido normal a seguir prova que o lock libertou.
4. **`detail` é sempre um código.** Uma função só, `_ml_write_error`.

### `model_version` (D-06)

Lida **depois** do `build_ml_anomalies_report`, no mesmo `try`. `"v1"` com a v1 activa, `"legacy"` com os dois `.pkl` soltos (o estado real de `scripts/models/` hoje), a chave **presente** no caminho vazio, e ausente no 503 — porque um erro não é um relatório.

## Decisões tomadas na execução

1. **O mapeamento de `ModelRegistryError` é por código, não "sempre 503".** O plano traz as duas coisas nos `must_haves`: uma tabela com "ModelRegistryError → 503" e, duas linhas abaixo, "`POST /api/ml/models/v9/activate` devolve **404** com `detail == 'active_not_found'`". Segui a específica: uma versão que não existe é um 404 honesto, e o frontend já traduz `active_not_found`. As nove chaves de `ERROR_CODES` estão escritas em `_ML_REGISTRY_STATUS`, e o teste compara com uma cópia à mão.
2. **`except (Exception, KeyboardInterrupt)`, nomeado à mão.** O `KeyboardInterrupt` é `BaseException`: um `Ctrl-C` a meio do `joblib.dump` dentro do `run_in_threadpool` não passava pelo `except Exception` e saía como 500 do uvicorn. O teste mede-o com um `train_model` que o levanta: 503 `training_failed`, nada escrito, `busy() is False`.
3. **O 422 do Pydantic devolve o valor rejeitado no `detail`** (`input`), e isso não é uma fuga: é o valor que o próprio cliente enviou. O check mede o que interessa — nenhum caminho **do servidor** (a pasta temporária) na resposta. Registado no teste, para que ninguém "corrija" um eco legítimo e quebre o `extra="forbid"`.
4. **`../x` nem chega ao handler** e o `v99999` dá 422 do `pattern` do FastAPI. O `invalid_version_id` do registo é provado no `test_ml_training.py`, com o mesmo `validate_version_id` mas sem o path-param pelo meio. O teste regista isto explicitamente para que ninguém escreva um caso impossível à espera do 404 do registo.

## Três erros meus que os testes apanharam

Todos os três são do tipo "passava por sorte":

1. **`_paralelo` fazia `join` antes de devolver** — a thread presa à espera do `Gate` só Via o `wait(timeout=60)` expirar, e era aí que o `Gate` era aberto. O teste dos três POSTs passava (o 409 saía na mesma, porque os outros dois batem no `claim()`) mas demorava um minuto e a cena "activar durante um treino" media a coisa errada: o `activate` já corria **depois** do treino acabar, e devolvia 200. Corrigido: `_paralelo` só arranca as threads, `_juntar` é quem espera, e a cena do `activate` passa a pôr o treino sozinho no `Gate` antes de disparar o activate.
2. **`exportar_eventos` devolvia o `.json` em vez da pasta** — `ML_EXPORT_DIR` a apontar para um ficheiro dá `dataset_not_found` em silêncio, e os seis casos "dentro dos limites" davam 404 em vez de 200.
3. **O check do `n_estimators=1000` lia a pasta errada.** O `.pkl` da v1 é o do *primeiro* treino dentro dos limites, não o do tecto. Passou a ler a versão que a própria resposta devolveu.

## Duas divergências face ao plano, ditas

- **39/39, não 40/40.** O plano previa um ficheiro de teste novo neste plano; o 10-03 não cria nenhum (estende `test_ml_models_api.py`). O 39 é o número certo depois do 10-02.
- **`test_ml_anomalies.py` também foi tocado.** O pin do contrato de topo de `/api/ml-anomalies` é uma lista escrita à mão e `model_version` partiu-o — o que é exactamente o que esse pin existe para fazer. Passou a ser a **segunda** lista escrita à mão do mesmo contrato (a primeira é a de `test_ml_models_api.py`, `CHAVES_ANTES_DA_CHAVE_NOVA`), para que nenhuma cresça sozinha.

## Verificação (tudo medido DEPOIS da última alteração)

```
.venv/Scripts/python.exe -X utf8 test_ml_models_api.py    -> [OK] Todos os testes passaram
.venv/Scripts/python.exe -X utf8 test_ml_anomalies.py     -> [OK] Todos os testes passaram
.venv/Scripts/python.exe -X utf8 run_all_tests.py          -> 39/39 ficheiros passaram
main.py: 4 rotas ML, 0 desprotegidas, dependencies= a nível de app: False
main.py: report["model_version"] aparece 1x, dentro de get_ml_anomalies
MLTrainRequest: 5 campos, extra='forbid'
model_registry.ERROR_CODES: 9 | ml_training.TRAINING_ERROR_CODES: 4
scripts/models/: ['isolation_forest.pkl', 'scaler.pkl']  (intacto)
```

## Ficheiros tocados

- `scripts/main.py` — `import ml_training`, `ConfigDict`, `_ML_WRITE_STATUS`, `_ML_REGISTRY_STATUS`, `MLTrainRequest`, `_ml_write_error`, as duas rotas POST, `report["model_version"]`, e o docstring de `get_ml_models` reescrito (a frase "só leitura, treinar é CLI" era falsa a partir daqui).
- `scripts/test_ml_models_api.py` — cinco secções novas (`limites_do_pedido`, `treino_ponta_a_ponta`, `activate_ponta_a_ponta`, `model_version_no_relatorio`, `dois_posts_concorrentes`) mais os utilitários (`ambiente_treino`, `Gate`, `_paralelo`/`_juntar`, `fingerprint`) e três listas escritas à mão (as duas tabelas de erro e o pin de `MLTrainRequest`).
- `scripts/test_ml_anomalies.py` — o pin do contrato de topo, com a chave nova.

**Não tocados:** `ml_models.js`, `ml_evaluation.js`, `index.html`, `style.css`, `serve_frontend.py`, `README.md`, `CLAUDE.md`, `docs/*` — são do agente de frontend (phase 11) e do de documentação.

## Risco residual que fica aberto

Quem tem a API key passa a poder escrever em `models/`, treinar e recarregar a cache. D-01 fecha o caso prático; **não** fecha o caso de fundo — a chave é global e sem papéis. O SHA-256 dos `.pkl` deixa de ser uma defesa e passa a ser um detector de corrupção. `docs/SECURITY.md` tem de ser **reescrito** sobre este ponto (D-08), não anotado, e é a próxima coisa a fazer depois da phase 11.