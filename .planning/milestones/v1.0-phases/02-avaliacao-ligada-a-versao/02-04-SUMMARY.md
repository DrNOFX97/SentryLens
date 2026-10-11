---
phase: 02-avaliacao-ligada-a-versao
plan: 04
subsystem: ml-registry
tags: [python, fastapi, javascript, node-vm, ml, isolation-forest, dashboard, dataset-origin, alerts-truncated, standalone-tests]

# Dependency graph
requires:
  - phase: 02-avaliacao-ligada-a-versao (02-01)
    provides: "ml_evaluation.js com a camada pura da aba (mlePercent/mleMetricCell/mleBuildEvalRows/mleEvalNoticeText) e mleRefresh a um só pedido a /api/ml/models; o contrato de 14 chaves com small_sample/min_events/min_attacks/dataset_origin; a sub-projeção de `evaluation` na API (D-08)"
  - phase: 02-avaliacao-ligada-a-versao (02-02)
    provides: "ml_evaluation.small_sample_flags com os DOIS limiares nomeados (D-05) e ORIGEM_PT com os três avisos de origem declarada"
  - phase: fase-6-ml-anomaly-detection
    provides: "ml_anomalies.build_ml_anomalies_report (total/ml_anomalies_count/rule_flagged_count/agree_count/diverge_count) e o cliente do Indexer limitado a 1000 alertas"
  - phase: 01-registo-de-modelos-ponta-a-ponta
    provides: "mlmErrorText/mlmCodeFromResponse reusados por ml_evaluation.js, o painel #tab-ml-evaluation e a whitelist de serve_frontend.py"
provides:
  - "scripts/main.py — GET /api/ml-anomalies com alerts_fetched e alerts_truncated (aditivo, D-10), o mesmo sinal de integridade que /api/redblue/metrics já expunha"
  - "ml_evaluation.js — camada pura com mleOriginHtml, mleSmallSampleNotice, mleLiveErrorMessage/mleLiveErrorHtml e mleBuildLiveAgreement; camada DOM com mleLiveHours/mleRefreshLive e o segundo pedido a /api/ml-anomalies"
  - "index.html — a tabela da Evaluation com seis colunas e o bloco #mle-live-block (select de janela, #mle-live-notice, #mle-live-body)"
  - "style.css — .mle-metric/.mle-warning/.mle-origin-*/.mle-live-error, com a paleta dos badges existentes"
  - "scripts/test_ml_models_ui.py — três fixtures reais de /api/ml-anomalies (com amostra, vazia, truncada)"
  - "scripts/test_ml_anomalies.py — a regressão da rota com as duas chaves novas, o conjunto exacto de chaves e os três estados de erro"
  - "scripts/test_serve_frontend.py — seis <th>, os ids do bloco ao vivo e a ausência de colisão com QUALQUER identificador de topo de ml_models.js"
affects: [02-avaliacao-ligada-a-versao, r9, model-registry, ml-registry, dashboards, live_soc, fase-3, fase-r10]

actuals:
  tokens: 13046   # chars/4 sobre o diff real (8 ficheiros, +729/-38); o estimate de 70000 era generoso
  tasks: 2
  commits: 3

# Tech tracking
tech-stack:
  added: []   # nada novo instalado — sem dependências, sem pacotes, sem serviços
  patterns:
    - "Sinal de integridade ≠ métrica: alerts_fetched/alerts_truncated descrevem a JANELA do pedido (o Indexer devolve no máximo 1000), nunca o desempenho do modelo — e por isso vivem na rota, não no motor"
    - "Camada pura com estado explícito: mleBuildLiveAgreement devolve {state, html} e o DOM só consome — 'Sem dados' e 'erro' são decisões do helper, não do desenho"
    - "Três fixtures reais da rota como contrato do frontend: com amostra / vazia / truncada, geradas pelo wrapper com o Indexer mockado, em vez de JSON escrito à mão"
    - "Erro tem frase própria por código HTTP genérico (MLE_LIVE_ERROR_TEXT) em vez de cair na mensagem do registo — 'não foi possível ler a pasta de modelos' mentiria num bloco que fala do Indexer"

key-files:
  created: []
  modified:
    - scripts/main.py
    - scripts/test_ml_anomalies.py
    - ml_evaluation.js
    - index.html
    - style.css
    - scripts/test_ml_models_ui.py
    - scripts/test_ml_models_ui.cjs
    - scripts/test_serve_frontend.py

key-decisions:
  - "A linha de aviso de amostra pequena e a linha de 'Sem avaliação' são <tr> de largura total (colspan=6)logo a seguir à linha da versão, e não uma sétima coluna: é a forma que o 02-01 já usava para 'Sem avaliação' e mantém a contagem de uma linha por versão"
  - "'Sem avaliação' mostra a Dataset como '—' e a Origem como 'origem desconhecida': uma versão sem avaliação não tem tamanho nem origem — MOSTRAR é mais honesto que uma célula vazia, que se lê como um carregamento falhado"
  - "mleLiveHours valida o valor lido do select (1..168) e cai em 24: um select adulterado não pode fazer um pedido que a rota recusa com 422"
  - "O aviso de truncagem no badge de origem vai num atributo title escapado, não em texto corrido: a explicação ('não foi declarada no comando — não assumimos que são reais') é longa e a tabela tem seis colunas"
  - "MLE_LIVE_ERROR_TEXT tem http_502/http_503/http_500 com frases próprias, E o resto cai em mlmErrorText: o must_have do plano exige que 503 diga 'o modelo não carregado', que a mensagem genérica do registo não diz"
  - "Os contadores de <tr>/colspan do 02-01 passaram a seis, e a asserção nova conta <td> por linha em vez de <tr>: o que se quer fixar é 'seis células na linha da versão', não 'N linhas', que passa a depender de small_sample"

patterns-established:
  - "'Sem dados' e 'erro' são dois estados disjuntos no frontend: mleBuildLiveAgreement só devolve {sem_dados, ok} e o erro nunca passa por ali — escreve-se em mleLiveErrorHtml, com a mensagem traduzida e o detalhe fora do DOM"
  - "Números vindos do payload passam por mleNumero/mleContagem: não-número é '—' (ou o estado 'sem_dados'), nunca o texto cru nem NaN — a mesma regra que mlePercent já usava nas métricas"
  - "A lista de ids do painel é testada em duas camadas: o .cjs prova o comportamento com fixtures, e o test_serve_frontend prova a forma (nº de <th>, ids, prefixos) contra os ficheiros reais servidos ao browser"

requirements-completed: [EVAL-03, UI-02]

coverage:
  - id: D1
    description: "/api/ml-anomalies expõe alerts_fetched e alerts_truncated de forma aditiva, e o conjunto de chaves de topo não mudou para lá dessas duas"
    requirement: EVAL-03
    verification:
      - kind: unit
        ref: "scripts/test_ml_anomalies.py#test_run (alerts_fetched/alerts_truncated e 'as chaves de topo são exactamente o contrato + as duas novas')"
        status: pass
    human_judgment: false
  - id: D2
    description: "A tabela da Evaluation mostra o tamanho do dataset e a origem declarada por versão, com o aviso de amostra pequena sempre presente quando small_sample é true"
    requirement: EVAL-03
    verification:
      - kind: unit
        ref: "scripts/test_ml_models_ui.cjs#mleOriginHtml / mleSmallSampleNotice / mleBuildEvalRows (seis <td>, aviso, origem)"
        status: pass
      - kind: automated_ui
        ref: "scripts/test_serve_frontend.py#check_static_frontend (seis <th>, ids do bloco, ausência de colisão de globais)"
        status: pass
    human_judgment: false
  - id: D3
    description: "O bloco de concordância ao vivo lê /api/ml-anomalies sem criar métricas: contagens e percentagem vêm da rota, e a janela truncada avisa em vez de passar por concordância total"
    requirement: UI-02
    verification:
      - kind: unit
        ref: "scripts/test_ml_models_ui.cjs#mleBuildLiveAgreement (ok / sem_dados / truncado / não-numérico / XSS)"
        status: pass
      - kind: integration
        ref: "scripts/test_ml_models_ui.py#ml_anomalies_fixtures (ml_report_ok/vazio/truncado gerados pela rota real com o Indexer mockado)"
        status: pass
    human_judgment: false
  - id: D4
    description: "Um erro no pedido a /api/ml-anomalies nunca é desenhado como 'Sem dados': 502 fala do Indexer, 503 do modelo não carregado, 401 da API key, e o código nunca aparece no DOM"
    requirement: UI-02
    verification:
      - kind: unit
        ref: "scripts/test_ml_models_ui.cjs#mleLiveErrorHtml (hash_mismatch/http_502/http_503/unauthorized/código inventado)"
        status: pass
      - kind: unit
        ref: "scripts/test_ml_anomalies.py#os três estados de erro da rota (401/502/503)"
        status: pass
    human_judgment: false
  - id: D5
    description: "A aba Evaluation no browser real com o laboratório ligado: as seis colunas, o aviso, o badge de origem e os dois estados do bloco ao vivo distinguíveis à vista"
    verification: []
    human_judgment: true
    rationale: "node:vm não tem DOM, rede nem serviço: o <human-check> do plano pede backend+frontend a correr e o Indexer com eventos, e nenhum serviço arranca nesta sessão (laboratório Wazuh desligado)"
  - id: D6
    description: "A leitura da aba com uma versão avaliada sobre o dataset real e a concordância ao vivo com o Indexer a responder"
    verification: []
    human_judgment: true
    rationale: "D-06: a primeira avaliação real depende de o utilizador exportar os documentos com o 02-03 e correr o `evaluate` com a VM ligada; sem isso scripts/models/ só tem os dois .pkl legados e a tabela mostra 'Sem avaliação'"

# Metrics
duration: ~75 min
completed: 2026-10-10
status: complete
---

# Phase 02 Plan 04: Fecho da aba Evaluation (dataset, origem e concordância ao vivo)

**A tabela da Evaluation passou a seis colunas com o tamanho do dataset, a origem declarada e o aviso de amostra pequena sempre presente — e por baixo dela um bloco de concordância ao vivo que lê `/api/ml-anomalies` sem inventar uma única métrica, escreve "Sem dados" quando a janela está vazia e uma mensagem de erro (nunca um número) quando o Indexer não responde.**

## Performance

- **Duration:** ~75 min
- **Started:** 2026-10-10T20:35:00+01:00
- **Completed:** 2026-10-10T21:50:00+01:00
- **Tasks:** 2
- **Files modified:** 8 (0 criados, 8 alterados; +729/-38)

## Accomplishments

- **`/api/ml-anomalies` ficou com o sinal de integridade da janela** (`alerts_fetched` + `alerts_truncated`, D-10), copiado do padrão que `/api/redblue/metrics` já usava: o fetch ao Indexer é limitado a 1000 alertas newest-first, e uma concordância calculada sobre uma janela truncada não é uma concordância completa. É **aditivo** — nenhuma chave que já existia muda de nome, de valor ou de significado, e a rota continua a exigir `X-API-Key`.
- **A regressão da rota ficou completa e mais forte do que estava**: 20 checks, com o **conjunto exacto** de chaves de topo (um terceiro campo novo aparece como falha), os três estados de janela (10 alertas / tecto de 1000 / vazia — e 0 não é truncagem) e os três estados de erro (401 sem chave, 502 com o Indexer a levantar, 503 sem modelo), mais uma volta a 200 depois de todos eles. As mutações do `indexer_client` e do `load_model` são restauradas em `finally`.
- **A tabela tem seis colunas** — Versão | Ativa | Dataset | Origem | ML | Regras. O tamanho vem de `entry.evaluation` (`n eventos · m ataques`), a origem de um badge que traduz as três origens declaradas (verde "dados reais", âmbar "dados sintéticos", cinza "origem não declarada" com a explicação no `title`) e o aviso de amostra pequena entra **sempre que `small_sample === true`**, com os dois limiares que o motor gravou e os números reais do dataset — nunca recalculados no frontend (D-05, D-08).
- **O bloco de concordância ao vivo é o segundo pedido da aba, com o seu próprio ciclo de estados**: `total === 0` (ou resposta ausente) escreve "Sem dados" e nunca "0,0 %"; `alerts_truncated === true` acrescenta o aviso do tecto de 1000 **sem mexer no valor**; e um erro é um caminho separado, com `mleLiveErrorHtml` a traduzir o código por `mlmErrorText` (ou pela frase própria do Indexer/modelo/API key) e o `detail` fora do DOM. Os dois pedidos são independentes: um registo ilegível não apaga a concordância, um Indexer em baixo não apaga a tabela.
- **Três fixtures reais da rota** (`ml_report_ok/vazio/truncado.json`) passaram a ser geradas pelo wrapper com o Indexer mockado e um modelo treinado em memória, e consumidas pelo `.cjs` — o bloco ao vivo é testado contra o JSON que a rota devolve, não contra um JSON escrito à mão. O `test_serve_frontend.py` ganhou os ids do bloco, a contagem de `<th>` e a **intersecção com todos os identificadores de topo de `ml_models.js`** (não só com a lista de globais conhecidos).

## Task Commits

Cada task foi commitada atomicamente:

1. **Task 1 — `alerts_fetched`/`alerts_truncated` em `/api/ml-anomalies` + regressão da rota**: `c01a434` (feat)
2. **Task 2 — tabela de seis colunas, aviso de amostra, origem e concordância ao vivo**: `86d962f` (feat)

Um terceiro commit de arrumação de texto entrou depois do segundo: `7cdb8fc` (docs).

## Files Created/Modified

- `scripts/main.py` - `report["alerts_fetched"]` e `report["alerts_truncated"]` dentro de `get_ml_anomalies`, imediatamente antes do `return`; nada mais da função tocado
- `scripts/test_ml_anomalies.py` - 20 checks: chaves novas, conjunto exacto de chaves, tecto de 1000, janela vazia, 401/502/503 e volta a 200; mutações restauradas em `finally`
- `ml_evaluation.js` - camada pura com `mleNumero`/`mleContagem`/`mleMetrica`/`mleOriginHtml`/`mleSmallSampleNotice`/`mleBuildLiveAgreement`/`mleLiveErrorMessage`/`mleLiveErrorHtml`; camada DOM com `mleLiveHours`, `mleRefreshLive`, `mleLoadingLive` e o segundo pedido em `mleRefresh`
- `index.html` - `<thead>` com seis `<th>`, `colspan="6"` no estado vazio, e o bloco `#mle-live-block` dentro do mesmo `section#ml-evaluation-panel`
- `style.css` - `.mle-metric`, `.mle-metric-label`, `.mle-warning`, `.mle-origin`, `.mle-origin-real/-synthetic/-unknown`, `.mle-live-error` (mesma paleta dos badges `.mlm-badge-*`)
- `scripts/test_ml_models_ui.py` - `ml_anomalies_fixtures()` gera as três janelas de `/api/ml-anomalies` com o Indexer mockado, e restaura cliente e modelo em `finally`
- `scripts/test_ml_models_ui.cjs` - os quatro helpers novos na extracção, as três fixtures com `[FALHOU]` explícito se faltarem, e os casos de origem/aviso/concordância/erro/XSS
- `scripts/test_serve_frontend.py` - seis `<th>`, os cinco ids do bloco, o bloco dentro do mesmo painel, e a intersecção com todos os identificadores de topo de `ml_models.js`

## Decisions Made

- **`MLE_LIVE_ERROR_TEXT` com `http_502`/`http_503`/`http_500` próprios** (ver Desvio 3): o `must_have` do plano exige que um 503 diga "o modelo não carregado", e `mlmErrorText("http_503")` devolvia a mensagem do registo ("não foi possível ler a pasta de modelos"), que é falsa num bloco que fala do Indexer. Os códigos de D-06 continuam a traduzir-se por `mlmErrorText`.
- **A linha de aviso e a de "Sem avaliação" são `<tr>` de largura total** (ver Desvio 2): o plano escreve "um único `<tr>` por versão" ao mesmo tempo que manda acrescentar um `<td colspan="6">`. A leitura escolhida é a que o `mleEmptyState` do 02-01 já usava — uma linha de versão mais, no máximo, uma linha auxiliar — e o teste passou a contar `<td>` por linha, que é o que a palavra "seis colunas" fixa.
- **Testes que comparam percentagens com a resposta real** (`agree/total` do `ml_report_ok.json` e do `ml_report_truncado.json`) em vez de números escritos à mão: se a rota mudar de forma, o teste diz qual é a esperado.
- **`mleLiveHours` valida 1..168** e cai em 24: o `select` só oferece esses quatro valores, mas um valor adulterado não pode gerar um pedido que a rota recusa com 422.
- **Nada de métrica nova, nem no teste**: as contagens do bloco ao vivo são comparadas com os valores da rota, não recalculadas a partir dos resultados.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule: critério de aceitação impossível] O gate "`alerts_truncated` exactamente uma vez em `main.py`"**
- **Found during:** Task 1 (cadeia de `<verify><automated>`)
- **Issue:** o plano manda copiar o padrão de `main.py:853-854` (`/api/redblue/metrics`) **e** exige que `alerts_truncated` apareça exactamente uma vez no ficheiro. Com o repositório real a chave já aparecia **10 vezes** (ml-anomalies passa a 11) — em `/api/redblue/metrics`, em `/api/metrics` e nas rotas de incidentes. Os dois requisitos do plano não podem ser literais ao mesmo tempo.
- **Fix:** o gate passou a verificar o que o requisito quer dizer: `alerts_truncated` atribuída **exactamente uma vez dentro de `get_ml_anomalies`**, `alerts_fetched` também, a rota ainda com `dependencies=_REQUIRE_API_KEY`, `report["alerts_truncated"]` em exactamente **duas** rotas (a nova e a de origem) e nenhuma rota nova.
- **Files modified:** nenhum (o gate é um comando de verificação, não um ficheiro do repo)
- **Verification:** exit 0 nos cinco critérios; a contagem bruta está confirmada por `git show HEAD:scripts/main.py` (10 antes, 11 depois).
- **Committed in:** n/a (contradição interna do plano)

**2. [Rule: texto do plano que não fecha] "Um único `<tr>` por versão" vs. `<td colspan="6">` de aviso**
- **Found during:** Task 2 (desenho de `mleBuildEvalRows`)
- **Issue:** a acção pede um `<td colspan="6">` de aviso **e** um único `<tr>` por versão — incompatíveis. O código do 02-01 já resolvia "Sem avaliação" com um `<tr>` auxiliar (`mleEmptyState`), e foi essa a forma mantida.
- **Fix:** uma linha de versão mais, no máximo, uma linha auxiliar de largura total. O `.cjs` passou a contar `<td>` na linha da versão (seis) em vez de `<tr>` no bloco, que passaria a depender de `small_sample`.
- **Files modified:** `scripts/test_ml_models_ui.cjs`
- **Verification:** `seisCelulas(...) === 6`, e os testes "a linha da v2 não mostra percentagem nenhuma" / "a linha sem avaliação diz 'Sem avaliação'" continuam verdes.
- **Committed in:** `86d962f`

**3. [Rule: mensagem que mente] `http_503` tinha de dizer "modelo não carregado"**
- **Found during:** Task 2 (composição de `mleLiveErrorHtml`)
- **Issue:** o `must_have` exige que um 503 mostre "a mensagem de `mlmErrorText(code)` (ex.: hash_mismatch **ou o modelo não carregado**)". Para `hash_mismatch` isso é `mlmErrorText`; para o 503 de "modelo ausente" o `detail` não é um código (é `str(FileNotFoundError)`), o `mlmCodeFromResponse` devolve `http_503` e `mlmErrorText("http_503")` é a mensagem genérica **do registo de modelos** — que num bloco que fala do Indexer é falsa.
- **Fix:** `MLE_LIVE_ERROR_TEXT` dá frases próprias a `http_502` (Indexer), `http_503` (modelo não carregado / registo recusou a versão) e `http_500`; os códigos de D-06 e `unauthorized` continuam por `mlmErrorText`, como o plano manda.
- **Files modified:** `ml_evaluation.js`, `scripts/test_ml_models_ui.cjs`
- **Verification:** quatro checks em `mleLiveErrorHtml` (hash_mismatch, http_502, http_503, unauthorized) mais cinco de código inventado/ausente/HTML.
- **Committed in:** `86d962f`

**4. [Rule: teste mais rigoroso do que o pedido] Colisão com QUALQUER identificador de `ml_models.js`**
- **Found during:** Task 2 (revisão do `test_serve_frontend.py`)
- **Issue:** o teste comparava a lista de identificadores de topo de `ml_evaluation.js` com uma lista fixa de treze nomes conhecidos. Um `mlmFoo` novo que aparecesse nos dois ficheiros — exatamente o que o Pitfall 9 avisa — passava em silêncio.
- **Fix:** o mesmo `check` passa a intersetar contra **todos** os identificadores de topo declarados em `ml_models.js` (via o mesmo `re.findall`).
- **Files modified:** `scripts/test_serve_frontend.py`
- **Verification:** `ml_evaluation.js não repete nenhum identificador de topo de ml_models.js` — exit 0 com 45+ nomes de cada lado.
- **Committed in:** `86d962f`

**5. [Rule: palavra inglesa em comentário PT] "não é worth um pedido"**
- **Found during:** Task 2 (revisão do diff antes do commit)
- **Issue:** comentário novo com uma palavra em inglês dentro de texto em PT-PT.
- **Fix:** reescrito para "não justifica um pedido ao registo".
- **Files modified:** `ml_evaluation.js`
- **Verification:** `node --check ml_evaluation.js` exit 0 e `test_ml_models_ui.py` exit 0 depois da correcção.
- **Committed in:** `7cdb8fc`

---

**Total deviations:** 5 auto-fixed (1 critério de aceitação impossível, 1 texto do plano que não fecha, 1 mensagem que mentia, 1 teste mais rigoroso, 1 texto)
**Impact on plan:** Nenhuma alteração de âmbito. Os oito ficheiros do `files_modified` e nada mais; nenhum serviço arrancado, nenhum socket aberto, `scripts/models/`, `scripts/snapshots/` e `scripts/attack_log.jsonl` intactos.

## Issues Encountered

- **Um erro de escrita meu no teste Node passou meia hora:** escrevi `mlmReportOk` (com um `m` a mais) em três sítios do `.cjs` novo. O sintoma era absurdo — `typeof mlmReportOk` devolvia `"undefined"` enquanto `mlReportOk.total` devolvia `10`, na mesma expressão — e foi o que-delayou o diagnóstico: a primeira leitura foi "impossível em JS", não "erro de escrita". O `node:vm` não corre o `.cjs` com o resto das definições em jogo, por isso o `ReferenceError` só aparecia no fim, depois de ~300 `[OK]`. Corrigido com uma substituição global e confirmado por `node --check` + o wrapper a verde. **Fica registado porque o próximo teste novo vai ter o mesmo risco.**
- **`includes("")` é sempre verdadeiro**: a asserção "a origem fora do contrato nunca é desenhada em bruto" não pode ser escrita como `!badge.includes(String(valor))` quando `valor` é `""`. O teste passou a usar `String(valor) !== ""` como guarda, e ganhou à parte uma asserção explícita para o caso do `<img`.
- **O `.cjs` não tem como ser testado sozinho**: depende das fixtures do wrapper. Uma fixture nova em falta sai com `[FALHOU] <nome> em falta — regenera com test_ml_models_ui.py` e código 1, em vez de um `TypeError` de `readFileSync` perdido no meio da saída.
- **A 502 do `main.py` nunca foi chamada com o Indexer real**: o teste restaura `main.indexer_client.get_recent_alerts` antes de cadascenario e repõe um `AsyncMock` antes do "volta a 200" final — a primeira versão desse check chamava o cliente verdadeiro e dava 502, que é o laboratório desligado e não um defeito da rota.

## User Setup Required

None — nada a instalar nem a configurar. Sem dependências novas, sem variáveis novas, sem migração de `metadata.json` (as 14 chaves não mudaram).

## Verification Run

Todos os comandos de `<verify><automated>` das duas tasks, com `scripts\.venv\Scripts\python.exe` (CPython 3.12.14) e Node v24.14.1, **laboratório Wazuh desligado** e nenhum serviço arrancado:

| # | Comando | Resultado |
|---|---|---|
| 1 | `test_ml_models_ui.py` | exit 0, **320 `[OK]`** (Python + Node), 0 linhas `[FALHOU]` |
| 2 | `test_serve_frontend.py` | exit 0, 0 linhas `[FALHOU]` |
| 3 | `test_ml_anomalies.py` | exit 0, **20 `[OK]`**, 0 linhas `[FALHOU]` |
| 4 | `test_ml_models_api.py` | exit 0 |
| 5 | `node --check ml_evaluation.js` | exit 0 |
| 6 | `node --check ml_models.js` | exit 0 |
| 7 | Portões Task 1 (`alerts_truncated` aditivo) | exit 0, 5 `[OK]` |
| 8 | Portões Task 2 (ids, `.mle-*`, prefixos, colisão, D-11) | exit 0, todos `[OK]` |
| 9 | `run_all_tests.py` | exit 0, **38/38** (baseline 38/38; nenhum ficheiro novo, runner sem edição) |
| 10 | `scripts/models/`, `scripts/snapshots/`, `attack_log.jsonl` | intactos: os dois `.pkl` com 539673 e 767 bytes e mtime 14/09/2026; `attack_log.jsonl` com as mesmas 12 linhas |

Ciclo TDD respeitado nas duas tasks: `test_ml_anomalies.py` correu a vermelho com `KeyError: 'alerts_fetched'` antes de `main.py` ser tocado; o `.cjs` novo correu a vermelho com `ReferenceError: mleOriginHtml is not defined` antes de `ml_evaluation.js` ter os helpers.

## Next Phase Readiness

- **A Fase 2 está fechada**: o 02-01Evaluation, o 02-02 contrato do payload, o 02-03 exportador e este 02-04 UI. `EVAL-03` e `UI-02` ficam cobertos por código; o que falta é a leitura com dados reais.
- **Risco residual a sinalizar:** o par `mlm*`/`mle*` do escopo global partilhado ganhou ~13 identificadores novos neste plano. A colisão está presa por três testes (o `vm` partilhado, a lista de prefixos e a intersecção nova), mas **cada ficheiro novo precisa do prefixo próprio desde a primeira linha** — não há teste que apanhe um nome colidente escrito depois da revisão.
- **Contrato da rota:** `/api/ml-anomalies` ganhou duas chaves. Qualquer consumidor novo deve tolerar a ausência delas (`alerts_truncated` ausente = "não truncado"), que é o caminho que o frontend trata.
- **Pendente de humano:** o `<human-check>` do plano (aba no browser com o laboratório ligado) e a primeira avaliação real sobre o dataset de 2026-09-14 — ver abaixo.

## `<human-check>` pendente (executado pelo utilizador, com o laboratório ligado)

> Este plano **não** executou nenhum `<human-check>`: nenhum serviço arranca nesta sessão. O que fica por verificar à mão, com os comandos exactos:

1. **Avaliação real sobre o dataset real (D-06), pela primeira vez.** Com a VM do Wazuh ligada, a partir de `scripts/`:
   ```powershell
   .\.venv\Scripts\python.exe export_raw_events.py --hours 168 --size 1000 --agent "WIN-PC01" --output raw_events_2026-10.json
   ```
   Depois avaliar a versão (que tem de existir: `python model_registry.py adopt` primeiro), com o `--dataset-origin real`:
   ```powershell
   .\.venv\Scripts\python.exe model_registry.py evaluate v1 --events snapshots\raw_events_2026-10.json --dataset-origin real
   ```
   **A verificar:** o CLI imprime `n ataques rotulados`. **Atenção ao que o 02-03 já registou:** o `attack_log.jsonl` actual só tem 12 entradas de **2026-10-06** e o dataset de 2026-09-14 está fora dessa janela — se exportar hoje o que o Indexer tem, o log tem de cobrir essa janela, senão `attacks_in_dataset = 0` e o recall sai 0 por definição (Pitfall 10). O próprio CLI avisa nesse caso.

2. **Painel no browser.** Com as três VMs ligadas: `.\scripts\start-backend.ps1` e depois `.\scripts\start-frontend.ps1`, abrir `http://localhost:5500/index.html` e clicar em **📐 Evaluation**.
   - **A verificar (2):** a tabela tem seis colunas; a linha da v1 traz `n eventos · m ataques`, o badge verde **"dados reais"** (ou o cinza **"origem não declarada"**, se o `evaluate` foi corrido sem `--dataset-origin`) e a linha de aviso âmbar com os dois limiares. Clicar com o rato no badge cinza mostra a explicação no `title`.
   - **A verificar (3):** mudar a janela para **168 h** — os números do bloco ao vivo mudam (ou passam a "Sem dados") **sem recarregar a página**, e a tabela de versões **não** muda.
   - **A verificar (4):** parar o Wazuh e carregar em **Atualizar** — o bloco ao vivo mostra a mensagem do Indexer (**não** "Sem dados"), com o texto vermelho, e a tabela de versões continua visível por cima.

---
*Phase: 02-avaliacao-ligada-a-versao*
*Completed: 2026-10-10*