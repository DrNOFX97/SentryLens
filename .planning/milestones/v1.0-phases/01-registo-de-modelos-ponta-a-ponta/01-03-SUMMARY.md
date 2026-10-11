---
phase: 01-registo-de-modelos-ponta-a-ponta
plan: 03
subsystem: ui
tags: [vanilla-js, node-vm, frontend-estatico, escape-html, acessibilidade-teclado, testing]

# Dependency graph
requires:
  - phase: (nenhuma — continua a primeira fatia do R9)
    provides: "ml_models.js com a camada pura (mlmErrorText, mlmCell, mlmBuildModelsRows) e a camada DOM testadas em node:vm por test_ml_models_ui.py + test_ml_models_ui.cjs"
    plan: "01-01 (36724f6, cbbefd6, b9155af, 6703532)"
  - phase: (nenhuma)
    provides: "o contrato de GET /api/ml/models já transporta active, active_error, loaded, status/error_code por versão, a entrada legacy (kind/status no_metadata + files) e os metadados completos de cada vN"
    plan: "01-02 (a1e4001, 2605b32, d5ba48a)"
provides:
  - "ml_models.js: mlmStatusText, mlmFormatDate, mlmOriginText/Xml, mlmTrainedAtText — os 8 estados do contrato mapeados a texto PT, sem o código em bruto"
  - "ml_models.js: mlmModelsNoticeText com os cinco avisos (ACTIVE inválido, ativo legado, adopt interrompido, loaded != active, ainda não carregou)"
  - "ml_models.js: linhas com class atk-row/data-index/tabindex, painel de detalhe (mlmBuildDetail, mlmRenderDetail, mlmSelectEntry) e seleção por rato e Enter/Espaço que segue a chave da versão entre refrescamentos"
  - "index.html: #ml-models-detail-panel com meta, artefactos, parâmetros, dataset e avaliação"
  - "scripts/test_ml_models_ui.cjs: 185 casos Node (era 71), com fixtures inline do SKELETON.md e do relatório real do legado"
affects: [01-04-adocao, fase-2-avalicao, fase-3-treino, r10-ativar-versoes]

# Actuals — pares com o `estimate` do plano para calibrar estimativas futuras.
actuals:
  tokens: 19900
  tasks: 2
  commits: 2

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Camada pura por behaviour: cada estado novo da UI é um helper que devolve texto/HTML e tem casos Node próprios; a função que escreve no DOM só cola o resultado (node:vm carrega ml_models.js sem DOM, logo nenhuma linha de topo pode tocar em document)"
    - "Seleção por CHAVE, não por índice: mlmEntryKey/mlmFindEntryIndex re-resolvem a versão em cada refresh, para a lista poder reordenar-se e para o legado desaparecer depois de um adopt sem o detalhe ficar a mostrar outra versão"
    - "Estado não-errado desenha-se neutro: 'no_metadata' sem error_code (o legado, que está a ser usado) nunca entra num badge de vermelho"

key-files:
  created: []
  modified:
    - ml_models.js
    - index.html
    - scripts/test_ml_models_ui.cjs

key-decisions:
  - "mlmStatusText devolve texto simples e quem o decide é quem desenha: só os estados que não são 'ok' nem 'no_metadata' entram em span mlm-badge-error — assim o legado, o 'ok' e os 6 erros ficam decididos num único sítio, com o badge de erro impercetível para quem só chama o helper"
  - "'(estimada)' só aparece quando há data: sem trained_at devolve 'desconhecido' a seco, não 'desconhecido (estimada)' (ver Deviation 1)"
  - "mlmOriginText/mlmOriginHtml separados: o detalhe precisa do texto simples e a tabela precisa do badge; duplicar a regra de origem era pedir que divergissem"
  - "Um objeto de parâmetros/versões de bibliotecas com valores não-escalados nunca entra no innerHTML: cada chave e cada valor vai por escapeHtml, e uma lista vazia é 'desconhecido', não uma lista sem linhas"
  - "Em erro de pedido o detalhe esconde-se e a seleção é limpa: mostrar o detalhe de uma versão de um relatório que já não está no ecrã seria afirmar um estado que ninguém pediu"

patterns-established:
  - "Pattern: fakeEvent(key, indice) no teste Node — um evento com {key, target.closest(seletor), preventDefault que conta} e um callback que regista os índices chamados; é o que permite testar teclado sem DOM"
  - "Pattern: fixtures inline no .cjs que copiam a entrada do contrato do SKELETON.md, ao lado das fixtures reais que o wrapper Python tira da rota — o contrato escrito e o contrato implementado são testados lado a lado"

requirements-completed: [UI-01, REG-02, API-02]

coverage:
  - id: D1
    description: "A aba Models marca a versão ativa, o modelo legado e uma versão adotada com badges distintos, e diz o estado de integridade de cada uma em português"
    requirement: UI-01
    verification:
      - kind: automated_ui
        ref: "scripts/test_ml_models_ui.cjs#mlmStatusText (8 estados) + mlmOriginHtml + fixture legacy do SKELETON.md + report_legacy.json real"
        status: pass
    human_judgment: false
  - id: D2
    description: "Uma versão com problema (hash_mismatch, artifact_missing, metadata_missing, metadata_invalid, invalid_version_id, registry_unavailable) mostra a mensagem de MLM_ERROR_TEXT; nenhum dos 6 códigos, nem o detail da resposta, chega ao HTML"
    requirement: API-02
    verification:
      - kind: automated_ui
        ref: "scripts/test_ml_models_ui.cjs#linhas com os 6 estados de erro: badge + mensagem PT e código ausente"
        status: pass
      - kind: automated_ui
        ref: "scripts/test_ml_models_ui.cjs#mlmErrorText / mlmCodeFromResponse (do 01-01, mantidos)"
        status: pass
    human_judgment: false
  - id: D3
    description: "A aba avisa, com texto acionável, quando o ACTIVE é inválido, quando falta completar um adopt, quando o ativo é o legado, e quando o processo carregou uma versão diferente da ativa (D-02)"
    requirement: UI-01
    verification:
      - kind: automated_ui
        ref: "scripts/test_ml_models_ui.cjs#os cinco avisos de mlmModelsNoticeText (inclui 'loaded == active' NÃO pedir reinício)"
        status: pass
    human_judgment: false
  - id: D4
    description: "Selecionar uma versão (rato, Enter ou Espaço) abre o detalhe com origem, datas, tipo, parâmetros, dataset, versões de bibliotecas, SHA-256 e tamanho de cada artefacto, com 'desconhecido' em cada valor null"
    requirement: UI-01
    verification:
      - kind: automated_ui
        ref: "scripts/test_ml_models_ui.cjs#mlmBuildDetail: entrada completa, entrada com tudo null, legado (inline e real) e versão sem metadata.json"
        status: pass
    human_judgment: false
  - id: D5
    description: "Enter e Espaço selecionam a linha focada (e chamam preventDefault uma vez); qualquer outra tecla não faz nada; a seleção segue a chave da versão entre refrescamentos e desaparece quando a versão já não está na lista"
    requirement: UI-01
    verification:
      - kind: automated_ui
        ref: "scripts/test_ml_models_ui.cjs#mlmIsSelectKey / mlmHandleRowKey (Enter, Espaço, Spacebar, 'a', Tab, fora de linha) / mlmRowIndexFromEvent / mlmFindEntryIndex (reordenação e legado depois do adopt)"
        status: pass
    human_judgment: false
  - id: D6
    description: "Nenhum texto vindo de scripts/models/ chega ao DOM sem escape: label, datas de treino e de ficheiro, chaves e valores de parâmetros e de bibliotecas, nome do dataset e hashes"
    requirement: UI-01
    verification:
      - kind: automated_ui
        ref: "scripts/test_ml_models_ui.cjs#XSS: <script> no label, <img> na data do ficheiro, <b>/<img> em parameters e library_versions"
        status: pass
    human_judgment: false
  - id: D7
    description: "A entrada do legado continua neutra depois da expansão: badge 'legado, sem metadados', badge 'ativa', estado 'Sem metadados nem hash...', data do ficheiro e 'Sem avaliação'"
    requirement: REG-02
    verification:
      - kind: automated_ui
        ref: "scripts/test_ml_models_ui.cjs#report_legacy.json (resposta real da rota): sem mlm-badge-error, sem MLM_GENERIC_ERROR, '(data do ficheiro)'"
        status: pass
    human_judgment: false
  - id: D8
    description: "A aba Models no browser real com o modelo legado do utilizador: aspeto dos badges, clique, Enter numa linha com foco, painel de detalhe e ausência de caminhos no ecrã"
    requirement: UI-01
    verification: []
    human_judgment: true
    rationale: "node:vm não tem DOM: os testes provam as strings que os helpers devolvem e a aritmética da seleção, não o aspeto, o foco visível de uma <tr tabindex=0>, o clique a sério nem o aspeto do painel de detalhe. Exige o <human-check> da Task 2 com o backend e o frontend arrancados, que não foi executado neste ambiente (acumula com coverage.D10 de 01-01 e de 01-02)."

# Metrics
duration: 26min
completed: 2026-10-10
status: complete
---

# Phase 1 Plan 03: Estados e detalhe da aba Models — Summary

**A aba Models passou a distinguir ativa, legado, adotada e versões com problema com mensagens PT acionáveis, e a dizer quando é preciso reiniciar o backend; selecionar uma versão (rato ou Enter/Espaço) abre um painel de detalhe com os SHA-256, os tamanhos e todos os metadados, com "desconhecido" em cada valor em falta.**

## Performance

- **Duration:** ~26 min
- **Started:** 2026-10-10T13:28:00+01:00
- **Completed:** 2026-10-10T13:54:00+01:00
- **Tasks:** 2 (Task 1 estados e avisos; Task 2 painel de detalhe)
- **Files modified:** 3 (nenhum criado) — 815 linhas, +796/−19
- **Estimate do plano:** 50 000 tokens / 2 tasks — o real foi ~19 900 (chars/4 sobre o diff).

## Accomplishments

- **Os oito estados do contrato estão mapeados um a um e provados um a um.** `mlmStatusText` devolve texto simples para `ok` ("Íntegra (SHA-256 verificado)"), para `no_metadata` ("Sem metadados nem hash — carrega sem verificação até ser adotado") e, para qualquer outro, a mensagem de `MLM_ERROR_TEXT`; um código inventado cai na genérica. A tabela é quem decide o que vai dentro de um `span mlm-badge-error`, e esse critério não é "`status != ok`" — é "`status` não é `ok` nem `no_metadata`". Com isso, o legado (que tem `status: "no_metadata"` e `error_code: null` porque está a ser usado à vontade, REG-02) não pode voltar a aparecer a vermelho, e nenhum dos seis códigos de problema chega ao HTML em bruto.
- **Os cinco avisos dizem o que fazer, não o que aconteceu.** ACTIVE inválido aponta para `models/ACTIVE` e para os 503; ativo legado sugere `python model_registry.py adopt`; `active: null` com versões em lista sugere voltar a correr o adopt (o adopt interrompido do 01-04); `loaded != active` diz que o backend está a usar outra versão e manda reiniciar o `start-backend.ps1` com os dois nomes entre «» (D-02); e `loaded: null` diz que ainda não carregou. O caso `loaded == active` foi testado a **não** pedir reinício, senão o aviso vira ruído e ninguém o lê.
- **A seleção segue a chave da versão, não a posição na tabela.** Entre dois refrescamentos a lista pode reordenar-se, e o legado desaparece depois de um adopt (D-03). Com a posição, o detalhe mudava de versão sozinho; com a chave, `mlmFindEntryIndex` re-resolve a cada refresh e devolve `-1` → o painel esconde-se. Ambos os casos têm teste.
- **O detalhe é honesto sobre o que não sabe:** `desconhecido` em cada `null` (dataset com os quatro campos a null dá quatro `desconhecido`), `sem hash registado` nos dois `.pkl` do legado com o tamanho e a data do ficheiro, e para uma versão sem `metadata.json` utilizável uma linha `empty-state` com a mensagem de `MLM_ERROR_TEXT.metadata_invalid` — nunca o código, nunca um caminho.
- **Nada do que vem de `scripts/models/` entra no DOM sem `escapeHtml`**, incluindo as chaves e os valores dos objetos (`parameters`, `library_versions`) e os nomes do dataset, com quatro fixtures de XSS nos testes Node.

## Task Commits

Cada task foi commitada atomicamente:

1. **Task 1: Estados da aba Models — legado, adotado, erros por versão, avisos de ACTIVE e de modelo carregado** — `efd8a9b` (feat)
2. **Task 2: Painel de detalhe dos metadados da versão selecionada** — `1f584c5` (feat)

_Note: as duas tasks têm `tdd="true"`. Os casos de comportamento foram acrescentados primeiro a `scripts/test_ml_models_ui.cjs` e corridos a falhar — `ReferenceError: mlmStatusText is not defined` na Task 1 e `ReferenceError: mlmEntryKey is not defined` na Task 2 — e só depois o JavaScript foi implementado._

**Commits sem `Co-Authored-By` e sem "Generated with ..."** (D-08): confirmado com `git log --format=%B d5ba48a..HEAD` filtrado por `co-authored-by|generated with` → **vazio**. (O `grep` binário não existe nesta máquina Windows; foi o equivalente em PowerShell, `Select-String`.)

## Files Created/Modified

- `ml_models.js` — **alterado.** +245/−5 na Task 2, +124/−19 na Task 1. Camada pura nova: `MLM_OK_TEXT`, `MLM_NO_METADATA_TEXT`, `MLM_ARTIFACT_NAMES`, `mlmStatusText`, `mlmFormatDate`, `mlmOriginText`, `mlmOriginHtml`, `mlmTrainedAtText`, `mlmEntryKey`, `mlmFindEntryIndex`, `mlmRowIndexFromEvent`, `mlmIsSelectKey`, `mlmHandleRowKey`, `mlmLibraryVersionsText`, `mlmArtifactsHtml`, `mlmParamsHtml`, `mlmDatasetHtml`, `mlmBuildDetail`; `mlmBuildModelsRows` reescrito (5 colunas com badges e origem/data reais, `class="atk-row" data-index tabindex="0"`) e `mlmModelsNoticeText` reescrito com os cinco avisos. Camada DOM: `mlmLastReport`/`mlmSelectedKey`, `mlmRenderDetail`, `mlmMarkSelectedRow`, `mlmHideDetail`, `mlmSelectEntry`, `mlmReapplySelection`, listeners `click`/`keydown` no `#mlm-models-body` dentro de `mlmInit`, e o `catch` de `mlmRefresh` a limpar o estado. `app.js` não foi tocado.
- `index.html` — **alterado.** +20 linhas: `section.panel#ml-models-detail-panel[hidden]` dentro de `#tab-ml-models`, depois de `#ml-models-panel`, com `h2#mlm-detail-title`, `div#mlm-detail-meta.inc-meta`, `ul#mlm-detail-artifacts` / `#mlm-detail-params` / `#mlm-detail-dataset` (`.atk-evidence`) e `p#mlm-detail-eval`. Nenhum id novo na whitelist do `serve_frontend.py` (é HTML dentro do `index.html` já servido).
- `scripts/test_ml_models_ui.cjs` — **alterado.** +436 linhas, 71 → **185** checks. Fixtures inline `versioned()`/`legacy()` copiadas do contrato do `SKELETON.md` (`SHA_MODEL`/`SHA_SCALER` de 64 hex, `size_bytes` 539673/767, `trained_at_estimated: true`), a matriz dos 6 estados de erro, os 5 avisos, o detalhe (completo, tudo-null, legado inline, legado real de `report_legacy.json`, versão sem `metadata.json`), e `fakeEvent(key, indice)` para o teclado. `scripts/test_ml_models_ui.py` **não** precisou de mudar: as fixtures reais que faltavam já eram `report_v1`/`report_legacy`/`report_empty`.

## Decisions Made

- **`mlmStatusText` devolve texto simples e não decide o badge.** A função tem de responder a `mlmStatusText({status: "ok"}) === "Íntegra (SHA-256 verificado)"` e a `mlmStatusText` de um erro dar exactamente `MLM_ERROR_TEXT[código]` — o que é o mesmo valor com ou sem badge. Quem decide o `span` é a tabela, e assim um erro continua a ser reconhecido por `status` (não por `error_code`, que era o critério do 01-02 e que também funciona, mas deixa o "estado" e o "aspeto" no mesmo sitio).
- **`mlmOriginText` e `mlmOriginHtml` em vez de uma função só.** O detalhe precisa de texto simples e a tabela precisa do badge; era uma regra de origem escrita duas vezes, e duas regras iguais divergem.
- **Chaves de `parameters` e `library_versions` ordenadas alfabeticamente** antes de as desenhar. Um objeto JSON vem na ordem do ficheiro, que é ordem de escrita; ordenar dá um detalhe estável entre refrescamentos e torna o teste comparável.
- **O detalhe é desenhado a partir do relatório já carregado, sem novo pedido.** A lista já traz `metadata` e `files` completos, por isso pedir outra vez seria um pedido por clique sem ganho nenhum.
- **`renderPanelError("#ml-models-detail-panel", "")` antes de preencher.** Um erro de carregamento anterior que tenha criado o banner não pode ficar por cima do detalhe novo (o mesmo cuidado que o `renderPanelError` dos painéis de lista já tem).
- **`mlmArtifactsHtml` devolve a linha `empty-state` no primeiro artefacto em falta** de uma versão sem metadados, em vez de duas linhas iguais. Uma mensagem de erro repetida duas vezes lê-se como bug.
- **O texto de `evalText` continua a ser "Sem avaliação"** (D-05) — nenhuma versão tem avaliação até à Fase 2, e o `evalText` nunca mostra números.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 5 — Correcção] `trained_at` null devolvia "desconhecido (estimada)"**
- **Found during:** Task 1, primeira execução do `test_ml_models_ui.py` depois de implementar
- **Issue:** o plano descreve `mlmTrainedAtText` como "mlmFormatDate(trained_at) seguido de ' (estimada)' quando trained_at_estimated === true". Aplicado à letra, uma versão sem `trained_at` mas com `trained_at_estimated: true` (que é o caso real de um `metadata.json` escrito por outra ferramenta) mostrava "desconhecido (estimada)" — dizer ao mesmo tempo que não se sabe a data e que se sabe que é estimada. O próprio `behavior` do plano diz "trained_at null dá 'desconhecido'".
- **Fix:** o sufixo só é acrescentado quando há data; sem `trained_at` a função devolve `desconhecido` a seco. A data estimada continua marcada em todas as versões que a têm.
- **Files modified:** `ml_models.js`
- **Verification:** `test_ml_models_ui.py` exit 0 (o caso `mlmTrainedAtText: sem data de treino -> desconhecido` falhava antes da correção e passa depois); `run_all_tests.py` 36/36
- **Committed in:** `efd8a9b`

---

**Total deviations:** 1 auto-fixed (1 correcção)
**Impact on plan:** a correção resolve a contradição interna entre o `action` e o `behavior` do plano a favor do comportamento especificado. Zero scope creep — nada foi criado fora dos `files_modified`, nenhuma capacidade foi acrescentada e nenhum ficheiro novo apareceu.

## Issues Encountered

- **O `grep` do comando de verificação (`git log ... | grep -i "co-authored-by|generated with"`) não existe nesta máquina Windows** — não há `grep` binário no PATH. A verificação foi feita com o equivalente exato em PowerShell (`git log --format=%B d5ba48a..HEAD | Select-String -Pattern "co-authored-by|generated with"`) → vazio. Fica registado porque o `CLAUDE.md` do projeto dá esse comando como verificação de D-08 e ele não é executável tal como está escrito neste ambiente.
- **O `data-index` da linha e a seleção por teclado não podiam ser provados com o relatório real**, porque `report_v1.json` e `report_legacy.json` só têm uma versão cada e o `behavior` fala de posições 0, 1, 2. As fixtures inline do `SKELETON.md` (que o plano mandava usar) cobriram isso; os relatórios reais continuam a ser testados em paralelo, para o contrato escrito e o contrato implementado não ficarem separados.

## Commands Run (resultados reais)

| Comando | Resultado |
|---|---|
| `cd scripts && .venv/Scripts/python test_ml_models_ui.py` | **exit 0** — 3 checks do wrapper + **185** checks Node `[OK]` (189 no total), zero `[FALHOU]` (71 checks Node no fim do 01-02) |
| `cd scripts && .venv/Scripts/python test_serve_frontend.py` | **exit 0** — 43 checks `[OK]`, zero `[FALHOU]`; inclui `/ml_models.js é servido como JavaScript`, o check de prefixo `mlm`/`MLM_` em todas as declarações de topo e os 9 códigos de D-06 |
| `cd scripts && .venv/Scripts/python test_ml_models_api.py` | **exit 0** — 109 checks `[OK]`, zero `[FALHOU]` (não foi tocado; correram-se para confirmar que a mudança é só de frontend) |
| `node --check ml_models.js` | **exit 0** (Node v24.14.1) |
| `cd scripts && .venv/Scripts/python run_all_tests.py` | **exit 0** — `36/36 ficheiros passaram` (mesma contagem do baseline; nenhuma regressão) |
| `grep -q 'id="ml-models-detail-panel"' index.html` (+ os outros 5 ids) | **todos presentes** (`ml-models-detail-panel`, `mlm-detail-title`, `mlm-detail-meta`, `mlm-detail-artifacts`, `mlm-detail-params`, `mlm-detail-dataset`, `mlm-detail-eval`) |
| `grep -q 'function mlmRenderDetail'` / `'function mlmSelectEntry'` / `'mlmHandleRowKey('` em `ml_models.js` | **todos presentes** |
| declarações de topo de `ml_models.js` fora do prefixo `mlm`/`MLM_` | **`[]`** |
| linhas de topo que tocam em `document` | **1**, e é a guarda `if (typeof document !== "undefined") { mlmInit(); }` |
| `git log --format=%B d5ba48a..HEAD \| Select-String "co-authored-by\|generated with"` | **vazio** (23 linhas de mensagem revistas, 0 correspondências) |

Baseline antes de qualquer alteração: `run_all_tests.py` **36/36**.

**Verificação humana por fazer:** o `<human-check>` da Task 2 (`coverage.D8`) **não foi executado** — este ambiente não arrancou o backend nem o frontend, e não há DOM nos testes standalone. Continua a acumular com o `coverage.D10` do 01-01 e do 01-02.

## User Setup Required

None — no external service configuration required. Nenhum serviço novo, nenhuma variável de ambiente nova, nenhuma entrada nova na whitelist do `serve_frontend.py` (o painel de detalhe é HTML dentro do `index.html`, que já é servido).

## Next Phase Readiness

- **01-04 (adopt)** pode mostrar, depois de um adopt bem-sucedido, exatamente o que os avisos já sabem dizer: `active` deixa de ser `"legacy"`, a entrada `kind: "legacy"` desaparece da lista (D-03) e o detalhe que estava aberto nela tem de esconder-se — é o caso `mlmFindEntryIndex(APOS_ADOPT, "legacy") === -1`, já coberto por teste. Se o adopt for interrompido entre criar a `v1` e escrever o `ACTIVE`, a UI mostra o aviso (c) ("Nenhuma versão ativa... volta a correr o adopt"), que é o texto certo para esse estado.
- **Fase 2 (avaliação)** só tem de escrever `evaluation` no `metadata.json`: `mlmBuildEvalRows`, `mlmBuildDetail.evalText` e a coluna Avaliação já distinguem "não há" de "há" sem mostrarem números, e nenhum deles precisa de mudar para exibir métricas — é trabalho novo, não uma adaptação.
- **Fase 3 (treino)** ganha o `origin: "trained"` sem `adopted: true`: `mlmOriginText` já devolve "treinado" e `mlmTrainedAtText` já deixa de marcar "(estimada)" quando `trained_at_estimated` for false. Os `parameters`, `library_versions` e `dataset` que o treino vai preencher já têm casa no detalhe.
- **`SKELETON.md` ficou ligeiramente atrás da implementação, como o 01-02 já tinha registado:** a tabela de `status` de uma entrada versionada continua a não listar `no_metadata`, que é o `status` da entrada **legacy** (linha 86 do SKELETON define a entrada, mas a lista de estados da linha 85 não o inclui). Não foi corrigido aqui: o `SKELETON.md` é contrato, e mexer nele é do 01-04 ou de DOC-01.
- **Sem dívida técnica deixada por este plano.** O único ponto a vigiar é o mesmo do 01-02 e continua valendo: o SHA-256 deteta corrupção e troca acidental, **não autentica** (D-04, T-01-09), e o legado carrega sem verificação até ser adotado (T-01-10) — a UI diz "Sem metadados nem hash — carrega sem verificação até ser adotado", que é a afirmação honesta.

---
*Phase: 01-registo-de-modelos-ponta-a-ponta*
*Completed: 2026-10-10*