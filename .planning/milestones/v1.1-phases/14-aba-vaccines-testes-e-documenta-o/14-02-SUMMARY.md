---
phase: 14-aba-vaccines-testes-e-documenta-o
plan: 02
subsystem: frontend
tags: [vaccines, dashboard, filters, generator-status, read-only, static-contract, escapeHtml]

requires:
  - phase: 14-aba-vaccines-testes-e-documenta-o
    provides: "14-01: aba Vaccines (vaccines.js), run_tracer e run_guards"
  - phase: 13-store-e-api-de-leitura
    provides: "GET /api/vaccines com query attack_id/technique/include_superseded e bloco generator"
provides:
  - "Filtros no servidor (ataque, tecnica MITRE, incluir substituidas) e botao Atualizar na aba Vaccines"
  - "Linha de estado do gerador (#vac-generator): ha X min, erro por codigo estavel, ataques a assentar, teto de alertas"
  - "Veredito em badge (vac-verdict-*) e vaccines substituidas esbatidas com 'Substituida por <id>'"
  - "run_filters e run_states em test_vaccines_frontend.py"
affects: [14-03 selecao/detalhe/cadeia, 14-04 documentacao]

status: complete
plan_head_before: 01f2301c5c189a894b0066565b6257bafa0ae699
plan_head_after: d7c102d40b0df59e11769c67150ec17f6ec1945f

actuals:
  tokens: 21000
  tasks: 2
  commits: 2

tech-stack:
  added: []
  patterns:
    - "Query string montada por URLSearchParams a partir de valores validados por regex; valor invalido nao faz pedido"
    - "Re-pedido unico no finally quando os filtros mudaram a meio (nunca dois pedidos em paralelo)"
    - "real_api_keys(extra_paths) pede caminhos com filtros a rota real sobre o store semeado"
    - "Texto do gerador em textContent; error_code so como chave de vacErrorText"

key-files:
  created: []
  modified:
    - index.html
    - vaccines.js
    - style.css
    - scripts/test_vaccines_frontend.py

key-decisions:
  - "Select de tecnica por uniao das tecnicas vistas na sessao (vacTechniques), preservando a selecao"
  - "Estado do gerador desconhecido ou ausente desenha 'Estado do gerador indisponivel/desconhecido' como erro, nunca o texto do servidor"
  - "Commits com o prefixo feat(14-02) por instrucao do orquestrador (o plano sugeria feat(vaccines-ui))"

requirements-completed: []

coverage:
  - id: D1
    description: "Filtros ataque/tecnica/substituidas e Atualizar vao ao servidor; a tabela mostra o subconjunto certo; filtro vazio distinto de Sem dados"
    requirement: VAC-07
    verification:
      - kind: unit
        ref: "scripts/test_vaccines_frontend.py (run_filters, rota real com TestClient)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Linha do gerador por codigo estavel, badges de veredito e vaccines substituidas esbatidas"
    requirement: VAC-07
    verification:
      - kind: unit
        ref: "scripts/test_vaccines_frontend.py (run_states)"
        status: pass
      - kind: manual
        ref: "Task 2 human-check (aspeto visual no browser) - pendente, juntado ao UAT no fim da fase"
        status: pending
    human_judgment: true
---

# Phase 14 Plan 02: Filtros, estado do gerador e badges Summary

**A aba Vaccines passa a filtrar no servidor (ataque, tecnica MITRE, incluir substituidas) com botao Atualizar, mostra o estado do gerador ("Ultima execucao ha X min" ou a frase do codigo estavel de erro), desenha o veredito em badge e esbate as vaccines substituidas com "Substituida por <id>"; tudo preso por run_filters/run_states ligados a rota real.**

## Performance

- **Tasks:** 2 (1 tracer + 1 auto/tdd)
- **Files modified:** 4 (nenhum criado)
- **Commits:** 2 (medidos pelo ledger, `plan_head_before` -> `plan_head_after`)

## Accomplishments

- **Task 1 (tracer, `072a78f`):** `div.filter-row` em `#vaccines-panel` (`#vac-attack-filter`, `#vac-technique-filter`, `#vac-superseded-filter`, `#vac-refresh-btn`). `vacBuildQuery()` valida o id de ataque (`VAC_ATTACK_ID_RE`; invalido devolve null e nao faz pedido, mostra a frase em `#vac-notice`), so aceita tecnicas que casam `VAC_TECHNIQUE_RE` e monta `URLSearchParams`. `vacRefresh()` ignora pedidos concorrentes e, no `finally`, corre UM novo pedido se a query visivel mudou. `vacAddTechniques`/`vacTechniqueOptionsHtml` acumulam as tecnicas (escapadas) e repoem a selecao. `run_filters` confirma markup, literais, e na rota real: `attack_id=3&technique=T1053` -> so C; `attack_id=2` -> so B; com `include_superseded=true` -> B e A; `technique=T9999` -> 200, `vaccines []`, `reason None`, `available True`.
- **Task 2 (`d7c102d`):** `#vac-generator` (panel-note, role=status). `vacAgo`, `vacGeneratorText`, `vacRenderGenerator` (texto em `textContent`, classe `vac-generator-error` em erro, explica `pending_settle` e `alerts_truncated`). `VAC_ERROR_TEXT` ganhou uma frase para cada codigo de `GENERATOR_ERROR_CODES`. `vacVerdictBadge`, `vacRowClass`, `vacSupersededNote`. Regras `vac-*` em `style.css`. `run_states` fixa tudo (frases para cada codigo, estados do gerador, campos lidos contra `GENERATOR_KEYS`, classes no CSS servido). Verificada a logica de `vacGeneratorText` com node (ok com pending/truncated, erro com ultimo sucesso, never_run, codigo desconhecido cai na frase generica).

## Task Commits

1. **Task 1: Tracer filtros + Atualizar** — `072a78f` (feat(14-02))
2. **Task 2: Gerador, badges, substituidas** — `d7c102d` (feat(14-02))

## Deviations from Plan

**1. [Instrucao do orquestrador] Prefixo dos commits**
- O plano sugeria `feat(vaccines-ui): ...`; o orquestrador exigiu `type(14-02): ...`. Os dois commits foram feitos primeiro como `feat(vaccines-ui)` (a85a488, 3e5d80d, nunca publicados) e reescritos com `git commit-tree` + `git reset --soft` (mesma arvore, so a mensagem mudou) para `feat(14-02)`. Nenhum ficheiro de trabalho foi tocado.

**2. [Rule 1 - Bug] `ok` nao era literal em `vacGeneratorText`**
- **Found during:** Task 2 (o check "cada estado de GENERATOR_STATUSES" falhou)
- **Fix:** o estado e agora validado explicitamente (`error`/`ok`/`no_data`); um estado desconhecido desenha "Estado do gerador desconhecido." como erro, em vez de cair no ramo de sucesso.
- **Files modified:** `vaccines.js`

Sem desvios de comportamento alem destes.

## Procedimento C

Nao foi necessario. `git diff --quiet -- index.html style.css` saiu 0 antes de qualquer edicao em ambas as tarefas (o trabalho alheio ja estava integrado em `a4bbc72`), por isso `index.html` e `style.css` foram editados e adicionados normalmente. Os criterios de aceitacao baseados em `git show HEAD:index.html | grep` dao os valores esperados. `.planning/config.json`, `.github/`, `packer/`, `scripts/.venv2/`, `.planning/state.json`, `.planning/milestone.lock` e `scripts/setup-boot-lab-entry.ps1` ficaram intocados.

## Verification

- `test_vaccines_frontend.py` (run_tracer, run_guards, run_filters, run_states): verde, 0 `[FALHOU]`.
- `run_all_tests.py vaccine`: 5/5.
- `run_all_tests.py` (suite completa): **45/45** (`git ls-files 'scripts/test_*.py'` mede 45), em 2 de 3 corridas completas; ver deferred issue abaixo para a corrida que falhou.
- `git diff --quiet 878d8e5 HEAD -- app.js` -> 0; nenhum `Co-Authored-By` nos commits do plano.

## Deferred Issues

- **`test_ml_training.py` intermitente na suite completa em paralelo** (1 corrida em 4 falhou 5 checks da secao "13. o temporario do joblib.dump e apagado": `(a) ... o %TEMP% ficou limpo`). Isolado passa sempre. O teste olha para `%TEMP%` por ficheiros com `ml_training.TEMP_PREFIX`, e partilha esse diretorio com os outros testes que correm em simultaneo; nem `test_vaccines_frontend.py` nem este plano criam ficheiros com esse prefixo (os temporarios dele usam `TemporaryDirectory` e sao limpos). Pre-existente, fora do ambito, nao corrigido.

## Known Stubs

Nenhum.

## Known Follow-ups (fora do ambito)

- O `<human-check>` visual da Task 2 (badges, linha esbatida, destaque do erro, backend parado) fica juntado ao UAT no fim da fase (D-09: sem browser automatizado).
- O estado do gerador e em memoria (A5 da Phase 13): depois de reiniciar o backend a linha diz "ainda nao correu" ate ao primeiro ciclo.
- VAC-07/VAC-08 continuam por fechar: so o 14-04 fecha a fase.

## Threat Flags

Nenhum: sem superficie nova. Mitigacoes do plano aplicadas: T-14-07 (validacao antes do pedido), T-14-17 (options e badge escapados, linha do gerador em `textContent`), T-14-18 (`error_code` so como chave), T-14-19 (re-pedido unico + frase distinta para filtro vazio).

## Self-Check: PASSED

- `vaccines.js`, `index.html`, `style.css`, `scripts/test_vaccines_frontend.py` existem; commits `072a78f` e `d7c102d` existem.
