---
phase: 17-aba-testes-e-documenta-o
plan: 03
subsystem: ui
tags: [vaccines, state-badge, filter, kpi, css-tokens, ui_helpers, node-vm]
status: complete

requires:
  - phase: 17-aba-testes-e-documenta-o
    provides: 17-01/17-02 (bloco Decisão, vacRenderDecision, vacRefresh com fila) e 17-06 (frases dos erros)
  - phase: 16-api-de-decisao
    provides: ?state= na rota, state_counts no envelope, estado derivado
provides:
  - badge de estado (texto + classe) na coluna Estado e no bloco Decisão
  - estilos da aba com tokens (.vac-state*, .vac-decision*) e regra [hidden] do formulário
  - filtro por estado (#vac-state-filter) igual a main.VaccineState
  - três contadores das vaccines atuais (#vac-counts) com — sem amostra
  - cabeçalho e comentário de topo sem "só leitura"
affects: [17-05]

actuals:
  tokens: 8400
  tasks: 2
  commits: 2
plan_head_before: 156a4309eeb4573e9acbcd510b5cd249ff33d043
plan_head_after: ba0affd511f32f8efb4fd58bb95ca2445c8ed29a

tech-stack:
  added: []
  patterns:
    - "o vacStateBadge real corre em node:vm com um htmlT simulado (só as 4 declarações de que depende) para provar classe, escape e travessão"
    - "o varrimento de [hidden] lê o index.html servido e exige .<classe>[hidden] sempre que a classe tem display em style.css"
    - "o state_counts REAL da rota (depois das decisões) e o de um store inexistente passam por slVacStateCounts em node"

key-files:
  created: []
  modified:
    - vaccines.js
    - style.css
    - index.html
    - ui_helpers.js
    - scripts/test_ui_helpers.cjs
    - scripts/test_vaccines_frontend.py
    - scripts/test_migration_ml_vaccines.cjs

key-decisions:
  - "Proposta e estado desconhecido partilham a cor neutra; o texto do badge é sempre a pista principal"
  - "Os contadores reutilizam .kpi-grid e kpiRender (— neutro, nunca 0) em vez de um componente novo"
  - "vacShowDecisionLines aceita linhas em texto simples ou já em htmlT, para meter o badge na linha de estado"

requirements-completed: [VLB-06, VLB-07]

duration: 20min
completed: 2026-11-04
---

# Phase 17 Plan 03: Estado visível na lista Summary

**O estado de cada vaccine passa a ver-se em badge com texto na tabela e no bloco Decisão, filtra-se por Proposta/Aprovada/Rejeitada, três contadores das vaccines atuais mostram — quando não há amostra, e a aba deixa de dizer "só leitura".**

## Accomplishments

- `vaccines.js`: `vacStateBadge` (modificador de classe só para proposed/approved/rejected, senão `vac-state-unknown`; ausente ou não-string é `—`), `VAC_STATES`, `vacRenderCounts`, `state` em `vacBuildQuery`, `vac-state-filter` na lista de `change`, comentário de topo reescrito.
- `ui_helpers.js`: `slVacStateCounts` (inteiro >= 0 ou `null` por chave, forma fixa de 3 chaves, só chaves próprias).
- `style.css`, `index.html`, testes (ver abaixo).
- Backend, `app.js`, `api.js`, `kpi.js` e `serve_frontend.py` intactos face à base da fase (`git diff` vazio).

## Regras CSS acrescentadas

```css
/* regra partilhada dos badges: + .vac-state */
.vac-state { background: var(--neutral-bg); color: var(--text); }
.vac-state-approved { background: var(--sev-low-bg); }
.vac-state-rejected { background: var(--sev-high-bg); }
.vac-decision { margin: 0 0 12px; padding: 12px 16px; border: 1px solid var(--border); border-radius: 8px; background: var(--surface-sunken); }
.vac-decision-form { display: grid; gap: 8px; }
.vac-decision-form[hidden] { display: none; }
.vac-decision-final { font-size: var(--fs-sm); color: var(--text-secondary); font-weight: 600; margin: 0; }
.vac-decision-error { color: var(--sev-critical-fg); font-weight: 600; }
.vac-decision-actions button:disabled { opacity: .5; cursor: not-allowed; }
```

## Markup (index.html)

Filtro, na `filter-row`, a seguir ao select de técnica: `<label for="vac-state-filter">Estado:</label>` e `<select id="vac-state-filter">` com Todos (`""`), Proposta, Aprovada, Rejeitada.

Contadores, logo a seguir ao `panel-note` do cabeçalho e antes da `filter-row`:

```html
<div class="kpi-grid" id="vac-counts" role="group" aria-label="Vaccines atuais por estado">
  <div class="card" id="vac-count-proposed"><h3>Propostas</h3><div class="value">—</div></div>
  <div class="card" id="vac-count-approved"><h3>Aprovadas</h3><div class="value">—</div></div>
  <div class="card" id="vac-count-rejected"><h3>Rejeitadas</h3><div class="value">—</div></div>
</div>
<p class="panel-note">Contagem das vaccines atuais (sem as substituídas), independente dos filtros da tabela.</p>
```

## Texto final do cabeçalho

"Regras de deteção PROPOSTAS a partir de ataques não detetados ou só parcialmente detetados no Red vs Blue, geradas pelo backend em segundo plano. No detalhe, um analista da Equipa SOC pode aprovar ou rejeitar cada proposta atual; a decisão é final e fica registada com autor, data e motivo. Aprovada significa só aceite pelo analista: nenhuma vaccine é aplicada no Wazuh."

## Verificação

- `python run_all_tests.py vaccine`:

```
PASS test_migration_ml_vaccines.py
PASS test_vaccine_decision.py
PASS test_vaccine_decision_api.py
PASS test_vaccine_decision_store.py
PASS test_vaccine_engine.py
PASS test_vaccine_ingest.py
PASS test_vaccine_store.py
PASS test_vaccines_api.py
PASS test_vaccines_frontend.py

9/9 ficheiros passaram
```

- `python run_all_tests.py` (suite completa, depois do segundo commit): `84/84 ficheiros passaram`.
- Verdes também `test_ui_helpers`, `test_frontend_static`, `test_no_raw_innerhtml`, `test_no_literal_colors`, `test_contrast`, `test_icons_a11y`, `test_serve_frontend`.
- Prova de sensibilidade: com `VAC_STATES` acrescido de um valor falso e sem `vacRenderCounts(null)` no caminho de erro, `test_vaccines_frontend.py` falha nos dois checks respetivos (ficheiro restaurado a seguir).
- Mensagens de commit sem `Co-Authored-By`.

Pendente de verificação humana (fim de fase, os testes não executam `vaccines.js` num browser): com backend e frontend a correr e vaccines em vários estados, abrir Vaccines -> Candidates e ler cabeçalho, contadores (não mudam ao filtrar; mostram — com o store vazio) e coluna Estado; usar o filtro Estado e "Incluir substituídas"; abrir uma vaccine aprovada, uma rejeitada e uma substituída; repetir no modo escuro.

## Task Commits

1. Task 1: `7b2c3e2` feat(vaccines-ui): badge de estado e estilos do bloco Decisão
2. Task 2: `ba0affd` feat(vaccines-ui): filtro por estado, contadores e textos da aba

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Harness de `test_migration_ml_vaccines.cjs` sem `ui_helpers.js` e `kpi.js`**
- **Found during:** Task 2, `run_all_tests.py vaccine` (1 falha: `ReferenceError: slVacStateCounts is not defined`)
- **Issue:** o teste carrega `vaccines.js` num contexto só com `api.js`, `state.js`, `html.js` e os ficheiros de ML. O caminho de erro de `vacRefresh` passou a chamar `vacRenderCounts(null)`, que usa `slVacStateCounts` e `kpiRender`; no browser ambos carregam antes de `vaccines.js` (índice do `index.html`), no harness não.
- **Fix:** acrescentar `ui_helpers.js` e `kpi.js` à lista de ficheiros carregados, pela mesma ordem do `index.html`.
- **Files modified:** `scripts/test_migration_ml_vaccines.cjs` (fora de `files_modified` do plano)
- **Commit:** `ba0affd`

### Notas de processo

- TDD: escrevi o teste primeiro nas duas tarefas, mas não corri cada um contra o código antigo antes de implementar (o primeiro `Run` já foi sobre o código novo; o único RED visto foi o de `css_rules` a incluir comentários no seletor). A sensibilidade dos checks foi provada depois por mutação (ver Verificação).
- O check `[hidden]` da Task 1 só obriga a regra para classes com `display` próprio; `.panel` (painel de detalhe com `hidden`) não tem `display`, por isso a regra nativa chega.
- Commits feitos diretamente em `main` (execução sequencial pedida pelo orquestrador, mesmo precedente dos planos anteriores da fase).

## Known Stubs

None.

## Threat Flags

None. T-17-12 a T-17-15 mitigadas: o modificador de classe só aceita os três estados (provado com `<b>x</b>` e `constructor`); `?state=` só sai se estiver em `VAC_STATES`, igual a `main.VaccineState`; os contadores dão — com `null`/inválido (provado contra o `state_counts` real e um store inexistente); o cabeçalho e o comentário de topo já não dizem "só leitura".

## Self-Check: PASSED

- `vaccines.js` define `vacStateBadge`, `vacRenderCounts` e `VAC_STATES`; `ui_helpers.js` define `slVacStateCounts`; `index.html` tem `id="vac-state-filter"` e `id="vac-counts"`; `style.css` tem `.vac-state-approved` e `.vac-decision-form[hidden]`; `scripts/test_vaccines_frontend.py` tem `def run_state_ui`.
- Commits `7b2c3e2` e `ba0affd` presentes no histórico de `main`.
