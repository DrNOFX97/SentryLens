---
phase: 17-aba-testes-e-documenta-o
plan: 01
subsystem: ui
tags: [vaccines, decision, frontend, node-vm, ui_helpers]
status: complete

requires:
  - phase: 16-api-de-decisao
    provides: POST /api/vaccines/{id}/decision, estado derivado, notice, GET /api/soc/analysts
provides:
  - secção Decisão no detalhe da aba Vaccines (Aprovar / Rejeitar por data-action)
  - helpers puros slVacDecisionBody e slVacAnalystOptions em ui_helpers.js
  - vacDecide (único POST de vaccines.js) com guarda de clique duplo
  - prova por teste de que o corpo do helper é aceite pela rota real
affects: [17-02, 17-03, 17-06]

actuals:
  tokens: 10000
  tasks: 2
  commits: 2
plan_head_before: 42c218e071a95453b596aa9763655759c20b9b38
plan_head_after: 4c995f44cc2d068fc88e1c7bae635d9aeeb2ebff

tech-stack:
  added: []
  patterns:
    - "helper puro executado em node:vm a partir do teste Python (node_ui_helpers) para provar o contrato com a rota real"
    - "listener delegado com closest('[data-action]') sobre o contentor do bloco, vaccine lida de vacDetailVaccine e não do DOM"

key-files:
  created: []
  modified:
    - index.html
    - ui_helpers.js
    - vaccines.js
    - scripts/test_ui_helpers.cjs
    - scripts/test_vaccines_frontend.py

key-decisions:
  - "A secção Decisão é markup estático em index.html; o JS só mexe em hidden, disabled, textContent e nas option do select"
  - "Ordem da validação local: analista, escolha, motivo; o motivo conta pontos de código (Array.from), como o len do Python"
  - "Só entram na lista analistas com active === 1 ou true (o SQLite devolve 0/1)"
  - "O parâmetro com a escolha chama-se choice; decision fica reservado ao objeto vaccine.decision da API"

requirements-completed: [VLB-06, VLB-07]

duration: 25min
completed: 2026-10-30
---

# Phase 17 Plan 01: Aprovar e rejeitar no detalhe da vaccine Summary

**Tracer ponta a ponta da decisão: o analista aprova ou rejeita uma vaccine no detalhe, com validação local por `slVacDecisionBody` e `POST` real, sem handlers inline e com o corpo do helper provado contra a rota real.**

## Accomplishments

- `index.html`: secção Decisão no `#vaccine-detail-panel`, entre o aviso "não aplicada no Wazuh" e Origem (só `div`, sem `section` aninhado).
- `ui_helpers.js`: `slVacDecisionBody` e `slVacAnalystOptions`, puros e sem DOM.
- `vaccines.js`: lista de analistas, render do bloco, `vacDecide`, listener delegado e frases da validação local.
- Testes: `slVac*` em node:vm e contrato do bloco em `test_vaccines_frontend.py`, sem ficheiro de teste novo (a suite continua com 84 ficheiros).
- Backend, `app.js` e `api.js` intactos desde a base da fase (`git diff` vazio).

## Markup final da secção Decisão (ids)

`#vac-detail-decision` (div.vac-decision), `#vac-decision-state` (p), `#vac-decision-form` (div, `hidden`), `#vac-decision-analyst` (select, primeira option `value=""` "Escolher…"), `#vac-decision-reason` (textarea, `maxlength="500"`, `rows="3"`), `#vac-decision-count` (small, "0/500"), `p.vac-decision-final` (aviso fixo), `button[data-action="vac-approve"]` e `button[data-action="vac-reject"]` (type=button, começam `disabled`, classes `btn-primary` / `btn-danger`), `#vac-decision-status` (p, `role="status"`, fora do formulário).

## Assinaturas dos helpers

- `SL_VAC_REASON_MAX = 500`, `SL_VAC_ANALYST_ID_RE`, `SL_VAC_FORBIDDEN_REASON_RE` (flag `u`, categorias Cc Cf Cs Co Cn Zl Zp).
- `slVacDecisionBody(analystId, choice, reason)` devolve `{code, body}`; `body` é exatamente `{decision, analyst_id, reason}` (reason aparado ou null); códigos `analyst_required`, `invalid_author`, `invalid_decision`, `reason_required`, `invalid_reason`.
- `slVacAnalystOptions(envelope)` devolve `[{id, name}]` só de analistas ativos com id válido e nome não vazio; entrada ausente ou malformada dá `[]`.

## Chaves novas de `VAC_ERROR_TEXT` (validação local)

`analyst_required`, `invalid_author`, `invalid_decision`, `reason_required`, `invalid_reason`. As frases dos códigos do servidor são do 17-06. `VAC_STATE_LABELS` ganhou `approved: "Aprovada"` e `rejected: "Rejeitada"`.

## Entradas novas de `respostas` em `real_api_keys`

`decisao` e `decisao_rejeitar` ((estado, corpo) dos dois POST), `corpos` (corpos enviados, vindos do node), `analistas` (GET `/api/soc/analysts?active_only=true`, com um analista desativado semeado), `decisao_409` (segunda aprovação de `ID_C`) e `lista_decidida` (GET com `include_superseded=true` depois das decisões). As chaves de todas entram nas chaves reais. Sem node no PATH não há POST e as entradas de decisão ficam `None`, por isso os checks falham de propósito.

## Pins do teste que mudaram

- `run_tracer` e): passa a exigir um só `method:` e um só `"POST"`, dentro de `vacDecide`, e nenhum PUT/PATCH/DELETE.
- `run_detail` a): h3 do painel `["Decisão", "Origem", "Propostas", "Cadeia"]`.
- `run_detail` b): `'"/api/vaccines/"'` aparece 2 vezes (`vacSelect` e `vacDecide`).
- `_MESSAGE_SINKS` ganhou `vacRenderDecisionError` e `vacSetAnalystsError`; `SERVED_PATHS` ganhou `/ui_helpers.js`; `API_VARS` ganhou `decision` e `analyst`; os checks de campos usam agora `field_accesses` (vaccines.js mais os corpos `slVac*`).

## Task Commits

1. Task 1 (tracer): `add94b1` feat(vaccines-ui): aprovar e rejeitar no detalhe da vaccine
2. Task 2: `4c995f4` test(vaccines-ui): contrato do bloco Decisão

## Verificação

Saída de `python run_all_tests.py vaccine`: `9/9 ficheiros passaram`. Verdes também `test_vaccines_frontend.py`, `test_ui_helpers.py`, `test_frontend_static.py`, `test_no_raw_innerhtml.py`, `test_no_literal_colors.py`, `test_icons_a11y.py`, `test_serve_frontend.py`, `test_contrast.py`.

Pendente de verificação humana (fim de fase, `human_verify_mode: end-of-phase`; os testes não executam `vaccines.js`): com backend e frontend a correr, abrir Vaccines, escolher uma vaccine proposta, confirmar botões desativados com "Escolher…"; Rejeitar sem motivo mostra "Rejeitar exige um motivo…" sem POST no separador Network; Rejeitar com motivo e Aprovar mostram o aviso do servidor e a linha passa a Aprovada/Rejeitada; depois de recarregar o analista volta a "Escolher…".

## Deviations from Plan

None - plan executed exactly as written.

Nota de processo: os commits foram feitos diretamente em `main` (estratégia `branching_strategy: none`, execução sequencial pedida pelo orquestrador, mesmo precedente da Phase 16). A verificação de ramo protegido do protocolo de commit devolve "protegido" para `main`; não alterei a configuração para a contornar.

## Known Stubs

None. Limitação deliberada do tracer, que o 17-02 resolve: com a lista de analistas ainda por carregar, falhada ou vazia, o bloco mostra só o rótulo do estado (sem frase própria para esses casos).

## Threat Flags

None. Nenhuma superfície nova além da rota de decisão já coberta pelo threat model do plano; todo o texto dinâmico passa por `htmlT`/`textContent` e o POST usa `apiRequest` (chave no cabeçalho).

## Self-Check: PASSED

- index.html, ui_helpers.js, vaccines.js, scripts/test_ui_helpers.cjs e scripts/test_vaccines_frontend.py existem e contêm os símbolos prometidos.
- Commits `add94b1` e `4c995f4` presentes no histórico de `main`.
