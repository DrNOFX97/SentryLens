---
phase: 17-aba-testes-e-documenta-o
plan: 02
subsystem: ui
tags: [vaccines, decision, frontend, node-vm, ui_helpers, conflict]
status: complete

requires:
  - phase: 17-aba-testes-e-documenta-o
    provides: 17-01 (bloco Decisão, vacDecide, analistas) e 17-06 (frases dos códigos de erro)
  - phase: 16-api-de-decisao
    provides: estado derivado, decision, 409 already_decided / vaccine_superseded
provides:
  - bloco Decisão por modos (decidida só de leitura, substituída, sem analistas, analistas indisponíveis, a carregar, estado desconhecido)
  - reposição do analista e do motivo ao mudar de vaccine, contador do motivo
  - aviso do detalhe por estado, sempre com "não aplicada no Wazuh"
  - seguimento de erro que refaz detalhe e lista (409 e erros em que o servidor pode ter gravado)
  - fila de refresco em vacRefresh
affects: [17-03, 17-05]

actuals:
  tokens: 14000
  tasks: 2
  commits: 2
plan_head_before: c4769611cadfe5ce6a15d785582452670795086f
plan_head_after: 96016009254b926728e75fcd5a0f2496faf2fff3

tech-stack:
  added: []
  patterns:
    - "o que o bloco mostra decide-se numa função pura com forma fixa de 7 chaves (slVacDecisionView), testada em node:vm sobre as vaccines reais da rota"
    - "seguimento de erro por tabela pura (slVacErrorFollowUp): refresh / reload_analysts / none; só GET, nunca novo POST"

key-files:
  created: []
  modified:
    - ui_helpers.js
    - vaccines.js
    - scripts/test_ui_helpers.cjs
    - scripts/test_vaccines_frontend.py

key-decisions:
  - "decided não depende da lista de analistas: uma vaccine decidida ou substituída mostra sempre o seu bloco, mesmo com a lista a falhar"
  - "O 500 genérico da rota de analistas (http_5xx) vira incidents_unavailable no modo analysts_error"
  - "slVacErrorFollowUp entrou em _MESSAGE_SINKS (recebe err.message como código, nunca texto)"
  - "vacRefresh só faz a volta extra da fila se a query atual é válida (current !== null), para um refresco pedido por uma decisão não mostrar o aviso de ID de ataque inválido"

requirements-completed: [VLB-06, VLB-07]

duration: 25min
completed: 2026-10-30
---

# Phase 17 Plan 02: Bloco Decisão que nunca mente Summary

**O bloco Decisão mostra só de leitura uma vaccine decidida (autor, data, motivo), explica porque não há botões, repõe-se ao mudar de vaccine e, depois de um 409 ou de qualquer erro em que o servidor pode ter gravado, refaz o detalhe e a lista para o estado real aparecer.**

## Accomplishments

- `ui_helpers.js` (puro): `slVacDecisionView`, `slVacWarningText`, `slVacReasonCounter`, `slVacErrorFollowUp`.
- `vaccines.js`: `vacRenderDecision` passou a um `switch` sobre `slVacDecisionView(...).mode`; `vacResetDecisionForm`, contador por listener `input`, aviso por estado (`vacRenderDetail`, 200 do `vacDecide`, `vacRenderDetailError`), seguimento em `vacRenderDecisionError`, `vacRefreshQueued`.
- Testes: checks de `slVac*` em `test_ui_helpers.cjs`; `run_decision_view` e `run_conflict` em `test_vaccines_frontend.py` (sobre o 409 real, as vaccines C/B/A reais e todas as recusas reais da rota).
- Backend, `app.js`, `api.js` e `index.html` intactos (`git diff` vazio face à base da fase).

## Modos do bloco Decisão (avaliados por esta ordem)

| Modo | Quando | Mostra | Formulário |
|------|--------|--------|------------|
| `none` | sem vaccine | linha vazia | escondido |
| `decided` | `state` approved ou rejected (mesmo substituída) | "Estado: <rótulo> · por <autor> · em <data>" e "Motivo: <motivo ou —>" | escondido |
| `unknown_state` | `state` diferente de proposed/approved/rejected | "Estado <estado> — sem decisão possível neste painel." | escondido |
| `superseded` | proposed com `superseded_by` | "Substituída por <id> — já não pode ser decidida; decide a vaccine atual deste ataque." | escondido |
| `analysts_error` | proposta atual e erro ao ler os analistas (`http_5xx` vira `incidents_unavailable`) | "Estado: Proposta" e a frase do código | escondido |
| `loading` | analistas ainda por carregar | "Estado: Proposta" e "A carregar os analistas da Equipa SOC…" | escondido |
| `no_analysts` | lista vazia | "Estado: Proposta" e "Sem analistas ativos na Equipa SOC…" | escondido |
| `controls` | proposta atual com analistas | "Estado: Proposta" | visível |

Aviso por estado: Proposta / Aprovada ("aceite pelo analista") / Rejeitada, todos com "não aplicada no Wazuh"; estado desconhecido ou detalhe com erro dizem "Estado desconhecido — não aplicada no Wazuh".

## Seguimentos de erro (`slVacErrorFollowUp`)

| Seguimento | Códigos |
|------------|---------|
| `refresh` (`vacSelect(vacSelectedId)` + `vacRefresh()`) | `already_decided`, `vaccine_superseded`, `entry_not_found`, `store_unavailable`, `timeout`, `network_error`, `invalid_response`, `http_409`, `http_5xx` |
| `reload_analysts` (`vacLoadAnalysts()`) | `analyst_not_found`, `analyst_inactive`, `incidents_unavailable` |
| `none` | validação (`analyst_required`, `reason_required`, `invalid_*`), `unauthorized`, `http_403`, `http_405`, `http_422`, vazio, não-string, desconhecidos |

Provado contra as recusas reais da rota: `already_decided`, `vaccine_superseded`, `entry_not_found` dão refresh; `analyst_not_found`, `analyst_inactive` dão reload_analysts; o resto dá none. O detalhe real de C a seguir ao 409 é `approved` e a vista refeita é `decided` com autor Eddie; o de A é `superseded`.

## O que mudou em `vacRefresh`

- Novo `let vacRefreshQueued`. Se já está a carregar, marca a fila e sai (antes saía sem registar nada).
- No `finally`, lê e limpa a marca e faz uma (e só uma) nova volta se a marca estava posta ou a query mudou, desde que a query atual seja válida. O comportamento dos filtros mantém-se.
- `vacDecide`: no erro, uma resposta de outra vaccine não mostra frase nem toca no detalhe, mas se o seguimento é `refresh` chama `vacRefresh()`.

## Task Commits

1. Task 1: `7deca32` feat(vaccines-ui): bloco Decisão por estado, reposição e aviso
2. Task 2: `9601600` feat(vaccines-ui): 409 refaz o detalhe e a lista

## Verificação

- `python run_all_tests.py vaccine`: `9/9 ficheiros passaram`.
- `python run_all_tests.py` (suite completa, depois do segundo commit): `84/84 ficheiros passaram`.
- Verdes também `test_ui_helpers`, `test_frontend_static`, `test_no_raw_innerhtml`, `test_no_literal_colors`, `test_contrast`, `test_icons_a11y`, `test_serve_frontend`.
- Mensagens de commit sem `Co-Authored-By`.

Pendente de verificação humana (fim de fase, `human_verify_mode: end-of-phase`; os testes não executam `vaccines.js` num browser): com backend e frontend a correr, abrir a mesma vaccine proposta em dois separadores; aprovar no primeiro; no segundo (ainda com os botões) escolher um analista e Rejeitar com motivo. Esperado: o segundo mostra a frase de "já decidida", o bloco passa a só de leitura com "Aprovada · por <analista do primeiro separador>", a linha da tabela e os contadores ficam com o estado real, sem botões.

## Deviations from Plan

None - plan executed exactly as written.

Notas de processo:
- Task 1: os helpers foram escritos antes dos checks do cjs (ordem inversa à do TDD estrito), mas os checks de contrato de `vaccines.js` foram vistos a falhar (14 falhas) antes da implementação do JS. Task 2: RED visto (11 falhas) antes da implementação.
- Dois checks do `run_decision_view` foram afinados depois de falharem por pedirem o literal no sítio errado (`htmRender` mora em `vacShowDecisionLines`, a limpeza do estado passa por `vacSetDecisionStatus`); o contrato verificado é o mesmo.
- Os commits foram feitos diretamente em `main` (execução sequencial pedida pelo orquestrador, mesmo precedente dos planos anteriores da fase).

## Known Stubs

None.

## Threat Flags

None. T-17-07 a T-17-11 mitigadas: autor, motivo e `superseded_by` entram por `vacCell` dentro de `htmlT`; o seguimento só faz GET; a reposição ao mudar de vaccine impede decidir em nome de outro analista por engano.

## Self-Check: PASSED

- `ui_helpers.js` define `slVacDecisionView`, `slVacWarningText`, `slVacReasonCounter`, `slVacErrorFollowUp`; `vaccines.js` contém `vacRefreshQueued` e `vacResetDecisionForm`; `scripts/test_vaccines_frontend.py` contém `def run_conflict` e `def run_decision_view`.
- Commits `7deca32` e `9601600` presentes no histórico de `main`.
