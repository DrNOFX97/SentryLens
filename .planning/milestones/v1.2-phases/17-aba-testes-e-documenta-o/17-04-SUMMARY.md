---
phase: 17-aba-testes-e-documenta-o
plan: 04
subsystem: docs
tags: [docs, vaccines, decision, data-model, api]
status: complete

requires:
  - phase: 15-store-de-decis-es
    provides: tabela vaccine_decisions, estado derivado, ERROR_CODES, count_by_state
  - phase: 16-api-de-decisao
    provides: POST /api/vaccines/{id}/decision, VACCINE_DECISION_HTTP_STATUS, VACCINE_DECISION_NOTICE, state e state_counts
provides:
  - docs/DATA_MODEL.md com a subsecção Decisão do analista (R12) e a secção Vaccine (R11) corrigida
  - docs/API.md com a rota POST de decisão, ?state=, state_counts, tabela de códigos e tabela-resumo
affects: [17-05]

actuals:
  tokens: 9000
  tasks: 2
  commits: 2
plan_head_before: 2fd44ed2bc07d69acd3f129320891a97015cf2fe
plan_head_after: 112d7b45cb8087b206928981de531ba18442c727

key-files:
  created: []
  modified:
    - docs/DATA_MODEL.md
    - docs/API.md

key-decisions:
  - "Títulos mantidos onde são citados por nome: 'Vaccine (R11)' no DATA_MODEL.md; a secção da API passou a 'Vaccines (R11, R12)' e a ligação do DATA_MODEL.md foi atualizada"
  - "Exemplos só com ids de teste e nomes da Equipa SOC do laboratório (analyst-eddie, Eddie); nenhuma chave, caminho ou IP"
  - "invalid_decided_at fica documentado como defesa: o instante vem do servidor, por isso o cliente não o consegue provocar"

requirements-completed: [VLB-07]

duration: 15min
completed: 2026-10-30
---

# Phase 17 Plan 04: Documentação do R12 (DATA_MODEL e API) Summary

**O contrato do R12 que as Phases 15 e 16 fixaram (tabela `vaccine_decisions` só de acréscimo, estado derivado, `state_counts` e `POST /api/vaccines/{id}/decision` com todos os códigos e status) está descrito em `docs/DATA_MODEL.md` e `docs/API.md`, verificado por script contra o código.**

## Accomplishments

### docs/DATA_MODEL.md (commit 184aa3b)

- Frases do R11 corrigidas: já não diz que o estado é sempre `proposed` nem que não há rota de escrita. A coluna `state` de `vaccines` continua `proposed` (CHECK), mas o `state` servido é derivado da decisão.
- Exemplo JSON ganhou `"decision": null`, mais um exemplo curto de vaccine rejeitada (autor Eddie).
- "Campos do store" lista `state` derivado e o bloco `decision` (`DECISION_FIELDS`); o envelope ganhou `state_counts` e o filtro `state`; a única escrita é o POST de decisão (PUT/PATCH/DELETE dão 405).
- Nova subsecção `### Decisão do analista (R12)`: uma linha por coluna de `DECISIONS_SCHEMA`, `UNIQUE(vaccine_id)`, triggers `vaccine_decisions_no_update`/`vaccine_decisions_no_delete`, `previous_state`, transição `proposed -> approved | rejected` final, estado derivado, vaccine substituída (`vaccine_superseded`) e aprovada-depois-substituída, regra do motivo, autoria autodeclarada (`ANALYST_NAME_RE` / `invalid_author`), `state_counts`, tabela de códigos com HTTP. Frase central: aprovada significa só aceite pelo analista, nada aplicado no Wazuh (R21).

### docs/API.md (commit 112d7b4)

- Secção passou a "Vaccines (R11, R12)"; intro reescrita (já não diz "Não existe rota de escrita").
- Tabela: `GET /api/vaccines` com `state` e `state_counts`; nova linha `POST /api/vaccines/{id}/decision`.
- Subsecção "Decisão (R12)": corpo fechado, teto de 8192 bytes (422 `invalid_body`), exemplo de pedido e resposta com o `VACCINE_DECISION_NOTICE` literal, tabela com os 14 códigos e status de `VACCINE_DECISION_HTTP_STATUS`, 401, 405, 409 sem idempotência, 503 depois de gravar, CORS.
- Lista de testes e tabela-resumo do fim atualizadas.

## Verificação

Script da Task 1 (`DATA_MODEL.md`): `em falta: [] frases antigas: []`, código 0.
Script da Task 2 (`API.md`): `códigos em falta: [] sem status na mesma linha: [] outros em falta: []`, código 0.
Critérios: `### Decisão do analista (R12)` 1 vez; `não aplicad` 1 vez; `Não existe rota de escrita` 0; linha `POST | /api/vaccines/{id}/decision` 2 vezes (tabela da secção e tabela-resumo). Nenhum trailer de coautor nos dois commits. Os ficheiros mantêm as terminações CRLF (diff pequeno).

## Task Commits

1. Task 1: `184aa3b` docs(r12): modelo de dados da decisão do analista
2. Task 2: `112d7b4` docs(r12): API da decisão do analista

## Deviations from Plan

None - plan executed exactly as written. (Nota de processo: commits diretos em `main`, `branching_strategy: none`, execução sequencial pedida pelo orquestrador, como no 17-01.)

## Known Stubs

None.

## Threat Flags

None. Só documentação; sem superfície nova. T-17-16 mitigado (a frase "aprovada = aceite, nada aplicado" está nos dois documentos e o `notice` literal é verificado por script); T-17-18 mitigado (exemplos sem segredos).

## Self-Check: PASSED

- docs/DATA_MODEL.md e docs/API.md existem e contêm os símbolos prometidos.
- Commits `184aa3b` e `112d7b4` presentes no histórico de `main`.
