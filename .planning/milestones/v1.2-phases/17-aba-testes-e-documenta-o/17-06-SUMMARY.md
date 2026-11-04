---
phase: 17-aba-testes-e-documenta-o
plan: 06
subsystem: ui
tags: [vaccines, decision, errors, frontend, stable-codes]
status: complete

requires:
  - phase: 17-aba-testes-e-documenta-o
    provides: 17-01 (bloco Decisão, vacDecide, validação local, real_api_keys com decisões)
  - phase: 16-api-de-decisao
    provides: códigos estáveis da rota de decisão (ERROR_CODES, VACCINE_DECISION_ROUTE_CODES)
provides:
  - uma frase PT-PT acionável em VAC_ERROR_TEXT para cada código que a decisão pode devolver (rota, validação local, transporte)
  - VAC_GENERIC_ERROR e incidents_unavailable reescritos para servir leitura e decisão
  - run_decision_errors e client_code, provados contra recusas reais da rota
affects: [17-02]

actuals:
  tokens: 9000
  tasks: 1
  commits: 1
plan_head_before: 851f7afc77575604869606ee9af60a89fcfca4a1
plan_head_after: c3632f845762f4d38137381d6263d32d9d2bf965

tech-stack:
  added: []
  patterns:
    - "o código que o cliente vê é recalculado em Python (client_code) com a regra de apiCodeFromResponse + vacCodeFromApiError e comparado com as chaves de VAC_ERROR_TEXT"

key-files:
  created: []
  modified:
    - vaccines.js
    - scripts/test_vaccines_frontend.py

key-decisions:
  - "incidents_unavailable passa a dizer 'base de incidentes e da Equipa SOC' e serve o gerador e a decisão"
  - "VAC_GENERIC_ERROR deixa de dizer 'ao ler': 'Erro inesperado no pedido de vaccines — vê o backend.log.'"
  - "invalid_analyst_id (D-11) não existe no backend: um analyst_id mal formado dá invalid_author (F16 16-01); segue-se o código"
  - "O ramo de apiErrorMessage em vacErrorText fica como rede de segurança, mas timeout e invalid_response passam a ter chave própria"

requirements-completed: [VLB-06, VLB-07]

duration: 15min
completed: 2026-10-30
---

# Phase 17 Plan 06: Frases para os códigos de erro da decisão Summary

**Cada erro da decisão aparece pela frase do código estável: 34 chaves em `VAC_ERROR_TEXT`, uma frase PT-PT acionável por código da rota, da validação local e do transporte, provada contra as recusas reais da rota de decisão.**

## Accomplishments

- `vaccines.js`: frases novas para `invalid_vaccine_id`, `invalid_decided_at`, `invalid_body`, `analyst_not_found`, `analyst_inactive`, `already_decided`, `vaccine_superseded`, `timeout`, `invalid_response`, `http_403`, `http_405`, `http_409`, `http_500`, `http_504`; reescritas `invalid_author` (nome com caracteres fora do aceite, corrige-se na Equipa SOC), `http_422` (serve filtros e decisão), `incidents_unavailable` e `VAC_GENERIC_ERROR`.
- `timeout` e `invalid_response` dizem que o pedido pode ter chegado ao backend, que a decisão pode ter ficado gravada e que a vista é atualizada; nenhuma fala do Wazuh Indexer.
- `scripts/test_vaccines_frontend.py`: `run_decision_errors` (chamada no `__main__` a seguir a `run_decision_contract`), `client_code` e `transport_code`, `respostas["erros_decisao"]` em `real_api_keys`, `/api.js` em `SERVED_PATHS`.
- O texto do servidor continua a nunca entrar no DOM: `detail` só serve de chave de lookup.

## Lista final de chaves de `VAC_ERROR_TEXT` (34)

`already_decided`, `analyst_inactive`, `analyst_not_found`, `analyst_required`, `attack_log_unreadable`, `attack_outside_alert_window`, `entry_not_found`, `http_403`, `http_404`, `http_405`, `http_409`, `http_422`, `http_500`, `http_502`, `http_503`, `http_504`, `incidents_unavailable`, `indexer_unavailable`, `invalid_author`, `invalid_body`, `invalid_decided_at`, `invalid_decision`, `invalid_reason`, `invalid_response`, `invalid_vaccine_id`, `ml_model_unavailable`, `network_error`, `reason_required`, `source_unavailable`, `store_unavailable`, `timeout`, `unauthorized`, `unexpected_error`, `vaccine_superseded`.

## Código real de cada recusa (TestClient, stores temporários)

| Pedido | HTTP | detail | Código que o cliente vê |
|--------|------|--------|-------------------------|
| segunda aprovação de C | 409 | `already_decided` | `already_decided` |
| decidir A (substituída por B) | 409 | `vaccine_superseded` | `vaccine_superseded` |
| rejeitar sem motivo | 422 | `reason_required` | `reason_required` |
| `analyst-ninguem` | 422 | `analyst_not_found` | `analyst_not_found` |
| `analyst-mike` (desativado) | 422 | `analyst_inactive` | `analyst_inactive` |
| chave extra `decided_by_name` | 422 | `invalid_body` | `invalid_body` |
| `analyst_id` com apóstrofo | 422 | `invalid_author` | `invalid_author` |
| `decision: maybe` | 422 | `invalid_decision` | `invalid_decision` |
| motivo com quebra de linha | 422 | `invalid_reason` | `invalid_reason` |
| `vac-xyz` no caminho | 422 | `invalid_vaccine_id` | `invalid_vaccine_id` |
| `vac-000000000000` | 404 | `entry_not_found` | `entry_not_found` |
| PUT na rota | 405 | `Method Not Allowed` (não é slug) | `http_405` |
| POST sem API key | 401 | (qualquer) | `unauthorized` |

`store_unavailable` e `incidents_unavailable` (503) não se provocam aqui; têm frase por pertencerem a `VACCINE_DECISION_ROUTE_CODES` e a rota 503 já tem teste próprio em `test_vaccine_decision_api.py`.

## Verificação

- `test_vaccines_frontend.py`: sem `[FALHOU]`, código 0 (RED confirmado antes: 18 falhas por frases em falta).
- `python run_all_tests.py vaccine`: `9/9 ficheiros passaram`.
- Critério de aceitação do conjunto de chaves (ERROR_CODES + códigos da rota + transporte do `api.js` + extras): `em falta: []`.
- `grep -c "ao ler as vaccines" vaccines.js` dá 0; mensagem do commit sem `Co-Authored-By`.
- Verdes também `test_frontend_static`, `test_no_raw_innerhtml`, `test_no_literal_colors`, `test_contrast`, `test_icons_a11y`, `test_ui_helpers`, `test_serve_frontend`.

## Deviations from Plan

None - plan executed exactly as written.

Nota de processo: o commit foi feito diretamente em `main` (execução sequencial pedida pelo orquestrador, mesmo precedente do 17-01). O teste e o código entram no mesmo commit (o plano prevê um só commit).

## Known Stubs

None.

## Threat Flags

None. T-17-22 e T-17-23 mitigadas: nenhum código conhecido cai na frase genérica, provado por `run_decision_errors`.

## Self-Check: PASSED

- `vaccines.js` e `scripts/test_vaccines_frontend.py` existem e contêm `already_decided:` e `def run_decision_errors`.
- Commit `c3632f8` presente no histórico de `main`.
