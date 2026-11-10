---
phase: 19-api-de-cobertura-mitre
plan: 01
subsystem: api
tags: [mitre, att&ck, coverage, fastapi, pure-function]

requires:
  - phase: 18-catalogo-mitre
    provides: mitre_catalog (tabela de 17 técnicas, tactics_for, parent_of, resolve_alert_techniques, ENTERPRISE_TACTICS)
provides:
  - "GET /api/mitre/coverage (API key por rota), cobertura por técnica e por tática"
  - "mitre_coverage.build_mitre_coverage_report: função pura, contrato fechado do envelope, das linhas e das táticas"
affects: [19-02, 20-matriz-mitre-frontend]

actuals:
  tokens: 9777
  tasks: 2
  commits: 3

plan_head_before: e72d14f761e39078e7b8459c91842ff9279ed5ca
plan_head_after: b86d9345da5568f32f5e31f1fd9200eedaf517a1
commits: 3

tech-stack:
  added: []
  patterns:
    - "função pura com fonte em baixo = None -> contagens null (mesma convenção de soc_metrics)"
    - "contrato fixado por igualdade exata de chaves (ENVELOPE_KEYS, ROW_KEYS, TACTIC_KEYS)"
    - "pureza provada por AST (imports, open, constantes proibidas)"

key-files:
  created:
    - scripts/mitre_coverage.py
    - scripts/test_mitre_coverage.py
    - scripts/test_mitre_coverage_api.py
  modified:
    - scripts/main.py

key-decisions:
  - "Dois pedidos ao Indexer por chamada (fonte de alertas própria + o do _build_attack_registry) em vez de mudar a assinatura do registry (D-09)"
  - "rate em % com 1 casa decimal, null sem denominador; unknown fora do denominador"
  - "alerts_truncated null quando a fonte de alertas está em baixo"
  - "correlation.reason só passa se estiver na allowlist; senão correlation_unavailable"
  - "name da linha é o da tabela só para o id exato; sub-técnica herdada fica com name null"

patterns-established:
  - "Contagem por id exato: nenhuma contagem atravessa pai/filha; parent_of só herda tática e preenche o campo parent"
  - "Tática sempre da tabela via tactics_for; nunca do log, do registry nem de rule.mitre.tactic"

requirements-completed: [API-01, API-02]

coverage:
  - id: D1
    description: "GET /api/mitre/coverage exige API key por rota (401 sem chave ou com chave errada) e devolve o envelope completo com 17 técnicas, alertas por origem wazuh/catalog, ataques do attack_registry, detetados e taxa"
    requirement: "API-01"
    verification:
      - kind: integration
        ref: "scripts/test_mitre_coverage_api.py#run_tracer"
        status: pass
    human_judgment: false
  - id: D2
    description: "Regras de contagem D-01..D-12 (linhas por id exato, alertas por origem, vereditos e taxa com unknown fora do denominador, táticas multi-valor com total único, unmapped, fonte None -> null) fixadas por testes puros"
    requirement: "API-02"
    verification:
      - kind: unit
        ref: "scripts/test_mitre_coverage.py"
        status: pass
    human_judgment: false
  - id: D3
    description: "Caso misto pela rota com o attack_registry real e a janela hours (T1110 100.0, T1053 0.0 em 3 táticas, Credential Access 50.0, totals.rate 25.0, unmapped T1059/T1087)"
    requirement: "API-01"
    verification:
      - kind: integration
        ref: "scripts/test_mitre_coverage_api.py#run_mix"
        status: pass
    human_judgment: false
  - id: D4
    description: "Sem efeitos secundários e sem I/O: não mutação das entradas e da tabela, determinismo, pureza por AST"
    requirement: "API-01"
    verification:
      - kind: unit
        ref: "scripts/test_mitre_coverage.py#run_no_side_effects"
        status: pass
      - kind: unit
        ref: "scripts/test_mitre_coverage.py#run_purity"
        status: pass
    human_judgment: false

duration: 14min
completed: 2026-11-10
status: complete
---

# Phase 19 Plan 01: API de cobertura MITRE Summary

**`GET /api/mitre/coverage` responde ponta a ponta (alertas do Indexer + attack_registry -> `build_mitre_coverage_report` pura -> JSON), com cobertura por técnica e por tática, alertas contados por origem (wazuh/catalog) e taxa de deteção que nunca transforma uma fonte em baixo ou sem amostra em zero.**

## Performance

- **Duration:** ~14 min
- **Completed:** 2026-11-10T10:04Z
- **Tasks:** 2 (Task 1 tracer, Task 2 TDD)
- **Files modified:** 4 (3 novos, `main.py` só com linhas acrescentadas: 24 adicionadas, 0 removidas)

## Accomplishments

- Rota nova entre `get_attack` e o bloco "Attack Library", com `dependencies=_REQUIRE_API_KEY` e `hours` (1..720, default 168); janela dos ataques igual à de `list_attacks`.
- `scripts/mitre_coverage.py` puro (só importa `__future__`, `attack_registry`, `mitre_catalog`; sem `open`, sem `load_mitre_techniques`).
- Contrato fixado por igualdade exata de chaves nos testes; 88 ficheiros de teste (86 + 2).

## Task Commits

1. **Task 1: Tracer, rota e função pura para as duas fontes disponíveis** - `d85ac4c` (feat)
2. **Task 2 RED: regras de contagem puras** - `390e71b` (test)
3. **Task 2 GREEN: fontes None, veredito defensivo, allowlist da correlação, run_mix** - `b86d934` (feat)

**Plan metadata:** commit `docs(19-01)` a seguir a este ficheiro.

## Assinatura final

```python
build_mitre_coverage_report(raw_alerts, attacks, table, hours, *, alerts_truncated=False, correlation=None) -> dict
detection_rate(counts) -> float | None
```

`raw_alerts=None` = fonte de alertas em baixo; `attacks=None` = fonte de ataques em baixo. Constantes públicas: `SOURCE_UNAVAILABLE`, `ATTACK_COUNT_KEYS`, `ALERT_COUNT_KEYS`, `ROW_KEYS`, `TACTIC_KEYS`, `ENVELOPE_KEYS`, `CORRELATION_REASONS`, `CORRELATION_FALLBACK_REASON`.

## JSON do tracer (`run_tracer`; recortado a T1110, Credential Access e Discovery)

Entrada: 1 ataque `brute_force_rdp` detetado (regra+ML); alertas `rule.mitre.id=[T1110]`, Event ID 4625 (sem `rule.mitre`) e Event ID 4624.

```json
{"window_hours": 168, "attack_version": "v18.1",
 "sources": {"alerts": {"available": true, "reason": null},
             "attacks": {"available": true, "reason": null,
                         "correlation": {"available": true, "reason": null, "alerts_truncated": false}}},
 "alerts_truncated": false,
 "totals": {"alerts": {"fetched": 3, "with_technique": 2, "without_technique": 1},
            "attacks": {"launched": 1, "detected": 1, "partial": 0, "not_detected": 0, "unknown": 0},
            "rate": 100.0},
 "tactics": [{"tactic": "Credential Access", "technique_ids": ["T1110", "T1110.003"],
              "attacks": {"launched": 1, "detected": 1, "partial": 0, "not_detected": 0, "unknown": 0}, "rate": 100.0},
             {"tactic": "Discovery", "technique_ids": ["T1135"],
              "attacks": {"launched": 0, "detected": 0, "partial": 0, "not_detected": 0, "unknown": 0}, "rate": null}],
 "techniques": [{"id": "T1110", "name": "Brute Force", "parent": null, "tactics": ["Credential Access"],
                 "alerts": {"total": 2, "wazuh": 1, "catalog": 1},
                 "attacks": {"launched": 1, "detected": 1, "partial": 0, "not_detected": 0, "unknown": 0},
                 "rate": 100.0}],
 "unmapped": []}
```

(O corpo real tem as 14 táticas e as 17 linhas de `techniques`.)

## TDD: o que já passava antes do GREEN da Task 2

Corrida RED (`390e71b`) sobre a implementação do tracer:

- Passavam: `run_empty`, `run_rows`, `run_unmapped`, `run_sources_by_origin`, `run_tactics`, `run_contract`, `run_no_side_effects`, `run_purity`; da `run_correlation`: truncagem passada/omissão, correlação disponível, código fora da allowlist, indisponível sem código e `None`; da `run_rates`: as 4 verificações antes do caso do veredito inválido.
- Falhavam: `run_rates` (KeyError `'lixo'` no veredito inválido), `run_unavailable_sources` (TypeError ao iterar `None`) e 3 casos da allowlist (`indexer_unavailable`, `ml_model_unavailable`, `attack_outside_alert_window` saíam como `correlation_unavailable`, porque o tracer só tinha a versão mínima do bloco).

## Resumo de `run_all_tests.py mitre`

```
PASS test_event_catalog_mitre.py
PASS test_mitre_catalog.py
PASS test_mitre_coverage.py
PASS test_mitre_coverage_api.py

4/4 ficheiros passaram
```

Suite completa: `87/88 ficheiros passaram`; a falha é `test_attack_targets.py`, flake conhecido em paralelo (CLAUDE.md, `docs/ROADMAP_STATUS.md`); isolado passa (rc 0), tal como `test_attack_log_ids.py`, que falhou num run paralelo anterior. `run_all_tests.py metrics` 2/2 e `detection` 3/3.

## Decisions Made

- **D-09:** dois pedidos ao Indexer por chamada (o da fonte de alertas e o de `_build_attack_registry`); reaproveitar obrigaria a mudar a assinatura do registry, usada por `/api/attacks`, `/api/attacks/{id}` e pelo loop das vaccines.
- `rate` = `round(100*detected/(detected+partial+not_detected), 1)` ou `null`.
- `alerts_truncated` é `null` quando a fonte de alertas está em baixo.
- `sources.attacks.correlation` = `{available, reason, alerts_truncated}`; `reason` só da allowlist.
- `name` só para o id exato da tabela; ordenação por id (string) em `techniques[]`, `unmapped[]` e `technique_ids`.

## Deviations from Plan

None - plan executed exactly as written. Duas notas, não desvios: a Task 2 (TDD) levou dois commits (RED `390e71b`, GREEN `b86d934`) em vez de um; e `run_mix` foi acrescentado no commit GREEN.

## Known Stubs

None.

## Threat Flags

None. A rota nova é só GET com API key por rota (T-19-01 provado por `run_tracer`); sem novo acesso a ficheiros, sem pacotes novos (`requirements.txt` inalterado).

## Known follow-ups (fora do âmbito)

- Plano 19-02: try/except por fonte na rota (D-07), `source_unavailable` sem 500, prova da truncagem no teto pela rota, 405 em métodos de escrita. Hoje, com o Indexer ou o log de ataques em baixo, a rota ainda dá erro (não isola fontes).
- Phase 20: a UI tem de dizer que a soma por tática pode exceder `totals.attacks` (D-10), escapar os ids de `unmapped[]` (texto livre do log, A-02) e mostrar `sources.attacks.correlation.reason` quando os vereditos são `unknown`.
- Phase 20 (DOC-01): documentar a rota em `docs/API.md`, o contrato em `docs/DATA_MODEL.md` e a contagem de testes 86 -> 88 em `README.md`/`CLAUDE.md`.

## Self-Check: PASSED

- Ficheiros criados existem: `scripts/mitre_coverage.py`, `scripts/test_mitre_coverage.py`, `scripts/test_mitre_coverage_api.py`.
- Commits `d85ac4c`, `390e71b`, `b86d934` são ancestrais de HEAD; `git rev-list --count e72d14f..HEAD` = 3.
- Critérios de aceitação das duas tarefas e `<verification>` do plano reexecutados e verdes (exceto o flake conhecido acima, que passa isolado).
