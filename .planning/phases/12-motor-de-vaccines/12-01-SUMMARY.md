---
phase: 12-motor-de-vaccines
plan: 01
subsystem: backend
tags: [vaccines, detection-engineering, attack-registry, deterministic-id, pure-module]

requires:
  - phase: 11
    provides: attack_registry.build_attack_registry (veredito/esperado/event_ids por ataque), redblue_correlator.DEFAULT_WINDOW_SECONDS
provides:
  - "scripts/vaccine_engine.py: build_vaccine_candidates(registry, correlation=None), vaccine_id(attack_id, missing_sensors) e as constantes/chaves fechadas do contrato"
  - "scripts/test_vaccine_engine.py: run_tracer + run_selection (87 checks, standalone)"
affects: [12-02 (validate_vaccine, no_data/source_unavailable), 12-03 (escritor do attack log grava id), 13 (store e /api/vaccines/{id}), 14 (aba)]

plan_head_before: a3988d959c69c4fbdb5b6a93ad04e769fabe14f3
plan_head_after: fd57313bc17ed11893fe87c3e83491d6dd38fcbb

actuals:
  tokens: 7900
  tasks: 2
  commits: 2

tech-stack:
  added: []
  patterns:
    - "Motor puro sobre a saida de attack_registry: nunca recalcula veredito/esperado/event_ids"
    - "Cada ataque gerador acaba numa vaccine ou num motivo contado em skipped (invariante testada)"
    - "Robustez por isinstance em cada acesso, sem try/except generico"

key-files:
  created:
    - scripts/vaccine_engine.py
    - scripts/test_vaccine_engine.py
  modified: []

key-decisions:
  - "D-03 fixado por literais: id = vac- + 12 hex de sha256('<attack_id>:<sensores em falta por ordem de EXPECTED_SOURCES>'); 2:rule,ml=vac-5fe3861aa2a3, 3:ml=vac-bd617cce8054, 4:network=vac-13daa7f56fa1, 4:rule,ml=vac-ca13ec0fa618, 2:ml=vac-ed793c0b3437, 2:network=vac-32b35d85e61e"
  - "D-07 refinado: uma vaccine por ataque com proposals[] (uma por sensor em falta); so a proposta rule traz regra {event_ids, min_count=1, window_seconds=300}"
  - "Deteccao de duplicados feita tambem no motor (pre-passagem de contagem de ids), nao so pela flag duplicate_id do registo"

requirements-completed: [VAC-01, VAC-02, VAC-03]

coverage:
  - id: D1
    description: "Seleção: uma vaccine por ataque not_detected/partial, nenhuma por detected/unknown (incl. truncagem e correlação indisponível)"
    requirement: VAC-01
    verification:
      - kind: unit
        ref: "scripts/test_vaccine_engine.py#run_tracer,run_selection"
        status: pass
    human_judgment: false
  - id: D2
    description: "Proposta rule {event_ids, min_count, window_seconds} e proposals ml/network com recomendação constante; sensores em falta seguem attack_library (provado com get_expected_sensors substituído)"
    requirement: VAC-02
    verification:
      - kind: unit
        ref: "scripts/test_vaccine_engine.py#run_tracer (VAC-02)"
        status: pass
    human_judgment: false
  - id: D3
    description: "Origem por referência (sem tool/target/source/operator) e id determinístico fixado por literais, único ao reprocessar"
    requirement: VAC-03
    verification:
      - kind: unit
        ref: "scripts/test_vaccine_engine.py#run_tracer,run_selection (determinismo)"
        status: pass
    human_judgment: false

duration: 4min
completed: 2026-10-11
status: complete
---

# Phase 12 Plan 01: Motor de vaccines Summary

**Motor puro `build_vaccine_candidates` que, sobre o registo real de ataques, propõe uma regra de deteção rastreável (proposals[] por sensor em falta, id sha256 determinístico fixado por literais) e conta cada ataque saltado em vez de o omitir.**

## Performance

- **Duration:** 4 min
- **Started:** 2026-10-11T22:52:11Z
- **Completed:** 2026-10-11T22:55:18Z (código); SUMMARY a seguir
- **Tasks:** 2/2
- **Files modified:** 2 (ambos novos)

## Accomplishments

- Sobre as fixtures reais de `test_attack_registry.py` o motor devolve exatamente 3 vaccines (ataques 4, 3, 2, por esta ordem); o ataque `detected` não gera nada.
- Cada vaccine traz `proposals[]` com uma entrada por sensor em falta (D-01): `rule` com `{event_ids, min_count: 1, window_seconds: 300}` e nomes/severidade de `event_catalog`; `ml`/`network` com `rule=None` e uma recomendação constante em PT-PT, sem comandos.
- VAC-02: `missing_sensors` segue `attack_library.get_expected_sensors` via `attack_registry.expected_detection`. Provado com `mock.patch.object(attack_registry, "get_expected_sensors", ...)`: smb_enum passa a esperar `["network"]`, uma só proposta network e id `vac-32b35d85e61e`. (O default `["rule","ml"]` da biblioteca coincide com `DEFAULT_EXPECTED`, por isso só a substituição prova a ligação.)
- Origem (VAC-03) por referência: `attack_id`, `scenario`, tática/técnica MITRE (só se casarem a regex), `incident_ids` (só ids) e evidência (ids de eventos, contagem, tipos de deteção de rede). `tool`, `target`, `source`, `operator`, `details` e dicts de incidentes nunca entram (varrimento de `json.dumps(out)` sem hydra/netexec/psexec/alice/IPs).
- Seleção endurecida (D-04): `skipped.no_attack_id`, `duplicate_id` (todas as entradas que partilham o id, também com a flag a False), `invalid_origin`, `no_missing_sensors`, `no_event_ids`; invariante `partial + not_detected == total + soma(skipped)` verificada em todos os cenários. Truncagem e correlação indisponível dão `unknown` e nunca geram; entradas malformadas contam em `considered.invalid` sem exceção.

## Ids golden fixados no teste (literais)

| Ataque : sensores em falta | Id |
|---|---|
| 2:rule,ml | vac-5fe3861aa2a3 |
| 3:ml | vac-bd617cce8054 |
| 4:network | vac-13daa7f56fa1 |
| 4:rule,ml | vac-ca13ec0fa618 |
| 2:ml (partial de smb_enum) | vac-ed793c0b3437 |
| 2:network (biblioteca substituída) | vac-32b35d85e61e |

## Contadores de skipped (cenários do teste)

| Cenário | Resultado |
|---|---|
| fixtures reais | todos a 0, total 3, considered {attacks 4, detected 1, partial 1, not_detected 2} |
| hostis reais (id True, id 8 x2) | no_attack_id 1, duplicate_id 2, total 0 |
| formato antigo sem id | no_attack_id 1 |
| ids 0, -1, "2", 2.0, 10**12, None, True | no_attack_id 7 |
| partial totalmente coberto | no_missing_sensors 1 |
| not_detected rule sem event_ids válidos | no_event_ids 1 |
| scenario "../etc", "", None | invalid_origin 1 cada |
| truncagem de alertas | só o ataque 3 gera; unknown 2; alerts_truncated true |

## Task Commits

1. **Task 1 (tracer):** `e60e736` - feat(12-01): motor puro de vaccines com proposals e id determinístico (tracer)
2. **Task 2:** `fd57313` - feat(12-01): saltos contados, duplicados e matriz de vereditos no motor de vaccines

O tracer feedback gate correu em modo automático/end-of-phase: `<verify>` só automatizado, reexecutado ponta a ponta antes da expansão, verde.

## Verification

- `cd scripts && .venv/Scripts/python -X utf8 test_vaccine_engine.py`: 87 checks `[OK]`, 0 `[FALHOU]`, saída 0.
- `python run_all_tests.py vaccine`: `PASS test_vaccine_engine.py`.
- `python run_all_tests.py` (suite completa): 40/40 ficheiros passaram (39 anteriores + este).
- Só `scripts/vaccine_engine.py` e `scripts/test_vaccine_engine.py` tocados por commits do plano; nenhuma eliminação de ficheiros; sem trailer de coautor.

## Deviations from Plan

None - plan executed exactly as written.

Nota operacional (não é desvio): numa primeira corrida da suite completa `test_jev_client.py` falhou uma vez; passou isolado, com filtro e numa segunda corrida completa (40/40). `jev_client.py` tem alterações não commitadas alheias a este plano, por isso foi tratado como transitório e não foi investigado nem alterado.

## Issues Encountered

None.

## Known Stubs

None.

## Known follow-ups (fora do âmbito)

- Hoje `attack_scenarios.format_log_entry` não grava `id`: um ataque lançado pelo CLI fica `id: null` no registo e, por D-04, conta em `skipped.no_attack_id`. Resolvido na fase pelo plano 12-03; este plano não tocou em `attack_scenarios.py`. Entradas antigas sem `id` continuam em `skipped.no_attack_id` (sem backfill).
- Quando o veredito de um ataque evolui (partial para not_detected) o id muda de propósito (D-03; `vac-ed793c0b3437` -> `vac-5fe3861aa2a3`); a política para a vaccine antiga do mesmo `attack_id` é decisão da Phase 13.
- 12-02 acrescenta `validate_vaccine`, o varrimento "nenhum comando" e os estados `no_data`/`source_unavailable` (as chaves `available`/`reason` já existem no envelope).

## Threat Flags

None - sem novos endpoints, caminhos de autenticação nem acesso a ficheiros; módulo puro.

## Next Phase Readiness

Pronto para 12-02 (contrato fechado e honestidade) e 12-03 (id no escritor do attack log), ambos sobre `vaccine_engine.py`/`test_vaccine_engine.py`.

## Self-Check: PASSED

- FOUND: scripts/vaccine_engine.py, scripts/test_vaccine_engine.py
- FOUND commits: e60e736, fd57313
