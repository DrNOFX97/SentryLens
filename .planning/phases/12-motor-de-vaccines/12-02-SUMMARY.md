---
phase: 12-motor-de-vaccines
plan: 02
subsystem: backend
tags: [vaccines, closed-contract, validator, allowlist, no-data, source-unavailable, pure-module]

requires:
  - phase: 12-01
    provides: build_vaccine_candidates, vaccine_id, constantes e chaves fechadas do contrato
provides:
  - "scripts/vaccine_engine.py: validate_vaccine(v) -> list[str], REASONS, envelope de três estados (source_unavailable / no_data / reason None)"
  - "scripts/test_vaccine_engine.py: run_contract (allowlist + DENY_RE + negativos + hostil pelo registo + gate AST) e run_honesty"
affects: [12-03, 13 (store chama validate_vaccine antes de gravar), 14 (aba desenha no_data como "Sem dados")]

plan_head_before: b0cf78c174ea0447a6aeabaecbe2143b984f1a00
plan_head_after: d432a2ee642c76ba1bac1862df787780e1424281

actuals:
  tokens: 6100
  tasks: 2
  commits: 2

tech-stack:
  added: []
  patterns:
    - "Contrato fechado a todos os níveis + validador por campo em allowlist (precedente: ml_evaluation.validate_evaluation)"
    - "Envelope de três estados como em soc_metrics.py: zeros só quando medidos, None quando não"
    - "Gate AST no teste: motor só importa a allowlist e não chama open/print/eval/exec"

key-files:
  created: []
  modified:
    - scripts/vaccine_engine.py
    - scripts/test_vaccine_engine.py

key-decisions:
  - "Regex da origem passam a fullmatch (match com $ aceitava um newline final); aplicado na projeção do motor e no validador"
  - "Correlação sem available=True (False, ausente, não-dict) é source_unavailable ANTES de olhar para vereditos: fail-closed"
  - "considered/skipped/alerts_truncated a None em source_unavailable; zeros verdadeiros só em no_data"

requirements-completed: [VAC-02, VAC-04]

coverage:
  - id: D1
    description: "Nenhuma vaccine contém um comando: contrato fechado, validate_vaccine por allowlist, varrimento de todas as strings, 27 negativos e ataque hostil pelo registo real"
    requirement: VAC-02
    verification:
      - kind: unit
        ref: "scripts/test_vaccine_engine.py#run_contract"
        status: pass
    human_judgment: false
  - id: D2
    description: "Sem amostra devolve no_data, fonte indisponível/não confirmada devolve source_unavailable com contagens None, tudo unknown é um terceiro resultado; nunca se fabrica uma vaccine"
    requirement: VAC-04
    verification:
      - kind: unit
        ref: "scripts/test_vaccine_engine.py#run_honesty"
        status: pass
    human_judgment: false

duration: 5min
completed: 2026-10-11
status: complete
---

# Phase 12 Plan 02: Contrato fechado e honestidade Summary

**`validate_vaccine` com contrato fechado e allowlist por campo (nenhum comando passa, provado por varrimento de todas as strings, 27 negativos e um log hostil pelo registo real) e envelope de três estados que nunca inventa vaccines (`no_data`, `source_unavailable`, ou `reason None`).**

## Performance

- **Duration:** ~5 min
- **Started:** 2026-10-11T22:59:34Z
- **Completed:** 2026-10-11T23:03Z
- **Tasks:** 2/2
- **Files modified:** 2 (`scripts/vaccine_engine.py`, `scripts/test_vaccine_engine.py`)

## Accomplishments

- `validate_vaccine(v)` nunca levanta (testado com `None`, `"x"`, `[]`, `5`, `{}`), devolve códigos ordenados e sem repetidos, e `[]` se e só se a vaccine for uma que o motor produziria. Chaves IGUAIS a `VACCINE_KEYS`/`ORIGIN_KEYS`/`EVIDENCE_KEYS`/`PROPOSAL_KEYS`/`RULE_KEYS`/`EVENT_KEYS`; cada string vem de regex apertada, tupla fixa, `classify_alert` ou `RECOMMENDATIONS` por igualdade exata. Recalcula `vaccine_id(attack_id, missing_sensors)` e exige igualdade (`id_mismatch`).
- Varrimento com `DENY_RE` (metacaracteres de shell, ferramentas, `--x`, IPv4) a chaves e valores de todo o corpus (fixtures, com incidentes, truncado, hostil, Pitfall 3, event_ids sujos, tipos de rede sujos): zero ocorrências. Sanidade: `RECOMMENDATIONS` e nomes/severidades de `CRITICAL_EVENTS` não casam, e `DENY_RE` apanha mesmo os 8 comandos de exemplo.
- Ataque hostil pelo registo real (`technique` com netexec+IP, `tool` hydra, `operator` com `; rm -rf`, `details.command`; incidente com id `X; rm`): uma vaccine com `mitre_technique=None`, `incident_ids == ["INC-20261007-001"]`, sem `netexec`/`hydra`/`rm -rf`/`192.0.2.` no JSON, validada.
- Gate AST (`ast.parse` do código-fonte do motor): imports contidos em `{__future__, hashlib, re, attack_registry, event_catalog, redblue_correlator}` e nenhuma chamada a `open/print/input/eval/exec/compile/__import__/breakpoint`.
- Três estados (VAC-04, D-02), tal como `soc_metrics.py`: `source_unavailable` (registo ausente/malformado, ou `correlation` sem `available=True`; `considered`/`skipped`/`alerts_truncated` a `None`), `no_data` (fonte ok e lista vazia; zeros verdadeiros), e `reason None` com `available=True` mesmo sem vaccines (tudo unknown/detected). O `error_code` da correlação nunca é copiado.

## Códigos de problema de `validate_vaccine`

`not_a_dict`, `vaccine_keys`, `id_format`, `id_mismatch`, `verdict`, `expected_source`, `sensors`, `missing_sensors`, `proposals`, `proposal_keys`, `rule`, `events`, `recommendation`, `origin_keys`, `attack_id`, `scenario`, `mitre_tactic`, `mitre_technique`, `incident_ids`, `evidence`.

## Os três estados do resultado

| Estado | available | reason | vaccines | considered / skipped / alerts_truncated |
|---|---|---|---|---|
| Fonte em baixo ou não confirmada | false | `source_unavailable` | [] | None / None / None |
| Sem amostra (lista vazia, fonte ok) | false | `no_data` | [] | zeros / zeros / `alerts_truncated` da correlação |
| Há ataques, nada a propor (ex.: tudo unknown) | true | None | [] | contagens reais |

## Task Commits

1. **Task 1:** `e4dee31` - feat(12-02): validate_vaccine com contrato fechado e varrimento sem comandos
2. **Task 2:** `d432a2e` - feat(12-02): no_data e source_unavailable, nunca inventa vaccines

## Verification

- `cd scripts && .venv/Scripts/python -X utf8 test_vaccine_engine.py`: 182 checks `[OK]`, 0 `[FALHOU]`, saída 0 (`run_tracer`, `run_selection`, `run_contract`, `run_honesty`).
- `python run_all_tests.py`: 40/40 ficheiros passaram, incluindo `PASS test_vaccine_engine.py`, sem Wazuh.
- `build_vaccine_candidates(None)` -> `source_unavailable None`; `validate_vaccine(None/'x'/[])` -> `['not_a_dict']` x3.
- Só `scripts/vaccine_engine.py` e `scripts/test_vaccine_engine.py` tocados; nenhuma eliminação de ficheiros; sem trailer de coautor; alterações alheias da árvore de trabalho intocadas e por stagiar.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Regex da origem aceitavam newline final**
- **Found during:** Task 1 (desenho do validador)
- **Issue:** `SCENARIO_RE`/`MITRE_*_RE`/`INCIDENT_ID_RE`/`LABEL_RE` usam `$`, e `re.match` com `$` aceita `"smb_enum\n"`. Um newline final passava a projeção do motor.
- **Fix:** projeção do motor e validador usam `fullmatch`.
- **Files modified:** scripts/vaccine_engine.py
- **Commit:** e4dee31

**2. [Rule 1 - Alinhamento de testes do 12-01 com o contrato novo] Dois checks do 12-01 alterados**
- **Found during:** Task 2
- **Issue:** (a) `run_selection` passava `correlation={"alerts_truncated": True}` sem `available`, o que por D-02 é agora `source_unavailable`; (b) o check "malformado" esperava `considered.attacks == 0` para registo `None`/`{}`/`{"attacks": None}`/`"x"`/`5`, que agora são `source_unavailable` com `considered None` (nada foi medido).
- **Fix:** (a) o teste passa `{"available": True, "alerts_truncated": True}`; (b) o check passa a exigir `reason == "source_unavailable"` e `considered is None`. As expectativas de `run_tracer` ficaram sem alteração. A intenção original de ambos os checks (truncagem propaga; entradas malformadas não levantam) mantém-se.
- **Files modified:** scripts/test_vaccine_engine.py
- **Commit:** d432a2e

**Total deviations:** 2 auto-fixed (1 bug, 1 alinhamento de testes). **Impact:** nenhum no âmbito; o plano previa o comportamento novo mas não a necessidade de atualizar estes dois checks.

## Issues Encountered

None.

## Known Stubs

None.

## Known follow-ups (fora do âmbito)

- `attack_scenarios.format_log_entry` ainda não grava `id`: ataques lançados pelo CLI ficam `id: null` e contam em `skipped.no_attack_id`. Plano 12-03 (wave 3); este plano não tocou em `attack_scenarios.py`.
- Política para a vaccine antiga quando o id evolui (partial para not_detected) e quem chama o motor e quando: Phase 13.
- A Phase 13 deve chamar `validate_vaccine` antes de gravar (a docstring do módulo diz-o).
- Docs (`DATA_MODEL.md` com a entidade Vaccine, README, contagem de testes 40 no CLAUDE.md): Phase 14 (VAC-08).

## Threat Flags

None - módulo puro, sem novos endpoints, I/O nem autenticação. T-12-05 a T-12-09 mitigadas pelos testes acima.

## Next Phase Readiness

Pronto para 12-03 (escritor do attack log grava `id`), que usa `validate_vaccine` sobre uma vaccine vinda do escritor real.

## Self-Check: PASSED

- FOUND: scripts/vaccine_engine.py (`def validate_vaccine`, `REASONS`), scripts/test_vaccine_engine.py (`run_contract`, `run_honesty`, `ast.parse`)
- FOUND commits: e4dee31, d432a2e
