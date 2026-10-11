---
phase: 12-motor-de-vaccines
verified: 2026-10-12T00:30:00Z
status: passed
score: 4/4 must-haves verified
covered_files:
  - scripts/attack_scenarios.py
  - scripts/test_attack_log_ids.py
  - scripts/test_vaccine_engine.py
  - scripts/vaccine_engine.py
covered_digest: "v2:sha256:9a0c0f0332fee310440af870101143b58681ade0792b34fe1e8d827ce35cd1b7"
behavior_unverified: 0
overrides_applied: 0
re_verification: false
---

# Phase 12: Motor de vaccines - Verification Report

**Phase Goal:** O backend sabe propor, a partir dos gaps do Red vs Blue, uma regra de deteção rastreável até ao ataque que a originou, e recusa propor quando não há amostra.
**Verified:** 2026-10-12
**Status:** passed
**Re-verification:** No (initial verification)

## Goal Achievement

### Observable Truths (ROADMAP success criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Um candidato por ataque `not_detected`/`partial`, nenhum por `detected`/`unknown` (incluindo `unknown` por truncagem) | VERIFIED | `vaccine_engine.build_vaccine_candidates` (l.206-216) só deixa passar `GENERATING_VERDICTS`. Sonda própria sobre `attack_registry.build_attack_registry` real: 3 `not_detected` -> 3 vaccines; os mesmos 3 ataques com `alerts_truncated=True` -> 0 vaccines, `considered.unknown=3`. `test_vaccine_engine.py` cobre a matriz de vereditos, truncagem, correlação indisponível e vereditos inválidos. |
| 2 | Regra proposta (`event_ids`, janela, condição, sensor) derivada de attack_library/attack_scenarios/event_catalog; nenhum campo com comando executável (chaves fechadas, varrimento de todos os valores) | VERIFIED | `_build_proposal`: `rule={event_ids, min_count=1, window_seconds=DEFAULT_WINDOW_SECONDS}` + `events` de `classify_alert`; ml/network só levam recomendação PT-PT constante. Sensores esperados vêm de `attack_registry.expected_detection` -> `attack_library.get_expected_sensors` (teste substitui a biblioteca e a vaccine muda). `validate_vaccine` fecha chaves a todos os níveis e aceita strings só de allowlist; teste varre chaves e valores com `DENY_RE`, inclui entrada hostil (netexec/hydra/rm -rf/IP) que não vaza. Um teste AST proíbe I/O e imports fora da allowlist no motor. |
| 3 | Origem rastreável (`attack_id`, cenário, MITRE, incidentes, evidência por referência) e id determinístico, sem duplicados ao reprocessar | VERIFIED | `_build_origin` guarda só referências (ids de incidente validados por regex, contagens e event_ids; sem tool/target/source/operator/details). `vaccine_id` = `vac-` + sha256[:12] de `<attack_id>:<sensores em falta>`, com literais golden nos testes. Sonda: duas corridas dão resultado igual; teste com lista invertida também. Ids duplicados no log são saltados (`skipped.duplicate_id`), nunca atribuídos ao ataque errado. `attack_scenarios.run_scenario` grava `id` max+1 (`next_attack_id`, fail-closed `AttackIdUnavailable`, sem backfill); `test_attack_log_ids.py` percorre escritor real -> registo -> motor -> vaccine com `validate_vaccine == []`. |
| 4 | Sem amostra ou fonte indisponível -> "Sem dados"/código estável, nunca fabrica vaccine | VERIFIED | `_envelope`: `no_data` (lista vazia, zeros verdadeiros) e `source_unavailable` (registo malformado ou `correlation.available` não True; contagens `None`, nunca zeros inventados; `error_code` da correlação não é copiado). Confirmado por sonda: registo vazio -> `reason=no_data`, correlação em baixo -> `reason=source_unavailable`, `vaccines=[]`. Tudo `unknown` -> `reason=None`, `available=True`, 0 vaccines, distinto dos dois estados anteriores. |

**Score:** 4/4 truths verified (0 behavior-unverified; o motor é puro e os testes exercitam as transições).

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `scripts/vaccine_engine.py` (403 linhas) | `build_vaccine_candidates`, `vaccine_id`, `validate_vaccine`, constantes de contrato | VERIFIED | Substantivo, sem stubs; módulo puro (sem I/O). Ainda sem consumidores em `main.py`: intencional, a Phase 13 liga-o. |
| `scripts/test_vaccine_engine.py` (610 linhas) | Suite standalone sem Wazuh | VERIFIED | Corre e passa ("Todos os testes passaram"); registada em `run_all_tests.py` (PASS). |
| `scripts/attack_scenarios.py` | Escritor grava `id` | VERIFIED | `next_attack_id`, `valid_attack_id`, `format_log_entry(attack_id=)`, `run_scenario` e `--self-check` ("grava id max+1" OK). |
| `scripts/test_attack_log_ids.py` (310 linhas) | Tracer escritor -> vaccine, fail-closed, sem backfill, paridade com o registo | VERIFIED | Passa; confirma que o `attack_log.jsonl` real não é escrito (sha256). |

### Key Link Verification

| From | To | Via | Status |
|------|----|-----|--------|
| `vaccine_engine` | `attack_registry` (`EXPECTED_SOURCES`, `VERDICTS`, `normalize_attack_id`) | import | WIRED |
| `vaccine_engine` | `event_catalog.classify_alert` | `_build_proposal`/`validate_vaccine` | WIRED |
| `vaccine_engine` | `redblue_correlator.DEFAULT_WINDOW_SECONDS` | `window_seconds` | WIRED |
| registo -> `expected.detection` | `attack_library.get_expected_sensors` | `attack_registry.expected_detection` | WIRED (teste substitui a biblioteca) |
| `attack_scenarios.run_scenario` | `attack_registry.normalize_attack_id` | paridade por regra repetida (evita import circular) + teste de paridade | WIRED |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Motor | `.venv/Scripts/python -X utf8 test_vaccine_engine.py` | passa, exit 0 | PASS |
| Escritor de ids | `... test_attack_log_ids.py` | passa, exit 0 | PASS |
| Self-check do escritor | `... attack_scenarios.py --self-check` | `[OK] run_scenario grava id max+1` | PASS |
| Sonda independente (registo real, truncado/não, indisponível, vazio) | script no scratchpad | resultados como na tabela de truths | PASS |
| Suite completa | `... run_all_tests.py` | 40/41; só `test_attack_registry.py` falha | ver abaixo |

### Pre-existing failure (fora do âmbito, alegação confirmada)

`test_attack_registry.py` falha 2 checks ("lista: ataque 1 com incidente ligado", "detalhe: 200 com esperado vs real e incidentes"). Confirmado que é anterior e alheio à Phase 12: extraí `HEAD` (`git archive HEAD scripts`) para uma pasta isolada e `test_attack_registry.py` passa ("Todas as verificações passaram"; o `PermissionError` de ficheiro temporário que aparece no output é ruído registado também no HEAD). Na árvore de trabalho falha porque o diff não commitado de `scripts/incident_store.py` insere `assigned_to` como parâmetro posicional de `IncidentStore.list_incidents`, e `scripts/main.py:1535` chama `list_incidents(None, None, None, 100000, 0)` posicionalmente (agora `100000` cai em `assigned_to`). Nem `main.py` nem `incident_store.py` foram tocados por commits da Phase 12 (`git status`: ambos modificados só na árvore de trabalho). Já registado em `deferred-items.md`. Sugestão: passar `limit=`/`offset=` por palavra-chave em `main.py` quando o trabalho de triagem/atribuição for commitado.

### Requirements Coverage

| Requirement | Plan | Status | Evidence |
|-------------|------|--------|----------|
| VAC-01 | 12-01 | SATISFIED | Verdade 1 |
| VAC-02 | 12-01, 12-02 | SATISFIED | Verdade 2 |
| VAC-03 | 12-01, 12-03 | SATISFIED | Verdade 3 |
| VAC-04 | 12-02 | SATISFIED | Verdade 4 |

Sem requisitos órfãos: VAC-05..08 pertencem às Phases 13 e 14.

### Anti-Patterns Found

Nenhum. Sem `TBD`/`FIXME`/`XXX`/`TODO` nem stubs nos quatro ficheiros da fase (motor sem retornos vazios que não sejam envelopes honestos e deliberados).

### Human Verification Required

Nenhuma: a fase é um módulo puro sem rota nem ecrã, e todo o comportamento é exercitado por testes standalone que passam.

### Gaps Summary

Sem lacunas. Notas informativas (não bloqueantes): (1) `validate_vaccine` é a barreira que a Phase 13 tem de chamar antes de gravar; (2) o `vaccine_id` deteta troca/duplicação mas não autentica; (3) a única falha da suite completa (`test_attack_registry.py`) vem de trabalho não commitado alheio à fase.

---

_Verified: 2026-10-12_
_Verifier: Claude (gsd-verifier)_
