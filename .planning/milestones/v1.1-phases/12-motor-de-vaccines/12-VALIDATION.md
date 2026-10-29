---
phase: "12"
slug: motor-de-vaccines
status: draft
nyquist_compliant: false
wave_0_complete: false
created: "2026-10-11"
---

# Phase 12 — Validation Strategy

> Contrato de validação por fase. Detalhe completo na secção Validation Architecture de `12-RESEARCH.md`.

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | scripts standalone (sem pytest), `[OK]`/`[FALHOU]` + `sys.exit(1)` |
| **Config file** | none |
| **Quick run command** | `cd scripts && .venv/Scripts/python test_vaccine_engine.py` |
| **Full suite command** | `cd scripts && .venv/Scripts/python run_all_tests.py` |
| **Estimated runtime** | ~13 seconds (suite completa) |

## Sampling Rate

- **After every task commit:** `python test_vaccine_engine.py`
- **After every plan wave:** `python run_all_tests.py`
- **Before `/gsd-verify-work`:** suite completa verde
- **Max feedback latency:** 15 seconds

## Per-Task Verification Map

Comandos a partir de `scripts/` com o venv (`.venv/Scripts/python -X utf8 ...`).

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 12-01-01 | 01 | 1 | VAC-01, VAC-02, VAC-03 | T-12-03, T-12-04 | uma vaccine por not_detected/partial com proposals[], ids golden, sensores em falta vindos de attack_library; tool/alvo/operador nunca copiados | unit (tracer) | `test_vaccine_engine.py` | ❌ criado na própria tarefa | ⬜ pending |
| 12-01-02 | 01 | 1 | VAC-01, VAC-03 | T-12-01, T-12-02 | id inválido/repetido saltado e contado (D-04); `unknown` e truncagem nunca geram; ids estáveis e independentes da ordem | unit | `test_vaccine_engine.py` + `run_all_tests.py vaccine` | ✅ (12-01-01) | ⬜ pending |
| 12-02-01 | 02 | 2 | VAC-02 | T-12-05, T-12-09 | contrato fechado, `validate_vaccine` em allowlist, nenhuma string casa a deny-list de comandos, gate AST de imports | unit | `test_vaccine_engine.py` | ✅ (12-01-01) | ⬜ pending |
| 12-02-02 | 02 | 2 | VAC-04 | T-12-06, T-12-07, T-12-08 | `no_data`, `source_unavailable` e "tudo unknown" distintos; nunca zeros inventados nem vaccines com fonte em baixo | unit + suite | `test_vaccine_engine.py && run_all_tests.py` | ✅ (12-01-01) | ⬜ pending |
| 12-03-01 | 03 | 3 | VAC-03 | T-12-10, T-12-14 | entrada do escritor real grava id, é lida do disco e gera vaccine validada; formato antigo e `--self-check` intactos | integração pura (tracer) | `test_attack_log_ids.py && test_attack_registry.py && attack_scenarios.py --self-check` | ❌ criado na própria tarefa | ⬜ pending |
| 12-03-02 | 03 | 3 | VAC-03 | T-12-10, T-12-11, T-12-12, T-12-13, T-12-14 | ids max+1 sem colisão, linhas hostis ignoradas, sem backfill, fail-closed antes de lançar (CLI código 2), log real intocado | unit + suite | `test_attack_log_ids.py && run_all_tests.py` | ✅ (12-03-01) | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

## Wave 0 Requirements

- [ ] `scripts/test_vaccine_engine.py` — criado pela tarefa 12-01-01 (teste primeiro, vermelho); cobre VAC-01..VAC-04 sobre fixtures de `test_attack_registry.py`
- [ ] `scripts/test_attack_log_ids.py` — criado pela tarefa 12-03-01 (teste primeiro, vermelho); cobre VAC-03 com o escritor real do attack log

## Manual-Only Verifications

All phase behaviors have automated verification.

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 15s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
