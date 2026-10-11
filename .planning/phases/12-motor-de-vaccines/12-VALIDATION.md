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

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 12-01-xx | 01 | 1 | VAC-01..VAC-04 | — | sem comandos executáveis; `unknown` nunca vira vaccine | unit | `python test_vaccine_engine.py` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

## Wave 0 Requirements

- [ ] `scripts/test_vaccine_engine.py` — cobre VAC-01..VAC-04 sobre fixtures de `test_attack_registry.py`

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
