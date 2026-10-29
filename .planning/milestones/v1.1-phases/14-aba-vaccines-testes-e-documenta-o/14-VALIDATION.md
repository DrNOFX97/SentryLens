---
phase: "14"
slug: "aba-vaccines-testes-e-documenta-o"
status: validated
nyquist_compliant: true
wave_0_complete: true
created: "2026-10-19"
---

# Phase 14 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution. Reconstruído a partir dos 4 `*-PLAN.md`/`*-SUMMARY.md` (nenhum `14-VALIDATION.md` existia antes desta auditoria).

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | nenhum (scripts standalone, padrão do repositório — `[OK]`/`[FALHOU]`, `sys.exit(1)`) |
| **Config file** | none |
| **Quick run command** | `cd scripts && .venv/Scripts/python -X utf8 test_vaccines_frontend.py` |
| **Full suite command** | `cd scripts && .venv/Scripts/python run_all_tests.py` |
| **Estimated runtime** | ~13s (suite completa, paralela) |

---

## Sampling Rate

- **After every task commit:** `test_vaccines_frontend.py` (e `test_serve_frontend.py` nas tarefas que tocam a whitelist)
- **After every plan wave:** `run_all_tests.py vaccine` (filtro) ou `run_all_tests.py` completo (14-04)
- **Before `/gsd-verify-work`:** suite completa verde — confirmado: 75/75 em 2026-10-19
- **Max feedback latency:** ~13s

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 14-01-01 | 01 | 1 | VAC-07 | — | N/A | contrato estático + integração | `test_vaccines_frontend.py` | ✅ | ✅ |
| 14-01-02 | 01 | 1 | VAC-07 | — | N/A | contrato estático (whitelist) | `test_serve_frontend.py` | ✅ | ✅ |
| 14-02-01 | 02 | 2 | VAC-07 | — | N/A | contrato estático | `test_vaccines_frontend.py` | ✅ | ✅ |
| 14-02-02 | 02 | 2 | VAC-07 | — | N/A | contrato estático + suite | `test_vaccines_frontend.py`, `run_all_tests.py vaccine` | ✅ | ✅ |
| 14-03-01 | 03 | 3 | VAC-07 | — | N/A | contrato estático | `test_vaccines_frontend.py` | ✅ | ✅ |
| 14-03-02 | 03 | 3 | VAC-07 | — | N/A | contrato estático + suite | `test_vaccines_frontend.py`, `run_all_tests.py vaccine` | ✅ | ✅ |
| 14-04-01 | 04 | 4 | VAC-08 | — | N/A | documentação (chaves do modelo) | script inline (`DATA_MODEL.md`) | ✅ | ✅ |
| 14-04-02 | 04 | 4 | VAC-08 | — | N/A | documentação (endpoints) | script inline (`API.md`) | ✅ | ✅ |
| 14-04-03 | 04 | 4 | VAC-02, VAC-08 | — | N/A | suite completa + documentação (dívida/evidência) | `run_all_tests.py`, scripts inline (README/CLAUDE.md/ROADMAP_STATUS.md) | ✅ | ✅ |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

Todas as 11 ocorrências de `<automated>` nos 4 planos apontam para estes três ficheiros/scripts inline — nenhuma tarefa ficou sem comando automático (confirmado por contagem: nº de `<automated>` ≥ nº de tarefas em cada plano).

---

## Wave 0 Requirements

*Existing infrastructure covers all phase requirements.* (`test_vaccines_frontend.py`, `test_serve_frontend.py` e `run_all_tests.py` já existiam de fases anteriores — Phase 14 só os estendeu.)

---

## Manual-Only Verifications

*All phase behaviors have automated verification.* As 4 verificações humanas declaradas em `14-VERIFICATION.md` (filtros/UX, banner de erro com backend parado, navegação por teclado + cadeia, vaccine aparecer depois de um ataque real) são sobre **experiência visual/UX e um cenário com o laboratório ligado** — fora do que um teste automatizado observa — não substitutos de cobertura Nyquist em falta.

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (nenhuma)
- [x] No watch-mode flags
- [x] Feedback latency < 15s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-10-19

## Validation Audit

| Gaps found | Resolved | Escalated |
|---|---|---|
| 0 | 0 | 0 |
