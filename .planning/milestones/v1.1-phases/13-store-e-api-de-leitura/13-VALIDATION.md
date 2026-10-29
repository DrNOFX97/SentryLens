---
phase: "13"
slug: store-e-api-de-leitura
status: draft
nyquist_compliant: false
wave_0_complete: false
created: "2026-10-12"
---

# Phase 13 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Scripts standalone (sem pytest), `check(label, cond)`, `sys.exit(1)` se falhar |
| **Config file** | none |
| **Quick run command** | `cd scripts && .venv/Scripts/python.exe -X utf8 test_vaccine_store.py` (idem para os outros) |
| **Full suite command** | `cd scripts && .venv/Scripts/python.exe run_all_tests.py` |
| **Estimated runtime** | ~5 s por ficheiro; ~15 s suite completa |

## Sampling Rate

- **After every task commit:** o ficheiro de teste da tarefa
- **After every plan wave:** `run_all_tests.py vaccine` e `run_all_tests.py attack`
- **Before `/gsd-verify-work`:** suite completa verde
- **Max feedback latency:** 15 s

## Per-Task Verification Map

| Requirement | Behavior | Test Type | Automated Command | File Exists |
|-------------|----------|-----------|-------------------|-------------|
| VAC-05 | insert 1.ª vez; reprocessar não acrescenta; reinício devolve mesma lista; imutabilidade (UPDATE/DELETE abortam); `superseded_by` | unit | `python test_vaccine_store.py` | ❌ W0 |
| VAC-05 | validate antes de gravar; settle/janela; falha do Indexer não apaga; `origin.incident_ids` (regressão `list_incidents`) | integration (mock) | `python test_vaccine_ingest.py` | ❌ W0 |
| VAC-06 | 401 sem key; vazio 200 `no_data`; filtros/ordem; detalhe 200/404 `entry_not_found`/422; escrita 405; 503 `store_unavailable` sem texto de exceção | integration | `python test_vaccines_api.py` | ❌ W0 |

## Wave 0 Requirements

- [ ] `scripts/test_vaccine_store.py` — VAC-05 (store)
- [ ] `scripts/test_vaccine_ingest.py` — VAC-05 (ciclo)
- [ ] `scripts/test_vaccines_api.py` — VAC-06 (rotas)

## Manual-Only Verifications

All phase behaviors have automated verification.

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] No 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] Feedback latency < 15s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
