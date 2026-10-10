---
gsd_state_version: '1.0'
status: planned
progress:
  total_phases: 3
  completed_phases: 1
  total_plans: 8
  completed_plans: 4
  percent: 33
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-10-09)

**Core value:** Medir de forma honesta, com dados reais, quão bem o laboratório deteta e responde a ataques — nunca apresentar como real um valor inventado ou sem amostra.
**Current focus:** Phase 2 — Avaliação ligada à versão (planeada, 4 planos prontos para executar)

## Current Position

Phase: 2 of 3 (Avaliação ligada à versão)
Plan: 0 of 4 in current phase
Status: Ready to execute
Last activity: 2026-10-10 — Fase 2 planeada (4 planos, 3 waves; decisões D-01..D-11 do utilizador)

Progress: [░░░░░░░░░░] 33%

## Performance Metrics

**Velocity:**
- Total plans completed: 4
- Average duration: -
- Total execution time: 1.0 hours

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 1. Registo de modelos ponta a ponta | 4 | 4 | 1 sessao |

**Recent Trend:**
- Last 5 plans: 01-01, 01-02, 01-03, 01-04
- Trend: 4 planos numa sessao (wave 1 → 2 → 3)

*Updated after each plan completion*

## Accumulated Context

### Decisions

Decisões registadas na tabela Key Decisions do PROJECT.md.
Decisões recentes que afetam o trabalho atual:

- [Roadmap]: 3 fatias verticais (registo -> avaliação -> treino+docs) em vez de camadas horizontais; a fase 1 já inclui API e aba Models para ficar visível de ponta a ponta.
- [Roadmap]: UI-03 (sidebar + whitelist do `serve_frontend.py`) fica na Fase 1 e ativa os dois itens; a aba Evaluation abre com "Sem avaliação" até à Fase 2.
- [Roadmap]: TST-01 fecha na Fase 3, mas os testes de cada fase escrevem-se com o respetivo código.
- [Projeto]: Modelo legado copiado (nunca movido) para `v1` por `adopt`; SHA-256 verificado antes de `joblib.load`.
- [Fase 1]: O badge de erro da aba Models depende de `entry.error_code` e não de `status != "ok"` — o legado (`status: "no_metadata"`, `error_code: null`) desenha-se neutro.
- [Fase 1]: `_resume_adoption` converte qualquer falha de verificação numa v1 existente em `already_adopted` (a causa original fica só no log, via `__cause__`).
- [Fase 2]: `ml_evaluation.py` novo com a lógica de métricas; `model_registry.py` continua stdlib puro e importa-o só dentro de `_cmd_evaluate` (D-01).
- [Fase 2]: O `evaluate` carrega a versão pedida por `resolve_version_artifacts()` (novo), não a que está em `ACTIVE` (D-02).
- [Fase 2]: Rótulo (`feature_extractor.label_with_attack_log`) e decisão (`ml_anomalies.build_ml_anomalies_report`) emparelhados por índice posicional, com guarda `labels_misaligned` (D-03) — é o que impede um número silenciosamente errado.
- [Fase 2]: Aviso de amostra pequena com dois limiares nomeados: `MIN_EVENTS = 50`, `MIN_ATTACKS = 10` (D-05).
- [Fase 2]: `evaluation` fica fora de `METADATA_PUBLIC_KEYS` e a API expõe uma sub-projeção (`EVALUATION_PUBLIC_KEYS`), fechando o risco residual T-01-14 (D-07, D-08).
- [Fase 2]: A aba Evaluation passa a `ml_evaluation.js` (prefixo `mle`), revertendo a implementação da Fase 1 que a tinha posto em `ml_models.js` (D-09).

### Pending Todos

- **Verificação humana pendente na Fase 1 (D9/D10 nos três SUMMARY):** abrir o dashboard real e confirmar os badges, o detalhe por teclado e o aviso de reinício do backend. Os testes cobrem a camada pura em `node:vm`, não o browser.
- **Fase 2 por executar** (`/gsd-execute-phase 2`). A execução da avaliação real sobre dados do laboratório exige o Wazuh Indexer ligado — em 2026-10-10 está desligado (9200 e 55000 fechadas); os testes da fase não dependem dele.

### Blockers/Concerns

- Avaliação atual assenta em 35 eventos (20 ataques): os avisos de amostra pequena têm de aparecer sempre (Fase 2).
- O marco R9 não tem token de versão `vX.Y` (é "R9" do Roadmap v2); ferramentas que procuram milestones por `vX.Y` podem não o reconhecer.
- **D-04 (aceita, não resolvida):** o SHA-256 deteta corrupção/troca acidental mas **não autentica** — quem escreve em `models/` reescreve o `metadata.json`. O legado carrega sem verificação até ao `adopt`. A documentação da Fase 3 tem de manter esta honestidade.
- O `run_all_tests.py` tem timeout de 300 s por ficheiro; numa máquina fria o `test_attack_library.py` pode ir a ~190 s.

## Deferred Items

Items acknowledged and deferred at milestone close, most recent first:

| Category | Item | Status | Deferred At | Milestone |
|----------|------|--------|-------------|-----------|
| *(none)* | | | | |

## Session Continuity

Last session: 2026-10-10
Stopped at: Fase 1 executada e verificada; Fase 2 planeada (4 planos, 3 waves, decisões D-01..D-11)
Resume file: None

Próximo passo natural: `/gsd-execute-phase 2`. A verificação humana da aba Models/Evaluation
(num browser real) e a avaliação real sobre dados do Wazuh continuam pendentes.
