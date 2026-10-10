---
gsd_state_version: '1.0'
status: phase-complete
progress:
  total_phases: 3
  completed_phases: 2
  total_plans: 8
  completed_plans: 8
  percent: 67
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-10-09)

**Core value:** Medir de forma honesta, com dados reais, quão bem o laboratório deteta e responde a ataques — nunca apresentar como real um valor inventado ou sem amostra.
**Current focus:** Phase 3 — Treino gera versões, testes e documentação (por planear)

## Current Position

Phase: 3 of 3 (Treino gera versões, testes e documentação)
Plan: 0 of 3 in current phase
Status: Ready to execute
Last activity: 2026-10-10 — Fase 3 planeada (3 planos, 3 waves; decisões D-01..D-11 do utilizador)

Progress: [██████░░░░] 67%

## Performance Metrics

**Velocity:**
- Total plans completed: 4
- Average duration: -
- Total execution time: 1.0 hours

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 1. Registo de modelos ponta a ponta | 4 | 4 | 1 sessao |
| 2. Avaliação ligada à versão | 4 | 4 | 1 sessao |

**Recent Trend:**
- Last 5 plans: 02-01, 02-02, 02-03, 02-04
- Trend: 8 planos em duas sessões (2 fases completas)

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
- [Fase 2]: Verificado na prática: o `comparison` do `evaluate` sobre o dataset real dá 5/2/3/25, **idêntico** ao `ml_training_report.json` histórico — as métricas são comparáveis com as do README (D-04).
- [Fase 2]: `export_raw_events.py` exporta documentos brutos num formato que `feature_extractor.extract_features` lê; provado por um teste que escreve o ficheiro com um cliente real e só depois o passa ao extractor.
- [Fase 2]: `/api/ml-anomalies` ganhou `alerts_fetched` e `alerts_truncated` (aditivo; nenhum consumidor existente foi quebrado).

### Pending Todos

- **Verificação humana pendente nas Fases 1 e 2:** abrir o dashboard real e confirmar os badges, o detalhe por teclado, a Evaluation e o aviso de reinício do backend. Os testes cobrem a camada pura em `node:vm`, não o browser.
- **A exportação real do Wazuh continua por executar** (Indexer desligado). Comandos exactos em `02-VERIFICATION.md`.
- **O dataset histórico foi encontrado** (`scripts/snapshots/real_events_2026-09-14.json`, 1,7 MB, não versionado) mas **não é rotulável**: o `attack_log.jsonl` só cobre 2026-10-06 e a janela do dataset é 2026-09-14 15:22–15:34. Rotulado contra ele dá 0 ataques. Para uma avaliação a sério é preciso lançar os ataques e exportar na mesma janela — trabalho de laboratório, não de código.
- Fase 3 por executar (`/gsd-execute-phase 3`): 3 planos, um por wave, sequenciais.
- **Risco conhecido para a execução da Fase 3:** `test_ml_evaluation.py:185` chama `train_anomaly_model.evaluate(linhas, model, scaler)` com três posicionais — o novo `dataset_origin` tem de ter valor por omissão ou esse teste parte.

### Blockers/Concerns

- Avaliação atual assenta em 35 eventos (20 ataques): os avisos de amostra pequena têm de aparecer sempre (Fase 2).
- O marco R9 não tem token de versão `vX.Y` (é "R9" do Roadmap v2); ferramentas que procuram milestones por `vX.Y` podem não o reconhecer.
- **D-04 (aceita, não resolvida):** o SHA-256 deteta corrupção/troca acidental mas **não autentica** — quem escreve em `models/` reescreve o `metadata.json`. O legado carrega sem verificação até ao `adopt`. A documentação da Fase 3 tem de manter esta honestidade.
- O `run_all_tests.py` tem timeout de 300 s por ficheiro; numa máquina fria o `test_attack_library.py` pode ir a ~190 s.
- **Costura da Fase 2:** as 14 chaves de `evaluation` estão escritas à mão em dois ficheiros (motor e registo), presas por comparação em `test_ml_models_api.py`. Mudar a lista obriga a migrar os `metadata.json` gravados e `schema_version` continua 1.
- `docs/ML.md:71-75` está desatualizado: diz que o gap do formato de exportação "fica para uma sessão futura" — já foi resolvido pelo `export_raw_events.py`. A correcção é do DOC-01 (Fase 3).

## Deferred Items

Items acknowledged and deferred at milestone close, most recent first:

| Category | Item | Status | Deferred At | Milestone |
|----------|------|--------|-------------|-----------|
| *(none)* | | | | |

## Session Continuity

Last session: 2026-10-10
Stopped at: Fases 1 e 2 do R9 executadas e verificadas (8 planos); Fase 3 por planear
Resume file: None

Próximo passo natural: `/gsd-plan-phase 3` (treino gera versões, testes e documentação).
Ficam pendentes a verificação humana no browser e a exportação real do Wazuh.
