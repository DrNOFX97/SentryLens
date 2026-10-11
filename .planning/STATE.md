---
gsd_state_version: '1.0'
status: milestone-complete
progress:
  total_phases: 3
  completed_phases: 3
  total_plans: 11
  completed_plans: 11
  percent: 100
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-10-09)

**Core value:** Medir de forma honesta, com dados reais, quão bem o laboratório deteta e responde a ataques — nunca apresentar como real um valor inventado ou sem amostra.
**Current focus:** R9 fechado. O passo seguinte é o R10 (ML Learning Loop), ainda por planear.

## Current Position

Phase: 3 of 3 complete (Treino gera versões, testes e documentação)
Plan: 3 of 3 in current phase
Status: Milestone R9 concluído — pronto para `/gsd-complete-milestone` e para planear o R10
Last activity: 2026-10-11 — `f23405b` partiu o repositório; corrigido em `a0464f7` (comando `train` do REG-04 ligado) e em três commits `docs:` que corrigem afirmações falsas sobre o registo de modelos

Progress: [██████████] 100%

**Estado medido hoje:** `run_all_tests.py` → **38/38** (medido, não transportado).
`scripts/models/` só tem os dois `.pkl` legados — sem `vN/`, sem `ACTIVE`, sem
`metadata.json`: o comando `train` existe e foi verificado contra um registo temporário,
mas nunca foi corrido sobre os dados do utilizador.

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
- Fase 3 executada (3 planos, 3 waves) e verificada: **38/38 medidos** em 2026-10-11.
- **Verificar o registo real:** `scripts/models/` só tem os dois `.pkl` legados. Para haver versões é preciso correr `model_registry.py adopt` (ou `train`) — decisão do utilizador, não foi feito por mim porque escreve no disco dele.
- **Risco conhecido para a execução da Fase 3:** resolvido — `dataset_origin` tem valor por omissão (`"unknown"`) em `train_anomaly_model.evaluate`.

### Blockers/Concerns

- **Aprendido em 2026-10-11 (relevante para o resto do marco):** o meu commit `f23405b` partiu `model_registry.py` com `attack_log_path=None, *,)` — sintaxe inválida que não deixava o `main.py` importar. Reportei-o como "R9 concluído, 38/38 verdes" sem voltar a correr a suite depois da minha própria alteração. **Regra que daí sai: um número de suite só conta se foi medido depois da última alteração, no mesmo comando.** Três testes também "passavam" a afirmar coisas que não mediam (o `loaded` sem o GET que carrega, uma restauração que voltava a adulterar o ficheiro, e um `v2` esperado de um registo vazio que dá `v1`). Corrigidos em `a0464f7`.
- **Três bugs pré-existentes em `model_registry.py`** nunca detectados porque `register_trained_version` não tinha caller: auto-import de si próprio em `next_version_id`, `NameError` em `ARTIFACT_FILES`, e recusa se a pasta do registo não existir. **Lição: função sem caller não é testada — só passa no teste que a exercita.**
- `train_anomaly_model.py` continua a importar `model_registry` sem usar (import morto). Não é erro, mas é a forma como a falha passou despercebida.
- Avaliação atual assiste em 35 eventos (20 ataques): os avisos de amostra pequena têm de aparecer sempre (Fase 2).
- O marco R9 não tem token de versão `vX.Y` (é "R9" do Roadmap v2); ferramentas que procuram milestones por `vX.Y` podem não o reconhecer.
- **D-04 (aceita, não resolvida):** o SHA-256 deteta corrupção/troca acidental mas **não autentica** — quem escreve em `models/` reescreve o `metadata.json`. O legado carrega sem verificação até ao `adopt`. Registado em `docs/SECURITY.md`.
- **Para o R10 (decidir no desenho):** `train_anomaly_model.save_model` faz `joblib.dump` num caminho escolhido pelo chamador — exposto por HTTP é escrita arbitrária no host; e `next_version_id` é TOCTOU puro, sem qualquer primitivo de concorrência em `model_registry.py`.
- O `run_all_tests.py` tem timeout de 300 s por ficheiro; numa máquina fria o `test_attack_library.py` pode ir a ~190 s.
- **Costura da Fase 2:** as 14 chaves de `evaluation` estão escritas à mão em dois ficheiros (motor e registo), presas por comparação em `test_ml_models_api.py`. Mudar a lista obriga a migrar os `metadata.json` gravados e `schema_version` continua 1.

## Deferred Items

Items acknowledged and deferred at milestone close, most recent first:

| Category | Item | Status | Deferred At | Milestone |
|----------|------|--------|-------------|-----------|
| *(none)* | | | | |

## Session Continuity

Last session: 2026-10-11
Stopped at: R9 fechado — 11 planos, 38/38 medidos, `train` ligado ao REG-04, documentação corrigida
Resume file: None

Próximo passo: `/gsd-complete-milestone` para fechar o R9, depois planear o R10
(ML Learning Loop — treinar a partir do dashboard e comparar versões).
Ficam pendentes a verificação humana no browser e a exportação real do Wazuh.
