# Roadmap: SentryLens

## Overview

Este roadmap começou por cobrir o marco **R9 — ML Intelligence** (Roadmap v2) e foi
alargado ao **R10 — ML Learning Loop** quando o R9 fechou. O projeto já existe e
funciona: o Isolation Forest deteta anomalias, mas há um só modelo (dois `.pkl`
soltos, sem metadados) e um relatório de avaliação avulso que não está ligado a
nenhum modelo. O R9 dá rastreabilidade a isto; o R10 fecha o ciclo — treinar e
activar a partir do dashboard, e comparar versões lado a lado.

A jornada do R9 teve três fatias verticais. Primeiro, o registo de modelos ficou
visível de ponta a ponta (registo versionado, carregamento com hash verificado,
`GET /api/ml/models` e aba Models), incluindo o modelo legado e o comando
`adopt`. Depois, a avaliação passou a viver dentro de cada versão e aparece na
aba Evaluation, com ML contra regras e sempre com os avisos de dataset. Por fim,
o treino passou a gerar versões novas sozinho e o marco fechou com testes e
documentação.

O R10 parte da leitura: o backend deixou de ser só de leitura. Treinar e activar
passam a existir por HTTP, com as quatro protecções de D-01, e o relatório de
anomalias diz de que versão veio cada número.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Registo de modelos ponta a ponta** - Versões em `models/vN`, legado, `adopt`, carregamento com SHA-256, `GET /api/ml/models` e aba Models
- [x] **Phase 2: Avaliação ligada à versão** - Avaliação guardada no `metadata.json`, comando `evaluate` e aba Evaluation (ML vs regras)
- [x] **Phase 3: Treino gera versões, testes e documentação** - Cada treino cria e ativa uma versão nova; suite de testes completa e documentação atualizada
- [x] **Phase 10: Registo com proveniência, motor de treino e superfície HTTP** (R10, backend) - `catalog_sha256` e `feature_stats` no `metadata.json`, compare-and-set no `ACTIVE`, `ml_training.py`, e `POST /api/ml/train` + `POST /api/ml/models/{id}/activate` com as quatro protecções de D-01
- [ ] **Phase 11: O learning loop no dashboard** (R10, frontend) - Botão Treinar com a UX honesta do `loaded != active`, comparação vN vs vN-1 derivada do que a API já traz, e fecho contra a resposta real

> **Nota de planeamento:** os planos de frontend do R10 foram escritos primeiro
> (commit `50d6926`, `10-01/02/03-PLAN.md`) e **sobrepostos** pelos planos de
> backend do mesmo nome (`a514a27`). Recuperados de `50d6926` para a phase 11 em
> `e28d490`. A ordem de execução é 10 → 11: o botão Treinar depende do `POST
> /api/ml/train` existir.

## Phase Details

### Phase 1: Registo de modelos ponta a ponta
**Goal:** O analista abre a aba Models e vê as versões de modelo (incluindo o modelo legado), qual está ativa e os metadados de cada uma, com o carregamento do modelo protegido por verificação de integridade.
**Mode:** mvp
**Depends on:** Nothing (first phase)
**Requirements:** REG-01, REG-02, REG-03, SEC-01, SEC-02, API-01, API-02, UI-01, UI-03
**Success Criteria** (what must be TRUE):
  1. Com versões em `scripts/models/vN/` e um `ACTIVE` a apontar para uma delas, `GET /api/ml/models` (com API key) devolve as versões com os respetivos metadados e indica a ativa; sem modelos devolve lista vazia com 200, e sem API key devolve 401. O campo de avaliação de cada versão existe no contrato (vazio até à Fase 2).
  2. Só com os `.pkl` soltos atuais em `models/`, a aba Models mostra uma entrada "legado, sem metadados", e a deteção de anomalias (`/api/ml-anomalies`) continua a funcionar com esse modelo sem regressão (`python run_all_tests.py` continua verde).
  3. `python model_registry.py adopt` copia (nunca move) o modelo legado para `models/v1/` com metadados marcados como "adotado" e a data de treino estimada pela data do ficheiro; os `.pkl` originais ficam intactos e a aba Models passa a mostrar a v1 como ativa.
  4. Um `.pkl` cujo SHA-256 não bate com o `metadata.json` é recusado antes de `joblib.load`, com um erro acionável; um `ACTIVE` com id inválido ou inexistente (por exemplo `../x`) é rejeitado e nunca resolve um caminho fora de `models/`; falhas de leitura chegam à API e ao dashboard como códigos estáveis, sem texto de exceção nem caminhos.
  5. Os itens "Models" e "Evaluation" da sidebar deixam de ser `data-planned` e abrem abas reais (`ml_models.js` servido pelo `serve_frontend.py`); a aba Models lista as versões, marca a ativa e o legado e mostra os metadados de cada uma, e a aba Evaluation já abre com o estado honesto "Sem avaliação" até à Fase 2.
**Plans:** 4 plans

Plans:
- [x] 01-01-PLAN.md — Tracer: registo em disco → `GET /api/ml/models` (API key) → abas Models e Evaluation reais (wave 1)
- [x] 01-02-PLAN.md — SHA-256 antes de `joblib.load`, legado "sem metadados", ids/ACTIVE validados, 503 com códigos, `loaded` (wave 2)
- [x] 01-03-PLAN.md — Aba Models: estados (legado, adotado, erros), avisos de ACTIVE/`loaded` e detalhe dos metadados (wave 2)
- [x] 01-04-PLAN.md — `python model_registry.py adopt` (cópia atómica para v1, ACTIVE só se não existir) e fluxo ponta a ponta (wave 3)
**UI hint**: yes

### Phase 2: Avaliação ligada à versão
**Goal:** O analista vê, por versão de modelo, como o ML se compara às regras (precisão, recall, F1) e a concordância ao vivo entre os dois, sempre com os avisos de dataset e nunca com números de outro modelo.
**Mode:** mvp
**Depends on:** Phase 1
**Requirements:** EVAL-01, EVAL-02, EVAL-03, UI-02
**Success Criteria** (what must be TRUE):
  1. `python model_registry.py evaluate vN --events <ficheiro>` recalcula a avaliação dessa versão sobre os dados indicados e grava-a no `metadata.json` dessa versão (precisão/recall/F1 do ML e das regras, contagens de comparação e aviso do dataset); as restantes versões não são alteradas.
  2. Uma versão sem avaliação mostra "Sem avaliação" na API e na aba Evaluation; nunca aparecem números de outra versão nem do `ml_training_report.json` avulso.
  3. A aba Evaluation mostra, por versão avaliada, o ML contra as regras (precisão, recall, F1) e o tamanho do dataset (eventos e ataques), com o aviso de amostra pequena sempre presente quando o nº de eventos é baixo.
  4. A aba Evaluation mostra a concordância ao vivo entre ML e regras, obtida de `/api/ml-anomalies` (sem criar métricas ou detetores novos); sem amostra mostra "Sem dados" em vez de um valor.
**Plans:** 4 plans

Plans:
- [x] 02-01-PLAN.md — Tracer: `resolve_version_artifacts` → `evaluate` → `metadata.json` → API → `ml_evaluation.js` (wave 1)
- [x] 02-02-PLAN.md — Motor de avaliação (precisão/recall/F1, limiares de amostra, comparabilidade) e suite própria (wave 2)
- [x] 02-03-PLAN.md — Exportador bruto do Indexer, testado sem o laboratório ligado (wave 2)
- [x] 02-04-PLAN.md — Aba Evaluation completa: dataset, origem, aviso de amostra e concordância ao vivo (wave 3)
**Decisões:** `02-CONTEXT.md` (D-01..D-11, decididas pelo utilizador em 2026-10-10)
**UI hint**: yes

> **Nota de execução:** a avaliação real sobre dados do laboratório exige o Wazuh Indexer ligado.
> O dataset histórico (`scripts/snapshots/real_events_2026-09-14.json`) **foi encontrado**, mas o
> `attack_log.jsonl` só cobre 2026-10-06 e não o rotula — dá 0 ataques, recall 0 por definição.
> Para uma avaliação rotulada a sério é preciso lançar os ataques e exportar na mesma janela.

### Phase 3: Treino gera versões, testes e documentação
**Goal:** Cada treino deixa uma versão rastreável e ativa sem passos manuais, e o marco R9 fica fechado com testes completos e documentação a refletir o registo de modelos.
**Mode:** mvp
**Depends on:** Phase 2
**Requirements:** REG-04, TST-01, DOC-01
**Success Criteria** (what must be TRUE):
  1. Cada execução de `train_anomaly_model.py` grava uma versão nova `vN` (a seguinte) com metadados (data, parâmetros, nome/tamanho/nº de ataques/sintético do dataset, SHA-256 dos dois `.pkl`) e ativa-a; a aba Models mostra a nova versão como ativa e as versões anteriores ficam intactas.
  2. Os testes standalone cobrem registo, `adopt`, hash adulterado recusado, id inválido recusado, legado sem metadados, avaliação ausente e a rota `GET /api/ml/models`; `python run_all_tests.py` termina verde, sem o laboratório Wazuh ligado. Os testes do âmbito das Fases 1 e 2 escrevem-se com o respetivo código; esta fase fecha a cobertura completa.
  3. `docs/ROADMAP_STATUS.md` marca o R9 como concluído (✅) e `docs/DATA_MODEL.md`, `README.md` e `CLAUDE.md` descrevem o registo de modelos (versões, `ACTIVE`, `adopt`, verificação SHA-256 e `/api/ml/models`).
**Plans:** 3 plans

Plans:
- [x] 03-01-PLAN.md — Tracer: `next_version_id` + `build_trained_metadata` + `register_trained_version` → treino → `GET /api/ml/models` → `/api/ml-anomalies` com a vN → aba Models (wave 1)
- [x] 03-02-PLAN.md — TST-01: garantias negativas do caminho novo, gate dos sete itens e suite completa (wave 2)
- [x] 03-03-PLAN.md — DOC-01: `README.md`, `CLAUDE.md`, `docs/DATA_MODEL.md`, `docs/ROADMAP_STATUS.md`, `docs/ML.md` (wave 3)
**Decisões:** `03-CONTEXT.md` (D-01..D-11, decididas pelo utilizador em 2026-10-10)
**UI hint**: no — D-10 confirmado por inspecção do código: `ml_models.js` já desenha `parameters`, `dataset`, `library_versions` e `origin: "trained"`. Falta é a prova (fixture da versão treinada completa), não a capacidade.

### Phase 10: Registo com proveniência, motor de treino e superfície HTTP (R10, backend)
**Goal:** O backend passa a ter escrita no registo por HTTP, com a proveniência do lote gravada no `metadata.json` e as quatro protecções que fecham a superfície nova.
**Mode:** mvp
**Depends on:** Phase 3
**Requirements:** REG-05, API-01, API-02, TST-01
**Success Criteria** (what must be TRUE):
  1. `POST /api/ml/train` (com API key) treina, regista, activa e recarrega a cache numa só resposta, e nenhum caminho vem do corpo: `extra="forbid"`, `dataset`/`dataset_origin` obrigatórios, três tetos testados pelos dois lados.
  2. Um treino e uma activação nunca correm ao mesmo tempo: o segundo pedido dá 409 `training_in_progress` e não escreve nada.
  3. `/api/ml-anomalies` traz `model_version` (`"vN"`, `"legacy"` ou `None`) sem que nenhuma chave anterior mude.
  4. Nenhum `detail` traz texto de excepção, caminho ou traceback, em nenhum dos sete caminhos de erro.
**Plans:** 3 plans

Plans:
- [x] 10-01-PLAN.md — Registo com proveniência: `catalog_sha256`, `dataset` de D-02, `feature_stats` de D-03, compare-and-set no `ACTIVE`, e o `run()` de `test_model_registry.py` corrigido (wave 1)
- [x] 10-02-PLAN.md — `ml_training.py`: `train_next_version` sem nenhum caminho do cliente, single-flight com `threading.Lock`, e o CLI a registar o modelo que treina de facto (wave 2)
- [x] 10-03-PLAN.md — Camada HTTP: as duas rotas POST, `_ml_write_error`, `model_version` e o contrato de single-flight por HTTP (wave 3)
**Decisões:** `10-CONTEXT.md` (D-01..D-08, decididas pelo utilizador em 2026-10-11)

### Phase 11: O learning loop no dashboard (R10, frontend)
**Goal:** O analista treina a partir da aba 📦 Models e vê o que aconteceu — incluindo que o backend ainda não a usa — e compara vN com vN-1 na aba Evaluation sem um endpoint novo.
**Mode:** mvp
**Depends on:** Phase 10 (o `POST /api/ml/train` tem de existir)
**Requirements:** UI-01, UI-02, UI-05, API-02
**Success Criteria** (what must be TRUE):
  1. O botão Treinar no painel diz exactamente o que aconteceu à versão nova, e diz que é preciso reiniciar o backend quando `loaded != active`.
  2. Um 409/422/503 desenha-se como erro com a frase do código, nunca como "Sem dados" nem como linha vazia.
  3. A aba Evaluation mostra a comparação vN vs vN-1 derivada do que `/api/ml/models` já traz, com delta em pontos percentuais e o aviso de lote (D-03).
  4. Nenhum ficheiro JS novo na raiz: `serve_frontend.py` não é tocado.
**Plans:** 3 plans

Plans:
- [x] 11-01-PLAN.md — `ml_models.js` ganha `mlmPost`, o botão Treinar e o aviso `loaded != active` (wave 1)
- [x] 11-02-PLAN.md — `ml_evaluation.js` ganha a comparação vN vs vN-1 derivada, mais `model_version` no bloco ao vivo e o hash do catálogo no detalhe (wave 2)
- [x] 11-03-PLAN.md — Fecho: `feature_stats` lido contra o `metadata.json` real, suite completa e a pergunta em aberto da sidebar (wave 3)
**Nota:** estes três planos foram escritos **antes** do backend do R10 existir — o 11-03 existe precisamente para conferir as hipóteses deles contra a resposta real (`feature_stats`, `model_version`).

## Progress

**Execution Order:**
Phases execute in order: 1 → 2 → 3 → 10 → 11

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Registo de modelos ponta a ponta | 4/4 | Complete | 2026-10-10 |
| 2. Avaliação ligada à versão | 4/4 | Complete | 2026-10-10 |
| 3. Treino gera versões, testes e documentação | 3/3 | Complete | 2026-10-11 |
| 10. Registo, motor e superfície HTTP (backend do R10) | 3/3 | Complete | 2026-10-11 |
| 11. O learning loop no dashboard (frontend do R10) | 3/3 | Complete | 2026-10-11 |
