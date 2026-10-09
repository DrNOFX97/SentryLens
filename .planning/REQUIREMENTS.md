# Requirements: SentryLens

**Defined:** 2026-10-09
**Core Value:** Medir de forma honesta, com dados reais, quão bem o laboratório deteta e responde a ataques — nunca apresentar como real um valor inventado ou sem amostra.

## v1 Requirements

Milestone atual: **R9 — ML Intelligence** (Roadmap v2). Cada requisito mapeia para uma fase do roadmap.

### Registo de modelos

- [ ] **REG-01**: O analista consegue listar as versões de modelo existentes em `scripts/models/vN/` (lidas do `metadata.json` de cada uma) e ver qual é a ativa, indicada pelo ficheiro `models/ACTIVE`.
- [ ] **REG-02**: O modelo atual (ficheiros soltos `isolation_forest.pkl` + `scaler.pkl` em `models/`) aparece como "legado, sem metadados" e continua a carregar enquanto não for adotado.
- [ ] **REG-03**: `python model_registry.py adopt` copia (nunca move) o modelo legado para `models/v1/` com metadados marcados como "adotado" e a data de treino estimada pela data do ficheiro.
- [ ] **REG-04**: Cada execução de `train_anomaly_model.py` grava uma versão nova `vN` com metadados (data, parâmetros, nome/tamanho/nº de ataques/sintético do dataset, SHA-256 dos dois `.pkl`) e ativa-a.

### Integridade e segurança

- [ ] **SEC-01**: Antes de `joblib.load`, o carregamento do modelo confere o SHA-256 dos `.pkl` com o `metadata.json` e recusa carregar se não bater, com um erro acionável.
- [ ] **SEC-02**: Os ids de versão são validados (`^v[0-9]{1,4}$`); um `ACTIVE` com id inválido ou inexistente é rejeitado e nunca resolve um caminho fora de `models/`.

### Avaliação

- [ ] **EVAL-01**: A avaliação de uma versão (precisão/recall/F1 do ML e das regras, contagens de comparação, aviso do dataset) é guardada no `metadata.json` dessa versão.
- [ ] **EVAL-02**: `python model_registry.py evaluate vN --events <ficheiro>` recalcula a avaliação dessa versão sobre os dados indicados e grava-a.
- [ ] **EVAL-03**: Uma versão sem avaliação mostra "Sem avaliação" (nunca números de outro modelo), e a avaliação traz sempre o aviso de amostra pequena quando o nº de eventos é baixo.

### API

- [ ] **API-01**: `GET /api/ml/models` (API key na própria rota) devolve as versões, a ativa e a avaliação de cada uma; sem modelos devolve lista vazia com 200.
- [ ] **API-02**: Um erro ao ler o registo nunca expõe texto de exceção nem caminhos; devolve códigos estáveis.

### Dashboard

- [ ] **UI-01**: A aba "📦 Models" lista as versões, marca a ativa e o legado, e mostra os metadados de cada uma.
- [ ] **UI-02**: A aba "📐 Evaluation" mostra o ML contra as regras (precisão, recall, F1) por versão e a concordância ao vivo entre os dois, reutilizando `/api/ml-anomalies`, sempre com os avisos de dataset.
- [ ] **UI-03**: Os itens "Models" e "Evaluation" da sidebar deixam de ser `data-planned` e passam a abas reais; `ml_models.js` entra na whitelist do `serve_frontend.py`.

### Qualidade e documentação

- [ ] **TST-01**: Testes standalone cobrem registo, `adopt`, hash adulterado recusado, id inválido recusado, legado sem metadados, avaliação ausente e a rota; a suite completa continua verde.
- [ ] **DOC-01**: `docs/ROADMAP_STATUS.md` (R9 ✅), `docs/DATA_MODEL.md`, `README.md` e `CLAUDE.md` refletem o registo de modelos.

## v2 Requirements

Adiado; não está no roadmap atual.

### Aprendizagem contínua (R10)

- **LRN-01**: Treinar um modelo novo a partir do dashboard.
- **LRN-02**: Comparar versões automaticamente e propor/ativar a melhor.
- **LRN-03**: Reverter a versão ativa a partir do dashboard.

## Out of Scope

| Feature | Reason |
|---------|--------|
| Treinar modelos a partir do dashboard | É o R10; o backend do R9 é só de leitura |
| Calibrar o `confidence` das deteções (R7) | Dívida conhecida, não é pré-requisito do R9 |
| Calcular métricas ML novas além das existentes | O R9 liga a avaliação à versão e mostra-a; não cria detetores nem métricas novas |
| Mover ou apagar os `.pkl` atuais | `adopt` só copia; mexer nos ficheiros do utilizador não foi pedido |

## Traceability

Preenchido na criação do roadmap (2026-10-09).

| Requirement | Phase | Status |
|-------------|-------|--------|
| REG-01 | Phase 1 | Pending |
| REG-02 | Phase 1 | Pending |
| REG-03 | Phase 1 | Pending |
| REG-04 | Phase 3 | Pending |
| SEC-01 | Phase 1 | Pending |
| SEC-02 | Phase 1 | Pending |
| EVAL-01 | Phase 2 | Pending |
| EVAL-02 | Phase 2 | Pending |
| EVAL-03 | Phase 2 | Pending |
| API-01 | Phase 1 | Pending |
| API-02 | Phase 1 | Pending |
| UI-01 | Phase 1 | Pending |
| UI-02 | Phase 2 | Pending |
| UI-03 | Phase 1 | Pending |
| TST-01 | Phase 3 | Pending |
| DOC-01 | Phase 3 | Pending |

**Coverage:**
- v1 requirements: 16 total
- Mapped to phases: 16
- Unmapped: 0 ✓

---
*Requirements defined: 2026-10-09*
*Last updated: 2026-10-09 after roadmap creation*
