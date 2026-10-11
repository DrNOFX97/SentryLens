# SentryLens

## What This Is

SentryLens é um laboratório SOC de aprendizagem do CET (curso de cibersegurança): ingere alertas do Wazuh (Manager API 55000, Indexer API 9200), classifica-os, correlaciona ataques lançados (Red vs Blue) com deteções de regra, ML e rede, gere incidentes e expõe tudo num dashboard estático. Backend FastAPI em `scripts/`, frontend estático na raiz, mais um analisador de logs offline (`log_analyzer.py`, Fase 1) que partilha a classificação de Event IDs.

## Core Value

Medir de forma honesta, com dados reais, quão bem o laboratório deteta e responde a ataques — nunca apresentar como real um valor inventado ou sem amostra.

## Requirements

### Validated

- ✓ Classificação de Event IDs partilhada entre Fase 1 e Fase 2 (`event_catalog.py`) — existing
- ✓ Painéis Wazuh: alertas, estatísticas, brute-force, ciclo de vida de contas, desvios RBAC, atividade de contas admin — existing
- ✓ Autenticação por API key por rota, CORS restrito a loopback, push em tempo real por WebSocket — existing
- ✓ Histórico próprio em JSONL + índice SQLite, relatório HTML, conformidade RGPD/NIS2/AI Act — existing
- ✓ Deteção de anomalias com Isolation Forest (`ml_anomalies.py`, `train_anomaly_model.py`) — existing
- ✓ Red vs Blue (correlator, cenários de ataque com allowlist de alvos), monitorização de rede via SSH+tshark — existing
- ✓ R2 Live SOC, R3 Incidentes, R4 Attack Registry, R5 Attack Library, R6 Network SOC, R7 Detection Engine — Roadmap v2
- ✓ R8 Métricas MTTD/MTTR/cobertura/taxa de deteção (`soc_metrics.py`, `GET /api/metrics`) — Roadmap v2

- ✓ R9 ML Intelligence: registo versionado (`scripts/models/vN/` + `metadata.json` + `ACTIVE`), avaliação ligada à versão, SHA-256 antes de `joblib.load`, `GET /api/ml/models`, abas Models e Evaluation — v1.0
- ✓ R10 ML Learning Loop: treino e ativação por HTTP (`POST /api/ml/train`, `/activate`) com as quatro protecções de D-01, compare-and-set no `ACTIVE`, comparação vN vs vN-1 e feature stats no dashboard — v1.0

### Active

- [ ] Primeiro ciclo de treino real: lançar ataques, exportar alertas na mesma janela, treinar `v1` e avaliar com dataset rotulável
- [ ] Verificação humana pendente do R9/R10 no dashboard (badges, aviso de reinício após `adopt`, avaliação rotulada)

### Out of Scope

- Calibrar o `confidence` das deteções (R7) — dívida conhecida, não é pré-requisito do R9
- Recolher métricas ML novas além das já existentes (`/api/ml-anomalies`) — o R9 só liga a avaliação à versão e mostra-a

## Current State

v1.0 (R9 + R10) entregue a 2026-10-11: 5 fases, 17 planos, suite `run_all_tests.py` 39/39. `scripts/models/` ainda só tem os dois `.pkl` legados (sem `vN/` nem `ACTIVE`); o treino por HTTP está testado mas nunca correu sobre dados reais. O dataset de 2026-09-14 não é rotulável com o `attack_log.jsonl` actual.

## Context

- Projeto de curso (CET), laboratório em VirtualBox: Wazuh-Manager (Ubuntu), alvo Windows 11, Kali atacante.
- A fonte de verdade de arquitetura, endpoints e troubleshooting é `README.md`; `CLAUDE.md` guia o trabalho; o estado do Roadmap v2 (R0–R25) está em `docs/ROADMAP_STATUS.md`.
- 33 ficheiros de teste standalone em `scripts/` (sem pytest), todos sem o Wazuh ligado (tudo mockado). `python run_all_tests.py` corre-os.
- Hoje existe um só modelo (2 `.pkl` de 14 de setembro, sem metadados) e um relatório avulso `ml_training_report.json` (26 de setembro) que não está ligado a nenhum modelo; avaliação sobre 35 eventos (20 ataques).
- Desenho do R9 aprovado em conversa a 2026-10-09; o spec em `docs/superpowers/specs/` ainda por escrever.
- O processo anterior (R2–R8) usou specs/planos em `docs/superpowers/` e execução inline; o GSD é introduzido a partir do R9.

## Constraints

- **Segurança**: nunca ler nem imprimir `scripts/.env`; os `.pkl` executam código ao carregar, por isso só se carregam ficheiros locais com hash verificado — o laboratório tem credenciais reais do Wazuh.
- **Compatibilidade**: não mudar contratos de API existentes; as rotas `/api/*` exigem API key (por rota, nunca a nível de app).
- **Dados reais**: sem mocks apresentados como dados reais; sem amostra → "Sem dados".
- **Plataforma**: Windows 11, PowerShell/Git Bash, Python no `.venv` de `scripts/`; backend na porta 8001 (nunca 8000).
- **Git**: commits e PRs **sem** `Co-Authored-By` do Claude (regra do `CLAUDE.md`); correr o backend/frontend pelos scripts do repo.
- **Idioma**: documentação e interface em português.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Registo de modelos com versões (`models/vN` + `ACTIVE`), não só metadados do modelo atual | O R10 vai criar modelos novos; o histórico evita refazer o registo | ✓ Good (v1.0) |
| Verificar o SHA-256 do `.pkl` contra o `metadata.json` antes de `joblib.load` | `.pkl` executa código ao carregar; o hash fecha o risco de ficheiro adulterado com poucas linhas | ✓ Good (v1.0) |
| Modelo atual copiado (não movido) para `v1` por um comando `adopt` | Não-destrutivo; o modelo legado continua a carregar até ser adotado | ✓ Good (v1.0) |
| Avaliação guardada dentro da versão do modelo | O relatório avulso atual não é rastreável até um modelo | ✓ Good (v1.0) |
| Sem mapeamento de codebase GSD na inicialização | O `CLAUDE.md` e o `README.md` já documentam a arquitetura em detalhe | ✓ Good (v1.0) |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-10-11 after v1.0 milestone*
