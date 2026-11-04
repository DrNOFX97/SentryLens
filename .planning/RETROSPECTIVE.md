# Retrospective

## Milestone: v1.2 — R12 Vaccine Lab

**Shipped:** 2026-11-04
**Phases:** 3 | **Plans:** 12

### What Was Built
- Tabela `vaccine_decisions` só de acréscimo com máquina de estados pura; `vaccines` do R11 intacta byte a byte.
- `POST /api/vaccines/{id}/decision` e `?state=`/`state_counts` no `GET`, com códigos de erro estáveis.
- Botões Aprovar/Rejeitar, badge de estado, filtro e contadores na aba Vaccines.

### What Worked
- Fatias verticais (store → API → dashboard + docs) com o contrato fixado por teste em cada camada.
- Provar os helpers do frontend em `node:vm` contra as respostas reais da rota.
- Contagem da suite com proveniência (execução completa datada) em vez de números herdados.

### What Was Inefficient
- `STATE.md` e `ROADMAP.md` ficaram desfasados do código entre planos e foram acertados à mão.
- O flake de `test_ml_training.py` só foi corrigido na causa no último plano (pasta temporária partilhada).

### Patterns Established
- Seguimento de erro por tabela pura (`slVacErrorFollowUp`): só GET, nunca novo POST automático.
- Varrimento AST para provar que nada aplica nem executa comandos.

### Key Lessons
- Um teste que lista uma pasta temporária partilhada é um flake à espera de acontecer: isolar por execução.
- Os testes não abrem browser; o UAT humano continua a ser necessário para o que é visual.

### Cost Observations
- Planos executados por subagentes sequenciais na árvore principal (`use_worktrees` desligado).
