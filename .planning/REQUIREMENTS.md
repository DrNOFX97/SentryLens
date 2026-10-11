# Requirements: SentryLens — v1.1 R11 Vaccine Engine

**Defined:** 2026-10-11
**Core Value:** Medir de forma honesta, com dados reais, quão bem o laboratório deteta e responde a ataques — nunca apresentar como real um valor inventado ou sem amostra.

## v1.1 Requirements

Uma *vaccine* é uma regra de deteção **proposta** a partir de um ataque não detetado ou só parcialmente detetado. Nunca é aplicada, nunca contém comandos executáveis.

### Motor

- [x] **VAC-01**: O analista obtém candidatos a vaccine a partir do relatório Red vs Blue: ataques `not_detected` e `partial` geram candidato; `detected` e `unknown` nunca geram.
- [x] **VAC-02**: Cada vaccine traz a regra proposta (`event_ids`, janela, condição e sensor esperado) derivada de `attack_library`, `attack_scenarios` e `event_catalog`; nenhum campo contém um comando executável.
- [ ] **VAC-03**: Cada vaccine liga à origem (`attack_id`, cenário, técnica MITRE, incidentes e evidência por referência) e tem id determinístico: reprocessar os mesmos ataques não cria duplicados.
- [x] **VAC-04**: Sem amostra ou com fonte indisponível, o motor devolve "Sem dados" ou um código estável; nunca inventa uma vaccine.

### Persistência e API

- [ ] **VAC-05**: As vaccines persistem num store escrito só pelo backend, com estado fixo `proposed`; reiniciar o backend não as perde nem as duplica.
- [ ] **VAC-06**: `GET /api/vaccines` e `GET /api/vaccines/{id}` (só leitura, API key por rota) devolvem a lista e o detalhe; id inexistente dá 404 com código estável `entry_not_found`; erros nunca expõem texto de exceção nem caminhos.

### Dashboard

- [ ] **VAC-07**: A aba "Vaccines" (`vaccines.js`, sem editar `app.js`, servido pelo `serve_frontend.py`) lista as vaccines com filtros e detalhe, e mostra "Sem dados" quando não há amostra.

### Qualidade

- [ ] **VAC-08**: Testes standalone sem o Wazuh cobrem motor, store e rotas, a suite `run_all_tests.py` continua verde, e `DATA_MODEL.md`, `ROADMAP_STATUS.md`, `README.md` e `CLAUDE.md` refletem o R11.

## Future Requirements

Deferidos para o Vaccine Lab e seguintes.

- **LAB-01** (R12): criar, aprovar e rejeitar vaccines por HTTP, com autor e audit log.
- **RPL-01** (R13): replay de um ataque contra uma vaccine.
- **REG-01** (R14): suite de regressão de segurança sobre as vaccines aprovadas.

## Out of Scope

| Feature | Reason |
|---------|--------|
| Aplicar regras no Wazuh | O R11 só propõe; aplicar muda o SIEM e exige aprovação (R12+) |
| Mudar estado por HTTP | Escrita por HTTP pertence ao R12 |
| Comandos executáveis nas vaccines | Mesmo contrato da Attack Library: catálogo só de leitura |
| Gerar regras com ML | `confidence` calibrado continua em dívida (R7) |

## Traceability

Preenchido na criação do roadmap (2026-10-11).

| Requirement | Phase | Status |
|-------------|-------|--------|
| VAC-01 | Phase 12 | Complete |
| VAC-02 | Phase 12 | Complete |
| VAC-03 | Phase 12 | Pending |
| VAC-04 | Phase 12 | Complete |
| VAC-05 | Phase 13 | Pending |
| VAC-06 | Phase 13 | Pending |
| VAC-07 | Phase 14 | Pending |
| VAC-08 | Phase 14 | Pending |

**Coverage:**
- v1.1 requirements: 8 total
- Mapped to phases: 8 ✓
- Unmapped: 0

---
*Requirements defined: 2026-10-11*
*Last updated: 2026-10-11 after roadmap creation (traceability filled)*
