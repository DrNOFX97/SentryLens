# Requirements: SentryLens

**Defined:** 2026-10-29
**Core Value:** Medir de forma honesta, com dados reais, quão bem o laboratório deteta e responde a ataques — nunca apresentar como real um valor inventado ou sem amostra.

## v1.2 Requirements — R12 Vaccine Lab

Um analista decide o destino de cada vaccine proposta (aprovar ou rejeitar), com autor, motivo e rasto de auditoria. Aprovar **nunca** aplica nada no Wazuh.

### Decisão

- [x] **VLB-01**: Um analista pode aprovar ou rejeitar uma vaccine por `POST /api/vaccines/{id}/decision` (`approved` | `rejected`), com API key por rota; CORS e `allow_methods` ficam coerentes com o método usado.
- [x] **VLB-02**: O estado segue `proposed → approved | rejected` e é final: uma segunda decisão sobre a mesma vaccine devolve 409 com código estável, e uma vaccine já substituída (`superseded_by`) não pode ser decidida.
- [x] **VLB-03**: Cada decisão fica num registo só de acréscimo (tabela `vaccine_decisions`) com quem decidiu (analista da Equipa SOC), quando, o motivo (obrigatório ao rejeitar) e o estado anterior; a tabela `vaccines` continua imutável com `state='proposed'` imposto pelo SQLite.
- [x] **VLB-04**: Nenhuma rota nem código aplica uma vaccine no Wazuh nem executa comandos; "aprovada" significa só "aceite pelo analista", e um teste varre isto.

### Leitura e dashboard

- [x] **VLB-05**: `GET /api/vaccines[/{id}]` devolve o estado derivado e a decisão (autor, data, motivo) e filtra por estado; sem decisão mostra `proposed`, sem amostra continua "Sem dados" (nunca 0).
- [x] **VLB-06**: O detalhe da vaccine na aba Vaccines tem botões Aprovar e Rejeitar (com campo de motivo), via `data-action` e listener delegado (nenhum handler inline), com erros mostrados pela frase do código estável.

### Qualidade

- [x] **VLB-07**: Testes sem Wazuh (store, API, estático do frontend) e documentação (`DATA_MODEL.md`, `API.md`, `ROADMAP_STATUS.md`, `README.md`, `CLAUDE.md`) refletem o R12 com contagens medidas.

## v2 Requirements

Reconhecidos, fora deste marco.

- **VLB-V2-01**: Dry-run: mostrar que alertas passados a regra proposta teria apanhado, sem a ativar (aproxima-se do R13).
- **VLB-V2-02**: Papéis por tier (por exemplo só Tier 2+ aprova); exige identidade por pedido, que o backend ainda não tem.
- **VLB-V2-03**: Reverter uma decisão (reabrir) com o seu próprio registo de auditoria.

## Out of Scope

| Feature | Reason |
|---------|--------|
| Aplicar a vaccine aprovada no Wazuh | Resposta automática é o R21 e exige reversão, limites e interruptor de emergência |
| Simulação / replay de ataques | R13 (Attack Replay Lab) |
| Papéis por tier | Só existe uma API key; qualquer analista decide e fica registado |
| Apagar ou editar decisões | O registo é só de acréscimo, por desenho |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| VLB-02 | Phase 15, 16 | Complete |
| VLB-03 | Phase 15 | Complete |
| VLB-01 | Phase 16 | Complete |
| VLB-04 | Phase 16 | Complete |
| VLB-05 | Phase 16 | Complete |
| VLB-06 | Phase 17 | Complete |
| VLB-07 | Phase 17 | Complete |

**Coverage:**
- v1.2 requirements: 7 total
- Mapped to phases: 7
- Unmapped: 0 ✓

---
*Requirements defined: 2026-10-29*
*Last updated: 2026-10-29 after v1.2 milestone start*
