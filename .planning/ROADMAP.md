# Roadmap: SentryLens

## Milestones

- ✅ **v1.0 ML Registry & Learning Loop** — Phases 1-3, 10-11 (R9 + R10, shipped 2026-10-11)
- ✅ **v1.1 R11 Vaccine Engine** — Phases 12-14 (shipped 2026-10-29)
- 🚧 **v1.2 R12 Vaccine Lab** — Phases 15-17 (em curso)

## Phases

<details>
<summary>✅ v1.0 ML Registry & Learning Loop (Phases 1-3, 10-11) — SHIPPED 2026-10-11</summary>

- [x] Phase 1: Registo de modelos ponta a ponta (4/4 plans)
- [x] Phase 2: Avaliação ligada à versão (4/4 plans)
- [x] Phase 3: Treino gera versões, testes e documentação (3/3 plans)
- [x] Phase 10: Registo com proveniência, motor de treino e superfície HTTP — R10 backend (3/3 plans)
- [x] Phase 11: O learning loop no dashboard — R10 frontend (3/3 plans)

Detalhe completo: `.planning/milestones/v1.0-ROADMAP.md`

</details>

<details>
<summary>✅ v1.1 R11 Vaccine Engine (Phases 12-14) — SHIPPED 2026-10-29</summary>

- [x] Phase 12: Motor de vaccines (3/3 plans) — completed 2026-10-12
- [x] Phase 13: Store e API de leitura (3/3 plans) — completed 2026-10-12
- [x] Phase 14: Aba Vaccines, testes e documentação (4/4 plans) — completed 2026-10-29

Uma vaccine é só uma proposta: nunca aplicada no Wazuh, sem comandos executáveis, estado fixo `proposed`.

Detalhe completo: `.planning/milestones/v1.1-ROADMAP.md`

</details>

### 🚧 v1.2 R12 Vaccine Lab (Em curso)

**Milestone Goal:** Um analista aprova ou rejeita uma vaccine proposta, com autor, motivo e auditoria só de acréscimo; aprovar nunca aplica nada no Wazuh.

**Phase Numbering:** a numeração continua a do v1.1 (que acabou na Phase 14). Decimais (15.1, ...) são inserções urgentes.

- [ ] **Phase 15: Store de decisões** - Tabela `vaccine_decisions` só de acréscimo e máquina de estados pura, sem tocar em `vaccines`
- [ ] **Phase 16: API de decisão** - `POST /api/vaccines/{id}/decision`, estado e decisão no `GET`, filtro por estado, códigos de erro estáveis, nada é aplicado
- [ ] **Phase 17: Aba, testes e documentação** - Botões Aprovar/Rejeitar no detalhe, suite verde e docs a refletir o R12

## Phase Details

### Phase 15: Store de decisões

**Goal:** O backend sabe registar uma decisão sobre uma vaccine num registo de auditoria só de acréscimo, e deriva o estado atual sem nunca alterar a vaccine.
**Depends on:** v1.1 (store de vaccines com `superseded_by`)
**Requirements:** VLB-02, VLB-03
**Success Criteria** (what must be TRUE):
  1. Existe `vaccine_decisions` com triggers que recusam UPDATE e DELETE, e a tabela `vaccines` continua com `CHECK (state = 'proposed')` e os triggers do R11 intactos (provado por teste).
  2. Uma decisão guarda vaccine, `approved`/`rejected`, autor, instante UTC, motivo e estado anterior; rejeitar sem motivo é recusado.
  3. Decidir duas vezes a mesma vaccine, ou uma vaccine substituída, ou um id que não existe, falha com um código estável distinto, e nada é gravado.
  4. O estado derivado de uma vaccine é a última decisão, ou `proposed` quando não há nenhuma.

**Plans:** 3 plans

Plans:
**Wave 1**
- [ ] 15-01-PLAN.md — Checkpoint do DDL (one-way) + tracer: regra pura `vaccine_decision.py` -> `vaccine_decisions` -> `decide_vaccine` (BEGIN IMMEDIATE) -> leitura com estado derivado; validação completa da entrada com códigos estáveis (VLB-02, VLB-03)
**Wave 2**
- [ ] 15-02-PLAN.md — Decisão final: recusas sem gravar (`already_decided`, `vaccine_superseded`, `entry_not_found`, `reason_required`), aprovada e substituída continua aprovada, corrida com o gerador e decisões simultâneas (VLB-02, VLB-03)
**Wave 3**
- [ ] 15-03-PLAN.md — Filtro por estado derivado no store e provas no ficheiro: triggers/UNIQUE/CHECK/FK, `vaccines` do R11 intacta byte a byte, ficheiro antigo lido sem ser tocado, suite 83/83 (VLB-02, VLB-03)

### Phase 16: API de decisão

**Goal:** O analista decide por HTTP e lê o resultado, com as garantias de segurança do R11 mantidas.
**Depends on:** Phase 15
**Requirements:** VLB-01, VLB-04, VLB-05
**Success Criteria** (what must be TRUE):
  1. `POST /api/vaccines/{id}/decision` exige API key (sem ela, 401), valida o corpo de contrato fechado e devolve 404/409/422/503 com códigos estáveis; o `GET` continua sem efeitos secundários.
  2. `GET /api/vaccines[/{id}]` traz `state` e `decision`, filtra por estado, e sem amostra devolve "Sem dados", nunca 0.
  3. Nenhuma rota nem módulo aplica uma vaccine no Wazuh ou executa comandos (varrimento por teste), e o texto das respostas diz que "aprovada" não é "aplicada".
  4. `allow_methods` do CORS e `test_cors.py` cobrem o método novo.

### Phase 17: Aba, testes e documentação

**Goal:** O analista decide no dashboard e o marco fecha com a suite completa e a documentação.
**Depends on:** Phase 16
**Requirements:** VLB-06, VLB-07
**Success Criteria** (what must be TRUE):
  1. O detalhe da vaccine tem Aprovar e Rejeitar (motivo obrigatório ao rejeitar) via `data-action`, sem handlers inline, e o estado e a decisão aparecem na tabela e no detalhe.
  2. Os erros aparecem pela frase do código estável; um 409 (já decidida) atualiza a vista em vez de a deixar a mentir.
  3. `run_all_tests.py` termina com código 0 numa execução completa, sem Wazuh, incluindo os testes novos.
  4. `DATA_MODEL.md`, `API.md`, `ROADMAP_STATUS.md` (R12 ✅), `README.md` e `CLAUDE.md` descrevem o R12 com contagens medidas.

## Progress

| Milestone | Phases | Plans | Status | Shipped |
|-----------|--------|-------|--------|---------|
| v1.0 ML Registry & Learning Loop | 1-3, 10-11 | 17/17 | Complete | 2026-10-11 |
| v1.1 R11 Vaccine Engine | 12-14 | 10/10 | Complete | 2026-10-29 |
| v1.2 R12 Vaccine Lab | 15-17 | 0/3 | Em curso | — |
