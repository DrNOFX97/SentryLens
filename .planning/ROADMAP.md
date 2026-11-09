# Roadmap: SentryLens

## Milestones

- ✅ **v1.0 ML Registry & Learning Loop** — Phases 1-3, 10-11 (R9 + R10, shipped 2026-10-11)
- ✅ **v1.1 R11 Vaccine Engine** — Phases 12-14 (shipped 2026-10-29)
- ✅ **v1.2 R12 Vaccine Lab** — Phases 15-17 (shipped 2026-11-04)
- 🚧 **v1.3 R16 MITRE ATT&CK** — Phases 18-20 (em curso)

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

<details>
<summary>✅ v1.2 R12 Vaccine Lab (Phases 15-17) — SHIPPED 2026-11-04</summary>

- [x] Phase 15: Store de decisões (3/3 plans) — completed 2026-10-29
- [x] Phase 16: API de decisão (3/3 plans) — completed 2026-10-30
- [x] Phase 17: Aba, testes e documentação (6/6 plans) — completed 2026-11-04

Um analista aprova ou rejeita uma vaccine com autor, motivo e auditoria só de acréscimo; aprovar nunca aplica nada no Wazuh (isso é o R21).

Detalhe completo: `.planning/milestones/v1.2-ROADMAP.md`

</details>

### 🚧 v1.3 R16 MITRE ATT&CK (Em curso)

**Milestone Goal:** Cada alerta passa a ter técnica e tática MITRE com origem conhecida (`wazuh` ou `catalog`), e o dashboard mostra que técnicas foram lançadas, vistas e detetadas, sem nunca inventar um mapeamento nem mostrar 0 sem amostra.

**Phase Numbering:** a numeração continua a do v1.2 (que acabou na Phase 17). Decimais (18.1, ...) são inserções urgentes.

**Testes:** cada fase traz os seus próprios testes standalone (padrão do projeto, sem pytest, sem Wazuh); o TST-01 fecha na Phase 20 com a suite completa verde.

- [ ] **Phase 18: Técnica e tática por alerta** - `technique_id` no catálogo, tabela técnica→tática versionada com validação fail-fast, resolvedor puro com origem e campos aditivos no `DetectionEvent`
- [ ] **Phase 19: API de cobertura MITRE** - `GET /api/mitre/coverage` só de leitura, por técnica e por tática, com fontes isoladas, truncagem e secção "sem tática"
- [ ] **Phase 20: Matriz MITRE, testes e documentação** - Aba com a matriz táticas × técnicas em 3 estados e detalhe por célula, suite verde e docs a refletir o R16

## Phase Details

### Phase 18: Técnica e tática por alerta

**Goal:** O backend sabe dizer, para qualquer alerta cru, que técnicas MITRE lhe correspondem, de onde vem cada uma e a que tática pertence — sem inventar técnicas e sem mudar o comportamento de quem já usa o catálogo.
**Depends on:** Nada (primeira fase do v1.3; parte de `event_catalog.py`, `attack_scenarios.py` e `detection_event.py` existentes)
**Requirements:** MITRE-01, MITRE-02, MITRE-03, MITRE-04
**Success Criteria** (what must be TRUE):
  1. As entradas de `CRITICAL_EVENTS` com técnica clara têm `technique_id` (ex.: 4625→T1110, 4698→T1053.005), as restantes ficam vazias, e `classify_alert()` e o `log_analyzer.py` (Fase 1) devolvem exatamente o mesmo que antes para os mesmos eventos (provado por teste).
  2. Existe uma tabela técnica→tática versionada no repo que cobre as técnicas do catálogo, dos cenários de `attack_scenarios.py` e as vistas em `rule.mitre` no snapshot do R9; um id fora do formato `Tnnnn`/`Tnnnn.nnn` ou uma tática fora das táticas Enterprise impede o backend de arrancar, como o `attack_library.yaml`.
  3. Para um alerta com `rule.mitre.id`, o resolvedor puro devolve essas técnicas com origem `wazuh`; sem `rule.mitre`, devolve a do catálogo pelo Event ID com origem `catalog`; sem nenhuma das duas, devolve lista vazia — nunca uma técnica inventada.
  4. `GET /api/detections` passa a trazer, nas deteções de regra, `technique` (primeira técnica resolvida ou `null`), `techniques` e `technique_source`; todos os campos que já existiam mantêm nome, tipo e significado (provado contra o contrato anterior).

**Plans:** 3/3 plans executed

Plans:
**Wave 1**
- [x] 18-01-PLAN.md — Tabela técnica→tática versionada (`mitre_techniques.yaml`, ATT&CK v18.1) + `mitre_catalog.py` (carregador fail-fast em cache, `tactics_for`, `parent_of`) + chamada no arranque de `main.py` + coerência dos cenários (T1053 → Execution) (MITRE-02; onda 1)
- [x] 18-02-PLAN.md — `technique_id` nas 8 entradas inequívocas de `CRITICAL_EVENTS`, extração partilhada `wazuh_win_fields`/`catalog_technique_id`, provas de que `classify_alert()` e o `log_analyzer.py` não mudam (MITRE-01; onda 1, em paralelo)

**Wave 2** *(blocked on Wave 1 completion)*
- [x] 18-03-PLAN.md — Resolvedor `resolve_alert_techniques` (wazuh > catálogo > vazio, endurecido) e campos aditivos `techniques`/`technique_source` no `DetectionEvent` e em `GET /api/detections`, com prova do contrato anterior (MITRE-03, MITRE-04; onda 2)

### Phase 19: API de cobertura MITRE

**Goal:** O analista consegue perguntar por HTTP, por técnica e por tática, quantos ataques foram lançados, quantos foram detetados e quantos alertas foram vistos — com a origem de cada número e sem nunca transformar uma fonte em baixo em zero.
**Depends on:** Phase 18
**Requirements:** API-01, API-02
**Success Criteria** (what must be TRUE):
  1. `GET /api/mitre/coverage` exige API key por rota (401 sem ela), não tem efeitos secundários e devolve, por técnica, as táticas, os alertas vistos com contagem por origem (`wazuh`/`catalog`), os ataques lançados do attack_registry, os detetados e a taxa.
  2. Por tática, a resposta traz a % de ataques detetados, e `null` quando a tática não tem ataques lançados — nunca 0.
  3. Com o Indexer ou o registo de ataques indisponível, a rota responde com `source_unavailable` para essa fonte e o resto dos dados, nunca 500; quando o Indexer atinge o teto de alertas, `alerts_truncated` vem a `true`.
  4. Uma técnica vista num alerta sem tática conhecida na tabela aparece numa secção "sem tática" com as suas contagens, em vez de ser descartada.

**Plans:** TBD

### Phase 20: Matriz MITRE, testes e documentação

**Goal:** O analista vê no dashboard que técnicas foram lançadas, vistas e detetadas, e o marco fecha com a suite completa verde e a documentação a descrever o R16.
**Depends on:** Phase 19
**Requirements:** UI-01, UI-02, TST-01, DOC-01
**Success Criteria** (what must be TRUE):
  1. O grupo MITRE ATT&CK deixa de estar "Planeado (R16)" e passa a uma aba real com a matriz táticas × técnicas, em que cada célula mostra um de 3 estados — não executada, executada e detetada, executada e não detetada — e a contagem de alertas vistos.
  2. O topo da aba mostra a % de deteção por tática, com `—` quando não há amostra; clicar numa célula, ou Enter/Espaço com o foco nela, abre o detalhe com os alertas por origem e os ataques com o seu veredito.
  3. A aba não tem handlers inline (`data-action` + listener delegado), a lógica de decisão vive em helpers `sl*` puros de `ui_helpers.js` testados em `node:vm`, o ficheiro novo está na whitelist do `serve_frontend.py`, e os contratos estáticos do frontend (sem `innerHTML` cru, sem cores literais, contraste, ícones acessíveis) continuam verdes.
  4. `python run_all_tests.py` termina com código 0 numa execução completa, sem Wazuh, incluindo os testes novos de resolução de técnicas, validação da tabela, rota (fontes em baixo e truncagem) e contrato estático do frontend/`ui_helpers`.
  5. `README.md`, `CLAUDE.md`, `docs/API.md` (rota nova), `docs/DATA_MODEL.md`, `docs/ROADMAP_STATUS.md` (R16 ✅) e a página Roadmap v2 do Notion descrevem o R16 entregue, com contagens medidas.

**Plans:** TBD
**UI hint**: yes

## Progress

| Milestone | Phases | Plans | Status | Shipped |
|-----------|--------|-------|--------|---------|
| v1.0 ML Registry & Learning Loop | 1-3, 10-11 | 17/17 | Complete | 2026-10-11 |
| v1.1 R11 Vaccine Engine | 12-14 | 10/10 | Complete | 2026-10-29 |
| v1.2 R12 Vaccine Lab | 15-17 | 12/12 | Complete | 2026-11-04 |
| v1.3 R16 MITRE ATT&CK | 18-20 | 0/? | Em curso | — |

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 18. Técnica e tática por alerta | 3/3 | Planned | - |
| 19. API de cobertura MITRE | 0/? | Not started | - |
| 20. Matriz MITRE, testes e documentação | 0/? | Not started | - |
