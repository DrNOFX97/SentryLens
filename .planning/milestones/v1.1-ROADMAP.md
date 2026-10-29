# Roadmap: SentryLens

## Milestones

- ✅ **v1.0 ML Registry & Learning Loop** — Phases 1-3, 10-11 (R9 + R10, shipped 2026-10-11)
- 🚧 **v1.1 R11 Vaccine Engine** — Phases 12-14 (em curso)

## Overview

O v1.1 abre o ciclo "ataque → deteção → incidente → vaccine" do Roadmap v2. Hoje o
Red vs Blue já diz, por ataque lançado, se foi `detected`, `partial`, `not_detected`
ou `unknown`, mas um ataque que escapou fica só como um número na métrica: ninguém
propõe o que faltava detetar. O R11 fecha essa lacuna **só de leitura** — um ataque
não detetado ou só parcialmente detetado passa a gerar uma *vaccine*, uma regra de
deteção proposta, rastreável até ao ataque que a originou, guardada e visível, mas
nunca aplicada no Wazuh e sem comandos executáveis.

A jornada tem três fatias verticais, da lógica para o ecrã. Primeiro o motor puro,
que decide que ataques geram vaccine, que regra se propõe e de onde vem, sem tocar em
disco nem em HTTP. Depois o store e a API de leitura, onde as vaccines persistem com
estado fixo `proposed` e passam a ser consultáveis com API key. Por fim a aba
Vaccines no dashboard e o fecho do marco com a suite completa e a documentação.

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

### 🚧 v1.1 R11 Vaccine Engine (Em curso)

**Milestone Goal:** Um ataque não detetado ou só parcialmente detetado passa a gerar uma *vaccine*: uma regra de deteção proposta, rastreável até ao ataque que a originou, guardada e visível mas nunca aplicada.

**Phase Numbering:**
- Integer phases (12, 13, 14): Planned milestone work (a numeração continua a do v1.0, que acabou na Phase 11)
- Decimal phases (12.1, 12.2): Urgent insertions (marked with INSERTED)

- [x] **Phase 12: Motor de vaccines** - Motor puro: que ataques geram vaccine, regra proposta, origem rastreável, id determinístico e "Sem dados" honesto (completed 2026-10-12)
- [x] **Phase 13: Store e API de leitura** - Vaccines persistidas com estado fixo `proposed`, `GET /api/vaccines[/{id}]` com API key e códigos de erro estáveis (completed 2026-10-12)
- [x] **Phase 14: Aba Vaccines, testes e documentação** - `vaccines.js` com filtros e detalhe, suite completa verde e docs a refletir o R11 (completed 2026-10-29)

## Phase Details

### Phase 12: Motor de vaccines

**Goal:** O backend sabe propor, a partir dos gaps do Red vs Blue, uma regra de deteção rastreável até ao ataque que a originou — e recusa propor quando não há amostra.
**Mode:** mvp
**Depends on:** Nothing (primeira fase do v1.1; assenta no Red vs Blue, no Attack Registry e na Attack Library já entregues)
**Requirements:** VAC-01, VAC-02, VAC-03, VAC-04
**Success Criteria** (what must be TRUE):
  1. Dado um relatório Red vs Blue com ataques de cada veredito, o motor devolve exatamente um candidato por ataque `not_detected` ou `partial` e nenhum por ataque `detected` ou `unknown` (incluindo o `unknown` de alertas truncados, que nunca vira "não detetado").
  2. Cada vaccine traz a regra proposta (`event_ids`, janela, condição e sensor esperado) derivada de `attack_library`, `attack_scenarios` e `event_catalog`, e nenhum campo de nenhuma vaccine contém um comando executável (chaves fechadas, verificado varrendo todos os valores).
  3. Cada vaccine liga à origem — `attack_id`, cenário, técnica MITRE, incidentes e evidência por referência (nunca cópia de payload) — e tem um id determinístico: correr o motor duas vezes sobre os mesmos ataques dá os mesmos ids e nenhum duplicado.
  4. Sem amostra (nenhum ataque lançado) ou com uma fonte indisponível, o motor devolve "Sem dados" ou um código estável; nunca fabrica uma vaccine para encher a lista.

**Plans:** 3/3 plans complete

Plans:
**Wave 1**
- [x] 12-01-PLAN.md — Tracer: registo real -> build_vaccine_candidates com proposals[], origem e ids golden; sensores em falta via attack_library; saltos D-04, matriz de vereditos e determinismo (VAC-01, VAC-02, VAC-03)

**Wave 2** *(blocked on Wave 1 completion)*
- [x] 12-02-PLAN.md — validate_vaccine (contrato fechado, nenhum comando) e três estados honestos no_data/source_unavailable/tudo unknown; suite completa verde (VAC-02, VAC-04)

**Wave 3** *(blocked on Wave 2 completion)*
- [x] 12-03-PLAN.md — Escritor do attack log grava id (max+1, fail-closed, sem backfill); entrada do escritor real -> registo -> motor -> vaccine validada (VAC-03)

**UI hint**: no — módulo puro sem I/O; a superfície visível chega na Phase 14.

> **Verificação:** o motor é uma função pura, por isso o que se observa é o teste standalone (`test_vaccine_engine.py`, sem Wazuh) a correr sobre fixtures de relatórios Red vs Blue; não há rota nem ecrã nesta fase.

### Phase 13: Store e API de leitura

**Goal:** O analista consulta por HTTP as vaccines propostas, que sobrevivem a um reinício do backend sem duplicados e nunca mudam de estado.
**Mode:** mvp
**Depends on:** Phase 12
**Requirements:** VAC-05, VAC-06
**Success Criteria** (what must be TRUE):
  1. As vaccines persistem num store escrito só pelo backend, todas com estado `proposed`; depois de reiniciar o backend a mesma lista volta, sem perdas, e reprocessar os mesmos ataques não acrescenta linhas.
  2. `GET /api/vaccines` (com API key) devolve a lista — vazia com 200 quando não há amostra — e sem API key devolve 401; `GET /api/vaccines/{id}` devolve o detalhe (regra e origem) e um id inexistente dá 404 com o código estável `entry_not_found`.
  3. Não existe rota de escrita em `/api/vaccines`: um POST/PUT/PATCH/DELETE a qualquer das duas rotas não altera nada, e o estado só pode ser `proposed`.
  4. Falhas de leitura (Indexer indisponível, store ilegível) chegam como códigos estáveis, nunca como texto de exceção, traceback ou caminho de ficheiro; cada rota tem a API key aplicada individualmente.

**Plans:** 3/3 plans complete

Plans:
**Wave 1**
- [x] 13-01-PLAN.md — Tracer: ciclo do backend (attack log -> registo -> motor -> validate_vaccine) grava vaccines assentes no SQLite (`proposed`, sem duplicados, sobrevive a reinício) e GET /api/vaccines[/{id}] com API key; fix de list_incidents por nome; store endurecido com superseded_by (VAC-05, VAC-06)

**Wave 2** *(blocked on Wave 1 completion)*
- [x] 13-02-PLAN.md — Loop de background no arranque com cadência configurável, estado do gerador com códigos estáveis em GET /api/vaccines (`generator`), matriz de falhas, truncagem e janela/estabilização (VAC-05, VAC-06)

**Wave 3** *(blocked on Wave 2 completion)*
- [x] 13-03-PLAN.md — Filtros attack_id/technique/include_superseded por HTTP e garantias negativas: sem rota de escrita (405), API key por rota, 503 store_unavailable sem fuga (VAC-05, VAC-06)

> **Decisão para o discuss-phase:** quem escreve no store e quando — `GET` tem de continuar sem efeitos secundários visíveis, por isso a vaccine tem de ser gerada e persistida fora do pedido (por exemplo reaproveitando o ciclo de ingestão de incidentes/alertas) ou por um passo explícito do backend. Fica por decidir antes de planear; não está nos requisitos.

### Phase 14: Aba Vaccines, testes e documentação

**Goal:** O analista vê as vaccines na aba Vaccines do dashboard, com o que cada uma propõe e de onde vem, e o marco R11 fica fechado com testes completos e documentação atualizada.
**Mode:** mvp
**Depends on:** Phase 13
**Requirements:** VAC-07, VAC-08
**Success Criteria** (what must be TRUE):
  1. O item "Vaccines" da sidebar abre uma aba real (`vaccines.js` servido pelo `serve_frontend.py`, sem editar `app.js`) que lista as vaccines com filtros e abre um detalhe com a regra proposta e a origem (ataque, cenário, técnica MITRE, incidentes); todo o texto dinâmico passa por `escapeHtml`.
  2. Sem amostra a aba mostra "Sem dados"; um 401/404/502/503 desenha-se como erro com a frase do código, nunca como "Sem dados" nem como lista vazia.
  3. `python run_all_tests.py` termina verde sem o Wazuh ligado, com testes standalone novos para motor, store e rotas, incluindo as garantias negativas (sem rota de escrita, sem comando executável, sem texto de exceção, sem duplicados após reprocessar ou reiniciar).
  4. `docs/DATA_MODEL.md` define a entidade Vaccine, `docs/ROADMAP_STATUS.md` marca o R11 como concluído (✅) e `README.md` e `CLAUDE.md` descrevem o motor, o store e a rota.

**Plans:** 4/4 plans complete

Plans:
**Wave 1**
- [x] 14-01-PLAN.md — Tracer: Candidates abre a aba Vaccines (vaccines.js servido pelo serve_frontend.py, sem editar app.js) que lista GET /api/vaccines lendo só campos da resposta real; guardas do contrato estático (escape, erros só por código, "Sem dados" honesto, sem polling, app.js intacto) (VAC-07, VAC-08)

**Wave 2** *(blocked on Wave 1 completion)*
- [x] 14-02-PLAN.md — Tracer: filtros (ataque, técnica, substituídas) e Atualizar enviados ao servidor; linha de estado do gerador, badges de veredito e substituídas esbatidas (VAC-07, VAC-08)

**Wave 3** *(blocked on Wave 2 completion)*
- [x] 14-03-PLAN.md — Tracer: clicar numa vaccine abre o detalhe com Origem, Propostas e o aviso "Proposta — não aplicada no Wazuh"; Cadeia substituída por / substitui, sem links (VAC-07, VAC-08)

**Wave 4** *(blocked on Wave 3 completion)*
- [x] 14-04-PLAN.md — Tracer: entidade Vaccine e rotas documentadas contra o código (DATA_MODEL, API); R11 ✅ no Roadmap v2, README e CLAUDE.md atualizados com as contagens reais; suite completa verde sem o Wazuh numa única execução, flake da suite paralela registado como dívida (VAC-08)

**UI hint**: yes

> **Testes por fase:** os testes do âmbito de cada fase escrevem-se com o respetivo código (como no v1.0); esta fase fecha a cobertura completa da suite e a documentação, e é por isso que VAC-08 mapeia aqui.

## Progress

**Execution Order:**
Phases execute in numeric order: 12 → 13 → 14

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 12. Motor de vaccines | v1.1 | 3/3 | Complete    | 2026-10-12 |
| 13. Store e API de leitura | v1.1 | 3/3 | Complete    | 2026-10-12 |
| 14. Aba Vaccines, testes e documentação | v1.1 | 4/4 | Complete    | 2026-10-29 |
