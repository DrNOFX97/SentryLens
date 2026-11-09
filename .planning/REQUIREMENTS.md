# Requirements: SentryLens — v1.3 R16 MITRE ATT&CK

**Defined:** 2026-11-09
**Core Value:** Medir de forma honesta, com dados reais, quão bem o laboratório deteta e responde a ataques — nunca apresentar como real um valor inventado ou sem amostra.

**Origem:** Fase 10 de `docs/plans/2026-11-09-arquitetura-fases-10-19.md`, remapeada para o R16 do Roadmap v2. Evidência: `scripts/snapshots/raw_events_r9_ciclo1.json` tem 664/1000 alertas com `rule.mitre` (listas `id[]` e `tactic[]` sem emparelhamento); o R8 já mede cobertura por `mitre_technique` dos ataques (`soc_metrics.py`), mas nenhum alerta tem técnica própria.

## v1 Requirements

### Técnica por alerta

- [x] **MITRE-01**: Cada entrada de `CRITICAL_EVENTS` em `scripts/event_catalog.py` pode ter `technique_id`, vazio quando não há técnica clara (ex.: 4625→T1110, 4698→T1053.005); `classify_alert()` e o `log_analyzer.py` (Fase 1) continuam a funcionar sem alterações de comportamento.
- [x] **MITRE-02**: Uma tabela técnica→tática versionada (ficheiro de dados no repo) cobre as técnicas do catálogo, dos cenários de `attack_scenarios.py` e as já vistas em `rule.mitre`; é validada no arranque de forma fail-fast (formato `Tnnnn` / `Tnnnn.nnn`, tática pertencente às táticas Enterprise), como o `attack_library.yaml`.
- [ ] **MITRE-03**: Uma função pura devolve as técnicas de um alerta cru — `rule.mitre.id` primeiro, catálogo por Event ID como fallback, vazio quando nenhum existe — cada uma com origem `wazuh` | `catalog`; nunca inventa uma técnica.
- [ ] **MITRE-04**: O `DetectionEvent` de regra passa a ter `technique` (primeira técnica resolvida, ou `None`) e ganha de forma aditiva `techniques` (lista) e `technique_source`; nenhum campo existente de `GET /api/detections` muda de nome, tipo ou significado.

### API

- [ ] **API-01**: `GET /api/mitre/coverage` (API key por rota, só leitura) devolve por técnica: táticas, alertas vistos (com contagem por origem), ataques lançados (attack_registry), detetados e taxa; e por tática a % de ataques detetados, `null` sem ataques.
- [ ] **API-02**: Fontes isoladas na rota (`source_unavailable`, nunca 500 por uma fonte em baixo); `alerts_truncated` quando o Indexer atinge o teto; técnicas sem tática conhecida aparecem numa secção "sem tática" em vez de serem descartadas.

### Dashboard

- [ ] **UI-01**: O item planeado R16 da sidebar (grupo MITRE ATT&CK) passa a uma aba real com a matriz táticas × técnicas em 3 estados — não executada, executada e detetada, executada e não detetada — mais a contagem de alertas vistos por célula.
- [ ] **UI-02**: A % por tática aparece no topo (`—` sem amostra); uma célula abre, por clique ou teclado, o detalhe com os alertas por origem e os ataques com veredito; sem handlers inline (`data-action` + listener delegado) e com a lógica de decisão em helpers `sl*` puros em `ui_helpers.js`.

### Testes e documentação

- [ ] **TST-01**: Testes standalone (padrão do projeto, sem pytest) cobrem a resolução de técnicas, a validação da tabela, a rota (incluindo fontes em baixo e truncagem) e o contrato estático do frontend/`ui_helpers`; `python run_all_tests.py` termina verde.
- [ ] **DOC-01**: `README.md`, `CLAUDE.md`, `docs/API.md`, `docs/DATA_MODEL.md`, `docs/ROADMAP_STATUS.md` e a página Roadmap v2 do Notion refletem o R16 entregue.

## v2 Requirements

Deferred to future release. Tracked but not in current roadmap.

### Simulação e incidentes

- **SIM-01**: Integrar o Caldera (ler operações pela API, `caldera_runs`, detetada = alerta com a técnica no host dentro de N minutos) — requer Caldera instalado no lab; candidato a R13/R15.
- **INC-01**: Subir um nível a severidade de um incidente quando tem técnicas de duas ou mais táticas (sinal de cadeia de ataque).
- **INC-02**: Scan de reconhecimento (Nikto) ao mesmo host antes do primeiro alerta entra como primeiro evento da timeline do incidente.

## Out of Scope

| Feature | Reason |
|---------|--------|
| PostgreSQL | Estado próprio fica em SQLite/JSONL (Roadmap v2); stores R3/R11/R12 dependem de CHECK/triggers SQLite |
| Login, perfis, JWT, CRUD de utilizadores | Muda o contrato da API (hoje API key por rota); só se pedido explicitamente |
| Casos (`cases`, `case_notes`) e `/api/metrics/soc` | Duplicam o R3 (estados, notas append-only, tiers) e o R8 (MTTD/MTTR) |
| Tabela `mitre_techniques` em base de dados | Dados estáticos de referência ficam num ficheiro versionado, como `attack_library.yaml` |
| Matriz MITRE completa (todas as técnicas Enterprise) | Só o subconjunto relevante ao lab; o resto não teria amostra |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| MITRE-01 | Phase 18 | Complete |
| MITRE-02 | Phase 18 | Complete |
| MITRE-03 | Phase 18 | Pending |
| MITRE-04 | Phase 18 | Pending |
| API-01 | Phase 19 | Pending |
| API-02 | Phase 19 | Pending |
| UI-01 | Phase 20 | Pending |
| UI-02 | Phase 20 | Pending |
| TST-01 | Phase 20 | Pending |
| DOC-01 | Phase 20 | Pending |

**Coverage:**
- v1 requirements: 10 total
- Mapped to phases: 10 (Phase 18: 4, Phase 19: 2, Phase 20: 4)
- Unmapped: 0 ✓

---
*Requirements defined: 2026-11-09*
*Last updated: 2026-11-09 after roadmap creation (Phases 18-20)*
