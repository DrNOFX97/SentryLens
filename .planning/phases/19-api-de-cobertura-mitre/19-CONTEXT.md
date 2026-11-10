# Phase 19: API de cobertura MITRE - Context

**Gathered:** 2026-11-10
**Status:** Ready for planning

<domain>
## Phase Boundary

`GET /api/mitre/coverage`: rota só de leitura, com API key por rota, que responde por técnica e por tática a "quantos ataques foram lançados, quantos detetados, quantos alertas vistos", com a origem de cada número e sem nunca transformar uma fonte em baixo em zero. Consome o resolvedor, a tabela e o helper `parent_of` da Fase 18 (`mitre_catalog.py`, `mitre_techniques.yaml`) e o `attack_registry`.

Fora desta fase: a aba/matriz no dashboard (Fase 20), testes de frontend e docs (Fase 20, TST-01/DOC-01), Caldera, auth, escrita de qualquer tipo.

Requisitos: API-01, API-02.

</domain>

<decisions>
## Implementation Decisions

### Já decididos (Fase 18 e marco — não reabrir)
- **D-00a:** Técnica do alerta: `rule.mitre.id` primeiro (origem `wazuh`), `technique_id` do catálogo como fallback (origem `catalog`), lista vazia sem nenhum (Fase 18, D-00a). A rota usa `mitre_catalog.resolve_alert_techniques`, não reimplementa.
- **D-00b:** Sub-técnica herda a tática do pai (Fase 18, D-04); "detetado" não é cruzado por pai (ver D-02 emendado); a tática vem sempre da tabela via `tactics_for` (D-07); `attack_log.jsonl` nunca é reescrito (D-08).
- **D-00c:** Sem dados é `null`/`Sem dados`, nunca `0`. Rota só `GET`, `dependencies=_REQUIRE_API_KEY` na própria rota. Sem PostgreSQL, sem tabela nova.

### Que técnicas aparecem em `techniques[]`
- **D-01:** `techniques[]` traz **todas as técnicas da tabela** (com contagens reais, incluindo zero ataques e zero alertas) **mais** qualquer técnica vista num alerta ou ataque que não esteja na tabela. A Fase 20 desenha a matriz (e o estado "não executada") só a partir desta resposta, sem ler a tabela por outra via.
- **D-02:** Cada id exato tem **linha própria** (`T1110` e `T1110.003` são duas linhas, com contagens exatas do que foi visto/lançado nesse id). "Detetado" vem só do veredito `detected` do `attack_registry` (D-04), sem cruzamento extra por técnica; `parent_of` serve apenas para herdar a tática e para o campo `parent` da linha. As contagens por linha não se somam entre pai e filhas. *(Emendado em 2026-11-10 por decisão do utilizador: a versão anterior fazia o pai decidir "detetado", em tensão com D-04.)*
- **D-03:** Técnica sem tática (sem entrada própria nem pai na tabela) **não** fica em `techniques[]`: vai para `unmapped[]` com as mesmas contagens, para a secção "sem tática" nunca descartar nada (API-02).

### Definição de "detetado" e da taxa
- **D-04:** "Detetado" = veredito `detected` do `attack_registry` (todas as fontes esperadas viram o ataque). `partial` conta como lançado e **não** detetado, mas a resposta traz `partial` como contagem à parte para não o esconder. Igual à leitura do R8.
- **D-05:** `unknown` (Indexer/modelo em baixo, alertas truncados) fica **fora do denominador**: `taxa = detected / (detected + partial + not_detected)`; `unknown` é contado à parte. Se o denominador for 0 (sem ataques, ou só `unknown`), a taxa é `null`, nunca 0.
- **D-06:** Por técnica, cada linha traz `attacks: {launched, detected, partial, not_detected, unknown}` e `rate`. `launched` conta todos os ataques lançados dessa técnica (inclui `unknown`).

### Fontes, janela e truncagem
- **D-07:** Duas fontes **isoladas**, cada uma com `available` e, se em baixo, `reason: "source_unavailable"`: **alertas** (Indexer direto, `resolve_alert_techniques` por alerta, `exclude_infra_noise=True` como o registry) e **ataques** (`attack_registry` via `_build_attack_registry`). Indexer em baixo → `alerts` indisponível mas os ataques continuam (com veredito `unknown`); log/registo de ataques em baixo → `attacks` indisponível mas os alertas continuam. Nunca 500 por uma fonte em baixo. Nenhum texto de exceção na resposta, só códigos estáveis (detalhe só no log).
- **D-08:** Parâmetro `hours`: omissão **168**, máximo **720** (mesma janela máxima de `/api/attacks`); teto de alertas `ATTACK_ALERTS_SIZE` (8000). `alerts_truncated: true` quando o Indexer devolve ≥ 8000. Se a fonte de alertas está em baixo, as contagens de alertas são `null` (nunca 0).
- **D-09:** Se o planner conseguir reutilizar os alertas já buscados por `_build_attack_registry` em vez de um segundo pedido ao Indexer sem acoplar as duas fontes (D-07), pode; a isolamento das fontes tem prioridade sobre poupar um pedido.

### Tática multi-valor e envelope
- **D-10:** Uma técnica com várias táticas conta em **todas** elas (fiel à matriz ATT&CK, coerente com D-05 da Fase 18 "nada de tática principal"). A soma por tática pode exceder o total de ataques; por isso a resposta traz o **total único de ataques** à parte e a Fase 20 deve dizê-lo na UI.
- **D-11:** Envelope: `sources` = `{alerts, attacks}` (cada um `available`, `reason`); `alerts_truncated`; `tactics[]` (as 14 táticas Enterprise na ordem ATT&CK, cada uma com `attacks: {launched, detected, ...}`, `rate` = % ou `null`); `techniques[]` (cada uma com `id`, `name`, `tactics`, `alerts: {total, wazuh, catalog}`, `attacks`, `rate`); `unmapped[]` (mesma forma que `techniques[]`, sem tática); totais únicos. Nomes exatos dos campos ficam ao planner, desde que cubram o que o roadmap exige (SC 1–4).
- **D-12:** `rate` por tática é uma percentagem (ou `null`), nunca 0 sem ataques lançados com veredito conhecido. — **Reversibility:** costly — a Fase 20 e `docs/API.md` dependem dos nomes e do tipo dos campos; mudá-los depois obriga a refazer o frontend e os testes de contrato.

### Claude's Discretion
- Nomes exatos dos campos e módulo de cálculo (ex.: `mitre_coverage.py` puro, `build_mitre_coverage_report(...)`) — a rota é fina, a lógica é pura e testável com mocks, como `soc_metrics.py`.
- Se os totais únicos e o `rate` global saem no topo ou em `totals`.
- Ordenação das linhas de `techniques[]` (por id é o mais previsível).
- Validação do parâmetro `hours` e códigos de erro estáveis (seguir `/api/attacks`).

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Âmbito e requisitos
- `.planning/REQUIREMENTS.md` — API-01, API-02 (e UI-01/02 da Fase 20, que consome esta resposta)
- `.planning/ROADMAP.md` §Phase 19 — critérios de sucesso
- `.planning/PROJECT.md` — Constraints e Key Decisions do R16
- `.planning/phases/18-t-cnica-e-t-tica-por-alerta/18-CONTEXT.md` — decisões D-00a a D-11 da Fase 18 (resolvedor, tabela, `parent_of`, sub-técnicas)

### Código a seguir como padrão
- `scripts/mitre_catalog.py` — `resolve_alert_techniques`, `tactics_for`, `parent_of`, `load_mitre_techniques`
- `scripts/mitre_techniques.yaml` — tabela técnica→tática (17 técnicas, ATT&CK v18.1)
- `scripts/attack_registry.py` — `build_attack_registry` (veredito `detected`/`partial`/`not_detected`/`unknown`, campo `mitre_technique`, `mitre_tactic`)
- `scripts/main.py` `_build_attack_registry` (~linha 1744), `ATTACK_ALERTS_SIZE`, `ATTACK_MAX_HOURS`, `/api/attacks` (~1799) — padrão de fontes isoladas, `alerts_truncated`, códigos de erro estáveis
- `scripts/main.py` `/api/metrics` (~1414) e `scripts/soc_metrics.py` — padrão de rota fina + `build_*_report` pura, `source_unavailable`
- `scripts/main.py` `/api/detections` (~1233) — padrão de fontes independentes que nunca derrubam a rota
- `scripts/wazuh_client.py` `get_recent_alerts(..., exclude_infra_noise)` — fonte de alertas
- `CLAUDE.md` — testes standalone (sem pytest), `SENTRYLENS_API_KEY` antes de `import main`, `allow_methods` do CORS só muda se houver método novo (aqui só GET)

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `mitre_catalog.resolve_alert_techniques(raw)`: devolve `[{id, source, tactics}]` por alerta cru — fonte das contagens `wazuh`/`catalog`.
- `mitre_catalog.parent_of` / `tactics_for`: cruzamento por pai e tática da tabela.
- `attack_registry.build_attack_registry` via `main._build_attack_registry(attack_log, hours)`: ataques com `mitre_technique`, `actual.verdict`.
- `main._read_attack_log()`: leitura do log com tratamento de erro.

### Established Patterns
- Módulo puro `build_*_report(...)` + rota fina em `main.py` + teste standalone com `AsyncMock` do Indexer.
- Fonte em baixo → `available: false`/`reason: "source_unavailable"`, nunca 500 nem texto de exceção.
- `alerts_truncated = len(raw_alerts) >= tamanho` (nunca esconder que o teto foi atingido).

### Integration Points
- Nova rota `GET /api/mitre/coverage` em `main.py` com `dependencies=_REQUIRE_API_KEY`.
- A Fase 20 (`mitre.js` + helpers `sl*`) lê esta resposta sem a recalcular.
- `_build_attack_registry` devolve `incidents_available` e `correlation.error_code`; mapear para os `reason` estáveis desta rota.

</code_context>

<specifics>
## Specific Ideas

- Janela por omissão de 168 h porque os ataques do laboratório são esporádicos e 24 h costuma vir vazio.
- A tabela só tem 17 técnicas hoje; é de propósito que a matriz da Fase 20 seja pequena (o roadmap exclui a matriz Enterprise completa).

</specifics>

<deferred>
## Deferred Ideas

- Cache da resposta (a rota lê Indexer e log a cada pedido, como `/api/attacks`) — só se se revelar lenta.
- Atribuição de técnica a ataques por `technique` do log vs. cenário já vem do registry (`technique_source`); nenhuma lógica nova aqui.
- Caldera como fonte de "ataques lançados" — SIM-01, fora do v1.3.

</deferred>

---

*Phase: 19-api-de-cobertura-mitre*
*Context gathered: 2026-11-10*
