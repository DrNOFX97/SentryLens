---
phase: 19-api-de-cobertura-mitre
verified: 2026-11-10T11:00:00Z
status: human_needed
score: 4/4 must-haves verified
covered_files:
  - .planning/phases/19-api-de-cobertura-mitre/19-01-PLAN.md
  - .planning/phases/19-api-de-cobertura-mitre/19-01-SUMMARY.md
  - .planning/phases/19-api-de-cobertura-mitre/19-02-PLAN.md
  - .planning/phases/19-api-de-cobertura-mitre/19-02-SUMMARY.md
  - scripts/main.py
  - scripts/mitre_coverage.py
  - scripts/test_mitre_coverage.py
  - scripts/test_mitre_coverage_api.py
covered_digest: "v3:sha256:efe327bb8c4c4cc304ca192c9e6be65a83a595882cc80d830654770d87530995"
behavior_unverified: 0
overrides_applied: 0
human_verification:
  - test: 'Com o backend e a VM Wazuh ligados, curl com o header X-API-Key a http://127.0.0.1:8001/api/mitre/coverage; depois repetir com a VM Wazuh desligada'
    expected: "Ligada: 200, sources.alerts.available true, 17 linhas em techniques[], 14 táticas. Desligada: continua 200, sources.alerts = {available:false, reason:'source_unavailable'}, alerts_truncated/totals.alerts/alerts nulos, ataques com vereditos unknown (sources.attacks.correlation.reason 'indexer_unavailable'), sem texto de exceção no corpo"
    why_human: "Os testes simulam o Indexer com AsyncMock; só o laboratório real prova o httpx a falhar de verdade (ligação recusada/timeout) e o volume real de alertas. O 19-02-SUMMARY regista esta verificação como 'por fazer'."
---

# Phase 19: API de cobertura MITRE - Relatório de verificação

**Objetivo da fase:** O analista consegue perguntar por HTTP, por técnica e por tática, quantos ataques foram lançados, quantos foram detetados e quantos alertas foram vistos, com a origem de cada número e sem nunca transformar uma fonte em baixo em zero.
**Verificado:** 2026-11-10
**Estado:** human_needed (tudo o que é verificável em código está verificado; só falta o `curl` manual com a VM Wazuh ligada/desligada)
**Re-verificação:** Não (verificação inicial)

## Conquista do objetivo

### Verdades observáveis (critérios de sucesso do ROADMAP)

| # | Verdade | Estado | Evidência |
|---|---------|--------|-----------|
| 1 | `GET /api/mitre/coverage` exige API key por rota (401), sem efeitos secundários, devolve por técnica as táticas, alertas por origem `wazuh`/`catalog`, ataques lançados, detetados e taxa | VERIFICADO | `scripts/main.py:1858` `@app.get("/api/mitre/coverage", dependencies=_REQUIRE_API_KEY)`. `mitre_coverage.py:124-174` constrói por linha `alerts {total,wazuh,catalog}` (via `resolve_alert_techniques`), `attacks {launched,detected,partial,not_detected,unknown}` e `rate`. Testes `[OK]`: "tracer: sem X-API-Key -> 401", "chave errada -> 401"; `run_read_only` (log byte a byte igual, nenhum método de escrita do IncidentStore); `run_purity` por AST (módulo só importa `__future__`, `attack_registry`, `mitre_catalog`). Sonda própria: 17 linhas em `techniques[]` mesmo sem dados. |
| 2 | Por tática, % de ataques detetados e `null` sem ataques lançados, nunca 0 | VERIFICADO | `detection_rate()` (`mitre_coverage.py:55-64`) devolve `None` se `counts` é `None` ou o denominador é 0; `unknown` fica fora do denominador. Sonda própria com `raw_alerts=[]`, `attacks=[]`: `totals.rate None`, taxas das táticas `None`, 14 táticas na ordem `ENTERPRISE_TACTICS`. Caso misto `run_mix`: T1053 parcial -> 0.0 (veredito conhecido) nas suas 3 táticas, Credential Access 50.0. |
| 3 | Indexer ou registo de ataques em baixo -> `source_unavailable` para essa fonte e o resto dos dados, nunca 500; `alerts_truncated: true` no teto | VERIFICADO (a nível de código/mock; ver verificação humana) | `main.py:1868-1895`: dois `try/except Exception` independentes, um por fonte; o corpo leva só `source_unavailable`, o detalhe vai para `logger.warning(exc_info=True)`. Testes `[OK]`: "indexer em baixo: sources.alerts = source_unavailable", "alerts_truncated None"; "log ilegível (bytes)", "log é um diretório", "registry a levantar" -> `sources.attacks = source_unavailable`, sempre 200; "8000 alertas: alerts_truncated True", "7999: False". Sonda própria com ambas as fontes `None`: ambas `source_unavailable`, `totals` tudo `None`, `alerts_truncated None`, taxas das táticas `None`, nunca 0. |
| 4 | Técnica vista sem tática conhecida aparece em secção "sem tática" com contagens, não é descartada | VERIFICADO | `mitre_coverage.py:160-174`: linha com `tactics == []` vai para `unmapped[]` com as mesmas contagens; só `tactics_for` (tabela) decide a tática. `run_mix`: T1059/T1087 em `unmapped[]`, contam em `totals`, em nenhuma tática. |

**Pontuação:** 4/4 verdades verificadas (0 presentes mas com comportamento não verificado).

### Must-haves adicionais dos PLANs

| Must-have | Estado | Evidência |
|-----------|--------|-----------|
| D-01: `techniques[]` com as 17 técnicas da tabela + vistas com tática herdada | VERIFICADO | `rows` inicializado com `for tid in table`; `setdefault` para ids novos; sonda: 17 linhas. |
| D-02 emendado: linha por id exato, sem cruzamento pai/filha | VERIFICADO | Contagem só em `rows[tid]`; `parent_of` só para o campo `parent`. |
| D-04/D-05/D-06: `partial` não conta como detetado, `unknown` fora do denominador | VERIFICADO | `detection_rate`; `_verdict_of` defensivo (veredito ausente -> `unknown`, nunca `detected`). |
| D-10: tática multi-valor conta em todas; totais únicos à parte | VERIFICADO | `for tactic in tactics_for(...)` em `by_tactic`; `unique` conta cada ataque uma vez. |
| Tática só da tabela (nunca de `mitre_tactic`, log ou `rule.mitre.tactic`) | VERIFICADO | `mitre_coverage.py` nunca lê `mitre_tactic` nem abre o alerta cru (grep + teste AST). |
| Só GET; POST/PUT/PATCH/DELETE -> 405; `allow_methods` do CORS inalterado | VERIFICADO | Testes `[OK]` "POST/PUT/PATCH/DELETE ... -> 405"; `hours` 0/721/abc -> 422; diff de 41 linhas só acrescentadas em `main.py`, `attack_registry.py`, `mitre_catalog.py`, `test_cors.py` sem diff. |
| Prohibition API-01 (não inflar/deflatar cobertura; não re-derivar veredito) | VERIFICADO (juízo, não autoritativo) | A função só lê `actual.verdict` do registry; `partial`/`unknown` nunca somam a `detected`. |
| Prohibition API-02 (não inventar mapeamento MITRE) | VERIFICADO (juízo, não autoritativo) | Tática só de `tactics_for`; ids sem tática vão a `unmapped[]`, nunca arrumados debaixo de uma tática. |

### Artefactos

| Artefacto | Estado | Detalhes |
|-----------|--------|----------|
| `scripts/mitre_coverage.py` | VERIFICADO | 210 linhas, lógica real, pura, ligado à rota. |
| `scripts/main.py` (`import mitre_coverage`, rota) | VERIFICADO | Linhas 59 e 1858-1895. |
| `scripts/test_mitre_coverage.py` | VERIFICADO | Passa (rc 0). |
| `scripts/test_mitre_coverage_api.py` | VERIFICADO | Passa (rc 0), 100 verificações `[OK]` segundo o SUMMARY. |

### Ligações-chave

| De | Para | Via | Estado |
|----|------|-----|--------|
| `main.get_mitre_coverage` | `mitre_coverage.build_mitre_coverage_report` | chamada direta com `raw_alerts`, `attacks`, `table`, `hours`, `alerts_truncated`, `correlation` | LIGADO |
| `main.get_mitre_coverage` | `indexer_client.get_recent_alerts` | `hours`, `size=ATTACK_ALERTS_SIZE`, `exclude_infra_noise=True` | LIGADO |
| `main.get_mitre_coverage` | `_read_attack_log` + `_build_attack_registry` | dentro do `try` da fonte de ataques, filtro de janela igual a `list_attacks` | LIGADO |
| `mitre_coverage` | `mitre_catalog` (`resolve_alert_techniques`, `tactics_for`, `parent_of`, `ENTERPRISE_TACTICS`) | import | LIGADO |

### Fluxo de dados (nível 4)

| Dado | Origem | Dados reais | Estado |
|------|--------|-------------|--------|
| `alerts` por linha | `resolve_alert_techniques` sobre alertas crus do Indexer | Sim | FLUXO |
| `attacks`/`rate` por linha e tática | `attack_registry` real (`run_mix` usa o registry real, não um mock do registry) | Sim | FLUXO |
| `sources.*` | estado real dos dois `try` | Sim | FLUXO |

### Verificações comportamentais

| Comportamento | Comando | Resultado | Estado |
|---------------|---------|-----------|--------|
| Testes MITRE | `./.venv/Scripts/python.exe run_all_tests.py mitre` | 4/4 ficheiros passaram | PASS |
| Rota (401, fontes em baixo, teto, métodos, só leitura) | `python test_mitre_coverage_api.py` | rc 0, todos `[OK]` | PASS |
| Fontes `None` e sem dados na função pura | sonda própria (ver verdades 2 e 3) | `null`, nunca 0 | PASS |
| Suite completa | 88/88 (relato do 19-02-SUMMARY, execução completa; não repetida por mim) | - | Aceite do SUMMARY |

### Cobertura de requisitos

| Requisito | Plano | Descrição | Estado | Evidência |
|-----------|-------|-----------|--------|-----------|
| API-01 | 19-01, 19-02 | Rota só leitura com API key por rota; por técnica: táticas, alertas por origem, ataques, detetados e taxa; por tática % ou `null` | SATISFEITO | Verdades 1 e 2. Marcado `[x]` e "Complete" em REQUIREMENTS.md (linhas 19 e 62). |
| API-02 | 19-01, 19-02 | Fontes isoladas (`source_unavailable`), `alerts_truncated`, secção "sem tática" | SATISFEITO | Verdades 3 e 4. Marcado `[x]` e "Complete" em REQUIREMENTS.md (linhas 20 e 63). |

Requisitos órfãos (mapeados a esta fase em REQUIREMENTS.md mas sem plano): nenhum. Os dois IDs aparecem no frontmatter dos dois PLANs.

### Anti-padrões

Nenhum `TBD`/`FIXME`/`XXX`/`TODO`/`HACK` nos 3 ficheiros novos. Nenhum stub; `return null`/`[]` não aparece em caminhos de render. Sem bloqueadores.

### Avaliação dos avisos do 19-REVIEW.md (WR-01 e WR-02)

Nenhum viola um must-have; ficam como avisos (WARNING), não como lacunas.

- **WR-01 (id de técnica do log sem normalização):** confirmei por sonda: um ataque com `"t1110"` (minúsculas) vai para `unmapped[]` como `t1110` e a linha `T1110` fica com `launched` 1 em vez de 2. O defeito é real, mas o contrato do plano manda explicitamente que "texto livre vindo do log de ataques" apareça em `unmapped[]` (D-03, e o teste que o review cita fixa isso de propósito). O dado não é descartado, não é inventado e nunca é contado como detetado; apenas fica repartido por duas linhas. Não viola API-02. Recomendação: normalizar (`strip().upper()` + `mitre_catalog.TECHNIQUE_RE`) antes da Fase 20, e a UI da Fase 20 tem de escapar os ids de `unmapped[]` (texto livre).
- **WR-02 (dois pedidos independentes ao Indexer):** previsto e aceite em D-09/A-06 (isolamento das fontes tem prioridade). Os dois snapshots podem divergir (`alerts_truncated` do topo vs `sources.attacks.correlation.alerts_truncated`), mas nenhuma divergência converte uma fonte em baixo em zero: se o pedido A falha, `alerts` fica `null`; se o B falha, os vereditos ficam `unknown` com `reason: indexer_unavailable`. Não viola SC 3. Recomendação: documentar em `docs/API.md` (Fase 20, DOC-01) e acrescentar o caso `side_effect=[alertas, RuntimeError]`.
- Info IN-01/IN-02/IN-03 (acesso direto a `attack["mitre_technique"]`, `except Exception` largo, códigos de correlação duplicados): latentes, sem efeito hoje, porque `build_attack_registry` define sempre a chave.

### Itens para verificação humana

#### 1. `curl` com a VM Wazuh ligada e depois desligada

**Teste:** Com o backend a correr, `curl -H "X-API-Key: <chave>" "http://127.0.0.1:8001/api/mitre/coverage"` com a VM Wazuh ligada; repetir com a VM desligada.
**Esperado:** Ligada: 200 com `sources.alerts.available: true`, 17 linhas em `techniques[]` e 14 táticas. Desligada: continua 200, `sources.alerts = {available:false, reason:"source_unavailable"}`, `alerts_truncated`, `totals.alerts` e `alerts` a `null`, ataques com vereditos `unknown` e `correlation.reason: "indexer_unavailable"`, sem texto de exceção nem caminhos no corpo.
**Porque é humano:** Os testes usam `AsyncMock`; só o laboratório real exerce o cliente `httpx` a falhar de verdade. O 19-02-SUMMARY regista esta verificação como "por fazer".

### Resumo de lacunas

Sem lacunas bloqueadoras. Os 4 critérios de sucesso do ROADMAP e os must-haves dos dois planos estão implementados, ligados e provados por testes que passam (4/4 ficheiros MITRE, rc 0 no teste da rota, sondas próprias). O único passo em aberto é a confirmação manual no laboratório (ver acima), por isso o estado é `human_needed`. Avisos a tratar antes/na Fase 20: WR-01 (normalizar ids) e WR-02 (documentar a assimetria de snapshots).

---

_Verificado: 2026-11-10_
_Verificador: Claude (gsd-verifier)_
