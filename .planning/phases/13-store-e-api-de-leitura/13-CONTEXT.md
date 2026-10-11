# Phase 13: Store e API de leitura - Context

**Gathered:** 2026-10-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Persistir as vaccines geradas pelo motor da Fase 12 num store SQLite escrito só pelo backend (estado fixo `proposed`, sem duplicados, sobrevive a reinício) e expô-las por `GET /api/vaccines` e `GET /api/vaccines/{id}` (só leitura, API key por rota, códigos de erro estáveis). Sem rotas de escrita. A aba Vaccines e a documentação final são a Fase 14. Aplicar regras no Wazuh está fora de âmbito (R12+).

</domain>

<decisions>
## Implementation Decisions

### Quem escreve e quando
- **D-01:** Um loop de background iniciado no `startup` de `main.py` (padrão `_system_monitor_loop`/`network_poll_loop`) lê o attack log, constrói o registo, corre `vaccine_engine.build_vaccine_candidates` e grava as vaccines novas. Os `GET` só leem, nunca escrevem.
- **D-02:** Cadência fixa de ~5 min (alinhada com a janela de correlação de 300 s), configurável por variável de ambiente. Reprocessar é barato e seguro porque o id é determinístico (Fase 12, D-03) e a escrita é idempotente.
- **D-03:** Falhas do loop (Indexer indisponível, etc.) não derrubam o backend nem apagam o que já está no store; o estado do loop (última execução, último erro como código estável) fica registado para diagnóstico.

### Tecnologia do store
- **D-04:** SQLite, módulo novo estilo `incident_store.py` (uma ligação por operação, `RLock`). `PRIMARY KEY` no id e `INSERT OR IGNORE` garantem "sem duplicados"; `CHECK (state = 'proposed')` (e/ou trigger) impede qualquer outro estado. — **Reversibility:** costly — o formato do ficheiro e do id é a chave de `/api/vaccines/{id}` e da aba da Fase 14.
- **D-05:** Ficheiro `scripts/vaccines.sqlite3`, gitignored, caminho sobrescrevível por variável `SENTRYLENS_*`, sempre resolvido relativamente ao ficheiro do módulo e nunca ao cwd.

### Id que evolui
- **D-06:** Quando um ataque passa de `partial` a `not_detected` o id muda (Fase 12, D-03). A vaccine antiga **fica** no store e ganha `superseded_by = <id novo>`. É metadado, não um estado novo: `state` continua `proposed`. A lista omite as substituídas por omissão (parâmetro para as incluir).
- **D-07:** Se o ataque passa a `detected`, a vaccine existente mantém-se intacta (histórico). Não há estado `resolved`/`stale` nesta fase; fechar vaccines é R12+.

### Forma da API de leitura
- **D-08:** `GET /api/vaccines` aceita `limit` (1–500, omissão 200), `offset`, filtro por `attack_id` e `technique` (MITRE, regex como em `/api/attacks`) e `include_superseded` (omissão false). Ordem: mais recentes primeiro. A resposta traz `total` e o envelope com `reason`/origem.
- **D-09:** Lista vazia devolve `200` com `vaccines: []` e `reason` estável (ex. `no_data`). Store ilegível devolve `503` com `detail: "store_unavailable"`. `GET /api/vaccines/{id}` com id inexistente devolve `404` com `detail: "entry_not_found"`. Nenhuma resposta expõe texto de exceção, traceback ou caminhos.
- **D-10:** `dependencies=_REQUIRE_API_KEY` aplicado individualmente em cada rota. Nenhum POST/PUT/PATCH/DELETE em `/api/vaccines`.

### Claude's Discretion
- Esquema exato das colunas (JSON da vaccine vs colunas) e índices, desde que respeite D-04.
- Nome da variável de ambiente (da cadência e do caminho) e do módulo do store.
- Forma do estado do loop (D-03) e se é exposto na resposta ou só em log.
- Regex do id na rota (derivar do formato de `vaccine_engine.vaccine_id`).

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requisitos e roadmap
- `.planning/ROADMAP.md` — Phase 13, critérios de sucesso 1–4
- `.planning/REQUIREMENTS.md` — VAC-05, VAC-06 e Out of Scope
- `.planning/phases/12-motor-de-vaccines/12-CONTEXT.md` — D-03 (id determinístico), D-04 (`skipped`), nota sobre a política da vaccine antiga entregue a esta fase

### Código a reutilizar
- `scripts/vaccine_engine.py` — `build_vaccine_candidates`, `vaccine_id`, `validate_vaccine` (validar antes de gravar)
- `scripts/incident_store.py` — padrão SQLite (ligação por operação, RLock, triggers append-only)
- `scripts/main.py` — `startup` (linha ~379), `_REQUIRE_API_KEY`, `_read_attack_log`, `_build_attack_registry`, rotas `/api/attacks` e `/api/attack-library` (404 `entry_not_found`)
- `scripts/attack_registry.py` — registo que alimenta o motor
- `scripts/soc_metrics.py` — padrão de `source_unavailable`
- `scripts/history_store.py` — alternativa JSONL (não escolhida)
- `CLAUDE.md` — regra de API key por rota, CORS, gitignore

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `vaccine_engine.build_vaccine_candidates(registry, correlation)`: devolve vaccines + `skipped` + envelope; `validate_vaccine` para validar à entrada do store.
- `main._read_attack_log()` + `main._build_attack_registry(attack_log, hours)`: já usados por `/api/attacks`, reutilizáveis no loop.
- `incident_store.IncidentStore`: modelo de estrutura do store.

### Established Patterns
- Loops de background criados no `startup` e guardados em `app.state.*_task`.
- Rotas só-leitura com `dependencies=_REQUIRE_API_KEY` e 404 `entry_not_found`.
- Testes standalone sem pytest, `TestClient(main.app)` + `on_startup.clear()`, mocks `AsyncMock`, `SENTRYLENS_API_KEY` antes de `import main`.

### Integration Points
- Novo loop em `startup`; novas rotas junto de `/api/attacks`; ficheiro novo no `.gitignore`; novo teste registado em `run_all_tests.py`.

</code_context>

<specifics>
## Specific Ideas

No specific requirements — open to standard approaches.

</specifics>

<deferred>
## Deferred Ideas

- Estados `resolved`/`stale` e aplicar regras no Wazuh — R12+.
- Janela por cenário no `attack_library.yaml` — herdado da Fase 12.
- Filtros do lado do cliente e aba Vaccines — Fase 14.

</deferred>

---

*Phase: 13-Store e API de leitura*
*Context gathered: 2026-10-12*
