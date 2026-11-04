# Phase 16: API de decisão - Context

**Gathered:** 2026-10-29
**Status:** Ready for planning

<domain>
## Phase Boundary

O analista aprova ou rejeita uma vaccine por HTTP (`POST /api/vaccines/{id}/decision`) e lê o estado e a decisão no `GET` (`state`, `decision`, filtro `?state=`, contagens por estado), com as garantias do R11: API key por rota, GET sem efeitos secundários, códigos estáveis, nada aplicado no Wazuh. Cobre VLB-01, VLB-02 (só o mapeamento HTTP), VLB-04 e VLB-05. **Não** inclui botões, estados na aba nem frases novas (Phase 17), nem lógica nova de transição (Phase 15, já feita), nem aplicar nada no Wazuh (R21).

</domain>

<decisions>
## Implementation Decisions

### Pedido e resposta do POST

- **D-01:** Rota `POST /api/vaccines/{vaccine_id}/decision` com `dependencies=_REQUIRE_API_KEY` (por rota, nunca a nível de app) e `vaccine_id` com `Path(pattern=VACCINE_ID_RE)`. Corpo de contrato fechado: `{"decision": "approved|rejected", "analyst_id": "analyst-...", "reason": "opcional; obrigatório se rejected; máx 500"}`. O cliente **nunca** envia `decided_by_name`, `decided_at` nem `state`: o nome vem do `incident_store` (nome atual do analista), o instante é gerado no servidor (UTC, offset 0). — **Reversibility:** costly — o formato do corpo passa a ser consumido pela Phase 17 e por qualquer cliente; mudá-lo depois toca em rota, testes e frontend.
- **D-02:** Resposta 200: `{"vaccine": <vaccine com state e decision>, "notice": "..."}`. A rota relê `get_vaccine` depois de decidir para devolver o estado já derivado (poupa um GET ao frontend e evita uma vista a mentir). O `notice` diz literalmente que "aprovada" significa só aceite pelo analista e que **nada foi aplicado no Wazuh**. Nenhum campo se chama `applied`/`active`.
- **D-03:** O analista identifica-se por `analyst_id` no corpo, validado com `incident_store.get_analyst` (existe e `active`). Documenta-se como **autoria autodeclarada, não autenticada**: só existe uma API key, por isso o registo é "quem o cliente disse" (limite à maneira do SHA-256 dos `.pkl`). Identidade por pedido é VLB-V2-02. O frontend (Phase 17) escolhe o analista a partir de `GET /api/soc/analysts`, como `incidents.js`, sem `localStorage`.

### Validação e erros (códigos estáveis)

- **D-04:** O corpo valida-se **à mão**: a rota lê o corpo cru e usa o `validate_request` da Phase 15, em vez de Pydantic. Assim todo o 422 tem `detail` em **string** (código estável) e o `vacCodeFromResponse` do frontend funciona (um 422 do Pydantic traz `detail` em lista e cairia em `http_422`). Corpo que não é JSON objeto, chave extra (`decided_by_name`, `state`, `decided_at`, ...) ou tipo errado → código novo `invalid_body`.
- **D-05:** Mapeamento fixo (`detail` = código, string):

  | Causa | HTTP | detail |
  |---|---|---|
  | sem/errada API key | 401 | o de `require_api_key` |
  | `INVALID_INPUT_CODES` (F15) e `invalid_body` | 422 | o próprio código |
  | analista inexistente / inativo | 422 | `analyst_not_found` / `analyst_inactive` |
  | `entry_not_found` | 404 | `entry_not_found` |
  | `already_decided`, `vaccine_superseded` | 409 | o próprio código |
  | `sqlite3.Error` do store de vaccines | 503 | `store_unavailable` |
  | falha a ler analistas | 503 | `incidents_unavailable` |
  | PUT/PATCH/DELETE na rota | 405 | (FastAPI) |

  O 422 para analista é porque o erro está no corpo (`analyst_id`), não no recurso da URL; o 404 fica reservado à vaccine. Nunca texto de exceção nem caminhos no corpo.
- **D-06:** Falha a ler os analistas dá `503 incidents_unavailable` com código próprio; **não** se reutiliza `_incidents_call` (que devolve 500 genérico). Nada é gravado.
- **D-07:** Nome de analista fora do charset fechado da Phase 15 (por exemplo apóstrofo) continua a dar `invalid_author`; **aceita-se e documenta-se** em vez de relaxar o regex já fechado. Os analistas atuais (Eddie, Jeremy, Mike) não são afetados. A frase para `invalid_author` é da Phase 17.
- **D-08:** Repetir exatamente a mesma decisão dá **409 `already_decided`, sem exceção** (VLB-02 literal, sem 200 idempotente). Um clique duplo gera um 409 legítimo, que a Phase 17 trata como "atualizar vista". A rota nunca faz "ler, verificar, depois decidir": a corrida já está fechada em `decide_vaccine` (`BEGIN IMMEDIATE`).
- **D-09:** Limites: só limites de campo (os da Phase 15: `reason` máx 500, regex dos ids) mais um **teto de tamanho bruto do corpo** de poucos KB, recusado antes de parsear. Sem rate limit (laboratório de um só utilizador).

### Leitura (VLB-05)

- **D-10:** `GET /api/vaccines` ganha `state: Literal["proposed","approved","rejected"] | None = Query(None)`, passado a `list_vaccines(state=...)`. Valor fora do conjunto → **422 do FastAPI** (como `technique`), não lista vazia. `total` respeita o filtro; `available`/`reason` continuam baseados em `store_total` (filtro sem resultado ≠ `no_data`).
- **D-11:** O envelope do `GET /api/vaccines` traz **contagens por estado** (`proposed`/`approved`/`rejected`) para os KPIs da Phase 17, sobre o **universo das vaccines atuais** (`superseded_by IS NULL`), **sem** os filtros `state`/`attack_id`/`technique` (o KPI não muda ao filtrar a tabela). Sem amostra (store inexistente ou vazio) as contagens são `None`, nunca 0. Pede uma leitura nova, só de leitura, em `vaccine_store.py` (aditiva, sem tocar no esquema).
- **D-12:** Vaccine aprovada e depois substituída: mantém-se a regra da Phase 15 (continua `approved`, só aparece com `include_superseded=true`, `superseded_by` assinala-o). **Sem campo novo** no envelope.
- **D-13:** `GET /api/vaccines/{id}` não muda de código se a Phase 15 já traz `state`/`decision` por `_to_vaccine` (confirmado); só ganha testes. O GET continua sem efeitos: bytes/mtime iguais, ficheiro inexistente não é criado.

### Garantias (VLB-04) e fan-out

- **D-14:** Teste de varrimento por **AST de `main.py` + `vaccine_*.py`**: sem `subprocess`, `os.system`, `ssh_client` nem escritas ao Manager Wazuh nas funções de vaccines; nenhuma rota `/api/vaccines/**` com `apply`/`deploy`/`activate`; o handler só chama `decide_vaccine`/`get_vaccine`/`get_analyst` (e a leitura de contagens). O texto do `notice` e a docstring da rota dizem que aprovada ≠ aplicada, e há teste para isso. Não existe rota de editar/apagar decisões (405).
- **D-15:** **Sem evento WebSocket** nem cópia da decisão no JSONL do `history_store`: a única fonte de verdade é `vaccine_decisions` (duas cópias divergem). A Phase 17 refresca com um `GET` depois de decidir.
- **D-16:** CORS: `POST` já está em `allow_methods=["GET","POST","PATCH"]`; **nenhuma alteração** de `allow_methods` se ficamos em POST. O critério 4 cumpre-se com um teste de preflight em `test_cors.py` a `POST /api/vaccines/vac-.../decision` (`Access-Control-Request-Headers: x-api-key,content-type`) e fixando que `PUT`/`DELETE` não passam a ser permitidos.

### Claude's Discretion

- Valor exato do teto do corpo (D-09) e o status HTTP quando o excede (preferência: manter 422 `invalid_body` para uniformidade em vez de 413).
- Nome do campo das contagens no envelope (D-11) e nome do método de leitura no store.
- Código exato do `notice` (texto em português) desde que diga "aceite pelo analista" e "não aplicada no Wazuh".
- Divisão em planos/waves; o rascunho sugere tracer-bullet primeiro (rota ponta a ponta → leitura → garantias/CORS), com 16-01 separável numa função pura `(status, detail)` + a rota se a validação à mão o justificar.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requisitos e roadmap
- `.planning/REQUIREMENTS.md` — VLB-01, VLB-02, VLB-04, VLB-05 (esta fase); VLB-06/07 são a Phase 17
- `.planning/ROADMAP.md` § Phase 16 — critérios de sucesso 1 a 4
- `.planning/PROJECT.md` — Constraints (Segurança, Dados reais, Git sem `Co-Authored-By`)
- `.planning/phases/16-api-de-decisao/16-DESIGN-DRAFT.md` — rascunho de desenho (superseded por este CONTEXT onde divergir; útil para a lista de testes e riscos)

### Contrato da Phase 15 (o que a rota consome, já executado)
- `.planning/phases/15-store-de-decis-es/15-CONTEXT.md` — decisões D-01..D-14 do store
- `scripts/vaccine_decision.py` — `INVALID_INPUT_CODES`/`NOT_FOUND_CODES`/`CONFLICT_CODES`, `VaccineDecisionError`, `validate_request`, `DECISION_RECORD_KEYS`, regex de ids e nome
- `scripts/vaccine_store.py` — `decide_vaccine`, `list_vaccines(state=...)`, `get_vaccine`, `_to_vaccine`

### Rotas, auth e analistas
- `scripts/main.py` — `GET /api/vaccines[/{id}]` (~linha 1956), `_REQUIRE_API_KEY`, `CORSMiddleware`/`allow_methods` (~linha 229), `AnalystCreate`, `GET /api/soc/analysts`, `_incidents_call`
- `scripts/incident_store.py` — `get_analyst` / `list_analysts` (`active`)
- `scripts/test_cors.py`, `scripts/test_vaccines_api.py`, `scripts/test_vaccines_frontend.py` — testes a manter verdes/atualizar
- `docs/DATA_MODEL.md` § Vaccine (R11) — contrato da entidade que a F17 documenta

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `vaccine_decision.validate_request` / `VaccineDecisionError.code`: validação e códigos prontos; a rota só os mapeia para HTTP.
- `VaccineStore.decide_vaccine` + `get_vaccine`/`list_vaccines`: já devolvem `state` derivado e bloco `decision`.
- `run_in_threadpool` (padrão das rotas de vaccines): os stores são síncronos.
- `incident_store.get_analyst`: valida o analista.

### Established Patterns
- API key **por rota** (`dependencies=_REQUIRE_API_KEY`), nunca a nível de app; 404 `entry_not_found`, 503 `store_unavailable`, 405 a escritas indevidas.
- `detail` é sempre string com código estável; sem amostra é `None`/"Sem dados", nunca 0.
- Testes standalone: `SENTRYLENS_API_KEY` antes de `import main`, `TestClient`, `main.app.router.on_startup.clear()`, `VACCINES_DB_PATH` num tmp, stores mockados/tmp.

### Integration Points
- `main.py`: rota nova ao lado de `GET /api/vaccines/{id}`; parâmetro `state` na lista; contagens no envelope.
- `vaccine_store.py`: leitura nova de contagens por estado (aditiva).
- Novo `scripts/test_vaccine_decision_api.py` (apanhado por `run_all_tests.py` por glob); `test_cors.py` e `test_vaccines_api.py` atualizados.
- Frontend: **zero alterações** nesta fase; `test_vaccines_frontend.py` tem de continuar verde com `state` novo nas linhas (`VAC_STATE_LABELS` só conhece `proposed`; verificar o fallback do render com `approved`/`rejected`).

</code_context>

<specifics>
## Specific Ideas

- "Aprovada ≠ aplicada" tem de ler-se sem ambiguidade na resposta, na docstring e em teste.
- O registo mostra o nome humano da Equipa SOC (Eddie, Jeremy, Mike), vindo do `incident_store`, nunca do corpo.
- A autoria autodeclarada documenta-se como limite, não como identidade.

</specifics>

<deferred>
## Deferred Ideas

- Botões Aprovar/Rejeitar, estados na aba, frases para os códigos novos — Phase 17.
- DATA_MODEL/API/README/CLAUDE.md e contagens medidas da suite — Phase 17.
- Reverter/reabrir decisões (VLB-V2-03), papéis por tier / identidade por pedido (VLB-V2-02), dry-run (VLB-V2-01) — v2.
- Evento WebSocket ao decidir e cópia no JSONL do histórico — recusados nesta fase; reabrir só se o painel passar a usar tempo real.
- Aplicar a vaccine no Wazuh — R21.

</deferred>

---

*Phase: 16-API de decisão*
*Context gathered: 2026-10-29*
