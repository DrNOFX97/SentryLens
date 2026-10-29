# Phase 15: Store de decisões - Context

**Gathered:** 2026-10-29
**Status:** Ready for planning

<domain>
## Phase Boundary

O backend regista uma decisão (`approved` | `rejected`) sobre uma vaccine num registo de auditoria só de acréscimo, e deriva o estado atual sem nunca alterar a vaccine. É só o store e a regra de transição (módulo de domínio + SQLite): **não** inclui rota HTTP (Phase 16), botões (Phase 17) nem qualquer aplicação no Wazuh. Cobre VLB-02 e VLB-03.

</domain>

<decisions>
## Implementation Decisions

### Forma do registo

- **D-01:** Tabela nova `vaccine_decisions` **no mesmo ficheiro** `vaccines.sqlite3`, criada pelo mesmo `SCHEMA` de `vaccine_store.py` (`executescript` a cada ligação de escrita). A tabela `vaccines` do R11 **não muda**: o `CHECK (state = 'proposed')` e os triggers `vaccines_no_delete`/`vaccines_immutable` ficam byte-a-byte iguais, e um teste prova-o. — **Reversibility:** one-way — o esquema fica gravado nos ficheiros `vaccines.sqlite3` já existentes; mudá-lo depois exige migração.
- **D-02:** Colunas: `id INTEGER PRIMARY KEY AUTOINCREMENT`, `vaccine_id TEXT NOT NULL UNIQUE`, `decision TEXT NOT NULL CHECK (decision IN ('approved','rejected'))`, `decided_by TEXT NOT NULL`, `decided_by_name TEXT NOT NULL`, `decided_at TEXT NOT NULL`, `reason TEXT`, `previous_state TEXT NOT NULL CHECK (previous_state = 'proposed')`. `UNIQUE(vaccine_id)` é o que torna a decisão **final** no próprio ficheiro, não só no código.
- **D-03:** Triggers `BEFORE UPDATE` e `BEFORE DELETE` em `vaccine_decisions` com `RAISE(ABORT, ...)`, no estilo dos de `vaccines`. Nenhum caminho de código edita ou apaga uma decisão. — **Reversibility:** one-way — apagar/editar decisões fica impossível por desenho; reabrir uma decisão é VLB-V2-03 e precisaria do seu próprio registo.

### Autor da decisão

- **D-04:** Guardam-se `decided_by` (id do analista, ex.: `analyst-soc1`) **e** `decided_by_name` (nome tal como estava no momento, ex.: `Eddie`). A auditoria fica legível se o analista for renomeado ou desativado depois.
- **D-05:** O store **não lê** `incidents.sqlite3` (ficheiros separados, sem chave estrangeira possível) e só valida o **formato** do id e do nome (comprimento e charset fechados, sem controlo nem HTML). Verificar que o analista existe e está ativo é da rota (Phase 16), que já tem `incident_store.list_analysts`.

### Transição, corrida com o gerador e estado derivado

- **D-06:** `decide_vaccine(...)` faz **verificação e escrita na mesma transação** (`BEGIN IMMEDIATE`, sob `self.lock`): a vaccine existe, `superseded_by IS NULL` e ainda não há decisão; só então insere. Fecha a corrida com o loop do gerador (que corre `UPDATE superseded_by` noutra ligação).
- **D-07:** O SQLite **não aplica chaves estrangeiras por omissão** (`PRAGMA foreign_keys` é por ligação e começa desligado). Se `vaccine_decisions.vaccine_id` levar `REFERENCES vaccines(id)`, a ligação de decisão liga o PRAGMA; de qualquer forma a existência da vaccine é verificada **explicitamente** na transação, nunca confiada ao FK.
- **D-08:** Falhas por **código estável de conjunto fechado**, sem gravar nada: vaccine inexistente, vaccine substituída, já decidida, decisão inválida, motivo inválido (nomes exatos ao critério do planner, ver Claude's Discretion). Nunca texto de exceção.
- **D-09:** Estado derivado = a decisão registada, ou `proposed` quando não há nenhuma. Uma vaccine **aprovada e depois substituída** mantém `state = approved`; o facto de estar substituída aparece à parte em `superseded_by` (como no R11). A decisão nunca se reescreve e a vaccine nova nasce `proposed`.

### Leitura

- **D-10:** A leitura continua só-leitura e **nunca cria** o ficheiro nem a tabela. Um `vaccines.sqlite3` antigo sem `vaccine_decisions` conta como "sem decisões" (tudo `proposed`), sem erro e sem migração no arranque; a tabela só nasce na primeira escrita. Verifica-se a existência da tabela em `sqlite_master`.
- **D-11:** O campo `state` que o store devolve passa a ser o derivado (hoje vem sempre da coluna, `proposed`); `decision` traz `decided_by`, `decided_by_name`, `decided_at`, `reason` (ou `None`). Esta é a base do VLB-05; a rota e o filtro por estado ficam na Phase 16.

### Motivo

- **D-12:** Rejeitar **exige** motivo (não vazio depois de `strip`); aprovar aceita vazio (guardado como `NULL`). Máximo **500 caracteres**, texto simples. Imposto também por `CHECK` na tabela, não só no código. O motivo é dado do analista: nunca é interpretado como HTML nem como instrução.

### Convenções herdadas do R11 (não voltam a ser perguntadas)

- **D-13:** Parâmetros **só por nome** (padrão `list_vaccines`, depois do bug posicional de `list_incidents`); instante UTC passado pelo chamador (`now_iso`, como `upsert_batch`); valores sempre por `?`, cláusulas SQL fixas escolhidas pelo código.
- **D-14:** Módulo de domínio puro para a regra de transição, testável sem SQLite, como `vaccine_engine.py`; o store aplica-a. Testes standalone (sem pytest), sem Wazuh, no estilo de `test_vaccine_store.py`.

### Claude's Discretion

- Nomes exatos dos códigos de erro estáveis (D-08) e das exceções, desde que sejam um conjunto fechado e distinto por causa.
- Se o filtro por estado no SQL entra já nesta fase (o SQL vive aqui) ou só na Phase 16 (onde está o VLB-05).
- Regex exata do id e do nome do autor, e o índice em `decided_at`, se for útil.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requisitos e roadmap
- `.planning/REQUIREMENTS.md` — VLB-02 e VLB-03 (esta fase); VLB-01/04/05 são a Phase 16
- `.planning/ROADMAP.md` § Phase 15 — critérios de sucesso 1 a 4
- `.planning/PROJECT.md` — Constraints (Segurança, Dados reais, Git sem `Co-Authored-By`) e Key Decisions do R11

### Store de vaccines (o que se estende sem alterar)
- `scripts/vaccine_store.py` — `SCHEMA`, `VaccineStore` (`_connect`, `_tx`, `_read`, `upsert_batch`, `list_vaccines`, `get_vaccine`), `_to_vaccine` e `STORE_FIELDS`
- `scripts/vaccine_ingest.py` — `persist_vaccines` e o loop que escreve `superseded_by` (a outra ponta da corrida de D-06)
- `scripts/vaccine_engine.py` — padrão de módulo puro e `validate_vaccine`
- `scripts/test_vaccine_store.py` — padrão de teste do store (estado imposto pelo ficheiro, triggers, ligação só-leitura)
- `docs/DATA_MODEL.md` § Vaccine (R11) — contrato da entidade que o R12 estende

### Analistas (só para o formato do autor; a validação é Phase 16)
- `scripts/incident_store.py` — `soc_analysts` (`id`, nome, `active`, tier) e `list_analysts`
- `scripts/main.py` — modelos `AnalystCreate`/`AnalystUpdate` e `GET /api/soc/analysts`

### Histórico das decisões do R11
- `.planning/milestones/v1.1-phases/13-store-e-api-de-leitura/` — decisões do store (A1: `ON CONFLICT DO NOTHING`, A2: estabilização, `no_data` com store inexistente)
- `.planning/milestones/v1.1-ROADMAP.md` — o que o R11 prometeu sobre `proposed` e sobre o R12

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `VaccineStore._tx()` / `_read()`: transação de escrita com commit/rollback e ligação `mode=ro` que devolve `None` se o ficheiro não existe — a base de D-06 e D-10.
- `VaccineStore.lock` (`RLock`): serializa as escritas dentro do processo; D-06 acrescenta `BEGIN IMMEDIATE` para a corrida com outras ligações.
- `resolve_db_path()`: caminho do ficheiro resolvido pelo módulo, nunca pelo cwd; reutilizar tal e qual.

### Established Patterns
- Imutabilidade imposta no ficheiro (`CHECK` + triggers `RAISE(ABORT)`), não só no código.
- Escrita por `INSERT ... ON CONFLICT ... DO NOTHING`, nunca `INSERT OR IGNORE` (que engole em silêncio uma violação de `CHECK`): com `UNIQUE(vaccine_id)` a decisão duplicada tem de falhar de forma **explícita**, não ser ignorada.
- Parâmetros só por nome; erros como códigos estáveis, nunca texto de exceção; sem amostra é `None`/"Sem dados", nunca 0.

### Integration Points
- `_to_vaccine` e `STORE_FIELDS` (hoje `state`, `superseded_by`, `created_at`): onde o estado derivado e o bloco `decision` entram na leitura (D-11).
- `SCHEMA` é executado a cada ligação de escrita: acrescentar a tabela e os triggers aí cria-os na primeira escrita, em ficheiros novos e antigos.
- Phase 16 vai chamar `decide_vaccine` a partir de `main.py`; por isso o contrato de erros (D-08) tem de ser estável desde já.

</code_context>

<specifics>
## Specific Ideas

- "Aprovar não é aplicar": o store não tem nenhuma função que aplique, e nada em `vaccine_decisions` representa uma ação no Wazuh; só "aceite" ou "recusada" pelo analista.
- O autor aparece no registo com o nome humano da Equipa SOC (Eddie, Jeremy, Mike), não só com o id.

</specifics>

<deferred>
## Deferred Ideas

- Reverter/reabrir uma decisão com o seu próprio registo de auditoria — VLB-V2-03 (v2).
- Papéis por tier (só Tier 2+ aprova) — VLB-V2-02; o backend só tem uma API key, sem identidade por pedido.
- Dry-run que mostra o que a regra teria apanhado — VLB-V2-01 / R13.
- Truncagem de alertas por ataque em vez de por lote (`ATTACK_ALERTS_SIZE`) — dívida do R11, não é desta fase.

</deferred>

---

*Phase: 15-store-de-decis-es*
*Context gathered: 2026-10-29*
