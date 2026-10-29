# Phase 13: Store e API de leitura - Research

**Researched:** 2026-10-12
**Domain:** Persistência SQLite append-only + loop de background + rotas FastAPI só de leitura (backend Python, stdlib + FastAPI já instalados)
**Confidence:** HIGH (tudo é código do próprio repo + stdlib; os comportamentos de SQLite foram confirmados com uma sonda local nesta sessão)

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Quem escreve e quando**
- **D-01:** Um loop de background iniciado no `startup` de `main.py` (padrão `_system_monitor_loop`/`network_poll_loop`) lê o attack log, constrói o registo, corre `vaccine_engine.build_vaccine_candidates` e grava as vaccines novas. Os `GET` só leem, nunca escrevem.
- **D-02:** Cadência fixa de ~5 min (alinhada com a janela de correlação de 300 s), configurável por variável de ambiente. Reprocessar é barato e seguro porque o id é determinístico (Fase 12, D-03) e a escrita é idempotente.
- **D-03:** Falhas do loop (Indexer indisponível, etc.) não derrubam o backend nem apagam o que já está no store; o estado do loop (última execução, último erro como código estável) fica registado para diagnóstico.

**Tecnologia do store**
- **D-04:** SQLite, módulo novo estilo `incident_store.py` (uma ligação por operação, `RLock`). `PRIMARY KEY` no id e `INSERT OR IGNORE` garantem "sem duplicados"; `CHECK (state = 'proposed')` (e/ou trigger) impede qualquer outro estado. — **Reversibility:** costly — o formato do ficheiro e do id é a chave de `/api/vaccines/{id}` e da aba da Fase 14.
- **D-05:** Ficheiro `scripts/vaccines.sqlite3`, gitignored, caminho sobrescrevível por variável `SENTRYLENS_*`, sempre resolvido relativamente ao ficheiro do módulo e nunca ao cwd.

**Id que evolui**
- **D-06:** Quando um ataque passa de `partial` a `not_detected` o id muda (Fase 12, D-03). A vaccine antiga **fica** no store e ganha `superseded_by = <id novo>`. É metadado, não um estado novo: `state` continua `proposed`. A lista omite as substituídas por omissão (parâmetro para as incluir).
- **D-07:** Se o ataque passa a `detected`, a vaccine existente mantém-se intacta (histórico). Não há estado `resolved`/`stale` nesta fase; fechar vaccines é R12+.

**Forma da API de leitura**
- **D-08:** `GET /api/vaccines` aceita `limit` (1–500, omissão 200), `offset`, filtro por `attack_id` e `technique` (MITRE, regex como em `/api/attacks`) e `include_superseded` (omissão false). Ordem: mais recentes primeiro. A resposta traz `total` e o envelope com `reason`/origem.
- **D-09:** Lista vazia devolve `200` com `vaccines: []` e `reason` estável (ex. `no_data`). Store ilegível devolve `503` com `detail: "store_unavailable"`. `GET /api/vaccines/{id}` com id inexistente devolve `404` com `detail: "entry_not_found"`. Nenhuma resposta expõe texto de exceção, traceback ou caminhos.
- **D-10:** `dependencies=_REQUIRE_API_KEY` aplicado individualmente em cada rota. Nenhum POST/PUT/PATCH/DELETE em `/api/vaccines`.

### Claude's Discretion
- Esquema exato das colunas (JSON da vaccine vs colunas) e índices, desde que respeite D-04.
- Nome da variável de ambiente (da cadência e do caminho) e do módulo do store.
- Forma do estado do loop (D-03) e se é exposto na resposta ou só em log.
- Regex do id na rota (derivar do formato de `vaccine_engine.vaccine_id`).

### Deferred Ideas (OUT OF SCOPE)
- Estados `resolved`/`stale` e aplicar regras no Wazuh — R12+.
- Janela por cenário no `attack_library.yaml` — herdado da Fase 12.
- Filtros do lado do cliente e aba Vaccines — Fase 14.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| VAC-05 | As vaccines persistem num store escrito só pelo backend, com estado fixo `proposed`; reiniciar o backend não as perde nem as duplica. | `VaccineStore` SQLite (PK + `ON CONFLICT(id) DO NOTHING` + `CHECK(state='proposed')` + triggers de imutabilidade); loop de background idempotente; `validate_vaccine` antes de gravar. Ver "Architecture Patterns" e "Common Pitfalls" 1-4. |
| VAC-06 | `GET /api/vaccines` e `GET /api/vaccines/{id}` (só leitura, API key por rota) devolvem a lista e o detalhe; id inexistente dá 404 com código estável `entry_not_found`; erros nunca expõem texto de exceção nem caminhos. | Duas rotas `@app.get` com `dependencies=_REQUIRE_API_KEY`, `Path(pattern=VACCINE_ID_RE)`, mapa de erros para códigos estáveis, `generator` no envelope para o erro do Indexer. Ver "Code Examples" e "Security Domain". |
</phase_requirements>

## Summary

A fase é maioritariamente "colar peças já existentes": o motor (`vaccine_engine`) devolve vaccines já validáveis, `IncidentStore` dá o molde do store, `/api/attacks` e `/api/attack-library` dão o molde das rotas, e o `startup` de `main.py` dá o molde do loop. Não há dependências externas novas (só stdlib `sqlite3` e FastAPI, já instalados), por isso não há `Package Legitimacy Audit` nem a pesquisa de documentação externa foi necessária.

O risco real não está na mecânica, está em **três armadilhas de correção** que o CONTEXT não cobre e que, se ignoradas, produzem vaccines falsas e permanentes: (1) o loop corre de 5 em 5 minutos e a janela de correlação é de 300 s, logo qualquer ataque avaliado poucos segundos depois do lançamento aparece como `not_detected` só porque os alertas ainda não chegaram, e a vaccine fica gravada para sempre (D-07 mantém-na intacta); (2) `INSERT OR IGNORE` (D-04) também **ignora em silêncio violações de `CHECK`**, por isso o `CHECK(state='proposed')` deixa de ser uma garantia; usar `ON CONFLICT(id) DO NOTHING`, que só ignora o conflito de PK; (3) a chamada `incident_store.list_incidents(None, None, None, 100000, 0)` em `main._build_attack_registry` está desalinhada pelo trabalho por commitar em `incident_store.py` (novo parâmetro `assigned_to` antes de `limit`) e devolve **sempre zero incidentes**, o que esvaziaria `origin.incident_ids` de todas as vaccines gravadas pelo loop.

Fora disso, a política de `superseded_by` (D-06) tem de ser generalizada a qualquer mudança de id para o mesmo `attack_id` (inclui `not_detected` -> `partial` e o vaivém), e o `GET` não toca no Indexer, por isso o "Indexer indisponível" do critério de sucesso 4 só chega ao analista se o estado do loop for exposto no envelope (recomendado: bloco `generator`).

**Primary recommendation:** Criar `scripts/vaccine_store.py` (SQLite, `ON CONFLICT DO NOTHING`, triggers a só deixar mexer em `superseded_by`), `scripts/vaccine_ingest.py` (seleção de ataques estabilizados + validação + gravação em lote numa transação) e, em `main.py`, um `_vaccine_loop` + duas rotas GET; corrigir a chamada posicional de `list_incidents` para argumentos nomeados; expor `generator` (estado do loop com códigos estáveis) na resposta da lista.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Gerar candidatos (motor) | API / Backend (`vaccine_engine`, puro) | — | Já existe (Fase 12); esta fase só o chama. |
| Quando/quem grava (loop) | API / Backend (task asyncio no `startup`) | — | D-01: o `GET` não escreve; o loop reaproveita `_build_attack_registry` de `main.py`. |
| Persistência e imutabilidade | Database / Storage (SQLite + CHECK + triggers) | API / Backend (`VaccineStore`) | A garantia "estado só `proposed`, sem DELETE" deve viver no próprio ficheiro, não só no código Python. |
| Leitura HTTP | API / Backend (rotas GET) | Database / Storage | Só `SELECT`; erros SQLite viram `503 store_unavailable`. |
| Autenticação | API / Backend (`require_api_key` por rota) | — | CLAUDE.md: nunca a nível de app. |
| Apresentação | Browser / Client | — | Fase 14 (fora de âmbito). |

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `sqlite3` (stdlib) | 3.53.1 no `.venv` (global: 3.50.4) [VERIFIED: `.venv/Scripts/python.exe -c "import sqlite3;print(sqlite3.sqlite_version)"`] | Store das vaccines | Mesmo padrão de `incident_store.py`; `ON CONFLICT ... DO NOTHING` exige SQLite >= 3.24, satisfeito. |
| FastAPI | já instalado em `scripts/.venv` [VERIFIED: `main.py:36` `from fastapi import Depends, FastAPI, Header, HTTPException, Path, Query, Response, WebSocket, WebSocketDisconnect`] | Rotas | Mesmo padrão das rotas existentes. |
| Python | 3.12.14 no `.venv` [VERIFIED: `.venv/Scripts/python.exe --version`] | Runtime | — |

### Supporting
| Módulo do repo | Uso nesta fase |
|----------------|----------------|
| `vaccine_engine.build_vaccine_candidates`, `validate_vaccine`, `vaccine_id`, `VACCINE_ID_RE`, `REASONS`, `SKIP_REASONS` | Gerar e validar antes de gravar; regex da rota. |
| `main._build_attack_registry`, `load_attack_log`, `ATTACK_LOG_PATH`, `_REQUIRE_API_KEY`, `_now_iso`, `run_in_threadpool` | Entradas do loop e padrão das rotas. |
| `incident_engine.parse_timestamp` (importado em `main.py` como `incident_engine_parse`) | Filtrar o attack log por janela e por "estabilização". |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| SQLite (D-04, bloqueado) | JSONL append-only (`history_store`) | Não escolhido pelo utilizador; dedup por varrimento. |
| `INSERT OR IGNORE` (D-04 literal) | `INSERT ... ON CONFLICT(id) DO NOTHING` | Ver Pitfall 2: o segundo só ignora o conflito de PK, o primeiro engole também falhas de `CHECK`. Cumpre a intenção de D-04 ("sem duplicados"). |

**Installation:** nenhuma. `pip install` não é necessário.

## Package Legitimacy Audit

Nenhum pacote externo novo é instalado nesta fase (só `sqlite3` da stdlib e dependências já presentes em `scripts/requirements.txt`). Auditoria não aplicável.

**Packages removed due to [SLOP] verdict:** none
**Packages flagged as suspicious [SUS]:** none

## Architecture Patterns

### System Architecture Diagram

```
 attack_log.jsonl ──load_attack_log──┐
                                     ▼
              [filtro: dentro da janela VACCINE_WINDOW_HOURS
                       E mais antigo que VACCINE_SETTLE_SECONDS]
                                     │ (vazio -> estado "no_data", sem chamar o Indexer)
                                     ▼
   Wazuh Indexer ◄── _build_attack_registry(entradas, hours) ──► modelo ML, incident_store, network buffer
   (falha -> correlation.error_code estável)         │
                                     ▼
            vaccine_engine.build_vaccine_candidates(registry, correlation)
              reason=source_unavailable ─► estado do loop: erro (código estável), NADA gravado
                                     │ vaccines[]
                                     ▼
             validate_vaccine(v)==[]  (rejeitadas: contadas, código no log, nunca gravadas)
                                     ▼
        VaccineStore.upsert_batch(...)  [1 transação, RLock]
           ├─ INSERT ... ON CONFLICT(id) DO NOTHING        (idempotente)
           └─ UPDATE superseded_by (único campo mutável; triggers recusam o resto)
                                     │
   ┌──────────── scripts/vaccines.sqlite3 (gitignored) ────────────┐
   │                                                                │
   ▼                                                                ▼
 GET /api/vaccines  (lista + filtros + generator{estado do loop})   GET /api/vaccines/{id}
   401 sem key · 200 {vaccines:[], reason:"no_data"} · 503 store_unavailable · 404 entry_not_found
```

### Recommended Project Structure
```
scripts/
├── vaccine_store.py        # NOVO: VaccineStore (SQLite), SCHEMA, resolução do caminho
├── vaccine_ingest.py       # NOVO: select_settled_entries, persist_vaccines (puro + store), códigos de erro
├── main.py                 # EDIT: instância do store, estado do loop, _run_vaccine_cycle/_vaccine_loop, startup, 2 rotas GET, fix list_incidents
├── test_vaccine_store.py   # NOVO
├── test_vaccine_ingest.py  # NOVO (ciclo com Indexer mockado)
└── test_vaccines_api.py    # NOVO (rotas)
.gitignore                  # EDIT: scripts/vaccines.sqlite3 (+ -journal)
```
`run_all_tests.py` apanha `test_*.py` por glob [VERIFIED: `run_all_tests.py` linha `files = sorted(p for p in HERE.glob("test_*.py") if needle in p.name)`], por isso **não há nada para "registar"** (o CONTEXT diz o contrário; é só criar os ficheiros).

Fatiamento sugerido (3 planos, vertical, cada um com os seus testes): 13-01 store + teste; 13-02 ingest + loop + fix `list_incidents` + teste de ciclo; 13-03 rotas + `.gitignore` + teste de rotas.

### Pattern 1: Store SQLite append-only com um só campo mutável
**What:** tabela `vaccines` com PK no id, `CHECK(state='proposed')`, `CHECK(json_valid(payload))`, triggers `BEFORE DELETE` e `BEFORE UPDATE OF <todas menos superseded_by>` a abortar. A vaccine inteira (como o motor a produz, já validada) vai em `payload` (JSON); só `attack_id`, `scenario`, `mitre_technique`, `verdict` e `superseded_by` são colunas, para filtrar e ordenar.
**When to use:** sempre; é o esquema recomendado (discricionário no CONTEXT).
**Esquema (recomendação):**
```sql
CREATE TABLE IF NOT EXISTS vaccines (
    id TEXT PRIMARY KEY CHECK (id GLOB 'vac-*' AND length(id) = 16),
    state TEXT NOT NULL DEFAULT 'proposed' CHECK (state = 'proposed'),
    attack_id INTEGER NOT NULL,
    scenario TEXT NOT NULL,
    mitre_technique TEXT,
    verdict TEXT NOT NULL CHECK (verdict IN ('not_detected', 'partial')),
    payload TEXT NOT NULL CHECK (json_valid(payload)),
    created_at TEXT NOT NULL,
    superseded_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_vaccines_attack ON vaccines(attack_id);
CREATE INDEX IF NOT EXISTS idx_vaccines_technique ON vaccines(mitre_technique);
CREATE TRIGGER IF NOT EXISTS vaccines_no_delete BEFORE DELETE ON vaccines
BEGIN SELECT RAISE(ABORT, 'vaccines e append-only'); END;
CREATE TRIGGER IF NOT EXISTS vaccines_immutable
BEFORE UPDATE OF id, state, attack_id, scenario, mitre_technique, verdict, payload, created_at ON vaccines
BEGIN SELECT RAISE(ABORT, 'vaccines so aceita superseded_by'); END;
```
Comportamento confirmado com sonda local (sqlite 3.53.1, esquema equivalente): `ON CONFLICT(id) DO NOTHING` -> `rowcount` 1 na 1.ª vez e 0 no duplicado; `UPDATE ... SET superseded_by` -> `rowcount` 1 (permitido); `UPDATE ... SET state='x'`, `UPDATE ... SET payload='y'` e `DELETE` -> `IntegrityError` ("blocked ... IntegrityError") [VERIFIED: sonda `sq.py` corrida nesta sessão]. `json_valid` é função embutida (JSON1 incluída no SQLite >= 3.38) [ASSUMED: não sondei `json_valid` isoladamente; a sonda não a usou. Se o planner quiser a garantia, o teste do store deve inserir `payload='x'` e esperar `IntegrityError`.]

### Pattern 2: Política de `superseded_by` (generaliza D-06)
**What:** para cada vaccine emitida X de um `attack_id` A, na mesma transação: (a) marcar como substituídas por X todas as outras linhas de A que ainda não apontem para X; (b) limpar `superseded_by` de X se estiver preenchido. Assim "a atual" de um ataque é sempre a última emitida pelo motor, também no vaivém `partial -> not_detected -> partial` (o id volta ao antigo, que já existe e estava marcado como substituído).
```sql
UPDATE vaccines SET superseded_by = :x
 WHERE attack_id = :a AND id != :x AND (superseded_by IS NULL OR superseded_by != :x);
UPDATE vaccines SET superseded_by = NULL WHERE id = :x AND superseded_by IS NOT NULL;
```
Idempotente: se nada mudou, os dois `UPDATE` não tocam em linhas. D-06 só fala de `partial -> not_detected`, mas `not_detected -> partial` (um alerta atrasado chega) também muda o id (o conjunto em falta encolhe) [VERIFIED: `vaccine_engine.py:73-79` e `:233` — `missing` calcula-se de `expected` e `achieved`]. D-07 mantém-se: `detected` não emite vaccine, logo nada é tocado.

### Pattern 3: Loop de background (padrão do repo)
**What:** coroutine `while True: ciclo; await asyncio.sleep(intervalo)`, criada no `startup` e guardada em `app.state.vaccine_task`. O ciclo é uma função separada (`_run_vaccine_cycle`) **chamável diretamente nos testes** porque os testes fazem `main.app.router.on_startup.clear()` [VERIFIED: `test_metrics_api.py:23`]. Escritas SQLite via `run_in_threadpool` (como `_incidents_call`). Falhas: `except Exception` por iteração, `logger.exception`, estado com código estável; `asyncio.CancelledError` não é apanhada por `except Exception`.
**Startup atual** (`main.py:379-399`): a função `_start_system_monitor` já cria 3 tasks; acrescentar a quarta ali ou num segundo `@app.on_event("startup")`. Se acrescentar uma segunda função, os testes continuam a limpá-la com `on_startup.clear()`.

### Pattern 4: Resposta de lista com `generator`
Recomendação (discricionário, mas o critério de sucesso 4 pede "Indexer indisponível" como código estável e o `GET` não toca no Indexer):
```json
{
  "available": true,
  "reason": null,
  "total": 3, "limit": 200, "offset": 0,
  "vaccines": [ { "...vaccine do motor...", "state": "proposed", "superseded_by": null, "created_at": "..." } ],
  "generator": { "status": "ok", "last_run_at": "...", "last_success_at": "...", "error_code": null,
                 "alerts_truncated": false }
}
```
`reason` = `"no_data"` só quando o store tem **zero linhas** (qualquer filtro à parte); lista vazia por causa de filtros devolve `reason: null` e `total: 0` (não é "Sem dados"). `generator.status` ∈ {`never_run`, `ok`, `no_data`, `error`}; `error_code` ∈ {`indexer_unavailable`, `ml_model_unavailable`, `attack_outside_alert_window`, `attack_log_unreadable`, `incidents_unavailable`, `store_unavailable`, `source_unavailable`, `unexpected_error`, `null`} (os três primeiros já existem em `main._build_attack_registry`: `correlation["error_code"] = "attack_outside_alert_window"` (`main.py:1517`), `"ml_model_unavailable"` (`:1520`), `"indexer_unavailable"` (`:1526`)). Nunca texto de exceção. O estado vive em memória (dict no `main.py` ou pequena classe em `vaccine_ingest`); depois de um reinício começa em `never_run`, o que é verdadeiro e suficiente para diagnóstico.
Detalhe: `GET /api/vaccines/{id}` devolve `{"vaccine": {...}}` (como `/api/attacks/{id}` devolve `{"attack": ...}`), **incluindo** vaccines substituídas (senão os links antigos dariam 404).

### Anti-Patterns to Avoid
- **Gravar dentro do `GET`** (ou criar tabelas/linhas): só o loop escreve. (Nota: `_connect` cria o ficheiro e o esquema na primeira ligação, também a de um `GET`; é benigno e igual ao `IncidentStore`, mas fica registado. Não cachear `_schema_ready` como no `IncidentStore` torna o store resistente a o ficheiro ser apagado em runtime; custo desprezável.)
- **Adicionar `state`/`superseded_by`/`created_at` ao dict antes de `validate_vaccine`**: o validador exige `set(v) == VACCINE_KEYS` [VERIFIED: `vaccine_engine.py:370-371` `if set(v) != VACCINE_KEYS: problems.add("vaccine_keys")`]. Validar o dict do motor, só depois gravar; os campos extra juntam-se na leitura.
- **Passar o attack log inteiro sem filtro** (ver Pitfall 1 e 5).
- **Chamar `list_incidents` com argumentos posicionais** (Pitfall 3).

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Id da vaccine | novo hash | `vaccine_engine.vaccine_id` / o `id` que o motor já devolve | D-03 (Fase 12), literais golden nos testes. |
| Validação do conteúdo antes de gravar | validador próprio | `vaccine_engine.validate_vaccine` | Contrato fechado, allowlists; a docstring do motor manda chamá-lo. |
| Dedup | consulta "existe?" antes de inserir | PK + `ON CONFLICT(id) DO NOTHING` | Atómico, sem corrida entre o loop e outra thread. |
| "Estado só `proposed`" | verificação só em Python | `CHECK` + triggers no SQLite | Sobrevive a um bug futuro no código e a uma escrita acidental. |
| Autenticação | comparação manual de key | `_REQUIRE_API_KEY` (`secrets.compare_digest`) | `main.py:170-179`. |
| Erros estáveis | `str(exc)` na resposta | constantes (`entry_not_found`, `store_unavailable`) | Critério de sucesso 4. |

**Key insight:** o motor já faz toda a lógica de domínio; esta fase só tem de ser **estritamente idempotente e honesta** (nunca gravar o que não foi medido, nunca vazar erros).

## Runtime State Inventory

Não é uma fase de rename/refactor/migração (greenfield: ficheiro novo). Única nota: o ficheiro `scripts/vaccines.sqlite3` e o seu `-journal` são estado de runtime novo, a acrescentar ao `.gitignore` (as linhas atuais cobrem `scripts/incidents.sqlite3` e `scripts/incidents.sqlite3-journal`, não este) [VERIFIED: `.gitignore`]. Nota extra: o `.gitignore` também ignora `CLAUDE.md`, por isso as alterações de documentação da Fase 14 ao `CLAUDE.md` não ficam em git.

## Common Pitfalls

### Pitfall 1: Vaccine falsa e permanente por avaliar um ataque demasiado cedo (a mais grave)
**What goes wrong:** o loop corre a cada ~300 s; um ataque lançado há segundos ainda não tem alertas (Wazuh, ML, deteção de rede) dentro da janela de correlação de 300 s; o registo dá `not_detected`; a vaccine é gravada e **nunca mais é corrigida** (D-07: se o ataque passa a `detected`, a vaccine mantém-se).
**Why it happens:** `build_attack_registry` calcula contra os alertas que existem *agora*; `verdict()` devolve `not_detected` sempre que `achieved` está vazio e não há truncagem [VERIFIED: `attack_registry.py:81-89` `if not achieved: return "unknown" if alerts_truncated else "not_detected"`]. Como cada ataque é avaliado pela primeira vez entre 0 e 300 s depois do lançamento, o caso é a regra, não a exceção.
**How to avoid:** filtrar o attack log **antes** do registo para só incluir ataques com `timestamp <= agora - VACCINE_SETTLE_SECONDS`. Recomendação: variável `SENTRYLENS_VACCINE_SETTLE_SECONDS`, omissão 600 (2x `DEFAULT_WINDOW_SECONDS`, folga para a latência de indexação) [ASSUMED: o valor 600 é um palpite razoável, não medido; a janela de 300 s é [VERIFIED: `redblue_correlator.py:35` `DEFAULT_WINDOW_SECONDS = 300`]]. Teste: ataque com 60 s não gera vaccine; com 700 s e sem alertas gera.
**Warning signs:** vaccines `not_detected` em ataques que o Attack Registry mostra depois como `detected`.

### Pitfall 2: `INSERT OR IGNORE` engole falhas de `CHECK`
**What goes wrong:** com `INSERT OR IGNORE`, uma linha que viole o `CHECK(state='proposed')` é descartada em silêncio (rowcount 0), indistinguível de "já existia".
**Evidence:** sonda local: `INSERT OR IGNORE INTO v(id,state,payload) VALUES('vac-2','applied','{}')` -> `rowcount 0` sem erro; com `INSERT ... ON CONFLICT(id) DO NOTHING` o mesmo estado inválido levanta `IntegrityError` [VERIFIED: sonda `sq.py`, saída "or ignore bad state rowcount 0" / "conflict-clause bad state raises: IntegrityError"].
**How to avoid:** usar `ON CONFLICT(id) DO NOTHING`. Cumpre D-04 (dedup por PK) sem esconder violações. Se o utilizador quiser a letra de D-04, é uma discrepância a confirmar (ver A1).

### Pitfall 3: `list_incidents` posicional desalinhado -> `incident_ids` sempre vazios
**What goes wrong:** `main.py:1535` chama `run_in_threadpool(incident_store.list_incidents, None, None, None, 100000, 0)`. A assinatura atual (trabalho por commitar) é `list_incidents(self, status=None, severity=None, since_iso=None, assigned_to=None, limit=100, offset=0)` [VERIFIED: `incident_store.py:334-336`]. Os 5 posicionais caem em `status, severity, since_iso, assigned_to=100000, limit=0`: filtra por `assigned_to = 100000` e limita a 0 linhas. Resultado: zero incidentes, `incidents_available` fica `True` (nenhum erro), e todas as vaccines gravadas perdem `origin.incident_ids` (que o store congela, ver Pitfall 6).
**Evidence:** `test_attack_registry.py` falha hoje 2 checks ("lista: ataque 1 com incidente ligado", "detalhe: 200 com esperado vs real e incidentes") [VERIFIED: corrida nesta sessão com `.venv/Scripts/python.exe -X utf8 test_attack_registry.py`]; já estava registado em `.planning/phases/12-motor-de-vaccines/deferred-items.md`.
**How to avoid:** incluir no plano 13-02 uma tarefa para trocar a chamada por argumentos nomeados (`limit=100000, offset=0`; `run_in_threadpool` aceita `functools.partial` ou uma pequena lambda) e um teste do ciclo que afirma `origin.incident_ids` não vazio quando há incidente ligado. Isto toca em `main.py` num ponto que está no diff por commitar de outro trabalho (JEV/analista); coordenar para não pisar esse diff.

### Pitfall 4: Vaivém de id deixa a vaccine "atual" marcada como substituída
**What goes wrong:** `partial` (id A) -> `not_detected` (id B): A fica `superseded_by=B`. Se depois o ataque voltar a `partial` (alertas voltam a entrar na janela, outro modelo ML), o motor emite A de novo; `ON CONFLICT DO NOTHING` não faz nada, e a lista mostra B como atual e A escondida.
**How to avoid:** a política do Pattern 2 (limpar `superseded_by` do emitido e apontar os outros para ele). Teste: sequência A, B, A e verificar que só A está ativa.

### Pitfall 5: Janela de alertas vs. teto de 1000 alertas
**What goes wrong:** `ATTACK_ALERTS_SIZE = 1000` e o Indexer devolve os mais recentes primeiro (`"sort": [{"@timestamp": {"order": "desc"}}]`) [VERIFIED: `wazuh_client.py:126-130`; `main.py:1495`]. Num laboratório ruidoso, com janela de 168 h, o teto é atingido, `alerts_truncated=True`, e todo ataque sem correspondência vira `unknown` (não gera vaccine), enquanto um `partial` ainda sai (com o risco de ser parcial só por truncagem).
**How to avoid:** (a) tornar a janela configurável (`SENTRYLENS_VACCINE_WINDOW_HOURS`, omissão 168 como `/api/attacks`, máximo `ATTACK_MAX_HOURS = 720` [VERIFIED: `main.py:1496`]); (b) registar `alerts_truncated` em `generator`; (c) **não** bloquear a gravação por truncagem (senão num lab ruidoso nunca grava), mas documentar. Decisão a confirmar em A3.
**Warning signs:** `generator.alerts_truncated == true` de forma persistente e nenhuma vaccine `not_detected`.

### Pitfall 6: Congelamento do `origin` na primeira gravação
**What goes wrong:** `origin.incident_ids` e `origin.evidence` mudam com o tempo (um incidente liga-se mais tarde). Com PK + `DO NOTHING` o primeiro snapshot fica para sempre.
**How to avoid:** assumir explicitamente "origem tal como no momento da proposta" (consistente com "append-only" e com `created_at`). Mitiga-se com o settle do Pitfall 1 (os incidentes já existem na maioria dos casos) e saltando o ciclo se `incidents_available` for `False` (código `incidents_unavailable`, sem gravar), porque gravar sem incidentes seria congelar uma origem incompleta. Alternativa (atualizar `origin` ao reprocessar) viola a imutabilidade pedida em VAC-05 e o trigger; não recomendada.

### Pitfall 7: Erros SQLite e JSON corrompido
**What goes wrong:** `sqlite3.Error` cobre ficheiro ilegível/bloqueado/esquema partido, mas um `payload` corrompido levanta `json.JSONDecodeError` (subclasse de `ValueError`), não `sqlite3.Error`, e acabaria em 500 com traceback no log mas resposta genérica do FastAPI.
**How to avoid:** o mapeamento da rota apanha `(sqlite3.Error, ValueError)` -> `HTTPException(503, "store_unavailable")` e faz `logger.exception` (detalhe só no log). Teste: store com `MagicMock(side_effect=sqlite3.OperationalError("db partida"))` como em `test_metrics_api.py:134-144`, e verificar que `"db partida"` não aparece em `r.text`.

### Pitfall 8: Métodos de escrita
**What goes wrong:** quem escrever um teste "POST devolve 405" e achar que `401` aparece primeiro. Sem rota POST registada, o FastAPI responde `405 Method Not Allowed` antes de correr dependências. O CORS permite `allow_methods=["GET", "POST"]` [VERIFIED: `main.py:222`] mas isso só afeta o preflight; não cria rota.
**How to avoid:** o teste do critério 3 deve afirmar `status_code == 405` para POST/PUT/PATCH/DELETE nas duas rotas, **e** que a contagem de linhas e o conteúdo do store não mudaram, **e** (introspeção) que `main.app.routes` não tem nenhuma rota `/api/vaccines*` com método fora de `{GET, HEAD}`. [ASSUMED: 405 vs 401 não foi testado nesta sessão; o teste do plano deve fixar o que realmente sai.]

## Code Examples

### Rotas (molde: `/api/attacks` e `/api/attack-library`)
```python
# Source: padrão de main.py:1557-1637 (list_attacks / get_attack_library_item)
from vaccine_engine import VACCINE_ID_RE
from vaccine_store import VaccineStore

@app.get("/api/vaccines", dependencies=_REQUIRE_API_KEY)
async def list_vaccines(
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
    attack_id: int | None = Query(None, ge=1, le=999_999_999),
    technique: str | None = Query(None, pattern=r"^T\d{4}(\.\d{3})?$", description="Técnica MITRE, ex. T1110"),
    include_superseded: bool = Query(False),
):
    try:
        rows, total, store_total = await run_in_threadpool(
            vaccine_store.list_vaccines, attack_id, technique, include_superseded, limit, offset)
    except (sqlite3.Error, ValueError):
        logger.exception("Vaccines: store ilegível")
        raise HTTPException(status_code=503, detail="store_unavailable")
    return {"available": store_total > 0, "reason": None if store_total else "no_data",
            "total": total, "limit": limit, "offset": offset, "vaccines": rows,
            "generator": vaccine_loop_state.snapshot()}

@app.get("/api/vaccines/{vaccine_id}", dependencies=_REQUIRE_API_KEY)
async def get_vaccine(vaccine_id: Annotated[str, Path(pattern=VACCINE_ID_RE)]):
    try:
        vaccine = await run_in_threadpool(vaccine_store.get_vaccine, vaccine_id)
    except (sqlite3.Error, ValueError):
        logger.exception("Vaccines: store ilegível")
        raise HTTPException(status_code=503, detail="store_unavailable")
    if vaccine is None:
        raise HTTPException(status_code=404, detail="entry_not_found")
    return {"vaccine": vaccine}
```
Notas: `VACCINE_ID_RE` é uma `str` `r"^vac-[0-9a-f]{12}$"` [VERIFIED: `vaccine_engine.py:45`], serve diretamente em `Path(pattern=...)`; id mal formado dá 422 (mesma convenção de `test_attack_library.py:231-232`). O `generator` no envelope alinha com `correlation` em `/api/attacks`.

### Escrita idempotente (só no loop)
```python
# Source: sonda sqlite local nesta sessão; padrão de incident_store.py (RLock + _tx)
def upsert_batch(self, vaccines: list[dict], now_iso: str) -> dict:
    counts = {"inserted": 0, "existing": 0}
    with self.lock, self._tx() as conn:           # uma transação: tudo ou nada
        for v in vaccines:
            origin = v["origin"]
            cur = conn.execute(
                "INSERT INTO vaccines (id, attack_id, scenario, mitre_technique, verdict, payload, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING",
                (v["id"], origin["attack_id"], origin["scenario"], origin["mitre_technique"], v["verdict"],
                 json.dumps(v, ensure_ascii=False, sort_keys=True), now_iso))
            counts["inserted" if cur.rowcount == 1 else "existing"] += 1
            conn.execute("UPDATE vaccines SET superseded_by = ? WHERE attack_id = ? AND id != ? "
                         "AND (superseded_by IS NULL OR superseded_by != ?)",
                         (v["id"], origin["attack_id"], v["id"], v["id"]))
            conn.execute("UPDATE vaccines SET superseded_by = NULL WHERE id = ? AND superseded_by IS NOT NULL", (v["id"],))
    return counts
```

### Leitura com ordem estável e filtros parametrizados
```python
# Ordem: attack_id é max+1 (monótono) -> "mais recentes primeiro"; o motor também ordena por attack_id desc
# (vaccine_engine.py:253 `vaccines.sort(key=lambda v: v["origin"]["attack_id"], reverse=True)`).
ORDER = "ORDER BY attack_id DESC, created_at DESC, id"
# WHERE montado só com cláusulas fixas e parâmetros `?`; nunca f-string com valores do pedido.
# `total` = COUNT(*) com os MESMOS filtros; `store_total` = COUNT(*) sem filtros (decide reason="no_data").
```
Ao ler: `vaccine = json.loads(row["payload"])`, depois `vaccine["state"] = row["state"]`, `vaccine["superseded_by"] = row["superseded_by"]`, `vaccine["created_at"] = row["created_at"]` (campos de store, fora do contrato do motor).

### Seleção de ataques estabilizados (puro, testável)
```python
def select_settled_entries(attack_log, now, window_hours, settle_seconds, parse):
    """Entradas com settle_seconds <= idade <= window_hours. `parse` = incident_engine.parse_timestamp.
    Entradas sem timestamp válido ficam de fora (o registo contá-las-ia como inválidas, sem efeito aqui)."""
```

### Variáveis de ambiente (recomendação; nomes discricionários)
| Variável | Omissão | Regra |
|----------|---------|-------|
| `SENTRYLENS_VACCINES_DB_PATH` | `scripts/vaccines.sqlite3` | relativo é resolvido contra `os.path.dirname(os.path.abspath(__file__))` do módulo, nunca o cwd (D-05; padrão de `RBAC_BASELINE_PATH` descrito em CLAUDE.md) |
| `SENTRYLENS_VACCINE_INTERVAL_SECONDS` | 300 | inteiro; inválido/<30 -> omissão (nunca derruba o arranque) |
| `SENTRYLENS_VACCINE_WINDOW_HOURS` | 168 | 1..`ATTACK_MAX_HOURS` (720) |
| `SENTRYLENS_VACCINE_SETTLE_SECONDS` | 600 | >= `DEFAULT_WINDOW_SECONDS` |

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `INSERT OR IGNORE` | `INSERT ... ON CONFLICT(target) DO NOTHING` (upsert, SQLite >= 3.24) | 2018 | Ignora só o conflito nomeado, não outras violações de constraint. |
| Cache `_schema_ready` por instância | `CREATE ... IF NOT EXISTS` em cada ligação | — | Sobrevive a apagar o ficheiro; custo desprezável. |

**Deprecated/outdated:** `@app.on_event("startup")` está em uso no repo (`main.py:379`); manter o padrão existente em vez de migrar para `lifespan` nesta fase.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Trocar `INSERT OR IGNORE` por `ON CONFLICT(id) DO NOTHING` é aceitável para o utilizador (D-04 menciona `INSERT OR IGNORE` literalmente). | Pitfall 2 | Baixo: mesma garantia de "sem duplicados", mais segura. Confirmar na revisão do plano. |
| A2 | Um atraso de estabilização (`SETTLE`, omissão 600 s) antes de avaliar um ataque é desejável e não contradiz D-01/D-02. O valor 600 não foi medido. | Pitfall 1 | Sem ele, vaccines `not_detected` falsas e permanentes; com valor demasiado alto, vaccines aparecem tarde. |
| A3 | Gravar mesmo com `alerts_truncated=True` (só sai `partial`) é aceitável; alternativa é recusar o ciclo. | Pitfall 5 | Vaccine `partial` possivelmente falsa por truncagem; recusar poderia impedir qualquer gravação num lab ruidoso. |
| A4 | A janela do loop (168 h, igual a `/api/attacks`) deve coincidir com a que o analista vê no Attack Registry. | Pitfall 5 | Veredito do loop divergente do registo mostrado. |
| A5 | `generator` exposto no envelope da lista (em vez de só log). | Pattern 4 | O critério 4 ("Indexer indisponível" chega como código estável) fica por cumprir se só houver log. |
| A6 | `json_valid` está disponível na build de SQLite do `.venv` e `405` (não `401`) é a resposta a métodos de escrita. | Pattern 1 / Pitfall 8 | Teste do plano falha e ajusta-se; baixo. |
| A7 | Não validar `validate_vaccine` na leitura (só na escrita). Uma linha adulterada diretamente no ficheiro seria servida. | Security | Quem escreve no ficheiro também forja o attack log; mesmo limite do SHA-256 dos `.pkl` (CLAUDE.md). Validar na leitura é opcional e barato. |

## Open Questions

1. **Confirmar settle/janela/truncagem (A2-A4).**
   - What we know: o motor é fail-closed para `unknown`, mas não conhece a latência de ingestão.
   - What's unclear: valores por omissão desejados.
   - Recommendation: planear com os valores acima e expor-os por variável de ambiente; o utilizador ajusta sem mudar código.

2. **Vaccines `network` quando a captura de rede não está configurada.**
   - What we know: `correlation["network_capture_configured"]` existe (`main.py:1549`), o motor ignora-o, e o default da Attack Library é só `rule, ml` [VERIFIED: `attack_library.yaml` linhas 18, 31, 43, 55, 68 `expected_sensors: [rule, ml]`]; só um `expected` com `network` no attack log cria a lacuna.
   - What's unclear: se sem VM SSH essa lacuna é real.
   - Recommendation: fora de âmbito; registar na dívida (não alterar o motor nesta fase). Se aparecer, o loop pode ignorar propostas só-`network` quando `network_capture_configured` é `False`.

3. **Quem trata o diff por commitar em `main.py`/`incident_store.py`.**
   - Recommendation: a tarefa que corrige `list_incidents` deve ser mínima (argumentos nomeados) e o executor deve verificar `git status`/`git diff scripts/main.py` antes, para não misturar commits com o trabalho JEV/analista.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Python `.venv` (`scripts/.venv`) | testes e backend | ✓ | 3.12.14 | — |
| `sqlite3` stdlib | store | ✓ | 3.53.1 (venv) | — |
| FastAPI/TestClient | rotas/testes | ✓ | instalado (os testes existentes correm) | — |
| Wazuh Indexer / lab | só em produção; **não** necessário para testes (tudo mockado) | n/a | — | `AsyncMock` |

**Missing dependencies with no fallback:** none
**Missing dependencies with fallback:** none

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Scripts standalone sem pytest (`check(label, cond)`, `sys.exit(1)` se falhar) [VERIFIED: `test_metrics_api.py:28-31, 147-152`] |
| Config file | none |
| Quick run command | `cd scripts && .venv/Scripts/python.exe -X utf8 test_vaccine_store.py` (idem para os outros) |
| Full suite command | `cd scripts && .venv/Scripts/python.exe run_all_tests.py` (ou `... run_all_tests.py vaccine`) |

Convenções obrigatórias para os testes de rotas: `os.environ.setdefault("SENTRYLENS_API_KEY", ...)` **antes** de `import main`; `main.app.router.on_startup.clear()`; substituir `main.vaccine_store`, `main.indexer_client` (`MagicMock` + `AsyncMock`), `main.ml_anomalies.load_model`/`build_ml_anomalies_report`, `main.load_attack_log`, `main.incident_store`, `main.vm_ssh_client = None` (molde `wire()` em `test_metrics_api.py:64-80`). IPs só de documentação (192.0.2.x / 203.0.113.x). Stores sempre em `tempfile` diretórios.

### Phase Requirements -> Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| VAC-05 | gravar 1.ª vez insere; reprocessar não acrescenta linhas | unit | `python test_vaccine_store.py` | ❌ Wave 0 |
| VAC-05 | "reiniciar": nova instância `VaccineStore` sobre o mesmo ficheiro devolve a mesma lista | unit | idem | ❌ Wave 0 |
| VAC-05 | `UPDATE state`, `UPDATE payload`, `DELETE` abortam; `state` != `proposed` falha | unit | idem | ❌ Wave 0 |
| VAC-05 | `superseded_by`: partial->not_detected, not_detected->partial, vaivém A-B-A; `detected` não toca | unit | idem | ❌ Wave 0 |
| VAC-05 | vaccine inválida (`validate_vaccine != []`) nunca é gravada; ciclo conta `rejected` | unit | `python test_vaccine_ingest.py` | ❌ Wave 0 |
| VAC-05 | settle: ataque com 60 s não gera; janela: ataque fora de `window_hours` não gera | unit | idem | ❌ Wave 0 |
| VAC-05 | ciclo com Indexer a falhar não apaga nada e deixa `error_code == "indexer_unavailable"` sem texto de exceção | integration (mock) | idem | ❌ Wave 0 |
| VAC-05 | `origin.incident_ids` não vazio quando há incidente ligado (regressão do fix de `list_incidents`) | integration (mock) | idem | ❌ Wave 0 |
| VAC-06 | sem key -> 401 nas 2 rotas; key errada -> 401 | integration | `python test_vaccines_api.py` | ❌ Wave 0 |
| VAC-06 | store vazio -> 200, `vaccines == []`, `reason == "no_data"` | integration | idem | ❌ Wave 0 |
| VAC-06 | lista/filtros `attack_id`, `technique`, `include_superseded`, `limit`/`offset`, ordem, `total` | integration | idem | ❌ Wave 0 |
| VAC-06 | detalhe 200 com regra e origem; id válido inexistente 404 `entry_not_found`; id malformado 422 | integration | idem | ❌ Wave 0 |
| VAC-06 | POST/PUT/PATCH/DELETE nas 2 rotas -> 405 e store inalterado; nenhuma rota `/api/vaccines*` com método de escrita; cada rota `/api/vaccines*` tem `require_api_key` nas dependências | integration | idem | ❌ Wave 0 |
| VAC-06 | store a falhar (`sqlite3.OperationalError("db partida")`, e `payload` corrompido) -> 503 `store_unavailable`; resposta sem "db partida", "Traceback", ".sqlite3" nem caminhos | integration | idem | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** o ficheiro de teste da tarefa (`python test_vaccine_store.py` etc.), < 5 s cada.
- **Per wave merge:** `python run_all_tests.py vaccine` e `python run_all_tests.py attack` (o fix de `list_incidents` mexe no Attack Registry).
- **Phase gate:** `python run_all_tests.py` verde antes de `/gsd-verify-work`. Nota: `test_attack_registry.py` hoje falha 2 checks por causa do Pitfall 3; o fix deve devolvê-lo a verde.

### Wave 0 Gaps
- [ ] `scripts/test_vaccine_store.py` — VAC-05 (store)
- [ ] `scripts/test_vaccine_ingest.py` — VAC-05 (ciclo, settle, janela, falhas)
- [ ] `scripts/test_vaccines_api.py` — VAC-06 (rotas, garantias negativas)
- Sem instalação de framework (já existe). Sem registo em `run_all_tests.py` (glob automático).

## Security Domain

`security_enforcement` está ativo (ASVS nível 1) [VERIFIED: `.planning/config.json` `"security_enforcement": true, "security_asvs_level": 1`].

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | parcial | API key por header, `secrets.compare_digest` (já existe, `require_api_key`) |
| V3 Session Management | no | sem sessões |
| V4 Access Control | yes | `dependencies=_REQUIRE_API_KEY` em **cada** rota (nunca a nível de app); sem rotas de escrita |
| V5 Input Validation | yes | `Path(pattern=VACCINE_ID_RE)`, `Query(ge/le/pattern)`; SQL só com parâmetros `?` |
| V6 Cryptography | no | o id é determinístico, não autentica (nota do motor); sem segredos novos |
| V7 Error Handling | yes | códigos estáveis (`entry_not_found`, `store_unavailable`, `generator.error_code`); `logger.exception` só no log |
| V12/V13 API | yes | CORS já restrito a loopback; só GET |

### Known Threat Patterns for FastAPI + SQLite

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| SQL injection via filtros (`technique`, `attack_id`, `id`) | Tampering | regex/limites no parâmetro + `?` no SQL; nunca f-string com valores do pedido (as cláusulas `WHERE` são strings fixas escolhidas por código) |
| Divulgação de erro (traceback, caminho, SQL) | Information disclosure | mapear `sqlite3.Error`/`ValueError` -> `503 store_unavailable`; códigos de erro do loop vêm de constantes, nunca de `str(exc)` |
| Alteração do estado por HTTP | Tampering / Elevation | nenhuma rota de escrita; triggers recusam `UPDATE`/`DELETE` fora de `superseded_by`; `CHECK(state='proposed')` |
| Conteúdo executável numa vaccine gravada | Tampering | `validate_vaccine` (allowlists, contrato fechado) antes de gravar |
| Ficheiro do store exposto pelo frontend estático | Information disclosure | `serve_frontend.py` tem whitelist fixa; o ficheiro fica em `scripts/` e no `.gitignore` |
| Adulteração direta do ficheiro SQLite | Tampering | fora de âmbito (mesmo limite que os `.pkl`, ver CLAUDE.md); o trigger só protege contra o código da app |
| Negação de serviço por `limit` enorme | DoS | `limit` <= 500, `offset` >= 0 |

## Sources

### Primary (HIGH confidence) — todo o código lido nesta sessão
- `scripts/vaccine_engine.py` (inteiro) — contrato do motor, `VACCINE_ID_RE`, `validate_vaccine`
- `scripts/incident_store.py` (inteiro) — molde do store, assinatura de `list_incidents`
- `scripts/main.py` (linhas 140-420, 1313-1340, 1480-1700) — startup, `_REQUIRE_API_KEY`, `_build_attack_registry`, rotas
- `scripts/attack_registry.py` (linhas 20-195) — `verdict`, `build_attack_registry`
- `scripts/wazuh_client.py` (`get_recent_alerts`), `scripts/feature_extractor.py` (`load_attack_log`)
- `scripts/test_metrics_api.py`, `scripts/test_attack_library.py`, `scripts/run_all_tests.py`, `.gitignore`, `.planning/config.json`
- Sonda SQLite local (nesta sessão): `ON CONFLICT DO NOTHING` vs `INSERT OR IGNORE`, triggers `BEFORE UPDATE OF`/`BEFORE DELETE`, CHECK
- Corridas locais: `test_attack_registry.py` (2 falhas), `test_vaccine_engine.py` (verde)

### Secondary / Tertiary
- Nenhuma fonte web usada (domínio inteiramente in-repo + stdlib).

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — stdlib + dependências já em uso.
- Architecture: HIGH — réplica de padrões existentes no repo, comportamento SQLite confirmado por sonda.
- Pitfalls: HIGH para 2, 3, 4, 7 (confirmados em código/sonda); MEDIUM para 1 e 5 (derivados do desenho, valores por omissão não medidos).

**Research date:** 2026-10-12
**Valid until:** 2026-11-11 (30 dias; sem dependências voláteis)
