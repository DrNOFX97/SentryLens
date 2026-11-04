# Phase 16: API de decisão - Pattern Map

**Mapped:** 2026-10-29
**Files analyzed:** 6 (3 backend, 3 testes)
**Analogs found:** 6 / 6

Todos os analogs abaixo são ficheiros git-tracked em `scripts/` (sem espelhos gitignored).

## File Classification

| Ficheiro novo/modificado | Role | Data Flow | Analog mais próximo | Qualidade |
|---|---|---|---|---|
| `scripts/main.py` (rota `POST /api/vaccines/{id}/decision`) | route/controller | request-response (write) | `GET /api/vaccines/{id}` (main.py:1990) + `create_analyst`/`update_analyst` (1542/1572) | role-match |
| `scripts/main.py` (`state` + contagens em `GET /api/vaccines`) | route | request-response (read) | `list_vaccines` (main.py:1956) | exact |
| `scripts/vaccine_store.py` (leitura nova de contagens por estado) | service/store | CRUD read-only | `VaccineStore.list_vaccines` / `get_vaccine` (265-308) | exact |
| `scripts/test_vaccine_decision_api.py` (novo) | test | request-response | `scripts/test_vaccines_api.py` (+ `test_vaccine_decision_store.py` para fixtures de store) | exact |
| `scripts/test_cors.py` (preflight da rota nova) | test | request-response | o próprio ficheiro (linhas 36-62) | exact |
| `scripts/test_vaccines_api.py` (envelope com state/decision/contagens) | test | request-response | o próprio ficheiro | exact |

## Pattern Assignments

### `scripts/main.py` — `POST /api/vaccines/{vaccine_id}/decision` (route, request-response write)

**Analog:** `get_vaccine` (main.py:1990-2001), colocar a rota logo a seguir.

**Padrão de rota + 404/503 estáveis** (main.py:1990-2001):
```python
@app.get("/api/vaccines/{vaccine_id}", dependencies=_REQUIRE_API_KEY)
async def get_vaccine(vaccine_id: Annotated[str, Path(pattern=VACCINE_ID_RE)]):
    """Detalhe ... 404 com código estável ... 503 estável ..."""
    try:
        vaccine = await run_in_threadpool(vaccine_store.get_vaccine, vaccine_id)
    except (sqlite3.Error, ValueError):
        logger.exception("Vaccines: store ilegível")
        raise HTTPException(status_code=503, detail="store_unavailable")
    if vaccine is None:
        raise HTTPException(status_code=404, detail="entry_not_found")
    return {"vaccine": vaccine}
```
ATENÇÃO: o nome `get_vaccine` já é uma função de rota em `main.py`; a nova rota deve chamar `vaccine_store.get_vaccine` (método), nunca o nome global. Usar um nome de função distinto, p.ex. `decide_vaccine_route`, para não sombrear `vaccine_store.decide_vaccine`.

**Imports já em main.py** (linha 96): `from vaccine_engine import VACCINE_ID_RE, build_vaccine_candidates`. Acrescentar `import vaccine_decision` / `from vaccine_decision import VaccineDecisionError, INVALID_INPUT_CODES, CONFLICT_CODES, NOT_FOUND_CODES, validate_request`. `_now_iso()` existe (main.py:~1360, `datetime.now(timezone.utc).isoformat()` -> offset `+00:00`, aceite por `_is_utc_instant`).

**Padrão de validação do analista** (D-03/D-06): NÃO usar `_incidents_call` (main.py:1363-1370 dá 500 genérico). Copiar só o `run_in_threadpool` + `except sqlite3.Error`, mas com 503 `incidents_unavailable`:
```python
try:
    analyst = await run_in_threadpool(incident_store.get_analyst, analyst_id)   # dict | None; coluna `active` 0/1, `name`
except sqlite3.Error:
    logger.exception("Vaccines: base de incidentes ilegível")
    raise HTTPException(status_code=503, detail="incidents_unavailable")
if analyst is None: raise HTTPException(422, "analyst_not_found")
if not analyst["active"]: raise HTTPException(422, "analyst_inactive")
```
(`incident_store.get_analyst` em incident_store.py:451 devolve `dict(row)` de `soc_analysts` ou `None`.)

**Núcleo: chamada ao store e mapeamento** (contrato em vaccine_store.py:235-261 e vaccine_decision.py:45-49,57-68):
```python
now_iso = _now_iso()
try:
    await run_in_threadpool(
        vaccine_store.decide_vaccine, vaccine_id=vaccine_id, decision=..., decided_by=analyst["id"],
        decided_by_name=analyst["name"], reason=..., now_iso=now_iso)
except VaccineDecisionError as e:           # NÃO deriva de ValueError; apanhar ANTES de sqlite3.Error/ValueError
    if e.code in INVALID_INPUT_CODES: status = 422
    elif e.code in NOT_FOUND_CODES:   status = 404
    else:                             status = 409      # CONFLICT_CODES
    raise HTTPException(status_code=status, detail=e.code)
except (sqlite3.Error, ValueError):
    logger.exception("Vaccines: escrita da decisão falhou")
    raise HTTPException(status_code=503, detail="store_unavailable")
vaccine = await run_in_threadpool(vaccine_store.get_vaccine, vaccine_id)   # relê; mesmo try/503 que o GET
return {"vaccine": vaccine, "notice": "..."}
```
Notas: `decide_vaccine` já valida (`validate_request`, ordem fixa) e faz `BEGIN IMMEDIATE`; a rota não faz "ler, verificar, decidir". Passar `decided_by=analyst["id"]`, nunca o do corpo sem verificar. Se `get_vaccine` devolver `None` depois de decidir, tratar como 503 (não deve acontecer).

**Corpo à mão (D-04/D-09)**: sem análogo exato (todas as outras rotas POST usam Pydantic, p.ex. `create_analyst(body: AnalystCreate)` main.py:1542-1553 com `ValueError -> 422 detail=str(e)`). Receber `request: Request`, ler `await request.body()`, recusar `len > TETO` antes de `json.loads`, exigir `dict` com chaves exatamente `{"decision","analyst_id"}` + opcional `"reason"`; tudo o resto `422 detail="invalid_body"`. Pré-validar `analyst_id` com `vaccine_decision.ANALYST_ID_RE` antes de ir à base (evita lookup com lixo; id mal formado -> `invalid_body` ou `invalid_author`, decidir no plano). Verificar que `Request` está importado de fastapi em main.py (Grep no import); senão acrescentar. Sugestão do draft: função pura `(status, detail)` testável sem HTTP (16-01a).

**Autenticação:** por rota, `dependencies=_REQUIRE_API_KEY` (main.py:215). Nunca a nível de app.

**405:** nada a escrever; não registar PUT/PATCH/DELETE para o path (FastAPI devolve 405).

---

### `scripts/main.py` — `GET /api/vaccines` (state + contagens)

**Analog:** o próprio `list_vaccines` (main.py:1956-1987, excerto acima no ficheiro).

Alterações pontuais:
- Parâmetro novo ao estilo dos existentes (`technique` usa `Query(None, pattern=...)`): `state: Literal["proposed","approved","rejected"] | None = Query(None, description=...)` e passar `state=state` a `vaccine_store.list_vaccines` (a assinatura já aceita `state`, vaccine_store.py:265-267). Importar `Literal` (`typing`) se ainda não estiver.
- Envelope (main.py:1979-1987): acrescentar um campo de contagens (nome livre, D-11), `None` sem amostra. `available`/`reason` continuam por `store_total`. Manter o `except (sqlite3.Error, ValueError)` -> 503 `store_unavailable` também para a leitura de contagens (pode ir no mesmo `try`).
- Atualizar a docstring (menciona filtros) para incluir `state` e as contagens.

---

### `scripts/vaccine_store.py` — leitura de contagens por estado (store, read-only)

**Analog:** `list_vaccines`/`get_vaccine` (vaccine_store.py:265-317).

**Padrão a copiar** (leitura só-leitura, sem criar ficheiro, fragmentos fixos, valores por `?`):
```python
with self._read() as conn:
    if conn is None:
        return [], 0, 0                          # ficheiro inexistente -> sem amostra (aqui devolver None, não zeros)
    columns, source, state_expression = self._read_fragments(conn)
    clauses = ["v.superseded_by IS NULL"]        # D-11: só as vaccines atuais, SEM filtros state/attack_id/technique
    ...
    conn.execute("SELECT " + state_expression + " AS s, COUNT(*)" + source + " WHERE v.superseded_by IS NULL GROUP BY s")
```
Regras: usar `_read_fragments` (cobre ficheiro antigo sem a tabela `vaccine_decisions` = tudo `proposed`); devolver `{"proposed": n, "approved": n, "rejected": n}` com zeros explícitos para estados ausentes SÓ quando há amostra (store com >=1 linha na tabela `vaccines`); sem ficheiro ou `COUNT(*) FROM vaccines == 0` -> `None`. Parâmetros por nome; sem escrita; sem tocar no esquema. Contagem de "store vazio" segue `store_total` (vaccine_store.py:295).

---

### `scripts/test_vaccine_decision_api.py` (test, request-response)

**Analog:** `scripts/test_vaccines_api.py` (cabeçalho e estilo) — linhas 16-52, 94-107.

**Setup obrigatório** (test_vaccines_api.py:26-52):
```python
os.environ.setdefault("SENTRYLENS_API_KEY", "test-key-vaccines-api")   # ANTES de import main
from fastapi.testclient import TestClient
import main
from incident_store import IncidentStore
from vaccine_store import VaccineStore
main.app.router.on_startup.clear()
client = TestClient(main.app)
HEADERS = {"X-API-Key": os.environ["SENTRYLENS_API_KEY"]}
failures: list[str] = []
def check(label, condition):
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition: failures.append(label)
```
Ligação a stores temporários (test_vaccines_api.py:100-102): `main.incident_store = IncidentStore(os.path.join(tmp, "i.sqlite3"))`, `main.vaccine_store = VaccineStore(os.path.join(tmp, "v.sqlite3"))`. Semear vaccines com `VaccineStore.upsert_batch(vaccines, now_iso)` (fixtures de vaccines válidas em `test_vaccine_decision_store.py`/`test_vaccine_store.py`; ler antes de escrever) e analistas com `incident_store.create_analyst(id, name, tier, email, now_iso)` (mesma assinatura de main.py:1546) e `deactivate_analyst`. Falha a ler incidentes: `main.incident_store = MagicMock()` com `get_analyst.side_effect = sqlite3.OperationalError`. `sqlite3.Error` no store de vaccines: monkeypatch de `main.vaccine_store.decide_vaccine`. Sem "no mocks" do Wazuh necessário (nenhuma rota toca no Indexer). Fim: `sys.exit(1)` se `failures` (ver rodapé de test_cors.py:64-67). Lista de casos: 16-DESIGN-DRAFT §5 (1-11) + D-14 (varrimento AST de `main.py` + `vaccine_*.py` com `ast.parse`: sem `subprocess`/`os.system`/`ssh_client`; nenhuma rota `/api/vaccines/**` com apply/deploy/activate). `run_all_tests.py` apanha por glob.

Provas "GET sem efeitos": comparar bytes + `os.stat().st_mtime_ns` do ficheiro antes/depois; ficheiro inexistente continua inexistente (`os.path.exists`).

---

### `scripts/test_cors.py` (test)

**Analog:** o próprio (test_cors.py:36-62). Reutilizar `preflight()` mas parametrizar a URL (hoje fixa em `URL = "/api/incidents/INC-.../team"`):
```python
def preflight(client, method, origin=LOCAL):
    return client.options(URL, headers={"Origin": origin,
        "Access-Control-Request-Method": method,
        "Access-Control-Request-Headers": "x-api-key,content-type"})
```
Acrescentar um `VAC_URL = "/api/vaccines/vac-0123456789ab/decision"`, preflight `POST` -> 200 com `POST` em `access-control-allow-methods`, origem devolvida; `PUT`/`DELETE` -> 400 (padrão das linhas 56-57). `main.py:229` `allow_methods=["GET","POST","PATCH"]` NÃO muda (D-16).

---

### `scripts/test_vaccines_api.py` (test, atualização)

Confirmar que nenhum caso assume `state == "proposed"` fixo nem um envelope de chaves fechado (verificar com Grep `state` / `set(...keys...)`); acrescentar casos de `?state=` (cada valor, `?state=applied` -> 422), contagens no envelope (None sem amostra) e `total` com filtro. Manter `test_vaccines_frontend.py` verde (render com `approved`/`rejected`: `VAC_STATE_LABELS` só conhece `proposed`; só verificar o fallback, não editar frontend).

## Shared Patterns

### API key por rota
**Fonte:** `main.py:215` `_REQUIRE_API_KEY = [Depends(require_api_key)]`; usada como `@app.xxx(path, dependencies=_REQUIRE_API_KEY)` em cada rota. **Aplicar a:** a rota POST nova (nunca a nível de app).

### Códigos estáveis em `detail` (string) e 503 sem texto de exceção
**Fonte:** `get_vaccine` main.py:1994-2000: `logger.exception(...)` + `HTTPException(status_code=503, detail="store_unavailable")`. Nunca `str(e)` no corpo (o `create_analyst` main.py:1550/1552 faz `detail=str(e)`: NÃO copiar isso).

### Stores síncronos
**Fonte:** `await run_in_threadpool(vaccine_store.<metodo>, ...)` (main.py:1972, 1995). Aplicar a todas as chamadas a `vaccine_store` e `incident_store`.

### Exceções de decisão fora do ramo ValueError
**Fonte:** `vaccine_decision.VaccineDecisionError` (vaccine_decision.py:57-68) não herda de `ValueError`; o `except (sqlite3.Error, ValueError)` dos GET não a apanha. Na rota POST, apanhar `VaccineDecisionError` primeiro.

### Partição de códigos
**Fonte:** `vaccine_decision.py:45-49` `INVALID_INPUT_CODES` (422) / `NOT_FOUND_CODES` (404) / `CONFLICT_CODES` (409); mais os códigos novos da rota (`invalid_body`, `analyst_not_found`, `analyst_inactive` -> 422; `incidents_unavailable` -> 503).

### Testes standalone
**Fonte:** test_vaccines_api.py:26-52 e test_cors.py:13-33: env var antes de `import main`, `main.app.router.on_startup.clear()`, `check()` imprimindo `[OK   ]/[FALHOU]`, `sys.exit(1)` no fim se falhou. Windows/cp1252: sem emojis nos labels.

## No Analog Found

| Ficheiro | Role | Data Flow | Razão |
|---|---|---|---|
| leitura do corpo cru + teto de tamanho (D-04/D-09) | route | request-response | Todas as rotas POST existentes usam modelos Pydantic; não há rota que leia `request.body()` à mão. Usar o desenho do CONTEXT (D-04, D-09) e, opcionalmente, função pura `(status, detail)`. |
| teste de varrimento AST (D-14) | test | transform | Sem teste AST de rotas semelhante identificado nesta passagem; `model_registry` tem "gate por AST" (CLAUDE.md) — procurar o teste correspondente (`test_model_registry*.py`) como modelo de `ast.parse`. |

## Metadata

**Analog search scope:** `scripts/main.py`, `scripts/vaccine_store.py`, `scripts/vaccine_decision.py`, `scripts/incident_store.py`, `scripts/test_cors.py`, `scripts/test_vaccines_api.py`
**Pattern extraction date:** 2026-10-29
