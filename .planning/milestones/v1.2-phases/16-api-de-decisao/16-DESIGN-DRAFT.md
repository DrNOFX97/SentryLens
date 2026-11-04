# Phase 16: API de decisão - RASCUNHO de desenho

**Estado:** rascunho escrito durante a execução da fase 15. NÃO é um CONTEXT.md nem um PLAN.md; serve de entrada ao `/gsd-discuss-phase 16`.
**Fonte da fase 15:** `15-CONTEXT.md` e `15-01/02/03-PLAN.md` (planos, não código executado). Tudo marcado **[DEPENDE F15]** assume o que os planos prometem e tem de ser reconfirmado contra o código real de `vaccine_store.py` / `vaccine_decision.py` depois da execução. O slug `16-api-de-decisao` é derivado do título no ROADMAP (que não indica slug).

## 1. Objetivo e requisitos

O analista decide por HTTP (aprovar/rejeitar) e lê o resultado, com as garantias do R11 (API key por rota, GET sem efeitos, códigos estáveis, nada aplicado no Wazuh).

| Req | O que a fase 16 entrega |
|---|---|
| VLB-01 | `POST /api/vaccines/{id}/decision`, API key por rota, CORS coerente |
| VLB-02 | 409 estável em segunda decisão / vaccine substituída (a regra vive na F15; aqui só o mapeamento HTTP) |
| VLB-04 | Nenhuma rota/código aplica no Wazuh nem executa comandos; texto "aprovada != aplicada"; teste de varrimento |
| VLB-05 | `GET` traz `state` + `decision`, filtro `?state=`, "Sem dados" nunca 0 |

## 2. O que a fase 15 fornece (contrato assumido) [DEPENDE F15]

- `VaccineStore.decide_vaccine(*, vaccine_id, decision, decided_by, decided_by_name, reason, now_iso) -> dict` (chaves `DECISION_RECORD_KEYS`); levanta `VaccineDecisionError` (atributo `code`, `str(e)==code`, NÃO deriva de `ValueError`, para não cair no `except (sqlite3.Error, ValueError)` dos GET) ou `sqlite3.Error`.
- Códigos (`vaccine_decision.py`): `INVALID_INPUT_CODES` = invalid_vaccine_id, invalid_decision, invalid_author, invalid_decided_at, reason_required, invalid_reason; `NOT_FOUND_CODES` = entry_not_found; `CONFLICT_CODES` = already_decided, vaccine_superseded. A partição já foi pensada para 422/404/409 (15-01-PLAN, "Phase 16: mapear ...").
- Ordem: entrada validada antes de tocar no disco; depois `entry_not_found`, `already_decided` (antes de `vaccine_superseded`), `vaccine_superseded`.
- Leitura: `state` derivado (`proposed|approved|rejected`) e bloco `decision` (`decided_by`, `decided_by_name`, `decided_at`, `reason` / `None`) em `get_vaccine` e `list_vaccines`; `list_vaccines(..., state=None, ...)` por nome (15-03), valor hostil/desconhecido devolve vazio sem erro (a validação do parâmetro HTTP é desta fase).
- Ficheiro antigo sem a tabela: lê-se como tudo `proposed`; a tabela só nasce na primeira escrita.
- A rota gera `now_iso` (UTC, offset 0) e passa o **nome atual** do analista; o store só valida formato (analyst id `^analyst-[a-z0-9-]{1,64}$`, nome 1-128 sem `<>&"'`).
- Reconfirmar: nome exato do campo `decision` no dict devolvido por `decide_vaccine`, e se inclui o `state` novo.

## 3. Superfície de API proposta

### 3.1 Rota nova

`POST /api/vaccines/{vaccine_id}/decision`, `dependencies=_REQUIRE_API_KEY` (por rota, nunca a nível de app), `vaccine_id` com `Path(pattern=VACCINE_ID_RE)`.

Corpo (contrato fechado, `extra="forbid"` se Pydantic):
```json
{"decision": "approved|rejected", "analyst_id": "analyst-soc1", "reason": "opcional; obrigatório se rejected; max 500"}
```
Não aceitar `decided_by_name`, `decided_at` nem `state` do cliente: o nome vem do `incident_store`, o instante do servidor.

Resposta 200: `{"vaccine": <vaccine com state e decision>, "notice": "..."}`; `notice` diz literalmente que "aprovada" significa aceite pelo analista e que nada foi aplicado no Wazuh (critério 3). Ver D-A.

Fluxo da rota: (1) valida o analista com `incident_store.get_analyst` (existe e `active`); (2) `run_in_threadpool(vaccine_store.decide_vaccine, ...)`; (3) mapeia erros; (4) relê `get_vaccine` para devolver o estado já derivado.

### 3.2 Mapeamento de erros (`detail` = código estável, string)

| Causa | HTTP | detail |
|---|---|---|
| sem/errada API key | 401 | o de `require_api_key` |
| `INVALID_INPUT_CODES` | 422 | o próprio código |
| analista inexistente / inativo | 422 (ver D-B) | `analyst_not_found` / `analyst_inactive` |
| `entry_not_found` | 404 | `entry_not_found` (o frontend já tem a frase) |
| `already_decided`, `vaccine_superseded` | 409 | o próprio código |
| `sqlite3.Error` | 503 | `store_unavailable` |
| falha a ler analistas | 503 | `incidents_unavailable` (não reutilizar `_incidents_call`, que dá 500 genérico) |
| PUT/PATCH/DELETE na rota | 405 | (FastAPI) |

Cuidado: erros de validação do Pydantic no corpo dão 422 com `detail` em lista (não é código estável) e `vacCodeFromResponse` só aceita string, caindo em `http_422`. Ver D-C.

### 3.3 GET (alterações)

- `GET /api/vaccines`: novo `state: Literal["proposed","approved","rejected"] | None = Query(None)` passado a `list_vaccines(state=...)`; fora do conjunto -> 422 do FastAPI (como `technique`). `total` respeita o filtro; `available`/`reason` continuam baseados em `store_total` (filtro sem resultado != `no_data`).
- `GET /api/vaccines/{id}`: provavelmente sem alteração de código se a F15 mudou `_to_vaccine`; só testes. **[DEPENDE F15]**
- Opcional: contagens por estado no envelope para os KPIs da F17; sem amostra = `None`, nunca 0 (D-E).
- O GET continua sem efeitos secundários (teste: bytes/mtime iguais; ficheiro inexistente não é criado).

### 3.4 CORS / `allow_methods`

`POST` já está em `allow_methods=["GET","POST","PATCH"]` (`main.py` ~linha 229) e `test_cors.py` já itera `GET/POST/PATCH`. **Sem método novo, nenhuma alteração de `allow_methods`** se ficarmos em POST. O critério 4 satisfaz-se com um teste de preflight a `POST /api/vaccines/vac-.../decision` (`Access-Control-Request-Headers: x-api-key,content-type`) e fixando que `PUT`/`DELETE` não passam a ser permitidos. Se se escolhesse PUT/PATCH (não recomendado), `main.py` e `test_cors.py` teriam de mudar juntos.

## 4. Impacto no frontend (quase tudo é F17; aqui o contrato que a F17 consome)

- Fase 16 em si: **zero alterações de frontend**. O `test_vaccines_frontend.py` (711 linhas) e `test_vaccines_api.py` (437) têm de continuar verdes: `state` novo nas linhas não pode partir o render (hoje `VAC_STATE_LABELS` só tem `proposed`). Verificar o que o render faz com `approved`/`rejected` antes da F17 (fallback seguro, escapado, nunca crash).
- `vaccines.js` (prefixo `vac`, escopo global partilhado): a F17 acrescenta labels `approved`/`rejected` e frases em `VAC_ERROR_TEXT` para `already_decided`, `vaccine_superseded`, `reason_required`, `invalid_reason`, `invalid_author`, `analyst_not_found`, `analyst_inactive`. Sugestão: a F16 fixa a lista de códigos, a F17 escreve as frases.
- `vacRequest` hoje só faz GET (`apiRequest(path)`); o POST precisa do método/corpo de `apiRequest` em `api.js` (verificar; `incRequest` em `incidents.js` já faz POST/PATCH, copiar o padrão).
- Sem ficheiro JS novo, logo `serve_frontend.ALLOWED_FILES` (já tem `/vaccines.js`) e `test_serve_frontend.py` não mudam. Um ficheiro novo (por exemplo `vaccine_decision.js`, não recomendado) obrigaria a ambos e a um prefixo livre (não `vac`, partilhado; ver lista em CLAUDE.md).
- Regras para a F17: nenhum `onclick=`; botões `data-action="vac-approve|vac-reject"` + `data-id`, listener delegado que vai à cache pelo id; texto dinâmico (motivo, nome do analista) sempre por `escapeHtml`/`htmlT` (`test_no_raw_innerhtml.py`); sem cores literais; elementos novos com `hidden` + `display` próprio precisam de regra `[hidden]`; um 409 refresca a vista.
- Identidade no browser: o frontend escolhe `analyst_id` a partir de `GET /api/soc/analysts` (como `incidents.js`) (D-D).

## 5. Testes a escrever (standalone, sem Wazuh, estilo existente)

Novo `scripts/test_vaccine_decision_api.py` (`SENTRYLENS_API_KEY` antes de `import main`, `TestClient`, `on_startup.clear()`, `VACCINES_DB_PATH` num tmp, analistas num `incident_store` tmp ou mock):

1. Auth: sem key 401, key errada 401, com key 200 (POST e GET).
2. Caminho feliz: approved e rejected (com motivo); resposta traz state, decision (id e nome vindos do `incident_store`, não do corpo), `decided_at` UTC do servidor, `notice` com "não aplicada".
3. Contrato fechado: chave extra (`decided_by_name`, `state`, `decided_at`) -> 422; `decision` inválida -> `invalid_decision`; rejeitar sem motivo -> `reason_required`; motivo > 500 ou com controlo -> `invalid_reason`; id mal formado -> 422.
4. 404 `entry_not_found` (id válido inexistente; e store inexistente sem criar o ficheiro).
5. 409 `already_decided` (mesma e outra decisão) e `vaccine_superseded`; em cada recusa nada gravado (contar linhas).
6. Analista inexistente/inativo; falha a ler incidentes -> 503.
7. `sqlite3.Error` forçado -> 503 `store_unavailable`, sem texto de exceção nem caminho no corpo.
8. GET: `state`/`decision` em linhas e detalhe; `?state=` por cada valor; `?state=applied` -> 422; `total` com filtro; filtro sem resultado != `no_data`; GET não escreve.
9. 405 para PUT/PATCH/DELETE na rota; não existe rota de editar/apagar decisões.
10. VLB-04 varrimento (AST/texto): `main.py` e `vaccine_*.py` sem `subprocess`, `os.system`, `ssh_client`, nem escritas ao Manager Wazuh nas funções de vaccines; nenhuma rota `/api/vaccines/**` com apply/deploy/activate; o handler só chama `decide_vaccine`/`get_vaccine`/`get_analyst`.
11. Texto: `notice` e docstring da rota dizem que aprovada != aplicada.

Atualizar: `test_cors.py` (preflight da rota nova), `test_vaccines_api.py` (envelope com `state`/`decision`; confirmar que não assume `state == 'proposed'` sempre), teste de cobertura de API key se existir (confirmar `dependencies` na rota nova). `run_all_tests.py` apanha o ficheiro novo por glob; a contagem da suite (83 após a F15) sobe; os números em CLAUDE.md só se atualizam na F17, medidos.

## 6. Riscos

1. **Autoria autodeclarada.** Só existe uma API key; `analyst_id` no corpo não prova quem decide. O registo é "quem o cliente disse", não autenticado. Documentar como limite (à maneira do SHA-256 dos .pkl) em vez de vender como identidade. Papéis/identidade por pedido é VLB-V2-02.
2. **422 do Pydantic não é código estável** (D-C).
3. **Corrida com o gerador:** já fechada na F15 (`BEGIN IMMEDIATE`); a rota nunca pode fazer "ler `get_vaccine`, verificar, depois decidir".
4. **Nome de analista fora do charset da F15** (ex.: apóstrofo) -> `invalid_author` sempre; o analista não consegue decidir (F15 registou isto para a F16, 15-01-PLAN) (D-F).
5. **Drift do contrato F15:** nomes de códigos/campos podem mudar na execução; reconfirmar antes de planear.
6. Stores síncronos: tudo por `run_in_threadpool`.
7. **Aprovada != aplicada** lê-se mal com facilidade; o campo nunca se chama `applied`/`active`, e a resposta e a docs dizem-no.
8. Clique duplo gera 409 legítimo; a F17 trata como "atualizar vista".
9. `reason` e nome são dados do utilizador servidos de volta: JSON seguro, o risco é só no render (F17) e em qualquer consumidor que trate o motivo como instrução.

## 7. Decisões em aberto para o discuss-phase

- **D-A** Resposta do POST: só o registo de decisão, ou a vaccine completa (recomendo a vaccine: poupa um GET e evita vista a mentir)? Identificar o analista por `analyst_id` no corpo (recomendo) vs header.
- **D-B** Analista inexistente/inativo: 422 (recomendo) vs 404/403.
- **D-C** 422 estável: validar o corpo à mão com os códigos da F15 (recomendo, uniforme) vs Pydantic + handler de `RequestValidationError` só para esta rota. E JSON malformado -> `invalid_body`?
- **D-D** Fonte do analista no frontend: lista de `/api/soc/analysts` (como `incidents.js`) vs analista guardado em localStorage. Condiciona o corpo.
- **D-E** Contagens por estado no envelope entram na F16 (para os KPIs da F17)?
- **D-F** Nome de analista incompatível com o charset da F15: frase própria para `invalid_author` ou relaxar o regex na F15 (barato se feito antes da F15 fechar)?
- **D-G** `?state=` desconhecido: 422 (recomendo) vs lista vazia.
- **D-H** Decisões de vaccines substituídas: manter a regra da F15 (aprovada e substituída continua aprovada, só aparece com `include_superseded`). Basta para o analista ver o histórico?
- **D-I** Repetir exatamente a mesma decisão: 409 (VLB-02, recomendo, sem exceção) vs 200 idempotente.
- **D-J** Limites do corpo/rate limit: ignorar (laboratório) ou fixar `max_length` nos modelos.
- **D-K** Evento WebSocket quando uma vaccine é decidida? (recomendo não.)
- **D-L** Duplicar a decisão no `history_store` JSONL? (recomendo não: duas fontes de verdade divergem.)

## 8. Divisão sugerida em planos/waves

Tracer-bullet primeiro, como na F15.

- **Wave 1 / 16-01 - Rota POST ponta a ponta (tracer):** validação do corpo, validação do analista, `decide_vaccine`, resposta 200 com `notice`, mapeamento 422/404/409/503, auth por rota, 405. Testes: feliz, auth, um erro por família (VLB-01, VLB-02). Depende da F15 completa.
- **Wave 2 / 16-02 - Leitura (VLB-05):** `?state=` na lista, `state`/`decision` provados em lista e detalhe, filtro sem resultado != no_data, GET sem efeitos, ajuste de `test_vaccines_api.py`/`test_vaccines_frontend.py` ao `state` novo, contagens se D-E for sim. Sequencial após 16-01 (ambos editam `main.py`).
- **Wave 3 / 16-03 - Garantias (VLB-04) e CORS:** varrimento "nada aplica/executa", texto aprovada != aplicada, preflight em `test_cors.py`, suite completa verde, confirmação de que não existe rota de editar/apagar. Docs só na F17.

Alternativa mais fina se D-C escolher validação manual: separar em 16-01a (função pura que traduz corpo + `VaccineDecisionError` em `(status, detail)`, testável sem HTTP) e 16-01b (a rota).

## 9. Fora desta fase

Botões, estados na aba e frases novas (F17); DATA_MODEL/API/README/CLAUDE.md (F17); reverter decisões, papéis por tier, dry-run (v2); qualquer aplicação no Wazuh (R21).
