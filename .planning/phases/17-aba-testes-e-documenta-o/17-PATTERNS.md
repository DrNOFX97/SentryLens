# Phase 17: Aba, testes e documentacao - Pattern Map

**Mapped:** 2026-10-30
**Files analyzed:** 11 (todos modificados; nenhum ficheiro novo, `ALLOWED_FILES` nao muda)
**Analogs found:** 11 / 11 (todos ficheiros git-tracked)

## File Classification

| Modified File | Role | Data Flow | Closest Analog | Match |
|---|---|---|---|---|
| `vaccines.js` | component (aba) | request-response (GET + POST) | proprio ficheiro + `incidents.js` (`incRequest`, `incLoadAnalystFilter`, `incAssign`) | exact |
| `index.html` (linhas ~1407-1451) | component (markup) | static | proprio bloco Vaccines | exact |
| `style.css` (linhas ~1042-1050) | config (estilo) | static | `.vac-verdict*`, `.vac-not-applied` | exact |
| `ui_helpers.js` | utility (funcoes puras `sl*`) | transform | `slMttdView` (l.376), `slAnalystActiveFilter` | exact |
| `scripts/test_ui_helpers.cjs` | test | transform | proprio ficheiro (`check(...)` antes de `finish()`) | exact |
| `scripts/test_vaccines_frontend.py` | test (contrato estatico) | file-I/O + request-response | proprio ficheiro | exact |
| `docs/DATA_MODEL.md` (sec. Vaccine R11, l.203+) | doc | - | mesma seccao | exact |
| `docs/API.md` (l.373-387 e tabela l.485) | doc | - | linhas GET vaccines | exact |
| `docs/ROADMAP_STATUS.md` (l.30 `R12 ... ⬜`, l.3, l.83, l.104) | doc | - | linha R11 (l.29) | exact |
| `README.md` (secao Testes, ~l.339) | doc | - | `python test_vaccines_api.py  # ...` | exact |
| `CLAUDE.md` (raiz) | doc | - | entradas `vaccine_*`/R11 e "Testes do backend" (contagem "81") | exact |

Nota: `serve_frontend.py` so muda se surgir ficheiro novo; nao e esperado.

## Pattern Assignments

### `vaccines.js` (component, request-response)

**Analog:** `vaccines.js` + `incidents.js`

**Transporte (vaccines.js 111-125):** estender `vacRequest(path)` para `vacRequest(path, method, body)`; o `apiRequest` ja suporta `method`/`body`.
```js
async function vacRequest(path) {
  try { return await apiRequest(path); }
  catch (err) { throw new Error(vacCodeFromApiError(err)); }
}
function vacCodeFromApiError(err) {
  if (!err || err.name !== "ApiError") return "unexpected_error";
  if (err.code === "validation_error" || err.code === "forbidden") return "http_" + (err.status || 422);
  return err.code;
}
```
Atencao: um 409/422 sem slug `[a-z_]` vira `http_409`/`http_422`; os slugs (`already_decided`, etc.) chegam em `err.code`. Confirmar em `api.js` que `detail` string vira `err.code` para 409.

**Seletor de analistas (incidents.js 245-258):**
```js
const data = await incRequest("GET", "/api/soc/analysts?active_only=true");
nomes = (data.analysts || []).filter((a) => a && a.active !== false && a.name).map((a) => a.name);
htmRender(select, htmlT`<option value="">Todos</option>${nomes.map((n) => htmlT`<option value="${n}">${n}</option>`)}`);
```
Adaptar: `<option value="">Escolher…</option>` sem pre-selecao, e `value` = `analyst.id` (o POST leva `analyst_id`), texto = `name`. Falha ou lista vazia -> frase no lugar dos botoes (D-03), nunca esconder o bloco.

**Estado de acao (incidents.js 480-500):** `btn.disabled = true` -> `try { await ...; } catch { texto de erro } finally { btn.disabled = false }`. Copiar a estrutura, mas o erro passa por `vacErrorText(code)` (nunca `apiErrorMessage` nem `err.message` cru; `test_vaccines_frontend.message_violations` so admite `.message` como argumento direto de `vacErrorText(`/`vacRenderError(`/`vacRenderDetailError(`; se criares um novo sink, acrescenta-o a `_MESSAGE_SINKS`).

**Listener delegado (vaccines.js 468-478):** copiar o padrao `addEventListener("click", e => e.target.closest("[data-action]"))` para `data-action="vac-approve"`/`"vac-reject"`; nunca `onclick=`.

**Pontos de integracao (todos em vaccines.js):**
- Estado como badge: substituir a celula `vacCell(VAC_STATE_LABELS[vaccine.state] || vaccine.state)` (l.166) por helper analogo a `vacVerdictBadge` (l.138-141): `htmlT\`<span class="vac-state vac-state-${String(state)}">${String(label)}</span>\``. `VAC_STATE_LABELS` (l.19) ganha `approved: "Aprovada"`, `rejected: "Rejeitada"`; estado desconhecido via `vacLabel` (l.133).
- `vacBuildQuery` (l.259-270): acrescentar `state` ao `URLSearchParams` so se estiver em `{proposed,approved,rejected}` (mesmo padrao do `VAC_TECHNIQUE_RE`); adicionar o id do novo select a lista de `change` (l.480).
- Contadores: em `vacRenderList` (l.172) ler `envelope.state_counts`; `null` -> "—", nunca 0.
- `vacRenderDetail` (l.433): acrescentar bloco Decisao com `htmRender`; autor `decided_by_name`, data via `vacDate`, motivo via `vacCell`.
- 409: `vacSelect(vacSelectedId)` + `vacRefresh()` (l.450 / l.304). 200: renderizar `envelope.vaccine` e `notice`; proteger com `const seq = ++vacSelectSeq` / `if (seq !== vacSelectSeq) return;` (l.452, 458).
- `VAC_ERROR_TEXT` (l.37-54): chaves novas `analyst_not_found, analyst_inactive, already_decided, vaccine_superseded, invalid_body, invalid_author, reason_required, invalid_decision, invalid_reason, invalid_vaccine_id, invalid_decided_at, http_405, http_409` (`incidents_unavailable` ja existe, l.47). Lista exata em `scripts/vaccine_decision.py` l.45-48: INVALID = `invalid_vaccine_id, invalid_decision, invalid_author, invalid_decided_at, reason_required, invalid_reason`; NOT_FOUND = `entry_not_found`; CONFLICT = `already_decided, vaccine_superseded`. Mais `invalid_analyst_id` / `analyst_*` vindos de `main.py` (`_vaccine_decision_refusal`, l.2050; confirmar no codigo).
- Corpo do POST (`main.py` l.2030-2031): exatamente `{"decision": "approved"|"rejected", "analyst_id": str, "reason": str|null}`; resposta `{vaccine, notice}`.
- Comentario de topo (l.1-5, "So leitura") e `VAC_*` constants: reescrever (D-10). Novos globais com prefixo `vac`/`VAC_`; o teste `top_level_decls` falha em colisao.

### `index.html` (markup)

**Analog:** bloco Vaccines l.1407-1451. Alterar:
- `<p class="panel-note">` l.1410-1413 (texto "So leitura... todas em estado proposta").
- Filtros (l.1415-1424): novo `<label for="vac-state-filter">` + `<select id="vac-state-filter">` (Todos/Proposta/Aprovada/Rejeitada), no mesmo formato do `vac-technique-filter`.
- Linha de 3 contadores perto de `#vac-generator`/`#vac-notice` (ambos `role="status"`).
- `#vac-detail-warning` (l.1444) passa a ser escrito por JS conforme o estado; seccao "Decisao" (`<h3>Decisao</h3><div id="vac-detail-decision">`) antes ou depois de "Origem". Sem `on*=`.
- Se algum elemento novo tiver `hidden` e `display` proprio, adicionar a regra `[hidden]{display:none}` em style.css.

### `style.css` (config)

**Analog (l.1042-1050):**
```css
.vac-verdict { background: var(--neutral-bg); color: var(--text); }
.vac-verdict-not_detected { background: var(--sev-critical-bg); }
.vac-verdict-partial { background: var(--sev-medium-bg); }
.vac-not-applied { background: var(--sev-medium-bg); border-left: 4px solid var(--sev-medium); padding: 8px 12px; font-weight: 600; margin: 0 0 12px; }
```
Acrescentar `.vac-state`, `.vac-state-proposed|approved|rejected` so com `var(--...)` (sem literais; `test_no_literal_colors`, `test_contrast`). Considerar juntar `.vac-state` a regra de badges partilhada da l.100 (`.alib-risk, .alib-replayable, .vac-verdict, ...`).

### `ui_helpers.js` (utility, transform)

**Analog:** `slMttdView(metrics, error)` (l.376-388): funcao pura que devolve `{value,label,sub}`, trata `null`/`undefined` -> "—". Sem DOM no topo (carregado em `node:vm`). Candidatas `sl*` novas (nomes ao criterio do planner):
- estado do bloco Decisao: `(vaccine, analysts, error)` -> `{mode: "controls"|"readonly"|"superseded"|"no_analysts"|"error", ...}` (D-03, D-06).
- validacao local: `(analystId, decision, reason)` -> codigo/frase (`reason` trim vazio no rejeitar; > 500; sem analista) (D-04, D-12).
- contadores: `state_counts` -> `{proposed,approved,rejected}` com "—" para `null` (D-08).
- codigo->frase pode ficar em `vaccines.js` (`VAC_ERROR_TEXT` ja la vive).

### `scripts/test_ui_helpers.cjs` (test)

**Analog:** proprio ficheiro; acrescentar `check(label, condicao)` imediatamente antes de `finish();` (ultima linha). Exemplo de estilo (fim do ficheiro):
```js
check("slWindowHours: valor valido passa", ctx.slWindowHours("24") === 24 && ctx.slWindowHours(2160) === 2160);
const af = (v) => JSON.stringify(ctx.slAnalystActiveFilter(v));
check("Ativos", af("1") === '{"activeOnly":true,"onlyInactive":false}');
```
Saida `[OK   ]`/`[FALHOU]`, `process.exit(1)` se falhar. Invocado por `test_ui_helpers.py` (nao requer alteracao).

### `scripts/test_vaccines_frontend.py` (test, contrato estatico)

**Analog:** proprio ficheiro. Estrutura: `check(label, bool)` + funcoes `run_tracer/run_guards/run_filters/run_states/run_detail/run_chain` chamadas em `__main__` (l.702-716) e `sys.exit(1)` se `failures`. Pontos a estender:
- `API_VARS` (l.99-100): variaveis cujos `.campo` sao rastreados contra as chaves reais da API; acrescentar o que o novo JS acede (ex.: `decision`, `state_counts` via `envelope`, `notice`) e garantir que `real_api_keys()` (l.143-190) devolve essas chaves: semear uma vaccine decidida (via `VaccineStore` + `vaccine_decision`) e chamar `POST .../decision` com o `TestClient` (`extra_paths` hoje so faz GET).
- Varrimentos globais ja existentes que o JS novo tem de cumprir: `_RAW_RE` (sem `htmlRaw(`/`escapeHtml(`), `_INNERHTML_RE` (sem `.innerHTML`), `top_level_decls` (sem colisao de globais), `message_violations`.
- Novos contratos de texto a acrescentar: `data-action` presente e sem `on\w+=` em vaccines.js e no bloco do index.html; `#vac-state-filter` existe; frases PT-PT para cada codigo de `vaccine_decision.ERROR_CODES` presentes em `VAC_ERROR_TEXT`; o texto "nao aplicada no Wazuh" no detalhe; `vac-state-*` em style.css sem cor literal.
- Rodar sempre como `PYTHONIOENCODING=utf-8 python test_vaccines_frontend.py` a partir de `scripts/`.

### Documentacao (D-16)

| Ficheiro | Onde / padrao a copiar |
|---|---|
| `docs/API.md` | Tabela l.373-374: acrescentar linha `POST /api/vaccines/{id}/decision` (corpo `{decision, analyst_id, reason?}`, resposta `{vaccine, notice}`, 401/404/405/409/422/503 com codigos), `state` em `GET /api/vaccines` e `state_counts` no envelope; atualizar tabela-resumo l.485-486 e a linha "Testes" l.386-387. |
| `docs/DATA_MODEL.md` | Seccao "Vaccine (R11)" l.203+: acrescentar entidade decisao (`decided_by`, `decided_by_name`, `decided_at`, `reason`, `previous_state`) e estado derivado `proposed/approved/rejected`; corrigir "estado fixo `proposed`" (l.251). Fonte: `scripts/vaccine_decision.py` l.51-54. |
| `docs/ROADMAP_STATUS.md` | l.30 `\| R12 \| Vaccine Lab \| ⬜ \| \|` -> ✅ com descricao no formato da l.29 (R11); l.3 ("R9 ao R11" -> R12); nota l.83 diz "aprovar e rejeitar e o R12": reescrever; acrescentar seccao "R12 - verificado por maquina / por verificar em humano" no formato da l.104. |
| `README.md` | Seccao Testes (~l.339): linha `python test_vaccines_frontend.py # ...` / novos testes no formato `python test_x.py  # o que cobre`; atualizar contagem. |
| `CLAUDE.md` | Entradas `vaccine_*` (aprovacao nao aplica nada, rota POST, estado derivado), "Testes do backend" ("81 ficheiros" -> contagem medida), seccao GSD (marco v1.2 completo). Nao correr `generate-claude-md`. |

A contagem de testes tem de vir de uma execucao real: `cd scripts && python run_all_tests.py` (deve terminar com codigo 0; flakes conhecidos: `test_attack_log_ids`, `test_attack_targets`; em worktrees `test_export_raw_events`/`test_ml_training` falham sempre).

## Shared Patterns

### Texto dinamico nunca HTML cru
**Fonte:** `vaccines.js` l.9-12 e `html.js` (`htmlT`/`htmRender`). **Aplica-se a:** todo o JS novo (bloco Decisao, notice, motivo). `notice` e `reason` entram por `htmlT` ou `textContent`; sem `innerHTML`, `htmlRaw`, `escapeHtml(`.

### Erros: codigo estavel como chave, nunca texto do servidor
**Fonte:** `vaccines.js` l.91-107 (`vacCodeFromResponse`, `vacErrorText`). **Aplica-se a:** POST de decisao e carregamento de analistas. Erro nunca se desenha como "sem dados".

### Sem dados e "—", nunca 0
**Fonte:** `vacCell` (l.75-78). **Aplica-se a:** contadores `state_counts == null`, data/autor ausentes.

### Descartar respostas fora de ordem
**Fonte:** `vaccines.js` l.450-466 (`vacSelectSeq`). **Aplica-se a:** `vacSelect` e ao handler do POST.

### Sem handlers inline
**Fonte:** `vaccines.js` l.468-478 + CLAUDE.md. **Aplica-se a:** index.html e HTML gerado por `htmlT`: `data-action`/`data-id` + listener delegado.

### Autoria autodeclarada, sem localStorage
**Fonte:** F16 D-03 / F17 D-01. O analista escolhido vive so em memoria do detalhe; recarregar volta a "Escolher…".

## No Analog Found

Nenhum ficheiro sem analogo. Elementos sem precedente direto (usar os padroes acima combinados): textarea com contador de caracteres e POST a partir da aba Vaccines (o POST de `incidents.js` e o analogo mais proximo); linha de contadores por estado (nenhuma aba tem contadores analogos, copiar `slMttdView`/`vacCell` para o "—").

## Metadata

**Analog search scope:** `vaccines.js`, `incidents.js`, `ui_helpers.js`, `index.html`, `style.css`, `scripts/test_vaccines_frontend.py`, `scripts/test_ui_helpers.cjs`, `scripts/serve_frontend.py`, `scripts/vaccine_decision.py`, `scripts/main.py` (rotas), `docs/*.md`
**Tracked-source gate:** `git ls-files` confirmou `vaccines.js`, `ui_helpers.js`, `test_ui_helpers.cjs`, `test_vaccines_frontend.py` como tracked.
**Pattern extraction date:** 2026-10-30
