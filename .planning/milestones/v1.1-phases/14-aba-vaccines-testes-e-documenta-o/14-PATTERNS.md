# Phase 14: Aba Vaccines, testes e documentação - Pattern Map

**Mapped:** 2026-10-12
**Files analyzed:** 9
**Analogs found:** 9 / 9 (todos os analogs verificados como git-tracked)

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match |
|---|---|---|---|---|
| `vaccines.js` (novo) | component (aba) | request-response | `attack_library.js` | exact |
| `index.html` (sidebar ~l.94-95, `tab-vaccines`, `<script>` ~l.1665) | markup | n/a | `index.html` `tab-attack-library` (l.1301-1352) | exact |
| `style.css` (classes `vac-*`) | config/style | n/a | `style.css` l.823-847 (`atk-row`, `alib-risk*`) | exact |
| `scripts/serve_frontend.py` (whitelist) | config | request-response | linhas 42-52 do próprio ficheiro | exact |
| `scripts/test_vaccines_frontend.py` (novo) | test | static-contract | `scripts/test_serve_frontend.py::check_static_frontend` (l.146-260) | role-match |
| `scripts/test_serve_frontend.py` (opcional: +`/vaccines.js` servido) | test | request-response | l.122-133 do próprio ficheiro | exact |
| `scripts/run_all_tests.py` | test runner | batch | auto-descoberta `HERE.glob("test_*.py")` (l.29) | exact |
| `docs/DATA_MODEL.md` (entidade Vaccine) | doc | n/a | secção "Biblioteca de ataques (R5)" l.164-201 | role-match |
| `docs/ROADMAP_STATUS.md`, `README.md`, `CLAUDE.md` | doc | n/a | linha R9 (l.27) / entradas por módulo em CLAUDE.md | exact |

NOTA: `run_all_tests.py` faz `glob("test_*.py")` - basta nomear o ficheiro `test_*.py`; não é preciso registo manual (confirmar no plano; se existir lista explícita, acrescentar lá).

## Pattern Assignments

### `vaccines.js` (aba, request-response)

**Analog:** `attack_library.js` (1-168). Prefixo de identificadores de topo: `vac`/`VAC_` (o teste de colisão global segue o estilo `mlm`/`mle`). Nunca redeclarar `API_BASE`, `API_KEY`, `escapeHtml`, `renderPanelError`.

**Cabeçalho/estado/ativação** (l.13-26):
```js
const alibTab = document.getElementById("tab-attack-library");
let alibLoading = false;
function alibIsActive() {
  return alibTab.classList.contains("active") && document.visibilityState === "visible";
}
function alibCell(value) {
  if (value === null || value === undefined || value === "") return "—";
  return escapeHtml(String(value));
}
```

**Request com erro estável como `detail`** (l.41-52):
```js
async function alibRequest(path) {
  const response = await fetch(`${API_BASE}${path}`, { headers: { "X-API-Key": API_KEY } });
  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    try {
      const data = await response.json();
      if (data && typeof data.detail === "string") detail = data.detail;
    } catch (_) { /* corpo não-JSON: fica o código HTTP */ }
    throw new Error(detail);
  }
  return response.json();
}
```
Adaptação D-08: 401/404/502/503 -> tabela PT código->frase (ex. `store_unavailable`, `entry_not_found`, `HTTP 401`), desenhada como erro via `renderPanelError`, nunca "Sem dados". `reason === "no_data"` -> "Sem dados"; `available` true com lista vazia por filtro -> mensagem distinta ("Nenhuma vaccine corresponde aos filtros").

**Linha clicável + detalhe anti-corrida** (l.67, 103-118, 144-154):
```js
body.innerHTML = entries.map((e) => `<tr class="atk-row${e.id === alibSelectedId ? " selected" : ""}" data-id="${escapeHtml(e.id)}" tabindex="0"> ...
let alibSelectSeq = 0;
async function selectAttackLibraryEntry(id) {
  const seq = ++alibSelectSeq; ...
  const entry = await alibRequest(`/api/attack-library/${encodeURIComponent(id)}`);
  if (seq !== alibSelectSeq) return;
```
Para vaccines: GET `/api/vaccines/{id}` devolve `{"vaccine": {...}}` (desembrulhar).

**Diferenças face ao analog (D-02/D-04):**
- Atribuir a cada ativação (não só a primeira): `alibOnShow` tem `alibLoaded` guard - REMOVER e manter só o `loading` guard; botão "Atualizar" chama `refresh`.
- Filtros enviados ao servidor: `URLSearchParams` com `attack_id` (inteiro 1..999999999), `technique` (`^T\d{4}(\.\d{3})?$`), `include_superseded=true`. O select de técnica é preenchido a partir das vaccines carregadas.
- Linha de estado do `generator` (D-03): `data.generator` = `vaccine_ingest` `snapshot()` (dict de estado + `counts`); mostrar "última execução há X min" e, se falhou, frase do código estável (nunca texto de exceção). Ler chaves reais de `scripts/vaccine_ingest.py` (classe com `record(ts, status, code)`; `_state`) antes de codar.

**Ciclo de vida** (l.158-168):
```js
const alibObserver = new MutationObserver(alibOnShow);
alibObserver.observe(alibTab, { attributes: true, attributeFilter: ["class"] });
document.addEventListener("visibilitychange", alibOnShow);
alibOnShow();
```

**Contrato dos dados** (`scripts/vaccine_engine.py` l.64-70):
```python
VACCINE_KEYS = {"id","verdict","expected","expected_source","achieved","missing_sensors","proposals","origin"}  # + superseded_by / criada vêm do store
ORIGIN_KEYS = {"attack_id","scenario","mitre_tactic","mitre_technique","incident_ids","evidence"}
EVIDENCE_KEYS = {"matched_event_ids","matched_alert_count","network_detection_types"}
PROPOSAL_KEYS = {"sensor","rule","events","recommendation"}
RULE_KEYS = {"event_ids","min_count","window_seconds"}
EVENT_KEYS = {"event_id","name","severity"}
```
Verificar nomes exatos de `state`/`created`/`superseded_by`/`supersedes` em `scripts/vaccine_store.py` (`list_vaccines`/`get_vaccine`) e em `test_vaccines_api.py`.

**API** (`scripts/main.py` l.1948-1985): `GET /api/vaccines` -> `{available, reason ("no_data"|null), total, limit, offset, vaccines[], generator}`; `GET /api/vaccines/{id}` -> `{vaccine}`; erros `store_unavailable` (503), `entry_not_found` (404).

---

### `index.html`

**Sidebar** (l.94-95), hoje:
```html
<summary>Vaccines</summary>
<button class="nav-item is-planned" data-planned="R11" data-label="Candidates">💉 Candidates<span class="nav-badge">R11</span></button>
```
Passar a (modelo l.59): `<button class="nav-item" data-tab="vaccines">💉 Candidates</button>`; Validation/Approved/Regression ficam planeados.

**Markup da aba** (modelo l.1301-1352): `div.tab-content#tab-vaccines` > `section.panel#vaccines-panel` (h2, `p.panel-note` com aviso, `div.filter-row` com `label`+`input`/`select`/checkbox/botão Atualizar, `div#vac-generator.panel-note[role=status]`, `div.table-scroll > table#vac-table > tbody#vac-body` com `<tr><td colspan="8" class="empty-state">A carregar...</td></tr>`) + `section.panel#vaccine-detail-panel[hidden]` com `h2`, `div.inc-meta`, `h3`s (Origem, Propostas, Cadeia) e aviso fixo "Proposta — não aplicada no Wazuh". 8 colunas D-04: id, ataque, cenário, técnica, veredito, sensores em falta, estado, criada.

**Script** (l.1665): `<script src="attack_library.js"></script>` -> acrescentar `<script src="vaccines.js"></script>` depois de `app.js` (e das abas já carregadas).

### `style.css`
Modelo (l.823-847):
```css
.atk-row { cursor: pointer; }
.atk-row:hover, .atk-row.selected { background: #eef7f9; }
.alib-risk { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 12px; font-weight: 600; background: #e0e6ea; color: var(--ink-900); }
.alib-risk-medium { background: #fdecc8; }
.alib-risk-high { background: #f8d7da; }
```
Criar `.vac-verdict`, `.vac-verdict-not_detected` (vermelho #f8d7da), `.vac-verdict-partial` (#fdecc8), `.vac-row-superseded { opacity: .55 }`. Reutilizar `atk-row` para linhas clicáveis.

### `scripts/serve_frontend.py` (l.42-52)
```python
    "/attack_library.js": "attack_library.js",
    ...
    "/ml_evaluation.js": "ml_evaluation.js",
```
Acrescentar `"/vaccines.js": "vaccines.js",`.

### `scripts/test_vaccines_frontend.py` (novo, static-contract)
**Analog:** `check_static_frontend()` de `test_serve_frontend.py` (l.146-260) + cabeçalho/`check()` (l.29-36) + sys.exit (l.263-271).
```python
failures: list[str] = []
def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition: failures.append(label)
```
Padrões a copiar:
- Ler ficheiros: `(serve_frontend.PROJECT_ROOT / "index.html").read_text(encoding="utf-8")`.
- Markers em index.html: `data-tab="vaccines"`, `id="tab-vaccines"`, `<script src="vaccines.js"></script>`, ids `vac-*`; linha Candidates sem `is-planned` (padrão l.200-203); Validation/Approved/Regression ainda `is-planned`.
- Ordem de scripts (padrão l.166-168): `vaccines.js` depois de `app.js`.
- Colisão de globais (l.209-213): `re.findall(r"^(?:const|let|var|class|function|async function)\s+([A-Za-z_$][\w$]*)", js, re.M)` -> todos com prefixo `vac`/`VAC_`; sem interseção com `app.js` e `attack_library.js`.
- Servido: subir `HTTPServer(("127.0.0.1", 0), serve_frontend.FrontendHandler)` e usar `get(port,"/vaccines.js")` (l.38-63, 122-123) ou testar `"/vaccines.js" in serve_frontend.<mapa de whitelist>` (confirmar nome da variável em l.~40).
- `app.js` não editado: checar `git diff --quiet -- app.js` via subprocess ou que `app.js` não contém `vaccines`/`vac` (garantia estática; preferir a segunda, sem git).
- `escapeHtml` no texto dinâmico: `"escapeHtml(" in js` e proibir `innerHTML` com `${` de campos crus (heurística: toda interpolação em templates passa por `vacCell`/`escapeHtml`).
- Frase "Proposta — não aplicada no Wazuh" presente em index.html ou vaccines.js; ausência de métodos de escrita (`method: "POST"|"PUT"|"DELETE"|"PATCH"` ausentes em vaccines.js).
- Sem dependência de Wazuh, sem browser.

### `scripts/test_serve_frontend.py` (opcional)
Acrescentar após l.133, no mesmo estilo:
```python
status, headers, _ = get(port, "/vaccines.js")
check("/vaccines.js é servido como JavaScript", status == 200 and headers.get("content-type", "").startswith("application/javascript"))
```

### Documentação (D-10)
- `docs/DATA_MODEL.md`: nova secção "## Vaccine (R11)" depois de "Biblioteca de ataques (R5)" (l.164-201); estilo: bloco de exemplo + "Campos" + regras (id `vac-`+12 hex sha256 de `attack_id:sensores`, `superseded_by`, `reason: no_data`, 404/503 estáveis); listar `VACCINE_KEYS`/`ORIGIN_KEYS`/`PROPOSAL_KEYS`/`RULE_KEYS`/`EVENT_KEYS` e as 3 chaves do `generator`.
- `docs/ROADMAP_STATUS.md` l.29: `| R11 | Vaccine Engine | ⬜ | |` -> `✅` com nota no formato das linhas R5-R9 (módulos `vaccine_engine.py`/`vaccine_store.py`/`vaccine_ingest.py`, `GET /api/vaccines[/{id}]`, aba `vaccines.js`, só leitura, tudo `proposed`).
- `README.md` e `CLAUDE.md`: acrescentar uma entrada por módulo na lista "Arquitetura do backend" (formato `- \`modulo.py\` — descrição`, como `attack_library.py`/`soc_metrics.py`) para motor, store, ingest/loop, rota e `vaccines.js`; atualizar a contagem de ficheiros de teste ("38 ficheiros") conforme o total real. EDITAR, nunca regenerar `CLAUDE.md`.

## Shared Patterns

### Auth no frontend
`X-API-Key: API_KEY` em cada `fetch` (global de `app.js`); nenhuma query param. Sem WebSocket nesta aba.

### Escape / estados vazios
Todo o texto dinâmico via `escapeHtml`; sem dados -> "Sem dados"; erro -> `renderPanelError("#vaccines-panel", msg)` (e `""` para limpar); mensagens de erro derivadas de códigos estáveis, nunca texto de exceção do servidor.

### Testes standalone
Sem pytest, `check()` + `[OK]/[FALHOU]`, `sys.exit(1)` em falha; nome `test_*.py` para a descoberta de `run_all_tests.py`.

## No Analog Found
Nenhum. Único elemento sem analog direto: linha de estado do gerador (D-03) e o select de técnica dinâmico - compor com `panel-note[role=status]` (`alib-notice`) e `<option>` gerados com `escapeHtml`.

## Metadata
**Analog search scope:** raiz (`*.js`, `index.html`, `style.css`), `scripts/` (serve_frontend, test_*, main.py, vaccine_*), `docs/`
**Tracked-source check:** `git ls-files` confirmou attack_library.js, index.html, style.css, serve_frontend.py, test_serve_frontend.py, test_attack_library.py, docs/DATA_MODEL.md, docs/ROADMAP_STATUS.md
**Pattern extraction date:** 2026-10-12
