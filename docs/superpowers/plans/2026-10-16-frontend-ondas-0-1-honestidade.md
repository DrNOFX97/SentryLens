# Frontend — Ondas 0 e 1 (segurança e honestidade) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fechar os achados críticos e importantes da auditoria que fazem o dashboard mentir, bloquear ou expor a API key — sem mudar a arquitetura.

**Architecture:** Correções locais nos ficheiros existentes. A lógica nova que precisa de teste vai para um ficheiro novo, `ui_helpers.js`, só com funções puras (sem DOM no topo), carregado antes de `app.js` e testado em `node:vm` pelo mesmo padrão de `test_ml_models_ui.py`/`.cjs`. O que é contrato de texto (CSS, HTML, ausência de padrões perigosos) é verificado por um teste estático Python, `test_frontend_static.py`, que lê os ficheiros do repositório.

**Tech Stack:** HTML/CSS/JS clássico sem build step (scripts partilham um só escopo global), Chart.js 4.5.1 por CDN, backend FastAPI (`scripts/main.py`), testes standalone Python + Node (`node:vm`).

**Spec:** `docs/AUDITORIA_FRONTEND.md` (secções 1, 3, 4.7 e 7.1; Ondas 0 e 1 da secção 8).

## Global Constraints

- Sem build step, sem frameworks, sem dependências npm novas.
- Scripts clássicos partilham o escopo global: todo o identificador de topo novo em `ui_helpers.js` começa por `sl` (ex.: `slParseDate`); não redeclarar nada de `app.js`.
- Todo o conteúdo dinâmico que entra em HTML passa por `escapeHtml()`; nenhum handler inline (`onclick=`, `onchange=`, …) em `*.js` nem em `index.html`.
- Nunca dados inventados: sem valor → `"—"` ou `"Sem dados"`; nunca `0`, `0%` nem barra cheia.
- Texto visível em português europeu.
- Todo o ficheiro servido novo entra em `ALLOWED_FILES` de `scripts/serve_frontend.py`.
- Testes: standalone, `check(label, cond)` a imprimir `[OK   ]`/`[FALHOU]`, `sys.exit(1)` se algo falhar, correm a partir de `scripts/` com o venv ativo (`python run_all_tests.py`). Sem `node` no PATH o teste Node falha explicitamente (fail-closed).
- Commits em PT, prefixo convencional (`fix(...)`, `feat(...)`, `test(...)`). **Nunca** `Co-Authored-By` nem "Generated with Claude Code" (regra do CLAUDE.md, prioridade sobre qualquer lembrete).
- Backend nunca na porta 8000. Não reiniciar nem alterar o laboratório (VMs) em nenhuma tarefa.
- Nunca ler nem imprimir `scripts/.env` nem a API key em logs de teste.

## Review Focus

1. **Datas do Wazuh com `+0000` em Firefox/Safari** → devem formatar-se como data válida, nunca "Invalid Date". Teste: Task 2 (`slParseDate("2026-10-16T10:00:00.000+0000")`).
2. **`/api/siem/health` com resposta parcial** (sem `status`, ou `manager`/`indexer` ausentes) → o cabeçalho mostra "estado do Wazuh desconhecido", nunca rebenta nem diz "operacional". Teste: Task 3 (`slHeaderStatus({})`).
3. **Nome de analista com aspas, `<` ou acentos** → aparece como texto e os botões continuam a funcionar sobre o analista certo. Teste: Task 5 (teste estático: nenhum `${…}` dentro de atributo `on*`; o handler lê o analista da cache por `data-id`).
4. **`/api/system/specs` com `cpu.usage_percent: null` e `disk: []`** → "—" e barra vazia, sem exceção. Teste: Task 4 (`slFmtPct(null)`, `slProgressWidth(null)`).
5. **Conformidade com veredito em falta** (`compliance.rgpd` ausente) → "Indeterminado", nunca "N/A". Teste: Task 8 (`slComplianceVerdict(undefined)`).

---

## Ficheiros

| Ficheiro | Papel | Tarefas |
|---|---|---|
| `.gitignore` | ignorar todos os logs do backend | 1 |
| `ui_helpers.js` *(novo)* | funções puras partilhadas (`sl*`) | 2, 3, 4, 7, 8, 9 |
| `scripts/test_ui_helpers.py` + `scripts/test_ui_helpers.cjs` *(novos)* | wrapper Python + teste `node:vm` de `ui_helpers.js` | 2, 3, 4, 7, 8, 9 |
| `scripts/test_frontend_static.py` *(novo)* | contrato estático de `index.html`/`style.css`/`*.js`/`.gitignore` | 1, 3–12 |
| `scripts/serve_frontend.py` | whitelist de `ui_helpers.js` | 2 |
| `scripts/test_serve_frontend.py` | `ui_helpers.js` é servido | 2 |
| `index.html` | `<script>` novo, subtítulo, modais, colunas, opção falsa, parágrafo duplicado | 2, 3, 5, 6, 9, 10, 11 |
| `style.css` | `[hidden]` nos modais, barra vazia por omissão, `status-warn` | 3, 4, 6 |
| `app.js` | cabeçalho, Sistema, ML anomalias, conformidade, hash | 3, 4, 7, 8, 12 |
| `soc_team.js` | sem handlers inline, sem ações falsas, filtros | 5, 9 |
| `incidents.js` | sem `CURRENT_USER` | 10 |
| `ml_models.js` / `scripts/test_ml_models_ui.cjs` | origem coerente com o dataset, escape duplo | 11 |
| `ml_evaluation.js`, `attack_library.js`, `redblue.js`, `live_soc.js` | limpezas pontuais | 12 |
| `README.md` | lista de testes | 13 |

---

### Task 0: Pré-requisito — árvore de trabalho limpa (dono: Fernando)

A árvore tem alterações por commitar em `app.js`, `index.html`, `style.css`, `ml_evaluation.js`, `scripts/*.py` e o `overview.js` novo (trabalho "Overview Fase A"). Este plano edita os mesmos ficheiros.

- [ ] **Step 1:** Decidir e fazer commit (ou stash) desse trabalho num commit próprio, antes da Task 1. Nada deste plano o deve absorver.
- [ ] **Step 2:** Criar o ramo: `git switch -c frontend-ondas-0-1`.
- [ ] **Step 3:** Confirmar a base: `cd scripts && python run_all_tests.py` — anotar quais falham já antes (flakes conhecidos em `docs/ROADMAP_STATUS.md`), para não os atribuir a este plano.

---

### Task 1: Logs do backend fora do git + chave rodada

**Files:**
- Modify: `.gitignore:14-15`
- Create: `scripts/test_frontend_static.py`

**Interfaces:**
- Produces: `scripts/test_frontend_static.py` com `ROOT = Path(__file__).resolve().parent.parent`, `read(rel: str) -> str` (UTF-8) e `check(label, cond)`. As tarefas seguintes acrescentam secções a este ficheiro, cada uma numa função `def section_<nome>() -> None` chamada no fim do ficheiro.

- [ ] **Step 1: Escrever o teste a falhar** — `section_gitignore()`:

```python
for name in ["scripts/backend.log", "scripts/backend.log.err",
             "scripts/backend.log-PC-Vicente.err", "scripts/frontend.log", "scripts/x.err"]:
    r = subprocess.run(["git", "check-ignore", "-q", name], cwd=ROOT)
    check(f"{name} ignorado pelo git", r.returncode == 0)
```

- [ ] **Step 2:** `cd scripts && python test_frontend_static.py` → `[FALHOU] scripts/backend.log-PC-Vicente.err ignorado pelo git`.
- [ ] **Step 3:** Em `.gitignore`, substituir as linhas `scripts/*.log` e `scripts/*.log.err` por `scripts/*.log*` e `scripts/*.err`.
- [ ] **Step 4:** Correr de novo → todos `[OK]`.
- [ ] **Step 5 (manual, Fernando):** rodar `SENTRYLENS_API_KEY` em `scripts/.env`, reiniciar com `.\scripts\start-backend.ps1` e `.\scripts\start-frontend.ps1`; apagar `scripts/backend.log-PC-Vicente.err`, os `scripts/*.err` antigos e os ficheiros de `.playwright-mcp/` que contêm `api_key=` (verificar com `grep -l "api_key=" .playwright-mcp/*` sem imprimir conteúdo). A chave nova continua a ir para o access log até à Onda 5 (W5.4) — isso é esperado.
- [ ] **Step 6: Commit**

```bash
git add .gitignore scripts/test_frontend_static.py
git commit -m "fix(seguranca): ignora todos os logs do backend no git"
```

---

### Task 2: `ui_helpers.js` com datas do Wazuh + harness de teste

**Files:**
- Create: `ui_helpers.js`, `scripts/test_ui_helpers.py`, `scripts/test_ui_helpers.cjs`
- Modify: `scripts/serve_frontend.py` (`ALLOWED_FILES`), `scripts/test_serve_frontend.py`, `index.html:1743-1744`, `app.js:198-205`

**Interfaces:**
- Produces (globais de `ui_helpers.js`):
  - `slParseDate(ts: string|number|null|undefined) -> Date|null` — converte o sufixo `±HHMM` em `±HH:MM`; `null` para vazio ou inválido.
  - `slFormatTimestamp(ts) -> string` — `toLocaleString("pt-PT")` ou `"—"`.
- Produces (harness): `test_ui_helpers.py` corre `node test_ui_helpers.cjs <caminho de ui_helpers.js>`; o `.cjs` carrega o ficheiro com `vm.runInContext` num contexto sem `document`, expõe `check()` e acaba com `process.exit(1)` se houver falhas. As tarefas seguintes só acrescentam `check(...)` ao `.cjs`.
- `app.js` `formatTimestamp(ts)` passa a ser `return slFormatTimestamp(ts);` (mantém o nome; os outros módulos usam-no).

- [ ] **Step 1: Testes a falhar** em `test_ui_helpers.cjs`:

```js
check("slParseDate aceita +0000 do Wazuh",
  ctx.slParseDate("2026-10-16T10:00:00.000+0000").toISOString() === "2026-10-16T10:00:00.000Z");
check("slParseDate aceita +01:00", ctx.slParseDate("2026-10-16T11:00:00+01:00").toISOString() === "2026-10-16T10:00:00.000Z");
check("slParseDate inválido -> null", ctx.slParseDate("não é data") === null);
check("slParseDate vazio -> null", ctx.slParseDate("") === null && ctx.slParseDate(null) === null && ctx.slParseDate(undefined) === null);
check("slFormatTimestamp inválido -> travessão", ctx.slFormatTimestamp("xyz") === "—");
check("slFormatTimestamp válido não é Invalid Date",
  !/Invalid/.test(ctx.slFormatTimestamp("2026-10-16T10:00:00.000+0000")) && ctx.slFormatTimestamp("2026-10-16T10:00:00.000+0000") !== "—");
check("ui_helpers.js não toca em document no topo", true); // garantido por o vm não ter document: o carregamento falharia
```

E em `test_ui_helpers.py`: `shutil.which("node")` ausente → `check("node não encontrado no PATH…", False)`; senão `subprocess.run([node, cjs, str(ROOT / "ui_helpers.js")])` e `check("teste Node de ui_helpers.js", rc == 0)` com o stdout reencaminhado.

Em `test_serve_frontend.py`, junto aos outros `.js`: `check("/ui_helpers.js é servido como JavaScript", …)` (mesmo formato da linha 116-117).

- [ ] **Step 2:** `python test_ui_helpers.py` → falha (ficheiro inexistente); `python test_serve_frontend.py` → `[FALHOU] /ui_helpers.js…`.
- [ ] **Step 3:** Criar `ui_helpers.js` (cabeçalho a explicar: funções puras, prefixo `sl`, sem DOM, testadas por `test_ui_helpers.cjs`) com as duas funções; `"/ui_helpers.js": "ui_helpers.js"` em `ALLOWED_FILES`; `<script src="ui_helpers.js"></script>` entre `config.js` e `app.js` em `index.html`; `formatTimestamp` delega.
- [ ] **Step 4:** Os dois testes passam; `python run_all_tests.py` sem regressões face à Task 0.
- [ ] **Step 5: Commit** — `feat(frontend): ui_helpers.js com datas do Wazuh compatíveis com Firefox/Safari`.

---

### Task 3: Indicador do cabeçalho a partir de `/api/siem/health`

**Files:**
- Modify: `ui_helpers.js`, `app.js:50-53,1284-1301,1387-1393`, `index.html:19,38`, `style.css:92-111`
- Test: `scripts/test_ui_helpers.cjs`, `scripts/test_frontend_static.py`

**Interfaces:**
- Consumes: `fetchJSON(path)` de `app.js`.
- Produces: `slHeaderStatus(health: object|null, failed: boolean) -> {text: string, cls: string}` com a tabela exata:

| Entrada | `text` | `cls` |
|---|---|---|
| `null`, `failed=true` | `● sem ligação ao backend` | `status-error` |
| `null`, `failed=false` | `● a verificar` | `status-unknown` |
| `status: "ok"` | `● Wazuh operacional` | `status-ok` |
| `status: "degraded"` | `● Wazuh degradado` | `status-warn` |
| `status: "down"` | `● Wazuh em baixo` | `status-error` |
| outro / em falta | `● estado do Wazuh desconhecido` | `status-unknown` |

- `app.js`: nova `async function refreshHeaderStatus()` — `fetchJSON("/api/siem/health")`, aplica `slHeaderStatus` a `#status-indicator` (`textContent` + `className = "status-indicator " + cls`). `setStatus` é removida e `refreshDashboard` deixa de mexer no indicador.

- [ ] **Step 1: Testes a falhar** — no `.cjs`, um `check` por linha da tabela, mais `slHeaderStatus({}, false).cls === "status-unknown"` e `slHeaderStatus({status:"ok"}, true).text === "● Wazuh operacional"` (com resposta, o `failed` é ignorado). No estático, `section_header()`:

```python
app = read("app.js")
check("setStatus removido", "function setStatus" not in app)
check("cabeçalho lê /api/siem/health", 'refreshHeaderStatus' in app and '/api/siem/health' in app)
check("subtítulo não afirma ligação", "ligado ao Wazuh em tempo real" not in read("index.html"))
check("estilo status-warn existe", ".status-warn" in read("style.css"))
```

- [ ] **Step 2:** Correr os dois testes → falham.
- [ ] **Step 3:** Implementar `slHeaderStatus`; `refreshHeaderStatus` chamada no arranque, no fim de cada `refreshDashboard()` e num `setInterval` de 30 000 ms que só corre com `document.visibilityState === "visible"`. Subtítulo de `index.html:19` passa a `Laboratório SOC sobre Wazuh`. Em `style.css`, `.status-warn { background: #5c4400; color: #ffd27a; }` (contraste ≥ 4,5:1 — confirmar com o script de contraste da auditoria antes do commit).
- [ ] **Step 4:** Testes passam. Verificação manual: com o backend ligado e as VMs paradas, o cabeçalho diz "● Wazuh em baixo" (ou "degradado"), nunca "operacional".
- [ ] **Step 5: Commit** — `fix(cabecalho): estado do Wazuh vem de /api/siem/health em vez de inferido`.

---

### Task 4: Painel Sistema honesto (barras vazias, sem exceções)

**Files:**
- Modify: `ui_helpers.js`, `app.js:440-443,510-549,551-676,678-695`, `style.css:598-607`
- Test: `scripts/test_ui_helpers.cjs`, `scripts/test_frontend_static.py`

**Interfaces:**
- Produces:
  - `slNumberOrNull(v) -> number|null` — `null` para `null`/`undefined`/`""`/boolean/não finito.
  - `slFmtPct(v, digits = 0) -> string` — `"—"` ou `` `${n.toFixed(digits)}%` ``.
  - `slProgressWidth(v) -> string` — `"0%"` sem valor, senão o valor limitado a 0–100 com `%`.
- `setProgressBar(barEl, percent, level)` passa a usar `slProgressWidth` e, sem valor, `className = "progress-fill"` (sem `level-*`).
- `loadSystemPanel()` fica dentro de `try/catch`; no `catch`: `renderPanelError("#system-panel", err.message || "Não foi possível ler o estado desta máquina.")`, os quatro "A carregar..." trocados por "Sem dados" e `resetSystemSummaryCard()` (nova, sem parâmetros) põe o badge a `—`, as quatro barras vazias e os textos a `—`. Sucesso → `renderPanelError("#system-panel", null)`.
- `forceSpeedtest()`: o erro passa a `renderPanelError("#system-panel", "Não foi possível medir a rede: " + err.message)`.

- [ ] **Step 1: Testes a falhar**:

```js
check("slFmtPct(null) -> —", ctx.slFmtPct(null) === "—");
check("slFmtPct(12.34,1) -> 12.3%", ctx.slFmtPct(12.34, 1) === "12.3%");
check("slFmtPct(true) -> —", ctx.slFmtPct(true) === "—");
check("slProgressWidth(null) -> 0%", ctx.slProgressWidth(null) === "0%");
check("slProgressWidth(150) -> 100%", ctx.slProgressWidth(150) === "100%");
check("slProgressWidth(-5) -> 0%", ctx.slProgressWidth(-5) === "0%");
```

Estático, `section_system()`:

```python
css = read("style.css")
block = re.search(r"\.progress-fill\s*\{([^}]*)\}", css).group(1)
check(".progress-fill começa com largura 0", re.search(r"width:\s*0", block) is not None)
check(".progress-fill sem verde por omissão", "#27ae60" not in block)
body = re.search(r"async function loadSystemPanel\(\)\s*\{(.*?)\n\}", read("app.js"), re.S).group(1)
check("loadSystemPanel tem try/catch", "try {" in body and "catch" in body)
check("nenhum .toFixed direto sobre specs.*", re.search(r"specs\.[a-z_.]+\.toFixed", body) is None)
```

- [ ] **Step 2:** Correr → falham.
- [ ] **Step 3:** Implementar. Em `style.css`: `.progress-fill { width: 0; background: transparent; }` (as classes `level-*` continuam a dar cor). Todos os `.toFixed` de `loadSystemPanel` e `renderSystemSummaryCard` passam por `slFmtPct`.
- [ ] **Step 4:** Testes passam. Manual: com o backend parado (`Stop` do terminal do backend), a aba Sistema mostra o banner, "Sem dados" e barras vazias; o cartão do Overview mostra `—` e barras vazias.
- [ ] **Step 5: Commit** — `fix(sistema): sem dados mostra barras vazias e banner, nunca verde a 100%`.

---

### Task 5: Equipa SOC sem handlers inline e sem ações falsas

**Files:**
- Modify: `soc_team.js:6-16,97-116,224-240,254-304,320-336,340-397,538-547`, `index.html:1162-1166,1218-1222`
- Test: `scripts/test_frontend_static.py`

**Interfaces:**
- `renderAnalystsTable` gera `<button class="btn-sm" data-action="edit" data-id="${escapeHtml(a.id)}">Editar</button>` e, se ativo, `<button class="btn-sm btn-danger" data-action="deactivate" data-id="…">Desativar</button>`. Um único listener `click` em `#analysts-body` (registado em `stInit`) procura o analista em `stAnalystsCache` pelo `data-id` e chama `openAnalystModal("edit", id)` ou `deactivateAnalyst(id, analyst.name)`.
- Turnos e regras de escalamento: a coluna "Ações" desaparece (cabeçalho no HTML e célula no JS); os `colspan` dos estados vazios passam de 6 para 5. Removidos: `deleteShift`, `deleteEscalationRule`, os ramos "editar" de `openShiftModal`/`openEscalationModal` e dos dois `submit`, `stShowPanel` e os `window.* =` do fim do ficheiro.

- [ ] **Step 1: Teste a falhar** — `section_no_inline_handlers()`:

```python
for rel in ["index.html", *sorted(p.name for p in ROOT.glob("*.js"))]:
    txt = read(rel)
    check(f"{rel} sem handlers inline", re.search(r"\son[a-z]+\s*=", txt) is None)
soc = read("soc_team.js")
check("soc_team.js sem ações por implementar", "não implementad" not in soc)
check("soc_team.js sem window.* para handlers", "window.deactivateAnalyst" not in soc)
check("botões da tabela de analistas por data-action", 'data-action="deactivate"' in soc)
```

- [ ] **Step 2:** Correr → falha (`soc_team.js sem handlers inline`).
- [ ] **Step 3:** Implementar conforme Interfaces. Nenhum `${…}` dentro de atributo que não seja `data-*`, `class` ou `colspan`.
- [ ] **Step 4:** Teste passa. Manual (browser, backend ligado): criar o analista `analyst-teste` com o nome `O'Neil <b>x</b>` → aparece como texto literal; "Desativar" desativa esse analista (e não outro); a consola não mostra erros.
- [ ] **Step 5: Commit** — `fix(soc-team): remove handlers inline (XSS) e botões sem rota no backend`.

---

### Task 6: Modais que fecham de verdade

**Files:**
- Modify: `style.css:891-893`, `index.html:1107,1172,1228`, `soc_team.js` (`stInit`, `open*Modal`, `close*Modal`)
- Test: `scripts/test_frontend_static.py`

**Interfaces:**
- CSS: `.modal[hidden] { display: none; }` (a regra `.modal.hidden`, morta, sai).
- HTML: cada `.modal-content` ganha `role="dialog" aria-modal="true" aria-labelledby="<id do h3>"`.
- `soc_team.js`: `stOpenModal(modalId: string, focusId: string) -> void` e `stCloseModal(modalId: string) -> void`. Abrir guarda `document.activeElement`, tira o `hidden` e foca `focusId`; fechar repõe o `hidden` e devolve o foco. Um único `keydown` em `document`: `Escape` fecha o modal visível (se houver). Os seis `open*/close*` existentes passam a chamá-las.

- [ ] **Step 1: Teste a falhar** — `section_modals()`:

```python
css = read("style.css")
check(".modal[hidden] esconde", re.search(r"\.modal\[hidden\]\s*\{[^}]*display:\s*none", css) is not None)
html = read("index.html")
check("3 modais com role=dialog", html.count('role="dialog"') == 3 and html.count('aria-modal="true"') == 3)
check("Escape fecha modal", "Escape" in read("soc_team.js"))
```

- [ ] **Step 2:** Correr → falha.
- [ ] **Step 3:** Implementar.
- [ ] **Step 4:** Teste passa. Manual: abrir a aba Equipa SOC → nenhum modal visível e o menu clica; "Novo Analista" abre o modal com o foco no campo ID; Esc fecha e o foco volta ao botão.
- [ ] **Step 5: Commit** — `fix(soc-team): modais escondidos por omissão, Esc e foco`.

---

### Task 7: Anomalias ML sem 0% inventado

**Files:**
- Modify: `ui_helpers.js`, `app.js:1156-1204`, `index.html:548-554`
- Test: `scripts/test_ui_helpers.cjs`, `scripts/test_frontend_static.py`

**Interfaces:**
- Produces: `slAgreementText(agree, total) -> string` — `"—"` se `total` não for número finito > 0 ou `agree` não for número finito; senão `` `${Math.round(agree / total * 100)}%` ``.
- `renderMlAnomaliesTable`: a célula do score usa `slNumberOrNull(r.ml_score)` (Task 4) → `"—"` ou `toFixed(4)`; a classe `agreement-${…}` passa por `escapeHtml`.
- A nota fixa "Modelo treinado sobre dados sintéticos; ver README…" é substituída por "A versão do modelo e a origem dos dados de treino estão na aba Models." (o resto da nota mantém-se).

- [ ] **Step 1: Testes a falhar**:

```js
check("concordância sem eventos -> —", ctx.slAgreementText(0, 0) === "—");
check("concordância total null -> —", ctx.slAgreementText(3, null) === "—");
check("concordância 3/4 -> 75%", ctx.slAgreementText(3, 4) === "75%");
```

Estático: `check("nota ML sem afirmação fixa de dados sintéticos", "Modelo treinado sobre dados sintéticos" not in read("index.html"))` e `check("ml_score não usa toFixed direto", "r.ml_score.toFixed" not in read("app.js"))`.

- [ ] **Step 2:** Correr → falham.
- [ ] **Step 3:** Implementar.
- [ ] **Step 4:** Testes passam.
- [ ] **Step 5: Commit** — `fix(ml-anomalias): sem amostra mostra travessão, nunca 0%`.

---

### Task 8: Conformidade com estado real e justificação

**Files:**
- Modify: `ui_helpers.js`, `app.js:1208-1233`
- Test: `scripts/test_ui_helpers.cjs`

**Interfaces:**
- Produces: `slComplianceVerdict(v: {estado?: string, justificacao?: string}|null|undefined) -> {label: string, title: string}`:
  - `estado === "aplicavel"` → `"✅ Aplicável"`; `"verificado_e_nao_aplicavel"` → `"➖ Não aplicável"`; qualquer outro, ou `v` em falta → `"❔ Indeterminado"`.
  - `title` = `v.justificacao` se for string; com `v` em falta → `"Sem veredito do motor de conformidade"`; senão `""`.
- `renderComplianceTable`: cada célula é `<td title="${escapeHtml(title)}">${escapeHtml(label)}</td>`.

- [ ] **Step 1: Testes a falhar**:

```js
const ap = ctx.slComplianceVerdict({ estado: "aplicavel", justificacao: "Dados pessoais" });
check("aplicável + justificação", ap.label === "✅ Aplicável" && ap.title === "Dados pessoais");
check("não aplicável", ctx.slComplianceVerdict({ estado: "verificado_e_nao_aplicavel" }).label === "➖ Não aplicável");
check("estado desconhecido -> Indeterminado", ctx.slComplianceVerdict({ estado: "xpto" }).label === "❔ Indeterminado");
const miss = ctx.slComplianceVerdict(undefined);
check("sem veredito -> Indeterminado com motivo", miss.label === "❔ Indeterminado" && miss.title === "Sem veredito do motor de conformidade");
```

- [ ] **Step 2:** Correr → falham.
- [ ] **Step 3:** Implementar; remover o `estadoLabel` local.
- [ ] **Step 4:** Testes passam. Manual: o rato sobre uma célula mostra a justificação.
- [ ] **Step 5: Commit** — `fix(conformidade): mostra estado real e justificação do motor`.

---

### Task 9: Filtros da Equipa SOC (estado e janela do resumo por tier)

**Files:**
- Modify: `ui_helpers.js`, `soc_team.js:78-95,165-188,468-478`
- Test: `scripts/test_ui_helpers.cjs`, `scripts/test_frontend_static.py`

**Interfaces:**
- Produces:
  - `slAnalystActiveFilter(value: string) -> {activeOnly: boolean, onlyInactive: boolean}` — `"1"` → `{true,false}`; `"0"` → `{false,true}`; `""` e qualquer outro → `{false,false}`. O backend só sabe `active_only` (`main.py:1554`); "Inativos" filtra no cliente (`a.active === 0`, ou `!a.active`).
  - `slTierWindowHours(days) -> number` — `min(days × 24, 720)`; dias não numéricos ou ≤ 0 → `168`.
- `loadTierSummary`: usa `slTierWindowHours` e, quando a janela foi cortada, a nota diz `Janela de 720 h (máximo desta fonte)`.
- Edição de analista: o campo `#analyst-name` fica `disabled` no modo editar (o PATCH não aceita nome: `AnalystUpdate` em `main.py:1321`) e volta a `disabled = false` em `openAnalystModal("create")`.

- [ ] **Step 1: Testes a falhar**:

```js
const f = (v) => JSON.stringify(ctx.slAnalystActiveFilter(v));
check("Ativos", f("1") === '{"activeOnly":true,"onlyInactive":false}');
check("Inativos", f("0") === '{"activeOnly":false,"onlyInactive":true}');
check("Todos", f("") === '{"activeOnly":false,"onlyInactive":false}');
check("7 dias -> 168 h", ctx.slTierWindowHours(7) === 168);
check("90 dias -> 720 h (le=720)", ctx.slTierWindowHours(90) === 720);
check("inválido -> 168 h", ctx.slTierWindowHours("abc") === 168);
```

Estático: `check("nome bloqueado ao editar analista", re.search(r'analyst-name"\)\.disabled\s*=\s*true', read("soc_team.js")) is not None)`.

- [ ] **Step 2:** Correr → falham.
- [ ] **Step 3:** Implementar.
- [ ] **Step 4:** Testes passam. Manual: "Período = 90 dias" → o Resumo por Tier carrega (sem 422) e diz "720 h (máximo desta fonte)"; "Inativos" mostra só inativos.
- [ ] **Step 5: Commit** — `fix(soc-team): filtro de estado correto e janela do resumo dentro do limite`.

---

### Task 10: Incidentes sem filtro "Meus incidentes" falso

**Files:**
- Modify: `index.html:1011`, `incidents.js:214-223`
- Test: `scripts/test_frontend_static.py`

**Interfaces:**
- Sai a opção `__mine__` e o ramo que lê `CURRENT_USER`. O `#inc-assigned-filter` mantém "Todos" e passa a ser preenchido, ao carregar a aba, com os analistas ativos de `GET /api/soc/analysts` (`<option value="${escapeHtml(a.name)}">`), porque o backend filtra `assigned_to` pelo texto guardado na atribuição (que hoje é o nome escrito à mão). Se o pedido falhar, fica só "Todos" — sem mensagem extra.

- [ ] **Step 1: Teste a falhar**:

```python
check("sem CURRENT_USER", "CURRENT_USER" not in read("incidents.js"))
check("sem opção __mine__", "__mine__" not in read("index.html"))
```

- [ ] **Step 2:** Correr → falha.
- [ ] **Step 3:** Implementar.
- [ ] **Step 4:** Teste passa. Manual: escolher um analista no filtro mostra só os incidentes atribuídos a esse nome.
- [ ] **Step 5: Commit** — `fix(incidentes): filtro por analista real em vez de utilizador inexistente`.

---

### Task 11: Models — origem coerente com o dataset e texto sem duplicados

**Files:**
- Modify: `ml_models.js:87-97,510-536`, `index.html:605-634,643`
- Test: `scripts/test_ml_models_ui.cjs`, `scripts/test_frontend_static.py`

**Interfaces:**
- `mlmTrainBody(dataset, dataset_origin)`: com `dataset === "sample_fixture"` devolve sempre `dataset_origin: "synthetic"`, seja qual for o pedido.
- DOM: ao mudar `#mlm-train-dataset` para "Gerador sintético", `#mlm-train-origin` passa a `synthetic` e fica `disabled`; ao voltar a "Export recente", fica ativo. A opção por omissão de `#mlm-train-origin` passa a `unknown` (`MLM_TRAIN_ORIGEM_OMISSAO`), não `real`.
- `mlmRenderTrainResult` recebe texto simples: os dois chamadores deixam de passar `escapeHtml(...)` (o `textContent` já é seguro).
- `index.html`: sai a primeira cópia do parágrafo do treino (linhas 608-615, dentro do primeiro `.panel-note`), ficando o parágrafo de descrição só com as duas primeiras frases.

- [ ] **Step 1: Testes a falhar** — em `test_ml_models_ui.cjs`, junto aos testes de `mlmTrainBody`:

```js
check("sample_fixture força origem synthetic", ctx.mlmTrainBody("sample_fixture", "real").dataset_origin === "synthetic");
check("latest_export mantém origem declarada", ctx.mlmTrainBody("latest_export", "real").dataset_origin === "real");
```

Estático:

```python
html = read("index.html")
check("parágrafo do treino aparece uma vez", html.count("O botão treina a partir do próprio dashboard") == 1)
check("origem por omissão não é 'real'", '<option value="real" selected>' not in html)
check("sem escape duplo no resultado do treino", "mlmRenderTrainResult(\"erro\", escapeHtml(" not in read("ml_models.js"))
```

- [ ] **Step 2:** `python test_ml_models_ui.py` e `python test_frontend_static.py` → falham.
- [ ] **Step 3:** Implementar.
- [ ] **Step 4:** Testes passam (incluindo os que já existiam em `test_ml_models_ui.cjs`).
- [ ] **Step 5: Commit** — `fix(ml-models): dataset sintético nunca é declarado como real`.

---

### Task 12: Limpezas pontuais

**Files:**
- Modify: `ml_evaluation.js:435-438,510`, `attack_library.js:99-101`, `app.js:1343-1348`, `redblue.js:247-249`, `live_soc.js:202-211`
- Test: `scripts/test_frontend_static.py`

**Interfaces / decisões:**
- `ml_evaluation.js`: apagar a primeira `mleRenderEvaluation` (435-438); `colspan="8"` no estado vazio da comparação.
- `attack_library.js` `alibShowDetailError`: tira o `hidden` de `#attack-library-detail-panel` antes do `renderPanelError` quando há mensagem.
- `app.js` `activateTab`: `` document.querySelector(`.nav-item[data-tab="${CSS.escape(tabName)}"]`) ``.
- `redblue.js`: a nota passa a "Este painel mostra o que foi detetado, por que método e ao fim de quanto tempo. O seguimento (estados, notas, atribuição) está na aba Incidentes."
- `style.css`: apagar as regras mortas `tr.row-gap`, `.mle-verdict`, `.modal.hidden` (se ainda existir depois da Task 6), `.tier-badge-inline*`, `.role-badge-inline*` e `.status-badge*` (confirmar com `grep` que nenhum `*.js`/`index.html` as usa).
- `live_soc.js`: o `catch` de `lsRefreshHealth` guarda `response.status` no erro; a nota passa a `401` → "API key inválida ou em falta — confirma SENTRYLENS_API_KEY."; erro de rede (sem status) → "Sem ligação ao backend (localhost:8001)."; outro → "O backend respondeu HTTP <n> ao pedir a saúde do SIEM."

- [ ] **Step 1: Teste a falhar** — `section_cleanups()`:

```python
ev = read("ml_evaluation.js")
check("mleRenderEvaluation declarada uma vez", ev.count("function mleRenderEvaluation(") == 1)
check("comparação vazia com colspan 8", 'colspan="7"' not in ev)
check("activateTab escapa o hash", "CSS.escape(tabName)" in read("app.js"))
check("nota Red vs Blue atualizada", "não regista ações de resposta" not in read("redblue.js"))
check("Live SOC distingue 401", "API key inválida" in read("live_soc.js"))
css = read("style.css")
for dead in ["row-gap", "mle-verdict", "tier-badge-inline", "role-badge-inline", ".status-badge"]:
    check(f"CSS morto removido: {dead}", dead not in css)
check("detalhe da Attack Library mostra o painel no erro",
      re.search(r"function alibShowDetailError[\s\S]{0,300}hidden\s*=\s*false", read("attack_library.js")) is not None)
```

- [ ] **Step 2:** Correr → falha.
- [ ] **Step 3:** Implementar.
- [ ] **Step 4:** Teste passa. Manual: abrir `index.html#a"b` não rebenta a navegação (fica no Overview).
- [ ] **Step 5: Commit** — `fix(frontend): limpezas pontuais da auditoria (evaluation, attack library, hash, textos)`.

---

### Task 13: Verificação final e documentação

**Files:**
- Modify: `README.md` (secção Testes)

- [ ] **Step 1:** `cd scripts && python run_all_tests.py` → tudo verde exceto os flakes anotados na Task 0.
- [ ] **Step 2: Verificação no browser** (Playwright ou à mão), repetindo os cenários da secção 0 da auditoria com o frontend numa porta livre e os pedidos a `:8001` intercetados — nunca parando o backend real:
  - backend desligado → nenhuma aba com "A carregar..." nas zonas tocadas por este plano (Sistema, Ciclo de Vida/Privilégios/Contas Admin podem ainda ter — são da Onda 2, anotar), barras vazias, cabeçalho "● sem ligação ao backend";
  - `/api/siem/health` com `{"status":"down", …}` e `/api/system/*` OK → cabeçalho "● Wazuh em baixo";
  - aba Equipa SOC → nenhum modal visível; o menu clica;
  - 390 px → anotar (corrigido na Onda 4).
- [ ] **Step 3:** Acrescentar `test_frontend_static.py` e `test_ui_helpers.py` à lista de testes do `README.md`, uma linha cada, no formato das existentes.
- [ ] **Step 4:** `git log --format=%B main..HEAD | grep -i co-authored-by` → vazio.
- [ ] **Step 5: Commit** — `docs(readme): testes do frontend (estático e ui_helpers)`.

---

## Planos seguintes (um por onda, a escrever quando esta fechar)

| Plano | Conteúdo (ver `docs/AUDITORIA_FRONTEND.md`, secção 8) | Depende de |
|---|---|---|
| Onda 2 — cliente HTTP e estados | `api.js` (`apiRequest`, `ApiError`, timeout 15 s), `state.js`, migração módulo a módulo; fim de "A carregar..." preso e de "Failed to fetch" | este plano |
| Onda 3 — desempenho | `router.js` (aba ativa + visível), polling só visível em `app.js`/`redblue.js`/`incidents.js`, `/ws/network` em lote, Chart.js e fontes locais | Onda 2 |
| Onda 4 — sistema de design | tokens semânticos, tema escuro, rampa de severidade validada, escala tipográfica, `.badge`/`.btn`, ícones SVG, `prefers-reduced-motion` | — (pode correr em paralelo à 3) |
| Onda 5 — arquitetura de informação | menu de 38 → ≤ 22 entradas, página Roadmap, regra de língua, seletor de janela único, um só MTTD, ticket de WS + CSP | Ondas 2 e 4 |
| Onda 6 — dataviz | gráficos existentes corrigidos, matriz de cobertura, faixa ataque → deteção | Onda 4 |
| Onda 7 — refatoração | `html\`\``, `table.js`, `kpi()`, `fmt.js`, partir `app.js` | Onda 2 |
| Onda 8 — portefólio | `docs/DEMO.md`, gravação real, secção de segurança no README, ensaio cronometrado | Ondas 1–6 |
