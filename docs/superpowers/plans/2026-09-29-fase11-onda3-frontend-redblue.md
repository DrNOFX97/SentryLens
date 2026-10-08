# Fase 11 (Onda 3) — Aba "Red vs Blue" no Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Acrescentar ao dashboard a 10ª aba "⚔️ Red vs Blue", que mostra os
dados **reais** já expostos pelo backend da Onda 1 e 2 (correlação Red vs
Blue, log de ataques, captura de rede ao vivo, agentes).

**Architecture:** Um ficheiro novo `redblue.js`, carregado depois de
`app.js`, reaproveita as funções/constantes globais de `app.js`
(`fetchJSON`, `escapeHtml`, `formatTimestamp`, `severityBadge`,
`renderPanelError`, `API_BASE`, `API_KEY`, `WS_RECONNECT_DELAYS_MS`) sem
editar `app.js`. Uma única rota nova no backend (`GET
/api/redblue/attack-log`) expõe o que ainda não tinha endpoint (o
`attack_log.jsonl` e o mapeamento MITRE dos cenários). Tudo o resto lê
endpoints já existentes.

**Tech Stack:** FastAPI (uma rota), HTML/CSS/JS vanilla (mesmo padrão de
`app.js`), Chart.js já carregado (não é necessário para esta aba).

**Spec:** não existe spec dedicada à Onda 3. As fontes são: a secção
"Fase 11 — Red vs Blue (Onda 3 — frontend, planeado, não implementado)" da
página Notion `3caa99e6-526b-8111-89be-db8b6ffe765b`, e a nota de
delimitação nas duas specs
`docs/superpowers/specs/2026-09-17-fase11-redblue-correlator-design.md`
(linha 270) e `docs/superpowers/specs/2026-09-28-fase11-onda2-network-monitoring-design.md`
(linha 350). Os rulings deste plano são provisórios por não haver spec.

## Global Constraints

- **NUNCA mocks, fixtures ou dados inventados** — nem no código, nem nos
  testes, nem nos estados vazios. Cada número e linha mostrados vêm de um
  endpoint real. Sem dados → estado vazio ou erro honesto, nunca
  valores de exemplo. Os testes usam o ficheiro real
  `scripts/attack_log.jsonl` e o backend real; a validação da UI é feita
  no browser contra o backend real a correr.
- **Não editar `app.js`.** A working tree tem uma alteração local sem
  commit (`const API_KEY = "<chave real>"`); nunca fazer `git add app.js`
  nem `git add -A`/`git add .`. Adicionar sempre ficheiros pelo nome.
  Nenhum ficheiro novo contém a chave — `redblue.js` só lê a constante
  global `API_KEY`.
- **NUNCA adicionar `Co-Authored-By: Claude` nem qualquer atribuição ao
  Claude Code** em commits (regra do utilizador, `CLAUDE.md`).
- **Backend na porta 8001, nunca 8000.** Frontend servido por HTTP
  (`http://localhost:5500`), nunca `file://`.
- **Toda a rota REST `/api/*` nova leva `dependencies=_REQUIRE_API_KEY`**
  individualmente (nunca a nível de app).
- **Todo o texto dinâmico passa por `escapeHtml()`** (`scenario`, `target`,
  `tool`, `command`, IPs, nomes de agente podem ser controlados por um
  atacante).
- **Sem "ações de resposta" do Blue Team**: a nota da Onda 3 no Notion
  fala em "ações de resposta (mesmo que manuais nesta fase)", mas nenhum
  endpoint nem ficheiro regista ações de resposta. O painel diz isso
  explicitamente em vez de inventar uma lista.
- **Sem estado "em curso"**: o `attack_log.jsonl` só regista os estados
  `launched`, `failed` e `skipped`; a aba mostra esses três, nunca um
  estado que os dados não têm.
- **Texto em português europeu**, reutilizando as classes de
  `style.css` (`.panel`, `.kpi-grid`, `.card`, `.table-scroll`, `.mono`,
  `.empty-state`, `.panel-note`, `.severity-badge`, `.agent-status`).
- **Sem novas dependências** (só o que `index.html` já carrega).

## Review Focus

1. **Ataques fora da janela de 7 dias.** `/api/redblue/metrics` aceita no
   máximo `hours=168`. O `attack_log.jsonl` real só tem 5 ataques, de
   2026-09-14 — fora dessa janela a 2026-09-29. Resultado esperado do
   backend: `overall.total_attempts == 0` e `coverage_rate == 0.0`. A aba
   tem de mostrar "—" (não "0%") e explicar que não há ataques na
   janela; os 5 ataques continuam visíveis no painel Red Team (que lê o
   log inteiro).
2. **Modelo de ML por treinar / Indexer em baixo.** `/api/redblue/metrics`
   devolve 503 (modelo) ou 502 (Indexer — o disco cheio de 2026-09-28
   ainda pode estar por resolver). Cada painel mostra o erro real
   (`renderPanelError`), sem deixar os outros painéis em branco.
3. **Captura de rede não configurada** (`VM_SSH_HOST` vazio em
   `scripts/.env`, que é o estado atual): `/api/redblue/network` devolve
   `configured:false`. O painel mostra "captura não configurada", não
   "0 pacotes", e não abre o WebSocket.
4. **Pacotes com `src_port`/`dst_port`/`length` a `null`** (ICMP, campos
   truncados): mostrar "—", nunca a palavra `null` nem `NaN`.
5. **`alerts_truncated: true`** (teto de 1000 alertas atingido): mostrar
   aviso de que a cobertura pode estar subestimada. E entradas em
   `invalid_entries`/`unknown_scenario`/`not_executed`: mostrar a
   contagem, nunca ignorar em silêncio.

---

## File Structure

| Ficheiro | Ação | Responsabilidade |
|---|---|---|
| `scripts/main.py` | Modificar | Nova rota `GET /api/redblue/attack-log` |
| `scripts/test_redblue_attack_log.py` | Criar | Teste da rota contra o `attack_log.jsonl` real |
| `index.html` | Modificar | Botão da 10ª aba, `tab-redblue` com os 4 painéis, `<script src="redblue.js">` |
| `style.css` | Modificar | Estilos mínimos `.rb-*` (só o que as classes existentes não cobrem) |
| `redblue.js` | Criar | Toda a lógica da aba (fetch, render, WebSocket de rede, refresh) |
| `README.md`, `CLAUDE.md` | Modificar | Documentar a aba e o endpoint |

---

## Task 1: Endpoint `GET /api/redblue/attack-log`

**Files:**
- Modify: `scripts/main.py` (junto a `get_redblue_network`, ~linha 755)
- Create: `scripts/test_redblue_attack_log.py`

**Interfaces:**
- Consumes: `load_attack_log(path)` (`feature_extractor.py`, já importada em
  `main.py`), `ATTACK_LOG_PATH` e `SCENARIOS` (já em `main.py`),
  `_REQUIRE_API_KEY`.
- Produces: `GET /api/redblue/attack-log` →
  `{"entries": [<linha do attack_log.jsonl>...], "total": int,
  "scenarios": {nome: {"description","tool","event_ids","mitre_tactic","mitre_technique"}}}`.
  Sem ficheiro de log devolve `entries: []`, `total: 0` (200), como
  `load_attack_log` já faz.

- [ ] **Step 1: Escrever o teste (contra o ficheiro real)**

Criar `scripts/test_redblue_attack_log.py`:

```python
"""Testa GET /api/redblue/attack-log contra o attack_log.jsonl REAL
(scripts/attack_log.jsonl) — sem mocks: a rota só lê um ficheiro e um dict
de cenários, por isso não há nada para simular."""

import os
import sys

os.environ.setdefault("SENTRYLENS_API_KEY", "test-key-attack-log")

from fastapi.testclient import TestClient

import main
from attack_scenarios import SCENARIOS
from feature_extractor import load_attack_log

main.app.router.on_startup.clear()
client = TestClient(main.app)
HEADERS = {"X-API-Key": os.environ["SENTRYLENS_API_KEY"]}

failures = 0


def check(name: str, condition: bool) -> None:
    global failures
    if condition:
        print(f"[OK   ] {name}")
    else:
        failures += 1
        print(f"[FALHOU] {name}")


resp = client.get("/api/redblue/attack-log")
check("sem X-API-Key devolve 401", resp.status_code == 401)

resp = client.get("/api/redblue/attack-log", headers=HEADERS)
check("com X-API-Key devolve 200", resp.status_code == 200)
body = resp.json()

real_entries = load_attack_log(main.ATTACK_LOG_PATH)
check("entries é exatamente o conteúdo do attack_log.jsonl real", body["entries"] == real_entries)
check("total == len(entries)", body["total"] == len(real_entries))
check("scenarios tem exatamente os cenários de attack_scenarios.SCENARIOS", set(body["scenarios"]) == set(SCENARIOS))
check(
    "cada cenário expõe o MITRE real de SCENARIOS",
    all(
        body["scenarios"][name]["mitre_technique"] == s.mitre_technique
        and body["scenarios"][name]["mitre_tactic"] == s.mitre_tactic
        for name, s in SCENARIOS.items()
    ),
)
check(
    "nenhum cenário expõe build_command (não serializável / interno)",
    all("build_command" not in v for v in body["scenarios"].values()),
)

if failures:
    print(f"\n[FALHOU] {failures} caso(s)")
    sys.exit(1)
print("\n[OK] Todos os testes passaram")
```

- [ ] **Step 2: Correr e ver falhar**

Run (a partir de `scripts/`): `source .venv/Scripts/activate && python test_redblue_attack_log.py`
Expected: FALHA — `sem X-API-Key devolve 401` passa (404 não é 401, por isso na verdade falha) e o resto falha com 404 na rota.

- [ ] **Step 3: Implementar a rota**

Em `scripts/main.py`, logo a seguir a `get_redblue_network` (antes de `@app.get("/api/export/report"...)`):

```python
@app.get("/api/redblue/attack-log", dependencies=_REQUIRE_API_KEY)
async def get_redblue_attack_log():
    """
    Log de ataques real (attack_log.jsonl, escrito por attack_scenarios.py na
    VM Kali) + o mapeamento MITRE de cada cenário (SCENARIOS) — o que o
    painel Red Team da aba Red vs Blue precisa e que /api/redblue/metrics
    não devolve (só devolve as tentativas dentro da janela de correlação,
    e sem a ferramenta usada). Ficheiro ausente/vazio → entries: [].
    """
    entries = load_attack_log(ATTACK_LOG_PATH)
    return {
        "entries": entries,
        "total": len(entries),
        "scenarios": {
            name: {
                "description": s.description,
                "tool": s.tool,
                "event_ids": s.event_ids,
                "mitre_tactic": s.mitre_tactic,
                "mitre_technique": s.mitre_technique,
            }
            for name, s in SCENARIOS.items()
        },
    }
```

- [ ] **Step 4: Correr e ver passar**

Run: `python test_redblue_attack_log.py`
Expected: 6 linhas `[OK   ]` e `[OK] Todos os testes passaram`.

Run também a regressão que toca `main.py`: `python test_auth.py && python test_redblue.py`
Expected: ambos `[OK] Todos os testes passaram`.

- [ ] **Step 5: Commit**

```bash
git add scripts/main.py scripts/test_redblue_attack_log.py
git commit -m "feat: endpoint GET /api/redblue/attack-log (Fase 11, Onda 3)"
```

---

## Task 2: Esqueleto da aba, KPIs globais e painel Manager/Auditor

**Files:**
- Modify: `index.html` (botão da aba após `data-tab="compliance"`; `tab-content` após `tab-compliance`; `<script src="redblue.js">` a seguir a `app.js`)
- Modify: `style.css` (fim do ficheiro)
- Create: `redblue.js`

**Interfaces:**
- Consumes (globais de `app.js`): `fetchJSON(path)`, `escapeHtml(v)`,
  `formatTimestamp(ts)`, `renderPanelError(selector, msg|null)`,
  `API_BASE`, `API_KEY`. Endpoints: `GET /api/redblue/metrics?hours=168`,
  `GET /api/agents`, `GET /api/health`.
- Produces (usado pelas Tasks 3–5), em `redblue.js`:
  - `rbFormatSeconds(s)` → `"—"` se `null/undefined`, `"12.3 s"` se `< 60`, `"2 min 5 s"` caso contrário.
  - `rbFormatPercent(rate, attempts)` → `"—"` se `attempts === 0`, senão `"75%"`.
  - `rbCell(value)` → `escapeHtml(String(value))` ou `"—"` para `null/undefined/""`.
  - `let rbMetrics = null` (último payload de `/api/redblue/metrics`, ou `null` em erro) e `async function loadRedBlueMetrics()` que o preenche e chama `renderRedBlueKpis`, `renderBluePanel`, `renderRedPanel` (estas duas só existem a partir das Tasks 3/4 — nesta task chamam-se só se `typeof … === "function"`).
  - `async function refreshRedBlueTab()` — corre os loaders com `Promise.allSettled`; `setInterval(refreshRedBlueTab, 30000)`.

- [ ] **Step 1: Botão da aba e script**

Em `index.html`, a seguir à linha `<button class="tab-btn" data-tab="compliance">🛡️ Conformidade</button>`:

```html
    <button class="tab-btn" data-tab="redblue">⚔️ Red vs Blue</button>
```

E a seguir a `<script src="app.js"></script>`:

```html
  <script src="redblue.js"></script>
```

- [ ] **Step 2: Contentor da aba com os 4 painéis (vazios, com "A carregar...")**

Em `index.html`, depois do `</div>` que fecha `tab-compliance` (antes de `</main>`):

```html
    <!-- ===== Red vs Blue ===== -->
    <div class="tab-content" id="tab-redblue">
      <section class="panel" id="redblue-summary-panel">
        <h2>⚔️ Red vs Blue</h2>
        <p class="panel-note">
          Cruza o log de ataques lançados a partir da VM Kali com o que o Wazuh
          (regras e ML) e a captura de rede detetaram. Todos os dados vêm dos
          endpoints reais do backend; a correlação usa sempre a janela máxima
          de 7 dias, independentemente do período escolhido acima.
        </p>
        <section class="kpi-grid" id="redblue-kpi-grid">
          <div class="card"><h3>Ataques na Janela (7 dias)</h3><div class="value" id="kpi-rb-attempts">—</div></div>
          <div class="card"><h3>Cobertura Global</h3><div class="value" id="kpi-rb-coverage">—</div></div>
          <div class="card"><h3>MTTD Médio</h3><div class="value" id="kpi-rb-mttd">—</div></div>
          <div class="card"><h3>Só a Rede Viu</h3><div class="value" id="kpi-rb-network-only">—</div></div>
          <div class="card"><h3>Ninguém Viu</h3><div class="value" id="kpi-rb-neither">—</div></div>
        </section>
        <div id="redblue-notices"></div>
      </section>

      <section class="panel" id="redblue-red-panel">
        <h2>🔴 Red Team — Ataques Lançados</h2>
        <div class="table-scroll">
          <table id="redblue-attack-table">
            <thead>
              <tr><th>Data</th><th>Cenário</th><th>Alvo</th><th>Ferramenta</th><th>Estado</th><th>MITRE</th></tr>
            </thead>
            <tbody id="redblue-attack-body">
              <tr><td colspan="6" class="empty-state">A carregar...</td></tr>
            </tbody>
          </table>
        </div>
      </section>

      <section class="panel" id="redblue-blue-panel">
        <h2>🔵 Blue Team — Deteção por Cenário</h2>
        <p class="panel-note" id="redblue-blue-note"></p>
        <div class="table-scroll">
          <table id="redblue-blue-table">
            <thead>
              <tr>
                <th>Cenário</th><th>Tentativas</th><th>Cobertura</th><th>MTTD médio</th>
                <th>Regra</th><th>ML</th><th>Ambos</th><th>Só rede</th><th>Nenhum</th>
              </tr>
            </thead>
            <tbody id="redblue-blue-body">
              <tr><td colspan="9" class="empty-state">A carregar...</td></tr>
            </tbody>
          </table>
        </div>
        <h3 class="rb-subtitle">MTTD por técnica MITRE ATT&amp;CK</h3>
        <div class="table-scroll">
          <table id="redblue-technique-table">
            <thead>
              <tr><th>Técnica</th><th>Tática</th><th>Tentativas</th><th>Detetadas</th><th>MTTD médio</th></tr>
            </thead>
            <tbody id="redblue-technique-body">
              <tr><td colspan="5" class="empty-state">A carregar...</td></tr>
            </tbody>
          </table>
        </div>
      </section>

      <section class="panel" id="redblue-network-panel">
        <h2>🌐 Rede em Tempo Real</h2>
        <p class="panel-note" id="redblue-network-note">A carregar...</p>
        <section class="kpi-grid">
          <div class="card"><h3>Pacotes no Buffer</h3><div class="value" id="kpi-rb-packets">—</div></div>
          <div class="card"><h3>Deteções Atuais</h3><div class="value" id="kpi-rb-detections">—</div></div>
          <div class="card"><h3>Deteções Acumuladas</h3><div class="value" id="kpi-rb-history">—</div></div>
        </section>
        <h3 class="rb-subtitle">Deteções de rede</h3>
        <div class="table-scroll">
          <table id="redblue-detections-table">
            <thead><tr><th>Data</th><th>Tipo</th><th>Origem</th><th>Destino</th><th>Detalhe</th></tr></thead>
            <tbody id="redblue-detections-body">
              <tr><td colspan="5" class="empty-state">A carregar...</td></tr>
            </tbody>
          </table>
        </div>
        <h3 class="rb-subtitle">Últimos pacotes (só metadados)</h3>
        <div class="table-scroll">
          <table id="redblue-packets-table">
            <thead><tr><th>Data</th><th>Origem</th><th>Destino</th><th>Protocolo</th><th>Bytes</th></tr></thead>
            <tbody id="redblue-packets-body">
              <tr><td colspan="5" class="empty-state">A carregar...</td></tr>
            </tbody>
          </table>
        </div>
      </section>

      <section class="panel" id="redblue-manager-panel">
        <h2>🧭 Manager / Auditor</h2>
        <section class="kpi-grid">
          <div class="card"><h3>Backend</h3><div class="value" id="kpi-rb-backend">—</div></div>
          <div class="card"><h3>Agentes Ativos</h3><div class="value" id="kpi-rb-agents">—</div></div>
          <div class="card"><h3>Alertas Analisados</h3><div class="value" id="kpi-rb-alerts-fetched">—</div></div>
          <div class="card"><h3>Captura de Rede</h3><div class="value" id="kpi-rb-capture">—</div></div>
        </section>
        <div class="table-scroll">
          <table id="redblue-agents-table">
            <thead><tr><th>Agente</th><th>IP</th><th>Estado</th><th>Último contacto</th></tr></thead>
            <tbody id="redblue-agents-body">
              <tr><td colspan="4" class="empty-state">A carregar...</td></tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
```

- [ ] **Step 3: CSS mínimo**

Acrescentar ao fim de `style.css`:

```css
/* --- Aba Red vs Blue (Fase 11, Onda 3) --- */
.rb-subtitle { margin: 20px 0 8px; font-size: 1rem; }
.rb-notice { margin: 8px 0; padding: 8px 12px; border-radius: 6px; background: #fdebd0; color: #b9770e; font-size: 0.9rem; }
.rb-badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 0.8rem; font-weight: 600; color: #fff; }
.rb-badge.launched { background: #27ae60; }
.rb-badge.failed { background: #e74c3c; }
.rb-badge.skipped { background: #7f8c8d; }
tr.row-gap { background: #fdebd0; }
```

- [ ] **Step 4: `redblue.js` — helpers, KPIs, avisos e Manager/Auditor**

Criar `redblue.js`:

```js
// Aba "Red vs Blue" (Fase 11, Onda 3). Carregado depois de app.js e
// reutiliza os seus globais (fetchJSON, escapeHtml, formatTimestamp,
// renderPanelError, API_BASE, API_KEY) — não redeclarar nenhum deles aqui.
// Só mostra dados reais dos endpoints do backend; sem dados, estado vazio.

const RB_REFRESH_MS = 30000;
const RB_METRICS_HOURS = 168; // máximo aceite por /api/redblue/metrics
const RB_MAX_PACKET_ROWS = 200;
const RB_NETWORK_WS_URL = `${API_BASE.replace(/^http/, "ws")}/ws/network?api_key=${encodeURIComponent(API_KEY)}`;

let rbMetrics = null;
let rbAttackLog = null;

function rbCell(value) {
  if (value === null || value === undefined || value === "") return "—";
  return escapeHtml(String(value));
}

function rbFormatSeconds(seconds) {
  if (seconds === null || seconds === undefined) return "—";
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  return `${Math.floor(seconds / 60)} min ${Math.round(seconds % 60)} s`;
}

function rbFormatPercent(rate, attempts) {
  if (!attempts) return "—";
  return `${Math.round(rate * 100)}%`;
}

function rbSetText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function renderRedBlueKpis(data) {
  const overall = data.overall || {};
  const attempts = overall.total_attempts || 0;
  rbSetText("kpi-rb-attempts", attempts);
  rbSetText("kpi-rb-coverage", rbFormatPercent(overall.coverage_rate, attempts));
  rbSetText("kpi-rb-mttd", rbFormatSeconds(overall.avg_mttd_seconds));
  rbSetText("kpi-rb-network-only", data.network_capture_configured ? (overall.detected_by_network_only ?? 0) : "—");
  rbSetText("kpi-rb-neither", overall.detected_by_neither ?? 0);
  rbSetText("kpi-rb-alerts-fetched", data.alerts_fetched ?? "—");
  rbSetText("kpi-rb-capture", data.network_capture_configured ? "Configurada" : "Não configurada");

  const notices = [];
  if (attempts === 0) {
    notices.push("Sem ataques na janela de 7 dias — não há nada para correlacionar (cobertura e MTTD não se aplicam). O painel Red Team lista o log completo.");
  }
  if (data.alerts_truncated) {
    notices.push(`Foram analisados ${data.alerts_fetched} alertas (teto de 1000): a cobertura pode estar subestimada.`);
  }
  const counts = [
    ["not_executed", "não executadas"],
    ["unknown_scenario", "de cenário desconhecido"],
    ["invalid_entries", "inválidas"],
  ];
  counts.forEach(([key, label]) => {
    const n = (data[key] || []).length;
    if (n > 0) notices.push(`${n} entrada(s) do log ${label} ficaram de fora da correlação.`);
  });
  document.getElementById("redblue-notices").innerHTML = notices
    .map((n) => `<div class="rb-notice">⚠️ ${escapeHtml(n)}</div>`)
    .join("");
}

async function loadRedBlueMetrics() {
  try {
    rbMetrics = await fetchJSON(`/api/redblue/metrics?hours=${RB_METRICS_HOURS}`);
    renderPanelError("#redblue-summary-panel", null);
    renderRedBlueKpis(rbMetrics);
  } catch (err) {
    console.error(err);
    rbMetrics = null;
    const message = err.status === 503
      ? "Modelo de ML ainda não foi treinado. Corre scripts/train_anomaly_model.py."
      : (err.message || "Erro ao carregar a correlação Red vs Blue.");
    renderPanelError("#redblue-summary-panel", message);
  }
  if (typeof renderBluePanel === "function") renderBluePanel(rbMetrics);
  if (typeof renderRedPanel === "function") renderRedPanel(rbAttackLog, rbMetrics);
}

async function loadManagerPanel() {
  const tbody = document.getElementById("redblue-agents-body");
  try {
    const [health, agents] = await Promise.all([fetchJSON("/api/health"), fetchJSON("/api/agents")]);
    renderPanelError("#redblue-manager-panel", null);
    rbSetText("kpi-rb-backend", health.status === "ok" ? "Ativo" : String(health.status));
    const list = agents.agents || [];
    rbSetText("kpi-rb-agents", list.filter((a) => a.status === "active").length);
    if (list.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" class="empty-state">Nenhum agente encontrado</td></tr>';
      return;
    }
    tbody.innerHTML = list
      .map(
        (a) => `
      <tr>
        <td>${rbCell(a.name)}</td>
        <td class="mono">${rbCell(a.ip)}</td>
        <td><span class="agent-status ${escapeHtml(a.status)}">${rbCell(a.status)}</span></td>
        <td class="mono">${escapeHtml(formatTimestamp(a.last_keep_alive))}</td>
      </tr>`,
      )
      .join("");
  } catch (err) {
    console.error(err);
    renderPanelError("#redblue-manager-panel", err.message || "Erro ao carregar agentes.");
  }
}

async function refreshRedBlueTab() {
  await Promise.allSettled([
    loadRedBlueMetrics(),
    loadManagerPanel(),
    typeof loadRedPanel === "function" ? loadRedPanel() : Promise.resolve(),
    typeof loadNetworkPanel === "function" ? loadNetworkPanel() : Promise.resolve(),
  ]);
}

refreshRedBlueTab();
setInterval(refreshRedBlueTab, RB_REFRESH_MS);
```

- [ ] **Step 5: Verificar sintaxe**

Run: `node --check redblue.js` (se `node` não existir, saltar este passo e usar o Step 6).
Expected: sem output.

- [ ] **Step 6: Verificar no browser contra o backend real**

Com o backend real a correr em `scripts/` (`uvicorn main:app --port 8001`) e o frontend em `python -m http.server 5500` na raiz do repo, abrir `http://localhost:5500` no browser (chrome-devtools ou playwright), clicar na aba "⚔️ Red vs Blue" e confirmar:
- a consola não tem erros de JS;
- "Backend" mostra "Ativo" e "Agentes Ativos" bate com o valor da aba "Agentes";
- "Captura de Rede" mostra "Não configurada" (estado real atual, `VM_SSH_HOST` vazio);
- se `/api/redblue/metrics` responder 200 com `total_attempts == 0`, "Cobertura Global" mostra "—" e aparece o aviso de "Sem ataques na janela de 7 dias".

Comparar com a resposta real: `curl -s -H "X-API-Key: $KEY" localhost:8001/api/redblue/metrics` (com `KEY` lido de `scripts/.env`).

- [ ] **Step 7: Commit**

```bash
git add index.html style.css redblue.js
git commit -m "feat: aba Red vs Blue - esqueleto, KPIs e painel Manager/Auditor (Fase 11, Onda 3)"
```

---

## Task 3: Painel Red Team (log de ataques + MITRE)

**Files:**
- Modify: `redblue.js` (acrescentar antes das linhas finais `refreshRedBlueTab();`/`setInterval`)

**Interfaces:**
- Consumes: `GET /api/redblue/attack-log` (Task 1) →
  `{entries, total, scenarios}`; `rbCell`, `rbAttackLog` (Task 2).
- Produces: `async function loadRedPanel()` (preenche `rbAttackLog` e chama
  `renderRedPanel`) e `function renderRedPanel(attackLog, metrics)`. Já são
  chamadas por `refreshRedBlueTab`/`loadRedBlueMetrics` da Task 2 (que
  testam `typeof … === "function"`).

- [ ] **Step 1: Implementar**

```js
async function loadRedPanel() {
  try {
    rbAttackLog = await fetchJSON("/api/redblue/attack-log");
    renderPanelError("#redblue-red-panel", null);
  } catch (err) {
    console.error(err);
    rbAttackLog = null;
    renderPanelError("#redblue-red-panel", err.message || "Erro ao carregar o log de ataques.");
  }
  renderRedPanel(rbAttackLog, rbMetrics);
}

function renderRedPanel(attackLog) {
  const tbody = document.getElementById("redblue-attack-body");
  if (!attackLog) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Log de ataques indisponível</td></tr>';
    return;
  }
  const entries = attackLog.entries || [];
  if (entries.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Nenhum ataque registado em attack_log.jsonl</td></tr>';
    return;
  }
  const scenarios = attackLog.scenarios || {};
  const sorted = [...entries].sort((a, b) => String(b.timestamp).localeCompare(String(a.timestamp)));
  tbody.innerHTML = sorted
    .map((e) => {
      const s = scenarios[e.scenario];
      const mitre = s ? `${s.mitre_technique} — ${s.mitre_tactic}` : null;
      const status = String(e.status);
      return `
      <tr>
        <td class="mono">${escapeHtml(formatTimestamp(e.timestamp))}</td>
        <td>${rbCell(e.scenario)}</td>
        <td class="mono">${rbCell(e.target)}</td>
        <td>${rbCell(e.tool)}</td>
        <td><span class="rb-badge ${escapeHtml(status)}">${escapeHtml(status)}</span></td>
        <td>${rbCell(mitre)}</td>
      </tr>`;
    })
    .join("");
}
```

- [ ] **Step 2: Verificar no browser (dados reais)**

Recarregar a aba. O `scripts/attack_log.jsonl` real tem 5 linhas (2026-09-14). Confirmar que a tabela mostra exatamente 5 linhas, dos 5 cenários (`smb_enum`, `blank_password_check`, `account_lockout_spray`, `lateral_movement_schtasks`, `brute_force_rdp`), alvo `192.168.1.169`, ferramenta e MITRE iguais à resposta de `curl -s -H "X-API-Key: $KEY" localhost:8001/api/redblue/attack-log`, e que nenhum HTML dos campos é interpretado (tudo escapado).

- [ ] **Step 3: Commit**

```bash
git add redblue.js
git commit -m "feat: painel Red Team da aba Red vs Blue (Fase 11, Onda 3)"
```

---

## Task 4: Painel Blue Team (deteção por cenário e MTTD por técnica)

**Files:**
- Modify: `redblue.js`

**Interfaces:**
- Consumes: `rbMetrics` = payload de `/api/redblue/metrics`:
  `by_scenario[nome] = {attempts, detected, detected_by_rule, detected_by_ml, detected_by_both, detected_by_none, detected_by_network_only, detected_by_windows_only, detected_by_both_sources, detected_by_neither, coverage_rate, avg_mttd_seconds}`;
  `attempts[] = {scenario, target, timestamp, mitre_tactic, mitre_technique, detected, detected_by, mttd_seconds, matched_event_ids, detected_by_network, network_detection_types, mttd_network_seconds, coverage_gap}`.
- Produces: `function rbMttdByTechnique(attempts)` → array de
  `{technique, tactic, attempts, detected, avgMttd}` (média só sobre
  `mttd_seconds` não-nulos; `avgMttd = null` se nenhum) e
  `function renderBluePanel(metrics)`.

- [ ] **Step 1: Implementar**

```js
function rbMttdByTechnique(attempts) {
  const groups = new Map();
  (attempts || []).forEach((a) => {
    const g = groups.get(a.mitre_technique) || {
      technique: a.mitre_technique, tactic: a.mitre_tactic, attempts: 0, detected: 0, mttds: [],
    };
    g.attempts += 1;
    if (a.detected) g.detected += 1;
    if (a.mttd_seconds !== null && a.mttd_seconds !== undefined) g.mttds.push(a.mttd_seconds);
    groups.set(a.mitre_technique, g);
  });
  return [...groups.values()]
    .map((g) => ({
      technique: g.technique,
      tactic: g.tactic,
      attempts: g.attempts,
      detected: g.detected,
      avgMttd: g.mttds.length ? g.mttds.reduce((x, y) => x + y, 0) / g.mttds.length : null,
    }))
    .sort((x, y) => String(x.technique).localeCompare(String(y.technique)));
}

function renderBluePanel(metrics) {
  const body = document.getElementById("redblue-blue-body");
  const techBody = document.getElementById("redblue-technique-body");
  const note = document.getElementById("redblue-blue-note");
  note.textContent =
    "Ações de resposta: a aplicação não regista ações de resposta (nem manuais), por isso não há nada para mostrar aqui. " +
    "Este painel mostra apenas o que foi detetado, por que método e ao fim de quanto tempo.";

  if (!metrics) {
    body.innerHTML = '<tr><td colspan="9" class="empty-state">Correlação indisponível</td></tr>';
    techBody.innerHTML = '<tr><td colspan="5" class="empty-state">Correlação indisponível</td></tr>';
    return;
  }

  const names = Object.keys(metrics.by_scenario || {}).sort();
  if (names.length === 0) {
    body.innerHTML = '<tr><td colspan="9" class="empty-state">Sem tentativas de ataque na janela de 7 dias</td></tr>';
  } else {
    body.innerHTML = names
      .map((name) => {
        const b = metrics.by_scenario[name];
        return `
        <tr>
          <td>${rbCell(name)}</td>
          <td>${b.attempts}</td>
          <td>${rbFormatPercent(b.coverage_rate, b.attempts)}</td>
          <td>${rbFormatSeconds(b.avg_mttd_seconds)}</td>
          <td>${b.detected_by_rule}</td>
          <td>${b.detected_by_ml}</td>
          <td>${b.detected_by_both}</td>
          <td>${metrics.network_capture_configured ? b.detected_by_network_only : "—"}</td>
          <td>${b.detected_by_neither}</td>
        </tr>`;
      })
      .join("");
  }

  const techniques = rbMttdByTechnique(metrics.attempts);
  if (techniques.length === 0) {
    techBody.innerHTML = '<tr><td colspan="5" class="empty-state">Sem tentativas de ataque na janela de 7 dias</td></tr>';
  } else {
    techBody.innerHTML = techniques
      .map(
        (t) => `
      <tr>
        <td>${rbCell(t.technique)}</td>
        <td>${rbCell(t.tactic)}</td>
        <td>${t.attempts}</td>
        <td>${t.detected}</td>
        <td>${rbFormatSeconds(t.avgMttd)}</td>
      </tr>`,
      )
      .join("");
  }
}
```

- [ ] **Step 2: Verificar no browser**

Com o backend real: se `by_scenario` vier vazio (ataques de 2026-09-14 fora da janela) a tabela mostra a mensagem "Sem tentativas…". Quando existirem tentativas reais na janela (depois de o utilizador lançar cenários a partir do Kali), comparar cada linha com a resposta real de `/api/redblue/metrics`, e o MTTD por técnica com o recálculo independente:

```bash
curl -s -H "X-API-Key: $KEY" "localhost:8001/api/redblue/metrics?hours=168" | python -c "import sys,json,collections; d=json.load(sys.stdin); g=collections.defaultdict(list); [g[a['mitre_technique']].append(a['mttd_seconds']) for a in d['attempts'] if a['mttd_seconds'] is not None]; print({k: round(sum(v)/len(v),2) for k,v in g.items()})"
```

Expected: os valores batem com a coluna "MTTD médio" (formatada).

- [ ] **Step 3: Commit**

```bash
git add redblue.js
git commit -m "feat: painel Blue Team da aba Red vs Blue (Fase 11, Onda 3)"
```

---

## Task 5: Painel de rede em tempo real (snapshot + `/ws/network`)

**Files:**
- Modify: `redblue.js`

**Interfaces:**
- Consumes: `GET /api/redblue/network` →
  `{configured, packets:[{timestamp,src_ip,dst_ip,protocol,length,src_port,dst_port}], detections:[{type,src_ip,dst_ip,timestamp,detail}], detection_history:[...]}`;
  `WS /ws/network?api_key=` → mensagens
  `{"type":"packet","packet":{...}}` e
  `{"type":"network_detection","detection":{...}}`;
  `WS_RECONNECT_DELAYS_MS` (global de `app.js`), `RB_NETWORK_WS_URL`,
  `RB_MAX_PACKET_ROWS`.
- Produces: `async function loadNetworkPanel()` (snapshot; chamada por
  `refreshRedBlueTab`), `function connectNetworkSocket()`,
  `function renderNetworkPanel(state)` com
  `state = {configured, packets, detections, history}`.

- [ ] **Step 1: Implementar**

```js
const rbNetwork = { configured: false, packets: [], detections: [], history: [] };
let rbNetworkWs = null;
let rbNetworkReconnectAttempts = 0;

function rbDetectionDetail(detail) {
  if (!detail || typeof detail !== "object") return "—";
  return Object.entries(detail).map(([k, v]) => `${k}: ${v}`).join(", ");
}

function renderNetworkPanel() {
  const note = document.getElementById("redblue-network-note");
  const detBody = document.getElementById("redblue-detections-body");
  const pktBody = document.getElementById("redblue-packets-body");

  if (!rbNetwork.configured) {
    note.textContent =
      "Captura de rede não configurada: define VM_SSH_HOST, VM_SSH_USER e VM_SSH_KEY_PATH em scripts/.env e ativa a captura na VM (docs/LAB_WAZUH_HYPERV.md).";
    rbSetText("kpi-rb-packets", "—");
    rbSetText("kpi-rb-detections", "—");
    rbSetText("kpi-rb-history", "—");
    detBody.innerHTML = '<tr><td colspan="5" class="empty-state">Captura não configurada</td></tr>';
    pktBody.innerHTML = '<tr><td colspan="5" class="empty-state">Captura não configurada</td></tr>';
    return;
  }

  note.textContent = "Metadados de pacotes capturados na VM Wazuh (sem payload). Deteções por regras fixas: port scan, brute force e volume.";
  rbSetText("kpi-rb-packets", rbNetwork.packets.length);
  rbSetText("kpi-rb-detections", rbNetwork.detections.length);
  rbSetText("kpi-rb-history", rbNetwork.history.length);

  const dets = [...rbNetwork.history].reverse();
  detBody.innerHTML = dets.length
    ? dets
        .map(
          (d) => `
      <tr>
        <td class="mono">${escapeHtml(formatTimestamp(d.timestamp))}</td>
        <td>${rbCell(d.type)}</td>
        <td class="mono">${rbCell(d.src_ip)}</td>
        <td class="mono">${rbCell(d.dst_ip)}</td>
        <td>${escapeHtml(rbDetectionDetail(d.detail))}</td>
      </tr>`,
        )
        .join("")
    : '<tr><td colspan="5" class="empty-state">Nenhuma deteção de rede até agora</td></tr>';

  const pkts = rbNetwork.packets.slice(-RB_MAX_PACKET_ROWS).reverse();
  pktBody.innerHTML = pkts.length
    ? pkts
        .map((p) => {
          const src = p.src_port != null ? `${p.src_ip}:${p.src_port}` : p.src_ip;
          const dst = p.dst_port != null ? `${p.dst_ip}:${p.dst_port}` : p.dst_ip;
          return `
      <tr>
        <td class="mono">${escapeHtml(formatTimestamp(p.timestamp))}</td>
        <td class="mono">${rbCell(src)}</td>
        <td class="mono">${rbCell(dst)}</td>
        <td>${rbCell(p.protocol)}</td>
        <td>${rbCell(p.length)}</td>
      </tr>`;
        })
        .join("")
    : '<tr><td colspan="5" class="empty-state">Sem pacotes no buffer</td></tr>';
}

async function loadNetworkPanel() {
  try {
    const data = await fetchJSON("/api/redblue/network");
    renderPanelError("#redblue-network-panel", null);
    rbNetwork.configured = !!data.configured;
    rbNetwork.packets = data.packets || [];
    rbNetwork.detections = data.detections || [];
    rbNetwork.history = data.detection_history || [];
    renderNetworkPanel();
    if (rbNetwork.configured && !rbNetworkWs) connectNetworkSocket();
  } catch (err) {
    console.error(err);
    renderPanelError("#redblue-network-panel", err.message || "Erro ao carregar a captura de rede.");
  }
}

function connectNetworkSocket() {
  rbNetworkWs = new WebSocket(RB_NETWORK_WS_URL);
  rbNetworkWs.onopen = () => {
    rbNetworkReconnectAttempts = 0;
  };
  rbNetworkWs.onmessage = (event) => {
    let msg;
    try {
      msg = JSON.parse(event.data);
    } catch (err) {
      console.error("Mensagem /ws/network inválida:", err);
      return;
    }
    if (msg && msg.type === "packet" && msg.packet) {
      rbNetwork.packets.push(msg.packet);
      if (rbNetwork.packets.length > RB_MAX_PACKET_ROWS * 10) rbNetwork.packets.shift();
    } else if (msg && msg.type === "network_detection" && msg.detection) {
      rbNetwork.detections.push(msg.detection);
      rbNetwork.history.push(msg.detection);
    } else {
      return;
    }
    renderNetworkPanel();
  };
  rbNetworkWs.onerror = () => rbNetworkWs.close();
  rbNetworkWs.onclose = () => {
    rbNetworkWs = null;
    // Sem tempo real, o refresh de 30s (loadNetworkPanel) continua a atualizar
    // o painel por snapshot — e volta a abrir o socket se a captura estiver ativa.
    if (rbNetworkReconnectAttempts < WS_RECONNECT_DELAYS_MS.length) {
      const delay = WS_RECONNECT_DELAYS_MS[rbNetworkReconnectAttempts];
      rbNetworkReconnectAttempts += 1;
      setTimeout(() => {
        if (rbNetwork.configured && !rbNetworkWs) connectNetworkSocket();
      }, delay);
    }
  };
}
```

- [ ] **Step 2: Verificar no browser (estado real atual)**

Com `VM_SSH_HOST` vazio: o painel mostra a nota "Captura de rede não configurada…", KPIs "—", tabelas "Captura não configurada", e o separador Network do browser **não** mostra nenhum pedido a `/ws/network`. Confirmar com a resposta real `curl -s -H "X-API-Key: $KEY" localhost:8001/api/redblue/network` → `{"configured": false, ...}`.

- [ ] **Step 3: Verificar com captura real (só depois de o utilizador ativar a captura na VM)**

Depois de `VM_SSH_HOST/USER/KEY_PATH` estarem em `scripts/.env`, o backend reiniciado e o `tshark` a correr na VM: o painel mostra pacotes a chegar em tempo real (linhas novas no topo sem recarregar), o KPI "Pacotes no Buffer" bate com `len(packets)` do `curl`, e pacotes ICMP mostram origem/destino sem `:null`. Se este passo não puder ser feito, registar no relatório final que o caminho "configurado" ficou por validar — não simular.

- [ ] **Step 4: Commit**

```bash
git add redblue.js
git commit -m "feat: painel de rede em tempo real da aba Red vs Blue (Fase 11, Onda 3)"
```

---

## Task 6: Documentação

**Files:**
- Modify: `README.md` (secção de endpoints e de frontend)
- Modify: `CLAUDE.md` (nota "Frontend (10ª aba) ainda não implementado" em `redblue_correlator.py`, e a lista de ficheiros do frontend)

**Interfaces:** nenhuma.

- [ ] **Step 1: README**

Acrescentar `GET /api/redblue/attack-log` à tabela de endpoints (resposta:
`entries`, `total`, `scenarios`; exige `X-API-Key`) e descrever a 10ª aba
"⚔️ Red vs Blue" (`redblue.js`): 4 painéis (Red Team, Blue Team, Rede em
tempo real, Manager/Auditor), janela fixa de 7 dias, e as três situações
em que mostra estado vazio em vez de números (sem ataques na janela,
captura de rede não configurada, modelo de ML por treinar).

- [ ] **Step 2: CLAUDE.md**

Substituir "Frontend (10ª aba) ainda não implementado — ver Onda 2." pela
frase: "Frontend (10ª aba, `redblue.js`) implementado na Onda 3 — não edita
`app.js`, reutiliza os seus globais." Acrescentar `redblue.js` à descrição
do frontend estático. (`CLAUDE.md` está no `.gitignore` — só local.)

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: documenta a aba Red vs Blue e /api/redblue/attack-log (Fase 11, Onda 3)"
```

---

## Verificação final (depois da Task 6)

- [ ] `cd scripts && python test_redblue_attack_log.py && python test_redblue.py && python test_auth.py && python test_websocket_alerts.py` → todos `[OK]`.
- [ ] `git log --format=%B origin/main..main | grep -i co-authored-by` → vazio.
- [ ] `git status` → `app.js` continua como estava (alteração local da chave, nunca commitada) e nenhum ficheiro novo contém a chave: `git grep -n "805b6d80"` → sem resultados.
- [ ] Aba aberta no browser com o backend real: sem erros na consola, os 4 painéis mostram dados reais ou o estado vazio/erro honesto descrito no Review Focus.

## Self-Review

- **Spec coverage** (secção Onda 3 do Notion): aba nova (Task 2); Painel Red Team com timeline, MITRE e estado (Task 3 — estado limitado ao que o log tem); Painel Blue Team agrupado por cenário (Task 4 — "ações de resposta" declaradas como inexistentes); Manager/Auditor reaproveitando o que existe (Task 2); métricas agregadas e MTTD por técnica (Tasks 2 e 4); painel de rede da Onda 2 (Task 5). "Alimentar a IA" é backend/ML, fora do escopo de frontend.
- **Placeholders:** nenhum; todo o código está completo.
- **Consistência de nomes:** `rbMetrics`, `rbAttackLog`, `rbCell`, `rbFormatSeconds`, `rbFormatPercent`, `renderRedPanel`, `renderBluePanel`, `loadRedPanel`, `loadNetworkPanel`, `loadManagerPanel`, `refreshRedBlueTab` definidos uma vez e usados com a mesma assinatura. `renderRedPanel(attackLog, metrics)` aceita o 2º argumento mas só usa o 1º (ok em JS).
- **Review Focus → testes:** (1) Task 2 Step 6 e Task 4 Step 2; (2) `loadRedBlueMetrics` catch + Task 2 Step 6; (3) Task 5 Step 2; (4) Task 5 código `!= null` + Step 3; (5) Task 2 `renderRedBlueKpis` (avisos).
