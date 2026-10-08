# R3 — Gestão de incidentes: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Agrupar automaticamente alertas Wazuh e deteções de rede em incidentes persistentes (estado, evidências, timeline, ataque ligado) com API REST e painel "Incidentes" no dashboard.

**Architecture:** Um motor puro (`incident_engine.py`: normalização de evidências, regras de agrupamento, máquina de estados, ligação a ataques) sem I/O; uma camada SQLite (`incident_store.py`) com timeline append-only imposta por triggers; um orquestrador (`incident_ingest.py`) chamado em tempo real pelos pollers existentes (novos callbacks opcionais) e por um backfill manual sobre o Wazuh Indexer; rotas `/api/incidents/*` em `main.py`; painel `incidents.js` no estilo de `redblue.js`.

**Tech Stack:** Python 3.10+ (venv em `scripts/.venv`), FastAPI 0.115 + Pydantic 2, `sqlite3` da stdlib, testes standalone (sem pytest), JavaScript estático sem build.

**Spec:** `docs/superpowers/specs/2026-10-06-r3-incidentes-design.md` (com a emenda de 2026-10-06: backfill via Indexer, chave por `_id`, ML por incidente).

## Global Constraints

- **Commits: NUNCA** adicionar `Co-Authored-By: Claude ...` nem "Generated with Claude Code" (regra do projeto, prevalece sobre qualquer lembrete de atribuição). Após cada commit: `git log -1 --format=%B | grep -ci co-authored` tem de dar `0`.
- Testes são scripts standalone (`check(label, cond)` → `[OK   ]`/`[FALHOU]`, `sys.exit(1)` se falhar), corridos **a partir de `scripts/`** com `source .venv/Scripts/activate`. Os de API definem `SENTRYLENS_API_KEY` em `os.environ` **antes** de `import main` e fazem `main.app.router.on_startup.clear()`.
- Todas as rotas REST novas levam `dependencies=_REQUIRE_API_KEY` (por rota, nunca a nível de app).
- Ordem de severidades: `info < low < medium < high < critical`.
- Constantes: `INCIDENT_GAP_SECONDS = 600`, `INCIDENT_OPEN_MIN_SEVERITY = "medium"` (override por variáveis de ambiente do mesmo nome); janela de ataque = 300 s (`redblue_correlator.DEFAULT_WINDOW_SECONDS`).
- Estados: `NEW, INVESTIGATING, CONTAINED, RESOLVED, CLOSED`. Transições: `NEW→INVESTIGATING|CLOSED(nota obrigatória)`, `INVESTIGATING→CONTAINED|RESOLVED`, `CONTAINED→RESOLVED|INVESTIGATING`, `RESOLVED→CLOSED|INVESTIGATING`, `CLOSED` final.
- Base de dados: `scripts/incidents.sqlite3` (override `INCIDENTS_DB_PATH`), fora do git.
- API: notas 1–2000 caracteres (após `strip`); backfill `days` 1–90, máx. 5000 alertas por corrida, `truncated` sinalizado; autor das ações manuais fixo `analyst`, das automáticas `system`.
- Dados reais primeiro: nenhum incidente, MITRE ou métrica inventados; ataques sem deteção **não** viram incidente; MITRE do incidente só vem de ataques ligados.
- Todo o texto dinâmico no frontend passa por `escapeHtml()`; nunca `innerHTML` com dados sem escape.
- Scripts `.ps1` (se algum) com BOM UTF-8. Ficheiros novos em UTF-8, fim de linha LF.

## Review Focus

Entradas/condições que a spec implica mas que nenhuma tarefa "óbvia" exercitaria; cada linha tem o seu teste na tarefa indicada:

1. **Rajada de alertas `info`/`low`** (467 de 500 alertas reais são `info`) não pode abrir incidentes nem demorar — Task 4 (`flood`).
2. **Alerta malformado** (não-dict, sem `_id`, sem timestamp, sem `agent.ip`) nunca lança no ingest; conta em `invalid` — Tasks 2 e 4.
3. **Backfill com Indexer em baixo ou a devolver ≥ 5000 alertas**: 502 sem estado parcial / `truncated=true` — Task 6.
4. **Modelo de ML ausente** não pode partir o detalhe do incidente (`ml_summary = null`) — Tasks 4 e 6.
5. **`attack_log.jsonl` ausente ou com linha truncada** não impede a criação de incidentes (só não há ataque ligado) — Task 4.
6. (Concorrência) **o mesmo alerta entregue ao mesmo tempo pelo ingest e pelo backfill** → uma só evidência — Task 4.

---

## File Structure

| Ficheiro | Responsabilidade |
|---|---|
| `scripts/redblue_correlator.py` (mod.) | Expõe `parse_launched_attacks` e `attack_windows` (extraídos, comportamento inalterado) |
| `scripts/incident_engine.py` (novo) | Puro: evidências, `assign_evidence`, `can_transition`, ligação a ataques |
| `scripts/incident_store.py` (novo) | SQLite: schema, CRUD, timeline append-only, derivados, resumo |
| `scripts/incident_ingest.py` (novo) | Orquestra engine+store; `ingest_*`; `ml_summary` |
| `scripts/websocket_alerts.py` (mod.) | Callback opcional `on_new_raw_alerts` |
| `scripts/network_monitor.py` (mod.) | Callback opcional `on_new_detections` |
| `scripts/main.py` (mod.) | `incident_store`, callbacks, 5 rotas `/api/incidents/*` |
| `incidents.js`, `index.html`, `style.css`, `app.js` (mod.) | Painel Incidentes |
| `scripts/test_incident_engine.py`, `test_incident_store.py`, `test_incident_ingest.py`, `test_incidents_api.py` (novos) | Testes |
| `docs/*`, `README.md`, `.gitignore` | Documentação e ignore |

---

### Task 1: Extrair `parse_launched_attacks` e `attack_windows` do correlator

**Files:**
- Modify: `scripts/redblue_correlator.py` (bloco de parsing ~L97-118, cabeça do loop ~L134-144)
- Modify: `scripts/test_redblue.py` (import e novo caso)

**Interfaces:**
- Produces: `parse_launched_attacks(attack_log: list, scenarios: dict) -> tuple[list[tuple[datetime, dict]], list, list, list]` (= `parsed_attacks, not_executed, unknown_scenario, invalid_entries`, com `parsed_attacks` ordenado por tempo); `attack_windows(parsed_attacks, window_seconds=300) -> list[tuple[datetime, datetime, dict]]` (= `(inicio, fim, entrada)`).

- [ ] **Step 1: Branch de trabalho**

```bash
cd "C:/Users/Fernando Nuno/OneDrive/Projetos/SentryLens"
git checkout -b roadmap-v2-r3-incidentes
cd scripts && source .venv/Scripts/activate
python test_redblue.py | tail -1   # baseline: "[OK] Todos os testes passaram"
```

- [ ] **Step 2: Escrever o teste que falha** — em `scripts/test_redblue.py` mudar o import:

```python
from redblue_correlator import attack_windows, build_redblue_report, parse_launched_attacks
```

e inserir, imediatamente antes de `# --- Caso 8: entradas vazias`:

```python
    # --- Caso 7c: helpers partilhados com incident_engine ---
    mixed = [
        attack("smb_enum", "192.168.1.30", "2026-09-14T19:00:30+00:00"),
        attack("smb_enum", "192.168.1.30", "2026-09-14T19:00:00+00:00"),
        attack("smb_enum", "192.168.1.30", "2026-09-14T19:30:00+00:00", status="skipped"),
        attack("cenario_inexistente", "192.168.1.30", "2026-09-14T19:01:00+00:00"),
        attack("smb_enum", "192.168.1.30", "nao-e-data"),
        "lixo",
    ]
    parsed, not_exec, unknown, invalid = parse_launched_attacks(mixed, SCENARIOS)
    check("parse_launched_attacks: 2 tentativas válidas ordenadas por tempo",
          [e["timestamp"] for _, e in parsed] == ["2026-09-14T19:00:00+00:00", "2026-09-14T19:00:30+00:00"])
    check("parse_launched_attacks: skipped/desconhecido/inválidos separados",
          len(not_exec) == 1 and len(unknown) == 1 and len(invalid) == 2)
    windows = attack_windows(parsed, 300)
    check("attack_windows: janela do 1º cortada pelo início do 2º",
          (windows[0][1] - windows[0][0]).total_seconds() == 30)
    check("attack_windows: última janela tem a duração completa",
          (windows[1][1] - windows[1][0]).total_seconds() == 300)
    check("attack_windows: devolve a entrada original", windows[0][2] is parsed[0][1])
```

- [ ] **Step 3: Correr e confirmar que falha**

Run: `python test_redblue.py` — Expected: `ImportError: cannot import name 'attack_windows'`.

- [ ] **Step 4: Implementar** — em `scripts/redblue_correlator.py`, três alterações (C, A, B). **Ordem obrigatória: A e B primeiro, C por último.** O texto antigo de A e B só existe uma vez no ficheiro enquanto as funções novas (C) não estiverem inseridas; C contém blocos quase iguais e tornaria as substituições ambíguas.

  **(C) Funções novas — inserir por último**, antes de `def build_redblue_report(`:

```python
def parse_launched_attacks(attack_log: list[dict], scenarios: dict) -> tuple[list, list, list, list]:
    """Separa o attack_log em (tentativas, not_executed, unknown_scenario,
    invalid_entries). `tentativas` = [(datetime, entrada)] ordenadas por
    tempo: só entradas com status "launched", cenário conhecido e timestamp
    válido. Partilhada com incident_engine para a regra nunca divergir."""
    parsed_attacks: list[tuple[datetime, dict]] = []
    not_executed: list[dict] = []
    unknown_scenario: list[dict] = []
    invalid_entries: list[dict] = []
    for entry in attack_log or []:
        if not isinstance(entry, dict):
            invalid_entries.append(entry)
            continue
        if entry.get("status") != "launched":
            not_executed.append(entry)
            continue
        scenario_name = entry.get("scenario")
        if scenario_name not in scenarios:
            unknown_scenario.append(entry)
            continue
        ts = _parse_timestamp(entry.get("timestamp"))
        if ts is None:
            invalid_entries.append(entry)
            continue
        parsed_attacks.append((ts, entry))

    parsed_attacks.sort(key=lambda item: item[0])
    return parsed_attacks, not_executed, unknown_scenario, invalid_entries


def attack_windows(
    parsed_attacks: list[tuple[datetime, dict]], window_seconds: int = DEFAULT_WINDOW_SECONDS
) -> list[tuple[datetime, datetime, dict]]:
    """Janela de correlação de cada tentativa: `window_seconds` a partir do
    início, cortada pelo início da tentativa seguinte (o que vier primeiro)."""
    windows: list[tuple[datetime, datetime, dict]] = []
    for i, (ts, entry) in enumerate(parsed_attacks):
        window_end = ts + timedelta(seconds=window_seconds)
        if i + 1 < len(parsed_attacks):
            next_ts = parsed_attacks[i + 1][0]
            if next_ts < window_end:
                window_end = next_ts
        windows.append((ts, window_end, entry))
    return windows


```

**(A) — fazer primeiro.** Substituir, dentro de `build_redblue_report`, o bloco

```python
    parsed_attacks: list[tuple[datetime, dict]] = []
    not_executed: list[dict] = []
    unknown_scenario: list[dict] = []
    invalid_entries: list[dict] = []
    for entry in attack_log or []:
        if not isinstance(entry, dict):
            invalid_entries.append(entry)
            continue
        if entry.get("status") != "launched":
            not_executed.append(entry)
            continue
        scenario_name = entry.get("scenario")
        if scenario_name not in scenarios:
            unknown_scenario.append(entry)
            continue
        ts = _parse_timestamp(entry.get("timestamp"))
        if ts is None:
            invalid_entries.append(entry)
            continue
        parsed_attacks.append((ts, entry))

    parsed_attacks.sort(key=lambda item: item[0])
```

por

```python
    parsed_attacks, not_executed, unknown_scenario, invalid_entries = parse_launched_attacks(
        attack_log, scenarios
    )
```

**(B) — fazer a seguir.** Substituir o cabeçalho do loop

```python
    for i, (ts, entry) in enumerate(parsed_attacks):
        scenario_name = entry["scenario"]
        scenario = scenarios[scenario_name]
        target = entry.get("target")

        window_end = ts + timedelta(seconds=window_seconds)
        if i + 1 < len(parsed_attacks):
            next_ts = parsed_attacks[i + 1][0]
            if next_ts < window_end:
                window_end = next_ts
```

por

```python
    for ts, window_end, entry in attack_windows(parsed_attacks, window_seconds):
        scenario_name = entry["scenario"]
        scenario = scenarios[scenario_name]
        target = entry.get("target")
```

- [ ] **Step 5: Correr toda a suite do correlator**

Run: `python test_redblue.py | tail -1 && python test_redblue_attack_log.py | tail -1`
Expected: `[OK] Todos os testes passaram` nas duas (nenhum resultado existente mudou).

- [ ] **Step 6: Commit**

```bash
cd .. && git add scripts/redblue_correlator.py scripts/test_redblue.py
git commit -m "refactor(redblue): extrai parse_launched_attacks e attack_windows para reutilizacao (R3)"
git log -1 --format=%B | grep -ci co-authored   # 0
```

---

### Task 2: Motor puro `incident_engine.py`

**Files:**
- Create: `scripts/incident_engine.py`
- Test: `scripts/test_incident_engine.py`

**Interfaces:**
- Consumes: `event_catalog.classify_alert(int|None) -> dict`, `redblue_correlator._parse_timestamp`, `attack_windows`, `parse_launched_attacks`, `DEFAULT_WINDOW_SECONDS`.
- Produces (usados pelas Tasks 3–6): constantes `SEVERITY_ORDER, STATUSES, OPEN_STATUSES, TRANSITIONS, NETWORK_SEVERITY, INCIDENT_GAP_SECONDS, INCIDENT_OPEN_MIN_SEVERITY`; `parse_timestamp(raw) -> datetime|None`; `severity_rank(s) -> int`; `max_severity(a, b) -> str`; `evidence_from_raw_alert(raw) -> dict|None`; `evidence_from_network_detection(det) -> dict|None`; `assign_evidence(evidence, open_incidents, already_known=False, gap_seconds=None, min_open_severity=None) -> {"action": "duplicate|attach|open|ignore", "incident_id": str|None}`; `can_transition(current, target, note=None) -> (bool, str|None)` (razões `"transicao_invalida"`, `"nota_obrigatoria"`); `available_transitions(current) -> tuple[str, ...]`; `compute_windows(attack_log, scenarios, window_seconds=300) -> list`; `link_attacks(evidence_ts, asset, windows) -> list[dict]`; `attack_link_data(entry, scenarios) -> dict`.
- Evidência normalizada: `{"kind": "wazuh_alert"|"network_detection", "key": str, "ts": ISO-8601 com fuso, "asset": str, "severity": str, "payload": dict}`.

- [ ] **Step 1: Escrever o teste que falha** — criar `scripts/test_incident_engine.py`:

```python
"""
Testes do motor puro de incidentes (R3): normalização de evidências,
regras de agrupamento, máquina de estados e ligação a ataques. Sem I/O.

Correr (a partir de scripts/):
    python test_incident_engine.py
"""

import sys

from attack_scenarios import SCENARIOS
from incident_engine import (
    assign_evidence,
    attack_link_data,
    available_transitions,
    can_transition,
    compute_windows,
    evidence_from_network_detection,
    evidence_from_raw_alert,
    link_attacks,
    max_severity,
)

failures: list[str] = []

# Event IDs de event_catalog.py: 4625=high, 4720=medium, 4722=low; sem Event ID = info
HIGH, MEDIUM, LOW = 4625, 4720, 4722
ASSET = "192.168.1.169"


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def raw_alert(alert_id, ts, ip=ASSET, event_id=None) -> dict:
    alert = {
        "_id": alert_id, "@timestamp": ts,
        "agent": {"name": "FARENSE1910", "ip": ip}, "rule": {"id": "60122", "level": 5},
    }
    if event_id is not None:
        alert["data"] = {"win": {"system": {"eventID": str(event_id)}}}
    return alert


def ev(alert_id, ts, event_id=None, ip=ASSET) -> dict:
    return evidence_from_raw_alert(raw_alert(alert_id, ts, ip=ip, event_id=event_id))


def open_inc(inc_id, last, asset=ASSET, status="NEW") -> dict:
    return {"id": inc_id, "asset": asset, "status": status, "last_evidence_at": last}


def run() -> None:
    # --- evidence_from_raw_alert ---
    e = ev("a1", "2026-10-06T10:00:00Z", HIGH)
    check("alerta bruto válido vira evidência wazuh_alert", e is not None and e["kind"] == "wazuh_alert")
    check("key usa o _id do Wazuh", e["key"] == "alert:a1")
    check("asset = agent.ip", e["asset"] == ASSET)
    check("severidade vem do event_catalog (4625=high)", e["severity"] == "high")
    check("ts normalizado com fuso (Z -> +00:00)", e["ts"] == "2026-10-06T10:00:00+00:00")
    check("payload é o alerta bruto", e["payload"]["_id"] == "a1")
    check("alerta sem Event ID Windows é info", ev("a2", "2026-10-06T10:00:00Z")["severity"] == "info")
    for label, bad in [
        ("sem _id", {**raw_alert("x", "2026-10-06T10:00:00Z"), "_id": None}),
        ("sem timestamp", raw_alert("x", None)),
        ("com timestamp inválido", raw_alert("x", "ontem")),
        ("sem agent.ip", {**raw_alert("x", "2026-10-06T10:00:00Z"), "agent": {"name": "n"}}),
        ("com agent que não é dict", {**raw_alert("x", "2026-10-06T10:00:00Z"), "agent": "n"}),
        ("que não é dict", "lixo"),
        ("None", None),
    ]:
        check(f"alerta {label} -> None sem lançar", evidence_from_raw_alert(bad) is None)

    # --- evidence_from_network_detection ---
    det = {"type": "port_scan", "src_ip": "192.168.1.170", "dst_ip": ASSET,
           "timestamp": "2026-10-06T10:00:05+00:00", "detail": {"distinct_ports": 16}}
    n = evidence_from_network_detection(det)
    check("deteção de rede vira evidência network_detection", n is not None and n["kind"] == "network_detection")
    check("asset = dst_ip", n["asset"] == ASSET)
    check("port_scan tem severidade medium", n["severity"] == "medium")
    check("key por tipo/src/dst/minuto", n["key"] == f"net:port_scan:192.168.1.170:{ASSET}:2026-10-06T10:00")
    spike = evidence_from_network_detection(
        {"type": "volume_spike", "src_ip": "192.168.1.170", "dst_ip": None,
         "timestamp": "2026-10-06T10:00:05+00:00", "detail": {}})
    check("volume_spike (dst_ip=None) usa src_ip como asset", spike["asset"] == "192.168.1.170")
    check("volume_spike tem severidade low", spike["severity"] == "low")
    novo = evidence_from_network_detection({**det, "type": "tipo_novo"})
    check("tipo desconhecido cai para low", novo["severity"] == "low")
    for label, bad in [("sem timestamp", {**det, "timestamp": None}), ("sem type", {**det, "type": None}),
                       ("sem IPs", {**det, "src_ip": None, "dst_ip": None}), ("não-dict", 42)]:
        check(f"deteção {label} -> None sem lançar", evidence_from_network_detection(bad) is None)

    # --- assign_evidence ---
    high = ev("b1", "2026-10-06T10:05:00Z", HIGH)
    medium = ev("b2", "2026-10-06T10:05:00Z", MEDIUM)
    low = ev("b3", "2026-10-06T10:05:00Z", LOW)
    info = ev("b4", "2026-10-06T10:05:00Z")
    inc = open_inc("INC-1", "2026-10-06T10:00:00+00:00")

    check("já conhecida -> duplicate", assign_evidence(high, [], already_known=True)["action"] == "duplicate")
    check("high sem incidente aberto -> open", assign_evidence(high, [])["action"] == "open")
    check("medium sem incidente aberto -> open", assign_evidence(medium, [])["action"] == "open")
    check("low sem incidente aberto -> ignore", assign_evidence(low, [])["action"] == "ignore")
    check("info sem incidente aberto -> ignore", assign_evidence(info, [])["action"] == "ignore")
    r = assign_evidence(low, [inc])
    check("low com incidente aberto do mesmo ativo dentro do gap -> attach",
          r["action"] == "attach" and r["incident_id"] == "INC-1")
    check("info com incidente aberto dentro do gap -> attach", assign_evidence(info, [inc])["action"] == "attach")
    check("fora do gap (15 min) -> open novo",
          assign_evidence(high, [open_inc("INC-2", "2026-10-06T09:50:00+00:00")])["action"] == "open")
    check("outro ativo -> não anexa", assign_evidence(high, [open_inc("INC-3", "2026-10-06T10:00:00+00:00", asset="10.0.0.9")])["action"] == "open")
    check("incidente RESOLVED não recebe evidências",
          assign_evidence(high, [open_inc("INC-4", "2026-10-06T10:00:00+00:00", status="RESOLVED")])["action"] == "open")
    check("incidente CLOSED não recebe evidências",
          assign_evidence(high, [open_inc("INC-5", "2026-10-06T10:00:00+00:00", status="CLOSED")])["action"] == "open")
    check("incidente CONTAINED recebe evidências",
          assign_evidence(high, [open_inc("INC-6", "2026-10-06T10:00:00+00:00", status="CONTAINED")])["action"] == "attach")
    older, newer = open_inc("INC-7", "2026-10-06T10:00:00+00:00"), open_inc("INC-8", "2026-10-06T10:03:00+00:00")
    check("com dois candidatos anexa ao de atividade mais recente",
          assign_evidence(high, [older, newer])["incident_id"] == "INC-8")
    late = ev("b5", "2026-10-06T09:58:00Z", HIGH)
    check("evidência ligeiramente anterior à última, dentro do gap -> attach",
          assign_evidence(late, [inc])["action"] == "attach")
    check("rede (medium) abre incidente", assign_evidence(n, [])["action"] == "open")
    check("rede com severidade low (volume_spike) também abre", assign_evidence(spike, [])["action"] == "open")
    check("gap_seconds=60 não anexa a 5 min", assign_evidence(high, [inc], gap_seconds=60)["action"] == "open")
    check("min_open_severity=low faz low abrir", assign_evidence(low, [], min_open_severity="low")["action"] == "open")
    check("max_severity compara pela ordem info<low<medium<high<critical",
          max_severity("low", "high") == "high" and max_severity("critical", "high") == "critical"
          and max_severity("info", "info") == "info")

    # --- can_transition / available_transitions ---
    for a, b in [("NEW", "INVESTIGATING"), ("INVESTIGATING", "CONTAINED"), ("INVESTIGATING", "RESOLVED"),
                 ("CONTAINED", "RESOLVED"), ("CONTAINED", "INVESTIGATING"), ("RESOLVED", "CLOSED"),
                 ("RESOLVED", "INVESTIGATING")]:
        check(f"transição {a}->{b} é válida", can_transition(a, b) == (True, None))
    for a, b in [("NEW", "CONTAINED"), ("NEW", "RESOLVED"), ("INVESTIGATING", "NEW"), ("INVESTIGATING", "CLOSED"),
                 ("CLOSED", "NEW"), ("CLOSED", "INVESTIGATING"), ("RESOLVED", "NEW"), ("NEW", "NEW"),
                 ("NEW", "INEXISTENTE"), ("INEXISTENTE", "NEW")]:
        check(f"transição {a}->{b} é inválida", can_transition(a, b) == (False, "transicao_invalida"))
    check("NEW->CLOSED sem nota exige nota", can_transition("NEW", "CLOSED") == (False, "nota_obrigatoria"))
    check("NEW->CLOSED com nota só de espaços exige nota", can_transition("NEW", "CLOSED", "   ") == (False, "nota_obrigatoria"))
    check("NEW->CLOSED com nota é válida", can_transition("NEW", "CLOSED", "falso positivo") == (True, None))
    check("available_transitions(NEW)", available_transitions("NEW") == ("INVESTIGATING", "CLOSED"))
    check("available_transitions(CLOSED) é vazio", available_transitions("CLOSED") == ())
    check("available_transitions(desconhecido) é vazio", available_transitions("XYZ") == ())

    # --- compute_windows / link_attacks / attack_link_data ---
    log = [
        {"id": 7, "scenario": "brute_force_rdp", "target": ASSET, "timestamp": "2026-10-06T10:00:00Z",
         "status": "launched", "technique": "T1003", "tool": "mimikatz"},
        {"id": 8, "scenario": "smb_enum", "target": ASSET, "timestamp": "2026-10-06T10:02:00Z", "status": "launched"},
        {"scenario": "smb_enum", "target": ASSET, "timestamp": "2026-10-06T11:00:00Z", "status": "skipped"},
        "lixo",
    ]
    windows = compute_windows(log, SCENARIOS)
    check("compute_windows ignora skipped e lixo", len(windows) == 2)
    check("evidência dentro da janela do ataque 7", [a["id"] for a in link_attacks("2026-10-06T10:01:00+00:00", ASSET, windows)] == [7])
    check("janela do ataque 7 cortada pelo início do 8", [a["id"] for a in link_attacks("2026-10-06T10:02:30+00:00", ASSET, windows)] == [8])
    check("outro ativo não liga", link_attacks("2026-10-06T10:01:00+00:00", "10.0.0.9", windows) == [])
    check("antes do ataque não liga", link_attacks("2026-10-06T09:59:00+00:00", ASSET, windows) == [])
    check("depois da janela (300 s) não liga", link_attacks("2026-10-06T10:20:00+00:00", ASSET, windows) == [])
    check("timestamp inválido não liga nem lança", link_attacks("ontem", ASSET, windows) == [])
    check("sem ativo não liga", link_attacks("2026-10-06T10:01:00+00:00", None, windows) == [])
    check("attack_log vazio/None -> sem janelas", compute_windows(None, SCENARIOS) == [] and compute_windows([], SCENARIOS) == [])
    check("attack_link_data usa technique/tool do log",
          attack_link_data(log[0], SCENARIOS) == {
              "ref": "7", "attack_id": 7, "scenario": "brute_force_rdp", "technique": "T1003",
              "tool": "mimikatz", "attack_timestamp": "2026-10-06T10:00:00Z"})
    d8 = attack_link_data(log[1], SCENARIOS)
    check("attack_link_data cai para a técnica/ferramenta do cenário", d8["technique"] == "T1135" and d8["tool"] == "netexec")
    sem_id = attack_link_data({"scenario": "smb_enum", "target": ASSET, "timestamp": "2026-10-06T10:09:00Z", "status": "launched"}, SCENARIOS)
    check("sem id usa ref alvo@timestamp e attack_id=None",
          sem_id["ref"] == f"{ASSET}@2026-10-06T10:09:00Z" and sem_id["attack_id"] is None)

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")


if __name__ == "__main__":
    run()
```

- [ ] **Step 2: Correr e confirmar que falha**

Run (em `scripts/`): `python test_incident_engine.py` — Expected: `ModuleNotFoundError: No module named 'incident_engine'`.

- [ ] **Step 3: Implementar** — criar `scripts/incident_engine.py`:

```python
"""
Motor de agrupamento de incidentes (R3). Módulo puro, como lifecycle.py/
redblue_correlator.py: sem I/O, sem SQLite, sem relógio — recebe evidências
normalizadas e o estado dos incidentes abertos e devolve decisões. Nunca
lança exceção sobre dados malformados: entradas inválidas devolvem None.

Evidência normalizada: {kind, key, ts, asset, severity, payload}
  kind     "wazuh_alert" | "network_detection"
  key      chave única de deduplicação ("alert:<_id>" / "net:<tipo>:...")
  ts       ISO-8601 com fuso
  asset    IP do ativo afetado (agent.ip / dst_ip)
  payload  alerta bruto do Wazuh ou deteção de rede
"""

import os

from event_catalog import classify_alert
from redblue_correlator import (
    DEFAULT_WINDOW_SECONDS,
    _parse_timestamp,
    attack_windows,
    parse_launched_attacks,
)

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
STATUSES = ("NEW", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED")
OPEN_STATUSES = ("NEW", "INVESTIGATING", "CONTAINED")
TRANSITIONS = {
    "NEW": ("INVESTIGATING", "CLOSED"),
    "INVESTIGATING": ("CONTAINED", "RESOLVED"),
    "CONTAINED": ("RESOLVED", "INVESTIGATING"),
    "RESOLVED": ("CLOSED", "INVESTIGATING"),
    "CLOSED": (),
}
NETWORK_SEVERITY = {"port_scan": "medium", "brute_force": "medium", "volume_spike": "low"}


def _int_env(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, default))
    except ValueError:
        return default
    return value if value > 0 else default


def _severity_env(name: str, default: str) -> str:
    value = os.getenv(name, default).strip().lower()
    return value if value in SEVERITY_ORDER else default


INCIDENT_GAP_SECONDS = _int_env("INCIDENT_GAP_SECONDS", 600)
INCIDENT_OPEN_MIN_SEVERITY = _severity_env("INCIDENT_OPEN_MIN_SEVERITY", "medium")

parse_timestamp = _parse_timestamp


def severity_rank(severity: str | None) -> int:
    return SEVERITY_ORDER.get(severity, 0)


def max_severity(a: str, b: str) -> str:
    return a if severity_rank(a) >= severity_rank(b) else b


def _windows_event_id(raw: dict) -> int | None:
    try:
        value = raw.get("data", {}).get("win", {}).get("system", {}).get("eventID")
        return int(value) if value is not None else None
    except (ValueError, TypeError, AttributeError):
        return None


def evidence_from_raw_alert(raw: dict) -> dict | None:
    """Alerta bruto do Indexer (`_source` + `_id`) -> evidência, ou None se
    faltar _id, timestamp válido ou agent.ip."""
    if not isinstance(raw, dict):
        return None
    alert_id = raw.get("_id")
    ts = _parse_timestamp(raw.get("@timestamp"))
    agent = raw.get("agent")
    asset = agent.get("ip") if isinstance(agent, dict) else None
    if not alert_id or ts is None or not asset:
        return None
    return {
        "kind": "wazuh_alert",
        "key": f"alert:{alert_id}",
        "ts": ts.isoformat(),
        "asset": asset,
        "severity": classify_alert(_windows_event_id(raw))["severity"],
        "payload": raw,
    }


def evidence_from_network_detection(det: dict) -> dict | None:
    """Deteção de rede (network_detections.detect_network_anomalies) ->
    evidência, ou None se faltar timestamp, tipo ou IPs. O ativo é o destino
    (o alvo do padrão); volume_spike não tem destino, usa a origem."""
    if not isinstance(det, dict):
        return None
    ts = _parse_timestamp(det.get("timestamp"))
    det_type = det.get("type")
    asset = det.get("dst_ip") or det.get("src_ip")
    if ts is None or not det_type or not asset:
        return None
    return {
        "kind": "network_detection",
        # Mesma granularidade (minuto) com que network_monitor._poll_once deduplica.
        "key": f"net:{det_type}:{det.get('src_ip')}:{det.get('dst_ip')}:{ts.isoformat()[:16]}",
        "ts": ts.isoformat(),
        "asset": asset,
        "severity": NETWORK_SEVERITY.get(det_type, "low"),
        "payload": det,
    }


def assign_evidence(
    evidence: dict,
    open_incidents: list[dict],
    already_known: bool = False,
    gap_seconds: int | None = None,
    min_open_severity: str | None = None,
) -> dict:
    """Decide o destino de uma evidência: duplicate | attach | open | ignore.

    open_incidents: [{id, asset, status, last_evidence_at}] — só os do mesmo
    ativo interessam. Anexa ao incidente aberto (NEW/INVESTIGATING/CONTAINED)
    do mesmo ativo mais recentemente ativo cuja última evidência esteja a
    <= gap segundos (em qualquer sentido). Senão abre incidente se for
    deteção de rede ou tiver severidade >= limiar; senão ignora."""
    gap = INCIDENT_GAP_SECONDS if gap_seconds is None else gap_seconds
    minimum = min_open_severity or INCIDENT_OPEN_MIN_SEVERITY

    if already_known:
        return {"action": "duplicate", "incident_id": None}

    ev_ts = _parse_timestamp(evidence.get("ts"))
    best = None
    best_last = None
    for inc in open_incidents:
        if inc.get("asset") != evidence.get("asset") or inc.get("status") not in OPEN_STATUSES:
            continue
        last = _parse_timestamp(inc.get("last_evidence_at"))
        if ev_ts is None or last is None:
            continue
        if abs((ev_ts - last).total_seconds()) <= gap and (best is None or last > best_last):
            best, best_last = inc, last
    if best is not None:
        return {"action": "attach", "incident_id": best["id"]}

    if evidence.get("kind") == "network_detection" or severity_rank(evidence.get("severity")) >= severity_rank(minimum):
        return {"action": "open", "incident_id": None}
    return {"action": "ignore", "incident_id": None}


def can_transition(current: str, target: str, note: str | None = None) -> tuple[bool, str | None]:
    """(ok, razão). Razões: "transicao_invalida", "nota_obrigatoria"
    (NEW -> CLOSED exige nota: falso positivo)."""
    if target not in TRANSITIONS.get(current, ()):
        return False, "transicao_invalida"
    if current == "NEW" and target == "CLOSED" and not (note or "").strip():
        return False, "nota_obrigatoria"
    return True, None


def available_transitions(current: str) -> tuple[str, ...]:
    return TRANSITIONS.get(current, ())


def compute_windows(attack_log: list, scenarios: dict, window_seconds: int = DEFAULT_WINDOW_SECONDS) -> list:
    """Janelas (inicio, fim, entrada) das tentativas lançadas do attack_log —
    a mesma regra de redblue_correlator (via parse_launched_attacks)."""
    parsed, _, _, _ = parse_launched_attacks(attack_log, scenarios)
    return attack_windows(parsed, window_seconds)


def link_attacks(evidence_ts: str, asset: str | None, windows: list) -> list[dict]:
    """Entradas do attack_log cuja janela contém a evidência e cujo target é o ativo."""
    ts = _parse_timestamp(evidence_ts)
    if ts is None or not asset:
        return []
    return [entry for start, end, entry in windows if entry.get("target") == asset and start <= ts <= end]


def attack_link_data(entry: dict, scenarios: dict) -> dict:
    """Dados do evento `attack_linked`. technique/tool do próprio log (R0)
    prevalecem; sem eles, os do cenário."""
    scenario = scenarios.get(entry.get("scenario"))
    attack_id = entry.get("id")
    ref = str(attack_id) if attack_id is not None else f"{entry.get('target')}@{entry.get('timestamp')}"
    return {
        "ref": ref,
        "attack_id": attack_id,
        "scenario": entry.get("scenario"),
        "technique": entry.get("technique") or (scenario.mitre_technique if scenario else None),
        "tool": entry.get("tool") or (scenario.tool if scenario else None),
        "attack_timestamp": entry.get("timestamp"),
    }
```

- [ ] **Step 4: Correr e confirmar que passa**

Run: `python test_incident_engine.py | tail -3` — Expected: `[OK] Todos os testes passaram`.

- [ ] **Step 5: Commit**

```bash
cd .. && git add scripts/incident_engine.py scripts/test_incident_engine.py
git commit -m "feat(incidents): motor puro de agrupamento, estados e ligacao a ataques (R3)"
git log -1 --format=%B | grep -ci co-authored   # 0
```

---

### Task 3: Persistência `incident_store.py` + `.gitignore`

**Files:**
- Create: `scripts/incident_store.py`
- Test: `scripts/test_incident_store.py`
- Modify: `.gitignore`

**Interfaces:**
- Consumes (Task 2): `OPEN_STATUSES`, `can_transition`, `max_severity`, `parse_timestamp`.
- Produces: `IncidentStore(db_path)` com atributo `lock` (`threading.RLock`) e métodos:
  - `evidence_exists(key) -> bool`
  - `list_open_incidents(asset) -> list[dict]` (`id,status,severity,asset,last_evidence_at`)
  - `create_incident(evidence, now_iso) -> str` (id `INC-AAAAMMDD-NNN`, data = dia da 1.ª evidência)
  - `attach_evidence(incident_id, evidence, now_iso) -> None` (`IncidentNotFound` se não existir; `sqlite3.IntegrityError` se a `key` já existir)
  - `link_attack(incident_id, link_data, now_iso) -> bool` (False se o `ref` já estava ligado)
  - `add_note(incident_id, text, now_iso) -> None`
  - `set_status(incident_id, new_status, note, now_iso) -> None` (`IncidentNotFound`, `InvalidTransition(.reason)`)
  - `get_incident(incident_id) -> dict|None` (campos da tabela + `evidence`, `timeline`, `attack_ids`, `techniques`, `mttd_seconds`, `time_to_first_response_seconds`)
  - `list_incidents(status=None, severity=None, since_iso=None, limit=100, offset=0) -> list[dict]` (com `evidence_count` e derivados, sem `evidence`/`timeline`)
  - `summary(since_iso=None) -> dict` (`total, by_status, by_severity, open, high_or_critical_open, avg_mttd_seconds, avg_time_to_first_response_seconds`)
  - exceções `IncidentNotFound`, `InvalidTransition(reason)`.

- [ ] **Step 1: Escrever o teste que falha** — criar `scripts/test_incident_store.py`:

```python
"""
Testes da persistência SQLite de incidentes (R3). Cada caso usa uma base
temporária; nunca toca em scripts/incidents.sqlite3.

Correr (a partir de scripts/):
    python test_incident_store.py
"""

import os
import sqlite3
import sys
import tempfile

from incident_store import IncidentNotFound, IncidentStore, InvalidTransition

failures: list[str] = []
ASSET = "192.168.1.169"


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def ev(key, ts, severity="high", asset=ASSET, kind="wazuh_alert") -> dict:
    return {"kind": kind, "key": key, "ts": ts, "asset": asset, "severity": severity, "payload": {"k": key}}


def link(ref="7", attack_id=7, technique="T1003", ts="2026-10-06T10:00:00+00:00") -> dict:
    return {"ref": ref, "attack_id": attack_id, "scenario": "brute_force_rdp", "technique": technique,
            "tool": "mimikatz", "attack_timestamp": ts}


def run() -> None:
    tmp = tempfile.TemporaryDirectory()
    path = os.path.join(tmp.name, "i.sqlite3")
    store = IncidentStore(path)
    check("construir o store não cria o ficheiro (lazy)", not os.path.exists(path))
    check("evidence_exists numa base nova é False", store.evidence_exists("x") is False)
    check("a 1.ª operação cria o ficheiro", os.path.exists(path))

    NOW = "2026-10-06T10:01:00+00:00"
    inc1 = store.create_incident(ev("alert:a1", "2026-10-06T10:01:00+00:00"), NOW)
    check("1.º id do dia é INC-20261006-001", inc1 == "INC-20261006-001")
    inc2 = store.create_incident(ev("alert:a2", "2026-10-06T10:02:00+00:00", asset="10.0.0.9"), NOW)
    check("2.º id do dia é INC-20261006-002", inc2 == "INC-20261006-002")
    inc3 = store.create_incident(ev("alert:a3", "2026-10-07T00:00:05+00:00", asset="10.0.0.8"), NOW)
    check("id usa o dia da 1.ª evidência (sequência recomeça)", inc3 == "INC-20261007-001")

    i = store.get_incident(inc1)
    check("incidente novo: estado NEW, severidade, ativo", i["status"] == "NEW" and i["severity"] == "high" and i["asset"] == ASSET)
    check("incidente novo: created_at = now", i["created_at"] == NOW)
    check("incidente novo: 1 evidência com payload", len(i["evidence"]) == 1 and i["evidence"][0]["payload"] == {"k": "alert:a1"})
    check("timeline inicial = created, evidence_added", [e["kind"] for e in i["timeline"]] == ["created", "evidence_added"])
    check("eventos automáticos têm actor system", all(e["actor"] == "system" for e in i["timeline"]))
    check("get_incident inexistente -> None", store.get_incident("INC-NAO-EXISTE") is None)
    check("evidence_exists após criar", store.evidence_exists("alert:a1") and not store.evidence_exists("alert:zz"))
    check("sem ataque ligado: mttd None, ttfr None, técnicas vazias",
          i["mttd_seconds"] is None and i["time_to_first_response_seconds"] is None and i["techniques"] == [])

    # --- attach_evidence ---
    store.attach_evidence(inc1, ev("alert:a4", "2026-10-06T10:00:30+00:00", severity="low"), "2026-10-06T10:02:00+00:00")
    i = store.get_incident(inc1)
    check("attach: first_evidence_at recua para a evidência mais antiga", i["first_evidence_at"] == "2026-10-06T10:00:30+00:00")
    check("attach: last_evidence_at mantém a mais recente", i["last_evidence_at"] == "2026-10-06T10:01:00+00:00")
    check("attach: severidade não desce", i["severity"] == "high")
    store.attach_evidence(inc1, ev("alert:a5", "2026-10-06T10:03:00+00:00", severity="critical"), "2026-10-06T10:03:00+00:00")
    i = store.get_incident(inc1)
    check("attach: severidade sobe para o máximo", i["severity"] == "critical")
    check("attach: last_evidence_at avança", i["last_evidence_at"] == "2026-10-06T10:03:00+00:00")
    changed = [e for e in i["timeline"] if e["kind"] == "severity_changed"]
    check("attach: evento severity_changed com from/to", len(changed) == 1 and changed[0]["data"] == {"from": "high", "to": "critical"})
    check("attach: 3 evidências (a1, a4, a5)", len(i["evidence"]) == 3)
    try:
        store.attach_evidence("INC-NAO-EXISTE", ev("alert:b1", "2026-10-06T10:03:00+00:00"), NOW)
        check("attach a incidente inexistente lança IncidentNotFound", False)
    except IncidentNotFound:
        check("attach a incidente inexistente lança IncidentNotFound", True)
    try:
        store.attach_evidence(inc1, ev("alert:a4", "2026-10-06T10:04:00+00:00"), NOW)
        check("key repetida é recusada (UNIQUE)", False)
    except sqlite3.IntegrityError:
        check("key repetida é recusada (UNIQUE)", True)

    # --- list_open_incidents ---
    opens = store.list_open_incidents(ASSET)
    check("list_open_incidents devolve só o ativo pedido", [o["id"] for o in opens] == [inc1])
    check("list_open_incidents expõe last_evidence_at", opens[0]["last_evidence_at"] == "2026-10-06T10:03:00+00:00")

    # --- link_attack e derivados ---
    check("link_attack novo devolve True", store.link_attack(inc1, link(), NOW) is True)
    check("link_attack repetido (mesmo ref) devolve False", store.link_attack(inc1, link(), NOW) is False)
    i = store.get_incident(inc1)
    check("derivados: attack_ids e techniques", i["attack_ids"] == [7] and i["techniques"] == ["T1003"])
    check("derivados: mttd = 1.ª evidência - ataque (30.5 s)", i["mttd_seconds"] == 30.0)

    # --- set_status / add_note ---
    store.set_status(inc1, "INVESTIGATING", None, "2026-10-06T10:01:30+00:00")
    i = store.get_incident(inc1)
    check("set_status: estado atualizado", i["status"] == "INVESTIGATING")
    sc = [e for e in i["timeline"] if e["kind"] == "status_changed"][0]
    check("set_status: evento com from/to e actor analyst",
          sc["actor"] == "analyst" and sc["data"] == {"from": "NEW", "to": "INVESTIGATING"})
    check("derivados: tempo até à 1.ª resposta (INVESTIGATING - 1.ª evidência)", i["time_to_first_response_seconds"] == 60.0)
    try:
        store.set_status(inc1, "NEW", None, NOW)
        check("transição inválida lança InvalidTransition", False)
    except InvalidTransition as e:
        check("transição inválida lança InvalidTransition(transicao_invalida)", e.reason == "transicao_invalida")
    try:
        store.set_status(inc2, "CLOSED", "  ", NOW)
        check("NEW->CLOSED sem nota lança nota_obrigatoria", False)
    except InvalidTransition as e:
        check("NEW->CLOSED sem nota lança nota_obrigatoria", e.reason == "nota_obrigatoria")
    store.set_status(inc2, "CLOSED", " falso positivo ", NOW)
    i2 = store.get_incident(inc2)
    check("NEW->CLOSED com nota: fechado e nota guardada sem espaços",
          i2["status"] == "CLOSED" and [e for e in i2["timeline"] if e["kind"] == "status_changed"][0]["data"]["note"] == "falso positivo")
    try:
        store.set_status("INC-NAO-EXISTE", "INVESTIGATING", None, NOW)
        check("set_status inexistente lança IncidentNotFound", False)
    except IncidentNotFound:
        check("set_status inexistente lança IncidentNotFound", True)
    check("incidente fechado deixa de estar em list_open_incidents", store.list_open_incidents("10.0.0.9") == [])

    store.add_note(inc1, "<script>alert(1)</script>", "2026-10-06T10:05:00+00:00")
    notes = [e for e in store.get_incident(inc1)["timeline"] if e["kind"] == "note_added"]
    check("add_note: evento note_added, actor analyst, texto guardado verbatim",
          len(notes) == 1 and notes[0]["actor"] == "analyst" and notes[0]["data"] == {"text": "<script>alert(1)</script>"})
    try:
        store.add_note("INC-NAO-EXISTE", "x", NOW)
        check("add_note inexistente lança IncidentNotFound", False)
    except IncidentNotFound:
        check("add_note inexistente lança IncidentNotFound", True)

    # --- timeline append-only imposta pela base de dados ---
    conn = store._connect()
    try:
        for label, sql in [("UPDATE", "UPDATE incident_events SET kind = 'x'"), ("DELETE", "DELETE FROM incident_events")]:
            try:
                with conn:
                    conn.execute(sql)
                check(f"incident_events recusa {label}", False)
            except sqlite3.DatabaseError:
                check(f"incident_events recusa {label}", True)
    finally:
        conn.close()

    # --- list_incidents / summary ---
    rows = store.list_incidents()
    check("list_incidents devolve os 3, mais recente primeiro", [r["id"] for r in rows] == [inc3, inc1, inc2])
    check("list_incidents inclui evidence_count e não inclui timeline",
          next(r for r in rows if r["id"] == inc1)["evidence_count"] == 3 and "timeline" not in rows[0])
    check("filtro por estado", [r["id"] for r in store.list_incidents(status="CLOSED")] == [inc2])
    check("filtro por severidade", [r["id"] for r in store.list_incidents(severity="critical")] == [inc1])
    check("filtro since exclui antigos", [r["id"] for r in store.list_incidents(since_iso="2026-10-07T00:00:00+00:00")] == [inc3])
    check("paginação limit/offset", [r["id"] for r in store.list_incidents(limit=1, offset=1)] == [inc1])
    s = store.summary()
    check("summary: total e by_status", s["total"] == 3 and s["by_status"] == {"NEW": 1, "INVESTIGATING": 1, "CLOSED": 1})
    check("summary: abertos e altos/críticos abertos", s["open"] == 2 and s["high_or_critical_open"] == 2)
    check("summary: by_severity", s["by_severity"] == {"critical": 1, "high": 2})
    check("summary: MTTD médio só dos que têm ataque ligado", s["avg_mttd_seconds"] == 30.0)
    check("summary: tempo médio até à 1.ª resposta", s["avg_time_to_first_response_seconds"] == 60.0)
    empty = IncidentStore(os.path.join(tmp.name, "vazio.sqlite3")).summary()
    check("summary de base vazia", empty["total"] == 0 and empty["open"] == 0 and empty["avg_mttd_seconds"] is None)

    tmp.cleanup()

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")


if __name__ == "__main__":
    run()
```

- [ ] **Step 2: Correr e confirmar que falha**

Run: `python test_incident_store.py` — Expected: `ModuleNotFoundError: No module named 'incident_store'`.

- [ ] **Step 3: Implementar** — criar `scripts/incident_store.py`:

```python
"""
Persistência SQLite dos incidentes (R3) — separada de historico/index.sqlite3
de propósito: aquele índice é uma cache reconstruível a partir do JSONL,
enquanto aqui há estado e notas do analista que não podem ser perdidos.

Uma ligação por operação (sqlite3.connect(timeout=10)) e um RLock em volta
das sequências "ler abertos -> decidir -> gravar" (ver incident_ingest), porque
o ingest corre numa thread de executor e a API/backfill noutra. A timeline
(incident_events) é append-only: triggers recusam UPDATE e DELETE.
"""

import json
import os
import sqlite3
import threading
from contextlib import contextmanager

from incident_engine import OPEN_STATUSES, can_transition, max_severity, parse_timestamp

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    asset TEXT NOT NULL,
    created_at TEXT NOT NULL,
    first_evidence_at TEXT NOT NULL,
    last_evidence_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_asset_last ON incidents(asset, last_evidence_at);
CREATE TABLE IF NOT EXISTS incident_evidence (
    rowid_ INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(id),
    key TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    ts TEXT NOT NULL,
    severity TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_incident ON incident_evidence(incident_id);
CREATE TABLE IF NOT EXISTS incident_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(id),
    ts TEXT NOT NULL,
    kind TEXT NOT NULL,
    actor TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_incident ON incident_events(incident_id);
CREATE TRIGGER IF NOT EXISTS incident_events_no_update BEFORE UPDATE ON incident_events
BEGIN SELECT RAISE(ABORT, 'incident_events e append-only'); END;
CREATE TRIGGER IF NOT EXISTS incident_events_no_delete BEFORE DELETE ON incident_events
BEGIN SELECT RAISE(ABORT, 'incident_events e append-only'); END;
"""


class IncidentNotFound(Exception):
    pass


class InvalidTransition(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class IncidentStore:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self.lock = threading.RLock()
        self._schema_ready = False

    # --- infraestrutura ---

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        if not self._schema_ready:
            conn.executescript(SCHEMA)
            self._schema_ready = True
        return conn

    @contextmanager
    def _tx(self):
        conn = self._connect()
        try:
            with conn:  # commit no sucesso, rollback na exceção
                yield conn
        finally:
            conn.close()

    @staticmethod
    def _add_event(conn, incident_id: str, ts: str, kind: str, actor: str, data: dict) -> None:
        conn.execute(
            "INSERT INTO incident_events (incident_id, ts, kind, actor, data) VALUES (?, ?, ?, ?, ?)",
            (incident_id, ts, kind, actor, json.dumps(data, ensure_ascii=False)),
        )

    @staticmethod
    def _insert_evidence(conn, incident_id: str, evidence: dict) -> None:
        conn.execute(
            "INSERT INTO incident_evidence (incident_id, key, kind, ts, severity, payload) VALUES (?, ?, ?, ?, ?, ?)",
            (incident_id, evidence["key"], evidence["kind"], evidence["ts"], evidence["severity"],
             json.dumps(evidence["payload"], ensure_ascii=False)),
        )

    @staticmethod
    def _next_id(conn, day: str) -> str:
        prefix = f"INC-{day}-"
        count = conn.execute("SELECT COUNT(*) FROM incidents WHERE id LIKE ?", (prefix + "%",)).fetchone()[0]
        return f"{prefix}{count + 1:03d}"

    # --- leitura simples (usada pelo ingest) ---

    def evidence_exists(self, key: str) -> bool:
        with self._tx() as conn:
            return conn.execute("SELECT 1 FROM incident_evidence WHERE key = ?", (key,)).fetchone() is not None

    def list_open_incidents(self, asset: str) -> list[dict]:
        placeholders = ",".join("?" for _ in OPEN_STATUSES)
        with self._tx() as conn:
            rows = conn.execute(
                f"SELECT id, status, severity, asset, last_evidence_at FROM incidents "
                f"WHERE asset = ? AND status IN ({placeholders})",
                (asset, *OPEN_STATUSES),
            ).fetchall()
        return [dict(r) for r in rows]

    # --- escrita ---

    def create_incident(self, evidence: dict, now_iso: str) -> str:
        with self.lock, self._tx() as conn:
            day = parse_timestamp(evidence["ts"]).strftime("%Y%m%d")
            incident_id = self._next_id(conn, day)
            conn.execute(
                "INSERT INTO incidents (id, status, severity, asset, created_at, first_evidence_at, "
                "last_evidence_at, updated_at) VALUES (?, 'NEW', ?, ?, ?, ?, ?, ?)",
                (incident_id, evidence["severity"], evidence["asset"], now_iso,
                 evidence["ts"], evidence["ts"], now_iso),
            )
            self._insert_evidence(conn, incident_id, evidence)
            self._add_event(conn, incident_id, now_iso, "created", "system",
                            {"asset": evidence["asset"], "severity": evidence["severity"],
                             "first_evidence_at": evidence["ts"]})
            self._add_event(conn, incident_id, now_iso, "evidence_added", "system",
                            {"key": evidence["key"], "kind": evidence["kind"], "ts": evidence["ts"],
                             "severity": evidence["severity"]})
        return incident_id

    def attach_evidence(self, incident_id: str, evidence: dict, now_iso: str) -> None:
        with self.lock, self._tx() as conn:
            row = conn.execute(
                "SELECT severity, first_evidence_at, last_evidence_at FROM incidents WHERE id = ?", (incident_id,)
            ).fetchone()
            if row is None:
                raise IncidentNotFound(incident_id)
            self._insert_evidence(conn, incident_id, evidence)

            new_severity = max_severity(row["severity"], evidence["severity"])
            ev_ts = parse_timestamp(evidence["ts"])
            first = evidence["ts"] if ev_ts < parse_timestamp(row["first_evidence_at"]) else row["first_evidence_at"]
            last = evidence["ts"] if ev_ts > parse_timestamp(row["last_evidence_at"]) else row["last_evidence_at"]
            conn.execute(
                "UPDATE incidents SET severity = ?, first_evidence_at = ?, last_evidence_at = ?, updated_at = ? WHERE id = ?",
                (new_severity, first, last, now_iso, incident_id),
            )
            self._add_event(conn, incident_id, now_iso, "evidence_added", "system",
                            {"key": evidence["key"], "kind": evidence["kind"], "ts": evidence["ts"],
                             "severity": evidence["severity"]})
            if new_severity != row["severity"]:
                self._add_event(conn, incident_id, now_iso, "severity_changed", "system",
                                {"from": row["severity"], "to": new_severity})

    def link_attack(self, incident_id: str, link_data: dict, now_iso: str) -> bool:
        with self.lock, self._tx() as conn:
            rows = conn.execute(
                "SELECT data FROM incident_events WHERE incident_id = ? AND kind = 'attack_linked'", (incident_id,)
            ).fetchall()
            if any(json.loads(r["data"]).get("ref") == link_data["ref"] for r in rows):
                return False
            self._add_event(conn, incident_id, now_iso, "attack_linked", "system", link_data)
        return True

    def add_note(self, incident_id: str, text: str, now_iso: str) -> None:
        with self.lock, self._tx() as conn:
            if conn.execute("SELECT 1 FROM incidents WHERE id = ?", (incident_id,)).fetchone() is None:
                raise IncidentNotFound(incident_id)
            self._add_event(conn, incident_id, now_iso, "note_added", "analyst", {"text": text})
            conn.execute("UPDATE incidents SET updated_at = ? WHERE id = ?", (now_iso, incident_id))

    def set_status(self, incident_id: str, new_status: str, note: str | None, now_iso: str) -> None:
        with self.lock, self._tx() as conn:
            row = conn.execute("SELECT status FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            if row is None:
                raise IncidentNotFound(incident_id)
            ok, reason = can_transition(row["status"], new_status, note)
            if not ok:
                raise InvalidTransition(reason)
            data = {"from": row["status"], "to": new_status}
            if note and note.strip():
                data["note"] = note.strip()
            conn.execute("UPDATE incidents SET status = ?, updated_at = ? WHERE id = ?",
                         (new_status, now_iso, incident_id))
            self._add_event(conn, incident_id, now_iso, "status_changed", "analyst", data)

    # --- leitura completa ---

    @staticmethod
    def _timeline(conn, incident_id: str) -> list[dict]:
        rows = conn.execute(
            "SELECT id, ts, kind, actor, data FROM incident_events WHERE incident_id = ? ORDER BY id", (incident_id,)
        ).fetchall()
        return [{"id": r["id"], "ts": r["ts"], "kind": r["kind"], "actor": r["actor"],
                 "data": json.loads(r["data"])} for r in rows]

    @staticmethod
    def _derived(incident: dict, timeline: list[dict]) -> dict:
        links = [e["data"] for e in timeline if e["kind"] == "attack_linked"]
        attack_ids = [lk["attack_id"] for lk in links if lk.get("attack_id") is not None]
        techniques = sorted({lk["technique"] for lk in links if lk.get("technique")})

        mttd = None
        first_evidence = parse_timestamp(incident["first_evidence_at"])
        attack_times = [t for t in (parse_timestamp(lk.get("attack_timestamp")) for lk in links) if t is not None]
        if first_evidence is not None and attack_times:
            mttd = max(0.0, round((first_evidence - min(attack_times)).total_seconds(), 2))

        ttfr = None
        response = next((e for e in timeline if e["kind"] == "status_changed" and e["data"].get("to") == "INVESTIGATING"), None)
        if response is not None and first_evidence is not None:
            ttfr = round((parse_timestamp(response["ts"]) - first_evidence).total_seconds(), 2)

        return {"attack_ids": attack_ids, "techniques": techniques,
                "mttd_seconds": mttd, "time_to_first_response_seconds": ttfr}

    def get_incident(self, incident_id: str) -> dict | None:
        with self._tx() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            if row is None:
                return None
            incident = dict(row)
            evidence_rows = conn.execute(
                "SELECT key, kind, ts, severity, payload FROM incident_evidence WHERE incident_id = ? ORDER BY ts, rowid_",
                (incident_id,),
            ).fetchall()
            timeline = self._timeline(conn, incident_id)
        incident["evidence"] = [{"key": r["key"], "kind": r["kind"], "ts": r["ts"], "severity": r["severity"],
                                 "payload": json.loads(r["payload"])} for r in evidence_rows]
        incident["timeline"] = timeline
        incident.update(self._derived(incident, timeline))
        return incident

    def list_incidents(self, status: str | None = None, severity: str | None = None,
                       since_iso: str | None = None, limit: int = 100, offset: int = 0) -> list[dict]:
        clauses, params = [], []
        if status:
            clauses.append("i.status = ?")
            params.append(status)
        if severity:
            clauses.append("i.severity = ?")
            params.append(severity)
        if since_iso:
            clauses.append("i.last_evidence_at >= ?")
            params.append(since_iso)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._tx() as conn:
            rows = conn.execute(
                f"SELECT i.*, (SELECT COUNT(*) FROM incident_evidence e WHERE e.incident_id = i.id) AS evidence_count "
                f"FROM incidents i {where} ORDER BY i.last_evidence_at DESC, i.id DESC LIMIT ? OFFSET ?",
                (*params, limit, offset),
            ).fetchall()
            result = []
            for row in rows:
                incident = dict(row)
                incident.update(self._derived(incident, self._timeline(conn, incident["id"])))
                result.append(incident)
        return result

    def summary(self, since_iso: str | None = None) -> dict:
        incidents = self.list_incidents(since_iso=since_iso, limit=100000)
        by_status: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for inc in incidents:
            by_status[inc["status"]] = by_status.get(inc["status"], 0) + 1
            by_severity[inc["severity"]] = by_severity.get(inc["severity"], 0) + 1
        open_ones = [i for i in incidents if i["status"] in OPEN_STATUSES]
        mttds = [i["mttd_seconds"] for i in incidents if i["mttd_seconds"] is not None]
        ttfrs = [i["time_to_first_response_seconds"] for i in incidents if i["time_to_first_response_seconds"] is not None]
        return {
            "total": len(incidents),
            "by_status": by_status,
            "by_severity": by_severity,
            "open": len(open_ones),
            "high_or_critical_open": sum(1 for i in open_ones if i["severity"] in ("high", "critical")),
            "avg_mttd_seconds": round(sum(mttds) / len(mttds), 2) if mttds else None,
            "avg_time_to_first_response_seconds": round(sum(ttfrs) / len(ttfrs), 2) if ttfrs else None,
        }
```

- [ ] **Step 4: Correr e confirmar que passa**

Run: `python test_incident_store.py | tail -3` — Expected: `[OK] Todos os testes passaram`. (Nota: `mttd` do teste = 10:00:30 − 10:00:00 = 30.0 s, porque a evidência `a4` recuou a primeira evidência para 10:00:30.)

- [ ] **Step 5: Ignorar a base de dados e commit** — acrescentar a `.gitignore`, na secção de estado local gerado em runtime (junto a `scripts/historico/`):

```
scripts/incidents.sqlite3
scripts/incidents.sqlite3-journal
```

```bash
cd .. && git add .gitignore scripts/incident_store.py scripts/test_incident_store.py
git commit -m "feat(incidents): persistencia SQLite com timeline append-only (R3)"
git log -1 --format=%B | grep -ci co-authored   # 0
```

---

### Task 4: Orquestração `incident_ingest.py`

**Files:**
- Create: `scripts/incident_ingest.py`
- Test: `scripts/test_incident_ingest.py`

**Interfaces:**
- Consumes (Tasks 2–3): `IncidentStore` (todos os métodos acima, `lock`), `assign_evidence`, `attack_link_data`, `compute_windows`, `evidence_from_raw_alert`, `evidence_from_network_detection`, `link_attacks`, `parse_timestamp`; `feature_extractor.load_attack_log(path) -> list[dict]` (devolve `[]` se o ficheiro faltar; ignora linhas truncadas); `ml_anomalies.load_model(model_dir)` e `build_ml_anomalies_report(alerts, model, scaler)`.
- Produces: `ingest_evidences(store, evidences, attack_log, scenarios, now_iso=None) -> {"opened","attached","duplicate","ignored"}`; `ingest_raw_alerts(store, raw_alerts, attack_log_path, scenarios, now_iso=None) -> counts + "invalid"`; `ingest_network_detections(store, detections, attack_log_path, scenarios, now_iso=None) -> counts + "invalid"`; `ml_summary(raw_alerts, model_dir) -> {"scored","ml_anomalies","rule_flagged"} | None`.

- [ ] **Step 1: Escrever o teste que falha** — criar `scripts/test_incident_ingest.py`:

```python
"""
Testes do ingest de incidentes (R3): liga o motor puro à persistência.
Bases e attack_log temporários; modelo de ML falso.

Correr (a partir de scripts/):
    python test_incident_ingest.py
"""

import json
import os
import sys
import tempfile
import threading

import ml_anomalies
from attack_scenarios import SCENARIOS
from incident_ingest import ingest_network_detections, ingest_raw_alerts, ml_summary
from incident_store import IncidentStore

failures: list[str] = []
HIGH, LOW = 4625, 4722
ASSET = "192.168.1.169"
NOW = "2026-10-06T12:00:00+00:00"


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def raw(alert_id, ts, event_id=None, ip=ASSET) -> dict:
    alert = {"_id": alert_id, "@timestamp": ts, "agent": {"name": "FARENSE1910", "ip": ip}, "rule": {"id": "1", "level": 5}}
    if event_id is not None:
        alert["data"] = {"win": {"system": {"eventID": str(event_id)}}}
    return alert


class FakeScaler:
    def transform(self, vectors):
        return vectors


class FakeModel:
    def decision_function(self, scaled):
        return [-0.2] * len(scaled)

    def predict(self, scaled):
        return [-1] * len(scaled)


def run() -> None:
    tmp = tempfile.TemporaryDirectory()
    log_path = os.path.join(tmp.name, "attack_log.jsonl")
    with open(log_path, "w", encoding="utf-8") as f:
        f.write(json.dumps({"id": 7, "scenario": "brute_force_rdp", "target": ASSET,
                            "timestamp": "2026-10-06T10:00:00Z", "status": "launched",
                            "technique": "T1003", "tool": "mimikatz"}) + "\n")
        f.write('{"scenario": "smb_enum", "target"')  # linha truncada a meio de um append

    def new_store(name="i.sqlite3"):
        return IncidentStore(os.path.join(tmp.name, name))

    # --- caminho feliz: high abre, low/info anexam, ataque ligado ---
    store = new_store()
    alerts = [raw("a1", "2026-10-06T10:00:10Z", HIGH), raw("a2", "2026-10-06T10:02:00Z", LOW),
              raw("a3", "2026-10-06T10:03:00Z"), raw("a4", "2026-10-06T10:03:30Z", LOW, ip="192.168.1.50")]
    counts = ingest_raw_alerts(store, alerts, log_path, SCENARIOS, NOW)
    check("1 incidente aberto, 2 anexados, 1 ignorado (low de outro ativo)",
          counts == {"opened": 1, "attached": 2, "duplicate": 0, "ignored": 1, "invalid": 0})
    incidents = store.list_incidents()
    check("só existe 1 incidente", len(incidents) == 1)
    inc = store.get_incident(incidents[0]["id"])
    check("incidente tem as 3 evidências do mesmo ativo", len(inc["evidence"]) == 3)
    check("ataque 7 ligado: técnica e id do log (linha truncada ignorada)",
          inc["attack_ids"] == [7] and inc["techniques"] == ["T1003"])
    check("MTTD = 1.ª evidência - ataque (10 s)", inc["mttd_seconds"] == 10.0)
    links = [e for e in inc["timeline"] if e["kind"] == "attack_linked"]
    check("o ataque só é ligado uma vez, apesar de 3 evidências na janela", len(links) == 1)

    # --- idempotência ---
    again = ingest_raw_alerts(store, alerts, log_path, SCENARIOS, NOW)
    check("2.ª corrida: tudo duplicate (ou ignorado), nada novo",
          again["opened"] == 0 and again["attached"] == 0 and again["duplicate"] == 3)
    check("2.ª corrida não cria incidentes nem evidências", len(store.list_incidents()) == 1
          and len(store.get_incident(incidents[0]["id"])["evidence"]) == 3)

    # --- independência da ordem de chegada ---
    store_rev = new_store("rev.sqlite3")
    ingest_raw_alerts(store_rev, list(reversed(alerts)), log_path, SCENARIOS, NOW)
    check("ordem inversa dá o mesmo resultado (1 incidente, 3 evidências)",
          len(store_rev.list_incidents()) == 1 and store_rev.list_incidents()[0]["evidence_count"] == 3)

    # --- dois surtos separados por 30 min -> 2 incidentes ---
    store2 = new_store("dois.sqlite3")
    ingest_raw_alerts(store2, [raw("b1", "2026-10-06T10:00:00Z", HIGH), raw("b2", "2026-10-06T10:30:00Z", HIGH)],
                      log_path, SCENARIOS, NOW)
    check("surtos a 30 min de distância abrem 2 incidentes", len(store2.list_incidents()) == 2)

    # --- Review Focus 1: rajada de alertas info/low não abre incidentes e é rápida ---
    store3 = new_store("flood.sqlite3")
    flood = [raw(f"f{i}", f"2026-10-06T10:{i // 60:02d}:{i % 60:02d}Z", LOW if i % 2 else None) for i in range(500)]
    counts = ingest_raw_alerts(store3, flood, log_path, SCENARIOS, NOW)
    check("rajada de 500 alertas info/low: 0 incidentes", store3.list_incidents() == [] and counts["opened"] == 0)
    check("rajada: todos ignorados", counts["ignored"] == 500)

    # --- Review Focus 2: alertas malformados nunca lançam ---
    store4 = new_store("mal.sqlite3")
    counts = ingest_raw_alerts(store4, ["lixo", None, {"_id": "x"}, raw(None, "2026-10-06T10:00:00Z", HIGH),
                                        raw("ok1", "2026-10-06T10:00:00Z", HIGH)], log_path, SCENARIOS, NOW)
    check("malformados contam em invalid e o válido abre incidente", counts["invalid"] == 4 and counts["opened"] == 1)
    check("None/lista vazia não lançam", ingest_raw_alerts(store4, None, log_path, SCENARIOS)["opened"] == 0
          and ingest_raw_alerts(store4, [], log_path, SCENARIOS)["opened"] == 0)

    # --- Review Focus 5: attack_log ausente não impede incidentes ---
    store5 = new_store("semlog.sqlite3")
    counts = ingest_raw_alerts(store5, [raw("c1", "2026-10-06T10:00:10Z", HIGH)],
                               os.path.join(tmp.name, "nao-existe.jsonl"), SCENARIOS, NOW)
    inc5 = store5.get_incident(store5.list_incidents()[0]["id"])
    check("sem attack_log: incidente criado, sem ataque ligado", counts["opened"] == 1 and inc5["attack_ids"] == [])

    # --- rede: abre sozinha e depois anexa alertas Wazuh do mesmo ativo ---
    store6 = new_store("rede.sqlite3")
    det = {"type": "port_scan", "src_ip": "192.168.1.170", "dst_ip": ASSET,
           "timestamp": "2026-10-06T10:00:05+00:00", "detail": {"distinct_ports": 16}}
    counts = ingest_network_detections(store6, [det, {"type": None}], log_path, SCENARIOS, NOW)
    check("deteção de rede abre incidente; inválida conta em invalid", counts["opened"] == 1 and counts["invalid"] == 1)
    ingest_raw_alerts(store6, [raw("d1", "2026-10-06T10:01:00Z", HIGH)], log_path, SCENARIOS, NOW)
    inc6 = store6.get_incident(store6.list_incidents()[0]["id"])
    check("alerta Wazuh anexa-se ao incidente aberto pela rede (multi-fonte)",
          len(store6.list_incidents()) == 1 and sorted({e["kind"] for e in inc6["evidence"]}) == ["network_detection", "wazuh_alert"])
    check("ingest de rede repetido é duplicate",
          ingest_network_detections(store6, [det], log_path, SCENARIOS, NOW)["duplicate"] == 1)

    # --- Review Focus 6: o mesmo alerta entregue em simultâneo por várias threads ---
    store7 = new_store("conc.sqlite3")
    batch = [raw(f"k{i}", f"2026-10-06T10:00:{i:02d}Z", HIGH) for i in range(10)]
    errors: list[Exception] = []

    def worker() -> None:
        try:
            ingest_raw_alerts(store7, batch, log_path, SCENARIOS, NOW)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    check("8 threads em simultâneo não lançam", errors == [])
    check("8 threads: 1 incidente e 10 evidências (sem duplicados)",
          len(store7.list_incidents()) == 1 and store7.list_incidents()[0]["evidence_count"] == 10)

    # --- ml_summary ---
    ml_alerts = [raw("m1", "2026-10-06T10:00:00Z", HIGH), raw("m2", "2026-10-06T10:00:10Z", HIGH)]
    original = ml_anomalies.load_model
    try:
        def missing(model_dir=None):
            raise FileNotFoundError("sem modelo")
        ml_anomalies.load_model = missing
        check("ml_summary sem modelo -> None (Review Focus 4)", ml_summary(ml_alerts, tmp.name) is None)
        ml_anomalies.load_model = lambda model_dir=None: (FakeModel(), FakeScaler())
        s = ml_summary(ml_alerts, tmp.name)
        check("ml_summary com modelo falso", s == {"scored": 2, "ml_anomalies": 2, "rule_flagged": 2})
        check("ml_summary sem alertas -> None", ml_summary([], tmp.name) is None)
        check("ml_summary só com alertas sem Event ID -> scored 0",
              ml_summary([raw("m3", "2026-10-06T10:00:00Z")], tmp.name)["scored"] == 0)
    finally:
        ml_anomalies.load_model = original

    tmp.cleanup()

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")


if __name__ == "__main__":
    run()
```

- [ ] **Step 2: Correr e confirmar que falha**

Run: `python test_incident_ingest.py` — Expected: `ModuleNotFoundError: No module named 'incident_ingest'`.

- [ ] **Step 3: Implementar** — criar `scripts/incident_ingest.py`:

```python
"""
Orquestração do ingest de incidentes (R3): liga as evidências normalizadas
(incident_engine, puro) à persistência (incident_store). Chamado em tempo
real pelos pollers de alertas e de rede (callbacks opcionais) e pelo backfill
manual (POST /api/incidents/backfill).

Todas as sequências "ler abertos -> decidir -> gravar" correm dentro de
store.lock, para o ingest (thread de executor) e o backfill (thread da API)
nunca duplicarem incidentes nem evidências.
"""

import logging
from datetime import datetime, timezone

import ml_anomalies
from feature_extractor import load_attack_log
from incident_engine import (
    assign_evidence,
    attack_link_data,
    compute_windows,
    evidence_from_network_detection,
    evidence_from_raw_alert,
    link_attacks,
    parse_timestamp,
)

logger = logging.getLogger("sentrylens.incidents")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ingest_evidences(store, evidences: list[dict], attack_log: list[dict], scenarios: dict,
                     now_iso: str | None = None) -> dict:
    """Processa evidências já normalizadas, por ordem de tempo (o resultado não
    depende da ordem de chegada). Devolve contagens opened/attached/duplicate/ignored."""
    now = now_iso or _now_iso()
    windows = compute_windows(attack_log, scenarios)
    counts = {"opened": 0, "attached": 0, "duplicate": 0, "ignored": 0}

    with store.lock:
        for evidence in sorted(evidences, key=lambda e: parse_timestamp(e["ts"])):
            decision = assign_evidence(
                evidence,
                store.list_open_incidents(evidence["asset"]),
                already_known=store.evidence_exists(evidence["key"]),
            )
            action = decision["action"]
            if action == "duplicate":
                counts["duplicate"] += 1
                continue
            if action == "ignore":
                counts["ignored"] += 1
                continue
            if action == "open":
                incident_id = store.create_incident(evidence, now)
                counts["opened"] += 1
            else:
                incident_id = decision["incident_id"]
                store.attach_evidence(incident_id, evidence, now)
                counts["attached"] += 1
            for entry in link_attacks(evidence["ts"], evidence["asset"], windows):
                store.link_attack(incident_id, attack_link_data(entry, scenarios), now)
    return counts


def _ingest(store, evidences: list[dict], invalid: int, attack_log_path: str, scenarios: dict,
            now_iso: str | None) -> dict:
    counts = ingest_evidences(store, evidences, load_attack_log(attack_log_path), scenarios, now_iso)
    counts["invalid"] = invalid
    return counts


def ingest_raw_alerts(store, raw_alerts: list, attack_log_path: str, scenarios: dict,
                      now_iso: str | None = None) -> dict:
    """Alertas brutos do Indexer (com _id). Alertas malformados contam em
    "invalid" e nunca lançam."""
    evidences, invalid = [], 0
    for raw in raw_alerts or []:
        evidence = evidence_from_raw_alert(raw)
        if evidence is None:
            invalid += 1
        else:
            evidences.append(evidence)
    return _ingest(store, evidences, invalid, attack_log_path, scenarios, now_iso)


def ingest_network_detections(store, detections: list, attack_log_path: str, scenarios: dict,
                              now_iso: str | None = None) -> dict:
    evidences, invalid = [], 0
    for det in detections or []:
        evidence = evidence_from_network_detection(det)
        if evidence is None:
            invalid += 1
        else:
            evidences.append(evidence)
    return _ingest(store, evidences, invalid, attack_log_path, scenarios, now_iso)


def ml_summary(raw_alerts: list[dict], model_dir: str) -> dict | None:
    """Resumo de ML ao nível do incidente, calculado sobre os alertas brutos do
    próprio incidente (a janela certa para as features, que dependem dos alertas
    à volta). None se não houver alertas ou se o modelo não existir/falhar —
    o incidente funciona sem ML."""
    if not raw_alerts:
        return None
    try:
        model, scaler = ml_anomalies.load_model(model_dir)
        report = ml_anomalies.build_ml_anomalies_report(raw_alerts, model, scaler)
    except FileNotFoundError:
        return None
    except Exception:
        logger.exception("Falha ao calcular o resumo de ML do incidente")
        return None
    return {"scored": report["total"], "ml_anomalies": report["ml_anomalies_count"],
            "rule_flagged": report["rule_flagged_count"]}
```

- [ ] **Step 4: Correr e confirmar que passa**

Run: `python test_incident_ingest.py | tail -4` — Expected: `[OK] Todos os testes passaram`. Se o caso `ml_summary só com alertas sem Event ID` falhar porque `build_ml_anomalies_report` devolve `total == 0` com a chave certa, o valor esperado é `0` (alertas sem Event ID são descartados por `extract_features`).

- [ ] **Step 5: Commit**

```bash
cd .. && git add scripts/incident_ingest.py scripts/test_incident_ingest.py
git commit -m "feat(incidents): ingest de alertas e deteccoes de rede + resumo de ML por incidente (R3)"
git log -1 --format=%B | grep -ci co-authored   # 0
```

---

### Task 5: Callbacks `on_new_raw_alerts` e `on_new_detections` nos pollers

**Files:**
- Modify: `scripts/websocket_alerts.py` (`_poll_once` ~L46-98, `alert_poll_loop` ~L101-118)
- Modify: `scripts/network_monitor.py` (`_poll_once` ~L118-170, `network_poll_loop` ~L173-190)
- Test: `scripts/test_websocket_alerts.py`, `scripts/test_network_monitor.py`

**Interfaces:**
- Produces: `websocket_alerts._poll_once(..., on_new_alerts=None, on_new_raw_alerts=None)`; `alert_poll_loop(..., on_new_alerts=None, on_new_raw_alerts=None)`; `network_monitor._poll_once(..., detection_buffer, on_new_detections=None)`; `network_poll_loop(..., detection_buffer, interval_seconds=5, on_new_detections=None)`. Os callbacks são síncronos, recebem **só itens novos**, correm em `run_in_executor` e os erros nunca derrubam o polling.

- [ ] **Step 1: Testes que falham** — em `scripts/test_websocket_alerts.py`, dentro de `run_poll_once_tests()._run()`, imediatamente antes de `asyncio.run(_run())` (mesmo nível de indentação do último `check`):

```python
        # --- on_new_raw_alerts recebe os alertas BRUTOS novos (com _id), só quando há novos ---
        raw_received: list = []
        fake_raw = FakeIndexerClient([alert("r1", ts="2026-09-01T10:00:00Z"), alert("r2", ts="2026-09-01T10:01:00Z")])
        seen_raw: set[str] = set()
        await _poll_once(fake_raw, manager, main._enrich_alert, seen_raw, on_new_raw_alerts=raw_received.extend)
        check("on_new_raw_alerts recebeu os 2 alertas brutos novos (com _id)",
              [a["_id"] for a in raw_received] == ["r1", "r2"] and "@timestamp" in raw_received[0])
        raw_received.clear()
        await _poll_once(fake_raw, manager, main._enrich_alert, seen_raw, on_new_raw_alerts=raw_received.extend)
        check("on_new_raw_alerts não é chamado sem alertas novos", raw_received == [])

        def explode(_alerts):
            raise RuntimeError("boom")

        result_raw_err = await _poll_once(
            FakeIndexerClient([alert("r3", ts="2026-09-01T10:02:00Z")]), manager, main._enrich_alert, set(),
            on_new_raw_alerts=explode,
        )
        check("erro em on_new_raw_alerts não derruba o polling", len(result_raw_err) == 1)

        enriched_received: list = []
        await _poll_once(
            FakeIndexerClient([alert("r4", ts="2026-09-01T10:03:00Z")]), manager, main._enrich_alert, set(),
            on_new_alerts=enriched_received.extend,
        )
        check("on_new_alerts continua a receber os enriquecidos (sem _id)",
              len(enriched_received) == 1 and "friendly_name" in enriched_received[0] and "_id" not in enriched_received[0])
```

Em `scripts/test_network_monitor.py`, acrescentar antes de `def run() -> None:`:

```python
def run_on_new_detections_tests() -> None:
    async def _run() -> None:
        manager = NetworkConnectionManager()
        packet_buffer: deque = deque(maxlen=PACKET_BUFFER_MAX)
        detection_buffer: deque = deque(maxlen=5000)
        offset_state = {"offset": 0}
        seen_detections: set = set()
        received: list = []

        linhas_scan = "".join(
            f"{1758812770 + i}.0,192.168.1.170,192.168.1.21,6,66,50000,{4000 + i},,\n" for i in range(16)
        )
        await _poll_once(
            FakeSSHClient([(linhas_scan, 400)]), manager, packet_buffer, offset_state, seen_detections,
            "/var/log/sentrylens/network.csv", detection_buffer, on_new_detections=received.extend,
        )
        check("on_new_detections recebeu o port_scan novo", any(d["type"] == "port_scan" for d in received))

        received.clear()
        await _poll_once(
            FakeSSHClient([("", 400)]), manager, packet_buffer, offset_state, seen_detections,
            "/var/log/sentrylens/network.csv", detection_buffer, on_new_detections=received.extend,
        )
        check("on_new_detections não é chamado sem deteções novas (dedup)", received == [])

        def explode(_detections):
            raise RuntimeError("boom")

        packet_buffer2: deque = deque(maxlen=PACKET_BUFFER_MAX)
        new_packets, new_detections = await _poll_once(
            FakeSSHClient([(linhas_scan, 400)]), manager, packet_buffer2, {"offset": 0}, set(),
            "/var/log/sentrylens/network.csv", deque(maxlen=5000), on_new_detections=explode,
        )
        check("erro em on_new_detections não derruba o polling",
              len(new_packets) == 16 and any(d["type"] == "port_scan" for d in new_detections))

    asyncio.run(_run())


```

e em `run()` acrescentar a chamada a seguir a `run_poll_once_tests()`:

```python
    run_on_new_detections_tests()
```

- [ ] **Step 2: Correr e confirmar que falham**

Run: `python test_websocket_alerts.py 2>&1 | tail -5; python test_network_monitor.py 2>&1 | tail -5`
Expected: `TypeError: ... unexpected keyword argument 'on_new_raw_alerts'` / `'on_new_detections'`.

- [ ] **Step 3: Implementar `websocket_alerts.py`** — na assinatura de `_poll_once` acrescentar o parâmetro:

```python
    on_new_alerts=None,
    on_new_raw_alerts=None,
) -> list[dict]:
```

Na docstring, acrescentar no fim do parágrafo de `on_new_alerts`: `on_new_raw_alerts (opcional): igual, mas recebe os alertas BRUTOS novos (com _id, antes do enriquecimento) — usado pelos incidentes (R3), que precisam do alerta completo.`

No corpo, substituir

```python
    new_alerts: list[dict] = []
    for alert in alerts:
        alert_id = alert.get("_id")
        if alert_id is None or alert_id in seen_ids:
            continue
        seen_ids.add(alert_id)
        new_alerts.append(enrich_fn(alert))
```

por

```python
    new_alerts: list[dict] = []
    new_raw: list[dict] = []
    for alert in alerts:
        alert_id = alert.get("_id")
        if alert_id is None or alert_id in seen_ids:
            continue
        seen_ids.add(alert_id)
        new_alerts.append(enrich_fn(alert))
        new_raw.append(alert)
```

e logo a seguir ao bloco `if new_alerts and on_new_alerts is not None: ... except Exception: logger.exception("Falha no callback on_new_alerts")`, antes de `return new_alerts`:

```python
    if new_raw and on_new_raw_alerts is not None:
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, on_new_raw_alerts, new_raw)
        except Exception:
            logger.exception("Falha no callback on_new_raw_alerts")
```

Em `alert_poll_loop`, acrescentar `on_new_raw_alerts=None,` à assinatura (depois de `on_new_alerts=None,`) e passar `on_new_raw_alerts=on_new_raw_alerts` na chamada a `_poll_once(...)`.

- [ ] **Step 4: Implementar `network_monitor.py`** — na assinatura de `_poll_once` acrescentar, depois de `detection_buffer: deque,`:

```python
    on_new_detections=None,
```

Imediatamente depois de `detection_buffer.extend(new_detections)`:

```python
    if new_detections and on_new_detections is not None:
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, on_new_detections, new_detections)
        except Exception:
            logger.exception("Falha no callback on_new_detections")
```

Em `network_poll_loop` acrescentar `on_new_detections=None,` depois de `interval_seconds: int = 5,` e passar `on_new_detections=on_new_detections` na chamada a `_poll_once(...)` (a chamada atual é posicional até `detection_buffer`; acrescentar o argumento nomeado no fim).

- [ ] **Step 5: Correr e confirmar que passam (e que nada regrediu)**

Run: `python test_websocket_alerts.py 2>&1 | tail -3; python test_network_monitor.py 2>&1 | tail -3`
Expected: `[OK] Todos os testes passaram` em ambos.

- [ ] **Step 6: Commit**

```bash
cd .. && git add scripts/websocket_alerts.py scripts/network_monitor.py scripts/test_websocket_alerts.py scripts/test_network_monitor.py
git commit -m "feat(incidents): callbacks on_new_raw_alerts e on_new_detections nos pollers (R3)"
git log -1 --format=%B | grep -ci co-authored   # 0
```

---

### Task 6: Rotas `/api/incidents/*` e ligação ao ingest em `main.py`

**Files:**
- Modify: `scripts/main.py` (imports, constantes ~L100, instância ~L190, callbacks ~L284, startup ~L314-332, novas rotas depois de `get_redblue_attack_log`)
- Test: `scripts/test_incidents_api.py`

**Interfaces:**
- Consumes: Tasks 2–5.
- Produces: `main.INCIDENTS_DB_PATH`, `main.incident_store`, `main.BACKFILL_MAX_ALERTS = 5000`; rotas `GET /api/incidents`, `GET /api/incidents/{incident_id}`, `POST /api/incidents/{incident_id}/status`, `POST /api/incidents/{incident_id}/notes`, `POST /api/incidents/backfill`. Detalhe devolve o incidente + `evidence[]` (alertas Wazuh com `alert` enriquecido em vez de `payload`; deteções de rede com `payload`) + `timeline[]` + `ml_summary` + `available_transitions`.

- [ ] **Step 1: Escrever o teste que falha** — criar `scripts/test_incidents_api.py`:

```python
"""
Testes das rotas /api/incidents/* (R3) com TestClient, base SQLite temporária,
attack_log temporário, Indexer falso e sem modelo de ML.

Correr (a partir de scripts/):
    python test_incidents_api.py
"""

import json
import os
import sys
import tempfile
from unittest.mock import AsyncMock

os.environ.setdefault("SENTRYLENS_API_KEY", "test-key-incidents")

from fastapi.testclient import TestClient

import incident_ingest
import main
from attack_scenarios import SCENARIOS
from incident_store import IncidentStore

main.app.router.on_startup.clear()
client = TestClient(main.app)
HEADERS = {"X-API-Key": os.environ["SENTRYLENS_API_KEY"]}

failures: list[str] = []
ASSET = "192.168.1.169"
HIGH, LOW = 4625, 4722


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def raw(alert_id, ts, event_id=None, ip=ASSET) -> dict:
    alert = {"_id": alert_id, "@timestamp": ts, "agent": {"name": "FARENSE1910", "ip": ip},
             "rule": {"id": "1", "level": 5, "description": "regra"}, "full_log": "x"}
    if event_id is not None:
        alert["data"] = {"win": {"system": {"eventID": str(event_id)}}}
    return alert


def recent(seconds_ago: int) -> str:
    from datetime import datetime, timedelta, timezone
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat()


def run() -> None:
    tmp = tempfile.TemporaryDirectory()
    log_path = os.path.join(tmp.name, "attack_log.jsonl")
    with open(log_path, "w", encoding="utf-8") as f:
        f.write(json.dumps({"id": 7, "scenario": "brute_force_rdp", "target": ASSET, "timestamp": recent(130),
                            "status": "launched", "technique": "T1003", "tool": "mimikatz"}) + "\n")
    main.ATTACK_LOG_PATH = log_path
    main.ML_MODEL_DIR = os.path.join(tmp.name, "sem-modelo")  # Review Focus 4: sem modelo
    main.incident_store = IncidentStore(os.path.join(tmp.name, "i.sqlite3"))

    # --- 401 sem chave em todas as rotas ---
    for method, path in [("get", "/api/incidents"), ("get", "/api/incidents/INC-X"),
                         ("post", "/api/incidents/INC-X/status"), ("post", "/api/incidents/INC-X/notes"),
                         ("post", "/api/incidents/backfill")]:
        r = getattr(client, method)(path)
        check(f"{method.upper()} {path} sem X-API-Key -> 401", r.status_code == 401)

    # --- base vazia ---
    r = client.get("/api/incidents", headers=HEADERS)
    check("lista vazia: 200, incidents=[] e summary.total=0", r.status_code == 200 and r.json()["incidents"] == []
          and r.json()["summary"]["total"] == 0)

    # --- semear dados reais via ingest ---
    incident_ingest.ingest_raw_alerts(
        main.incident_store,
        [raw("a1", recent(120), HIGH), raw("a2", recent(60), LOW)],
        log_path, SCENARIOS,
    )
    r = client.get("/api/incidents", headers=HEADERS)
    body = r.json()
    check("lista: 1 incidente com evidence_count=2", len(body["incidents"]) == 1 and body["incidents"][0]["evidence_count"] == 2)
    inc_id = body["incidents"][0]["id"]
    check("lista: summary open=1 e high_or_critical_open=1", body["summary"]["open"] == 1 and body["summary"]["high_or_critical_open"] == 1)
    check("lista: técnica MITRE vem do ataque ligado", body["incidents"][0]["techniques"] == ["T1003"])
    check("lista: não expõe timeline nem payloads", "timeline" not in body["incidents"][0] and "evidence" not in body["incidents"][0])
    check("filtro status=NEW devolve 1", len(client.get("/api/incidents?status=NEW", headers=HEADERS).json()["incidents"]) == 1)
    check("filtro status=CLOSED devolve 0", client.get("/api/incidents?status=CLOSED", headers=HEADERS).json()["incidents"] == [])
    check("filtro severity=low devolve 0", client.get("/api/incidents?severity=low", headers=HEADERS).json()["incidents"] == [])
    check("status inválido -> 422", client.get("/api/incidents?status=XYZ", headers=HEADERS).status_code == 422)
    check("hours=0 -> 422", client.get("/api/incidents?hours=0", headers=HEADERS).status_code == 422)
    check("limit=501 -> 422", client.get("/api/incidents?limit=501", headers=HEADERS).status_code == 422)

    # --- detalhe ---
    check("detalhe inexistente -> 404", client.get("/api/incidents/INC-NAO-EXISTE", headers=HEADERS).status_code == 404)
    r = client.get(f"/api/incidents/{inc_id}", headers=HEADERS)
    d = r.json()
    check("detalhe: 200 com 2 evidências e timeline", r.status_code == 200 and len(d["evidence"]) == 2 and len(d["timeline"]) >= 3)
    check("detalhe: evidência Wazuh traz o alerta enriquecido e não o bruto",
          "friendly_name" in d["evidence"][0]["alert"] and "payload" not in d["evidence"][0])
    check("detalhe: sem modelo, ml_summary é null mas o pedido não falha", d["ml_summary"] is None)
    check("detalhe: available_transitions do estado NEW", d["available_transitions"] == ["INVESTIGATING", "CLOSED"])

    # --- estado ---
    r = client.post(f"/api/incidents/{inc_id}/status", headers=HEADERS, json={"status": "CONTAINED"})
    check("transição inválida NEW->CONTAINED -> 409", r.status_code == 409)
    r = client.post(f"/api/incidents/{inc_id}/status", headers=HEADERS, json={"status": "CLOSED"})
    check("NEW->CLOSED sem nota -> 422", r.status_code == 422)
    r = client.post(f"/api/incidents/{inc_id}/status", headers=HEADERS, json={"status": "XYZ"})
    check("estado inexistente no corpo -> 422", r.status_code == 422)
    r = client.post("/api/incidents/INC-NAO-EXISTE/status", headers=HEADERS, json={"status": "INVESTIGATING"})
    check("estado de incidente inexistente -> 404", r.status_code == 404)
    r = client.post(f"/api/incidents/{inc_id}/status", headers=HEADERS, json={"status": "INVESTIGATING"})
    check("NEW->INVESTIGATING -> 200 com o incidente atualizado",
          r.status_code == 200 and r.json()["status"] == "INVESTIGATING" and r.json()["time_to_first_response_seconds"] is not None)

    # --- notas ---
    xss = "<script>alert('x')</script>"
    r = client.post(f"/api/incidents/{inc_id}/notes", headers=HEADERS, json={"text": f"  {xss}  "})
    notes = [e for e in r.json()["timeline"] if e["kind"] == "note_added"]
    check("nota: 200, guardada verbatim (sem espaços), actor analyst",
          r.status_code == 200 and notes[0]["data"]["text"] == xss and notes[0]["actor"] == "analyst")
    check("nota vazia/só espaços -> 422", client.post(f"/api/incidents/{inc_id}/notes", headers=HEADERS, json={"text": "   "}).status_code == 422)
    check("nota com 2001 caracteres -> 422", client.post(f"/api/incidents/{inc_id}/notes", headers=HEADERS, json={"text": "x" * 2001}).status_code == 422)
    check("nota com 2000 caracteres -> 200", client.post(f"/api/incidents/{inc_id}/notes", headers=HEADERS, json={"text": "x" * 2000}).status_code == 200)
    check("nota em incidente inexistente -> 404", client.post("/api/incidents/INC-NAO-EXISTE/notes", headers=HEADERS, json={"text": "x"}).status_code == 404)

    # --- backfill (Indexer falso) ---
    main.indexer_client.get_recent_alerts = AsyncMock(return_value=[
        raw("n1", recent(3000), HIGH, ip="192.168.1.77"), raw("n2", recent(2990), LOW, ip="192.168.1.77")])
    r = client.post("/api/incidents/backfill", headers=HEADERS, json={"days": 7})
    check("backfill: 200 com contagens", r.status_code == 200 and r.json()["opened"] == 1 and r.json()["attached"] == 1
          and r.json()["fetched"] == 2 and r.json()["truncated"] is False)
    r = client.post("/api/incidents/backfill", headers=HEADERS, json={"days": 7})
    check("backfill repetido é idempotente (tudo duplicate)", r.json()["opened"] == 0 and r.json()["duplicate"] == 2)
    check("backfill repetido não criou incidentes", len(client.get("/api/incidents", headers=HEADERS).json()["incidents"]) == 2)
    check("days=0 -> 422", client.post("/api/incidents/backfill", headers=HEADERS, json={"days": 0}).status_code == 422)
    check("days=91 -> 422", client.post("/api/incidents/backfill", headers=HEADERS, json={"days": 91}).status_code == 422)
    original_max = main.BACKFILL_MAX_ALERTS
    main.BACKFILL_MAX_ALERTS = 2
    r = client.post("/api/incidents/backfill", headers=HEADERS, json={"days": 7})
    check("backfill no teto de alertas sinaliza truncated=true", r.json()["truncated"] is True)
    main.BACKFILL_MAX_ALERTS = original_max

    # --- Review Focus 3: Indexer em baixo -> 502 sem estado parcial ---
    before = len(client.get("/api/incidents", headers=HEADERS).json()["incidents"])
    main.indexer_client.get_recent_alerts = AsyncMock(side_effect=RuntimeError("indexer em baixo"))
    r = client.post("/api/incidents/backfill", headers=HEADERS, json={"days": 7})
    check("Indexer em baixo -> 502", r.status_code == 502)
    check("502 não deixou estado parcial", len(client.get("/api/incidents", headers=HEADERS).json()["incidents"]) == before)

    # --- erros de base de dados: 500 genérico sem caminhos/SQL ---
    good_store = main.incident_store
    main.incident_store = IncidentStore(tmp.name)  # um diretório não abre como base de dados
    r = client.get("/api/incidents", headers=HEADERS)
    check("erro de base de dados -> 500", r.status_code == 500)
    check("500 não revela caminhos nem SQL", tmp.name not in r.text and "sqlite" not in r.text.lower() and "SELECT" not in r.text)
    main.incident_store = good_store

    tmp.cleanup()

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")


if __name__ == "__main__":
    run()
```

- [ ] **Step 2: Correr e confirmar que falha**

Run: `python test_incidents_api.py 2>&1 | tail -3` — Expected: `AttributeError: module 'main' has no attribute 'incident_store'` (ou 404 nas rotas).

- [ ] **Step 3: Implementar em `main.py`** — alterações, pela ordem do ficheiro:

1. Imports: `import sqlite3` junto aos `import` da stdlib; `from datetime import datetime, timedelta, timezone` (acrescentar `timedelta`); `from typing import Annotated, Literal`; `from fastapi.concurrency import run_in_threadpool`; `from pydantic import BaseModel, Field, StringConstraints`; e junto aos imports de módulos do projeto (ordem alfabética):

```python
import incident_ingest
from incident_engine import available_transitions
from incident_store import IncidentNotFound, IncidentStore, InvalidTransition
```

2. Depois de `SENTRYLENS_HISTORY_DIR = ...` (constantes de configuração):

```python
# Base de dados dos incidentes (R3) — separada do índice de histórico, que é
# uma cache reconstruível; aqui há estado e notas do analista.
INCIDENTS_DB_PATH = os.getenv("INCIDENTS_DB_PATH", os.path.join(os.path.dirname(__file__), "incidents.sqlite3"))
# Teto de alertas por corrida de POST /api/incidents/backfill (o Indexer limita a 10000).
BACKFILL_MAX_ALERTS = 5000
```

3. Depois de `vm_ssh_client = ...`:

```python
incident_store = IncidentStore(INCIDENTS_DB_PATH)
```

4. Depois de `_persist_new_alerts(...)`:

```python
def _ingest_incident_alerts(raw_alerts: list[dict]) -> None:
    """Callback de alert_poll_loop (R3): agrupa alertas brutos novos em incidentes."""
    counts = incident_ingest.ingest_raw_alerts(incident_store, raw_alerts, ATTACK_LOG_PATH, SCENARIOS)
    if counts["opened"] or counts["attached"]:
        logger.info("Incidentes (alertas): %s", counts)


def _ingest_incident_detections(detections: list[dict]) -> None:
    """Callback de network_poll_loop (R3): agrupa deteções de rede novas em incidentes."""
    counts = incident_ingest.ingest_network_detections(incident_store, detections, ATTACK_LOG_PATH, SCENARIOS)
    if counts["opened"] or counts["attached"]:
        logger.info("Incidentes (rede): %s", counts)
```

5. No `_start_system_monitor`: na chamada a `alert_poll_loop(` acrescentar `on_new_raw_alerts=_ingest_incident_alerts,` a seguir a `on_new_alerts=_persist_new_alerts,`; na chamada a `network_poll_loop(` acrescentar `on_new_detections=_ingest_incident_detections,` como último argumento (a seguir a `network_detection_buffer,`).

6. Depois da rota `get_redblue_attack_log`, acrescentar:

```python
# ---------------------------------------------------------------------------
# Incidentes (Roadmap v2, R3) — ver docs/superpowers/specs/2026-10-06-r3-incidentes-design.md
# ---------------------------------------------------------------------------

IncidentStatus = Literal["NEW", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"]
IncidentSeverity = Literal["info", "low", "medium", "high", "critical"]


class StatusChange(BaseModel):
    status: IncidentStatus
    note: str | None = Field(default=None, max_length=2000)


class IncidentNote(BaseModel):
    text: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2000)]


class BackfillRequest(BaseModel):
    days: int = Field(default=7, ge=1, le=90)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _incidents_call(func, *args):
    """Corre uma operação da base de incidentes fora do event loop. Erros SQLite
    viram 500 genérico: nunca expõem caminhos nem SQL."""
    try:
        return await run_in_threadpool(func, *args)
    except sqlite3.Error:
        logger.exception("Falha na base de dados de incidentes")
        raise HTTPException(status_code=500, detail="Erro interno ao aceder à base de incidentes")


async def _incident_detail(incident_id: str) -> dict | None:
    incident = await _incidents_call(incident_store.get_incident, incident_id)
    if incident is None:
        return None
    raw_alerts = [e["payload"] for e in incident["evidence"] if e["kind"] == "wazuh_alert"]
    incident["ml_summary"] = await run_in_threadpool(incident_ingest.ml_summary, raw_alerts, ML_MODEL_DIR)
    for evidence in incident["evidence"]:
        if evidence["kind"] == "wazuh_alert":
            evidence["alert"] = _enrich_alert(evidence["payload"])
            del evidence["payload"]
    incident["available_transitions"] = list(available_transitions(incident["status"]))
    return incident


@app.get("/api/incidents", dependencies=_REQUIRE_API_KEY)
async def list_incidents(
    status: IncidentStatus | None = Query(None),
    severity: IncidentSeverity | None = Query(None),
    hours: int = Query(168, ge=1, le=720, description="Janela temporal (última evidência), em horas"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    incidents = await _incidents_call(incident_store.list_incidents, status, severity, since, limit, offset)
    summary = await _incidents_call(incident_store.summary, since)
    return {"window_hours": hours, "incidents": incidents, "summary": summary}


@app.post("/api/incidents/backfill", dependencies=_REQUIRE_API_KEY)
async def backfill_incidents(body: BackfillRequest):
    """Reprocessa os alertas do Wazuh Indexer (retenção de 90 dias) com a mesma
    função pura do ingest em tempo real. Idempotente. Deteções de rede só
    existem em memória, por isso não entram."""
    try:
        raw_alerts = await indexer_client.get_recent_alerts(hours=body.days * 24, size=BACKFILL_MAX_ALERTS)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erro ao contactar Wazuh Indexer: {e}")
    counts = await _incidents_call(
        incident_ingest.ingest_raw_alerts, incident_store, raw_alerts, ATTACK_LOG_PATH, SCENARIOS
    )
    counts["fetched"] = len(raw_alerts)
    counts["truncated"] = len(raw_alerts) >= BACKFILL_MAX_ALERTS
    return counts


@app.get("/api/incidents/{incident_id}", dependencies=_REQUIRE_API_KEY)
async def get_incident(incident_id: str):
    incident = await _incident_detail(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incidente não encontrado")
    return incident


@app.post("/api/incidents/{incident_id}/status", dependencies=_REQUIRE_API_KEY)
async def change_incident_status(incident_id: str, body: StatusChange):
    try:
        await _incidents_call(incident_store.set_status, incident_id, body.status, body.note, _now_iso())
    except IncidentNotFound:
        raise HTTPException(status_code=404, detail="Incidente não encontrado")
    except InvalidTransition as e:
        if e.reason == "nota_obrigatoria":
            raise HTTPException(status_code=422, detail="Fechar um incidente NEW exige uma nota (falso positivo)")
        raise HTTPException(status_code=409, detail="Transição de estado inválida")
    return await _incident_detail(incident_id)


@app.post("/api/incidents/{incident_id}/notes", dependencies=_REQUIRE_API_KEY)
async def add_incident_note(incident_id: str, body: IncidentNote):
    try:
        await _incidents_call(incident_store.add_note, incident_id, body.text, _now_iso())
    except IncidentNotFound:
        raise HTTPException(status_code=404, detail="Incidente não encontrado")
    return await _incident_detail(incident_id)
```

Nota de roteamento: `POST /api/incidents/backfill` é declarada **antes** de `/api/incidents/{incident_id}/...` e os caminhos não colidem (métodos/segmentos diferentes).

- [ ] **Step 4: Correr e confirmar que passa**

Run: `python test_incidents_api.py 2>&1 | grep -v "httpx:" | tail -6` — Expected: `[OK] Todos os testes passaram`.

- [ ] **Step 5: Regressão completa do backend**

```bash
fail=0; for t in test_*.py; do python "$t" >/dev/null 2>&1 || { echo "FALHOU $t"; fail=1; }; done; echo "any_fail=$fail ($(ls test_*.py | wc -l) ficheiros)"
```
Expected: `any_fail=0 (23 ficheiros)` (18 existentes + 4 novos + `test_serve_frontend.py` já contado nos 18 → 22; usar o número que `ls` imprimir — o que importa é `any_fail=0`).

- [ ] **Step 6: Commit**

```bash
cd .. && git add scripts/main.py scripts/test_incidents_api.py
git commit -m "feat(incidents): rotas /api/incidents/* e ligacao do ingest em tempo real (R3)"
git log -1 --format=%B | grep -ci co-authored   # 0
```

---

### Task 7: Painel "Incidentes" no frontend

**Files:**
- Create: `incidents.js`
- Modify: `index.html` (item da sidebar; painel; `<script>`), `style.css`, `app.js` (evento do WebSocket), `scripts/serve_frontend.py` (whitelist)
- Test: `scripts/test_serve_frontend.py` (whitelist) + verificação manual no browser

**Interfaces:**
- Consumes: rotas da Task 6; globais de `app.js`: `API_BASE`, `API_KEY`, `escapeHtml(value)`, `severityBadge(severity)`, `formatTimestamp(ts)`, `renderPanelError(selector, message)`, `periodSelect`.
- Produces: `refreshIncidentsTab()`; o evento DOM `sentrylens:new-alert` disparado por `app.js` quando chega `new_alert` no WebSocket.

- [ ] **Step 1: Teste que falha (whitelist do servidor)** — em `scripts/test_serve_frontend.py`, a seguir ao caso `"/index.html continua a ser servido"`, acrescentar:

```python
        status, headers, _ = get(port, "/incidents.js")
        check("/incidents.js é servido como JavaScript", status == 200 and headers.get("content-type", "").startswith("application/javascript"))
```

Run: `python test_serve_frontend.py | tail -3` — Expected: falha (404 em `/incidents.js`).

- [ ] **Step 2: Whitelist** — em `scripts/serve_frontend.py`, em `ALLOWED_FILES` acrescentar a seguir a `"/redblue.js": "redblue.js",`:

```python
    "/incidents.js": "incidents.js",
```

Run: `python test_serve_frontend.py | tail -3` — Expected: `[OK] Todos os testes passaram` (depois de criar o ficheiro no Step 3; criar um `incidents.js` vazio já chega para este teste).

- [ ] **Step 3: `index.html`** — (a) na sidebar, substituir o item planeado

```html
      <button class="nav-item is-planned" data-planned="R3" data-label="Incidentes">🧩 Incidentes<span class="nav-badge">R3</span></button>
```

por

```html
      <button class="nav-item" data-tab="incidents">🧩 Incidentes</button>
```

(b) antes de `<!-- ===== Secção planeada (sem dados reais ainda) ===== -->` acrescentar o painel:

```html
    <!-- ===== Incidentes (Roadmap v2, R3) ===== -->
    <div class="tab-content" id="tab-incidents">
      <section class="panel" id="incidents-panel">
        <h2>🧩 Incidentes</h2>
        <p class="panel-note">
          Agrupamento automático de deteções (alertas Wazuh e rede) por ativo, com estado e timeline.
          Só dados reais: ataques sem nenhuma deteção não geram incidente (ver Red vs Blue).
        </p>
        <section class="kpi-grid" id="incidents-kpi-grid">
          <div class="card"><h3>Abertos</h3><div class="value" id="kpi-inc-open">—</div></div>
          <div class="card critical"><h3>Altos/Críticos Abertos</h3><div class="value" id="kpi-inc-high">—</div></div>
          <div class="card"><h3>MTTD Médio</h3><div class="value" id="kpi-inc-mttd">—</div></div>
          <div class="card"><h3>Total na Janela</h3><div class="value" id="kpi-inc-total">—</div></div>
        </section>
        <div class="filter-row">
          <label for="inc-status-filter">Estado:</label>
          <select id="inc-status-filter">
            <option value="">Todos</option>
            <option value="NEW">Novo</option>
            <option value="INVESTIGATING">Em investigação</option>
            <option value="CONTAINED">Contido</option>
            <option value="RESOLVED">Resolvido</option>
            <option value="CLOSED">Fechado</option>
          </select>
          <label for="inc-severity-filter">Severidade:</label>
          <select id="inc-severity-filter">
            <option value="">Todas</option>
            <option value="critical">Crítico</option>
            <option value="high">Alto</option>
            <option value="medium">Médio</option>
            <option value="low">Baixo</option>
            <option value="info">Info</option>
          </select>
          <button id="inc-backfill-btn" type="button">📥 Importar histórico</button>
        </div>
        <div id="inc-notice" class="panel-note" role="status"></div>
        <div class="table-scroll">
          <table id="incidents-table">
            <thead>
              <tr>
                <th>ID</th><th>Severidade</th><th>Estado</th><th>Ativo</th>
                <th>Primeira evidência</th><th>Última evidência</th><th>Evidências</th><th>MITRE / ataque</th>
              </tr>
            </thead>
            <tbody id="incidents-body">
              <tr><td colspan="8" class="empty-state">A carregar...</td></tr>
            </tbody>
          </table>
        </div>
      </section>

      <section class="panel" id="incident-detail-panel" hidden>
        <h2 id="inc-detail-title">Incidente</h2>
        <div id="inc-detail-error" class="panel-error-banner" hidden></div>
        <div id="inc-detail-meta" class="inc-meta"></div>
        <div class="inc-actions" id="inc-actions"></div>
        <label for="inc-note-input" class="inc-note-label">Nota (obrigatória para fechar um incidente novo):</label>
        <textarea id="inc-note-input" rows="2" maxlength="2000"></textarea>
        <button id="inc-note-btn" type="button">➕ Adicionar nota</button>
        <h3>Evidências</h3>
        <div class="table-scroll">
          <table id="inc-evidence-table">
            <thead><tr><th>Hora</th><th>Tipo</th><th>Severidade</th><th>Descrição</th></tr></thead>
            <tbody id="inc-evidence-body"></tbody>
          </table>
        </div>
        <h3>Timeline</h3>
        <ol class="inc-timeline" id="inc-timeline"></ol>
      </section>
    </div>

```

(c) a seguir a `<script src="redblue.js"></script>` acrescentar `<script src="incidents.js"></script>`.

- [ ] **Step 4: `app.js`** — em `connectWebSocket()`, no ramo `msg.type === "new_alert"`, a seguir a `refreshDashboard();`:

```js
        document.dispatchEvent(new CustomEvent("sentrylens:new-alert"));
```

- [ ] **Step 5: `incidents.js`** — criar:

```js
// Aba "Incidentes" (Roadmap v2, R3). Carregado depois de app.js e redblue.js:
// reutiliza os seus globais (API_BASE, API_KEY, escapeHtml, severityBadge,
// formatTimestamp, renderPanelError, periodSelect) — não redeclarar nenhum
// aqui. Só mostra dados reais de /api/incidents/*; sem dados, estado vazio.
// Todo o texto dinâmico passa por escapeHtml (notas e payloads vêm do analista
// e do Wazuh).

const INC_REFRESH_MS = 30000;
const INC_STATUS_LABELS = {
  NEW: "Novo", INVESTIGATING: "Em investigação", CONTAINED: "Contido", RESOLVED: "Resolvido", CLOSED: "Fechado",
};
const INC_EVENT_LABELS = {
  created: "Incidente criado", evidence_added: "Evidência adicionada", attack_linked: "Ataque ligado",
  severity_changed: "Severidade alterada", status_changed: "Estado alterado", note_added: "Nota",
};

let incSelectedId = null;
let incRefreshing = false;

function incCell(value) {
  if (value === null || value === undefined || value === "") return "—";
  return escapeHtml(String(value));
}

function incSetText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function incFormatSeconds(seconds) {
  if (seconds === null || seconds === undefined) return "—";
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  return `${Math.floor(seconds / 60)} min ${Math.round(seconds % 60)} s`;
}

function incStatusBadge(status) {
  const label = INC_STATUS_LABELS[status] || status;
  return `<span class="inc-status inc-status-${escapeHtml(status)}">${escapeHtml(label)}</span>`;
}

async function incRequest(method, path, body) {
  const response = await fetch(`${API_BASE}${path}`, {
    method,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    try {
      const data = await response.json();
      if (data && typeof data.detail === "string") detail = data.detail;
    } catch (_) { /* corpo não-JSON: fica o código HTTP */ }
    const error = new Error(detail);
    error.status = response.status;
    throw error;
  }
  return response.json();
}

function incWindowHours() {
  // period-select está em dias; o endpoint aceita no máximo 720 h (30 dias).
  return Math.min(Number(periodSelect.value) * 24, 720);
}

function renderIncidentsKpis(summary) {
  incSetText("kpi-inc-open", summary.open);
  incSetText("kpi-inc-high", summary.high_or_critical_open);
  incSetText("kpi-inc-mttd", incFormatSeconds(summary.avg_mttd_seconds));
  incSetText("kpi-inc-total", summary.total);
}

function renderIncidentsTable(incidents) {
  const body = document.getElementById("incidents-body");
  if (!incidents.length) {
    body.innerHTML = `<tr><td colspan="8" class="empty-state">Sem incidentes nesta janela. Se ainda não importaste o histórico, usa «Importar histórico».</td></tr>`;
    return;
  }
  body.innerHTML = incidents.map((i) => {
    const mitre = i.techniques.length ? i.techniques.join(", ") : "—";
    const attack = i.attack_ids.length ? ` (ataque #${i.attack_ids.join(", #")})` : "";
    return `<tr class="inc-row${i.id === incSelectedId ? " selected" : ""}" data-id="${escapeHtml(i.id)}" tabindex="0">
      <td>${escapeHtml(i.id)}</td>
      <td>${severityBadge(i.severity)}</td>
      <td>${incStatusBadge(i.status)}</td>
      <td>${incCell(i.asset)}</td>
      <td>${escapeHtml(formatTimestamp(i.first_evidence_at))}</td>
      <td>${escapeHtml(formatTimestamp(i.last_evidence_at))}</td>
      <td>${incCell(i.evidence_count)}</td>
      <td>${escapeHtml(mitre + attack)}</td>
    </tr>`;
  }).join("");
}

function incEvidenceDescription(e) {
  if (e.kind === "wazuh_alert" && e.alert) {
    const a = e.alert;
    return `${a.friendly_name || "Alerta"} — ${a.rule_description || "sem descrição"} (${a.agent_name || "?"})`;
  }
  if (e.kind === "network_detection" && e.payload) {
    const p = e.payload;
    return `${p.type} ${p.src_ip || "?"} → ${p.dst_ip || "?"}`;
  }
  return "—";
}

function incTimelineText(ev) {
  const d = ev.data || {};
  switch (ev.kind) {
    case "created": return `${INC_EVENT_LABELS.created} em ${d.asset || "?"} (${d.severity || "?"})`;
    case "evidence_added": return `${INC_EVENT_LABELS.evidence_added}: ${d.kind || ""} (${d.severity || "?"})`;
    case "attack_linked": return `${INC_EVENT_LABELS.attack_linked}: ${d.scenario || "?"} / ${d.technique || "?"} / ${d.tool || "?"}${d.attack_id != null ? ` (#${d.attack_id})` : ""}`;
    case "severity_changed": return `${INC_EVENT_LABELS.severity_changed}: ${d.from} → ${d.to}`;
    case "status_changed": return `${INC_EVENT_LABELS.status_changed}: ${d.from} → ${d.to}${d.note ? ` — ${d.note}` : ""}`;
    case "note_added": return `${INC_EVENT_LABELS.note_added}: ${d.text || ""}`;
    default: return ev.kind;
  }
}

function renderIncidentDetail(incident) {
  const panel = document.getElementById("incident-detail-panel");
  panel.hidden = false;
  incSetText("inc-detail-title", `Incidente ${incident.id}`);

  const ml = incident.ml_summary
    ? `${incident.ml_summary.ml_anomalies}/${incident.ml_summary.scored} anomalias ML · ${incident.ml_summary.rule_flagged} por regra`
    : "sem modelo ML";
  document.getElementById("inc-detail-meta").innerHTML = `
    <span>${severityBadge(incident.severity)}</span> <span>${incStatusBadge(incident.status)}</span>
    <span>Ativo: <strong>${incCell(incident.asset)}</strong></span>
    <span>MITRE: ${incCell(incident.techniques.join(", "))}</span>
    <span>MTTD: ${escapeHtml(incFormatSeconds(incident.mttd_seconds))}</span>
    <span>1.ª resposta: ${escapeHtml(incFormatSeconds(incident.time_to_first_response_seconds))}</span>
    <span>${escapeHtml(ml)}</span>`;

  document.getElementById("inc-actions").innerHTML = incident.available_transitions.map((s) =>
    `<button type="button" class="inc-transition" data-status="${escapeHtml(s)}">→ ${escapeHtml(INC_STATUS_LABELS[s] || s)}</button>`
  ).join("") || `<span class="panel-note">Estado final — sem transições.</span>`;

  document.getElementById("inc-evidence-body").innerHTML = incident.evidence.map((e) => `<tr>
    <td>${escapeHtml(formatTimestamp(e.ts))}</td><td>${escapeHtml(e.kind)}</td>
    <td>${severityBadge(e.severity)}</td><td>${escapeHtml(incEvidenceDescription(e))}</td></tr>`).join("");

  document.getElementById("inc-timeline").innerHTML = incident.timeline.map((ev) =>
    `<li><time>${escapeHtml(formatTimestamp(ev.ts))}</time> <em>${escapeHtml(ev.actor)}</em> — ${escapeHtml(incTimelineText(ev))}</li>`
  ).join("");
}

function incShowDetailError(message) {
  const el = document.getElementById("inc-detail-error");
  el.hidden = !message;
  el.textContent = message ? `⚠️ ${message}` : "";
}

async function selectIncident(id) {
  incSelectedId = id;
  incShowDetailError("");
  try {
    renderIncidentDetail(await incRequest("GET", `/api/incidents/${encodeURIComponent(id)}`));
    document.querySelectorAll("#incidents-body tr[data-id]").forEach((tr) =>
      tr.classList.toggle("selected", tr.dataset.id === id));
  } catch (err) {
    incShowDetailError(err.message);
  }
}

async function incApply(promise) {
  incShowDetailError("");
  try {
    renderIncidentDetail(await promise);
    document.getElementById("inc-note-input").value = "";
    await refreshIncidentsTab();
  } catch (err) {
    incShowDetailError(err.message);
  }
}

async function refreshIncidentsTab() {
  if (incRefreshing) return;
  incRefreshing = true;
  try {
    const params = new URLSearchParams({ hours: String(incWindowHours()) });
    const status = document.getElementById("inc-status-filter").value;
    const severity = document.getElementById("inc-severity-filter").value;
    if (status) params.set("status", status);
    if (severity) params.set("severity", severity);
    const data = await incRequest("GET", `/api/incidents?${params}`);
    renderPanelError("#incidents-panel", "");
    renderIncidentsKpis(data.summary);
    renderIncidentsTable(data.incidents);
  } catch (err) {
    renderPanelError("#incidents-panel", `Não foi possível carregar os incidentes: ${err.message}`);
    document.getElementById("incidents-body").innerHTML =
      `<tr><td colspan="8" class="empty-state">Indisponível.</td></tr>`;
  } finally {
    incRefreshing = false;
  }
}

async function backfillIncidents() {
  const btn = document.getElementById("inc-backfill-btn");
  btn.disabled = true;
  incSetText("inc-notice", "A importar alertas do Wazuh…");
  try {
    const r = await incRequest("POST", "/api/incidents/backfill", { days: Number(periodSelect.value) });
    incSetText("inc-notice",
      `Importados ${r.fetched} alertas: ${r.opened} incidentes abertos, ${r.attached} anexados, ${r.duplicate} já conhecidos, ${r.ignored} abaixo do limiar, ${r.invalid} inválidos.` +
      (r.truncated ? " ⚠️ Atingido o teto de alertas por importação — alguns ficaram de fora." : "") +
      " Só alertas Wazuh (as deteções de rede só existem em memória).");
    await refreshIncidentsTab();
  } catch (err) {
    incSetText("inc-notice", `⚠️ Falha ao importar: ${err.message}`);
  } finally {
    btn.disabled = false;
  }
}

document.getElementById("incidents-body").addEventListener("click", (event) => {
  const tr = event.target.closest("tr[data-id]");
  if (tr) selectIncident(tr.dataset.id);
});
document.getElementById("incidents-body").addEventListener("keydown", (event) => {
  const tr = event.target.closest("tr[data-id]");
  if (tr && (event.key === "Enter" || event.key === " ")) {
    event.preventDefault();
    selectIncident(tr.dataset.id);
  }
});

document.getElementById("inc-actions").addEventListener("click", (event) => {
  const btn = event.target.closest("button.inc-transition");
  if (!btn || !incSelectedId) return;
  const note = document.getElementById("inc-note-input").value.trim();
  const isFalsePositive = btn.dataset.status === "CLOSED" &&
    document.querySelector("#inc-detail-meta .inc-status-NEW") !== null;
  if (isFalsePositive && !note) {
    incShowDetailError("Escreve uma nota (falso positivo) antes de fechar um incidente novo.");
    return;
  }
  incApply(incRequest("POST", `/api/incidents/${encodeURIComponent(incSelectedId)}/status`,
    { status: btn.dataset.status, note: note || null }));
});

document.getElementById("inc-note-btn").addEventListener("click", () => {
  const text = document.getElementById("inc-note-input").value.trim();
  if (!text || !incSelectedId) return;
  incApply(incRequest("POST", `/api/incidents/${encodeURIComponent(incSelectedId)}/notes`, { text }));
});

document.getElementById("inc-backfill-btn").addEventListener("click", backfillIncidents);
document.getElementById("inc-status-filter").addEventListener("change", refreshIncidentsTab);
document.getElementById("inc-severity-filter").addEventListener("change", refreshIncidentsTab);
periodSelect.addEventListener("change", refreshIncidentsTab);
document.addEventListener("sentrylens:new-alert", refreshIncidentsTab);

refreshIncidentsTab();
setInterval(refreshIncidentsTab, INC_REFRESH_MS);
```

- [ ] **Step 6: `style.css`** — acrescentar no fim:

```css
/* ===== Incidentes (Roadmap v2, R3) ===== */
.inc-row { cursor: pointer; }
.inc-row:hover, .inc-row.selected { background: #eef7f9; }
.inc-row:focus-visible { outline: 2px solid var(--cyan-600); outline-offset: -2px; }
.inc-status { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 12px; font-weight: 600; background: #e0e6ea; color: var(--ink-900); }
.inc-status-NEW { background: #fdecc8; }
.inc-status-INVESTIGATING { background: #d6ebf5; }
.inc-status-CONTAINED { background: #e3d9f3; }
.inc-status-RESOLVED { background: #d4efdf; }
.inc-status-CLOSED { background: #e0e0e0; color: #666; }
.inc-meta { display: flex; flex-wrap: wrap; gap: 8px 16px; align-items: center; margin-bottom: 12px; font-size: 14px; }
.inc-actions { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 12px; }
.inc-actions button, #inc-note-btn, #inc-backfill-btn { padding: 8px 12px; border: none; border-radius: 6px; background: var(--cyan-600); color: #fff; font-weight: 600; cursor: pointer; }
.inc-actions button:hover, #inc-note-btn:hover, #inc-backfill-btn:hover { background: var(--cyan-700); }
.inc-actions button:disabled, #inc-backfill-btn:disabled { opacity: 0.5; cursor: wait; }
.inc-note-label { display: block; margin: 8px 0 4px; font-size: 13px; color: #666; }
#inc-note-input { width: 100%; padding: 8px; border: 1px solid #ccd3d8; border-radius: 6px; font: inherit; margin-bottom: 8px; }
.inc-timeline { list-style: none; margin: 8px 0 0; padding: 0; font-size: 13px; }
.inc-timeline li { padding: 6px 0; border-bottom: 1px solid #eee; }
.inc-timeline time { font-family: var(--font-mono); color: #888; margin-right: 6px; }
```

- [ ] **Step 7: Verificação no browser (Playwright)** — com backend e frontend a correr (`serve_frontend.py` reiniciado para apanhar a nova whitelist) e o Wazuh ligado:

1. Abrir `http://localhost:5500/index.html#incidents`. Esperado: item "Incidentes" ativo na sidebar, KPIs a `—`/0, tabela com a mensagem "Sem incidentes nesta janela…", consola **sem erros**.
2. Carregar em "📥 Importar histórico". Esperado: aviso verde/cinzento com contagens (`Importados N alertas: X abertos…`), tabela preenchida com incidentes reais, KPIs atualizados. Segunda carga → `0 abertos`, tudo "já conhecidos".
3. Clicar numa linha. Esperado: painel de detalhe com evidências e timeline; botões só das transições válidas (`NEW` → "Em investigação", "Fechado").
4. Escrever na nota `<img src=x onerror=alert(1)>` e "Adicionar nota". Esperado: aparece **como texto** na timeline, **nenhum** alerta/diálogo; recarregar a página mantém-no como texto.
5. "Fechado" num incidente NEW **sem** nota → mensagem "Escreve uma nota…" e nenhum pedido enviado; com nota → fecha e o botão deixa de existir ("Estado final").
6. Largura 390 px: tabela com scroll horizontal dentro do painel, sem scroll horizontal da página.

- [ ] **Step 8: Commit**

```bash
git add incidents.js index.html style.css app.js scripts/serve_frontend.py scripts/test_serve_frontend.py
git commit -m "feat(ui): painel Incidentes com detalhe, timeline, estados e importacao de historico (R3)"
git log -1 --format=%B | grep -ci co-authored   # 0
```

---

### Task 8: Documentação, aceitação com dados reais e fecho

**Files:**
- Modify: `docs/API.md`, `docs/DATA_MODEL.md`, `docs/ARCHITECTURE.md`, `docs/ROADMAP_STATUS.md`, `docs/superpowers/specs/2026-10-06-r3-incidentes-design.md`, `README.md`, `CLAUDE.md` (local, não versionado), `scripts/README.md` se listar testes

- [ ] **Step 1: `docs/API.md`** — acrescentar uma secção "Incidentes (R3)" com a tabela das 5 rotas (método, caminho, parâmetros, resposta, erros 401/404/409/422/502/500) copiada da §3 da spec, e o exemplo de resposta de `GET /api/incidents` (`window_hours`, `incidents[]` com `evidence_count/techniques/attack_ids/mttd_seconds/time_to_first_response_seconds`, `summary`).

- [ ] **Step 2: `docs/DATA_MODEL.md`** — acrescentar "Incidente (R3)": as 3 tabelas SQLite (colunas), o formato `INC-AAAAMMDD-NNN` (dia da 1.ª evidência), as chaves de deduplicação, os tipos de evento da timeline e a nota de que `incident_events` é append-only (triggers).

- [ ] **Step 3: `docs/ARCHITECTURE.md`** — acrescentar a linha "Incidentes: `incident_engine.py` (puro), `incident_store.py`, `incident_ingest.py`" à tabela de módulos, a linha `incidents.sqlite3` à tabela de persistência, e atualizar a frase "só o correlator os une" para referir que os incidentes agrupam as três fontes por ativo.

- [ ] **Step 4: `docs/ROADMAP_STATUS.md`** — linha R3 → `✅` com nota "Incidentes automáticos (alertas Wazuh + rede), estados, timeline, backfill, painel"; R4/R7/R8 ficam com a nota "usa `attack_id` em `incident_events`" / "base para DetectionEvent" / "tempo até à 1.ª resposta já calculado". Acrescentar à "Dívida conhecida": janela de 10 min pode fundir ataques distintos ao mesmo ativo; deteções de rede só em memória (fora do backfill); autor fixo `analyst`.

- [ ] **Step 5: Spec** — em `docs/superpowers/specs/2026-10-06-r3-incidentes-design.md`: na tabela do §2, `id` passa a "(data da 1.ª evidência, sequência diária)"; em "Derivados", o tempo até à 1.ª resposta é "primeiro `status_changed → INVESTIGATING` menos `first_evidence_at`" (não `created_at`, que no backfill é a hora da importação); no §5/§1 "Críticos abertos" passa a "Altos/críticos abertos". Isto alinha a spec com o que foi implementado.

- [ ] **Step 6: `README.md`** — acrescentar a aba/painel Incidentes à descrição da sidebar e as 5 rotas à lista de endpoints; atualizar a contagem de ficheiros de teste e a lista (os 4 novos). Atualizar do mesmo modo a lista de testes do `CLAUDE.md` local (ficheiro não versionado; não fazer `git add`).

- [ ] **Step 7: Aceitação com dados reais** (Wazuh ligado, backend a correr com o novo código — reiniciar o `uvicorn`):

```bash
cd scripts && source .venv/Scripts/activate && python - <<'EOF'
import json, urllib.request
key = ""
for l in open(".env", encoding="utf-8"):
    if l.startswith("SENTRYLENS_API_KEY="): key = l.split("=", 1)[1].strip().strip("\"'")
def call(method, path, body=None):
    r = urllib.request.Request("http://127.0.0.1:8001" + path, method=method,
        headers={"X-API-Key": key, "Content-Type": "application/json"},
        data=None if body is None else json.dumps(body).encode())
    with urllib.request.urlopen(r, timeout=60) as f: return json.load(f)
print("backfill 1:", call("POST", "/api/incidents/backfill", {"days": 7}))
print("backfill 2:", call("POST", "/api/incidents/backfill", {"days": 7}))
s = call("GET", "/api/incidents?hours=168")["summary"]; print("summary:", s)
EOF
```

Critérios (da spec §8): a 2.ª corrida tem `opened: 0` e `duplicate` = nº de alertas que não foram ignorados; o resumo mostra incidentes com ativos reais; **nenhum** incidente tem técnica MITRE sem ataque ligado. Verificar também o tempo real: gerar/aguardar um alerta `high` novo e confirmar que o incidente aparece/atualiza em < 15 s (`/ws/alerts` poll de 10 s) e que `scripts/backend.log` regista `Incidentes (alertas): {...}`.

- [ ] **Step 8: Regressão completa e commit final**

```bash
cd scripts && fail=0; for t in test_*.py; do python "$t" >/dev/null 2>&1 || { echo "FALHOU $t"; fail=1; }; done; echo "any_fail=$fail"
cd .. && git add docs README.md docs/superpowers/specs/2026-10-06-r3-incidentes-design.md
git commit -m "docs(r3): documenta a gestao de incidentes e marca R3 como concluida"
git log -3 --format=%B | grep -ci co-authored   # 0
git status --short   # sem ficheiros por commitar além dos ja nao rastreados conhecidos
```

- [ ] **Step 9: Atualizar a página "Roadmap v2" no Notion** (R3 ✅, o que foi entregue, desvios da spec e a dívida nova) e dar o resumo ao utilizador, incluindo os números reais do backfill.

---

## Self-Review (feito contra a spec)

- **Cobertura da spec:** §1 modelo/regras → Task 2 (+ attack_windows Task 1); §2 persistência/derivados/ml_summary → Tasks 3 e 4 (`ml_summary`) e 6 (`_incident_detail`); §3 API → Task 6; §4 ingest (alertas, rede, ML, backfill) → Tasks 4, 5, 6; §5 frontend → Task 7; §6 testes → Tasks 1–7; §7 riscos → "Dívida conhecida" (Task 8) e Review Focus; §8 aceitação → Task 8 Step 7. Fora de âmbito respeitado (sem merge/split, sem pessoas, sem MTTR formal).
- **Placeholders:** nenhum "TBD/TODO"; todo o código está escrito. Os passos de documentação (Task 8, Steps 1–6) descrevem conteúdo a partir de material já definido na spec e neste plano.
- **Consistência de tipos:** nomes usados entre tarefas verificados — `evidence_from_raw_alert`, `evidence_from_network_detection`, `assign_evidence(already_known=)`, `can_transition → (bool, reason)`, `compute_windows`, `link_attacks`, `attack_link_data`, `IncidentStore.{evidence_exists,list_open_incidents,create_incident,attach_evidence,link_attack,add_note,set_status,get_incident,list_incidents,summary}`, `ingest_{evidences,raw_alerts,network_detections}`, `ml_summary`, `on_new_raw_alerts`, `on_new_detections`, `main.{incident_store,BACKFILL_MAX_ALERTS,INCIDENTS_DB_PATH}`.
- **Desvios deliberados da spec, a registar no Step 5 da Task 8:** (1) id `INC-` usa o dia da 1.ª evidência (não da criação) para o backfill dar IDs com sentido; (2) tempo até à 1.ª resposta mede-se a partir de `first_evidence_at`; (3) KPI "Altos/Críticos abertos" (o catálogo não tem `critical`).
