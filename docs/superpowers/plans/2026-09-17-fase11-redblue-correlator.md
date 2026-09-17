# Fase 11 (Onda 1) — Motor de Correlação Red vs Blue Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cruzar `scripts/attack_log.jsonl` (verdade dos ataques lançados
pela VM Kali) com os alertas Wazuh já classificados por regra + ML, para
responder por cenário de ataque: foi detetado? por regra, por ML, por
ambos, ou por nenhum? em quanto tempo (MTTD)? — expondo tudo via um novo
endpoint `GET /api/redblue/metrics`.

**Architecture:** Segue o padrão já estabelecido em `scripts/`
(`lifecycle.py`, `rbac.py`, `admin_activity.py`, `ml_anomalies.py`): um
módulo de domínio puro (`redblue_correlator.py`) recebe listas já obtidas
(log de ataques + resultados já classificados de `ml_anomalies.py`) e
devolve um dict de relatório; `main.py` fica só a camada HTTP fina. Não
duplica classificação — reaproveita `ml_anomalies.build_ml_anomalies_report()`
tal como está, só acrescentando um campo (`agent_ip`) ao seu output.

**Tech Stack:** Python stdlib (`datetime`, `dataclasses`) — sem
dependências novas. Testes: scripts standalone sem pytest, padrão
`check()`/`[OK]`/`[FALHOU]`/`sys.exit(1)` já usado em todo o projeto.

**Spec:** `docs/superpowers/specs/2026-09-17-fase11-redblue-correlator-design.md`
— este plano implementa exatamente essa spec (âmbito, decisões e formato
de saída já aprovados); os executores devem ler os dois documentos.

## Global Constraints

- Frontend (10ª aba) está **fora de escopo** deste plano — é uma Onda 2
  separada, só arranca depois desta onda fechada e aprovada.
- `redblue_correlator.py` é uma função pura: não faz I/O nem chamadas de
  rede, nunca lança exceção sobre dados malformados (ignora a entrada e
  segue em frente, mesma convenção de `lifecycle.py`/`feature_extractor.py`).
- Regra de correspondência fixada na spec: um alerta só conta como
  deteção de um ataque se `agent_ip == target` **e**
  `windows_event_id in scenario.event_ids`.
- Janela de correlação: `[timestamp, min(timestamp + window_seconds,
  timestamp_da_próxima_entrada_do_log)]`, `window_seconds=300` por
  omissão.
- Entradas do `attack_log` com `status != "launched"` vão para
  `not_executed`; entradas com nome de cenário desconhecido vão para
  `unknown_scenario` — nunca descartadas silenciosamente, nunca contam
  para `overall.total_attempts`.
- Todos os endpoints REST `/api/*` exigem `dependencies=_REQUIRE_API_KEY`
  individualmente na rota (nunca a nível de app) — ver `main.py:108-120`
  para o padrão exato.
- Testes: `os.environ.setdefault("SENTRYLENS_API_KEY", ...)` **antes** de
  `import main`; `main.app.router.on_startup.clear()` logo a seguir, para
  não arrancar os loops de background. Sem pytest — script standalone com
  `check(label, condition)`, `sys.exit(1)` se `failures` não estiver
  vazio no fim.
- Caminhos configuráveis via variável de ambiente resolvem-se sempre
  relativamente a `os.path.dirname(__file__)`, nunca ao cwd (ver
  `RBAC_BASELINE_PATH`/`ML_MODEL_DIR` em `main.py` como exemplo).

---

## File Structure

| File | Task | Responsibility |
|---|---|---|
| `scripts/attack_scenarios.py` | 1 | Acrescenta `mitre_tactic`/`mitre_technique` ao `Scenario` dataclass, preenchidos para os 5 cenários. |
| `scripts/feature_extractor.py` | 2 | Acrescenta `agent_ip` ao dict devolvido por `extract_features`. |
| `scripts/test_feature_extractor.py` | 2 | Novo caso de teste para `agent_ip`. |
| `scripts/ml_anomalies.py` | 2 | Acrescenta `agent_ip` ao dict de cada resultado de `build_ml_anomalies_report`. |
| `scripts/test_ml_anomalies.py` | 2 | Novo caso de teste para `agent_ip` no output do endpoint. |
| `scripts/redblue_correlator.py` | 3 | NOVO — função pura `build_redblue_report()`. |
| `scripts/test_redblue.py` | 3, 4 | NOVO — testes da correlação pura (Task 3) + testes do endpoint via HTTP (Task 4). |
| `scripts/main.py` | 4 | Nova env var `ATTACK_LOG_PATH` + endpoint `GET /api/redblue/metrics`. |
| `CLAUDE.md` | 5 | Documenta o novo módulo/endpoint/teste. |
| `README.md` | 5 | Nova secção de endpoint + linha na tabela de testes. |
| `scripts/.env.example` | 5 | Documenta `ATTACK_LOG_PATH`. |
| Notion (`page_id 3caa99e6-526b-8111-89be-db8b6ffe765b`) | 6 | Registo de execução da Onda 1. |

---

## Task 1: `attack_scenarios.py` — mapeamento MITRE ATT&CK por cenário

**Files:**
- Modify: `scripts/attack_scenarios.py:55-129` (dataclass + dict `SCENARIOS`), `scripts/attack_scenarios.py:188-195` (`_self_check`)

**Interfaces:**
- Produces: `Scenario.mitre_tactic: str`, `Scenario.mitre_technique: str` — consumidos por `redblue_correlator.build_redblue_report()` na Task 3 (lê `scenario.mitre_tactic`/`scenario.mitre_technique` de cada entrada de `scenarios[name]`).

- [ ] **Step 1: Alterar o dataclass `Scenario`**

Em `scripts/attack_scenarios.py`, substituir (linhas 55-63):

```python
@dataclass
class Scenario:
    name: str
    description: str
    tool: str
    event_ids: list[int]  # Event IDs do event_catalog.py que este cenário tipicamente gera
    build_command: Callable[[argparse.Namespace], list[str] | None]
    # build_command devolve None (em vez de lançar) quando faltam argumentos
    # obrigatórios (ex: credenciais) — o cenário fica "skipped", não crasha.
```

por:

```python
@dataclass
class Scenario:
    name: str
    description: str
    tool: str
    event_ids: list[int]  # Event IDs do event_catalog.py que este cenário tipicamente gera
    mitre_tactic: str  # Tactic MITRE ATT&CK (ex: "Credential Access") — ver redblue_correlator.py (Fase 11)
    mitre_technique: str  # Technique/sub-technique (ex: "T1110" ou "T1110.003")
    build_command: Callable[[argparse.Namespace], list[str] | None]
    # build_command devolve None (em vez de lançar) quando faltam argumentos
    # obrigatórios (ex: credenciais) — o cenário fica "skipped", não crasha.
```

- [ ] **Step 2: Preencher o mapeamento nos 5 cenários existentes**

Em `scripts/attack_scenarios.py`, substituir o dict `SCENARIOS` (linhas 93-129):

```python
SCENARIOS: dict[str, Scenario] = {
    "brute_force_rdp": Scenario(
        name="brute_force_rdp",
        description="Força bruta de RDP contra o agente alvo (gera 4625 repetidos).",
        tool="hydra",
        event_ids=[4625, 4740],
        mitre_tactic="Credential Access",
        mitre_technique="T1110",
        build_command=_brute_force_rdp_command,
    ),
    "smb_enum": Scenario(
        name="smb_enum",
        description="Enumeração de partilhas SMB (gera 5140/5145).",
        tool="netexec",
        event_ids=[5140, 5145],
        mitre_tactic="Discovery",
        mitre_technique="T1135",
        build_command=_smb_enum_command,
    ),
    "blank_password_check": Scenario(
        name="blank_password_check",
        description="Verificação de sessão nula / password em branco (gera 4797).",
        tool="netexec",
        event_ids=[4797],
        mitre_tactic="Credential Access",
        mitre_technique="T1110",
        build_command=_blank_password_check_command,
    ),
    "lateral_movement_schtasks": Scenario(
        name="lateral_movement_schtasks",
        description="Pós-comprometimento: cria tarefa agendada via SMB (gera 4672 + 4698).",
        tool="netexec",
        event_ids=[4672, 4698],
        mitre_tactic="Lateral Movement",
        mitre_technique="T1053",
        build_command=_lateral_movement_schtasks_command,
    ),
    "account_lockout_spray": Scenario(
        name="account_lockout_spray",
        description="Password spraying com password errada para forçar bloqueio (gera 4625/4740).",
        tool="netexec",
        event_ids=[4625, 4740],
        mitre_tactic="Credential Access",
        mitre_technique="T1110.003",
        build_command=_account_lockout_spray_command,
    ),
}
```

(Nota: `mitre_tactic`/`mitre_technique` são valores indicativos herdados
do ponto de partida documentado no Notion — a spec já regista esta
ressalva, não são um veredito MITRE formal.)

- [ ] **Step 3: Estender `_self_check()` para verificar o mapeamento**

Em `scripts/attack_scenarios.py`, substituir `_self_check` (linhas 188-195):

```python
def _self_check() -> None:
    """Verificação rápida e determinística do formato de log e do
    mapeamento MITRE (sem lançar nada)."""
    fixed_time = datetime(2026, 9, 12, 14, 30, 0, tzinfo=timezone.utc)
    entry = format_log_entry("brute_force_rdp", "192.168.1.20", "hydra", "launched", {"returncode": 0}, now=fixed_time)
    assert entry["timestamp"] == "2026-09-12T14:30:00+00:00", entry["timestamp"]
    assert entry["scenario"] == "brute_force_rdp"
    assert set(entry.keys()) == {"timestamp", "scenario", "target", "tool", "status", "details"}
    print("[OK   ] format_log_entry produz o formato JSONL esperado")

    for name, scenario in SCENARIOS.items():
        assert scenario.mitre_tactic, f"{name} sem mitre_tactic"
        assert scenario.mitre_technique, f"{name} sem mitre_technique"
    print(f"[OK   ] todos os {len(SCENARIOS)} cenários têm mitre_tactic/mitre_technique preenchidos")
```

- [ ] **Step 4: Correr a verificação**

Run: `cd scripts && python attack_scenarios.py --self-check`
Expected:
```
[OK   ] format_log_entry produz o formato JSONL esperado
[OK   ] todos os 5 cenários têm mitre_tactic/mitre_technique preenchidos
```

- [ ] **Step 5: Commit**

```bash
git add scripts/attack_scenarios.py
git commit -m "feat: acrescenta mapeamento MITRE ATT&CK aos cenários de ataque (Fase 11)"
```

---

## Task 2: `feature_extractor.py` + `ml_anomalies.py` — expor `agent_ip`

**Files:**
- Modify: `scripts/feature_extractor.py:133-148` (`extract_features`)
- Modify: `scripts/test_feature_extractor.py` (novo caso de teste)
- Modify: `scripts/ml_anomalies.py:84-94` (`build_ml_anomalies_report`)
- Modify: `scripts/test_ml_anomalies.py` (novo caso de teste)

**Interfaces:**
- Consumes: nenhuma interface nova de tasks anteriores.
- Produces: cada dict devolvido por `extract_features()` e cada item de
  `build_ml_anomalies_report(...)["results"]` passa a ter a chave
  `"agent_ip": str` — consumida por `redblue_correlator.build_redblue_report()`
  na Task 3 (`result.get("agent_ip")`).

- [ ] **Step 1: Escrever o teste que falha para `extract_features`**

Em `scripts/test_feature_extractor.py`, acrescentar depois do bloco
`# --- hour_of_day / day_of_week ---` (a seguir à linha 39):

```python
    # --- agent_ip (Fase 11: usado pelo redblue_correlator para casar
    # alerta com o alvo do ataque, distinto de source_ip que é o IP de
    # origem da ligação/logon) ---
    feats_ip = extract_features([alert(4624, "2026-09-10T14:05:00Z", agent_ip="192.168.1.99")])
    check("agent_ip extraído de agent.ip", feats_ip[0]["agent_ip"] == "192.168.1.99")
```

- [ ] **Step 2: Correr para confirmar que falha**

Run: `cd scripts && python test_feature_extractor.py`
Expected: `[FALHOU] agent_ip extraído de agent.ip` na lista de falhas, `sys.exit(1)` (o campo `"agent_ip"` ainda não existe no dict devolvido, `KeyError` seria lançado — na verdade este `check()` vai levantar `KeyError` antes de imprimir, o que interrompe o script com traceback; isso É o resultado esperado desta verificação, confirma que o campo não existe ainda).

- [ ] **Step 3: Implementar `agent_ip` em `extract_features`**

Em `scripts/feature_extractor.py`, dentro do `rows.append({...})` (linhas
133-148), acrescentar a chave `"agent_ip"` logo a seguir a `"agent_name"`:

```python
        rows.append({
            "timestamp": ts.isoformat(),
            "windows_event_id": event_id,
            "target_user": user,
            "source_ip": ip,
            "agent_name": alert.get("agent", {}).get("name", "Unknown"),
            "agent_ip": alert.get("agent", {}).get("ip", "-"),
            "severity": classification["severity"],
            "rule_flagged": classification["severity"] == "high",
            "hour_of_day": ts.hour,
            "day_of_week": ts.weekday(),
            "event_id_encoded": _encode_event_id(event_id),
            "failed_attempts_last_hour": len(recent_failures),
            "has_special_privileges": 1 if classification["category"] == "atividade_privilegiada" else 0,
            "is_new_source_ip": 1 if is_new_ip else 0,
            "severity_encoded": _SEVERITY_ORDER.get(classification["severity"], 0),
        })
```

- [ ] **Step 4: Correr o teste, confirmar que passa**

Run: `cd scripts && python test_feature_extractor.py`
Expected: `[OK] Todos os testes passaram`, saída 0.

- [ ] **Step 5: Escrever o teste que falha para `build_ml_anomalies_report`**

Em `scripts/test_ml_anomalies.py`, acrescentar a seguir à linha
`check("cada resultado tem rule_flagged e agreement", ...)` (linha 69):

```python
    check("cada resultado tem agent_ip", all(r.get("agent_ip") == "192.168.1.5" for r in body["results"]))
```

(O helper `alert()` deste ficheiro já fixa `"agent": {"name": "WIN-PC01",
"ip": "192.168.1.5"}` para todos os alertas mock — ver linha 39.)

- [ ] **Step 6: Correr para confirmar que falha**

Run: `cd scripts && python test_ml_anomalies.py`
Expected: `[FALHOU] cada resultado tem agent_ip` na lista de falhas (o
campo ainda não existe, `r.get("agent_ip")` devolve `None`, a condição é
`False` para todos — o `check()` não lança, só regista falha).

- [ ] **Step 7: Implementar `agent_ip` em `build_ml_anomalies_report`**

Em `scripts/ml_anomalies.py`, dentro do `results.append({...})` (linhas
84-94), acrescentar a chave `"agent_ip"` logo a seguir a `"agent_name"`:

```python
        results.append({
            "timestamp": row["timestamp"],
            "agent_name": row["agent_name"],
            "agent_ip": row["agent_ip"],
            "target_user": row["target_user"],
            "windows_event_id": row["windows_event_id"],
            "severity": row["severity"],
            "rule_flagged": rule_flagged,
            "ml_score": round(float(score), 4),
            "ml_is_anomaly": ml_is_anomaly,
            "agreement": agreement,
        })
```

- [ ] **Step 8: Correr o teste, confirmar que passa**

Run: `cd scripts && python test_ml_anomalies.py`
Expected: `[OK] Todos os testes passaram`, saída 0.

- [ ] **Step 9: Commit**

```bash
git add scripts/feature_extractor.py scripts/test_feature_extractor.py scripts/ml_anomalies.py scripts/test_ml_anomalies.py
git commit -m "feat: expoe agent_ip em extract_features e build_ml_anomalies_report (Fase 11)"
```

---

## Task 3: `redblue_correlator.py` — motor de correlação (função pura)

**Files:**
- Create: `scripts/redblue_correlator.py`
- Create: `scripts/test_redblue.py`

**Interfaces:**
- Consumes: `Scenario` de `attack_scenarios.py` (Task 1, campos
  `event_ids`/`mitre_tactic`/`mitre_technique`); formato de item de
  `ml_results` = dict com pelo menos `timestamp`/`agent_ip`/
  `windows_event_id`/`rule_flagged`/`ml_is_anomaly` (Task 2).
- Produces: `build_redblue_report(attack_log, ml_results, scenarios,
  window_seconds=300) -> dict` com as chaves `attempts`/`by_scenario`/
  `overall`/`not_executed`/`unknown_scenario` — consumido por `main.py`
  na Task 4.

- [ ] **Step 1: Escrever `scripts/test_redblue.py` com os testes da correlação pura (vão falhar — o módulo ainda não existe)**

```python
"""
Testes de regressão do motor de correlação Red vs Blue (Fase 11, Onda 1),
em duas partes:
  1. build_redblue_report() isolada (sem Wazuh, sem HTTP) — casos de
     correspondência/janela/exclusão.
  2. GET /api/redblue/metrics via TestClient (acrescentado na Task 4).

Segue o estilo de test_with_mock.py: script standalone, check()/[OK]/
[FALHOU], sys.exit(1) em caso de falha.

Correr:
    python test_redblue.py
"""

import sys

from attack_scenarios import SCENARIOS
from redblue_correlator import build_redblue_report

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def attack(scenario: str, target: str, timestamp: str, status: str = "launched") -> dict:
    return {"timestamp": timestamp, "scenario": scenario, "target": target, "tool": "x", "status": status, "details": {}}


def ml_result(timestamp: str, agent_ip: str, event_id: int, rule_flagged: bool = False, ml_is_anomaly: bool = False) -> dict:
    return {
        "timestamp": timestamp, "agent_ip": agent_ip, "windows_event_id": event_id,
        "rule_flagged": rule_flagged, "ml_is_anomaly": ml_is_anomaly,
    }


def run() -> None:
    # --- Caso 1: alerta correspondente dentro da janela -> detected=True ---
    attacks = [attack("brute_force_rdp", "192.168.1.20", "2026-09-14T10:00:00+00:00")]
    results = [ml_result("2026-09-14T10:00:10+00:00", "192.168.1.20", 4625, rule_flagged=True)]
    report = build_redblue_report(attacks, results, SCENARIOS)
    check("1 tentativa processada", len(report["attempts"]) == 1)
    a = report["attempts"][0]
    check("caso 1: detected=True", a["detected"] is True)
    check("caso 1: detected_by='rule'", a["detected_by"] == "rule")
    check("caso 1: mttd_seconds=10.0", a["mttd_seconds"] == 10.0)
    check("caso 1: mitre_technique vem do SCENARIOS", a["mitre_technique"] == "T1110")

    # --- Caso 2: sem qualquer alerta correspondente -> detected=False ---
    attacks2 = [attack("smb_enum", "192.168.1.21", "2026-09-14T11:00:00+00:00")]
    report2 = build_redblue_report(attacks2, [], SCENARIOS)
    a2 = report2["attempts"][0]
    check("caso 2: detected=False", a2["detected"] is False)
    check("caso 2: detected_by='none'", a2["detected_by"] == "none")
    check("caso 2: mttd_seconds=None", a2["mttd_seconds"] is None)

    # --- Caso 3: dois ataques próximos, janela do 1º cortada pelo 2º ---
    attacks3 = [
        attack("smb_enum", "192.168.1.22", "2026-09-14T12:00:00+00:00"),
        attack("blank_password_check", "192.168.1.22", "2026-09-14T12:01:00+00:00"),  # +60s
    ]
    # alerta de smb_enum chega aos +90s -> fora da janela do 1º ataque (cortada aos +60s pelo 2º)
    results3 = [ml_result("2026-09-14T12:01:30+00:00", "192.168.1.22", 5140)]
    report3 = build_redblue_report(attacks3, results3, SCENARIOS)
    check("caso 3: 1º ataque não detetado (janela cortada pelo 2º ataque)",
          report3["attempts"][0]["detected"] is False)

    # --- Caso 4: IP do agente não bate com o alvo -> não conta ---
    attacks4 = [attack("smb_enum", "192.168.1.23", "2026-09-14T13:00:00+00:00")]
    results4 = [ml_result("2026-09-14T13:00:05+00:00", "10.0.0.99", 5140)]
    report4 = build_redblue_report(attacks4, results4, SCENARIOS)
    check("caso 4: IP errado não conta como deteção", report4["attempts"][0]["detected"] is False)

    # --- Caso 5: Event ID fora de scenario.event_ids -> não conta ---
    attacks5 = [attack("smb_enum", "192.168.1.24", "2026-09-14T14:00:00+00:00")]
    results5 = [ml_result("2026-09-14T14:00:05+00:00", "192.168.1.24", 4625)]  # 4625 não é event_id de smb_enum
    report5 = build_redblue_report(attacks5, results5, SCENARIOS)
    check("caso 5: Event ID fora do cenário não conta", report5["attempts"][0]["detected"] is False)

    # --- Caso 6: status != "launched" -> not_executed, fora de attempts/overall ---
    attacks6 = [attack("smb_enum", "192.168.1.25", "2026-09-14T15:00:00+00:00", status="skipped")]
    report6 = build_redblue_report(attacks6, [], SCENARIOS)
    check("caso 6: entrada skipped vai para not_executed", len(report6["not_executed"]) == 1)
    check("caso 6: entrada skipped não entra em attempts", report6["attempts"] == [])
    check("caso 6: overall.total_attempts=0", report6["overall"]["total_attempts"] == 0)

    # --- Caso 7: nome de cenário desconhecido -> unknown_scenario ---
    attacks7 = [attack("cenario_inexistente", "192.168.1.26", "2026-09-14T16:00:00+00:00")]
    report7 = build_redblue_report(attacks7, [], SCENARIOS)
    check("caso 7: cenário desconhecido vai para unknown_scenario", len(report7["unknown_scenario"]) == 1)
    check("caso 7: cenário desconhecido não entra em attempts", report7["attempts"] == [])

    # --- Caso 8: entradas vazias -> estrutura vazia bem formada, nunca lança ---
    empty_report = build_redblue_report([], [], SCENARIOS)
    check("caso 8: attempts=[] com input vazio", empty_report["attempts"] == [])
    check("caso 8: by_scenario={} com input vazio", empty_report["by_scenario"] == {})
    check("caso 8: overall com zeros e mttd None", empty_report["overall"] == {
        "total_attempts": 0, "detected": 0, "coverage_rate": 0.0, "avg_mttd_seconds": None,
    })

    # --- Agregação por cenário ---
    check("by_scenario['brute_force_rdp'] agrega o caso 1 corretamente", report["by_scenario"]["brute_force_rdp"] == {
        "attempts": 1, "detected": 1, "detected_by_rule": 1, "detected_by_ml": 0, "detected_by_both": 0,
        "coverage_rate": 1.0, "avg_mttd_seconds": 10.0,
    })

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")
    sys.exit(0)


if __name__ == "__main__":
    run()
```

- [ ] **Step 2: Correr para confirmar que falha**

Run: `cd scripts && python test_redblue.py`
Expected: `ModuleNotFoundError: No module named 'redblue_correlator'`

- [ ] **Step 3: Implementar `scripts/redblue_correlator.py`**

```python
"""
Motor de correlação Red Team / Blue Team (Fase 11, Onda 1).

Cruza o log de ataques lançados pela VM Kali (attack_scenarios.py,
scripts/attack_log.jsonl) com os alertas Wazuh já classificados por
ml_anomalies.build_ml_anomalies_report() (regra + ML lado a lado), para
responder, por tentativa de ataque: foi detetado? por regra, por ML, por
ambos, ou por nenhum? em quanto tempo (MTTD)?

Módulo puro (como lifecycle.py/rbac.py/admin_activity.py/ml_anomalies.py):
não faz I/O nem chamadas de rede, só processa listas já obtidas. Nunca
lança exceção sobre dados malformados — entradas inválidas são ignoradas
ou desviadas para not_executed/unknown_scenario, nunca descartadas em
silêncio.
"""

from datetime import datetime, timedelta, timezone

DEFAULT_WINDOW_SECONDS = 300


def _parse_timestamp(raw_timestamp: str | None) -> datetime | None:
    """Mesma convenção do resto do projeto (lifecycle.py/feature_extractor.py):
    aceita o sufixo 'Z', assume UTC quando não há fuso indicado, devolve
    None em vez de lançar exceção para timestamps malformados."""
    if not raw_timestamp or not isinstance(raw_timestamp, str):
        return None
    normalized = raw_timestamp.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def build_redblue_report(
    attack_log: list[dict],
    ml_results: list[dict],
    scenarios: dict,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> dict:
    """Constrói o relatório de correlação Red vs Blue.

    Args:
        attack_log: entradas de scripts/attack_log.jsonl já lidas (ver
            feature_extractor.load_attack_log), cada uma com pelo menos
            timestamp/scenario/target/status.
        ml_results: a lista "results" já devolvida por
            ml_anomalies.build_ml_anomalies_report(), cada item com
            timestamp/agent_ip/windows_event_id/rule_flagged/ml_is_anomaly.
        scenarios: dict nome_do_cenário -> Scenario (ver
            attack_scenarios.SCENARIOS), usado para o event_ids e o
            mapeamento MITRE de cada cenário.
        window_seconds: duração máxima da janela de correlação por
            tentativa de ataque, cortada também pelo início da tentativa
            seguinte no log (o que vier primeiro).

    Returns:
        dict com attempts/by_scenario/overall/not_executed/unknown_scenario.
        Nunca lança exceção; entradas malformadas são ignoradas.
    """
    parsed_attacks: list[tuple[datetime, dict]] = []
    not_executed: list[dict] = []
    unknown_scenario: list[dict] = []
    for entry in attack_log or []:
        if not isinstance(entry, dict):
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
            continue
        parsed_attacks.append((ts, entry))

    parsed_attacks.sort(key=lambda item: item[0])

    parsed_alerts: list[tuple[datetime, dict]] = []
    for result in ml_results or []:
        ts = _parse_timestamp(result.get("timestamp"))
        if ts is None:
            continue
        parsed_alerts.append((ts, result))

    attempts: list[dict] = []
    for i, (ts, entry) in enumerate(parsed_attacks):
        scenario_name = entry["scenario"]
        scenario = scenarios[scenario_name]
        target = entry.get("target")

        window_end = ts + timedelta(seconds=window_seconds)
        if i + 1 < len(parsed_attacks):
            next_ts = parsed_attacks[i + 1][0]
            if next_ts < window_end:
                window_end = next_ts

        matches = [
            (alert_ts, result)
            for alert_ts, result in parsed_alerts
            if ts <= alert_ts <= window_end
            and result.get("agent_ip") == target
            and result.get("windows_event_id") in scenario.event_ids
        ]
        matches.sort(key=lambda item: item[0])

        detected = len(matches) > 0
        matched_by_rule = any(result.get("rule_flagged") for _, result in matches)
        matched_by_ml = any(result.get("ml_is_anomaly") for _, result in matches)
        if matched_by_rule and matched_by_ml:
            detected_by = "both"
        elif matched_by_rule:
            detected_by = "rule"
        elif matched_by_ml:
            detected_by = "ml"
        else:
            detected_by = "none"

        mttd_seconds = round((matches[0][0] - ts).total_seconds(), 2) if matches else None

        attempts.append({
            "scenario": scenario_name,
            "target": target,
            "timestamp": entry.get("timestamp"),
            "mitre_tactic": scenario.mitre_tactic,
            "mitre_technique": scenario.mitre_technique,
            "detected": detected,
            "detected_by": detected_by,
            "mttd_seconds": mttd_seconds,
            "matched_event_ids": sorted({result.get("windows_event_id") for _, result in matches}),
        })

    by_scenario: dict[str, dict] = {}
    for att in attempts:
        name = att["scenario"]
        bucket = by_scenario.setdefault(name, {
            "attempts": 0, "detected": 0,
            "detected_by_rule": 0, "detected_by_ml": 0, "detected_by_both": 0,
            "_mttd_values": [],
        })
        bucket["attempts"] += 1
        if att["detected"]:
            bucket["detected"] += 1
            bucket["_mttd_values"].append(att["mttd_seconds"])
        if att["detected_by"] == "rule":
            bucket["detected_by_rule"] += 1
        elif att["detected_by"] == "ml":
            bucket["detected_by_ml"] += 1
        elif att["detected_by"] == "both":
            bucket["detected_by_both"] += 1

    for bucket in by_scenario.values():
        mttd_values = bucket.pop("_mttd_values")
        bucket["coverage_rate"] = round(bucket["detected"] / bucket["attempts"], 4) if bucket["attempts"] else 0.0
        bucket["avg_mttd_seconds"] = round(sum(mttd_values) / len(mttd_values), 2) if mttd_values else None

    total_attempts = len(attempts)
    total_detected = sum(1 for a in attempts if a["detected"])
    all_mttd = [a["mttd_seconds"] for a in attempts if a["mttd_seconds"] is not None]
    overall = {
        "total_attempts": total_attempts,
        "detected": total_detected,
        "coverage_rate": round(total_detected / total_attempts, 4) if total_attempts else 0.0,
        "avg_mttd_seconds": round(sum(all_mttd) / len(all_mttd), 2) if all_mttd else None,
    }

    return {
        "attempts": attempts,
        "by_scenario": by_scenario,
        "overall": overall,
        "not_executed": not_executed,
        "unknown_scenario": unknown_scenario,
    }
```

- [ ] **Step 4: Correr o teste, confirmar que passa**

Run: `cd scripts && python test_redblue.py`
Expected: `[OK] Todos os testes passaram`, saída 0.

- [ ] **Step 5: Commit**

```bash
git add scripts/redblue_correlator.py scripts/test_redblue.py
git commit -m "feat: motor de correlacao Red vs Blue (redblue_correlator.py, Fase 11)"
```

---

## Task 4: Endpoint `GET /api/redblue/metrics`

**Files:**
- Modify: `scripts/main.py:57-58` (imports), `scripts/main.py:90-96` (nova env var), `scripts/main.py:649-651` (novo endpoint, entre `get_ml_anomalies` e `export_report`)
- Modify: `scripts/test_redblue.py` (acrescenta a Parte 2, testes via HTTP)

**Interfaces:**
- Consumes: `build_redblue_report` (Task 3), `agent_ip` em
  `ml_anomalies.build_ml_anomalies_report` (Task 2), `SCENARIOS` (Task 1),
  `feature_extractor.load_attack_log` (já existe).
- Produces: `GET /api/redblue/metrics` — endpoint HTTP, resposta JSON com
  o dict de `build_redblue_report` mais `"window_hours"`.

- [ ] **Step 1: Escrever os testes de endpoint que falham, acrescentados a `scripts/test_redblue.py`**

Substituir o corpo de `run()` em `scripts/test_redblue.py`: manter tudo o
que já lá está (Parte 1, da Task 3) e acrescentar antes do bloco final
`print()` / `if failures:`:

```python
    # =========================================================================
    # Parte 2: endpoint GET /api/redblue/metrics via HTTP (TestClient)
    # =========================================================================
    import json
    import os
    import tempfile
    from unittest.mock import AsyncMock

    from fastapi.testclient import TestClient

    os.environ.setdefault("SENTRYLENS_API_KEY", "chave-de-teste-nao-usar-em-producao")

    import main
    import ml_anomalies
    from feature_extractor import extract_features, vectorize
    from train_anomaly_model import train_model

    main.app.router.on_startup.clear()

    def alert(event_id: int, ts: str, agent_ip: str = "192.168.1.30") -> dict:
        return {
            "@timestamp": ts,
            "agent": {"name": "WIN-PC01", "ip": agent_ip},
            "rule": {"id": "1", "description": "x", "level": 5},
            "data": {"win": {"system": {"eventID": str(event_id)}, "eventdata": {"targetUserName": "convidado"}}},
            "full_log": "x",
        }

    mock_alerts = [alert(4625, f"2026-09-14T10:0{i}:00Z") for i in range(4)]
    feature_rows = extract_features(mock_alerts)
    vectors = vectorize(feature_rows)
    fake_model, fake_scaler = train_model(vectors, contamination=0.3, random_state=1)
    ml_anomalies._model = fake_model
    ml_anomalies._scaler = fake_scaler

    main.indexer_client.get_recent_alerts = AsyncMock(return_value=mock_alerts)
    client = TestClient(main.app, headers={"X-API-Key": os.environ["SENTRYLENS_API_KEY"]})

    # --- attack_log.jsonl com uma entrada que bate com os alertas mock ---
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False, encoding="utf-8") as tmp:
        tmp.write(json.dumps({
            "timestamp": "2026-09-14T10:00:00+00:00", "scenario": "brute_force_rdp",
            "target": "192.168.1.30", "tool": "hydra", "status": "launched", "details": {},
        }) + "\n")
        attack_log_path = tmp.name
    original_attack_log_path = main.ATTACK_LOG_PATH
    main.ATTACK_LOG_PATH = attack_log_path

    resp = client.get("/api/redblue/metrics")
    check("GET /api/redblue/metrics devolve 200", resp.status_code == 200)
    body = resp.json()
    check("overall.total_attempts == 1", body["overall"]["total_attempts"] == 1)
    check("overall.detected == 1 (alerta 4625 bate com brute_force_rdp)", body["overall"]["detected"] == 1)
    check("window_hours default é 168", body["window_hours"] == 168)

    # --- attack_log.jsonl ausente -> 200 com relatório vazio, nunca 404/500 ---
    main.ATTACK_LOG_PATH = os.path.join(tempfile.gettempdir(), "ficheiro-que-nao-existe-redblue.jsonl")
    resp_missing_log = client.get("/api/redblue/metrics")
    check("attack_log ausente -> 200", resp_missing_log.status_code == 200)
    check("attack_log ausente -> overall.total_attempts == 0", resp_missing_log.json()["overall"]["total_attempts"] == 0)
    main.ATTACK_LOG_PATH = original_attack_log_path
    os.unlink(attack_log_path)

    # --- modelo ML ausente -> 503 ---
    ml_anomalies._model = None
    ml_anomalies._scaler = None

    def _raise_not_found(model_dir=None):
        raise FileNotFoundError("modelo não encontrado (simulado)")

    original_load_model = ml_anomalies.load_model
    ml_anomalies.load_model = _raise_not_found
    resp_no_model = client.get("/api/redblue/metrics")
    check("sem modelo treinado devolve 503", resp_no_model.status_code == 503)
    ml_anomalies.load_model = original_load_model
    ml_anomalies._model = fake_model
    ml_anomalies._scaler = fake_scaler

    # --- erro no Indexer -> 502 ---
    main.indexer_client.get_recent_alerts = AsyncMock(side_effect=RuntimeError("Indexer em baixo (simulado)"))
    resp_indexer_error = client.get("/api/redblue/metrics")
    check("erro no Indexer devolve 502", resp_indexer_error.status_code == 502)
    main.indexer_client.get_recent_alerts = AsyncMock(return_value=mock_alerts)

    # --- sem X-API-Key -> 401 ---
    client_no_key = TestClient(main.app)
    resp_no_key = client_no_key.get("/api/redblue/metrics")
    check("sem X-API-Key devolve 401", resp_no_key.status_code == 401)
```

- [ ] **Step 2: Correr para confirmar que falha**

Run: `cd scripts && python test_redblue.py`
Expected: `AttributeError: module 'main' has no attribute 'ATTACK_LOG_PATH'`
(ou `404 Not Found` no primeiro pedido, se o import falhar de outra
forma) — o endpoint ainda não existe.

- [ ] **Step 3: Acrescentar a env var em `scripts/main.py`**

Em `scripts/main.py`, a seguir ao bloco `ML_MODEL_DIR` (linhas 88-90):

```python
# Diretório com isolation_forest.pkl + scaler.pkl (ver train_anomaly_model.py),
# usado pelo endpoint /api/ml-anomalies.
ML_MODEL_DIR = os.getenv("ML_MODEL_DIR", os.path.join(os.path.dirname(__file__), "models"))

# Caminho do log de ataques da VM Kali (ver attack_scenarios.py), usado
# pelo endpoint /api/redblue/metrics (Fase 11).
ATTACK_LOG_PATH = os.getenv("ATTACK_LOG_PATH", os.path.join(os.path.dirname(__file__), "attack_log.jsonl"))
```

- [ ] **Step 4: Acrescentar os imports em `scripts/main.py`**

Em `scripts/main.py`, os imports já trazem `import ml_anomalies` seguido
de `from admin_activity import build_admin_activity_report` (linhas
36-37) — inserir `from attack_scenarios import SCENARIOS` a seguir a
essa linha, mantendo ordem alfabética por bloco (mesmo estilo dos
imports já lá). Substituir:

```python
import ml_anomalies
from admin_activity import build_admin_activity_report
from compliance_evaluator import evaluate_alert_compliance, load_compliance_rules
```

por:

```python
import ml_anomalies
from admin_activity import build_admin_activity_report
from attack_scenarios import SCENARIOS
from compliance_evaluator import evaluate_alert_compliance, load_compliance_rules
```

E, no bloco de imports de `feature_extractor` (que ainda não existe em
`main.py` — acrescentar a linha nova, mantendo ordem alfabética com as
já existentes `from history_index import ...` / `from history_store import ...`):

```python
from event_catalog import classify_alert
from feature_extractor import load_attack_log
from history_index import index_alert, query_history_index, read_jsonl_at_offset
```

E, ao lado do `from rbac import build_privileges_report, load_rbac_baseline`
(linha 45), acrescentar a linha do novo módulo, mantendo ordem
alfabética:

```python
from rbac import build_privileges_report, load_rbac_baseline
from redblue_correlator import build_redblue_report
from report_generator import generate_html_report, render_compliance_section
```

- [ ] **Step 5: Implementar o endpoint em `scripts/main.py`**

Inserir depois do fim de `get_ml_anomalies` (a seguir à linha 649, antes
da definição de `export_report`):

```python
@app.get("/api/redblue/metrics", dependencies=_REQUIRE_API_KEY)
async def get_redblue_metrics(
    hours: int = Query(168, ge=1, le=168, description="Janela temporal em horas"),
    window_seconds: int = Query(300, ge=30, le=3600, description="Janela de correlação por ataque, em segundos"),
):
    """
    Motor de correlação Red vs Blue (Fase 11): cruza o log de ataques da
    VM Kali com os alertas já classificados por regra + ML, por cenário
    de ataque — cobertura, MTTD, e se foi detetado por regra, ML, ambos
    ou nenhum.
    """
    try:
        model, scaler = ml_anomalies.load_model(ML_MODEL_DIR)
    except FileNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e))

    try:
        raw_alerts = await indexer_client.get_recent_alerts(hours=hours, size=1000)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erro ao contactar Wazuh Indexer: {e}")

    ml_report = ml_anomalies.build_ml_anomalies_report(raw_alerts, model, scaler)
    attack_log = load_attack_log(ATTACK_LOG_PATH)
    report = build_redblue_report(attack_log, ml_report["results"], SCENARIOS, window_seconds=window_seconds)
    report["window_hours"] = hours
    return report
```

- [ ] **Step 6: Correr o teste, confirmar que passa**

Run: `cd scripts && python test_redblue.py`
Expected: `[OK] Todos os testes passaram`, saída 0.

- [ ] **Step 7: Correr toda a bateria de testes já existente, confirmar zero regressões**

Run:
```bash
cd scripts
python test_with_mock.py
python test_new_panels.py
python test_ml_anomalies.py
python test_feature_extractor.py
python test_auth.py
python test_redblue.py
```
Expected: todos terminam com `[OK] Todos os testes passaram` / saída 0.

- [ ] **Step 8: Commit**

```bash
git add scripts/main.py scripts/test_redblue.py
git commit -m "feat: endpoint GET /api/redblue/metrics (Fase 11, Onda 1)"
```

---

## Task 5: Documentação — `CLAUDE.md`, `README.md`, `.env.example`

**Files:**
- Modify: `CLAUDE.md` (secção "Arquitetura do backend" + lista de testes)
- Modify: `README.md:454` (tabela de testes) e a seguir a `README.md:1188`
  (nova subsecção de endpoint, a seguir a `GET /api/ml-anomalies`)
- Modify: `scripts/.env.example` (a seguir ao bloco `ML_MODEL_DIR`)

**Interfaces:** nenhuma — só documentação, sem código.

- [ ] **Step 1: `CLAUDE.md`**

Na secção "Arquitetura do backend (`scripts/`)", a seguir ao parágrafo
que descreve `admin_activity.py`, acrescentar:

```markdown
- `redblue_correlator.py` — motor de correlação Red vs Blue (Fase 11,
  Onda 1): cruza `attack_log.jsonl` (`attack_scenarios.py`) com os
  alertas já classificados por `ml_anomalies.build_ml_anomalies_report`
  (regra + ML), por cenário de ataque — cobertura, MTTD, detetado por
  regra/ML/ambos/nenhum. Função pura `build_redblue_report`, alimenta
  `GET /api/redblue/metrics`. Frontend (10ª aba) ainda não implementado —
  ver Onda 2.
```

Na lista de comandos de teste, acrescentar a linha:

```bash
python test_redblue.py           # /api/redblue/metrics (correlacao pura + endpoint)
```

- [ ] **Step 2: `README.md` — tabela de testes**

Em `README.md:454`, a seguir à linha
`python test_ml_anomalies.py      # /api/ml-anomalies`, acrescentar:

```
python test_redblue.py           # correlação Red vs Blue + /api/redblue/metrics
```

- [ ] **Step 3: `README.md` — nova subsecção de endpoint**

A seguir ao bloco `GET /api/ml-anomalies` (depois da linha 1188, `Erro →
503 se o modelo ainda não foi treinado...`), acrescentar:

```markdown
### `GET /api/redblue/metrics`
Fase 11 (Onda 1): cruza o log de ataques da VM Kali
(`scripts/attack_log.jsonl`) com os alertas já classificados por regra +
ML, por cenário de ataque — cobertura, MTTD (tempo até à primeira
deteção) e se foi apanhado por regra, por ML, por ambos ou por nenhum.
Frontend ainda não tem painel dedicado (Onda 2).

| Parâmetro | Tipo | Default | Descrição |
|---|---|---|---|
| `hours` | int (1–168) | 168 | Janela temporal para buscar alertas ao Indexer |
| `window_seconds` | int (30–3600) | 300 | Janela de correlação por tentativa de ataque, cortada pela tentativa seguinte no log |

```json
{
  "attempts": [
    {
      "scenario": "brute_force_rdp",
      "target": "192.168.1.169",
      "timestamp": "2026-09-14T15:34:27.258872+00:00",
      "mitre_tactic": "Credential Access",
      "mitre_technique": "T1110",
      "detected": true,
      "detected_by": "rule",
      "mttd_seconds": 8.4,
      "matched_event_ids": [4625]
    }
  ],
  "by_scenario": {
    "brute_force_rdp": {
      "attempts": 1, "detected": 1, "detected_by_rule": 1, "detected_by_ml": 0,
      "detected_by_both": 0, "coverage_rate": 1.0, "avg_mttd_seconds": 8.4
    }
  },
  "overall": {"total_attempts": 5, "detected": 4, "coverage_rate": 0.8, "avg_mttd_seconds": 12.1},
  "not_executed": [],
  "unknown_scenario": [],
  "window_hours": 168
}
```
Erro → `503` se o modelo ML ainda não foi treinado, `502` se o Wazuh
Indexer não responder. Ataques com `status` diferente de `launched`
(skipped/failed) entram em `not_executed`, nunca contam para as
métricas de cobertura.
```

- [ ] **Step 4: `.env.example`**

Em `scripts/.env.example`, a seguir ao bloco `ML_MODEL_DIR`, acrescentar:

```
# Caminho do log de ataques da VM Kali (ver attack_scenarios.py), usado
# pelo endpoint /api/redblue/metrics. Default: <pasta de scripts>/attack_log.jsonl
ATTACK_LOG_PATH=
```

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md README.md scripts/.env.example
git commit -m "docs: documenta o motor de correlacao Red vs Blue e /api/redblue/metrics (Fase 11)"
```

---

## Task 6: Registo de execução no Notion

**Files:** nenhum ficheiro do repositório — só a página Notion.

**Interfaces:** nenhuma.

- [ ] **Step 1: Confirmar os commits das Tasks 1-5**

Run: `git log --oneline -6`
Expected: 5 commits desta onda, do mais recente (`docs: documenta...`)
até ao mais antigo (`feat: acrescenta mapeamento MITRE...`).

- [ ] **Step 2: Apendar uma nova secção à página Notion**

Usar a ferramenta MCP do Notion (`notion-update-page` ou equivalente)
para apendar, no fim da página `page_id: 3caa99e6-526b-8111-89be-db8b6ffe765b`
(antes da secção "🥊 Fase 11 — Red vs Blue (planeado, não implementado)"
já existente, substituindo o texto dessa secção), um bloco no mesmo
formato usado pelas fases anteriores ("Registo de execução"):

- Título: `# 📝 Registo de execução — Fase 11 (Onda 1)`
- Nome dos 5 ficheiros criados/alterados por task, com o hash de cada
  commit (obtido no Step 1)
- Resumo do que foi validado pelos testes (12 casos: 8 da correlação
  pura + 4 do endpoint, mais as regressões das Tasks 1-2)
- Nota explícita: "Frontend (10ª aba, painéis Red Team/Blue Team/Manager)
  fica para a Onda 2 — ainda não implementado."
- Atualizar o título da secção existente "🥊 Fase 11 — Red vs Blue
  (planeado, não implementado)" para refletir que a Onda 1 (backend) está
  feita e só o frontend continua planeado.

- [ ] **Step 3: Confirmar a atualização**

Reler a página Notion (`notion-fetch` com o mesmo `page_id`) e confirmar
que a nova secção aparece e que a secção antiga foi atualizada, não
duplicada.
