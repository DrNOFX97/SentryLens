"""
Testes do ciclo e do loop de vaccines (Phase 13): main._run_vaccine_cycle,
main._vaccine_loop, o estado vaccine_ingest.VaccineLoopState e o bloco
`generator` de GET /api/vaccines. Indexer, modelo ML e bases mockados/
temporários, sem laboratório Wazuh. Só IPs de documentação.

Correr (a partir de scripts/):
    python test_vaccine_ingest.py
"""

import asyncio
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

os.environ.setdefault("SENTRYLENS_API_KEY", "test-key-vaccine-ingest")

from fastapi.testclient import TestClient

import incident_ingest
import main
import vaccine_ingest
from attack_scenarios import SCENARIOS
from incident_store import IncidentStore
from vaccine_store import VaccineStore

# Guardar os handlers de arranque ANTES de os limpar (para provar o registo do loop).
STARTUP_HANDLERS = list(main.app.router.on_startup)
main.app.router.on_startup.clear()
client = TestClient(main.app)
HEADERS = {"X-API-Key": os.environ["SENTRYLENS_API_KEY"]}

ASSET = "192.0.2.10"
OTHER = "203.0.113.7"
NOW = datetime.now(timezone.utc)

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def ts(seconds_ago: int) -> str:
    return (NOW - timedelta(seconds=seconds_ago)).isoformat()


def ml_row(seconds_ago: int, event_id: int, rule: bool, ml: bool, ip: str = ASSET) -> dict:
    return {"timestamp": ts(seconds_ago), "agent_ip": ip, "windows_event_id": event_id,
            "rule_flagged": rule, "ml_is_anomaly": ml}


def raw_alert(alert_id: str, seconds_ago: int, event_id: int) -> dict:
    return {"_id": alert_id, "@timestamp": ts(seconds_ago), "agent": {"name": "LAB1", "ip": ASSET},
            "rule": {"id": "1", "level": 5, "description": "regra"}, "full_log": "x",
            "data": {"win": {"system": {"eventID": str(event_id)}}}}


# Log "moderno" (as mesmas fixtures de test_attack_registry.py): ataque 1 detected,
# 2 not_detected, 3 partial, 4 (há 500 s) ainda não assentou.
ATTACKS = [
    {"id": 1, "scenario": "brute_force_rdp", "target": ASSET, "timestamp": ts(3000), "status": "launched",
     "technique": "T1110", "tool": "hydra", "operator": "alice", "source": "203.0.113.50"},
    {"id": 2, "scenario": "smb_enum", "target": ASSET, "timestamp": ts(2000), "status": "launched",
     "technique": "T1087", "tool": "netexec"},
    {"id": 3, "scenario": "lateral_movement_schtasks", "target": ASSET, "timestamp": ts(1000), "status": "launched",
     "technique": "T1053", "tool": "psexec"},
    {"id": 4, "scenario": "account_lockout_spray", "target": OTHER, "timestamp": ts(500), "status": "launched",
     "expected": ["network", "bogus"]},
    {"id": 5, "scenario": "smb_enum", "target": ASSET, "timestamp": ts(400), "status": "failed"},
    {"id": 6, "scenario": "nao_existe", "target": ASSET, "timestamp": ts(300), "status": "launched"},
]
ML_RESULTS = [
    ml_row(2980, 4625, True, True),
    ml_row(970, 4672, True, False),
]


def write_log(path: str, lines: list) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        for line in lines:
            handle.write((line if isinstance(line, str) else json.dumps(line)) + "\n")


def wire(tmp: str) -> tuple[str, str]:
    """Liga a app a um attack log, uma base de incidentes e um store de vaccines
    temporários, com Indexer e modelo ML falsos. Devolve (log, caminho do store)."""
    log_path = os.path.join(tmp, "attack_log.jsonl")
    vaccines_path = os.path.join(tmp, "v.sqlite3")
    write_log(log_path, ATTACKS)
    main.ATTACK_LOG_PATH = log_path
    main.incident_store = IncidentStore(os.path.join(tmp, "i.sqlite3"))
    main.vaccine_store = VaccineStore(vaccines_path)
    main.vaccine_loop_state = vaccine_ingest.VaccineLoopState()
    main.vm_ssh_client = None
    main.ml_anomalies.load_model = lambda _dir: (object(), object())
    main.ml_anomalies.build_ml_anomalies_report = lambda alerts, model, scaler: {"results": ML_RESULTS}
    main.indexer_client.get_recent_alerts = AsyncMock(return_value=[{"x": 1}])
    return log_path, vaccines_path


def seed_incident(log_path: str) -> None:
    incident_ingest.ingest_raw_alerts(main.incident_store, [raw_alert("a3", 970, 4672)], log_path, SCENARIOS)


def get_list() -> dict:
    return client.get("/api/vaccines", headers=HEADERS).json()


class Saved:
    """Guarda o que os testes substituem em `main` e repõe-no no fim."""

    NAMES = [(main.ml_anomalies, "load_model"), (main.ml_anomalies, "build_ml_anomalies_report"),
             (main.indexer_client, "get_recent_alerts"),
             (main, "_run_vaccine_cycle"), (main, "VACCINE_INTERVAL_SECONDS"), (main, "load_attack_log"),
             (main, "incident_store"), (main, "vaccine_store"), (main, "vaccine_loop_state"),
             (main, "build_vaccine_candidates"), (main, "ATTACK_ALERTS_SIZE"), (main, "VACCINE_WINDOW_HOURS"),
             (main, "VACCINE_SETTLE_SECONDS"), (main, "ATTACK_LOG_PATH"), (main, "vm_ssh_client")]

    def __enter__(self):
        self.values = [(obj, name, getattr(obj, name)) for obj, name in self.NAMES]
        return self

    def __exit__(self, *exc):
        for obj, name, value in self.values:
            setattr(obj, name, value)
        return False


async def _start_and_cancel() -> tuple[object, object]:
    """Arranca o loop pelo handler de startup, deixa correr e cancela."""
    await main._start_vaccine_loop()
    task = main.app.state.vaccine_task
    await asyncio.sleep(0.3)
    state_after_run = main.vaccine_loop_state.snapshot()
    task.cancel()
    try:
        await asyncio.wait_for(task, timeout=2)
    except asyncio.CancelledError:
        pass
    return task, state_after_run


async def _run_resilient_loop() -> int:
    calls = {"n": 0}

    async def flaky():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom C:\\segredo")

    main._run_vaccine_cycle = flaky
    task = asyncio.create_task(main._vaccine_loop())
    await asyncio.sleep(0.3)
    task.cancel()
    try:
        await asyncio.wait_for(task, timeout=2)
    except asyncio.CancelledError:
        pass
    return calls["n"]


def run_tracer() -> None:
    with Saved():
        tmp = tempfile.TemporaryDirectory()
        try:
            log_path, vaccines_path = wire(tmp.name)

            # --- estado novo ---
            body = get_list()
            check("estado novo: generator never_run com todos os campos None",
                  body["generator"] == {"status": "never_run", "error_code": None, "last_run_at": None,
                                        "last_success_at": None, "alerts_truncated": None, "counts": None})
            check("estado novo: set(generator) == GENERATOR_KEYS", set(body["generator"]) == vaccine_ingest.GENERATOR_KEYS)

            # --- ciclo feliz ---
            seed_incident(log_path)
            result = asyncio.run(main._run_vaccine_cycle())
            body = get_list()
            gen = body["generator"]
            check("ciclo feliz: o ciclo devolve ok", result["status"] == "ok")
            check("ciclo feliz: generator ok, sem error_code, last_run_at == last_success_at (str)",
                  gen["status"] == "ok" and gen["error_code"] is None and isinstance(gen["last_run_at"], str)
                  and gen["last_run_at"] == gen["last_success_at"])
            check("ciclo feliz: counts e alerts_truncated",
                  gen["counts"] == {"inserted": 2, "existing": 0, "rejected": 0, "pending_settle": 1, "outside_window": 0}
                  and gen["alerts_truncated"] is False)
            ids_before = [v["id"] for v in body["vaccines"]]
            check("ciclo feliz: vaccines vac-bd617cce8054 e vac-5fe3861aa2a3",
                  ids_before == ["vac-bd617cce8054", "vac-5fe3861aa2a3"])
            vaccines_before = body["vaccines"]
            first_success = gen["last_success_at"]

            # --- Indexer em baixo ---
            main.indexer_client.get_recent_alerts = AsyncMock(side_effect=RuntimeError("segredo-interno C:\\caminho\\x"))
            try:
                down = asyncio.run(main._run_vaccine_cycle())
                raised = False
            except Exception:
                raised = True
                down = {}
            check("Indexer em baixo: o ciclo não levanta", not raised)
            check("Indexer em baixo: resultado error/indexer_unavailable", down.get("error_code") == "indexer_unavailable")
            r = client.get("/api/vaccines", headers=HEADERS)
            gen = r.json()["generator"]
            check("Indexer em baixo: GET 200, generator error/indexer_unavailable, counts None",
                  r.status_code == 200 and gen["status"] == "error" and gen["error_code"] == "indexer_unavailable"
                  and gen["counts"] is None)
            check("Indexer em baixo: last_success_at inalterado, last_run_at diferente",
                  gen["last_success_at"] == first_success and gen["last_run_at"] != first_success)
            check("Indexer em baixo: a lista de vaccines é igual", r.json()["vaccines"] == vaccines_before)
            check("Indexer em baixo: sem segredo-interno, caminho ou Traceback na resposta",
                  not any(w in r.text for w in ("segredo-interno", "caminho", "Traceback")))
        finally:
            tmp.cleanup()

    # --- registo no arranque ---
    check("main._start_vaccine_loop está nos handlers de startup", main._start_vaccine_loop in STARTUP_HANDLERS)

    # --- arranque real e cancelamento ---
    with Saved():
        tmp = tempfile.TemporaryDirectory()
        try:
            log_path, _ = wire(tmp.name)
            seed_incident(log_path)
            main.VACCINE_INTERVAL_SECONDS = 0.05
            task, state = asyncio.run(_start_and_cancel())
            check("arranque: app.state.vaccine_task existe", getattr(main.app.state, "vaccine_task", None) is task)
            check("arranque: o loop correu um ciclo (status ok, last_run_at preenchido)",
                  state["status"] == "ok" and state["last_run_at"] is not None)
            check("cancelamento: a task fica cancelled() (CancelledError não é engolida)", task.cancelled())
        finally:
            tmp.cleanup()

    # --- resiliência ---
    with Saved():
        main.vaccine_loop_state = vaccine_ingest.VaccineLoopState()
        main.VACCINE_INTERVAL_SECONDS = 0.05
        calls = asyncio.run(_run_resilient_loop())
        snap = main.vaccine_loop_state.snapshot()
        check("resiliência: o loop continuou depois da falha (>= 2 chamadas em 0.3 s)", calls >= 2)
        check("resiliência: estado error/unexpected_error sem texto da exceção",
              snap["status"] == "error" and snap["error_code"] == "unexpected_error"
              and "segredo" not in json.dumps(snap))


if __name__ == "__main__":
    run_tracer()
    print()
    if failures:
        print(f"{len(failures)} verificação(ões) falharam:")
        for label in failures:
            print(f"  - {label}")
        sys.exit(1)
    print("Todas as verificações passaram.")
