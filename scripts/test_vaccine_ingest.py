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
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

os.environ.setdefault("SENTRYLENS_API_KEY", "test-key-vaccine-ingest")

from fastapi.testclient import TestClient

import incident_ingest
import main
import vaccine_engine
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


def snapshot_rows(path: str) -> list[tuple]:
    """(id, payload) de todas as linhas do store, ordenadas, lidas do ficheiro."""
    if not os.path.exists(path):
        return []
    conn = sqlite3.connect(path)
    try:
        return sorted(conn.execute("SELECT id, payload FROM vaccines").fetchall())
    finally:
        conn.close()


def failure_scenario(label: str, expected_code: str, setup) -> None:
    """Ciclo feliz (2 linhas) e depois um ciclo que falha: linhas intactas e código estável."""
    with Saved():
        tmp = tempfile.TemporaryDirectory()
        try:
            log_path, vaccines_path = wire(tmp.name)
            seed_incident(log_path)
            asyncio.run(main._run_vaccine_cycle())
            before = snapshot_rows(vaccines_path)
            check(f"{label}: o ciclo feliz grava 2 linhas", len(before) == 2)
            setup()
            try:
                result = asyncio.run(main._run_vaccine_cycle())
                raised = False
            except Exception:
                raised = True
                result = {}
            snap = main.vaccine_loop_state.snapshot()
            dumped = json.dumps(snap)
            check(f"{label}: o ciclo não levanta", not raised)
            check(f"{label}: estado error/{expected_code}",
                  snap["status"] == "error" and snap["error_code"] == expected_code
                  and result.get("error_code") == expected_code)
            check(f"{label}: sem segredo/partida/Traceback no estado",
                  not any(w in dumped for w in ("segredo", "partida", "Traceback")))
            check(f"{label}: as 2 linhas continuam iguais e nenhuma nova", snapshot_rows(vaccines_path) == before)
        finally:
            tmp.cleanup()


def run_failures() -> None:
    def no_model():
        def _raise(_dir):
            raise FileNotFoundError("C:\\segredo\\modelo.pkl")
        main.ml_anomalies.load_model = _raise
    failure_scenario("modelo ML em falta", "ml_model_unavailable", no_model)

    for exc in (PermissionError("C:\\segredo\\attack_log.jsonl"),
                UnicodeDecodeError("utf-8", b"\xff", 0, 1, "segredo")):
        def unreadable(_exc=exc):
            def _raise(_path):
                raise _exc
            main.load_attack_log = _raise
        failure_scenario(f"attack log ilegível ({type(exc).__name__})", "attack_log_unreadable", unreadable)

    def broken_incidents():
        broken = MagicMock()
        broken.list_incidents.side_effect = sqlite3.OperationalError("db incidentes partida")
        main.incident_store = broken
        main.VACCINE_SETTLE_SECONDS = 300  # há algo novo para gravar (ataque 4)
    failure_scenario("base de incidentes em baixo", "incidents_unavailable", broken_incidents)

    def broken_store():
        broken = MagicMock()
        broken.upsert_batch.side_effect = sqlite3.OperationalError("db partida C:\\segredo")
        main.vaccine_store = broken
        main.VACCINE_SETTLE_SECONDS = 300
    failure_scenario("escrita no store a falhar", "store_unavailable", broken_store)

    def boom():
        def _raise(*_args, **_kwargs):
            raise KeyError("segredo")
        main.build_vaccine_candidates = _raise
    failure_scenario("exceção inesperada", "unexpected_error", boom)

    # incidentes em baixo desde o início: vac-13daa7f56fa1 nunca é gravada
    with Saved():
        tmp = tempfile.TemporaryDirectory()
        try:
            _log, vaccines_path = wire(tmp.name)
            broken = MagicMock()
            broken.list_incidents.side_effect = sqlite3.OperationalError("db incidentes partida")
            main.incident_store = broken
            main.VACCINE_SETTLE_SECONDS = 300
            asyncio.run(main._run_vaccine_cycle())
            check("incidentes em baixo: nada gravado (vac-13daa7f56fa1 ausente)", snapshot_rows(vaccines_path) == [])
        finally:
            tmp.cleanup()

    # --- attack log vazio: no_data sem chamar o Indexer ---
    with Saved():
        tmp = tempfile.TemporaryDirectory()
        try:
            wire(tmp.name)
            main.load_attack_log = lambda _path: []
            result = asyncio.run(main._run_vaccine_cycle())
            snap = main.vaccine_loop_state.snapshot()
            check("log vazio: no_data, error_code None, counts None",
                  result["status"] == "no_data" and snap["status"] == "no_data" and snap["error_code"] is None
                  and snap["counts"] is None)
            check("log vazio: o Indexer não foi chamado", main.indexer_client.get_recent_alerts.await_count == 0)
        finally:
            tmp.cleanup()

    # --- truncagem (A3) ---
    with Saved():
        tmp = tempfile.TemporaryDirectory()
        try:
            log_path, vaccines_path = wire(tmp.name)
            seed_incident(log_path)
            main.ATTACK_ALERTS_SIZE = 1
            result = asyncio.run(main._run_vaccine_cycle())
            ids = [row[0] for row in snapshot_rows(vaccines_path)]
            snap = main.vaccine_loop_state.snapshot()
            check("truncagem: status ok e alerts_truncated True",
                  result["status"] == "ok" and snap["alerts_truncated"] is True)
            check("truncagem: só vac-bd617cce8054 gravada (o ataque 2 fica unknown)", ids == ["vac-bd617cce8054"])
        finally:
            tmp.cleanup()

    # --- janela (A4) ---
    old_attack = {"id": 7, "scenario": "smb_enum", "target": ASSET, "timestamp": ts(7200), "status": "launched"}
    for hours in (1, 168):
        with Saved():
            tmp = tempfile.TemporaryDirectory()
            try:
                log_path, _vaccines_path = wire(tmp.name)
                write_log(log_path, ATTACKS + [old_attack])
                seed_incident(log_path)
                main.VACCINE_WINDOW_HOURS = hours
                asyncio.run(main._run_vaccine_cycle())
                snap = main.vaccine_loop_state.snapshot()
                attack_ids = {v["origin"]["attack_id"] for v in get_list()["vaccines"]}
                if hours == 1:
                    check("janela 1 h: counts.outside_window == 1", snap["counts"]["outside_window"] == 1)
                    check("janela 1 h: nenhuma vaccine do ataque 7", 7 not in attack_ids)
                else:
                    check("janela 168 h: a vaccine do ataque 7 é gravada", 7 in attack_ids)
            finally:
                tmp.cleanup()

    # --- estabilização (A2) ---
    with Saved():
        tmp = tempfile.TemporaryDirectory()
        try:
            log_path, _vaccines_path = wire(tmp.name)
            seed_incident(log_path)
            main.VACCINE_SETTLE_SECONDS = 300
            asyncio.run(main._run_vaccine_cycle())
            snap = main.vaccine_loop_state.snapshot()
            ids = {v["id"] for v in get_list()["vaccines"]}
            check("settle 300 s: vac-13daa7f56fa1 gravada e pending_settle == 0",
                  "vac-13daa7f56fa1" in ids and snap["counts"]["pending_settle"] == 0)
        finally:
            tmp.cleanup()


def make_attack(attack_id: int) -> dict:
    """Dict com a mesma forma de um ataque de build_attack_registry (copiado de test_vaccine_engine.py)."""
    return {
        "id": attack_id, "duplicate_id": False, "timestamp": ts(100), "scenario": "smb_enum",
        "mitre_tactic": "Discovery", "mitre_technique": "T1135",
        "expected": {"detection": ["rule"], "source": "scenario_default", "event_ids": [5140, 5145]},
        "actual": {"verdict": "not_detected", "correlation_reason": None, "achieved": []},
        "evidence": {"matched_event_ids": [], "matched_alert_count": 0, "network_detection_types": [],
                     "incident_count": 0},
        "incidents": [],
    }


def run_selection() -> None:
    parse = main.incident_engine_parse
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)

    def at(seconds_ago: int, attack_id=1) -> dict:
        return {"id": attack_id, "timestamp": (now - timedelta(seconds=seconds_ago)).isoformat()}

    def select(attacks):
        return vaccine_ingest.select_attack_ids(attacks, now, 1, 600, parse)

    out = select([at(600, 1), at(599, 2), {"id": 3, "timestamp": (now + timedelta(seconds=60)).isoformat()},
                  at(3600, 4), at(3601, 5)])
    check("select: now-600 s assentou", 1 in out["settled"] and 1 not in out["pending_settle"])
    check("select: now-599 s pending_settle", 2 in out["pending_settle"] and 2 not in out["settled"])
    check("select: timestamp no futuro pending_settle", 3 in out["pending_settle"])
    check("select: now-3600 s (limite da janela) assentou", 4 in out["settled"])
    check("select: now-3601 s fora da janela (em nenhum)", 5 not in out["settled"] and 5 not in out["pending_settle"])
    stamp = at(100)["timestamp"]
    bad = select([{"id": None, "timestamp": stamp}, {"id": True, "timestamp": stamp},
                  {"id": "3", "timestamp": stamp}, {"id": 8, "timestamp": "nao-e-data"},
                  "texto", 42, None, at(700, 9)])
    check("select: id None/True/'3' e timestamp inválido ficam fora; não-dict ignorado sem exceção",
          bad["settled"] == {9} and bad["pending_settle"] == set())

    def env(value):
        environ = {} if value is None else {"X": value}
        return vaccine_ingest.env_int(environ, "X", 300, 30, 86400)

    check("env_int: ausente -> omissão", env(None) == 300)
    check("env_int: inválidos ('abc', '', '0', '-5', '99999999', '1.5') -> omissão",
          all(env(v) == 300 for v in ("abc", "", "0", "-5", "99999999", "1.5")))
    check("env_int: '120' -> 120; '30' e '86400' aceites", env("120") == 120 and env("30") == 30 and env("86400") == 86400)

    # --- persist_vaccines: válida, adulterada, pending, fora da janela (VAC-05) ---
    registry = {"attacks": [make_attack(i) for i in (2, 3, 4)]}
    correlation = {"available": True, "error_code": None, "alerts_fetched": 1, "alerts_truncated": False}
    vaccines = vaccine_engine.build_vaccine_candidates(registry, correlation)["vaccines"]
    by_attack = {v["origin"]["attack_id"]: v for v in vaccines}
    tampered = json.loads(json.dumps(by_attack[2]))
    tampered["command"] = "net user x /add"
    tmp = tempfile.TemporaryDirectory()
    try:
        store_path = os.path.join(tmp.name, "p.sqlite3")
        store = VaccineStore(store_path)
        counts = vaccine_ingest.persist_vaccines(
            store, [by_attack[2], tampered, by_attack[3], by_attack[4]],
            {"settled": {2}, "pending_settle": {3}}, now.isoformat())
        check("persist: inserted 1, rejected 1, pending_settle 1, outside_window 1",
              counts == {"inserted": 1, "existing": 0, "rejected": 1, "pending_settle": 1, "outside_window": 1})
        rows = snapshot_rows(store_path)
        check("persist: o payload gravado não tem a chave 'command'",
              len(rows) == 1 and "command" not in rows[0][1] and "net user" not in rows[0][1])
    finally:
        tmp.cleanup()

    # --- VaccineLoopState ---
    state = vaccine_ingest.VaccineLoopState()
    state.record("t1", "error", "texto livre C:\\segredo")
    check("state: error_code livre vira unexpected_error",
          state.snapshot()["error_code"] == "unexpected_error" and "segredo" not in json.dumps(state.snapshot()))
    state.record("t2", "weird")
    check("state: status desconhecido vira error", state.snapshot()["status"] == "error")
    state.record("t3", "ok", counts={"inserted": 1, "existing": 0, "rejected": 0, "pending_settle": 0,
                                     "outside_window": 0, "extra": 9}, alerts_truncated="sim")
    snap = state.snapshot()
    check("state: ok guarda só COUNT_KEYS e alerts_truncated não-bool vira None",
          set(snap["counts"]) == set(vaccine_ingest.COUNT_KEYS) and snap["alerts_truncated"] is None
          and snap["last_success_at"] == "t3")
    snap["counts"]["inserted"] = 99
    snap["status"] = "x"
    check("state: alterar o snapshot não muda o estado",
          state.snapshot()["counts"]["inserted"] == 1 and state.snapshot()["status"] == "ok")
    state.record("t4", "error", "store_unavailable")
    check("state: error mantém last_success_at e limpa counts",
          state.snapshot()["last_success_at"] == "t3" and state.snapshot()["counts"] is None
          and state.snapshot()["error_code"] == "store_unavailable")


if __name__ == "__main__":
    run_tracer()
    run_failures()
    run_selection()
    print()
    if failures:
        print(f"{len(failures)} verificação(ões) falharam:")
        for label in failures:
            print(f"  - {label}")
        sys.exit(1)
    print("Todas as verificações passaram.")
