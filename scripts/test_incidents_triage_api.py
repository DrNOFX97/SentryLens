"""
Testes de POST /api/incidents/{id}/triage (JEV, experimental, opt-in) com
TestClient, SQLite temporária e jev_client.triage mockado — sem rede.

Correr (a partir de scripts/):
    python test_incidents_triage_api.py
"""

import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

os.environ.setdefault("SENTRYLENS_API_KEY", "test-key-triage")
for var in ("SENTRYLENS_JEV_ENABLED", "TYPESAFE_API_KEY"):
    os.environ.pop(var, None)

from fastapi.testclient import TestClient

import incident_ingest
import jev_client
import main
from attack_scenarios import SCENARIOS
from incident_store import IncidentStore

main.app.router.on_startup.clear()
client = TestClient(main.app)
HEADERS = {"X-API-Key": os.environ["SENTRYLENS_API_KEY"]}
failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def raw(alert_id: str, seconds_ago: int, event_id: int) -> dict:
    ts = (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat()
    return {"_id": alert_id, "@timestamp": ts, "agent": {"name": "srv", "ip": "192.168.1.169"},
            "rule": {"id": "1", "level": 5, "description": "r"}, "full_log": "x",
            "data": {"win": {"system": {"eventID": str(event_id)}}}}


def run() -> None:
    tmp = tempfile.TemporaryDirectory()
    log_path = os.path.join(tmp.name, "attack_log.jsonl")
    open(log_path, "w", encoding="utf-8").close()
    main.ATTACK_LOG_PATH = log_path
    main.incident_store = IncidentStore(os.path.join(tmp.name, "i.sqlite3"))
    incident_ingest.ingest_raw_alerts(main.incident_store, [raw("a1", 120, 4625), raw("a2", 60, 4625)], log_path, SCENARIOS)
    inc_id = client.get("/api/incidents", headers=HEADERS).json()["incidents"][0]["id"]
    url = f"/api/incidents/{inc_id}/triage"

    check("sem X-API-Key -> 401", client.post(url).status_code == 401)

    triage = AsyncMock(return_value={"ok": True, "model": "jev-1.13.0", "answers": {"is_compromise": {"probability": 0.6}}})
    original = jev_client.triage
    jev_client.triage = triage
    try:
        r = client.post(url, headers=HEADERS)
        check("desligado por omissão -> 503 jev_disabled", r.status_code == 503 and r.json()["detail"] == "jev_disabled")
        check("desligado: nunca chama o JEV", triage.await_count == 0)

        os.environ["SENTRYLENS_JEV_ENABLED"] = "true"
        os.environ["TYPESAFE_API_KEY"] = "k"
        r = client.post("/api/incidents/INC-INEXISTENTE/triage", headers=HEADERS)
        check("incidente inexistente -> 404, sem chamar o JEV", r.status_code == 404 and triage.await_count == 0)

        r = client.post(url, headers=HEADERS)
        body = r.json()
        check("ligado -> 200 consultivo com respostas", r.status_code == 200 and body["advisory"] is True
              and body["incident_id"] == inc_id and body["answers"]["is_compromise"]["probability"] == 0.6)
        check("resposta sem campo 'ok' nem payloads", "ok" not in body and "payload" not in str(body))
        check("JEV chamado 1 vez com o incidente", triage.await_count == 1 and triage.await_args.args[0]["id"] == inc_id)

        before = client.get(f"/api/incidents/{inc_id}", headers=HEADERS).json()
        triage.return_value = {"ok": False, "error": "jev_unreachable"}
        r = client.post(url, headers=HEADERS)
        check("falha do JEV -> 502 com código estável", r.status_code == 502 and r.json()["detail"] == "jev_unreachable")
        after = client.get(f"/api/incidents/{inc_id}", headers=HEADERS).json()
        check("triagem nunca altera o incidente", before["status"] == after["status"] and before["timeline"] == after["timeline"])
    finally:
        jev_client.triage = original
        os.environ.pop("SENTRYLENS_JEV_ENABLED", None)
        os.environ.pop("TYPESAFE_API_KEY", None)


run()
sys.exit(1 if failures else 0)
