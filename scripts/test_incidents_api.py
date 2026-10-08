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
