"""
Testes de GET /api/metrics (R8): Indexer, modelo ML e base de incidentes
mockados. Sem laboratório Wazuh.

Correr (a partir de scripts/):
    python test_metrics_api.py
"""

import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

os.environ.setdefault("SENTRYLENS_API_KEY", "chave-de-teste-nao-usar-em-producao")

from fastapi.testclient import TestClient

import main
from incident_store import IncidentStore

main.app.router.on_startup.clear()

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


NOW = datetime.now(timezone.utc)
TARGET = "192.168.1.20"


def iso(delta_seconds: float) -> str:
    return (NOW + timedelta(seconds=delta_seconds)).isoformat()


RECENT_ATTACK = {"timestamp": iso(-3600), "scenario": "brute_force_rdp", "target": TARGET,
                 "tool": "hydra", "status": "launched", "details": {}}
OLD_ATTACK = {"timestamp": iso(-200 * 3600), "scenario": "brute_force_rdp", "target": TARGET,
              "tool": "hydra", "status": "launched", "details": {}}
ML_RESULT = {"timestamp": iso(-3600 + 20), "agent_ip": TARGET, "windows_event_id": 4625,
             "rule_flagged": True, "ml_is_anomaly": False}


def evidence(key: str, ts: str) -> dict:
    return {"kind": "wazuh_alert", "key": key, "ts": ts, "asset": TARGET, "severity": "high", "payload": {"k": key}}


def make_store(tmp: str) -> IncidentStore:
    store = IncidentStore(os.path.join(tmp, "i.sqlite3"))
    first = iso(-1800)
    inc_id = store.create_incident(evidence("alert:1", first), iso(-1790))
    store.set_status(inc_id, "INVESTIGATING", None, iso(-1740))   # 1.ª resposta = 60 s
    store.set_status(inc_id, "RESOLVED", None, iso(-1500))        # MTTR = 300 s
    store.create_incident(evidence("alert:2", iso(-900)), iso(-890))   # aberto
    return store


def wire(*, indexer_error: bool = False, model_missing: bool = False, store=None) -> None:
    main.indexer_client = MagicMock()
    if indexer_error:
        main.indexer_client.get_recent_alerts = AsyncMock(side_effect=RuntimeError("indexer em baixo"))
    else:
        main.indexer_client.get_recent_alerts = AsyncMock(return_value=[])
    if model_missing:
        def _missing(_dir):
            raise FileNotFoundError("sem modelo")
        main.ml_anomalies.load_model = _missing
    else:
        main.ml_anomalies.load_model = lambda _dir: (None, None)
    main.ml_anomalies.build_ml_anomalies_report = lambda alerts, model, scaler: {"results": [ML_RESULT]}
    main.load_attack_log = lambda _path: [RECENT_ATTACK, OLD_ATTACK]
    main.vm_ssh_client = None
    if store is not None:
        main.incident_store = store


def run() -> None:
    tmp = tempfile.TemporaryDirectory()
    client = TestClient(main.app, headers={"X-API-Key": os.environ["SENTRYLENS_API_KEY"]})
    client_no_key = TestClient(main.app)

    check("sem X-API-Key -> 401", client_no_key.get("/api/metrics").status_code == 401)
    check("hours=0 -> 422", client.get("/api/metrics?hours=0").status_code == 422)
    check("hours=169 -> 422", client.get("/api/metrics?hours=169").status_code == 422)

    # --- tudo disponível ---
    wire(store=make_store(tmp.name))
    r = client.get("/api/metrics")
    check("200 com tudo disponível", r.status_code == 200)
    body = r.json()
    check("ataque antigo (fora da janela) não conta: 1 lançado, 1 detetado",
          body["rate"]["launched"] == 1 and body["rate"]["detected"] == 1 and body["rate"]["false_negatives"] == 0)
    check("MTTD = 20 s", body["mttd"]["median_s"] == 20.0 and body["mttd"]["n"] == 1)
    check("MTTD de 1 amostra vem com small_sample", body["mttd"]["small_sample"] is True)
    check("MTTR = 300 s (1.ª evidência -> RESOLVED), 1 incidente aberto",
          body["mttr"]["n"] == 1 and body["mttr"]["median_s"] == 300.0 and body["mttr"]["open_count"] == 1)
    check("tempo até 1.ª resposta = 60 s", body["mttr"]["first_response"]["median_s"] == 60.0)
    check("cobertura: 1/1 cenário e 1/1 técnica", body["coverage"]["scenarios"]["covered"] == 1
          and body["coverage"]["techniques"]["total"] == 1)
    check("sem incidentes fechados: FP sem pct (amostra insuficiente)",
          body["rate"]["false_positives"]["closed_total"] == 0 and body["rate"]["false_positives"]["pct"] is None)
    check("window_hours = 168 por omissão", body["window_hours"] == 168)

    # --- Indexer em baixo: isola ---
    wire(indexer_error=True, store=make_store(tempfile.mkdtemp()))
    r = client.get("/api/metrics")
    body = r.json()
    check("Indexer em baixo -> 200 (nunca 5xx)", r.status_code == 200)
    check("Indexer em baixo: mttd/coverage/rate source_unavailable",
          all(body[k]["reason"] == "source_unavailable" for k in ("mttd", "coverage", "rate")))
    check("Indexer em baixo: MTTR continua a responder", body["mttr"]["available"] is True and body["mttr"]["n"] == 1)
    check("o erro não vaza texto de exceção", "indexer em baixo" not in r.text)

    # --- modelo ML em falta: isola ---
    wire(model_missing=True, store=make_store(tempfile.mkdtemp()))
    r = client.get("/api/metrics")
    check("modelo ML em falta -> 200 e source_unavailable no Red vs Blue",
          r.status_code == 200 and r.json()["mttd"]["reason"] == "source_unavailable")

    # --- base de incidentes em baixo: isola ---
    broken = MagicMock()
    broken.list_for_metrics = MagicMock(side_effect=sqlite3.OperationalError("db partida"))
    wire(store=broken)
    r = client.get("/api/metrics")
    body = r.json()
    check("base de incidentes em baixo -> 200", r.status_code == 200)
    check("base em baixo: MTTR e FP source_unavailable",
          body["mttr"]["reason"] == "source_unavailable"
          and body["rate"]["false_positives"]["reason"] == "source_unavailable")
    check("base em baixo: taxa de deteção continua a responder", body["rate"]["launched"] == 1)
    check("o erro não vaza texto de exceção (SQLite)", "db partida" not in r.text)


if __name__ == "__main__":
    run()
    if failures:
        print(f"\n{len(failures)} caso(s) falharam.")
        sys.exit(1)
    print("\nTodos os casos passaram.")
