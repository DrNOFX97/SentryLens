"""
Testes de GET /api/detections (R7): vista unificada dos 3 detetores
(regra/Wazuh, ML, rede) via detection_event.py. As 3 fontes são mockadas —
Indexer via AsyncMock (como test_with_mock.py), modelo ML treinado em
memória sobre os próprios alertas mock (como test_ml_anomalies.py),
network_detection_buffer populado manualmente (como test_network_soc.py).

Correr (a partir de scripts/):
    python test_detections_api.py
"""

import os
import sys
from unittest.mock import AsyncMock, MagicMock

os.environ.setdefault("SENTRYLENS_API_KEY", "chave-de-teste-nao-usar-em-producao")

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


ASSET = "192.168.1.5"


def alert(event_id: int, ts: str, user: str = "jsilva", ip: str = "203.0.113.50") -> dict:
    return {
        "@timestamp": ts,
        "agent": {"name": "WIN-PC01", "ip": ASSET},
        "rule": {"id": "1", "description": "x", "level": 5},
        "data": {"win": {"system": {"eventID": str(event_id)}, "eventdata": {"targetUserName": user, "ipAddress": ip}}},
        "full_log": "x",
    }


def detection(type_="port_scan", src_ip="192.168.1.170", dst_ip="192.168.1.20", timestamp="2026-10-07T10:00:00+00:00") -> dict:
    return {"type": type_, "src_ip": src_ip, "dst_ip": dst_ip, "timestamp": timestamp, "detail": {}}


MOCK_ALERTS = (
    [alert(4624, f"2026-09-01T09:0{i}:00Z", user="mcosta") for i in range(4)]
    + [alert(4625, f"2026-09-02T03:0{i}:00Z", user="convidado") for i in range(6)]
)


def _train_fake_model() -> None:
    feature_rows = extract_features(MOCK_ALERTS)
    vectors = vectorize(feature_rows)
    fake_model, fake_scaler = train_model(vectors, contamination=0.3, random_state=1)
    ml_anomalies._model = fake_model
    ml_anomalies._scaler = fake_scaler


def run() -> None:
    client = TestClient(main.app, headers={"X-API-Key": os.environ["SENTRYLENS_API_KEY"]})
    client_no_key = TestClient(main.app)

    # --- 401 sem X-API-Key ---
    check("GET /api/detections sem X-API-Key -> 401", client_no_key.get("/api/detections").status_code == 401)

    # --- as 3 fontes disponíveis e com dados ---
    _train_fake_model()
    main.indexer_client.get_recent_alerts = AsyncMock(return_value=MOCK_ALERTS)
    main.vm_ssh_client = MagicMock()
    main.network_detection_buffer.clear()
    main.network_detection_buffer.append(detection(timestamp="2026-10-07T10:05:00+00:00"))

    resp = client.get("/api/detections")
    check("GET /api/detections devolve 200", resp.status_code == 200)
    body = resp.json()
    check("window_hours default é 24", body["window_hours"] == 24)
    check("fonte rule disponível", body["sources"]["rule"]["available"] is True)
    check("fonte rule com 10 alertas", body["sources"]["rule"]["count"] == len(MOCK_ALERTS))
    check("fonte ml disponível", body["sources"]["ml"]["available"] is True)
    check("fonte network disponível", body["sources"]["network"]["available"] is True)
    check("fonte network com 1 deteção", body["sources"]["network"]["count"] == 1)
    check("total == soma das 3 fontes", body["total"] == sum(s["count"] for s in body["sources"].values()))
    check("events tem pelo menos 1 por fonte com dados", len(body["events"]) > 0)
    check("nenhum evento expõe 'ref' (dado bruto)", all("ref" not in e for e in body["events"]))
    check(
        "cada evento tem source/severity/asset/ts/label",
        all({"source", "severity", "asset", "ts", "label", "technique", "confidence", "description"} <= e.keys() for e in body["events"]),
    )
    check(
        "events ordenados por ts, mais recente primeiro",
        body["events"] == sorted(body["events"], key=lambda e: e["ts"], reverse=True),
    )
    check("sources só tem rule/ml/network", set(body["sources"].keys()) == {"rule", "ml", "network"})

    # --- limit capa o nº de eventos devolvidos e marca truncated ---
    resp_limit = client.get("/api/detections", params={"limit": 1})
    body_limit = resp_limit.json()
    check("limit=1 -> 1 evento devolvido", len(body_limit["events"]) == 1)
    check("limit=1 com total > 1 -> truncated=True", body_limit["truncated"] is True)
    check("total não muda com limit (reflete tudo o que havia)", body_limit["total"] == body["total"])

    # --- Indexer em baixo -> fonte 'rule' indisponível, resto continua a funcionar ---
    main.indexer_client.get_recent_alerts = AsyncMock(side_effect=RuntimeError("Indexer em baixo (simulado)"))
    resp_sem_indexer = client.get("/api/detections")
    check("Indexer em baixo -> GET /api/detections ainda devolve 200", resp_sem_indexer.status_code == 200)
    body_sem_indexer = resp_sem_indexer.json()
    check("Indexer em baixo -> fonte rule indisponível", body_sem_indexer["sources"]["rule"]["available"] is False)
    check("Indexer em baixo -> fonte rule count 0", body_sem_indexer["sources"]["rule"]["count"] == 0)
    check("Indexer em baixo -> fonte network continua disponível", body_sem_indexer["sources"]["network"]["available"] is True)
    main.indexer_client.get_recent_alerts = AsyncMock(return_value=MOCK_ALERTS)

    # --- sem modelo ML treinado -> fonte 'ml' indisponível, resto continua ---
    ml_anomalies._model = None
    ml_anomalies._scaler = None

    def _raise_not_found(model_dir=None):
        raise FileNotFoundError("modelo não encontrado (simulado)")

    original_load_model = ml_anomalies.load_model
    ml_anomalies.load_model = _raise_not_found
    resp_sem_modelo = client.get("/api/detections")
    check("sem modelo ML -> GET /api/detections ainda devolve 200", resp_sem_modelo.status_code == 200)
    body_sem_modelo = resp_sem_modelo.json()
    check("sem modelo ML -> fonte ml indisponível", body_sem_modelo["sources"]["ml"]["available"] is False)
    check("sem modelo ML -> fonte rule continua disponível", body_sem_modelo["sources"]["rule"]["available"] is True)
    ml_anomalies.load_model = original_load_model
    _train_fake_model()

    # --- sem VM_SSH_HOST (vm_ssh_client=None) -> fonte 'network' indisponível ---
    main.vm_ssh_client = None
    resp_sem_rede = client.get("/api/detections")
    body_sem_rede = resp_sem_rede.json()
    check("sem VM_SSH_HOST -> fonte network indisponível", body_sem_rede["sources"]["network"]["available"] is False)
    check("sem VM_SSH_HOST -> fonte network count 0", body_sem_rede["sources"]["network"]["count"] == 0)
    check("sem VM_SSH_HOST -> resto continua 200", resp_sem_rede.status_code == 200)
    main.vm_ssh_client = MagicMock()

    # --- hours/limit fora do intervalo -> 422 (nunca sem teto) ---
    check("hours=0 -> 422", client.get("/api/detections", params={"hours": 0}).status_code == 422)
    check("hours=200 (> 168) -> 422", client.get("/api/detections", params={"hours": 200}).status_code == 422)
    check("limit=0 -> 422", client.get("/api/detections", params={"limit": 0}).status_code == 422)
    check("limit=201 (> 200) -> 422", client.get("/api/detections", params={"limit": 201}).status_code == 422)

    main.network_detection_buffer.clear()

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")
    sys.exit(0)


if __name__ == "__main__":
    run()
