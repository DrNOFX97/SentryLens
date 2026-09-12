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
