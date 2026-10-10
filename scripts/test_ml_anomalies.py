"""
Testes de regressão de /api/ml-anomalies, sem laboratório Wazuh nem
modelo treinado em disco: treina um Isolation Forest minúsculo em
memória sobre um punhado de alertas mock e injeta-o via monkeypatch em
ml_anomalies (mesmo padrão de main.indexer_client.get_recent_alerts =
AsyncMock(...) usado em test_with_mock.py).

Cobre também os sinais de integridade da janela que a Fase 2 acrescentou à
resposta (alerts_fetched/alerts_truncated, D-10): com 10 alertas mockados,
com a janela a encher o tecto de 1000, com a janela vazia, e os três
estados de erro (401 sem chave, 502 com o Indexer a levantar, 503 sem
modelo) — para que a adição não tenha deslocado nada do contrato anterior.

Correr:
    python test_ml_anomalies.py
"""

import os
import sys
from unittest.mock import AsyncMock

from fastapi.testclient import TestClient

os.environ.setdefault("SENTRYLENS_API_KEY", "chave-de-teste-nao-usar-em-producao")

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

# Contrato de topo de /api/ml-anomalies: as chaves que já existiam, mais as
# duas que a Fase 2 acrescentou (alerts_fetched/alerts_truncated, D-10). É
# um conjunto exacto, não uma lista: um terceiro campo novo aparece aqui
# como falha em vez de passar em silêncio.
CHAVES_ESPERADAS = {
    "total", "ml_anomalies_count", "rule_flagged_count", "agree_count",
    "diverge_count", "results", "window_hours", "alerts_fetched", "alerts_truncated",
}

# Teto do pedido ao Indexer, o mesmo de /api/redblue/metrics e de
# get_recent_alerts(size=1000). Um fetch que chega ao limite devolve uma
# janela possivelmente truncada, e o dashboard tem de poder avisar.
TETO_ALERTAS = 1000


def run() -> None:
    # Treina um modelo minúsculo sobre os próprios MOCK_ALERTS, para não
    # depender de scripts/models/*.pkl existirem em disco.
    feature_rows = extract_features(MOCK_ALERTS)
    vectors = vectorize(feature_rows)
    fake_model, fake_scaler = train_model(vectors, contamination=0.3, random_state=1)
    ml_anomalies._model = fake_model
    ml_anomalies._scaler = fake_scaler

    original_get_recent = main.indexer_client.get_recent_alerts
    main.indexer_client.get_recent_alerts = AsyncMock(return_value=MOCK_ALERTS)
    client = TestClient(main.app, headers={"X-API-Key": os.environ["SENTRYLENS_API_KEY"]})

    try:
        resp = client.get("/api/ml-anomalies")
        check("GET /api/ml-anomalies devolve 200", resp.status_code == 200)
        body = resp.json()
        check("total bate com o nº de alertas mockados", body["total"] == len(MOCK_ALERTS))
        check("cada resultado tem ml_score e ml_is_anomaly", all("ml_score" in r and "ml_is_anomaly" in r for r in body["results"]))
        check("cada resultado tem rule_flagged e agreement", all("rule_flagged" in r and r["agreement"] in ("agree", "diverge") for r in body["results"]))
        check("cada resultado tem agent_ip", all(r.get("agent_ip") == "192.168.1.5" for r in body["results"]))
        check("agree_count + diverge_count == total", body["agree_count"] + body["diverge_count"] == body["total"])
        check("window_hours default é 24", body["window_hours"] == 24)

        # --- sinais de integridade da janela (D-10, chaves ADITIVAS) ---
        check("alerts_fetched é o nº de alertas mockados",
              body["alerts_fetched"] == len(MOCK_ALERTS))
        check("alerts_truncated é False com 10 alertas",
              body["alerts_truncated"] is False)
        check("as chaves de topo são exactamente o contrato + as duas novas",
              set(body) == CHAVES_ESPERADAS)

        # --- janela a encher o tecto: truncada, e o valor não muda ---
        cheio = [dict(MOCK_ALERTS[0]) for _ in range(TETO_ALERTAS)]
        main.indexer_client.get_recent_alerts = AsyncMock(return_value=cheio)
        resp_cheio = client.get("/api/ml-anomalies")
        check("janela cheia devolve 200", resp_cheio.status_code == 200)
        cheio_corpo = resp_cheio.json()
        check("alerts_fetched é 1000 com o tecto atingido",
              cheio_corpo["alerts_fetched"] == TETO_ALERTAS)
        check("alerts_truncated é True ao atingir o tecto de 1000",
              cheio_corpo["alerts_truncated"] is True)
        check("a truncagem não mexe nas chaves existentes",
              set(cheio_corpo) == CHAVES_ESPERADAS
              and cheio_corpo["total"] == TETO_ALERTAS
              and cheio_corpo["agree_count"] + cheio_corpo["diverge_count"] == cheio_corpo["total"])

        # --- janela vazia: 0 NÃO é truncagem (e é o "Sem dados" do frontend) ---
        main.indexer_client.get_recent_alerts = AsyncMock(return_value=[])
        resp_vazio = client.get("/api/ml-anomalies")
        check("janela vazia devolve 200", resp_vazio.status_code == 200)
        vazio_corpo = resp_vazio.json()
        check("janela vazia: total/agree/diverge a 0",
              vazio_corpo["total"] == 0 and vazio_corpo["agree_count"] == 0
              and vazio_corpo["diverge_count"] == 0)
        check("janela vazia: alerts_fetched 0 e alerts_truncated False (0 não é truncagem)",
              vazio_corpo["alerts_fetched"] == 0 and vazio_corpo["alerts_truncated"] is False)
    finally:
        main.indexer_client.get_recent_alerts = original_get_recent

    # --- 401 sem X-API-Key: a rota continua a exigir a chave ---
    sem_chave = TestClient(main.app)
    check("sem X-API-Key continua a dar 401",
          sem_chave.get("/api/ml-anomalies").status_code == 401)

    # --- 502 quando o Indexer não responde ---
    def _raise_indexer(*args, **kwargs):
        raise RuntimeError("Indexer fora do ar (simulado)")

    main.indexer_client.get_recent_alerts = _raise_indexer
    try:
        resp_502 = client.get("/api/ml-anomalies")
        check("Indexer a levantar devolve 502", resp_502.status_code == 502)
    finally:
        main.indexer_client.get_recent_alerts = original_get_recent

    # --- 503 quando não há modelo treinado ---
    ml_anomalies._model = None
    ml_anomalies._scaler = None

    def _raise_not_found(model_dir=None):
        raise FileNotFoundError("modelo não encontrado (simulado)")

    original_load_model = ml_anomalies.load_model
    ml_anomalies.load_model = _raise_not_found
    try:
        resp_missing = client.get("/api/ml-anomalies")
        check("sem modelo treinado devolve 503", resp_missing.status_code == 503)
    finally:
        ml_anomalies.load_model = original_load_model
        ml_anomalies._model = fake_model
        ml_anomalies._scaler = fake_scaler

    # O registo ficou como estava: voltar a pedir depois do 503 volta a dar
    # 200 — a adição das chaves não deslocou o carregamento do modelo. O
    # Indexer mockado é reposto ANTES, para que esta verificação não tente a
    # rede (o laboratório pode estar desligado, como está na maioria das vezes).
    main.indexer_client.get_recent_alerts = AsyncMock(return_value=MOCK_ALERTS)
    try:
        resp_final = client.get("/api/ml-anomalies")
        check("depois dos estados de erro a rota volta a 200", resp_final.status_code == 200)
    finally:
        main.indexer_client.get_recent_alerts = original_get_recent

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")
    sys.exit(0)


if __name__ == "__main__":
    run()
