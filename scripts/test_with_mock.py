"""
Testes de regressão da Fase 2 (FastAPI + Wazuh) sem precisar do laboratório
Wazuh real ligado. Mocka as respostas de WazuhIndexerClient/WazuhManagerClient
e valida, através dos endpoints reais, a classificação de eventos
(event_catalog), as agregações (/api/stats) e a deteção de brute-force
(/api/brute-force).

Correr:
    python test_with_mock.py
"""

import sys
from unittest.mock import AsyncMock

from fastapi.testclient import TestClient

import main
from event_catalog import classify_alert

# Desliga o startup event (loop de monitorização de sistema da Fase 2) —
# estes testes validam só a camada Wazuh, não devem tocar em psutil/speedtest
# nem escrever no system_alerts_history.json real.
main.app.router.on_startup.clear()

MOCK_ALERTS = [
    # 5 tentativas falhadas do mesmo utilizador -> deve disparar brute-force
    *[
        {
            "@timestamp": f"2026-08-28T10:0{i}:00Z",
            "agent": {"name": "WIN-PC01", "ip": "10.0.0.5"},
            "rule": {"id": "60122", "description": "Multiple failed logons", "level": 10},
            "data": {
                "win": {
                    "system": {"eventID": "4625"},
                    "eventdata": {"targetUserName": "admin"},
                }
            },
            "full_log": "Failed logon attempt",
        }
        for i in range(5)
    ],
    # 2 tentativas de outro utilizador -> não deve disparar (abaixo do threshold)
    *[
        {
            "@timestamp": f"2026-08-28T11:0{i}:00Z",
            "agent": {"name": "WIN-PC02", "ip": "10.0.0.6"},
            "rule": {"id": "60122", "description": "Multiple failed logons", "level": 10},
            "data": {
                "win": {
                    "system": {"eventID": "4625"},
                    "eventdata": {"targetUserName": "guest"},
                }
            },
            "full_log": "Failed logon attempt",
        }
        for i in range(2)
    ],
    # evento crítico: conta apagada
    {
        "@timestamp": "2026-08-28T12:00:00Z",
        "agent": {"name": "WIN-PC01", "ip": "10.0.0.5"},
        "rule": {"id": "60123", "description": "Account deleted", "level": 12},
        "data": {"win": {"system": {"eventID": "4726"}}},
        "full_log": "User account deleted",
    },
    # evento não catalogado
    {
        "@timestamp": "2026-08-28T13:00:00Z",
        "agent": {"name": "WIN-PC01", "ip": "10.0.0.5"},
        "rule": {"id": "1001", "description": "Generic event", "level": 3},
        "data": {"win": {"system": {"eventID": "9999"}}},
        "full_log": "Some generic event",
    },
]

MOCK_AGENTS = [
    {
        "id": "001", "name": "WIN-PC01", "ip": "10.0.0.5", "status": "active",
        "os": {"name": "Windows 11"}, "lastKeepAlive": "2026-08-28T13:00:00Z",
    },
    {
        "id": "002", "name": "WIN-PC02", "ip": "10.0.0.6", "status": "disconnected",
        "os": {"name": "Windows 10"}, "lastKeepAlive": "2026-08-28T09:00:00Z",
    },
]

MOCK_AGENTS_SUMMARY = {"connection": {"active": 1, "disconnected": 1, "never_connected": 0, "total": 2}}

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def run() -> None:
    main.indexer_client.get_recent_alerts = AsyncMock(return_value=MOCK_ALERTS)
    main.manager_client.get_agents = AsyncMock(return_value=MOCK_AGENTS)
    main.manager_client.get_agents_summary = AsyncMock(return_value=MOCK_AGENTS_SUMMARY)

    client = TestClient(main.app)

    # --- classify_alert (unidade) ---
    known = classify_alert(4625)
    check("classify_alert(4625) tem severidade 'high'", known["severity"] == "high")
    check("classify_alert(4625) tem nome 'Failed Logon'", known["friendly_name"] == "Failed Logon")

    unknown = classify_alert(9999)
    check("classify_alert(9999) devolve severidade 'info'", unknown["severity"] == "info")

    # --- GET /api/alerts ---
    resp = client.get("/api/alerts")
    check("GET /api/alerts devolve 200", resp.status_code == 200)
    body = resp.json()
    check("GET /api/alerts devolve o total de alertas mockados", body["total"] == len(MOCK_ALERTS))

    deleted_account_alert = next((a for a in body["alerts"] if a["windows_event_id"] == 4726), None)
    check(
        "Evento 4726 (conta apagada) é classificado como severidade 'high'",
        deleted_account_alert is not None and deleted_account_alert["severity"] == "high",
    )

    uncatalogued_alert = next((a for a in body["alerts"] if a["windows_event_id"] == 9999), None)
    check(
        "Evento não catalogado (9999) cai em severidade 'info'",
        uncatalogued_alert is not None and uncatalogued_alert["severity"] == "info",
    )

    # --- GET /api/alerts com filtro de severidade ---
    resp_high = client.get("/api/alerts", params={"severity": "high"})
    high_alerts = resp_high.json()["alerts"]
    check(
        "Filtro severity=high só devolve alertas 'high'",
        len(high_alerts) > 0 and all(a["severity"] == "high" for a in high_alerts),
    )

    # --- GET /api/alerts com filtro de categoria ---
    resp_autenticacao = client.get("/api/alerts", params={"category": "autenticacao"})
    autenticacao_alerts = resp_autenticacao.json()["alerts"]
    check(
        "Filtro category=autenticacao só devolve alertas dessa categoria (7 eventos 4625)",
        len(autenticacao_alerts) == 7 and all(a["category"] == "autenticacao" for a in autenticacao_alerts),
    )

    # --- GET /api/stats ---
    resp_stats = client.get("/api/stats")
    check("GET /api/stats devolve 200", resp_stats.status_code == 200)
    stats = resp_stats.json()
    check("GET /api/stats total_alerts bate certo", stats["total_alerts"] == len(MOCK_ALERTS))

    event_4625_entry = next((e for e in stats["top_events"] if e["event_id"] == 4625), None)
    check(
        "top_events inclui 4625 com contagem agregada (5 admin + 2 guest = 7)",
        event_4625_entry is not None and event_4625_entry["count"] == 7,
    )
    check(
        "by_category agrega corretamente (7 autenticacao, 1 ciclo_de_vida, 1 geral)",
        stats["by_category"] == {"autenticacao": 7, "ciclo_de_vida": 1, "geral": 1},
    )

    # --- GET /api/brute-force ---
    resp_bf = client.get("/api/brute-force", params={"threshold": 3})
    check("GET /api/brute-force devolve 200", resp_bf.status_code == 200)
    suspects = {s["user"] for s in resp_bf.json()["suspects"]}
    check("'admin' (5 falhas) é apanhado com threshold=3", "admin" in suspects)
    check("'guest' (2 falhas) NÃO é apanhado com threshold=3", "guest" not in suspects)

    # --- GET /api/agents ---
    resp_agents = client.get("/api/agents")
    check("GET /api/agents devolve 200", resp_agents.status_code == 200)
    check("GET /api/agents devolve os 2 agentes mockados", len(resp_agents.json()["agents"]) == 2)

    print()
    if failures:
        print(f"❌ {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("✅ Todos os testes passaram")
    sys.exit(0)


if __name__ == "__main__":
    run()
