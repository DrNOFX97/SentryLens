"""
Testes da saúde do SIEM (R2): build_siem_health_report (pura) e a rota
GET /api/siem/health com Manager/Indexer falsos. Sem laboratório Wazuh.

Correr (a partir de scripts/):
    python test_siem_health.py
"""

import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

os.environ.setdefault("SENTRYLENS_API_KEY", "test-key-siem-health")

from fastapi.testclient import TestClient

import main
from siem_health import build_siem_health_report, parse_wazuh_timestamp

main.app.router.on_startup.clear()
client = TestClient(main.app)
HEADERS = {"X-API-Key": os.environ["SENTRYLENS_API_KEY"]}
failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


NOW = datetime(2026, 10, 7, 12, 0, 0, tzinfo=timezone.utc)


def alert(seconds_ago: float) -> dict:
    ts = (NOW - timedelta(seconds=seconds_ago)).strftime("%Y-%m-%dT%H:%M:%S.000+0000")
    return {"@timestamp": ts}


SUMMARY = {"connection": {"active": 3, "disconnected": 1, "never_connected": 0, "pending": 0, "total": 4}}

# --- parse ---
check("parse +0000", parse_wazuh_timestamp("2026-10-07T12:00:00.000+0000") == NOW)
check("parse Z", parse_wazuh_timestamp("2026-10-07T12:00:00Z") == NOW)
check("parse inválido -> None", parse_wazuh_timestamp("lixo") is None and parse_wazuh_timestamp(None) is None)

# --- tudo ok ---
r = build_siem_health_report(SUMMARY, None, [alert(30), alert(90), alert(200), alert(4000)], None, now=NOW)
check("manager/indexer ok", r["manager"]["status"] == "ok" and r["indexer"]["status"] == "ok")
check("agentes lidos", r["agents"] == {"active": 3, "disconnected": 1, "never_connected": 0, "pending": 0, "total": 4})
check("atraso = 30 s", r["ingestion_lag_seconds"] == 30.0)
check("3 alertas na janela de 5 min", r["alerts_in_window"] == 3)
check("taxa = 0.6/min", r["alerts_per_minute"] == 0.6)
check("ordem do indexer não importa (máximo)", build_siem_health_report(SUMMARY, None, [alert(500), alert(10)], None, now=NOW)["ingestion_lag_seconds"] == 10.0)

# --- formato plano de agentes ---
check("resumo plano", build_siem_health_report({"active": 2}, None, [], None, now=NOW)["agents"]["active"] == 2)

# --- Indexer ok mas vazio: sem alertas != atraso 0 ---
r = build_siem_health_report(SUMMARY, None, [], None, now=NOW)
check("sem alertas: last_alert_at e atraso None", r["last_alert_at"] is None and r["ingestion_lag_seconds"] is None)
check("sem alertas: taxa 0 (dado real)", r["alerts_per_minute"] == 0 and r["alerts_in_window"] == 0)

# --- status agregado / stale / truncated ---
r = build_siem_health_report(SUMMARY, None, [alert(30)], None, now=NOW)
check("tudo ok: status ok, não stale, não truncado", r["status"] == "ok" and r["stale"] is False and r["truncated"] is False)
r = build_siem_health_report(SUMMARY, None, [alert(301)], None, now=NOW)
check("atraso > 5 min com indexer ok: stale + degraded", r["stale"] is True and r["status"] == "degraded")
check("atraso = 300 s ainda não é stale", build_siem_health_report(SUMMARY, None, [alert(300)], None, now=NOW)["stale"] is False)
r = build_siem_health_report(SUMMARY, None, [], None, now=NOW)
check("sem alertas na última hora: stale + degraded", r["stale"] is True and r["status"] == "degraded")
r = build_siem_health_report(SUMMARY, None, [alert(i) for i in range(10)], None, now=NOW, fetch_size=10)
check("len == limite -> truncated", r["truncated"] is True)
check("len < limite -> não truncado", build_siem_health_report(SUMMARY, None, [alert(1)] * 9, None, now=NOW, fetch_size=10)["truncated"] is False)
r = build_siem_health_report(SUMMARY, None, None, "timeout", now=NOW)
check("indexer em baixo -> degraded (não stale)", r["status"] == "degraded" and r["stale"] is False)
check("manager em baixo -> degraded", build_siem_health_report(None, "unreachable", [alert(5)], None, now=NOW)["status"] == "degraded")
r = build_siem_health_report(None, "unreachable", None, "timeout", now=NOW)
check("ambos em baixo -> down", r["status"] == "down")

# --- Indexer em baixo ---
r = build_siem_health_report(SUMMARY, None, None, "timeout", now=NOW)
check("indexer unavailable com erro", r["indexer"] == {"status": "unavailable", "error": "timeout"})
check("indexer em baixo: sem números inventados", r["last_alert_at"] is None and r["ingestion_lag_seconds"] is None and r["alerts_per_minute"] is None and r["alerts_in_window"] is None)
check("manager continua ok", r["manager"]["status"] == "ok" and r["agents"]["total"] == 4)

# --- Manager em baixo ---
r = build_siem_health_report(None, "401", [alert(5)], None, now=NOW)
check("manager unavailable, agents None", r["manager"]["status"] == "unavailable" and r["agents"] is None)
check("indexer continua com dados", r["ingestion_lag_seconds"] == 5.0)

# --- alerta futuro (relógios dessincronizados) não dá atraso negativo ---
check("atraso nunca negativo", build_siem_health_report(SUMMARY, None, [alert(-60)], None, now=NOW)["ingestion_lag_seconds"] == 0.0)

# --- rota ---
check("rota sem API key -> 401", client.get("/api/siem/health").status_code == 401)

main.manager_client = type("M", (), {"get_agents_summary": AsyncMock(return_value=SUMMARY)})()
main.indexer_client = type("I", (), {"get_recent_alerts": AsyncMock(return_value=[{"@timestamp": (datetime.now(timezone.utc) - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%S.000+0000")}])})()
resp = client.get("/api/siem/health", headers=HEADERS)
body = resp.json()
check("rota 200 com ambos ok", resp.status_code == 200 and body["manager"]["status"] == "ok" and body["indexer"]["status"] == "ok")
check("rota devolve agentes", body["agents"]["active"] == 3)
check("rota ok: status ok", body["status"] == "ok")
try:
    main.indexer_client.get_recent_alerts.assert_awaited_with(hours=1, size=500)
    asked_500 = True
except AssertionError:
    asked_500 = False
check("rota pede os 500 mais recentes (hours=1,size=500)", asked_500)

import httpx

main.manager_client = type("M", (), {"get_agents_summary": AsyncMock(side_effect=RuntimeError("falha https://10.9.8.7:55000/agents"))})()
main.indexer_client = type("I", (), {"get_recent_alerts": AsyncMock(side_effect=httpx.ConnectTimeout("10.9.8.7:9200"))})()
resp = client.get("/api/siem/health", headers=HEADERS)
body = resp.json()
check("rota 200 mesmo com ambos em baixo", resp.status_code == 200)
raw = resp.text
check("rota: sem host/URL/porta nem texto cru no JSON", "10.9.8.7" not in raw and "55000" not in raw and "9200" not in raw and "https" not in raw)
check("rota: códigos de erro estáveis", body["manager"]["error"] == "unreachable" and body["indexer"]["error"] == "timeout")
check("rota: status agregado down", body["status"] == "down")
check("rota: ambos unavailable, sem números", body["manager"]["status"] == "unavailable" and body["indexer"]["status"] == "unavailable" and body["agents"] is None and body["alerts_per_minute"] is None)

if failures:
    print(f"\n{len(failures)} teste(s) falharam")
    sys.exit(1)
print("\nTodos os testes passaram.")
