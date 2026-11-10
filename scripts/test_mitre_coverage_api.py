"""
Testes de GET /api/mitre/coverage (R16, Phase 19): Indexer, modelo ML, log de
ataques e incidentes mockados. Sem laboratório Wazuh. Só IPs de documentação
(192.0.2.x / 203.0.113.x).

Correr (a partir de scripts/):
    python test_mitre_coverage_api.py
"""

import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

os.environ.setdefault("SENTRYLENS_API_KEY", "chave-de-teste-nao-usar-em-producao")

from fastapi.testclient import TestClient

import main
import mitre_coverage
from mitre_catalog import ENTERPRISE_TACTICS

main.app.router.on_startup.clear()

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


ASSET = "192.0.2.10"
OTHER = "203.0.113.7"
NOW = datetime.now(timezone.utc)


def ts(seconds_ago: int) -> str:
    return (NOW - timedelta(seconds=seconds_ago)).isoformat()


def ml_row(seconds_ago: int, event_id: int, rule: bool, ml: bool, ip: str = ASSET) -> dict:
    return {"timestamp": ts(seconds_ago), "agent_ip": ip, "windows_event_id": event_id,
            "rule_flagged": rule, "ml_is_anomaly": ml}


_alert_seq = [0]


def _next_id() -> str:
    _alert_seq[0] += 1
    return f"alert-{_alert_seq[0]}"


def alert_mitre(ids: list, seconds_ago: int) -> dict:
    """Alerta cru com rule.mitre.id (origem wazuh)."""
    return {"_id": _next_id(), "@timestamp": ts(seconds_ago), "agent": {"name": "LAB1", "ip": ASSET},
            "rule": {"id": "1", "level": 5, "description": "regra", "mitre": {"id": ids}},
            "full_log": "x"}


def alert_event(event_id: int, seconds_ago: int) -> dict:
    """Alerta cru só com o Event ID, sem rule.mitre (origem catalog)."""
    return {"_id": _next_id(), "@timestamp": ts(seconds_ago), "agent": {"name": "LAB1", "ip": ASSET},
            "rule": {"id": "1", "level": 5, "description": "regra"}, "full_log": "x",
            "data": {"win": {"system": {"eventID": str(event_id)}}}}


def write_log(path: str, entries: list) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        for entry in entries:
            handle.write((entry if isinstance(entry, str) else json.dumps(entry)) + "\n")


def wire(tmpdir: str, *, attacks: list, alerts: list, ml_results: list) -> None:
    log_path = os.path.join(tmpdir, "attack_log.jsonl")
    write_log(log_path, attacks)
    main.ATTACK_LOG_PATH = log_path
    main.indexer_client = MagicMock()
    main.indexer_client.get_recent_alerts = AsyncMock(return_value=alerts)
    main.ml_anomalies.load_model = lambda _dir: (object(), object())
    main.ml_anomalies.build_ml_anomalies_report = lambda alerts, model, scaler: {"results": ml_results}
    main.incident_store = MagicMock()
    main.incident_store.list_incidents = MagicMock(return_value=[])
    main.vm_ssh_client = None


def run_tracer() -> None:
    saved = (main.ml_anomalies.load_model, main.ml_anomalies.build_ml_anomalies_report)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            client = TestClient(main.app, headers={"X-API-Key": os.environ["SENTRYLENS_API_KEY"]})
            client_no_key = TestClient(main.app)
            client_bad_key = TestClient(main.app, headers={"X-API-Key": "chave-errada"})

            attacks = [{"id": 1, "scenario": "brute_force_rdp", "target": ASSET,
                        "timestamp": ts(3000), "status": "launched", "tool": "hydra"}]
            ml_results = [ml_row(2980, 4625, True, True)]
            alerts = [alert_mitre(["T1110"], 2990), alert_event(4625, 2985), alert_event(4624, 2980)]
            wire(tmp, attacks=attacks, alerts=alerts, ml_results=ml_results)

            check("tracer: sem X-API-Key -> 401", client_no_key.get("/api/mitre/coverage").status_code == 401)
            check("tracer: chave errada -> 401", client_bad_key.get("/api/mitre/coverage").status_code == 401)

            r = client.get("/api/mitre/coverage")
            check("tracer: com chave -> 200", r.status_code == 200)
            body = r.json()
            check("tracer: envelope com exatamente as chaves do contrato",
                  set(body) == set(mitre_coverage.ENVELOPE_KEYS))
            check("tracer: window_hours 168 por omissão", body["window_hours"] == 168)
            check("tracer: attack_version v18.1", body["attack_version"] == "v18.1")
            check("tracer: 17 técnicas da tabela e unmapped vazio",
                  len(body["techniques"]) == 17 and body["unmapped"] == [])

            row = next(t for t in body["techniques"] if t["id"] == "T1110")
            check("tracer: T1110 alertas {total 2, wazuh 1, catalog 1}",
                  row["alerts"] == {"total": 2, "wazuh": 1, "catalog": 1})
            check("tracer: T1110 ataques 1 lançado e detetado",
                  row["attacks"] == {"launched": 1, "detected": 1, "partial": 0, "not_detected": 0, "unknown": 0})
            check("tracer: T1110 rate 100.0", row["rate"] == 100.0)
            check("tracer: T1110 tática Credential Access", row["tactics"] == ["Credential Access"])
            check("tracer: T1110 name Brute Force e parent None",
                  row["name"] == "Brute Force" and row["parent"] is None)

            check("tracer: 14 táticas pela ordem da matriz",
                  [t["tactic"] for t in body["tactics"]] == list(ENTERPRISE_TACTICS))
            by_tactic = {t["tactic"]: t for t in body["tactics"]}
            check("tracer: Credential Access rate 100.0", by_tactic["Credential Access"]["rate"] == 100.0)
            check("tracer: Discovery sem ataques -> rate None, launched 0",
                  by_tactic["Discovery"]["rate"] is None and by_tactic["Discovery"]["attacks"]["launched"] == 0)

            check("tracer: totals.alerts {fetched 3, com técnica 2, sem técnica 1}",
                  body["totals"]["alerts"] == {"fetched": 3, "with_technique": 2, "without_technique": 1})
            check("tracer: totals.rate 100.0", body["totals"]["rate"] == 100.0)
            check("tracer: sources.alerts disponível",
                  body["sources"]["alerts"] == {"available": True, "reason": None})
            check("tracer: sources.attacks e correlação disponíveis",
                  body["sources"]["attacks"]["available"] is True
                  and body["sources"]["attacks"]["correlation"]["available"] is True)
    finally:
        main.ml_anomalies.load_model, main.ml_anomalies.build_ml_anomalies_report = saved


if __name__ == "__main__":
    run_tracer()
    if failures:
        print(f"\n{len(failures)} caso(s) falharam:")
        for label in failures:
            print(f"  - {label}")
        sys.exit(1)
    print("\nTodos os casos passaram.")
