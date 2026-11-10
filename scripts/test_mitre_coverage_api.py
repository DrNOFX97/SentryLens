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


def run_mix() -> None:
    """Caso misto pela rota com o attack_registry real (sem mockar o registry)."""
    saved = (main.ml_anomalies.load_model, main.ml_anomalies.build_ml_anomalies_report)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            client = TestClient(main.app, headers={"X-API-Key": os.environ["SENTRYLENS_API_KEY"]})
            attacks = [
                {"id": 1, "scenario": "brute_force_rdp", "target": ASSET, "timestamp": ts(3000),
                 "status": "launched", "technique": "T1110", "tool": "hydra"},
                {"id": 2, "scenario": "smb_enum", "target": ASSET, "timestamp": ts(2000),
                 "status": "launched", "technique": "T1087", "tool": "netexec"},
                {"id": 3, "scenario": "lateral_movement_schtasks", "target": ASSET, "timestamp": ts(1000),
                 "status": "launched", "technique": "T1053", "tool": "psexec"},
                {"id": 4, "scenario": "account_lockout_spray", "target": OTHER, "timestamp": ts(500),
                 "status": "launched"},
                {"id": 5, "scenario": "brute_force_rdp", "target": ASSET, "timestamp": ts(200 * 3600),
                 "status": "launched", "technique": "T1110", "tool": "hydra"},
            ]
            ml_results = [ml_row(2980, 4625, True, True), ml_row(970, 4672, True, False)]
            alerts = [alert_mitre(["T1110"], 2990), alert_event(4625, 2985), alert_event(4624, 2980),
                      alert_mitre(["T1059"], 100)]
            wire(tmp, attacks=attacks, alerts=alerts, ml_results=ml_results)

            body = client.get("/api/mitre/coverage").json()
            rows = {t["id"]: t for t in body["techniques"] + body["unmapped"]}
            by_tactic = {t["tactic"]: t for t in body["tactics"]}

            check("mix: T1110 detetado, rate 100.0 (o ataque de 200 h fica fora da janela)",
                  rows["T1110"]["attacks"]["launched"] == 1 and rows["T1110"]["rate"] == 100.0)
            check("mix: T1053 parcial, rate 0.0",
                  rows["T1053"]["attacks"]["partial"] == 1 and rows["T1053"]["rate"] == 0.0)
            check("mix: T1110.003 (técnica do cenário) não detetado, rate 0.0",
                  rows["T1110.003"]["attacks"]["not_detected"] == 1 and rows["T1110.003"]["rate"] == 0.0)
            check("mix: ids de unmapped = T1059 (alerta) e T1087 (técnica do log fora da tabela)",
                  [u["id"] for u in body["unmapped"]] == ["T1059", "T1087"])
            check("mix: T1087 em unmapped com o ataque e tactics []",
                  rows["T1087"]["attacks"]["not_detected"] == 1 and rows["T1087"]["tactics"] == [])
            check("mix: Credential Access launched 2 e rate 50.0",
                  by_tactic["Credential Access"]["attacks"]["launched"] == 2
                  and by_tactic["Credential Access"]["rate"] == 50.0)
            check("mix: T1053 conta em Execution, Persistence e Privilege Escalation (launched 1, rate 0.0)",
                  all(by_tactic[n]["attacks"]["launched"] == 1 and by_tactic[n]["rate"] == 0.0
                      for n in ("Execution", "Persistence", "Privilege Escalation")))
            check("mix: Discovery sem ataques com tática -> rate None", by_tactic["Discovery"]["rate"] is None)
            check("mix: totals.attacks 4 lançados (1 detected, 1 partial, 2 not_detected, 0 unknown)",
                  body["totals"]["attacks"] == {"launched": 4, "detected": 1, "partial": 1,
                                                "not_detected": 2, "unknown": 0})
            check("mix: totals.rate 25.0", body["totals"]["rate"] == 25.0)

            wide = client.get("/api/mitre/coverage?hours=720").json()
            wide_rows = {t["id"]: t for t in wide["techniques"] + wide["unmapped"]}
            check("mix: com hours=720 o ataque de 200 h conta (5 lançados, T1110 com 2)",
                  wide["totals"]["attacks"]["launched"] == 5 and wide_rows["T1110"]["attacks"]["launched"] == 2
                  and wide["window_hours"] == 720)
    finally:
        main.ml_anomalies.load_model, main.ml_anomalies.build_ml_anomalies_report = saved


def mix_data() -> tuple[list, list, list]:
    """Os mesmos ataques, alertas e resultados ML de run_mix."""
    attacks = [
        {"id": 1, "scenario": "brute_force_rdp", "target": ASSET, "timestamp": ts(3000),
         "status": "launched", "technique": "T1110", "tool": "hydra"},
        {"id": 2, "scenario": "smb_enum", "target": ASSET, "timestamp": ts(2000),
         "status": "launched", "technique": "T1087", "tool": "netexec"},
        {"id": 3, "scenario": "lateral_movement_schtasks", "target": ASSET, "timestamp": ts(1000),
         "status": "launched", "technique": "T1053", "tool": "psexec"},
        {"id": 4, "scenario": "account_lockout_spray", "target": OTHER, "timestamp": ts(500),
         "status": "launched"},
        {"id": 5, "scenario": "brute_force_rdp", "target": ASSET, "timestamp": ts(200 * 3600),
         "status": "launched", "technique": "T1110", "tool": "hydra"},
    ]
    ml_results = [ml_row(2980, 4625, True, True), ml_row(970, 4672, True, False)]
    alerts = [alert_mitre(["T1110"], 2990), alert_event(4625, 2985), alert_event(4624, 2980),
              alert_mitre(["T1059"], 100)]
    return attacks, alerts, ml_results


def run_indexer_down() -> None:
    saved = (main.ml_anomalies.load_model, main.ml_anomalies.build_ml_anomalies_report)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            client = TestClient(main.app, headers={"X-API-Key": os.environ["SENTRYLENS_API_KEY"]})
            attacks, alerts, ml_results = mix_data()
            wire(tmp, attacks=attacks, alerts=alerts, ml_results=ml_results)
            main.indexer_client.get_recent_alerts = AsyncMock(
                side_effect=RuntimeError("segredo-interno C:\\caminho\\indexer"))

            r = client.get("/api/mitre/coverage")
            check("indexer em baixo: 200 (nunca 500)", r.status_code == 200)
            body = r.json()
            rows = body["techniques"] + body["unmapped"]
            check("indexer em baixo: sources.alerts = source_unavailable",
                  body["sources"]["alerts"] == {"available": False, "reason": "source_unavailable"})
            check("indexer em baixo: alerts None em todas as linhas",
                  all(row["alerts"] is None for row in rows))
            check("indexer em baixo: totals.alerts None", body["totals"]["alerts"] is None)
            check("indexer em baixo: alerts_truncated None", body["alerts_truncated"] is None)
            check("indexer em baixo: ataques continuam disponíveis",
                  body["sources"]["attacks"]["available"] is True)
            check("indexer em baixo: correlation.reason indexer_unavailable",
                  body["sources"]["attacks"]["correlation"]["reason"] == "indexer_unavailable")
            check("indexer em baixo: todos os vereditos unknown (4 lançados)",
                  body["totals"]["attacks"]["unknown"] == body["totals"]["attacks"]["launched"] == 4)
            check("indexer em baixo: totals.rate None", body["totals"]["rate"] is None)
            t1110 = next(t for t in body["techniques"] if t["id"] == "T1110")
            check("indexer em baixo: T1110 rate None", t1110["rate"] is None)
            check("indexer em baixo: 17 linhas da tabela", len(body["techniques"]) == 17)
            check("indexer em baixo: T1087 em unmapped (vem do log)",
                  any(u["id"] == "T1087" for u in body["unmapped"]))
            check("indexer em baixo: nenhum texto da exceção no corpo",
                  "segredo-interno" not in r.text and "caminho" not in r.text)
    finally:
        main.ml_anomalies.load_model, main.ml_anomalies.build_ml_anomalies_report = saved


if __name__ == "__main__":
    run_tracer()
    run_mix()
    run_indexer_down()
    if failures:
        print(f"\n{len(failures)} caso(s) falharam:")
        for label in failures:
            print(f"  - {label}")
        sys.exit(1)
    print("\nTodos os casos passaram.")
