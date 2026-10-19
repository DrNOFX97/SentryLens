"""
Testes das rotas de vaccines (Phase 13): GET /api/vaccines e
GET /api/vaccines/{id}, com o ciclo do backend (main._run_vaccine_cycle),
Indexer e modelo ML mockados, attack log e stores (incidentes e vaccines)
temporários. Sem laboratório Wazuh. Só IPs de documentação
(192.0.2.x / 203.0.113.x).

O ciclo corre sobre o registo verdadeiro (attack_registry) das mesmas
fixtures de test_attack_registry.py: o ataque 1 é detected, o 2 not_detected,
o 3 partial e o 4 (lançado há 500 s) ainda não assentou.

Correr (a partir de scripts/):
    python test_vaccines_api.py
"""

import asyncio
import json
import os
import re
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

os.environ.setdefault("SENTRYLENS_API_KEY", "test-key-vaccines-api")

from fastapi.testclient import TestClient

import incident_ingest
import main
import vaccine_engine
from attack_scenarios import SCENARIOS
from incident_store import IncidentStore
from vaccine_store import VaccineStore

main.app.router.on_startup.clear()
client = TestClient(main.app)
HEADERS = {"X-API-Key": os.environ["SENTRYLENS_API_KEY"]}

ASSET = "192.0.2.10"
OTHER = "203.0.113.7"
NOW = datetime.now(timezone.utc)

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def ts(seconds_ago: int) -> str:
    return (NOW - timedelta(seconds=seconds_ago)).isoformat()


def ml_row(seconds_ago: int, event_id: int, rule: bool, ml: bool, ip: str = ASSET) -> dict:
    return {"timestamp": ts(seconds_ago), "agent_ip": ip, "windows_event_id": event_id,
            "rule_flagged": rule, "ml_is_anomaly": ml}


def raw_alert(alert_id: str, seconds_ago: int, event_id: int) -> dict:
    return {"_id": alert_id, "@timestamp": ts(seconds_ago), "agent": {"name": "LAB1", "ip": ASSET},
            "rule": {"id": "1", "level": 5, "description": "regra"}, "full_log": "x",
            "data": {"win": {"system": {"eventID": str(event_id)}}}}


# Log "moderno" com 4 ataques lançados + ruído (failed, cenário desconhecido).
ATTACKS = [
    {"id": 1, "scenario": "brute_force_rdp", "target": ASSET, "timestamp": ts(3000), "status": "launched",
     "technique": "T1110", "tool": "hydra", "operator": "alice", "source": "203.0.113.50"},
    {"id": 2, "scenario": "smb_enum", "target": ASSET, "timestamp": ts(2000), "status": "launched",
     "technique": "T1087", "tool": "netexec"},
    {"id": 3, "scenario": "lateral_movement_schtasks", "target": ASSET, "timestamp": ts(1000), "status": "launched",
     "technique": "T1053", "tool": "psexec"},
    {"id": 4, "scenario": "account_lockout_spray", "target": OTHER, "timestamp": ts(500), "status": "launched",
     "expected": ["network", "bogus"]},
    {"id": 5, "scenario": "smb_enum", "target": ASSET, "timestamp": ts(400), "status": "failed"},
    {"id": 6, "scenario": "nao_existe", "target": ASSET, "timestamp": ts(300), "status": "launched"},
]
ML_RESULTS = [
    ml_row(2980, 4625, True, True),     # ataque 1: regra+ML -> detected
    ml_row(970, 4672, True, False),     # ataque 3: só regra -> partial (esperado regra+ML)
]


def write_log(path: str, lines: list) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        for line in lines:
            handle.write((line if isinstance(line, str) else json.dumps(line)) + "\n")


def wire(tmp: str) -> tuple[str, str]:
    """Liga a app a um attack log, uma base de incidentes e um store de vaccines
    temporários, com Indexer e modelo ML falsos. Devolve (log, caminho do store)."""
    log_path = os.path.join(tmp, "attack_log.jsonl")
    vaccines_path = os.path.join(tmp, "v.sqlite3")
    write_log(log_path, ATTACKS)
    main.ATTACK_LOG_PATH = log_path
    main.incident_store = IncidentStore(os.path.join(tmp, "i.sqlite3"))
    main.vaccine_store = VaccineStore(vaccines_path)
    main.vm_ssh_client = None
    main.ml_anomalies.load_model = lambda _dir: (object(), object())
    main.ml_anomalies.build_ml_anomalies_report = lambda alerts, model, scaler: {"results": ML_RESULTS}
    main.indexer_client.get_recent_alerts = AsyncMock(return_value=[{"x": 1}])
    return log_path, vaccines_path


def count_rows(path: str) -> int:
    conn = sqlite3.connect(path)
    try:
        return conn.execute("SELECT COUNT(*) FROM vaccines").fetchone()[0]
    finally:
        conn.close()


def run_tracer() -> None:
    original_load, original_build = main.ml_anomalies.load_model, main.ml_anomalies.build_ml_anomalies_report
    original_indexer = main.indexer_client.get_recent_alerts
    tmp = tempfile.TemporaryDirectory()
    try:
        log_path, vaccines_path = wire(tmp.name)

        # --- 401 nas duas rotas ---
        for path in ("/api/vaccines", "/api/vaccines/vac-5fe3861aa2a3"):
            check(f"GET {path} sem X-API-Key -> 401", client.get(path).status_code == 401)
            check(f"GET {path} com chave errada -> 401", client.get(path, headers={"X-API-Key": "errada"}).status_code == 401)

        # --- store vazio: 200 no_data e o pedido não cria o ficheiro ---
        r = client.get("/api/vaccines", headers=HEADERS)
        body = r.json()
        check("vazio: 200 com vaccines [], total 0, available false, reason no_data",
              r.status_code == 200 and body["vaccines"] == [] and body["total"] == 0
              and body["available"] is False and body["reason"] == "no_data")
        check("vazio: o GET não criou o ficheiro do store", not os.path.exists(vaccines_path))
        r = client.get("/api/vaccines/vac-5fe3861aa2a3", headers=HEADERS)
        check("vazio: detalhe de id válido -> 404 entry_not_found", r.status_code == 404
              and r.json() == {"detail": "entry_not_found"})
        check("vazio: o GET de detalhe também não criou o ficheiro", not os.path.exists(vaccines_path))

        # --- ciclo: incidente semeado ligado ao ataque 3 e uma passagem ---
        incident_ingest.ingest_raw_alerts(main.incident_store, [raw_alert("a3", 970, 4672)], log_path, SCENARIOS)
        result = asyncio.run(main._run_vaccine_cycle())
        check("ciclo: ok, inserted 2, pending_settle 1 (ataque 4 ainda não assentou)",
              result == {"status": "ok", "error_code": None,
                         "counts": {"inserted": 2, "existing": 0, "rejected": 0, "pending_settle": 1, "outside_window": 0},
                         "alerts_truncated": False})

        # --- lista ---
        r = client.get("/api/vaccines", headers=HEADERS)
        body = r.json()
        vaccines = body["vaccines"]
        check("lista: 200 com as duas vaccines por attack_id descendente",
              r.status_code == 200 and [v["id"] for v in vaccines] == ["vac-bd617cce8054", "vac-5fe3861aa2a3"])
        check("lista: total 2, available true, reason None, limit 200, offset 0",
              body["total"] == 2 and body["available"] is True and body["reason"] is None
              and body["limit"] == 200 and body["offset"] == 0)
        extra = vaccine_engine.VACCINE_KEYS | {"state", "superseded_by", "created_at"}
        check("lista: cada vaccine tem as chaves do motor + state/superseded_by/created_at, proposed",
              all(set(v) == extra and v["state"] == "proposed" and v["superseded_by"] is None
                  and isinstance(v["created_at"], str) for v in vaccines))
        v3, v2 = vaccines
        check("vaccine do ataque 3: T1053, falta só ml",
              v3["origin"]["attack_id"] == 3 and v3["origin"]["mitre_technique"] == "T1053"
              and v3["missing_sensors"] == ["ml"])
        check("vaccine do ataque 3: origin.incident_ids não vazio (regressão do list_incidents)",
              bool(v3["origin"]["incident_ids"])
              and all(re.fullmatch(r"INC-\d{8}-\d+", i) for i in v3["origin"]["incident_ids"]))
        check("vaccine do ataque 2: regra com event_ids [5140, 5145]",
              v2["proposals"][0]["rule"]["event_ids"] == [5140, 5145])
        stored_engine_form = {k: v for k, v in v2.items() if k not in ("state", "superseded_by", "created_at")}
        check("o que se grava é o dict do motor: passa validate_vaccine",
              vaccine_engine.validate_vaccine(stored_engine_form) == [])

        # --- detalhe ---
        r = client.get("/api/vaccines/vac-5fe3861aa2a3", headers=HEADERS)
        check("detalhe: 200 e body == {'vaccine': <entrada da lista>}",
              r.status_code == 200 and r.json() == {"vaccine": v2})
        r = client.get("/api/vaccines/vac-000000000000", headers=HEADERS)
        check("detalhe: id válido inexistente -> 404 entry_not_found",
              r.status_code == 404 and r.json() == {"detail": "entry_not_found"})
        check("detalhe: id malformado -> 422", client.get("/api/vaccines/abc", headers=HEADERS).status_code == 422)

        # --- idempotência e reinício ---
        before = client.get("/api/vaccines", headers=HEADERS).json()
        again = asyncio.run(main._run_vaccine_cycle())
        check("2.º ciclo: inserted 0 e existing 2", again["counts"]["inserted"] == 0 and again["counts"]["existing"] == 2)
        check("2.º ciclo: total continua 2 e há 2 linhas no ficheiro",
              client.get("/api/vaccines", headers=HEADERS).json()["total"] == 2 and count_rows(vaccines_path) == 2)
        main.vaccine_store = VaccineStore(vaccines_path)
        after_restart = client.get("/api/vaccines", headers=HEADERS).json()
        # `generator` é estado do loop em memória (13-02): fora da comparação do que está no ficheiro.
        check("reinício: nova instância sobre o mesmo ficheiro devolve o mesmo JSON",
              {k: v for k, v in after_restart.items() if k != "generator"}
              == {k: v for k, v in before.items() if k != "generator"})

        # --- paginação ---
        r = client.get("/api/vaccines?limit=1&offset=1", headers=HEADERS)
        check("limit=1&offset=1: só vac-5fe3861aa2a3 e total 2",
              r.status_code == 200 and [v["id"] for v in r.json()["vaccines"]] == ["vac-5fe3861aa2a3"]
              and r.json()["total"] == 2)
        for bad in ("limit=0", "limit=501", "offset=-1"):
            check(f"parâmetro inválido ({bad}) -> 422", client.get(f"/api/vaccines?{bad}", headers=HEADERS).status_code == 422)

        # --- nenhuma fuga de tool/target/source/operator/IPs ---
        dumped = json.dumps(client.get("/api/vaccines", headers=HEADERS).json())
        leaked = [w for w in ("hydra", "netexec", "psexec", "alice", "192.0.2.", "203.0.113.") if w in dumped]
        check("sem tool/target/source/operator/IPs do log na resposta", leaked == [])

        # --- store a falhar na leitura: 503 estável, sem texto de exceção ---
        broken = MagicMock()
        broken.list_vaccines.side_effect = sqlite3.OperationalError("db partida")
        broken.get_vaccine.side_effect = sqlite3.OperationalError("db partida")
        main.vaccine_store = broken
        for path in ("/api/vaccines", "/api/vaccines/vac-5fe3861aa2a3"):
            r = client.get(path, headers=HEADERS)
            check(f"store partido: {path} -> 503 store_unavailable sem texto de exceção",
                  r.status_code == 503 and r.json() == {"detail": "store_unavailable"} and "db partida" not in r.text)
    finally:
        main.ml_anomalies.load_model, main.ml_anomalies.build_ml_anomalies_report = original_load, original_build
        main.indexer_client.get_recent_alerts = original_indexer
        tmp.cleanup()


def set_ml(results: list) -> None:
    main.ml_anomalies.build_ml_anomalies_report = lambda alerts, model, scaler: {"results": results}


def ids_of(path: str) -> list[str]:
    return [v["id"] for v in client.get(path, headers=HEADERS).json()["vaccines"]]


def run_history() -> None:
    """D-06/D-07/D-08 por HTTP, sobre ciclos reais com resultados ML trocados entre ciclos."""
    original_load, original_build = main.ml_anomalies.load_model, main.ml_anomalies.build_ml_anomalies_report
    original_indexer = main.indexer_client.get_recent_alerts
    tmp = tempfile.TemporaryDirectory()
    try:
        log_path, vaccines_path = wire(tmp.name)
        incident_ingest.ingest_raw_alerts(main.incident_store, [raw_alert("a3", 970, 4672)], log_path, SCENARIOS)

        # --- ML completo: ataque 3 partial ---
        set_ml(ML_RESULTS)
        asyncio.run(main._run_vaccine_cycle())
        check("historico: ML completo -> lista por omissão [vac-bd617cce8054, vac-5fe3861aa2a3]",
              ids_of("/api/vaccines") == ["vac-bd617cce8054", "vac-5fe3861aa2a3"])

        # --- D-06: o ataque 3 passa a not_detected ---
        set_ml(ML_RESULTS[:1])
        result = asyncio.run(main._run_vaccine_cycle())
        check("D-06: ciclo sem a linha do ataque 3 -> inserted 1 e existing 1",
              result["counts"]["inserted"] == 1 and result["counts"]["existing"] == 1)
        r = client.get("/api/vaccines", headers=HEADERS)
        check("D-06: por omissão só a atual do ataque 3 (vac-3eb8018acb1c) + a do ataque 2, total 2",
              [v["id"] for v in r.json()["vaccines"]] == ["vac-3eb8018acb1c", "vac-5fe3861aa2a3"]
              and r.json()["total"] == 2)
        r = client.get("/api/vaccines?include_superseded=true", headers=HEADERS)
        body = r.json()
        by_id = {v["id"]: v for v in body["vaccines"]}
        check("D-06: include_superseded=true -> 3 vaccines, as do ataque 3 antes da do ataque 2, total 3",
              r.status_code == 200 and body["total"] == 3
              and [v["id"] for v in body["vaccines"]][2] == "vac-5fe3861aa2a3"
              and {v["id"] for v in body["vaccines"][:2]} == {"vac-bd617cce8054", "vac-3eb8018acb1c"})
        check("D-06: vac-bd617cce8054 tem superseded_by vac-3eb8018acb1c e state proposed",
              by_id["vac-bd617cce8054"]["superseded_by"] == "vac-3eb8018acb1c"
              and by_id["vac-bd617cce8054"]["state"] == "proposed")
        r = client.get("/api/vaccines/vac-bd617cce8054", headers=HEADERS)
        check("D-06: o detalhe da substituída continua a dar 200 com superseded_by",
              r.status_code == 200 and r.json()["vaccine"]["superseded_by"] == "vac-3eb8018acb1c")

        # --- filtros (D-08) ---
        check("filtro attack_id=3 -> só vac-3eb8018acb1c", ids_of("/api/vaccines?attack_id=3") == ["vac-3eb8018acb1c"])
        r = client.get("/api/vaccines?attack_id=3&include_superseded=true", headers=HEADERS)
        check("filtro attack_id=3&include_superseded=true -> 2 vaccines do ataque 3",
              r.json()["total"] == 2 and all(v["origin"]["attack_id"] == 3 for v in r.json()["vaccines"]))
        check("filtro technique=T1087 -> só vac-5fe3861aa2a3", ids_of("/api/vaccines?technique=T1087") == ["vac-5fe3861aa2a3"])
        r = client.get("/api/vaccines?technique=T1053&include_superseded=true", headers=HEADERS)
        check("filtro technique=T1053&include_superseded=true -> total 2", r.json()["total"] == 2)
        r = client.get("/api/vaccines?attack_id=999", headers=HEADERS)
        body = r.json()
        check("filtro sem resultados (store não vazio) -> 200, vaccines [], total 0, reason None, available True",
              r.status_code == 200 and body["vaccines"] == [] and body["total"] == 0
              and body["reason"] is None and body["available"] is True)
        r = client.get("/api/vaccines?attack_id=3&limit=1&offset=0&include_superseded=true", headers=HEADERS)
        check("o total conta com os mesmos filtros (limit=1 mas total 2)",
              len(r.json()["vaccines"]) == 1 and r.json()["total"] == 2)

        # --- vaivém: o ataque 3 volta a partial ---
        set_ml(ML_RESULTS)
        asyncio.run(main._run_vaccine_cycle())
        check("vaivém: a atual do ataque 3 volta a ser vac-bd617cce8054",
              ids_of("/api/vaccines") == ["vac-bd617cce8054", "vac-5fe3861aa2a3"])
        r = client.get("/api/vaccines?include_superseded=true", headers=HEADERS)
        by_id = {v["id"]: v for v in r.json()["vaccines"]}
        check("vaivém: vac-3eb8018acb1c com superseded_by vac-bd617cce8054 e include_superseded continua com 3",
              r.json()["total"] == 3 and by_id["vac-3eb8018acb1c"]["superseded_by"] == "vac-bd617cce8054"
              and by_id["vac-bd617cce8054"]["superseded_by"] is None)

        # --- D-07: o ataque 2 passa a detected, a vaccine fica ---
        before = client.get("/api/vaccines/vac-5fe3861aa2a3", headers=HEADERS).json()["vaccine"]
        set_ml(ML_RESULTS + [ml_row(1980, 5140, True, True)])
        asyncio.run(main._run_vaccine_cycle())
        listed = {v["id"]: v for v in client.get("/api/vaccines", headers=HEADERS).json()["vaccines"]}
        check("D-07: ataque 2 detected -> vac-5fe3861aa2a3 continua na lista por omissão",
              "vac-5fe3861aa2a3" in listed)
        after = listed["vac-5fe3861aa2a3"]
        check("D-07: igual byte a byte, superseded_by None e state proposed",
              json.dumps(after, sort_keys=True) == json.dumps(before, sort_keys=True)
              and after["superseded_by"] is None and after["state"] == "proposed")
        check("D-07: include_superseded=true continua com 3",
              client.get("/api/vaccines?include_superseded=true", headers=HEADERS).json()["total"] == 3)

        # --- 422 nos filtros ---
        for bad in ("attack_id=0", "attack_id=abc", "attack_id=1000000000", "technique=T11", "technique=t1110",
                    "technique=../../etc", "include_superseded=talvez"):
            check(f"filtro inválido ({bad}) -> 422",
                  client.get(f"/api/vaccines?{bad}", headers=HEADERS).status_code == 422)
    finally:
        main.ml_anomalies.load_model, main.ml_anomalies.build_ml_anomalies_report = original_load, original_build
        main.indexer_client.get_recent_alerts = original_indexer
        tmp.cleanup()


def snapshot_store(store: VaccineStore, path: str) -> tuple:
    """Estado completo do store lido diretamente (não pela rota): linhas com payload,
    superseded_by e state, mais um SELECT COUNT(*) ao ficheiro."""
    rows, total, store_total = store.list_vaccines(include_superseded=True, limit=500)
    return json.dumps(rows, sort_keys=True), total, store_total, count_rows(path)


def run_guarantees() -> None:
    """D-09/D-10: sem rota de escrita, API key em cada rota, estado sempre proposed,
    503 estável sem fuga de texto de exceção nem de caminho, 422/401."""
    original_load, original_build = main.ml_anomalies.load_model, main.ml_anomalies.build_ml_anomalies_report
    original_indexer = main.indexer_client.get_recent_alerts
    tmp = tempfile.TemporaryDirectory()
    try:
        log_path, vaccines_path = wire(tmp.name)
        incident_ingest.ingest_raw_alerts(main.incident_store, [raw_alert("a3", 970, 4672)], log_path, SCENARIOS)
        set_ml(ML_RESULTS)
        asyncio.run(main._run_vaccine_cycle())
        set_ml(ML_RESULTS[:1])
        asyncio.run(main._run_vaccine_cycle())
        real_store = main.vaccine_store
        check("garantias: o store de partida tem 3 linhas (uma substituída)", count_rows(vaccines_path) == 3)

        # --- D-10: nenhum método de escrita ---
        before = snapshot_store(real_store, vaccines_path)
        for path in ("/api/vaccines", "/api/vaccines/vac-5fe3861aa2a3"):
            for method in ("POST", "PUT", "PATCH", "DELETE"):
                r = client.request(method, path, headers=HEADERS, json={"state": "applied"})
                check(f"{method} {path} com chave -> 405", r.status_code == 405)
                r = client.request(method, path, json={"state": "applied"})
                check(f"{method} {path} sem chave -> 405 ou 401, nunca 2xx", r.status_code in (405, 401))
        check("depois das tentativas de escrita o store está igual (ids, payloads, superseded_by, state, linhas)",
              snapshot_store(real_store, vaccines_path) == before)

        # --- D-10: só duas rotas, só GET, API key na própria rota ---
        vaccine_routes = [r for r in main.app.routes if getattr(r, "path", "").startswith("/api/vaccines")]
        check("main.app.routes tem exatamente as rotas /api/vaccines e /api/vaccines/{vaccine_id}",
              sorted(r.path for r in vaccine_routes) == ["/api/vaccines", "/api/vaccines/{vaccine_id}"])
        check("ambas as rotas só aceitam GET/HEAD",
              all(r.methods <= {"GET", "HEAD"} and "GET" in r.methods for r in vaccine_routes))
        check("ambas têm require_api_key nas dependencies da própria rota",
              all(any(getattr(d, "dependency", None) is main.require_api_key for d in r.dependencies)
                  for r in vaccine_routes))

        # --- estado servido é sempre proposed ---
        r = client.get("/api/vaccines?include_superseded=true&limit=500", headers=HEADERS)
        served = r.json()["vaccines"]
        check("todas as vaccines servidas (incl. substituídas) têm state proposed",
              len(served) == 3 and all(v["state"] == "proposed" for v in served))

        # --- 401 com filtros ---
        for path in ("/api/vaccines?attack_id=3&include_superseded=true", "/api/vaccines/vac-5fe3861aa2a3"):
            check(f"GET {path} sem chave -> 401", client.get(path).status_code == 401)
            check(f"GET {path} com chave errada -> 401",
                  client.get(path, headers={"X-API-Key": "errada"}).status_code == 401)

        # --- 422 no detalhe ---
        for bad in ("abc", "vac-XYZ", "vac-0123456789ab0", "VAC-0123456789ab", "vac-0123456789AB"):
            r = client.get(f"/api/vaccines/{bad}", headers=HEADERS)
            check(f"detalhe com id malformado ({bad}) -> 422", r.status_code == 422)
        r = client.get("/api/vaccines/vac-0123456789ab/x", headers=HEADERS)
        check("detalhe com sub-caminho -> 404 (não chega à rota)", r.status_code == 404)
        check("id malformado sem chave -> 401 (a chave é verificada primeiro)",
              client.get("/api/vaccines/abc").status_code == 401)

        # --- 503 estável com store mockado ---
        for exc in (sqlite3.OperationalError("db partida C:\\segredo\\vaccines.sqlite3"),
                    ValueError("payload corrompido C:\\segredo")):
            broken = MagicMock()
            broken.list_vaccines.side_effect = exc
            broken.get_vaccine.side_effect = exc
            main.vaccine_store = broken
            for path in ("/api/vaccines", "/api/vaccines/vac-5fe3861aa2a3"):
                r = client.get(path, headers=HEADERS)
                leaked = [w for w in ("db partida", "payload corrompido", "segredo", ".sqlite3", "Traceback")
                          if w in r.text]
                check(f"{type(exc).__name__}: {path} -> 503 {{'detail': 'store_unavailable'}} sem fuga",
                      r.status_code == 503 and r.json() == {"detail": "store_unavailable"} and leaked == [])
        main.vaccine_store = real_store

        # --- 503 real: ficheiro que não é SQLite ---
        bad_path = os.path.join(tmp.name, "nao_e_sqlite.sqlite3")
        with open(bad_path, "wb") as handle:
            handle.write(b"isto nao e sqlite" * 100)
        main.vaccine_store = VaccineStore(bad_path)
        for path in ("/api/vaccines", "/api/vaccines/vac-5fe3861aa2a3"):
            r = client.get(path, headers=HEADERS)
            check(f"ficheiro não-SQLite: {path} -> 503 store_unavailable sem caminho nem .sqlite3",
                  r.status_code == 503 and r.json() == {"detail": "store_unavailable"}
                  and ".sqlite3" not in r.text and tmp.name not in r.text and "nao_e_sqlite" not in r.text)
        main.vaccine_store = real_store
        check("o store real continua a servir depois dos casos de erro",
              client.get("/api/vaccines", headers=HEADERS).status_code == 200)
    finally:
        main.vaccine_store = real_store if "real_store" in locals() else main.vaccine_store
        main.ml_anomalies.load_model, main.ml_anomalies.build_ml_anomalies_report = original_load, original_build
        main.indexer_client.get_recent_alerts = original_indexer
        tmp.cleanup()


if __name__ == "__main__":
    run_tracer()
    print()
    run_history()
    print()
    run_guarantees()
    print()
    if failures:
        print(f"{len(failures)} verificação(ões) falharam:")
        for label in failures:
            print(f"  - {label}")
        sys.exit(1)
    print("Todas as verificações passaram.")
