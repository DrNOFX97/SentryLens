"""
Testes do Attack Registry (R4): attack_registry (puro) e as rotas
GET /api/attacks e GET /api/attacks/{id} com TestClient, attack_log
temporário, Indexer/modelo ML falsos e base de incidentes temporária.
Sem laboratório Wazuh. Só IPs de documentação (192.0.2.x / 203.0.113.x).

Correr (a partir de scripts/):
    python test_attack_registry.py
"""

import json
import pickle
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

os.environ.setdefault("SENTRYLENS_API_KEY", "test-key-attack-registry")

from fastapi.testclient import TestClient

import attack_registry
import incident_ingest
import main
from attack_scenarios import SCENARIOS
from incident_store import IncidentStore

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


# Log "moderno" com 4 ataques lançados + ruído (failed, cenário desconhecido, não-dict).
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


def run_pure() -> None:
    reg = attack_registry.build_attack_registry(ATTACKS, SCENARIOS, ML_RESULTS)
    by_id = {a["id"]: a for a in reg["attacks"]}
    check("puro: só os 4 ataques lançados com cenário conhecido entram", sorted(by_id) == [1, 2, 3, 4])
    check("puro: skipped conta failed e cenário desconhecido", reg["skipped"] == {"not_executed": 1, "unknown_scenario": 1, "invalid": 0})
    check("puro: ordenado do mais recente para o mais antigo", [a["id"] for a in reg["attacks"]] == [4, 3, 2, 1])
    a1, a2, a3, a4 = by_id[1], by_id[2], by_id[3], by_id[4]
    check("puro: técnica/ferramenta reais do log (T1110/hydra), não inventadas", a1["mitre_technique"] == "T1110"
          and a1["technique_source"] == "log" and a1["tool"] == "hydra" and a1["tool_source"] == "log")
    check("puro: operador e origem do log", a1["operator"] == "alice" and a1["source"] == "203.0.113.50")
    check("puro: ataque 1 detected por regra+ML", a1["actual"]["verdict"] == "detected" and a1["actual"]["detected_by"] == "both")
    check("puro: ataque 1 evidência = referências (event ids + contagem)",
          a1["evidence"]["matched_event_ids"] == [4625] and a1["evidence"]["matched_alert_count"] == 1)
    check("puro: ataque 2 sem alertas -> not_detected explícito", a2["actual"]["verdict"] == "not_detected"
          and a2["actual"]["achieved"] == [] and a2["actual"]["mttd_seconds"] is None)
    check("puro: ataque 3 só regra -> partial", a3["actual"]["verdict"] == "partial" and a3["actual"]["achieved"] == ["rule"])
    check("puro: operador por omissão 'unknown' e source null", a2["operator"] == "unknown" and a2["source"] is None)
    check("puro: esperado por omissão do cenário", a2["expected"]["detection"] == ["rule", "ml"]
          and a2["expected"]["source"] == "scenario_default" and a2["expected"]["event_ids"] == [5140, 5145])
    check("puro: expected do log filtra valores fora da allowlist", a4["expected"]["detection"] == ["network"]
          and a4["expected"]["source"] == "log")
    check("puro: ataque 4 sem técnica no log usa a do cenário, assinalado", a4["mitre_technique"] == "T1110.003"
          and a4["technique_source"] == "scenario")
    check("puro: ataque 4 (alvo sem alertas nem rede) -> not_detected", a4["actual"]["verdict"] == "not_detected")
    s = attack_registry.summarize(reg["attacks"])
    check("puro: summary soma 4 (1 detected, 1 partial, 2 not_detected)",
          s == {"total": 4, "detected": 1, "partial": 1, "not_detected": 2, "unknown": 0})

    # rede esperada e detetada
    net = [{"type": "port_scan", "src_ip": "203.0.113.99", "dst_ip": OTHER, "timestamp": ts(480)}]
    reg_net = attack_registry.build_attack_registry(ATTACKS, SCENARIOS, ML_RESULTS, network_detections=net)
    a4n = {a["id"]: a for a in reg_net["attacks"]}[4]
    check("puro: expected=network e deteção de rede -> detected", a4n["actual"]["verdict"] == "detected"
          and a4n["evidence"]["network_detection_types"] == ["port_scan"])

    # correlação indisponível: nunca "não detetado"
    reg_off = attack_registry.build_attack_registry(ATTACKS, SCENARIOS, None, correlation_available=False)
    check("puro: sem correlação todos os vereditos são 'unknown'",
          {a["actual"]["verdict"] for a in reg_off["attacks"]} == {"unknown"})
    check("puro: sem correlação a identidade/esperado mantêm-se", {a["id"] for a in reg_off["attacks"]} == {1, 2, 3, 4}
          and all(a["expected"]["detection"] for a in reg_off["attacks"]))

    # incidentes ligados
    incs = [{"id": "INC-20261007-001", "severity": "high", "status": "NEW", "evidence_count": 2, "attack_ids": [1, "1", 99]},
            "lixo", {"id": "X", "attack_ids": None}]
    reg_inc = attack_registry.build_attack_registry(ATTACKS, SCENARIOS, ML_RESULTS, incidents=incs)
    by_inc = {a["id"]: a for a in reg_inc["attacks"]}
    check("puro: incidente ligado via attack_id (referência, sem payload)", by_inc[1]["evidence"]["incident_count"] == 2
          and by_inc[1]["incidents"][0] == {"id": "INC-20261007-001", "severity": "high", "status": "NEW", "evidence_count": 2})
    check("puro: ataque sem incidente tem lista vazia", by_inc[2]["incidents"] == [])

    # ficheiro antigo: sem id/technique/tool/operator (formato do attack_scenarios original)
    old = [{"timestamp": ts(100), "scenario": "smb_enum", "target": ASSET, "tool": "netexec", "status": "launched",
            "details": {"returncode": 0, "command": "netexec smb 192.0.2.10 --shares"}}]
    reg_old = attack_registry.build_attack_registry(old, SCENARIOS, [])
    o = reg_old["attacks"][0]
    check("puro: formato antigo lê-se (id null, técnica do cenário, operador unknown)",
          o["id"] is None and o["mitre_technique"] == "T1135" and o["operator"] == "unknown" and o["incidents"] == [])
    check("puro: 'details' do log (comando) não é exposto", "details" not in o and "command" not in json.dumps(o))

    # entradas hostis
    hostile = [
        {"id": True, "scenario": "smb_enum", "target": ASSET, "timestamp": ts(50), "status": "launched",
         "operator": "x\x00\x1b[31m" + "A" * 200, "tool": 5, "technique": ["T1"]},
        {"id": 7, "scenario": "smb_enum", "target": ASSET, "timestamp": "nao-e-data", "status": "launched"},
        {"id": 8, "scenario": "smb_enum", "target": ASSET, "timestamp": ts(40), "status": "launched"},
        {"id": 8, "scenario": "smb_enum", "target": ASSET, "timestamp": ts(30), "status": "launched"},
        "string", 5, None, [1],
    ]
    reg_h = attack_registry.build_attack_registry(hostile, SCENARIOS, [])
    ids = [a["id"] for a in reg_h["attacks"]]
    check("puro: id booleano não conta como id; timestamp inválido vai para invalid",
          None in ids and 7 not in ids and reg_h["skipped"]["invalid"] == 5)
    h0 = next(a for a in reg_h["attacks"] if a["id"] is None)
    check("puro: operador sem controlo e ≤64 caracteres", "\x00" not in h0["operator"] and "\x1b" not in h0["operator"]
          and len(h0["operator"]) <= 64)
    check("puro: tool/technique não-string caem para o cenário", h0["tool"] == "netexec" and h0["mitre_technique"] == "T1135")
    check("puro: ids duplicados assinalados", sum(1 for a in reg_h["attacks"] if a["duplicate_id"]) == 2)
    check("puro: NEL/LS/PS removidos de operador", attack_registry.clean_text("ab c d") == "a b c d")
    reg_tr = attack_registry.build_attack_registry(ATTACKS, SCENARIOS, ML_RESULTS, alerts_truncated=True)
    check("puro: truncado -> sem deteção 'unknown', com deteção mantém-se",
          {a["id"]: a["actual"]["verdict"] for a in reg_tr["attacks"]} == {1: "detected", 2: "unknown", 3: "partial", 4: "unknown"})
    check("puro: log vazio/None não lança", attack_registry.build_attack_registry([], SCENARIOS, [])["attacks"] == []
          and attack_registry.build_attack_registry(None, SCENARIOS, None)["attacks"] == [])


def run_routes() -> None:
    tmp = tempfile.TemporaryDirectory()
    log_path = os.path.join(tmp.name, "attack_log.jsonl")
    # mistura: linhas corrompidas, vazias, JSON não-dict e entradas válidas
    write_log(log_path, ["{truncado", "", "5", "[1]", *ATTACKS, "}}}"])
    main.ATTACK_LOG_PATH = log_path
    main.incident_store = IncidentStore(os.path.join(tmp.name, "i.sqlite3"))
    main.vm_ssh_client = None

    original_load, original_build = main.ml_anomalies.load_model, main.ml_anomalies.build_ml_anomalies_report
    main.ml_anomalies.load_model = lambda _dir: (object(), object())
    main.ml_anomalies.build_ml_anomalies_report = lambda alerts, model, scaler: {"results": ML_RESULTS}
    main.indexer_client.get_recent_alerts = AsyncMock(return_value=[{"x": 1}])

    # --- 401 ---
    for path in ("/api/attacks", "/api/attacks/1"):
        check(f"GET {path} sem X-API-Key -> 401", client.get(path).status_code == 401)
        check(f"GET {path} com chave errada -> 401", client.get(path, headers={"X-API-Key": "errada"}).status_code == 401)

    # --- lista (incidente semeado ligado ao ataque 1) ---
    incident_ingest.ingest_raw_alerts(main.incident_store, [raw_alert("a1", 2970, 4625)], log_path, SCENARIOS)
    r = client.get("/api/attacks", headers=HEADERS)
    body = r.json()
    check("lista: 200 com 4 ataques e correlation.available", r.status_code == 200 and len(body["attacks"]) == 4
          and body["correlation"]["available"] is True and body["incidents_available"] is True)
    check("lista: linhas corrompidas ignoradas, skipped reflete failed+desconhecido",
          body["skipped"]["not_executed"] == 1 and body["skipped"]["unknown_scenario"] == 1)
    check("lista: summary", body["summary"] == {"total": 4, "detected": 1, "partial": 1, "not_detected": 2, "unknown": 0})
    a1 = next(a for a in body["attacks"] if a["id"] == 1)
    check("lista: ataque 1 com incidente ligado", a1["evidence"]["incident_count"] == 1 and a1["incidents"][0]["id"].startswith("INC-"))
    check("lista: ataque sem deteção explícito (not_detected)",
          next(a for a in body["attacks"] if a["id"] == 2)["actual"]["verdict"] == "not_detected")
    check("filtro technique=T1110 devolve só o 1", [a["id"] for a in client.get("/api/attacks?technique=T1110", headers=HEADERS).json()["attacks"]] == [1])
    check("filtro status=not_detected devolve 2 e 4", sorted(a["id"] for a in client.get("/api/attacks?status=not_detected", headers=HEADERS).json()["attacks"]) == [2, 4])
    check("filtro hours=1 mantém os 4 ataques da última hora", len(client.get("/api/attacks?hours=1", headers=HEADERS).json()["attacks"]) == 4)
    check("paginação limit=1&offset=1", len(client.get("/api/attacks?limit=1&offset=1", headers=HEADERS).json()["attacks"]) == 1)
    for bad in ("technique=../../etc", "technique=T11", "status=XYZ", "hours=0", "hours=721", "limit=501", "limit=0", "offset=-1"):
        check(f"parâmetro inválido ({bad}) -> 422", client.get(f"/api/attacks?{bad}", headers=HEADERS).status_code == 422)

    # --- detalhe ---
    r = client.get("/api/attacks/1", headers=HEADERS)
    check("detalhe: 200 com esperado vs real e incidentes", r.status_code == 200
          and r.json()["attack"]["id"] == 1 and r.json()["attack"]["actual"]["verdict"] == "detected"
          and r.json()["attack"]["incidents"] and r.json()["correlation"]["available"] is True)
    check("detalhe: ataque não detetado devolve 200 'not_detected'",
          client.get("/api/attacks/2", headers=HEADERS).json()["attack"]["actual"]["verdict"] == "not_detected")
    r = client.get("/api/attacks/999", headers=HEADERS)
    check("detalhe: id inexistente -> 404 genérico", r.status_code == 404 and r.json() == {"detail": "Ataque não encontrado"})
    check("detalhe: id do ataque falhado (5, não 'launched') -> 404", client.get("/api/attacks/5", headers=HEADERS).status_code == 404)
    for bad in ("abc", "-1", "1.5", "1234567890", "1%3B2", "%2E%2E%2Fattack_log.jsonl", "..", "0x1"):
        status = client.get(f"/api/attacks/{bad}", headers=HEADERS).status_code
        check(f"detalhe: id malformado ({bad}) -> 404/422, nunca 200/500", status in (404, 422))
    check("detalhe: id com barra não chega à rota (404)", client.get("/api/attacks/1/2", headers=HEADERS).status_code == 404)

    # --- Indexer em baixo: 200, 'unknown', sem fuga ---
    main.indexer_client.get_recent_alerts = AsyncMock(side_effect=RuntimeError("segredo-interno C:\\caminho\\x"))
    r = client.get("/api/attacks", headers=HEADERS)
    check("Indexer em baixo: 200, vereditos 'unknown', error_code estável",
          r.status_code == 200 and r.json()["correlation"] == {**r.json()["correlation"], "available": False, "error_code": "indexer_unavailable"}
          and {a["actual"]["verdict"] for a in r.json()["attacks"]} == {"unknown"})
    check("Indexer em baixo: a exceção não vaza para o cliente", "segredo-interno" not in r.text and "caminho" not in r.text)
    check("Indexer em baixo: detalhe também 200 'unknown'",
          client.get("/api/attacks/2", headers=HEADERS).json()["attack"]["actual"]["verdict"] == "unknown")
    main.indexer_client.get_recent_alerts = AsyncMock(return_value=[{"x": 1}])

    # --- modelo ML ausente ---
    def _no_model(_dir):
        raise FileNotFoundError("C:\\segredo\\modelo.pkl")
    main.ml_anomalies.load_model = _no_model
    r = client.get("/api/attacks", headers=HEADERS)
    check("sem modelo ML: 200 com error_code ml_model_unavailable e sem caminho",
          r.status_code == 200 and r.json()["correlation"]["error_code"] == "ml_model_unavailable" and "segredo" not in r.text)
    for exc in (ValueError("pickle corrompido C:\segredo"), pickle.UnpicklingError("segredo"), RuntimeError("segredo")):
        def _corrupt(_dir, _exc=exc):
            raise _exc
        main.ml_anomalies.load_model = _corrupt
        r = client.get("/api/attacks", headers=HEADERS)
        check(f"modelo ML corrompido ({type(exc).__name__}): 200 com ml_model_unavailable, sem fuga",
              r.status_code == 200 and r.json()["correlation"]["error_code"] == "ml_model_unavailable" and "segredo" not in r.text)
    main.ml_anomalies.load_model = lambda _dir: (object(), object())

    # --- alertas truncados: sem correspondência -> 'unknown' (não 'not_detected') ---
    main.ATTACK_ALERTS_SIZE = 1  # get_recent_alerts devolve 1 alerta -> truncado
    r = client.get("/api/attacks", headers=HEADERS)
    by_id = {a["id"]: a for a in r.json()["attacks"]}
    check("truncado: correlation.alerts_truncated=true", r.json()["correlation"]["alerts_truncated"] is True)
    check("truncado: sem deteção -> 'unknown' com correlation_reason=alerts_truncated",
          by_id[2]["actual"]["verdict"] == "unknown" and by_id[2]["actual"]["correlation_reason"] == "alerts_truncated"
          and by_id[4]["actual"]["verdict"] == "unknown")
    check("truncado: detected/partial mantêm-se",
          by_id[1]["actual"]["verdict"] == "detected" and by_id[3]["actual"]["verdict"] == "partial"
          and by_id[1]["actual"]["correlation_reason"] is None)
    check("truncado: detalhe também 'unknown'",
          client.get("/api/attacks/2", headers=HEADERS).json()["attack"]["actual"]["verdict"] == "unknown")
    main.ATTACK_ALERTS_SIZE = 1000

    # --- ids duplicados: detalhe = o mais antigo ---
    dup_path = os.path.join(tmp.name, "dup.jsonl")
    write_log(dup_path, [
        {"id": 20, "scenario": "smb_enum", "target": ASSET, "timestamp": ts(100), "status": "launched", "operator": "recente"},
        {"id": 20, "scenario": "smb_enum", "target": ASSET, "timestamp": ts(5000), "status": "launched", "operator": "antigo"},
        {"id": 20, "scenario": "smb_enum", "target": ASSET, "timestamp": ts(3000), "status": "launched", "operator": "meio"},
    ])
    good_log, main.ATTACK_LOG_PATH = main.ATTACK_LOG_PATH, dup_path
    r = client.get("/api/attacks/20", headers=HEADERS)
    check("ids duplicados: detalhe devolve o mais antigo", r.status_code == 200
          and r.json()["attack"]["operator"] == "antigo" and r.json()["attack"]["duplicate_id"] is True)
    main.ATTACK_LOG_PATH = good_log

    # --- base de incidentes em baixo ---
    import sqlite3

    class BrokenStore:
        def list_incidents(self, *a, **k):
            raise sqlite3.OperationalError("disk I/O error em C:\\segredo\\i.sqlite3")
    good_store, main.incident_store = main.incident_store, BrokenStore()
    r = client.get("/api/attacks", headers=HEADERS)
    check("incidentes em baixo: 200, incidents_available=false, sem fuga",
          r.status_code == 200 and r.json()["incidents_available"] is False and "segredo" not in r.text
          and len(r.json()["attacks"]) == 4)
    main.incident_store = good_store

    # --- ataque fora da janela de alertas (> 720 h) ---
    old_path = os.path.join(tmp.name, "old.jsonl")
    old_ts = (NOW - timedelta(days=60)).isoformat()
    write_log(old_path, [{"id": 11, "scenario": "smb_enum", "target": ASSET, "timestamp": old_ts, "status": "launched"}])
    main.ATTACK_LOG_PATH = old_path
    r = client.get("/api/attacks/11", headers=HEADERS)
    check("ataque com >720 h: 200 'unknown' com attack_outside_alert_window",
          r.status_code == 200 and r.json()["attack"]["actual"]["verdict"] == "unknown"
          and r.json()["correlation"]["error_code"] == "attack_outside_alert_window")
    check("lista não inclui ataque fora da janela pedida", client.get("/api/attacks", headers=HEADERS).json()["attacks"] == [])

    # --- ficheiro antigo sem campos novos ---
    write_log(old_path, [{"timestamp": ts(100), "scenario": "smb_enum", "target": ASSET, "tool": "netexec",
                          "status": "launched", "details": {"command": "netexec smb 192.0.2.10"}}])
    r = client.get("/api/attacks", headers=HEADERS)
    check("log antigo sem id/operator: 200, id null, operador unknown",
          r.status_code == 200 and r.json()["attacks"][0]["id"] is None and r.json()["attacks"][0]["operator"] == "unknown")

    # --- log ausente e log ilegível ---
    main.ATTACK_LOG_PATH = os.path.join(tmp.name, "nao-existe.jsonl")
    r = client.get("/api/attacks", headers=HEADERS)
    check("log ausente: 200 lista vazia", r.status_code == 200 and r.json()["attacks"] == [] and r.json()["total"] == 0)
    check("log ausente: detalhe 404", client.get("/api/attacks/1", headers=HEADERS).status_code == 404)
    bad_path = os.path.join(tmp.name, "bad.jsonl")
    with open(bad_path, "wb") as handle:
        handle.write(b'{"id": 1}\n\xff\xfe\xfa\n')
    main.ATTACK_LOG_PATH = bad_path
    r = client.get("/api/attacks", headers=HEADERS)
    check("log com bytes inválidos: 500 genérico sem fuga de caminho/exceção",
          r.status_code == 500 and r.json() == {"detail": "Erro interno ao ler o registo de ataques"})
    main.ATTACK_LOG_PATH = tmp.name  # diretório em vez de ficheiro -> OSError
    r = client.get("/api/attacks", headers=HEADERS)
    check("log é um diretório: 500 genérico", r.status_code == 500 and tmp.name not in r.text)

    main.ml_anomalies.load_model, main.ml_anomalies.build_ml_anomalies_report = original_load, original_build
    tmp.cleanup()


def run_scenario_writer() -> None:
    from attack_scenarios import format_log_entry
    base = format_log_entry("smb_enum", ASSET, "netexec", "launched")
    check("attack_scenarios: sem campos novos o formato não muda",
          set(base) == {"timestamp", "scenario", "target", "tool", "status", "details"})
    full = format_log_entry("smb_enum", ASSET, "netexec", "launched", operator="alice", source="203.0.113.50",
                            expected=["rule", "network"])
    check("attack_scenarios: operator/source/expected opcionais gravados",
          full["operator"] == "alice" and full["source"] == "203.0.113.50" and full["expected"] == ["rule", "network"])
    reg = attack_registry.build_attack_registry([full], SCENARIOS, [])
    check("attack_scenarios -> registry: ida e volta", reg["attacks"][0]["operator"] == "alice"
          and reg["attacks"][0]["expected"]["detection"] == ["rule", "network"])


if __name__ == "__main__":
    run_pure()
    run_routes()
    run_scenario_writer()
    print()
    if failures:
        print(f"{len(failures)} verificação(ões) falharam:")
        for label in failures:
            print(f"  - {label}")
        sys.exit(1)
    print("Todas as verificações passaram.")
