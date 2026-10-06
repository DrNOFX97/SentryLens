"""
Testes do ingest de incidentes (R3): liga o motor puro à persistência.
Bases e attack_log temporários; modelo de ML falso.

Correr (a partir de scripts/):
    python test_incident_ingest.py
"""

import json
import os
import sys
import tempfile
import threading

import ml_anomalies
from attack_scenarios import SCENARIOS
from incident_ingest import ingest_network_detections, ingest_raw_alerts, ml_summary
from incident_store import IncidentStore

failures: list[str] = []
HIGH, LOW = 4625, 4722
ASSET = "192.168.1.169"
NOW = "2026-10-06T12:00:00+00:00"


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def raw(alert_id, ts, event_id=None, ip=ASSET) -> dict:
    alert = {"_id": alert_id, "@timestamp": ts, "agent": {"name": "FARENSE1910", "ip": ip}, "rule": {"id": "1", "level": 5}}
    if event_id is not None:
        alert["data"] = {"win": {"system": {"eventID": str(event_id)}}}
    return alert


class FakeScaler:
    def transform(self, vectors):
        return vectors


class FakeModel:
    def decision_function(self, scaled):
        return [-0.2] * len(scaled)

    def predict(self, scaled):
        return [-1] * len(scaled)


def run() -> None:
    tmp = tempfile.TemporaryDirectory()
    log_path = os.path.join(tmp.name, "attack_log.jsonl")
    with open(log_path, "w", encoding="utf-8") as f:
        f.write(json.dumps({"id": 7, "scenario": "brute_force_rdp", "target": ASSET,
                            "timestamp": "2026-10-06T10:00:00Z", "status": "launched",
                            "technique": "T1003", "tool": "mimikatz"}) + "\n")
        f.write('{"scenario": "smb_enum", "target"')  # linha truncada a meio de um append

    def new_store(name="i.sqlite3"):
        return IncidentStore(os.path.join(tmp.name, name))

    # --- caminho feliz: high abre, low/info anexam, ataque ligado ---
    store = new_store()
    alerts = [raw("a1", "2026-10-06T10:00:10Z", HIGH), raw("a2", "2026-10-06T10:02:00Z", LOW),
              raw("a3", "2026-10-06T10:03:00Z"), raw("a4", "2026-10-06T10:03:30Z", LOW, ip="192.168.1.50")]
    counts = ingest_raw_alerts(store, alerts, log_path, SCENARIOS, NOW)
    check("1 incidente aberto, 2 anexados, 1 ignorado (low de outro ativo)",
          counts == {"opened": 1, "attached": 2, "duplicate": 0, "ignored": 1, "invalid": 0})
    incidents = store.list_incidents()
    check("só existe 1 incidente", len(incidents) == 1)
    inc = store.get_incident(incidents[0]["id"])
    check("incidente tem as 3 evidências do mesmo ativo", len(inc["evidence"]) == 3)
    check("ataque 7 ligado: técnica e id do log (linha truncada ignorada)",
          inc["attack_ids"] == [7] and inc["techniques"] == ["T1003"])
    check("MTTD = 1.ª evidência - ataque (10 s)", inc["mttd_seconds"] == 10.0)
    links = [e for e in inc["timeline"] if e["kind"] == "attack_linked"]
    check("o ataque só é ligado uma vez, apesar de 3 evidências na janela", len(links) == 1)

    # --- idempotência ---
    again = ingest_raw_alerts(store, alerts, log_path, SCENARIOS, NOW)
    check("2.ª corrida: tudo duplicate (ou ignorado), nada novo",
          again["opened"] == 0 and again["attached"] == 0 and again["duplicate"] == 3)
    check("2.ª corrida não cria incidentes nem evidências", len(store.list_incidents()) == 1
          and len(store.get_incident(incidents[0]["id"])["evidence"]) == 3)

    # --- independência da ordem de chegada ---
    store_rev = new_store("rev.sqlite3")
    ingest_raw_alerts(store_rev, list(reversed(alerts)), log_path, SCENARIOS, NOW)
    check("ordem inversa dá o mesmo resultado (1 incidente, 3 evidências)",
          len(store_rev.list_incidents()) == 1 and store_rev.list_incidents()[0]["evidence_count"] == 3)

    # --- dois surtos separados por 30 min -> 2 incidentes ---
    store2 = new_store("dois.sqlite3")
    ingest_raw_alerts(store2, [raw("b1", "2026-10-06T10:00:00Z", HIGH), raw("b2", "2026-10-06T10:30:00Z", HIGH)],
                      log_path, SCENARIOS, NOW)
    check("surtos a 30 min de distância abrem 2 incidentes", len(store2.list_incidents()) == 2)

    # --- Review Focus 1: rajada de alertas info/low não abre incidentes e é rápida ---
    store3 = new_store("flood.sqlite3")
    flood = [raw(f"f{i}", f"2026-10-06T10:{i // 60:02d}:{i % 60:02d}Z", LOW if i % 2 else None) for i in range(500)]
    counts = ingest_raw_alerts(store3, flood, log_path, SCENARIOS, NOW)
    check("rajada de 500 alertas info/low: 0 incidentes", store3.list_incidents() == [] and counts["opened"] == 0)
    check("rajada: todos ignorados", counts["ignored"] == 500)

    # --- Review Focus 2: alertas malformados nunca lançam ---
    store4 = new_store("mal.sqlite3")
    counts = ingest_raw_alerts(store4, ["lixo", None, {"_id": "x"}, raw(None, "2026-10-06T10:00:00Z", HIGH),
                                        raw("ok1", "2026-10-06T10:00:00Z", HIGH)], log_path, SCENARIOS, NOW)
    check("malformados contam em invalid e o válido abre incidente", counts["invalid"] == 4 and counts["opened"] == 1)
    check("None/lista vazia não lançam", ingest_raw_alerts(store4, None, log_path, SCENARIOS)["opened"] == 0
          and ingest_raw_alerts(store4, [], log_path, SCENARIOS)["opened"] == 0)

    # --- Review Focus 5: attack_log ausente não impede incidentes ---
    store5 = new_store("semlog.sqlite3")
    counts = ingest_raw_alerts(store5, [raw("c1", "2026-10-06T10:00:10Z", HIGH)],
                               os.path.join(tmp.name, "nao-existe.jsonl"), SCENARIOS, NOW)
    inc5 = store5.get_incident(store5.list_incidents()[0]["id"])
    check("sem attack_log: incidente criado, sem ataque ligado", counts["opened"] == 1 and inc5["attack_ids"] == [])

    # --- rede: abre sozinha e depois anexa alertas Wazuh do mesmo ativo ---
    store6 = new_store("rede.sqlite3")
    det = {"type": "port_scan", "src_ip": "192.168.1.170", "dst_ip": ASSET,
           "timestamp": "2026-10-06T10:00:05+00:00", "detail": {"distinct_ports": 16}}
    counts = ingest_network_detections(store6, [det, {"type": None}], log_path, SCENARIOS, NOW)
    check("deteção de rede abre incidente; inválida conta em invalid", counts["opened"] == 1 and counts["invalid"] == 1)
    ingest_raw_alerts(store6, [raw("d1", "2026-10-06T10:01:00Z", HIGH)], log_path, SCENARIOS, NOW)
    inc6 = store6.get_incident(store6.list_incidents()[0]["id"])
    check("alerta Wazuh anexa-se ao incidente aberto pela rede (multi-fonte)",
          len(store6.list_incidents()) == 1 and sorted({e["kind"] for e in inc6["evidence"]}) == ["network_detection", "wazuh_alert"])
    check("ingest de rede repetido é duplicate",
          ingest_network_detections(store6, [det], log_path, SCENARIOS, NOW)["duplicate"] == 1)

    # --- Review Focus 6: o mesmo alerta entregue em simultâneo por várias threads ---
    store7 = new_store("conc.sqlite3")
    batch = [raw(f"k{i}", f"2026-10-06T10:00:{i:02d}Z", HIGH) for i in range(10)]
    errors: list[Exception] = []

    def worker() -> None:
        try:
            ingest_raw_alerts(store7, batch, log_path, SCENARIOS, NOW)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    check("8 threads em simultâneo não lançam", errors == [])
    check("8 threads: 1 incidente e 10 evidências (sem duplicados)",
          len(store7.list_incidents()) == 1 and store7.list_incidents()[0]["evidence_count"] == 10)

    # --- ml_summary ---
    ml_alerts = [raw("m1", "2026-10-06T10:00:00Z", HIGH), raw("m2", "2026-10-06T10:00:10Z", HIGH)]
    original = ml_anomalies.load_model
    try:
        def missing(model_dir=None):
            raise FileNotFoundError("sem modelo")
        ml_anomalies.load_model = missing
        check("ml_summary sem modelo -> None (Review Focus 4)", ml_summary(ml_alerts, tmp.name) is None)
        ml_anomalies.load_model = lambda model_dir=None: (FakeModel(), FakeScaler())
        s = ml_summary(ml_alerts, tmp.name)
        check("ml_summary com modelo falso", s == {"scored": 2, "ml_anomalies": 2, "rule_flagged": 2})
        check("ml_summary sem alertas -> None", ml_summary([], tmp.name) is None)
        check("ml_summary só com alertas sem Event ID -> scored 0",
              ml_summary([raw("m3", "2026-10-06T10:00:00Z")], tmp.name)["scored"] == 0)
    finally:
        ml_anomalies.load_model = original

    tmp.cleanup()

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")


if __name__ == "__main__":
    run()
