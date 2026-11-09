"""
Testes do tipo comum de deteção (R7): os 3 construtores puros de
detection_event.py — from_rule_alert/from_ml_anomaly/from_network_detection.
Sem I/O. Espelha os fixtures de test_incident_engine.py para
evidence_from_raw_alert/evidence_from_network_detection, para confirmar a
equivalência que o refactor de incident_engine.py assume (ver
docs/superpowers/specs/2026-10-07-r7-detection-engine-design.md).

Correr (a partir de scripts/):
    python test_detection_event.py
"""

import sys

from detection_event import DetectionEvent, from_ml_anomaly, from_network_detection, from_rule_alert

failures: list[str] = []

# Event IDs de event_catalog.py: 4625=high, 4720=medium, 4722=low; sem Event ID = info
HIGH, MEDIUM, LOW = 4625, 4720, 4722
# As 9 anotações de DetectionEvent antes da Phase 18 (R16).
OLD_DETECTION_KEYS = {"source", "severity", "asset", "ts", "technique", "confidence", "ref", "label", "description"}
ASSET = "192.168.1.169"


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


WAZUH_TACTICS_REAL = ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access", "Lateral Movement"]
T1078_TACTICS = ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"]


def raw_alert(alert_id, ts, ip=ASSET, event_id=None, mitre=None) -> dict:
    alert = {
        "_id": alert_id, "@timestamp": ts,
        "agent": {"name": "FARENSE1910", "ip": ip}, "rule": {"id": "60122", "level": 5},
    }
    if event_id is not None:
        alert["data"] = {"win": {"system": {"eventID": str(event_id)}}}
    if mitre is not None:
        alert["rule"]["mitre"] = mitre
    return alert


def run_from_rule_alert() -> None:
    e = from_rule_alert(raw_alert("a1", "2026-10-06T10:00:00Z", event_id=HIGH))
    check("alerta válido vira DetectionEvent source=rule", e is not None and e["source"] == "rule")
    check("asset = agent.ip", e["asset"] == ASSET)
    check("severidade vem do event_catalog (4625=high)", e["severity"] == "high")
    check("ts normalizado com fuso (Z -> +00:00)", e["ts"] == "2026-10-06T10:00:00+00:00")
    check("ref é o alerta bruto, não cópia", e["ref"] is not None and e["ref"].get("_id") == "a1")
    check("label é o nome amigável do Event ID", e["label"] == "Failed Logon")
    check("4625 sem rule.mitre: technique T1110 pelo catálogo", e["technique"] == "T1110")
    check("4625 sem rule.mitre: technique_source catalog", e["technique_source"] == "catalog")
    check(
        "4625 sem rule.mitre: techniques com a tática da tabela",
        e["techniques"] == [{"id": "T1110", "source": "catalog", "tactics": ["Credential Access"]}],
    )
    check("confidence fica None (ruling 2, R7)", e["confidence"] is None)
    w = from_rule_alert(raw_alert(
        "a3", "2026-10-06T10:00:00Z", event_id=HIGH,
        mitre={"id": ["T1078", "T1021"], "tactic": WAZUH_TACTICS_REAL}))
    check("rule.mitre: technique é a 1.ª (T1078)", w["technique"] == "T1078")
    check("rule.mitre: technique_source wazuh", w["technique_source"] == "wazuh")
    check("rule.mitre substitui o catálogo (sem T1110)", [t["id"] for t in w["techniques"]] == ["T1078", "T1021"])
    check("táticas de T1078 vêm da tabela", w["techniques"][0]["tactics"] == T1078_TACTICS)
    check("táticas de T1021 vêm da tabela", w["techniques"][1]["tactics"] == ["Lateral Movement"])
    check("com rule.mitre o 4625 mantém severity high", w["severity"] == "high")
    check("com rule.mitre o 4625 mantém label Failed Logon", w["label"] == "Failed Logon")
    sem_event_id = from_rule_alert(raw_alert("a2", "2026-10-06T10:00:00Z"))
    check("alerta sem Event ID Windows é info", sem_event_id["severity"] == "info")
    check("sem Event ID e sem rule.mitre: technique None", sem_event_id["technique"] is None)
    check("sem Event ID e sem rule.mitre: technique_source None", sem_event_id["technique_source"] is None)
    check("sem Event ID e sem rule.mitre: techniques []", sem_event_id["techniques"] == [])
    for label, bad in [
        ("sem timestamp", raw_alert("x", None)),
        ("com timestamp inválido", raw_alert("x", "ontem")),
        ("sem agent.ip", {**raw_alert("x", "2026-10-06T10:00:00Z"), "agent": {"name": "n"}}),
        ("com agent que não é dict", {**raw_alert("x", "2026-10-06T10:00:00Z"), "agent": "n"}),
        ("que não é dict", "lixo"),
        ("None", None),
    ]:
        check(f"alerta {label} -> None sem lançar", from_rule_alert(bad) is None)
    # Nota: from_rule_alert não exige _id (isso é um conceito de
    # incident_engine.key, não de DetectionEvent) — um alerta sem _id mas
    # com timestamp/asset válidos continua a normalizar.
    sem_id = from_rule_alert({**raw_alert("x", "2026-10-06T10:00:00Z", event_id=HIGH), "_id": None})
    check("alerta sem _id ainda normaliza (key é um conceito de incidente, não de DetectionEvent)", sem_id is not None)


def run_from_network_detection() -> None:
    det = {"type": "port_scan", "src_ip": "192.168.1.170", "dst_ip": ASSET,
           "timestamp": "2026-10-06T10:00:05+00:00", "detail": {"distinct_ports": 16}}
    n = from_network_detection(det)
    check("deteção de rede vira DetectionEvent source=network", n is not None and n["source"] == "network")
    check("asset = dst_ip", n["asset"] == ASSET)
    check("port_scan tem severidade medium", n["severity"] == "medium")
    check("rede: techniques [] e technique_source None", n["techniques"] == [] and n["technique_source"] is None)
    check("rede: technique None", n["technique"] is None)
    check("label == type", n["label"] == "port_scan")
    check("ref é a deteção bruta, não cópia", n["ref"] is det)
    spike = from_network_detection(
        {"type": "volume_spike", "src_ip": "192.168.1.170", "dst_ip": None,
         "timestamp": "2026-10-06T10:00:05+00:00", "detail": {}})
    check("volume_spike (dst_ip=None) usa src_ip como asset", spike["asset"] == "192.168.1.170")
    check("volume_spike tem severidade low", spike["severity"] == "low")
    novo = from_network_detection({**det, "type": "tipo_novo"})
    check("tipo desconhecido cai para low", novo["severity"] == "low")
    for label, bad in [("sem timestamp", {**det, "timestamp": None}), ("sem type", {**det, "type": None}),
                       ("sem IPs", {**det, "src_ip": None, "dst_ip": None}), ("não-dict", 42)]:
        check(f"deteção {label} -> None sem lançar", from_network_detection(bad) is None)


def ml_result(ts="2026-10-06T10:00:00Z", agent_ip=ASSET, is_anomaly=True, score=-0.3, severity="high") -> dict:
    return {
        "timestamp": ts, "agent_name": "FARENSE1910", "agent_ip": agent_ip, "target_user": "jsilva",
        "windows_event_id": HIGH, "severity": severity, "rule_flagged": True,
        "ml_score": score, "ml_is_anomaly": is_anomaly, "agreement": "agree",
    }


def run_from_ml_anomaly() -> None:
    e = from_ml_anomaly(ml_result())
    check("resultado ML anómalo vira DetectionEvent source=ml", e is not None and e["source"] == "ml")
    check("asset = agent_ip", e["asset"] == ASSET)
    check("severity vem do próprio resultado", e["severity"] == "high")
    check("ts normalizado com fuso", e["ts"] == "2026-10-06T10:00:00+00:00")
    check("ref é o próprio resultado, não cópia", e["ref"] is not None and e["ref"].get("agent_ip") == ASSET)
    check("description menciona o ml_score em bruto", "ml_score=-0.3" in (e["description"] or ""))
    check("technique fica None (ruling 2, R7)", e["technique"] is None)
    check("ML: techniques [] e technique_source None", e["techniques"] == [] and e["technique_source"] is None)
    check("confidence fica None (ruling 2, R7) — ml_score NÃO é uma probabilidade calibrada", e["confidence"] is None)

    nao_anomalo = from_ml_anomaly(ml_result(is_anomaly=False))
    check("resultado ML não-anómalo não vira evento (não é uma deteção)", nao_anomalo is None)

    sem_severity = from_ml_anomaly({**ml_result(), "severity": None})
    check("severity ausente cai para 'info'", sem_severity["severity"] == "info")

    for label, bad in [
        ("sem timestamp", {**ml_result(), "timestamp": None}),
        ("com timestamp inválido", {**ml_result(), "timestamp": "ontem"}),
        ("não-dict", "lixo"),
        ("None", None),
    ]:
        check(f"resultado ML {label} -> None sem lançar", from_ml_anomaly(bad) is None)


def run_annotations() -> None:
    check("anotações = as 9 antigas + techniques + technique_source",
          set(DetectionEvent.__annotations__) == OLD_DETECTION_KEYS | {"techniques", "technique_source"})
    regra = from_rule_alert(raw_alert("a1", "2026-10-06T10:00:00Z", event_id=HIGH))
    ml = from_ml_anomaly(ml_result())
    rede = from_network_detection({"type": "port_scan", "src_ip": "192.168.1.170", "dst_ip": ASSET,
                                   "timestamp": "2026-10-06T10:00:05+00:00", "detail": {}})
    for nome, ev in [("regra", regra), ("ml", ml), ("rede", rede)]:
        check(f"chaves do evento {nome} == anotações do DetectionEvent", set(ev) == set(DetectionEvent.__annotations__))


def run() -> None:
    run_from_rule_alert()
    run_from_network_detection()
    run_from_ml_anomaly()
    run_annotations()

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")


if __name__ == "__main__":
    run()
