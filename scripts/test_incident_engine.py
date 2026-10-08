"""
Testes do motor puro de incidentes (R3): normalização de evidências,
regras de agrupamento, máquina de estados e ligação a ataques. Sem I/O.

Correr (a partir de scripts/):
    python test_incident_engine.py
"""

import sys

from attack_scenarios import SCENARIOS
from incident_engine import (
    assign_evidence,
    attack_link_data,
    available_transitions,
    can_transition,
    compute_windows,
    evidence_from_network_detection,
    evidence_from_raw_alert,
    link_attacks,
    max_severity,
)

failures: list[str] = []

# Event IDs de event_catalog.py: 4625=high, 4720=medium, 4722=low; sem Event ID = info
HIGH, MEDIUM, LOW = 4625, 4720, 4722
ASSET = "192.168.1.169"


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def raw_alert(alert_id, ts, ip=ASSET, event_id=None) -> dict:
    alert = {
        "_id": alert_id, "@timestamp": ts,
        "agent": {"name": "FARENSE1910", "ip": ip}, "rule": {"id": "60122", "level": 5},
    }
    if event_id is not None:
        alert["data"] = {"win": {"system": {"eventID": str(event_id)}}}
    return alert


def ev(alert_id, ts, event_id=None, ip=ASSET) -> dict:
    return evidence_from_raw_alert(raw_alert(alert_id, ts, ip=ip, event_id=event_id))


def open_inc(inc_id, last, asset=ASSET, status="NEW") -> dict:
    return {"id": inc_id, "asset": asset, "status": status, "last_evidence_at": last}


def run() -> None:
    # --- evidence_from_raw_alert ---
    e = ev("a1", "2026-10-06T10:00:00Z", HIGH)
    check("alerta bruto válido vira evidência wazuh_alert", e is not None and e["kind"] == "wazuh_alert")
    check("key usa o _id do Wazuh", e["key"] == "alert:a1")
    check("asset = agent.ip", e["asset"] == ASSET)
    check("severidade vem do event_catalog (4625=high)", e["severity"] == "high")
    check("ts normalizado com fuso (Z -> +00:00)", e["ts"] == "2026-10-06T10:00:00+00:00")
    check("payload é o alerta bruto", e["payload"]["_id"] == "a1")
    check("alerta sem Event ID Windows é info", ev("a2", "2026-10-06T10:00:00Z")["severity"] == "info")
    for label, bad in [
        ("sem _id", {**raw_alert("x", "2026-10-06T10:00:00Z"), "_id": None}),
        ("sem timestamp", raw_alert("x", None)),
        ("com timestamp inválido", raw_alert("x", "ontem")),
        ("sem agent.ip", {**raw_alert("x", "2026-10-06T10:00:00Z"), "agent": {"name": "n"}}),
        ("com agent que não é dict", {**raw_alert("x", "2026-10-06T10:00:00Z"), "agent": "n"}),
        ("que não é dict", "lixo"),
        ("None", None),
    ]:
        check(f"alerta {label} -> None sem lançar", evidence_from_raw_alert(bad) is None)

    # --- evidence_from_network_detection ---
    det = {"type": "port_scan", "src_ip": "192.168.1.170", "dst_ip": ASSET,
           "timestamp": "2026-10-06T10:00:05+00:00", "detail": {"distinct_ports": 16}}
    n = evidence_from_network_detection(det)
    check("deteção de rede vira evidência network_detection", n is not None and n["kind"] == "network_detection")
    check("asset = dst_ip", n["asset"] == ASSET)
    check("port_scan tem severidade medium", n["severity"] == "medium")
    check("key por tipo/src/dst/minuto", n["key"] == f"net:port_scan:192.168.1.170:{ASSET}:2026-10-06T10:00")
    spike = evidence_from_network_detection(
        {"type": "volume_spike", "src_ip": "192.168.1.170", "dst_ip": None,
         "timestamp": "2026-10-06T10:00:05+00:00", "detail": {}})
    check("volume_spike (dst_ip=None) usa src_ip como asset", spike["asset"] == "192.168.1.170")
    check("volume_spike tem severidade low", spike["severity"] == "low")
    novo = evidence_from_network_detection({**det, "type": "tipo_novo"})
    check("tipo desconhecido cai para low", novo["severity"] == "low")
    for label, bad in [("sem timestamp", {**det, "timestamp": None}), ("sem type", {**det, "type": None}),
                       ("sem IPs", {**det, "src_ip": None, "dst_ip": None}), ("não-dict", 42)]:
        check(f"deteção {label} -> None sem lançar", evidence_from_network_detection(bad) is None)

    # --- assign_evidence ---
    high = ev("b1", "2026-10-06T10:05:00Z", HIGH)
    medium = ev("b2", "2026-10-06T10:05:00Z", MEDIUM)
    low = ev("b3", "2026-10-06T10:05:00Z", LOW)
    info = ev("b4", "2026-10-06T10:05:00Z")
    inc = open_inc("INC-1", "2026-10-06T10:00:00+00:00")

    check("já conhecida -> duplicate", assign_evidence(high, [], already_known=True)["action"] == "duplicate")
    check("high sem incidente aberto -> open", assign_evidence(high, [])["action"] == "open")
    check("medium sem incidente aberto -> open", assign_evidence(medium, [])["action"] == "open")
    check("low sem incidente aberto -> ignore", assign_evidence(low, [])["action"] == "ignore")
    check("info sem incidente aberto -> ignore", assign_evidence(info, [])["action"] == "ignore")
    r = assign_evidence(low, [inc])
    check("low com incidente aberto do mesmo ativo dentro do gap -> attach",
          r["action"] == "attach" and r["incident_id"] == "INC-1")
    check("info com incidente aberto dentro do gap -> attach", assign_evidence(info, [inc])["action"] == "attach")
    check("fora do gap (15 min) -> open novo",
          assign_evidence(high, [open_inc("INC-2", "2026-10-06T09:50:00+00:00")])["action"] == "open")
    check("outro ativo -> não anexa", assign_evidence(high, [open_inc("INC-3", "2026-10-06T10:00:00+00:00", asset="10.0.0.9")])["action"] == "open")
    check("incidente RESOLVED não recebe evidências",
          assign_evidence(high, [open_inc("INC-4", "2026-10-06T10:00:00+00:00", status="RESOLVED")])["action"] == "open")
    check("incidente CLOSED não recebe evidências",
          assign_evidence(high, [open_inc("INC-5", "2026-10-06T10:00:00+00:00", status="CLOSED")])["action"] == "open")
    check("incidente CONTAINED recebe evidências",
          assign_evidence(high, [open_inc("INC-6", "2026-10-06T10:00:00+00:00", status="CONTAINED")])["action"] == "attach")
    older, newer = open_inc("INC-7", "2026-10-06T10:00:00+00:00"), open_inc("INC-8", "2026-10-06T10:03:00+00:00")
    check("com dois candidatos anexa ao de atividade mais recente",
          assign_evidence(high, [older, newer])["incident_id"] == "INC-8")
    late = ev("b5", "2026-10-06T09:58:00Z", HIGH)
    check("evidência ligeiramente anterior à última, dentro do gap -> attach",
          assign_evidence(late, [inc])["action"] == "attach")
    check("rede (medium) abre incidente", assign_evidence(n, [])["action"] == "open")
    check("rede com severidade low (volume_spike) também abre", assign_evidence(spike, [])["action"] == "open")
    check("gap_seconds=60 não anexa a 5 min", assign_evidence(high, [inc], gap_seconds=60)["action"] == "open")
    check("min_open_severity=low faz low abrir", assign_evidence(low, [], min_open_severity="low")["action"] == "open")
    check("max_severity compara pela ordem info<low<medium<high<critical",
          max_severity("low", "high") == "high" and max_severity("critical", "high") == "critical"
          and max_severity("info", "info") == "info")

    # --- can_transition / available_transitions ---
    for a, b in [("NEW", "INVESTIGATING"), ("INVESTIGATING", "CONTAINED"), ("INVESTIGATING", "RESOLVED"),
                 ("CONTAINED", "RESOLVED"), ("CONTAINED", "INVESTIGATING"), ("RESOLVED", "CLOSED"),
                 ("RESOLVED", "INVESTIGATING")]:
        check(f"transição {a}->{b} é válida", can_transition(a, b) == (True, None))
    for a, b in [("NEW", "CONTAINED"), ("NEW", "RESOLVED"), ("INVESTIGATING", "NEW"), ("INVESTIGATING", "CLOSED"),
                 ("CLOSED", "NEW"), ("CLOSED", "INVESTIGATING"), ("RESOLVED", "NEW"), ("NEW", "NEW"),
                 ("NEW", "INEXISTENTE"), ("INEXISTENTE", "NEW")]:
        check(f"transição {a}->{b} é inválida", can_transition(a, b) == (False, "transicao_invalida"))
    check("NEW->CLOSED sem nota exige nota", can_transition("NEW", "CLOSED") == (False, "nota_obrigatoria"))
    check("NEW->CLOSED com nota só de espaços exige nota", can_transition("NEW", "CLOSED", "   ") == (False, "nota_obrigatoria"))
    check("NEW->CLOSED com nota é válida", can_transition("NEW", "CLOSED", "falso positivo") == (True, None))
    check("available_transitions(NEW)", available_transitions("NEW") == ("INVESTIGATING", "CLOSED"))
    check("available_transitions(CLOSED) é vazio", available_transitions("CLOSED") == ())
    check("available_transitions(desconhecido) é vazio", available_transitions("XYZ") == ())

    # --- compute_windows / link_attacks / attack_link_data ---
    log = [
        {"id": 7, "scenario": "brute_force_rdp", "target": ASSET, "timestamp": "2026-10-06T10:00:00Z",
         "status": "launched", "technique": "T1003", "tool": "mimikatz"},
        {"id": 8, "scenario": "smb_enum", "target": ASSET, "timestamp": "2026-10-06T10:02:00Z", "status": "launched"},
        {"scenario": "smb_enum", "target": ASSET, "timestamp": "2026-10-06T11:00:00Z", "status": "skipped"},
        "lixo",
    ]
    windows = compute_windows(log, SCENARIOS)
    check("compute_windows ignora skipped e lixo", len(windows) == 2)
    check("evidência dentro da janela do ataque 7", [a["id"] for a in link_attacks("2026-10-06T10:01:00+00:00", ASSET, windows)] == [7])
    check("janela do ataque 7 cortada pelo início do 8", [a["id"] for a in link_attacks("2026-10-06T10:02:30+00:00", ASSET, windows)] == [8])
    check("outro ativo não liga", link_attacks("2026-10-06T10:01:00+00:00", "10.0.0.9", windows) == [])
    check("antes do ataque não liga", link_attacks("2026-10-06T09:59:00+00:00", ASSET, windows) == [])
    check("depois da janela (300 s) não liga", link_attacks("2026-10-06T10:20:00+00:00", ASSET, windows) == [])
    check("timestamp inválido não liga nem lança", link_attacks("ontem", ASSET, windows) == [])
    check("sem ativo não liga", link_attacks("2026-10-06T10:01:00+00:00", None, windows) == [])
    check("attack_log vazio/None -> sem janelas", compute_windows(None, SCENARIOS) == [] and compute_windows([], SCENARIOS) == [])
    check("attack_link_data usa technique/tool do log",
          attack_link_data(log[0], SCENARIOS) == {
              "ref": "7", "attack_id": 7, "scenario": "brute_force_rdp", "technique": "T1003",
              "tool": "mimikatz", "attack_timestamp": "2026-10-06T10:00:00Z"})
    d8 = attack_link_data(log[1], SCENARIOS)
    check("attack_link_data cai para a técnica/ferramenta do cenário", d8["technique"] == "T1135" and d8["tool"] == "netexec")
    sem_id = attack_link_data({"scenario": "smb_enum", "target": ASSET, "timestamp": "2026-10-06T10:09:00Z", "status": "launched"}, SCENARIOS)
    check("sem id usa ref alvo@timestamp e attack_id=None",
          sem_id["ref"] == f"{ASSET}@2026-10-06T10:09:00Z" and sem_id["attack_id"] is None)

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")


if __name__ == "__main__":
    run()
