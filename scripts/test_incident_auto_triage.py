"""
Testes da triagem automática de incidentes novos: ao nascer, um incidente
passa para o Tier 1, com o analista principal do turno atual (se houver) e o
SLA da regra de escalamento. O estado fica em NEW (mudar de estado é sempre
humano) e só incidentes abertos pelo ingest AO VIVO (auto_triage=True) são
tratados, nunca o backfill histórico nem os que só recebem evidências.

Correr (a partir de scripts/):
    python test_incident_auto_triage.py
"""

import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

os.environ.setdefault("SENTRYLENS_API_KEY", "chave-de-teste-nao-usar-em-producao")

from attack_scenarios import SCENARIOS
from incident_ingest import ingest_raw_alerts
from incident_store import IncidentStore

failures: list[str] = []
HIGH, LOW = 4625, 4722
ASSET = "192.168.1.169"
NOW = "2026-10-06T12:00:00+00:00"
SLA_60 = (datetime.fromisoformat(NOW) + timedelta(minutes=60)).isoformat()


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def raw(alert_id, ts, event_id=None, ip=ASSET) -> dict:
    alert = {"_id": alert_id, "@timestamp": ts, "agent": {"name": "FARENSE1910", "ip": ip}, "rule": {"id": "1", "level": 5}}
    if event_id is not None:
        alert["data"] = {"win": {"system": {"eventID": str(event_id)}}}
    return alert


def equipa(store, *, turno=True, regra=True) -> None:
    store.create_analyst("analyst-soc1", "Eddie", 1, None, NOW)
    store.create_analyst("analyst-soc2", "Jeremy", 2, None, NOW)
    if turno:
        store.create_shift("analyst-soc1", "2026-10-06T00:00:00+00:00", "2026-10-06T23:59:00+00:00", "primary", NOW)
        store.create_shift("analyst-soc2", "2026-10-06T00:00:00+00:00", "2026-10-06T23:59:00+00:00", "on_call", NOW)
    if regra:
        store.create_escalation_rule(1, 2, "high", 1, 60, NOW)


def eventos(store, incident_id, kind) -> list[dict]:
    return [e for e in store.get_incident(incident_id)["timeline"] if e["kind"] == kind]


def run() -> None:
    tmp = tempfile.TemporaryDirectory()
    log = os.path.join(tmp.name, "attack_log.jsonl")
    open(log, "w", encoding="utf-8").close()
    n = [0]

    def nova(**kw) -> IncidentStore:
        n[0] += 1
        store = IncidentStore(os.path.join(tmp.name, f"t{n[0]}.sqlite3"))
        equipa(store, **kw)
        return store

    # --- caminho feliz ---
    store = nova()
    counts = ingest_raw_alerts(store, [raw("a1", "2026-10-06T10:00:10Z", HIGH)], log, SCENARIOS, NOW, auto_triage=True)
    check("abre 1 incidente", counts["opened"] == 1)
    inc = store.get_incident(store.list_incidents()[0]["id"])
    check("fica no Tier 1", inc["assigned_team_tier"] == 1)
    check("com o analista principal do turno (Eddie, não o de prevenção)", inc["assigned_to"] == "Eddie")
    check("SLA = agora + 60 min (regra Tier 1 / high)", inc["sla_deadline"] == SLA_60)
    check("continua em NEW (o estado é decisão humana)", inc["status"] == "NEW")
    ev = eventos(store, inc["id"], "team_assigned")
    check("1 evento team_assigned, feito pelo sistema", len(ev) == 1 and ev[0]["actor"] == "system")
    check("1 evento sla_set", len(eventos(store, inc["id"], "sla_set")) == 1)

    # --- só incidentes novos: evidência anexada não reatribui ---
    store.assign_to_tier(inc["id"], 2, "Jeremy", NOW)
    ingest_raw_alerts(store, [raw("a2", "2026-10-06T10:02:00Z", LOW)], log, SCENARIOS, NOW, auto_triage=True)
    again = store.get_incident(inc["id"])
    check("evidência anexada não mexe no tier/analista atribuídos à mão",
          again["assigned_team_tier"] == 2 and again["assigned_to"] == "Jeremy")
    check("nem acrescenta eventos team_assigned automáticos",
          len([e for e in eventos(store, inc["id"], "team_assigned") if e["actor"] == "system"]) == 1)

    # --- alerta repetido (duplicado) não volta a atribuir ---
    store = nova()
    ingest_raw_alerts(store, [raw("a1", "2026-10-06T10:00:10Z", HIGH)], log, SCENARIOS, NOW, auto_triage=True)
    ingest_raw_alerts(store, [raw("a1", "2026-10-06T10:00:10Z", HIGH)], log, SCENARIOS, NOW, auto_triage=True)
    check("duplicado: continua 1 incidente e 1 atribuição",
          len(store.list_incidents()) == 1 and len(eventos(store, store.list_incidents()[0]["id"], "team_assigned")) == 1)

    # --- por omissão (backfill) nada é atribuído ---
    store = nova()
    ingest_raw_alerts(store, [raw("a1", "2026-10-06T10:00:10Z", HIGH)], log, SCENARIOS, NOW)
    inc = store.get_incident(store.list_incidents()[0]["id"])
    check("sem auto_triage: sem tier, sem analista, sem SLA",
          inc["assigned_team_tier"] is None and inc["assigned_to"] is None and inc["sla_deadline"] is None)

    # --- sem ninguém de turno: Tier 1 + SLA, sem analista ---
    store = nova(turno=False)
    ingest_raw_alerts(store, [raw("a1", "2026-10-06T10:00:10Z", HIGH)], log, SCENARIOS, NOW, auto_triage=True)
    inc = store.get_incident(store.list_incidents()[0]["id"])
    check("sem turno: Tier 1, sem analista, com SLA",
          inc["assigned_team_tier"] == 1 and inc["assigned_to"] is None and inc["sla_deadline"] == SLA_60)

    # --- turno fora de horas: não conta ---
    store = nova()
    ingest_raw_alerts(store, [raw("a1", "2026-10-06T10:00:10Z", HIGH)], log, SCENARIOS, "2026-10-07T03:00:00+00:00", auto_triage=True)
    inc = store.get_incident(store.list_incidents()[0]["id"])
    check("turno de ontem não conta: sem analista", inc["assigned_to"] is None)

    # --- sem regra de escalamento: Tier 1 + analista, sem SLA ---
    store = nova(regra=False)
    ingest_raw_alerts(store, [raw("a1", "2026-10-06T10:00:10Z", HIGH)], log, SCENARIOS, NOW, auto_triage=True)
    inc = store.get_incident(store.list_incidents()[0]["id"])
    check("sem regra: Tier 1 e analista, sem SLA (não inventa prazo)",
          inc["assigned_team_tier"] == 1 and inc["assigned_to"] == "Eddie" and inc["sla_deadline"] is None)
    check("sem regra: nenhum evento sla_set", eventos(store, inc["id"], "sla_set") == [])

    # --- dois principais: escolha determinística (menor id) ---
    store = nova()
    store.create_analyst("analyst-soc0", "Zed", 1, None, NOW)
    store.create_shift("analyst-soc0", "2026-10-06T00:00:00+00:00", "2026-10-06T23:59:00+00:00", "primary", NOW)
    ingest_raw_alerts(store, [raw("a1", "2026-10-06T10:00:10Z", HIGH)], log, SCENARIOS, NOW, auto_triage=True)
    inc = store.get_incident(store.list_incidents()[0]["id"])
    check("2 principais: o de menor id (analyst-soc0 = Zed)", inc["assigned_to"] == "Zed")

    # --- os callbacks AO VIVO de main.py ligam a triagem; o backfill não ---
    import main
    store = nova()
    agora = datetime.now(timezone.utc)  # o callback usa a hora real, não NOW
    store.create_shift("analyst-soc1", (agora - timedelta(hours=1)).isoformat(),
                       (agora + timedelta(hours=1)).isoformat(), "primary", NOW)
    main.incident_store = store
    main._ingest_incident_alerts([raw("live1", "2026-10-06T10:00:10Z", HIGH)])
    inc = store.get_incident(store.list_incidents()[0]["id"])
    check("callback ao vivo de alertas: Tier 1 + Eddie", inc["assigned_team_tier"] == 1 and inc["assigned_to"] == "Eddie")
    store = nova()
    main.incident_store = store
    main._ingest_incident_detections([{"type": "port_scan", "src_ip": "10.0.0.9", "dst_ip": ASSET,
                                       "timestamp": "2026-10-06T10:00:10Z", "detail": {}}])
    lista = store.list_incidents()
    check("callback ao vivo de deteções de rede: Tier 1 no incidente aberto",
          len(lista) == 1 and store.get_incident(lista[0]["id"])["assigned_team_tier"] == 1)

    # --- uma falha na triagem não pára o ingest ---
    store = nova()

    def rebenta(*a, **k):
        raise RuntimeError("falha simulada")

    store.auto_triage = rebenta
    counts = ingest_raw_alerts(store, [raw("a1", "2026-10-06T10:00:10Z", HIGH)], log, SCENARIOS, NOW, auto_triage=True)
    check("triagem a falhar: o incidente abre na mesma", counts["opened"] == 1 and len(store.list_incidents()) == 1)


run()
if failures:
    print(f"\n[FALHOU] {len(failures)} caso(s) falharam")
    sys.exit(1)
print("\n[OK] Todos os testes passaram")
