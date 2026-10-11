"""
Testes do motor de vaccines (Phase 12): vaccine_engine (puro, sem Wazuh, sem
rede, sem a app FastAPI). O motor é exercitado sobre a saída verdadeira de
attack_registry.build_attack_registry (fixtures copiadas de
test_attack_registry.py) e sobre ataques montados à mão.
Só IPs de documentação (192.0.2.x / 203.0.113.x).

Correr (a partir de scripts/):
    python test_vaccine_engine.py
"""

import copy
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from unittest import mock

import attack_registry
import vaccine_engine
from attack_library import get_expected_sensors
from attack_scenarios import SCENARIOS
from event_catalog import classify_alert
from redblue_correlator import DEFAULT_WINDOW_SECONDS

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


def run_tracer() -> None:
    reg = attack_registry.build_attack_registry(ATTACKS, SCENARIOS, ML_RESULTS)
    out = vaccine_engine.build_vaccine_candidates(reg)
    vaccines = out["vaccines"]
    check("tracer: 3 vaccines, dos ataques 4, 3 e 2 por esta ordem (o detected 1 não gera)",
          [v["origin"]["attack_id"] for v in vaccines] == [4, 3, 2])
    by_attack = {v["origin"]["attack_id"]: v for v in vaccines}
    v2, v3, v4 = by_attack[2], by_attack[3], by_attack[4]

    # Ids golden: literais, nunca o resultado de outra chamada (D-03).
    check("tracer: id do ataque 4 == literal golden", v4["id"] == "vac-13daa7f56fa1")
    check("tracer: id do ataque 3 == literal golden", v3["id"] == "vac-bd617cce8054")
    check("tracer: id do ataque 2 == literal golden", v2["id"] == "vac-5fe3861aa2a3")
    check("tracer: vaccine_id(2, rule+ml) == literal", vaccine_engine.vaccine_id(2, ["rule", "ml"]) == "vac-5fe3861aa2a3")
    check("tracer: vaccine_id(3, ml) == literal", vaccine_engine.vaccine_id(3, ["ml"]) == "vac-bd617cce8054")
    check("tracer: vaccine_id(4, network) == literal", vaccine_engine.vaccine_id(4, ["network"]) == "vac-13daa7f56fa1")
    check("tracer: vaccine_id(4, rule+ml) == literal", vaccine_engine.vaccine_id(4, ["rule", "ml"]) == "vac-ca13ec0fa618")
    check("tracer: id casa VACCINE_ID_RE", all(re.match(vaccine_engine.VACCINE_ID_RE, v["id"]) for v in vaccines))

    # Vaccine 2: not_detected, esperado rule+ml.
    check("tracer: vaccine 2 veredito/esperado/origem do esperado", v2["verdict"] == "not_detected"
          and v2["expected"] == ["rule", "ml"] and v2["expected_source"] == "scenario_default")
    check("tracer: vaccine 2 achieved vazio e missing = todos os esperados",
          v2["achieved"] == [] and v2["missing_sensors"] == ["rule", "ml"])
    check("tracer: vaccine 2 propostas rule e ml, por esta ordem", [p["sensor"] for p in v2["proposals"]] == ["rule", "ml"])
    rule_proposal = {
        "sensor": "rule",
        "rule": {"event_ids": [5140, 5145], "min_count": 1, "window_seconds": 300},
        "events": [{"event_id": 5140, "name": "Network Share Accessed", "severity": "low"},
                   {"event_id": 5145, "name": "Network Share Permission Checked", "severity": "low"}],
        "recommendation": None,
    }
    check("tracer: proposals[0] da vaccine 2 é a regra {event_ids, min_count, window_seconds}",
          v2["proposals"][0] == rule_proposal)
    check("tracer: window_seconds == DEFAULT_WINDOW_SECONDS (D-05)",
          v2["proposals"][0]["rule"]["window_seconds"] == DEFAULT_WINDOW_SECONDS == 300)
    check("tracer: events vêm de event_catalog.classify_alert",
          all(e["name"] == classify_alert(e["event_id"])["friendly_name"]
              and e["severity"] == classify_alert(e["event_id"])["severity"] for e in v2["proposals"][0]["events"]))
    check("tracer: proposals[1] da vaccine 2 é ml com recomendação constante",
          v2["proposals"][1] == {"sensor": "ml", "rule": None, "events": None,
                                 "recommendation": vaccine_engine.RECOMMENDATIONS["ml"]})
    check("tracer: RECOMMENDATIONS tem só ml e network", set(vaccine_engine.RECOMMENDATIONS) == {"ml", "network"})

    # Vaccine 3: partial, só falta ml (D-01).
    check("tracer: vaccine 3 partial, achieved [rule], missing [ml]",
          v3["verdict"] == "partial" and v3["achieved"] == ["rule"] and v3["missing_sensors"] == ["ml"])
    check("tracer: vaccine 3 tem uma única proposta ml", [p["sensor"] for p in v3["proposals"]] == ["ml"])

    # Vaccine 4: esperado vindo do log, só network.
    check("tracer: vaccine 4 esperado [network] vindo do log, missing [network]",
          v4["expected"] == ["network"] and v4["expected_source"] == "log" and v4["missing_sensors"] == ["network"])
    check("tracer: vaccine 4 uma proposta network com rule None e recomendação constante",
          v4["proposals"] == [{"sensor": "network", "rule": None, "events": None,
                               "recommendation": vaccine_engine.RECOMMENDATIONS["network"]}])

    # Origem (VAC-03).
    check("tracer: origin da vaccine 2 completa e por referência", v2["origin"] == {
        "attack_id": 2, "scenario": "smb_enum", "mitre_tactic": "Discovery", "mitre_technique": "T1087",
        "incident_ids": [],
        "evidence": {"matched_event_ids": [], "matched_alert_count": 0, "network_detection_types": []}})
    check("tracer: evidência da vaccine 3", v3["origin"]["evidence"] == {
        "matched_event_ids": [4672], "matched_alert_count": 1, "network_detection_types": []})
    check("tracer: vaccine 4 técnica e tática do cenário",
          v4["origin"]["mitre_technique"] == "T1110.003" and v4["origin"]["mitre_tactic"] == "Credential Access")

    # Incidentes: só ids.
    incs = [{"id": "INC-20261007-001", "severity": "high", "status": "NEW", "evidence_count": 2, "attack_ids": [2]}]
    reg_inc = attack_registry.build_attack_registry(ATTACKS, SCENARIOS, ML_RESULTS, incidents=incs)
    out_inc = vaccine_engine.build_vaccine_candidates(reg_inc)
    v2_inc = next(v for v in out_inc["vaccines"] if v["origin"]["attack_id"] == 2)
    check("tracer: incident_ids só com os ids", v2_inc["origin"]["incident_ids"] == ["INC-20261007-001"])
    check("tracer: severidade/estado do incidente não entram na vaccine",
          '"severity": "high"' not in json.dumps(v2_inc) and '"NEW"' not in json.dumps(v2_inc))

    # Chaves fechadas.
    check("tracer: chaves da vaccine == VACCINE_KEYS", all(set(v) == vaccine_engine.VACCINE_KEYS for v in vaccines))
    check("tracer: chaves da origem == ORIGIN_KEYS", all(set(v["origin"]) == vaccine_engine.ORIGIN_KEYS for v in vaccines))
    check("tracer: chaves da evidência == EVIDENCE_KEYS",
          all(set(v["origin"]["evidence"]) == vaccine_engine.EVIDENCE_KEYS for v in vaccines))
    check("tracer: chaves de cada proposta == PROPOSAL_KEYS",
          all(set(p) == vaccine_engine.PROPOSAL_KEYS for v in vaccines for p in v["proposals"]))
    check("tracer: chaves da regra == RULE_KEYS",
          set(v2["proposals"][0]["rule"]) == vaccine_engine.RULE_KEYS)
    check("tracer: chaves de cada evento == EVENT_KEYS",
          all(set(e) == vaccine_engine.EVENT_KEYS for e in v2["proposals"][0]["events"]))
    check("tracer: chaves do envelope == RESULT_KEYS", set(out) == vaccine_engine.RESULT_KEYS)

    # Envelope.
    check("tracer: available True, reason None, total 3",
          out["available"] is True and out["reason"] is None and out["total"] == 3)
    check("tracer: considered conta os 4 ataques", out["considered"] == {
        "attacks": 4, "detected": 1, "partial": 1, "not_detected": 2, "unknown": 0, "invalid": 0})
    check("tracer: skipped todo a 0 e com as chaves de SKIP_REASONS",
          set(out["skipped"]) == set(vaccine_engine.SKIP_REASONS) and all(n == 0 for n in out["skipped"].values()))
    check("tracer: alerts_truncated False", out["alerts_truncated"] is False)

    # Nada de tool/alvo/operador/fonte.
    blob = json.dumps(out)
    leaks = [w for w in ("hydra", "netexec", "psexec", "alice", "192.0.2.", "203.0.113.") if w in blob]
    check(f"tracer: tool/target/source/operator não vazam para a vaccine {leaks}", not leaks)

    # VAC-02: sensores esperados vêm da attack_library (via registo).
    check("VAC-02: vaccine 2 expected == attack_library.get_expected_sensors('smb_enum')",
          v2["expected"] == get_expected_sensors("smb_enum") and v2["expected_source"] == "scenario_default")

    original = attack_registry.get_expected_sensors

    def fake_sensors(name):
        return ["network"] if name == "smb_enum" else original(name)

    with mock.patch.object(attack_registry, "get_expected_sensors", fake_sensors):
        reg_lib = attack_registry.build_attack_registry(ATTACKS, SCENARIOS, ML_RESULTS)
        out_lib = vaccine_engine.build_vaccine_candidates(reg_lib)
    lib_by_attack = {v["origin"]["attack_id"]: v for v in out_lib["vaccines"]}
    l2 = lib_by_attack[2]
    check("VAC-02: com a biblioteca substituída a vaccine 2 passa a esperar [network]",
          l2["expected"] == ["network"] and l2["missing_sensors"] == ["network"]
          and [p["sensor"] for p in l2["proposals"]] == ["network"])
    check("VAC-02: id da vaccine 2 com a biblioteca substituída == literal golden", l2["id"] == "vac-32b35d85e61e")
    check("VAC-02: vaccines 3 e 4 ficam iguais às do registo sem substituição",
          lib_by_attack[3] == v3 and lib_by_attack[4] == v4)
    check("VAC-02: a substituição foi restaurada no fim do with", attack_registry.get_expected_sensors is original)


if __name__ == "__main__":
    run_tracer()
    print()
    if failures:
        print(f"{len(failures)} falha(s):")
        for label in failures:
            print(f"  - {label}")
        sys.exit(1)
    print("Todos os testes passaram.")
