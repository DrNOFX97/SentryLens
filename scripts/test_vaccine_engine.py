"""
Testes do motor de vaccines (Phase 12): vaccine_engine (puro, sem Wazuh, sem
rede, sem a app FastAPI). O motor é exercitado sobre a saída verdadeira de
attack_registry.build_attack_registry (fixtures copiadas de
test_attack_registry.py) e sobre ataques montados à mão.
Só IPs de documentação (192.0.2.x / 203.0.113.x).

Correr (a partir de scripts/):
    python test_vaccine_engine.py
"""

import ast
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


def make_attack(attack_id, verdict, expected, achieved, scenario="smb_enum", event_ids=(5140, 5145),
                duplicate_id=False, expected_source="scenario_default", correlation_reason=None) -> dict:
    """Dict com a mesma forma de um ataque de build_attack_registry."""
    return {
        "id": attack_id,
        "duplicate_id": duplicate_id,
        "timestamp": ts(100),
        "scenario": scenario,
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1135",
        "expected": {"detection": list(expected), "source": expected_source, "event_ids": list(event_ids)},
        "actual": {"verdict": verdict, "correlation_reason": correlation_reason, "achieved": list(achieved)},
        "evidence": {"matched_event_ids": [], "matched_alert_count": 0, "network_detection_types": [],
                     "incident_count": 0},
        "incidents": [],
    }


def invariant_holds(out: dict) -> bool:
    """Cada ataque partial/not_detected acaba numa vaccine ou num motivo de skipped."""
    c = out["considered"]
    return c["partial"] + c["not_detected"] == out["total"] + sum(out["skipped"].values())


def run_selection() -> None:
    build = vaccine_engine.build_vaccine_candidates

    # Truncagem de alertas: o unknown por truncagem nunca gera.
    reg_tr = attack_registry.build_attack_registry(ATTACKS, SCENARIOS, ML_RESULTS, alerts_truncated=True)
    out_tr = build(reg_tr)
    check("selecao: truncado -> só o ataque 3 (partial) gera",
          [v["origin"]["attack_id"] for v in out_tr["vaccines"]] == [3])
    check("selecao: truncado -> 2 unknown, alerts_truncated True, reason None",
          out_tr["considered"]["unknown"] == 2 and out_tr["alerts_truncated"] is True and out_tr["reason"] is None)
    check("selecao: truncado -> invariante", invariant_holds(out_tr))
    out_tr_arg = build(attack_registry.build_attack_registry(ATTACKS, SCENARIOS, ML_RESULTS),
                       correlation={"alerts_truncated": True})
    check("selecao: correlation.alerts_truncated True também marca o resultado", out_tr_arg["alerts_truncated"] is True)

    # Correlação indisponível: tudo unknown, nada gera.
    reg_off = attack_registry.build_attack_registry(ATTACKS, SCENARIOS, None, correlation_available=False)
    out_off = build(reg_off)
    check("selecao: correlação indisponível -> 0 vaccines, 4 unknown, reason None",
          out_off["vaccines"] == [] and out_off["considered"]["unknown"] == 4 and out_off["reason"] is None)

    # Matriz de vereditos à mão.
    check("selecao: detected -> 0 vaccines", build({"attacks": [make_attack(1, "detected", ["rule"], ["rule"])]})["total"] == 0)
    check("selecao: unknown -> 0 vaccines", build({"attacks": [make_attack(1, "unknown", ["rule"], [])]})["total"] == 0)
    check("selecao: partial -> 1 vaccine", build({"attacks": [make_attack(1, "partial", ["rule", "ml"], ["rule"])]})["total"] == 1)
    check("selecao: not_detected -> 1 vaccine", build({"attacks": [make_attack(1, "not_detected", ["rule"], [])]})["total"] == 1)
    for bad in ("Not_Detected", "weird", 3):
        out_bad = build({"attacks": [make_attack(1, bad, ["rule"], [])]})
        check(f"selecao: veredito {bad!r} -> considered.invalid, sem vaccine",
              out_bad["considered"]["invalid"] == 1 and out_bad["total"] == 0)

    # D-04 pelo registo real: entradas hostis.
    hostile = [
        {"id": True, "scenario": "smb_enum", "target": ASSET, "timestamp": ts(50), "status": "launched"},
        {"id": 8, "scenario": "smb_enum", "target": ASSET, "timestamp": ts(40), "status": "launched"},
        {"id": 8, "scenario": "smb_enum", "target": ASSET, "timestamp": ts(30), "status": "launched"},
    ]
    out_h = build(attack_registry.build_attack_registry(hostile, SCENARIOS, []))
    check("D-04: id booleano -> skipped.no_attack_id", out_h["skipped"]["no_attack_id"] == 1)
    check("D-04: todas as entradas com id repetido -> skipped.duplicate_id == 2", out_h["skipped"]["duplicate_id"] == 2)
    check("D-04: hostis não geram nenhuma vaccine", out_h["total"] == 0 and invariant_holds(out_h))

    old = [{"timestamp": ts(100), "scenario": "smb_enum", "target": ASSET, "tool": "netexec", "status": "launched"}]
    out_old = build(attack_registry.build_attack_registry(old, SCENARIOS, []))
    check("D-04: formato antigo sem id -> skipped.no_attack_id == 1, total 0",
          out_old["skipped"]["no_attack_id"] == 1 and out_old["total"] == 0)

    # Duplicado detetado pelo próprio motor (flag a False).
    dup = build({"attacks": [make_attack(9, "not_detected", ["rule"], [], duplicate_id=False),
                             make_attack(9, "not_detected", ["rule"], [], duplicate_id=False)]})
    check("D-04: duplicado detetado pelo motor mesmo com duplicate_id False",
          dup["skipped"]["duplicate_id"] == 2 and dup["total"] == 0 and invariant_holds(dup))
    dup_flag = build({"attacks": [make_attack(9, "not_detected", ["rule"], [], duplicate_id=True)]})
    check("D-04: flag duplicate_id True conta como duplicate_id", dup_flag["skipped"]["duplicate_id"] == 1)

    # Ids inválidos.
    bad_ids = [0, -1, "2", 2.0, 10 ** 12, None, True]
    out_ids = build({"attacks": [make_attack(i, "not_detected", ["rule"], []) for i in bad_ids]})
    check("D-04: ids 0, -1, '2', 2.0, 10**12, None, True -> skipped.no_attack_id",
          out_ids["skipped"]["no_attack_id"] == len(bad_ids) and out_ids["total"] == 0 and invariant_holds(out_ids))

    # D-01 / Pitfall 3.
    p3 = build({"attacks": [make_attack(5, "partial", ["network"], ["rule"])]})
    v = p3["vaccines"][0]
    check("pitfall 3: esperado [network], atingido [rule] -> missing [network], nunca rule nem ml",
          v["missing_sensors"] == ["network"] and [p["sensor"] for p in v["proposals"]] == ["network"]
          and v["achieved"] == ["rule"])
    full = build({"attacks": [make_attack(5, "partial", ["rule"], ["rule", "ml"])]})
    check("selecao: partial com atingido a cobrir o esperado -> skipped.no_missing_sensors",
          full["skipped"]["no_missing_sensors"] == 1 and full["total"] == 0 and invariant_holds(full))

    # Sem event_ids válidos.
    for bad_events in ([], [True, "x"]):
        out_ne = build({"attacks": [make_attack(5, "not_detected", ["rule"], [], event_ids=bad_events)]})
        check(f"selecao: not_detected rule com event_ids {bad_events!r} -> skipped.no_event_ids",
              out_ne["skipped"]["no_event_ids"] == 1 and out_ne["total"] == 0 and invariant_holds(out_ne))
    out_ml = build({"attacks": [make_attack(5, "not_detected", ["ml"], [], event_ids=[])]})
    check("selecao: esperado [ml] com event_ids [] gera na mesma (a proposta rule não é precisa)",
          out_ml["total"] == 1 and out_ml["skipped"]["no_event_ids"] == 0)

    # Origem inválida.
    for bad_scenario in ("../etc", "", None):
        out_sc = build({"attacks": [make_attack(5, "not_detected", ["rule"], [], scenario=bad_scenario)]})
        check(f"selecao: scenario {bad_scenario!r} -> skipped.invalid_origin",
              out_sc["skipped"]["invalid_origin"] == 1 and out_sc["total"] == 0 and invariant_holds(out_sc))

    # event_ids sujos.
    out_ev = build({"attacks": [make_attack(5, "not_detected", ["rule"], [], event_ids=[5140, True, "5145", 5140, -1])]})
    check("selecao: event_ids [5140, True, '5145', 5140, -1] -> [5140]",
          out_ev["vaccines"][0]["proposals"][0]["rule"]["event_ids"] == [5140])

    # Evolução do id (D-03).
    evo_partial = build({"attacks": [make_attack(2, "partial", ["rule", "ml"], ["rule"])]})["vaccines"][0]
    evo_none = build({"attacks": [make_attack(2, "not_detected", ["rule", "ml"], [])]})["vaccines"][0]
    check("D-03: partial (missing ml) -> vac-ed793c0b3437", evo_partial["id"] == "vac-ed793c0b3437")
    check("D-03: not_detected (missing rule+ml) -> vac-5fe3861aa2a3", evo_none["id"] == "vac-5fe3861aa2a3")
    check("D-03: partial para not_detected muda o id", evo_partial["id"] != evo_none["id"])

    # Determinismo.
    reg = attack_registry.build_attack_registry(ATTACKS, SCENARIOS, ML_RESULTS)
    first, second = build(reg), build(reg)
    check("determinismo: duas corridas dão resultado igual", first == second)
    reg_rev = {"attacks": list(reversed(reg["attacks"])), "skipped": reg["skipped"]}
    check("determinismo: lista de ataques invertida dá o mesmo resultado", build(reg_rev) == first)
    ids = [x["id"] for x in first["vaccines"]]
    check("determinismo: ids únicos", len(set(ids)) == len(ids))

    # Cópia defensiva.
    snapshot = copy.deepcopy(reg)
    victim = build(reg)
    for vac in victim["vaccines"]:
        vac["expected"].append("x")
        vac["achieved"].append("x")
        vac["missing_sensors"].append("x")
        vac["origin"]["incident_ids"].append("x")
        vac["origin"]["evidence"]["matched_event_ids"].append(1)
        for prop in vac["proposals"]:
            if prop["rule"]:
                prop["rule"]["event_ids"].append(1)
    check("copia defensiva: mutar a vaccine não altera o registo", reg == snapshot)
    check("copia defensiva: nova corrida não herda a mutação", build(reg) == first)

    # Malformado.
    junk = build({"attacks": ["lixo", None, 5, [1], {"actual": None}, {"actual": {"verdict": 3}}, {}]})
    check("malformado: 7 entradas inválidas, sem exceção, total 0",
          junk["considered"]["invalid"] == 7 and junk["considered"]["attacks"] == 7 and junk["total"] == 0)
    for odd in (None, {}, {"attacks": None}, {"attacks": "x"}, "x", 5):
        out_odd = build(odd)
        check(f"malformado: registo {odd!r} -> resultado vazio sem exceção",
              out_odd["total"] == 0 and out_odd["considered"]["attacks"] == 0 and set(out_odd) == vaccine_engine.RESULT_KEYS)

    # Invariante nos resultados reais.
    check("invariante: registo das fixtures", invariant_holds(first))


# Deny-list de comandos (VAC-02): metacaracteres de shell, nomes de ferramentas,
# opções --x e IPv4. Aplicada a TODAS as strings (chaves e valores).
DENY_RE = re.compile(r"[;&|`$<>\\]|\b(netexec|hydra|psexec|nmap|schtasks|powershell|cmd|bash|sudo|curl|wget|rm|whoami)\b|--[a-z]|\b\d{1,3}(?:\.\d{1,3}){3}\b", re.IGNORECASE)

ENGINE_ALLOWED_IMPORTS = {"__future__", "hashlib", "re", "attack_registry", "event_catalog", "redblue_correlator"}
ENGINE_FORBIDDEN_CALLS = {"open", "print", "input", "eval", "exec", "compile", "__import__", "breakpoint"}


def walk_strings(value):
    """Todas as strings (chaves e valores) de dicts, listas e tuplos."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield from walk_strings(key)
            yield from walk_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from walk_strings(item)
    elif isinstance(value, str):
        yield value


def run_contract() -> None:
    build = vaccine_engine.build_vaccine_candidates
    validate = vaccine_engine.validate_vaccine

    corpus: list[tuple[str, dict]] = []

    def add(label: str, out: dict) -> None:
        for vac in out["vaccines"]:
            corpus.append((f"{label}/{vac['id']}", vac))

    # (a) fixtures, (b) com incidentes, (c) truncagem.
    reg = attack_registry.build_attack_registry(ATTACKS, SCENARIOS, ML_RESULTS)
    add("fixtures", build(reg))
    incs = [{"id": "INC-20261007-001", "severity": "high", "status": "NEW", "evidence_count": 2, "attack_ids": [2, 3]}]
    add("incidentes", build(attack_registry.build_attack_registry(ATTACKS, SCENARIOS, ML_RESULTS, incidents=incs)))
    add("truncado", build(attack_registry.build_attack_registry(ATTACKS, SCENARIOS, ML_RESULTS, alerts_truncated=True),
                          correlation={"available": True, "alerts_truncated": True}))

    # (d) ataque hostil pelo registo real: texto livre com comandos no log.
    hostile_log = [{"id": 30, "scenario": "smb_enum", "target": ASSET, "timestamp": ts(60), "status": "launched",
                    "technique": "T1110 netexec smb 192.0.2.10", "tool": "hydra -l admin", "operator": "x; rm -rf",
                    "details": {"command": "netexec smb 192.0.2.10 --shares"}}]
    hostile_incs = [{"id": "INC-20261007-001", "attack_ids": [30]}, {"id": "X; rm", "attack_ids": [30]}]
    out_hostile = build(attack_registry.build_attack_registry(hostile_log, SCENARIOS, [], incidents=hostile_incs))
    add("hostil", out_hostile)

    # (e) à mão: Pitfall 3, event_ids filtrados, tipos de deteção de rede sujos.
    add("pitfall3", build({"attacks": [make_attack(5, "partial", ["network"], ["rule"])]}))
    add("event_ids", build({"attacks": [make_attack(6, "not_detected", ["rule"], [], event_ids=[5140, True, "5145", 5140, -1])]}))
    net_attack = make_attack(7, "not_detected", ["rule", "ml", "network"], [])
    net_attack["evidence"]["network_detection_types"] = ["port_scan", "bad type; rm"]
    out_net = build({"attacks": [net_attack]})
    add("rede", out_net)

    check(f"contrato: corpus com vaccines suficientes ({len(corpus)})", len(corpus) >= 8)
    for label, vac in corpus:
        problems = validate(vac)
        check(f"contrato: validate_vaccine == [] para {label}", problems == [])

    # Varrimento: nenhuma string de nenhuma vaccine casa a deny-list.
    offenders = [(label, s) for label, vac in corpus for s in walk_strings(vac) if DENY_RE.search(s)]
    check(f"varrimento: nenhuma string do corpus casa DENY_RE {offenders[:3]}", not offenders)
    check("varrimento: o gerador vê chaves e valores", "proposals" in set(walk_strings(corpus[0][1]))
          and corpus[0][1]["id"] in set(walk_strings(corpus[0][1])))

    # Sanidade das fontes da allowlist.
    check("sanidade: RECOMMENDATIONS não casam DENY_RE",
          not any(DENY_RE.search(text) for text in vaccine_engine.RECOMMENDATIONS.values()))
    from event_catalog import CRITICAL_EVENTS
    check("sanidade: nomes/severidades de CRITICAL_EVENTS não casam DENY_RE",
          not any(DENY_RE.search(str(v.get("name", ""))) or DENY_RE.search(str(v.get("severity", "")))
                  for v in CRITICAL_EVENTS.values()))
    check("sanidade: o DENY_RE apanha mesmo comandos",
          all(DENY_RE.search(s) for s in ("netexec smb 192.0.2.10 --shares", "T1110; rm -rf /", "smb_enum && whoami",
                                          "hydra -l admin", "INC-1; drop", "$(id)", "a|b",
                                          "T1110 netexec smb 192.0.2.10")))

    # Negativos sobre a vaccine 2 das fixtures (tem proposta rule e ml).
    base = next(v for v in build(reg)["vaccines"] if v["origin"]["attack_id"] == 2)
    check("negativos: a base (ataque 2) é válida e tem rule e ml",
          validate(base) == [] and [p["sensor"] for p in base["proposals"]] == ["rule", "ml"])

    def negative(label: str, mutate) -> None:
        bad = copy.deepcopy(base)
        mutate(bad)
        problems = validate(bad)
        check(f"negativo: {label} -> rejeitado {problems}", problems != [])

    negative("recommendation de ml com comando", lambda v: v["proposals"][1].update(recommendation="netexec smb 192.0.2.10 --shares"))
    negative("recommendation de rule passa a texto", lambda v: v["proposals"][0].update(recommendation="Rever a regra."))
    negative("chave extra 'command' na vaccine", lambda v: v.update(command="x"))
    negative("chave extra 'command' em rule", lambda v: v["proposals"][0]["rule"].update(command="x"))
    negative("chave em falta em origin", lambda v: v["origin"].pop("scenario"))
    negative("rule.min_count = 5", lambda v: v["proposals"][0]["rule"].update(min_count=5))
    negative("rule.window_seconds = 60", lambda v: v["proposals"][0]["rule"].update(window_seconds=60))
    negative("rule.event_ids = []", lambda v: v["proposals"][0]["rule"].update(event_ids=[]))
    negative("mitre_technique com comando", lambda v: v["origin"].update(mitre_technique="T1110; rm -rf /"))
    negative("scenario com comando", lambda v: v["origin"].update(scenario="smb_enum && whoami"))
    negative("incident_ids com comando", lambda v: v["origin"].update(incident_ids=["INC-1; drop"]))
    negative("events[0].name alterado", lambda v: v["proposals"][0]["events"][0].update(name="Outro nome"))
    negative("id trocado por outro hex válido (id_mismatch)", lambda v: v.update(id="vac-000000000000"))
    negative("proposals por ordem invertida", lambda v: v["proposals"].reverse())
    negative("missing_sensors com sensor fora de EXPECTED_SOURCES", lambda v: v["missing_sensors"].append("bogus"))
    negative("matched_alert_count = True", lambda v: v["origin"]["evidence"].update(matched_alert_count=True))
    negative("chave extra na origem", lambda v: v["origin"].update(tool="hydra"))
    negative("verdict fora de GENERATING_VERDICTS", lambda v: v.update(verdict="detected"))
    negative("expected_source desconhecido", lambda v: v.update(expected_source="outro"))
    negative("event_ids com bool", lambda v: v["proposals"][0]["rule"].update(event_ids=[True, 5145]))
    negative("tipo de deteção de rede com comando", lambda v: v["origin"]["evidence"].update(network_detection_types=["x; rm"]))
    negative("matched_event_ids com texto", lambda v: v["origin"]["evidence"].update(matched_event_ids=["5140"]))
    negative("attack_id como texto", lambda v: v["origin"].update(attack_id="2"))
    negative("mitre_tactic com comando", lambda v: v["origin"].update(mitre_tactic="Discovery; rm"))
    negative("events com severidade alterada", lambda v: v["proposals"][0]["events"][0].update(severity="critical"))
    negative("proposta ml com rule preenchida", lambda v: v["proposals"][1].update(rule={"event_ids": [1], "min_count": 1, "window_seconds": 300}))

    for odd in (None, "x", [], 5, {}):
        try:
            problems = validate(odd)
            ok = isinstance(problems, list) and problems != []
        except Exception as exc:  # noqa: BLE001 - o teste prova que nunca levanta
            ok = False
            problems = repr(exc)
        check(f"validate_vaccine({odd!r}) -> lista não vazia, sem exceção", ok)
    codes = validate({"id": 5})
    check("validate_vaccine: códigos ordenados e sem repetidos",
          codes == sorted(set(codes)) and all(isinstance(c, str) for c in codes))

    # Hostil pelo registo.
    hv = out_hostile["vaccines"]
    check("hostil: uma só vaccine", len(hv) == 1)
    blob = json.dumps(out_hostile)
    leaks = [w for w in ("netexec", "hydra", "rm -rf", "192.0.2.") if w in blob]
    check(f"hostil: nada de netexec/hydra/rm -rf/IP no resultado {leaks}", not leaks)
    check("hostil: mitre_technique None (texto livre não passa a regex)", hv[0]["origin"]["mitre_technique"] is None)
    check("hostil: incident_ids só com o id válido", hv[0]["origin"]["incident_ids"] == ["INC-20261007-001"])
    check("hostil: validate_vaccine == []", validate(hv[0]) == [])

    check("rede: tipos sujos filtrados -> ['port_scan']",
          out_net["vaccines"][0]["origin"]["evidence"]["network_detection_types"] == ["port_scan"])

    # Gate AST: o motor continua puro.
    with open(vaccine_engine.__file__, encoding="utf-8") as handle:
        tree = ast.parse(handle.read())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    check(f"AST: imports do motor dentro da allowlist {sorted(imported - ENGINE_ALLOWED_IMPORTS)}",
          imported <= ENGINE_ALLOWED_IMPORTS)
    bad_calls = sorted({node.func.id for node in ast.walk(tree)
                        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                        and node.func.id in ENGINE_FORBIDDEN_CALLS})
    check(f"AST: sem open/print/input/eval/exec/compile/__import__ {bad_calls}", not bad_calls)


if __name__ == "__main__":
    run_tracer()
    run_selection()
    run_contract()
    print()
    if failures:
        print(f"{len(failures)} falha(s):")
        for label in failures:
            print(f"  - {label}")
        sys.exit(1)
    print("Todos os testes passaram.")
