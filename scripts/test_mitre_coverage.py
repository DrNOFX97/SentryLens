"""
Testes puros de mitre_coverage.build_mitre_coverage_report (R16, Phase 19):
linhas por id exato (D-01, D-02), alertas por origem (D-00a), vereditos e taxa
(D-04..D-06), táticas multi-valor (D-10), secção sem tática (D-03), fonte em
baixo -> null (D-08), correlação, contrato, ausência de efeitos secundários e
pureza (AST). Sem `import main`, sem Wazuh, sem I/O.

Correr (a partir de scripts/):
    python test_mitre_coverage.py
"""

import ast
import copy
import sys
from pathlib import Path

import mitre_coverage
from mitre_catalog import ENTERPRISE_TACTICS, load_mitre_techniques, tactics_for

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


T = load_mitre_techniques()
build = mitre_coverage.build_mitre_coverage_report
ZERO_ATTACKS = {"launched": 0, "detected": 0, "partial": 0, "not_detected": 0, "unknown": 0}


def alerta_mitre(ids, tactic=None, event_id=None) -> dict:
    mitre = {"id": list(ids)}
    if tactic is not None:
        mitre["tactic"] = tactic
    raw = {"rule": {"mitre": mitre}}
    if event_id is not None:
        raw["data"] = {"win": {"system": {"eventID": str(event_id)}}}
    return raw


def alerta_evento(event_id: int) -> dict:
    return {"data": {"win": {"system": {"eventID": str(event_id)}}}}


def ataque(tid, verdict) -> dict:
    return {"mitre_technique": tid, "actual": {"verdict": verdict}}


def linha(report: dict, tid: str) -> dict:
    for item in report["techniques"] + report["unmapped"]:
        if item["id"] == tid:
            return item
    raise KeyError(tid)


def tatica(report: dict, name: str) -> dict:
    return next(t for t in report["tactics"] if t["tactic"] == name)


def run_empty() -> None:
    r = build([], [], T, 168)
    check("vazio: techniques traz os ids da tabela, ordenados",
          [t["id"] for t in r["techniques"]] == sorted(T))
    check("vazio: cada linha com contagens 0 reais e rate None",
          all(t["alerts"] == {"total": 0, "wazuh": 0, "catalog": 0}
              and t["attacks"] == ZERO_ATTACKS and t["rate"] is None for t in r["techniques"]))
    check("vazio: unmapped vazio", r["unmapped"] == [])
    check("vazio: 14 táticas pela ordem da matriz, todas rate None",
          [t["tactic"] for t in r["tactics"]] == list(ENTERPRISE_TACTICS)
          and all(t["rate"] is None for t in r["tactics"]))
    check("vazio: totals com zeros reais e rate None",
          r["totals"] == {"alerts": {"fetched": 0, "with_technique": 0, "without_technique": 0},
                          "attacks": ZERO_ATTACKS, "rate": None})
    check("vazio: window_hours e attack_version", r["window_hours"] == 168 and r["attack_version"] == "v18.1")


def run_rows() -> None:
    r = build([alerta_mitre(["T1110.003"])], [ataque("T1110", "detected")], T, 168)
    filha, pai = linha(r, "T1110.003"), linha(r, "T1110")
    check("D-02: alerta da filha conta só na filha", filha["alerts"]["total"] == 1 and pai["alerts"]["total"] == 0)
    check("D-02: ataque do pai não passa para a filha (launched 0, detected 0, rate None)",
          filha["attacks"]["launched"] == 0 and filha["attacks"]["detected"] == 0 and filha["rate"] is None)
    check("D-02: ataque T1110 conta só em T1110 (launched 1, detected 1, rate 100.0)",
          pai["attacks"]["launched"] == 1 and pai["attacks"]["detected"] == 1 and pai["rate"] == 100.0)
    check("D-02: parent da filha é T1110 e o da técnica base é None", filha["parent"] == "T1110" and pai["parent"] is None)

    h = build([alerta_mitre(["T1110.001"])], [], T, 168)
    herdada = linha(h, "T1110.001")
    check("herança: T1110.001 está em techniques, não em unmapped",
          herdada in h["techniques"] and herdada not in h["unmapped"])
    check("herança: name None, parent T1110, tática Credential Access",
          herdada["name"] is None and herdada["parent"] == "T1110" and herdada["tactics"] == ["Credential Access"])
    check("herança: entra em technique_ids de Credential Access",
          "T1110.001" in tatica(h, "Credential Access")["technique_ids"])


def run_unmapped() -> None:
    r = build([alerta_mitre(["T1059"])], [], T, 168)
    check("D-03: T1059 vista num alerta vai para unmapped com as contagens",
          linha(r, "T1059") == {"id": "T1059", "name": None, "parent": None, "tactics": [],
                                "alerts": {"total": 1, "wazuh": 1, "catalog": 0},
                                "attacks": ZERO_ATTACKS, "rate": None}
          and linha(r, "T1059") in r["unmapped"])

    r2 = build([alerta_mitre(["T1059"])],
               [ataque("T1087", "not_detected"), ataque("Brute Force", "unknown")], T, 168)
    check("D-03: ids de unmapped (T1087 e texto livre incluídos), ordenados",
          [u["id"] for u in r2["unmapped"]] == ["Brute Force", "T1059", "T1087"])
    in_tactics = {tid for t in r2["tactics"] for tid in t["technique_ids"]}
    check("D-03: nenhum id sem tática em technique_ids de nenhuma tática",
          not ({"Brute Force", "T1059", "T1087"} & in_tactics))
    check("D-03: conta em totals mas em nenhuma tática",
          r2["totals"]["attacks"]["launched"] == 2 and all(t["attacks"]["launched"] == 0 for t in r2["tactics"]))
    check("D-03: unmapped nunca em techniques",
          not ({"Brute Force", "T1059", "T1087"} & {t["id"] for t in r2["techniques"]}))


def run_sources_by_origin() -> None:
    r = build([alerta_evento(4625), alerta_mitre(["T1078", "T1021"]), alerta_evento(4624)], [], T, 168)
    check("origem: 4625 sem rule.mitre conta em catalog na linha T1110",
          linha(r, "T1110")["alerts"] == {"total": 1, "wazuh": 0, "catalog": 1})
    check("origem: alerta com duas técnicas conta uma vez em cada linha",
          linha(r, "T1078")["alerts"] == {"total": 1, "wazuh": 1, "catalog": 0}
          and linha(r, "T1021")["alerts"] == {"total": 1, "wazuh": 1, "catalog": 0})
    check("origem: totals.alerts fetched/with/without",
          r["totals"]["alerts"] == {"fetched": 3, "with_technique": 2, "without_technique": 1})
    s = build([alerta_mitre(["T1110"], event_id=4625)], [], T, 168)
    check("origem: rule.mitre substitui o catálogo (wazuh 1, catalog 0)",
          linha(s, "T1110")["alerts"] == {"total": 1, "wazuh": 1, "catalog": 0})


def run_rates() -> None:
    r = build([], [ataque("T1110", v) for v in ("detected", "partial", "not_detected", "unknown")], T, 168)
    row = linha(r, "T1110")
    check("taxa: contagens launched 4 e um de cada veredito",
          row["attacks"] == {"launched": 4, "detected": 1, "partial": 1, "not_detected": 1, "unknown": 1})
    check("taxa: 1/3 -> 33.3 (unknown fora do denominador, partial como não detetado)", row["rate"] == 33.3)
    u = build([], [ataque("T1135", "unknown")], T, 168)
    check("taxa: só unknown -> launched 1 e rate None",
          linha(u, "T1135")["attacks"]["launched"] == 1 and linha(u, "T1135")["rate"] is None)
    w = build([], [ataque("T1110", "lixo"), {"mitre_technique": "T1110"}], T, 168)
    check("taxa: veredito inválido ou ausente conta como unknown (nunca detetado)",
          linha(w, "T1110")["attacks"] == {"launched": 2, "detected": 0, "partial": 0,
                                           "not_detected": 0, "unknown": 2})
    check("taxa: detection_rate(None) é None", mitre_coverage.detection_rate(None) is None)
    check("taxa: denominador 0 é None",
          mitre_coverage.detection_rate({"launched": 3, "detected": 0, "partial": 0,
                                         "not_detected": 0, "unknown": 3}) is None)
    check("taxa: 0 detetados em 2 não detetados é 0.0 (não None)",
          mitre_coverage.detection_rate({"launched": 2, "detected": 0, "partial": 0,
                                         "not_detected": 2, "unknown": 0}) == 0.0)


def run_tactics() -> None:
    r = build([], [ataque("T1053", "partial")], T, 168)
    nomes = ("Execution", "Persistence", "Privilege Escalation")
    check("D-10: T1053 conta em Execution, Persistence e Privilege Escalation (launched 1, partial 1, rate 0.0)",
          all(tatica(r, n)["attacks"]["launched"] == 1 and tatica(r, n)["attacks"]["partial"] == 1
              and tatica(r, n)["rate"] == 0.0 for n in nomes))
    check("D-10: totals.attacks conta o ataque uma só vez", r["totals"]["attacks"]["launched"] == 1)
    check("D-10: soma por tática (3) excede o total (1)",
          sum(t["attacks"]["launched"] for t in r["tactics"]) == 3 > r["totals"]["attacks"]["launched"])

    d = build([alerta_mitre(["T1110"], tactic=["Impact"])],
              [{"mitre_technique": "T1053", "mitre_tactic": "Lateral Movement",
                "actual": {"verdict": "detected"}}], T, 168)
    check("tática só da tabela: mitre_tactic do ataque ignorado (Lateral Movement launched 0)",
          tatica(d, "Lateral Movement")["attacks"]["launched"] == 0)
    check("tática só da tabela: rule.mitre.tactic do Wazuh ignorado (T1110 fora de Impact)",
          "T1110" not in tatica(d, "Impact")["technique_ids"] and tatica(d, "Impact")["attacks"]["launched"] == 0)


def run_unavailable_sources() -> None:
    a = build(None, [ataque("T1087", "detected")], T, 168, alerts_truncated=True)
    rows = a["techniques"] + a["unmapped"]
    check("D-08: alertas em baixo -> alerts None em todas as linhas", all(t["alerts"] is None for t in rows))
    check("D-08: totals.alerts e alerts_truncated None (não False)",
          a["totals"]["alerts"] is None and a["alerts_truncated"] is None)
    check("D-08: sources.alerts source_unavailable",
          a["sources"]["alerts"] == {"available": False, "reason": "source_unavailable"})
    check("D-08: as 17 linhas da tabela continuam e T1087 está em unmapped",
          len(a["techniques"]) == 17 and linha(a, "T1087") in a["unmapped"])
    check("D-08: ataques continuam contados com os alertas em baixo", linha(a, "T1087")["attacks"]["detected"] == 1)

    b = build([alerta_mitre(["T1059"])], None, T, 168)
    rows = b["techniques"] + b["unmapped"]
    check("D-08: ataques em baixo -> attacks e rate None em todas as linhas",
          all(t["attacks"] is None and t["rate"] is None for t in rows))
    check("D-08: ataques em baixo -> táticas com attacks e rate None",
          all(t["attacks"] is None and t["rate"] is None for t in b["tactics"]))
    check("D-08: totals.attacks e totals.rate None", b["totals"]["attacks"] is None and b["totals"]["rate"] is None)
    check("D-08: sources.attacks source_unavailable com correlation None",
          b["sources"]["attacks"] == {"available": False, "reason": "source_unavailable", "correlation": None})
    check("D-08: T1059 continua em unmapped com alerts total 1", linha(b, "T1059")["alerts"]["total"] == 1)
    check("D-08: alertas disponíveis -> alerts_truncated False", b["alerts_truncated"] is False)

    c = build(None, None, T, 168)
    check("D-08: as duas fontes em baixo -> 17 linhas, tudo None",
          len(c["techniques"]) == 17
          and all(t["alerts"] is None and t["attacks"] is None and t["rate"] is None for t in c["techniques"])
          and c["totals"] == {"alerts": None, "attacks": None, "rate": None})


def run_correlation() -> None:
    check("truncagem: alerts_truncated=True passa para o envelope",
          build([], [], T, 168, alerts_truncated=True)["alerts_truncated"] is True)
    check("truncagem: por omissão False", build([], [], T, 168)["alerts_truncated"] is False)

    def corr(correlation):
        return build([], [ataque("T1110", "unknown")], T, 168, correlation=correlation)["sources"]["attacks"]["correlation"]

    check("correlação: disponível com truncagem",
          corr({"available": True, "error_code": None, "alerts_truncated": True})
          == {"available": True, "reason": None, "alerts_truncated": True})
    check("correlação: indexer_unavailable passa",
          corr({"available": False, "error_code": "indexer_unavailable"})["reason"] == "indexer_unavailable")
    check("correlação: ml_model_unavailable passa",
          corr({"available": False, "error_code": "ml_model_unavailable"})["reason"] == "ml_model_unavailable")
    check("correlação: attack_outside_alert_window passa",
          corr({"available": False, "error_code": "attack_outside_alert_window"})["reason"]
          == "attack_outside_alert_window")
    leak = build([], [ataque("T1110", "unknown")], T, 168,
                 correlation={"available": False, "error_code": "segredo C:\\x"})
    check("correlação: código fora da allowlist vira correlation_unavailable",
          leak["sources"]["attacks"]["correlation"]["reason"] == "correlation_unavailable")
    check("correlação: texto fora da allowlist nunca aparece no resultado", "segredo" not in repr(leak))
    check("correlação: indisponível sem código vira correlation_unavailable",
          corr({"available": False, "error_code": None})["reason"] == "correlation_unavailable")
    check("correlação: None com ataques -> None", corr(None) is None)


def run_contract() -> None:
    r = build([alerta_mitre(["T1059", "T1110.001"]), alerta_evento(4625)],
              [ataque("T1053", "partial"), ataque("T1087", "detected")], T, 168)
    rows = r["techniques"] + r["unmapped"]
    check("contrato: chaves exatas do envelope", set(r) == set(mitre_coverage.ENVELOPE_KEYS))
    check("contrato: chaves exatas de cada linha", all(set(t) == set(mitre_coverage.ROW_KEYS) for t in rows))
    check("contrato: chaves exatas de cada tática", all(set(t) == set(mitre_coverage.TACTIC_KEYS) for t in r["tactics"]))
    check("contrato: ATTACK_COUNT_KEYS", mitre_coverage.ATTACK_COUNT_KEYS
          == ("launched", "detected", "partial", "not_detected", "unknown"))
    check("contrato: ALERT_COUNT_KEYS", mitre_coverage.ALERT_COUNT_KEYS == ("total", "wazuh", "catalog"))
    check("contrato: chaves das contagens em cada linha",
          all(tuple(t["attacks"]) == mitre_coverage.ATTACK_COUNT_KEYS
              and tuple(t["alerts"]) == mitre_coverage.ALERT_COUNT_KEYS for t in rows))
    check("contrato: techniques e unmapped ordenados por id",
          [t["id"] for t in r["techniques"]] == sorted(t["id"] for t in r["techniques"])
          and [t["id"] for t in r["unmapped"]] == sorted(t["id"] for t in r["unmapped"]))
    check("contrato: technique_ids ordenados",
          all(t["technique_ids"] == sorted(t["technique_ids"]) for t in r["tactics"]))
    rates = [t["rate"] for t in rows] + [t["rate"] for t in r["tactics"]] + [r["totals"]["rate"]]
    check("contrato: todo o rate é float ou None",
          all(v is None or (isinstance(v, float) and not isinstance(v, bool)) for v in rates))


def run_no_side_effects() -> None:
    alerts = [alerta_mitre(["T1110.001", "T1059"]), alerta_evento(4625), alerta_evento(4624)]
    attacks = [ataque("T1053", "partial"), ataque("T1087", "unknown")]
    corr = {"available": False, "error_code": "indexer_unavailable", "alerts_truncated": False}
    before = (copy.deepcopy(alerts), copy.deepcopy(attacks), copy.deepcopy(T), copy.deepcopy(corr))
    first = build(alerts, attacks, T, 168, correlation=corr)
    check("sem efeitos: entradas e tabela intactas",
          (alerts, attacks, T, corr) == before)
    second = build(alerts, attacks, T, 168, correlation=corr)
    check("sem efeitos: duas chamadas iguais dão resultados iguais", first == second)
    antes = tactics_for("T1110", T)
    first["techniques"][0]["tactics"].append("Impact")
    first["techniques"][0]["alerts"]["total"] = 999
    check("sem efeitos: mutar o resultado não muda tactics_for nem a tabela",
          tactics_for("T1110", T) == antes and T == before[2])
    check("sem efeitos: mutar o resultado não muda a chamada seguinte",
          build(alerts, attacks, T, 168, correlation=corr) == second)


def run_purity() -> None:
    tree = ast.parse(Path(mitre_coverage.__file__).read_text(encoding="utf-8"))
    imported = set()
    calls_open = False
    names_loader = False
    forbidden = {"mitre_tactic", "rule", "mitre"}
    forbidden_found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
            calls_open = True
        elif isinstance(node, ast.Name) and node.id == "load_mitre_techniques":
            names_loader = True
        elif isinstance(node, ast.Attribute) and node.attr == "load_mitre_techniques":
            names_loader = True
        elif isinstance(node, ast.alias) and node.name == "load_mitre_techniques":
            names_loader = True
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in forbidden:
            forbidden_found.add(node.value)
    check("pureza: só importa __future__, attack_registry e mitre_catalog",
          imported <= {"__future__", "attack_registry", "mitre_catalog"})
    check("pureza: nenhuma chamada a open()", not calls_open)
    check("pureza: nunca nomeia load_mitre_techniques", not names_loader)
    check("pureza: nenhuma constante 'mitre_tactic', 'rule' ou 'mitre' (nunca lê o alerta cru nem a tática do registry)",
          not forbidden_found)


if __name__ == "__main__":
    run_empty()
    run_rows()
    run_unmapped()
    run_sources_by_origin()
    run_rates()
    run_tactics()
    run_unavailable_sources()
    run_correlation()
    run_contract()
    run_no_side_effects()
    run_purity()
    if failures:
        print(f"\n{len(failures)} caso(s) falharam:")
        for label in failures:
            print(f"  - {label}")
        sys.exit(1)
    print("\nTodos os casos passaram.")
