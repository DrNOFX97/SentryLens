"""
Testes do technique_id do catálogo de Event IDs (event_catalog.py, Fase 18,
plano 18-02): o alerta cru chega à técnica MITRE por wazuh_win_fields ->
catalog_technique_id, e o que já existia (classify_alert, classify_wazuh_alert,
log_analyzer.py, chaves de CRITICAL_EVENTS) devolve exatamente o mesmo que
antes. Os digests fixados foram medidos antes da mudança (commit ac80dec).
Sem I/O de rede, sem `import main`.

Correr (a partir de scripts/):
    python test_event_catalog_mitre.py
"""

import ast
import dataclasses
import hashlib
import json
import sys
from pathlib import Path

import model_registry
from attack_library import MITRE_RE
from event_catalog import (
    CRITICAL_EVENTS,
    DEFENDER_CHANNEL,
    DEFENDER_EVENTS,
    catalog_technique_id,
    classify_alert,
    classify_wazuh_alert,
    wazuh_win_fields,
)

failures: list[str] = []

# Medidos em ac80dec, antes de qualquer edição do catálogo.
GOLDEN_CLASSIFY_SHA256 = "f56e004b1d19c8937dfdc3e47e1aa97689c0b259edd4812515e6e6337e08fd5a"
GOLDEN_LOG_ANALYZER_SHA256 = "1f2c7843d6ac3fd5c7b41fd9fef4bde9b943e007ce922a7c47e6b17ce3772051"
CATALOG_SHA256 = "5e98dbc2d47bdb4f737db77ff2f7cb6f4853704fee7141957536ebe3e54db5ca"
CRITICAL_EVENT_IDS = [
    4624, 4625, 4672, 4688, 4698, 4699, 4700, 4701, 4702, 4703, 4704, 4713, 4719,
    4720, 4722, 4723, 4724, 4725, 4726, 4728, 4729, 4732, 4733, 4738, 4740, 4756,
    4757, 4767, 4797, 5140, 5145,
]
# D-01: a lista exata dos Event IDs com técnica inequívoca. Acrescentar ou tirar
# um mapeamento em event_catalog.py obriga a mudar este literal de forma consciente.
EXPECTED_TECHNIQUE_IDS = {
    4625: "T1110",
    4698: "T1053.005",
    4720: "T1136.001",
    4726: "T1531",
    4728: "T1098",
    4732: "T1098",
    4756: "T1098",
    4719: "T1562.002",
}
ROOT = Path(__file__).resolve().parent.parent
CLASSIFY_KEYS = {"friendly_name", "severity", "category", "recommendation"}


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def _digest(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def classify_digest() -> str:
    """Receita fixada em ac80dec: saídas de classify_alert para os 31 Event IDs,
    None, 9999 e os 7 do Defender (no canal do Defender)."""
    out: list = []
    for eid in sorted(CRITICAL_EVENTS) + [None, 9999]:
        out.append([eid, classify_alert(eid)])
    for eid in sorted(DEFENDER_EVENTS):
        out.append(["defender", eid, classify_alert(eid, DEFENDER_CHANNEL)])
    return _digest(out)


def run_tracer() -> None:
    alerta = {"data": {"win": {"system": {"eventID": "4625"}}}}
    check("wazuh_win_fields extrai (4625, None, None)", wazuh_win_fields(alerta) == (4625, None, None))
    check("catalog_technique_id(4625) == T1110", catalog_technique_id(4625) == "T1110")
    check("alerta cru 4625 -> T1110 pela extração partilhada",
          catalog_technique_id(*wazuh_win_fields(alerta)[:2]) == "T1110")
    check("classify_wazuh_alert(4625) == classify_alert(4625)", classify_wazuh_alert(alerta) == classify_alert(4625))
    for eid in sorted(CRITICAL_EVENTS):
        if set(classify_alert(eid)) != CLASSIFY_KEYS:
            check(f"classify_alert({eid}) tem exatamente as 4 chaves", False)
            break
    else:
        check("classify_alert tem exatamente as 4 chaves em todos os Event IDs", True)
    check("digest de classify_alert igual ao medido antes da mudança", classify_digest() == GOLDEN_CLASSIFY_SHA256)
    check("o conjunto de chaves de CRITICAL_EVENTS não mudou (31)", sorted(CRITICAL_EVENTS) == CRITICAL_EVENT_IDS)
    check("model_registry.catalog_sha256() inalterado", model_registry.catalog_sha256() == CATALOG_SHA256)


def log_analyzer_digest() -> str:
    """Receita fixada em ac80dec: análise de sample_events.json pelo log_analyzer
    da Fase 1. Os alertas anomaly_* levam datetime.now() no timestamp, que é
    retirado para o digest ser estável entre corridas."""
    sys.path.append(str(ROOT))  # append: a raiz só tem log_analyzer.py, nada a sombrear
    import log_analyzer

    a = log_analyzer.WindowsEventLogAnalyzer()
    a.parse_evtx_json(str(ROOT / "sample_events.json"))
    a.analyze_events()
    alerts = []
    for alerta in a.alerts:
        d = dataclasses.asdict(alerta)
        if str(d["event_id"]).startswith("anomaly_"):
            d.pop("timestamp", None)
        alerts.append(d)
    return _digest({"alerts": alerts, "statistics": dict(sorted(a.statistics.items()))})


def _imported_modules(path: Path) -> set[str]:
    mods: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            mods.update(n.name.split(".")[0] for n in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module.split(".")[0])
    return mods


def run_mapping() -> None:
    actual = {eid: info["technique_id"] for eid, info in CRITICAL_EVENTS.items() if "technique_id" in info}
    check("exatamente os 8 mapeamentos de D-01", actual == EXPECTED_TECHNIQUE_IDS)
    check("technique_id é sempre um id MITRE bem formado",
          all(isinstance(t, str) and MITRE_RE.fullmatch(t) for t in actual.values()))
    check("nenhum technique_id é None nem vazio (vazio = chave ausente)",
          all(info.get("technique_id", "x") not in (None, "") for info in CRITICAL_EVENTS.values()))
    check("nenhuma entrada de DEFENDER_EVENTS tem technique_id (D-02)",
          not any("technique_id" in info for info in DEFENDER_EVENTS.values()))

    # catalog_technique_id
    casos = [
        ((4625,), "T1110"),
        ((4625, "Security"), "T1110"),
        ((4625, 42), "T1110"),
        ((4625, DEFENDER_CHANNEL), None),
        ((4625, DEFENDER_CHANNEL.upper()), None),
        ((5001, DEFENDER_CHANNEL), None),
        ((4624,), None),
        ((9999,), None),
        ((None,), None),
        (("4625",), None),
        ((True,), None),
        (([4625],), None),
    ]
    for args, esperado in casos:
        try:
            got = catalog_technique_id(*args)
        except Exception as exc:  # noqa: BLE001 - o contrato é nunca levantar
            check(f"catalog_technique_id{args} não levanta ({type(exc).__name__})", False)
            continue
        check(f"catalog_technique_id{args} == {esperado!r}", got == esperado)

    # wazuh_win_fields + equivalência de classify_wazuh_alert
    defender = {"data": {"win": {"system": {"eventID": "5001", "channel": DEFENDER_CHANNEL}}}}
    fixtures = [
        ({"data": {"win": {"system": {"eventID": "4698"}}}}, (4698, None, None)),
        ({"data": {"win": {"system": {"eventID": 4720, "channel": "Security"}, "eventdata": {"a": 1}}}},
         (4720, "Security", {"a": 1})),
        (defender, (5001, DEFENDER_CHANNEL, None)),
        ({"data": {"win": {"system": {"eventID": "abc"}}}}, (None, None, None)),
        ({"data": None}, (None, None, None)),
        ({"data": {"win": "x"}}, (None, None, None)),
        ({}, (None, None, None)),
        ("lixo", (None, None, None)),
        (None, (None, None, None)),
    ]
    for alerta, esperado in fixtures:
        try:
            got = wazuh_win_fields(alerta)
        except Exception as exc:  # noqa: BLE001
            check(f"wazuh_win_fields({alerta!r}) não levanta ({type(exc).__name__})", False)
            continue
        check(f"wazuh_win_fields({alerta!r}) == {esperado!r}", got == esperado)
        check(f"classify_wazuh_alert({alerta!r}) == classify_alert(*esperado)",
              classify_wazuh_alert(alerta) == classify_alert(*esperado))
    check("alerta do Defender 5001 não ganha técnica pelo catálogo",
          catalog_technique_id(*wazuh_win_fields(defender)[:2]) is None)

    # Fase 1 intacta
    check("digest da análise do log_analyzer igual ao medido antes da mudança",
          log_analyzer_digest() == GOLDEN_LOG_ANALYZER_SHA256)
    importados = _imported_modules(ROOT / "log_analyzer.py")
    check("log_analyzer.py não importa event_catalog, mitre_catalog nem detection_event",
          not importados & {"event_catalog", "mitre_catalog", "detection_event"})
    check("classify_alert continua igual ao digest medido com os 8 mapeamentos",
          classify_digest() == GOLDEN_CLASSIFY_SHA256)


if __name__ == "__main__":
    run_tracer()
    run_mapping()
    print()
    if failures:
        print(f"{len(failures)} teste(s) falharam:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("Todos os testes passaram")
