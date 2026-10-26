"""
Testes da ligação do catálogo do Defender aos alertas: classify_wazuh_alert
(event_catalog.py), main._enrich_alert e detection_event.from_rule_alert.
Sem o laboratório Wazuh: só funções puras sobre alertas brutos.
Ver docs/superpowers/specs/2026-10-26-defender-events-design.md.

Correr (a partir de scripts/):
    python test_defender_alerts.py
"""

import os
import sys

os.environ.setdefault("SENTRYLENS_API_KEY", "chave-de-teste-nao-usar-em-producao")

import main
from detection_event import from_rule_alert
from event_catalog import DEFENDER_CHANNEL, classify_wazuh_alert

main.app.router.on_startup.clear()

failures: list[str] = []

NAO_CATALOGADO = "Evento não catalogado"
ROTINA = r"HKLM\SOFTWARE\Microsoft\Windows Defender\CoreService\WdConfigHash = 0xBCF68827"


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def defender_alert(event_id, event_data=None, channel=DEFENDER_CHANNEL) -> dict:
    return {
        "_id": f"d{event_id}", "@timestamp": "2026-10-26T10:00:00Z",
        "agent": {"name": "FARENSE1910", "ip": "192.168.1.169"},
        "rule": {"id": "62123", "level": 12},
        "data": {"win": {"system": {"eventID": str(event_id), "channel": channel},
                         "eventdata": event_data}},
    }


def run_enrich_alert() -> None:
    e = main._enrich_alert(defender_alert(1116))
    check("_enrich_alert 1116 -> nome amigável", e["friendly_name"] == "Defender: Malware Detected")
    check("_enrich_alert 1116 -> high", e["severity"] == "high")
    check("_enrich_alert 1116 -> protecao_endpoint", e["category"] == "protecao_endpoint")
    check("_enrich_alert 1116 -> windows_event_id 1116", e["windows_event_id"] == 1116)

    e = main._enrich_alert(defender_alert(1116, channel="Application"))
    check("1116 no canal Application -> não catalogado", e["friendly_name"] == NAO_CATALOGADO)
    check("... mas o windows_event_id continua 1116", e["windows_event_id"] == 1116)

    antigo = main._enrich_alert({"@timestamp": "2026-10-26T10:00:00Z", "agent": {"ip": "1.2.3.4"},
                                 "data": {"win": {"system": {"eventID": "4625"}}}})
    check("4625 sem canal continua high / Failed Logon",
          antigo["severity"] == "high" and antigo["friendly_name"] == "Failed Logon")


def run_from_rule_alert() -> None:
    e = from_rule_alert(defender_alert(5001))
    check("from_rule_alert 5001 -> high", e is not None and e["severity"] == "high")
    check("from_rule_alert 5001 -> label", e["label"] == "Defender: Real-Time Protection Disabled")
    e = from_rule_alert(defender_alert(5007, {"newValue": ROTINA}))
    check("from_rule_alert 5007 de rotina -> info", e is not None and e["severity"] == "info")
    e = from_rule_alert(defender_alert(5007, {"newValue": r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\x = 0x0"}))
    check("from_rule_alert 5007 a mexer em Exclusions -> high", e is not None and e["severity"] == "high")
    antigo = from_rule_alert({"@timestamp": "2026-10-26T10:00:00Z", "agent": {"ip": "1.2.3.4"},
                              "data": {"win": {"system": {"eventID": "4625"}}}})
    check("from_rule_alert 4625 sem canal continua high / Failed Logon",
          antigo["severity"] == "high" and antigo["label"] == "Failed Logon")


def run_entradas_malformadas() -> None:
    casos = {
        "sem data": {},
        "data sem win": {"data": {}},
        "win sem system": {"data": {"win": {}}},
        "eventID não numérico": {"data": {"win": {"system": {"eventID": "abc", "channel": DEFENDER_CHANNEL}}}},
        "eventdata None": defender_alert(5007, None),
        "channel None": {"data": {"win": {"system": {"eventID": "1116", "channel": None}}}},
        "data não é dict": {"data": "x"},
    }
    for nome, alerta in casos.items():
        try:
            resultado = classify_wazuh_alert(alerta)
            check(f"{nome}: sem exceção", isinstance(resultado, dict) and "friendly_name" in resultado)
        except Exception as exc:  # noqa: BLE001 - é exatamente o que o teste procura
            check(f"{nome}: sem exceção (levantou {type(exc).__name__})", False)
    check("sem data -> não catalogado", classify_wazuh_alert({})["friendly_name"] == NAO_CATALOGADO)
    check("eventID não numérico -> não catalogado",
          classify_wazuh_alert(casos["eventID não numérico"])["friendly_name"] == NAO_CATALOGADO)


run_enrich_alert()
run_from_rule_alert()
run_entradas_malformadas()

if failures:
    print(f"\n[FALHOU] {len(failures)} caso(s) falharam")
    sys.exit(1)
print("\n[OK] Todos os testes passaram")
