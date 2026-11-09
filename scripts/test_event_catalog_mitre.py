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

import hashlib
import json
import sys

import model_registry
from event_catalog import (
    CRITICAL_EVENTS,
    DEFENDER_EVENTS,
    catalog_technique_id,
    classify_alert,
    classify_wazuh_alert,
    wazuh_win_fields,
)

failures: list[str] = []

# Medidos em ac80dec, antes de qualquer edição do catálogo.
GOLDEN_CLASSIFY_SHA256 = "f56e004b1d19c8937dfdc3e47e1aa97689c0b259edd4812515e6e6337e08fd5a"
CATALOG_SHA256 = "5e98dbc2d47bdb4f737db77ff2f7cb6f4853704fee7141957536ebe3e54db5ca"
CRITICAL_EVENT_IDS = [
    4624, 4625, 4672, 4688, 4698, 4699, 4700, 4701, 4702, 4703, 4704, 4713, 4719,
    4720, 4722, 4723, 4724, 4725, 4726, 4728, 4729, 4732, 4733, 4738, 4740, 4756,
    4757, 4767, 4797, 5140, 5145,
]
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
    from event_catalog import DEFENDER_CHANNEL

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


if __name__ == "__main__":
    run_tracer()
    print()
    if failures:
        print(f"{len(failures)} teste(s) falharam:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("Todos os testes passaram")
