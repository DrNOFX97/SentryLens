"""Cobertura MITRE ATT&CK por técnica e por tática (R16, Phase 19).

Função pura: sem I/O, sem relógio, sem estado. NUNCA lê a tabela de técnicas
sozinha — recebe-a por argumento (a rota passa `load_mitre_techniques()`).
Junta duas fontes já obtidas pela rota: os alertas crus do Wazuh Indexer e os
ataques do attack_registry.

Regras de honestidade (as mesmas do `soc_metrics.py`):

- Fonte em baixo = `None` -> contagens `null`, nunca 0 (D-00c, D-08).
- `rate` é uma percentagem com 1 casa decimal: detetados sobre
  (detetados + parciais + não detetados). `unknown` fica fora do denominador
  (D-05) e `partial` conta como não detetado mas aparece à parte; sem
  denominador a taxa é `null`, nunca 0 (D-06).
- A tática vem SEMPRE da tabela via `tactics_for` (D-00b): nunca do log de
  ataques, nunca do campo de tática do attack_registry, nunca de
  `rule.mitre.tactic` do Wazuh.
- Uma técnica sem tática (nem própria, nem herdada do pai) vai para
  `unmapped` com as mesmas contagens e `tactics: []`; nunca é descartada e
  nunca é arrumada debaixo de uma tática (D-03).
- "Detetado" é só o veredito `detected` do attack_registry, contado na linha
  do id exato do ataque (D-04, D-02 emendado). Não há cruzamento por técnica
  nem pelo pai: `parent_of` serve só para herdar a tática e para o campo
  `parent` de cada linha. Nenhuma contagem atravessa linhas.
- Os alertas só entram no vocabulário MITRE através de
  `resolve_alert_techniques` (Phase 18); este módulo nunca abre o alerta cru.
"""

from __future__ import annotations

from attack_registry import VERDICTS
from mitre_catalog import (
    ATTACK_VERSION,
    ENTERPRISE_TACTICS,
    SOURCE_CATALOG,
    SOURCE_WAZUH,
    parent_of,
    resolve_alert_techniques,
    tactics_for,
)

SOURCE_UNAVAILABLE = "source_unavailable"
ATTACK_COUNT_KEYS = ("launched", *VERDICTS)
ALERT_COUNT_KEYS = ("total", SOURCE_WAZUH, SOURCE_CATALOG)
ROW_KEYS = ("id", "name", "parent", "tactics", "alerts", "attacks", "rate")
TACTIC_KEYS = ("tactic", "technique_ids", "attacks", "rate")
ENVELOPE_KEYS = (
    "window_hours", "attack_version", "sources", "alerts_truncated",
    "totals", "tactics", "techniques", "unmapped",
)
CORRELATION_REASONS = ("indexer_unavailable", "ml_model_unavailable", "attack_outside_alert_window")
CORRELATION_FALLBACK_REASON = "correlation_unavailable"


def detection_rate(counts) -> float | None:
    """% de ataques detetados: detected / (detected + partial + not_detected),
    1 casa decimal. `unknown` fica fora do denominador. None se `counts` é
    None ou o denominador é 0 (nunca 0)."""
    if counts is None:
        return None
    denominator = counts["detected"] + counts["partial"] + counts["not_detected"]
    if denominator == 0:
        return None
    return round(100 * counts["detected"] / denominator, 1)


def _new_alert_counts() -> dict:
    return {key: 0 for key in ALERT_COUNT_KEYS}


def _new_attack_counts() -> dict:
    return {key: 0 for key in ATTACK_COUNT_KEYS}


def _add_attack(counts: dict, verdict: str) -> None:
    counts["launched"] += 1
    counts[verdict] += 1


def _correlation_block(correlation) -> dict | None:
    """Correlação do attack_registry, para explicar vereditos `unknown`. O
    código só passa se estiver na allowlist; qualquer outro valor (ou
    indisponível sem código) vira `correlation_unavailable`, para nunca
    expor texto de exceção. None se não foi passada."""
    if correlation is None:
        return None
    available = bool(correlation.get("available"))
    if available:
        reason = None
    else:
        code = correlation.get("error_code")
        reason = code if code in CORRELATION_REASONS else CORRELATION_FALLBACK_REASON
    return {
        "available": available,
        "reason": reason,
        "alerts_truncated": bool(correlation.get("alerts_truncated")),
    }


def _verdict_of(attack) -> str:
    """Veredito do ataque; ausente ou fora de VERDICTS conta como unknown
    (nunca como detetado, nunca descartado)."""
    actual = attack.get("actual") if isinstance(attack, dict) else None
    verdict = actual.get("verdict") if isinstance(actual, dict) else None
    return verdict if verdict in VERDICTS else "unknown"


def build_mitre_coverage_report(
    raw_alerts,
    attacks,
    table: dict,
    hours: int,
    *,
    alerts_truncated: bool = False,
    correlation: dict | None = None,
) -> dict:
    """Cobertura MITRE por técnica e por tática (ver docstring do módulo).

    raw_alerts: alertas crus do Indexer (lista); None = fonte em baixo.
    attacks: ataques do attack_registry já filtrados pela janela (lista);
        None = fonte em baixo.
    table: tabela de técnicas (`load_mitre_techniques()`).
    """
    rows: dict[str, dict] = {
        tid: {"alerts": _new_alert_counts(), "attacks": _new_attack_counts()}
        for tid in table
    }

    # Fonte de alertas em baixo (None): nada é contado e as contagens saem
    # null, nunca 0 (D-08).
    alerts_up = raw_alerts is not None
    with_technique = 0
    without_technique = 0
    for raw in raw_alerts if alerts_up else ():
        items = resolve_alert_techniques(raw, table)
        if not items:
            without_technique += 1
            continue
        with_technique += 1
        for item in items:
            row = rows.setdefault(
                item["id"], {"alerts": _new_alert_counts(), "attacks": _new_attack_counts()})
            row["alerts"]["total"] += 1
            row["alerts"][item["source"]] += 1

    # Fonte de ataques em baixo (None): idem para ataques e taxas.
    attacks_up = attacks is not None
    unique = _new_attack_counts()
    by_tactic = {tactic: _new_attack_counts() for tactic in ENTERPRISE_TACTICS}
    for attack in attacks if attacks_up else ():
        tid = attack["mitre_technique"]
        verdict = _verdict_of(attack)
        row = rows.setdefault(
            tid, {"alerts": _new_alert_counts(), "attacks": _new_attack_counts()})
        _add_attack(row["attacks"], verdict)
        _add_attack(unique, verdict)
        for tactic in tactics_for(tid, table):
            _add_attack(by_tactic[tactic], verdict)

    techniques: list[dict] = []
    unmapped: list[dict] = []
    for tid in sorted(rows):
        row = rows[tid]
        parent = parent_of(tid)
        entry = {
            "id": tid,
            "name": table[tid]["name"] if tid in table else None,
            "parent": parent if parent != tid else None,
            "tactics": tactics_for(tid, table),
            "alerts": dict(row["alerts"]) if alerts_up else None,
            "attacks": dict(row["attacks"]) if attacks_up else None,
            "rate": detection_rate(row["attacks"]) if attacks_up else None,
        }
        (techniques if entry["tactics"] else unmapped).append(entry)

    tactics = [
        {
            "tactic": tactic,
            "technique_ids": [t["id"] for t in techniques if tactic in t["tactics"]],
            "attacks": dict(by_tactic[tactic]) if attacks_up else None,
            "rate": detection_rate(by_tactic[tactic]) if attacks_up else None,
        }
        for tactic in ENTERPRISE_TACTICS
    ]

    return {
        "window_hours": hours,
        "attack_version": ATTACK_VERSION,
        "sources": {
            "alerts": (
                {"available": True, "reason": None} if alerts_up
                else {"available": False, "reason": SOURCE_UNAVAILABLE}),
            "attacks": (
                {"available": True, "reason": None,
                 "correlation": _correlation_block(correlation)} if attacks_up
                else {"available": False, "reason": SOURCE_UNAVAILABLE, "correlation": None}),
        },
        # Sem pedido ao Indexer não há truncagem a afirmar: None, nunca False.
        "alerts_truncated": bool(alerts_truncated) if alerts_up else None,
        "totals": {
            "alerts": (
                {"fetched": len(raw_alerts), "with_technique": with_technique,
                 "without_technique": without_technique} if alerts_up else None),
            "attacks": dict(unique) if attacks_up else None,
            "rate": detection_rate(unique) if attacks_up else None,
        },
        "tactics": tactics,
        "techniques": techniques,
        "unmapped": unmapped,
    }
