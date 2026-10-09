"""
Métricas SOC (R8): MTTD, MTTR, cobertura e taxa de deteção (com FN/FP).

Função pura: recebe o relatório Red vs Blue (redblue_correlator.
build_redblue_report) e a lista de incidentes (IncidentStore.list_for_metrics)
já obtidos, e devolve o relatório. Sem I/O, para ser testável sem o Wazuh.

Regras de honestidade dos dados: sem amostra o valor é None (nunca 0) e o
bloco fica available=False; uma fonte em baixo (None) fica
reason="source_unavailable"; abaixo de min_sample o valor é mostrado com
small_sample=True (e a taxa de FP não é calculada).

Ver docs/superpowers/specs/2026-10-09-r8-metricas-design.md.
"""

from __future__ import annotations

import math
import os
from datetime import datetime, timezone

from incident_engine import OPEN_STATUSES, parse_timestamp

DEFAULT_MIN_SAMPLE = 5

DEFINITIONS = {
    "mttd": "Tempo entre o ataque lançado e a 1.ª deteção sinalizada (regra, ML ou rede; a mais cedo).",
    "mttr": "Tempo entre a 1.ª evidência do incidente e a sua (última) passagem a RESOLVED; só incidentes resolvidos.",
    "fn": "Falso negativo: ataque lançado sem qualquer deteção sinalizada.",
    "fp": "Falso positivo: incidente fechado de NEW para CLOSED (com nota do analista). Taxa = FP / incidentes fechados.",
    "coverage": "Cobertura: cenários/técnicas lançados na janela com pelo menos uma deteção. Lacuna = lançado e nunca detetado.",
    "rate": "Taxa de deteção: ataques detetados / ataques lançados na janela (excluídos: não executados, cenário desconhecido, entradas inválidas).",
}


def _min_sample_from_env() -> int:
    try:
        value = int(os.getenv("METRICS_MIN_SAMPLE", DEFAULT_MIN_SAMPLE))
    except ValueError:
        return DEFAULT_MIN_SAMPLE
    return value if value > 0 else DEFAULT_MIN_SAMPLE


def median(values: list[float]) -> float | None:
    ordered = sorted(values)
    n = len(ordered)
    if n == 0:
        return None
    mid = n // 2
    return ordered[mid] if n % 2 else (ordered[mid - 1] + ordered[mid]) / 2


def percentile_nearest_rank(values: list[float], pct: float) -> float | None:
    ordered = sorted(values)
    if not ordered:
        return None
    rank = max(1, math.ceil(pct / 100 * len(ordered)))
    return ordered[rank - 1]


def duration_block(values: list, min_sample: int) -> dict:
    """Mediana/p90/média de uma lista de durações em segundos (None ignorados)."""
    clean = [float(v) for v in values if v is not None]
    n = len(clean)
    if n == 0:
        return {"available": False, "reason": "no_data", "n": 0, "small_sample": False,
                "median_s": None, "p90_s": None, "avg_s": None}
    return {
        "available": True, "reason": None, "n": n, "small_sample": n < min_sample,
        "median_s": round(median(clean), 2),
        "p90_s": round(percentile_nearest_rank(clean, 90), 2),
        "avg_s": round(sum(clean) / n, 2),
    }


def _unavailable_duration() -> dict:
    block = duration_block([], 1)
    block["reason"] = "source_unavailable"
    return block


def _is_detected(attempt: dict) -> bool:
    # `detected` do correlator é True para qualquer alerta correspondente,
    # mesmo não sinalizado por regra/ML — isso não é uma deteção.
    return attempt.get("detected_by", "none") != "none" or bool(attempt.get("detected_by_network"))


def _detection_seconds(attempt: dict) -> float | None:
    times = []
    if attempt.get("detected_by", "none") != "none" and attempt.get("mttd_seconds") is not None:
        times.append(attempt["mttd_seconds"])
    if attempt.get("detected_by_network") and attempt.get("mttd_network_seconds") is not None:
        times.append(attempt["mttd_network_seconds"])
    return min(times) if times else None


def _source_label(attempt: dict) -> str | None:
    sources = []
    if attempt.get("detected_by") in ("rule", "both"):
        sources.append("rule")
    if attempt.get("detected_by") in ("ml", "both"):
        sources.append("ml")
    if attempt.get("detected_by_network"):
        sources.append("network")
    if not sources:
        return None
    return sources[0] if len(sources) == 1 else "multiple"


def _mttd_block(attempts: list[dict], min_sample: int) -> dict:
    timed = [(a["scenario"], t) for a in attempts if (t := _detection_seconds(a)) is not None]
    block = duration_block([t for _, t in timed], min_sample)
    block["by_scenario"] = {
        name: duration_block([t for s, t in timed if s == name], min_sample)
        for name in sorted({a["scenario"] for a in attempts})
    }
    return block


def _coverage_block(attempts: list[dict]) -> dict:
    def group(key: str) -> tuple[dict, list[str]]:
        seen: dict[str, bool] = {}
        for a in attempts:
            name = a.get(key)
            if not name:
                continue
            seen[name] = seen.get(name, False) or _is_detected(a)
        total = len(seen)
        covered = sum(1 for v in seen.values() if v)
        gaps = sorted(k for k, v in seen.items() if not v)
        return ({"covered": covered, "total": total,
                 "pct": round(100 * covered / total, 1) if total else None}, gaps)

    scenarios, scenario_gaps = group("scenario")
    techniques, technique_gaps = group("mitre_technique")
    return {
        "available": bool(attempts), "reason": None if attempts else "no_data",
        "scenarios": scenarios, "techniques": techniques,
        "gaps": {"scenarios": scenario_gaps, "techniques": technique_gaps},
    }


def _is_false_positive(incident: dict) -> bool:
    return any(
        e.get("kind") == "status_changed"
        and (e.get("data") or {}).get("from") == "NEW"
        and (e.get("data") or {}).get("to") == "CLOSED"
        for e in incident.get("timeline") or []
    )


def _fp_block(incidents: list[dict] | None, min_sample: int) -> dict:
    if incidents is None:
        return {"available": False, "reason": "source_unavailable", "n": 0, "closed_total": 0,
                "small_sample": False, "pct": None}
    closed = [i for i in incidents if i.get("status") == "CLOSED"]
    false_positives = sum(1 for i in closed if _is_false_positive(i))
    enough = len(closed) >= min_sample
    return {"available": True, "reason": None, "n": false_positives, "closed_total": len(closed),
            "small_sample": not enough,
            "pct": round(100 * false_positives / len(closed), 1) if enough else None}


def _rate_block(report: dict, attempts: list[dict], incidents: list[dict] | None, min_sample: int) -> dict:
    launched = len(attempts)
    detected_attempts = [a for a in attempts if _is_detected(a)]
    by_source = {"rule": 0, "ml": 0, "network": 0, "multiple": 0}
    for a in detected_attempts:
        by_source[_source_label(a)] += 1
    detected = len(detected_attempts)
    return {
        "available": launched > 0, "reason": None if launched else "no_data",
        "launched": launched, "detected": detected, "not_detected": launched - detected,
        "false_negatives": launched - detected,
        "detection_pct": round(100 * detected / launched, 1) if launched else None,
        "small_sample": 0 < launched < min_sample,
        "by_source": by_source,
        "excluded": {
            "not_executed": len(report.get("not_executed") or []),
            "unknown_scenario": len(report.get("unknown_scenario") or []),
            "invalid_entries": len(report.get("invalid_entries") or []),
        },
        "false_positives": _fp_block(incidents, min_sample),
    }


def _resolved_seconds(incident: dict) -> float | None:
    if incident.get("status") not in ("RESOLVED", "CLOSED"):
        return None
    resolutions = [
        e for e in incident.get("timeline") or []
        if e.get("kind") == "status_changed" and (e.get("data") or {}).get("to") == "RESOLVED"
    ]
    if not resolutions:
        return None
    start = parse_timestamp(incident.get("first_evidence_at"))
    end = parse_timestamp(resolutions[-1].get("ts"))
    if start is None or end is None:
        return None
    return max(0.0, (end - start).total_seconds())


def _mttr_block(incidents: list[dict], min_sample: int) -> dict:
    block = duration_block([_resolved_seconds(i) for i in incidents], min_sample)
    block["open_count"] = sum(1 for i in incidents if i.get("status") in OPEN_STATUSES)
    block["first_response"] = duration_block(
        [i.get("time_to_first_response_seconds") for i in incidents], min_sample
    )
    return block


def build_metrics_report(
    redblue_report: dict | None,
    incidents: list[dict] | None,
    window_hours: int,
    min_sample: int | None = None,
    now: datetime | None = None,
) -> dict:
    """redblue_report/incidents = None significa "fonte indisponível" (≠ vazio)."""
    min_sample = min_sample if min_sample else _min_sample_from_env()
    generated_at = (now or datetime.now(timezone.utc)).isoformat()

    if redblue_report is None:
        down = {"available": False, "reason": "source_unavailable"}
        mttd = {**_unavailable_duration(), "by_scenario": {}}
        coverage = {**down, "scenarios": None, "techniques": None, "gaps": {"scenarios": [], "techniques": []}}
        rate = {**down, "launched": None, "detected": None, "not_detected": None, "false_negatives": None,
                "detection_pct": None, "small_sample": False,
                "by_source": None, "excluded": None, "false_positives": _fp_block(incidents, min_sample)}
    else:
        attempts = redblue_report.get("attempts") or []
        mttd = _mttd_block(attempts, min_sample)
        coverage = _coverage_block(attempts)
        rate = _rate_block(redblue_report, attempts, incidents, min_sample)

    if incidents is None:
        mttr = {**_unavailable_duration(), "open_count": None, "first_response": _unavailable_duration()}
    else:
        mttr = _mttr_block(incidents, min_sample)

    return {
        "window_hours": window_hours,
        "generated_at": generated_at,
        "min_sample": min_sample,
        "mttd": mttd,
        "mttr": mttr,
        "coverage": coverage,
        "rate": rate,
        "definitions": DEFINITIONS,
    }
