"""
Registo de ataques (R4). Módulo puro, como redblue_correlator.py/
incident_engine.py: sem I/O, sem rede, sem relógio. Recebe o attack_log, os
alertas já classificados (ml_results), as deteções de rede e os incidentes já
obtidos, e devolve o registo de cada ataque lançado: o que foi, o que se
esperava detetar e o que realmente foi detetado, com referências (ids e
contagens) a alertas e incidentes — nunca cópias de payloads.

Não reimplementa parsing nem janelas: usa parse_launched_attacks e
build_redblue_report. Nunca lança exceção sobre dados malformados.

Excepção à regra "sem I/O" (R5): expected_detection() consulta
attack_library.get_expected_sensors() para o default por cenário em vez de
reimplementar esse mapeamento aqui (fonte única de verdade). Isso é leitura
de um ficheiro já carregado em cache por load_attack_library() no arranque do
backend (ver main.py) — nunca toca em rede/relógio, e DEFAULT_EXPECTED
continua como rede de segurança para um cenário sem entrada na biblioteca.
"""

import re

from attack_library import get_expected_sensors
from redblue_correlator import DEFAULT_WINDOW_SECONDS, build_redblue_report, parse_launched_attacks

EXPECTED_SOURCES = ("rule", "ml", "network")
DEFAULT_EXPECTED = ("rule", "ml")  # rede de segurança: cenário sem entrada na Attack Library (R5)
VERDICTS = ("detected", "partial", "not_detected", "unknown")
UNKNOWN_OPERATOR = "unknown"
MAX_FIELD_LEN = 64

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f\x85  ]")


def clean_text(value, max_len: int = MAX_FIELD_LEN) -> str | None:
    """Texto seguro para expor: só str, sem caracteres de controlo, aparado,
    truncado. Vazio/inválido -> None."""
    if not isinstance(value, str):
        return None
    cleaned = _CONTROL_CHARS.sub(" ", value).strip()[:max_len].strip()
    return cleaned or None


def normalize_operator(raw) -> str:
    return clean_text(raw) or UNKNOWN_OPERATOR


def normalize_attack_id(raw) -> int | None:
    """Id inteiro positivo (bool e floats não contam); caso contrário None."""
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int) and 0 < raw <= 999_999_999:
        return raw
    return None


def expected_detection(entry: dict) -> tuple[list[str], str]:
    """(fontes esperadas, origem). O log pode trazer `expected`; valores fora
    da allowlist são descartados; sem nenhum válido usa-se o default do
    cenário — vindo da Attack Library (R5) quando o cenário lá tiver entrada,
    senão o DEFAULT_EXPECTED fixo (cenário novo ainda não documentado)."""
    raw = entry.get("expected")
    if isinstance(raw, list):
        valid = [s for s in EXPECTED_SOURCES if s in raw]
        if valid:
            return valid, "log"
    library_default = get_expected_sensors(entry.get("scenario") or "")
    return (library_default or list(DEFAULT_EXPECTED)), "scenario_default"


def achieved_sources(attempt: dict) -> list[str]:
    sources = []
    if attempt.get("detected_by") in ("rule", "both"):
        sources.append("rule")
    if attempt.get("detected_by") in ("ml", "both"):
        sources.append("ml")
    if attempt.get("detected_by_network"):
        sources.append("network")
    return sources


def verdict(expected: list[str], achieved: list[str], correlation_available: bool,
            alerts_truncated: bool = False) -> str:
    if not correlation_available:
        return "unknown"
    if not achieved:
        # Alertas cortados no teto: a ausência de correspondência pode ser um
        # falso negativo (os mais antigos ficaram de fora) -> não se afirma.
        return "unknown" if alerts_truncated else "not_detected"
    return "detected" if all(s in achieved for s in expected) else "partial"


def _incidents_by_attack(incidents: list[dict] | None) -> dict[str, list[dict]]:
    mapping: dict[str, list[dict]] = {}
    for inc in incidents or []:
        if not isinstance(inc, dict):
            continue
        for attack_id in inc.get("attack_ids") or []:
            mapping.setdefault(str(attack_id), []).append({
                "id": inc.get("id"),
                "severity": inc.get("severity"),
                "status": inc.get("status"),
                "evidence_count": inc.get("evidence_count"),
            })
    return mapping


def build_attack_registry(
    attack_log: list,
    scenarios: dict,
    ml_results: list[dict] | None,
    network_detections: list[dict] | None = None,
    incidents: list[dict] | None = None,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    correlation_available: bool = True,
    alerts_truncated: bool = False,
) -> dict:
    """Registo dos ataques lançados, do mais recente para o mais antigo.

    correlation_available=False (Indexer/modelo ML em baixo): os campos de
    identidade/esperado/incidentes continuam a sair, mas o veredito é
    "unknown" — nunca se afirma "não detetado" sem correlação feita.
    """
    parsed, not_executed, unknown_scenario, invalid_entries = parse_launched_attacks(attack_log, scenarios)
    report = build_redblue_report(
        attack_log, ml_results if correlation_available else [], scenarios,
        window_seconds=window_seconds,
        network_detections=network_detections if correlation_available else None,
    )
    attempts = report["attempts"]
    by_attack = _incidents_by_attack(incidents)

    id_counts: dict[int, int] = {}
    for _, entry in parsed:
        attack_id = normalize_attack_id(entry.get("id"))
        if attack_id is not None:
            id_counts[attack_id] = id_counts.get(attack_id, 0) + 1

    ok = correlation_available
    attacks: list[tuple] = []
    for (ts, entry), attempt in zip(parsed, attempts):
        scenario = scenarios[entry["scenario"]]
        attack_id = normalize_attack_id(entry.get("id"))
        expected, expected_source = expected_detection(entry)
        achieved = achieved_sources(attempt) if ok else []
        linked = by_attack.get(str(attack_id), []) if attack_id is not None else []
        technique = clean_text(entry.get("technique"))
        tool = clean_text(entry.get("tool"))
        attacks.append((ts, {
            "id": attack_id,
            "duplicate_id": attack_id is not None and id_counts[attack_id] > 1,
            "timestamp": attempt["timestamp"],
            "scenario": entry["scenario"],
            "mitre_tactic": scenario.mitre_tactic,
            "mitre_technique": technique or scenario.mitre_technique,
            "technique_source": "log" if technique else "scenario",
            "tool": tool or scenario.tool,
            "tool_source": "log" if tool else "scenario",
            "source": clean_text(entry.get("source")),
            "target": clean_text(entry.get("target")),
            "operator": normalize_operator(entry.get("operator")),
            "expected": {"detection": expected, "source": expected_source, "event_ids": list(scenario.event_ids)},
            "actual": {
                "verdict": verdict(expected, achieved, ok, alerts_truncated),
                "correlation_reason": "alerts_truncated" if ok and alerts_truncated and not achieved else None,
                "achieved": achieved,
                "detected_by": attempt["detected_by"] if ok else None,
                "detected_by_network": attempt["detected_by_network"] if ok else None,
                "coverage_gap": attempt["coverage_gap"] if ok else None,
                "mttd_seconds": attempt["mttd_seconds"] if ok else None,
                "mttd_network_seconds": attempt["mttd_network_seconds"] if ok else None,
            },
            "evidence": {
                "matched_event_ids": attempt["matched_event_ids"] if ok else [],
                "matched_alert_count": attempt["matched_alert_count"] if ok else None,
                "network_detection_types": attempt["network_detection_types"] if ok else [],
                "incident_count": len(linked),
            },
            "incidents": linked,
        }))

    # Ordena pelo instante real (os timestamps do log misturam 'Z' e '+00:00').
    attacks.sort(key=lambda item: item[0], reverse=True)
    return {
        "attacks": [a for _, a in attacks],
        "skipped": {
            "not_executed": len(not_executed),
            "unknown_scenario": len(unknown_scenario),
            "invalid": len(invalid_entries),
        },
    }


def summarize(attacks: list[dict]) -> dict:
    counts = {v: 0 for v in VERDICTS}
    for attack in attacks:
        counts[attack["actual"]["verdict"]] += 1
    return {"total": len(attacks), **counts}
