"""
Motor de correlação Red Team / Blue Team (Fase 11, Onda 1 + Onda 2).

Cruza o log de ataques lançados pela VM Kali (attack_scenarios.py,
scripts/attack_log.jsonl) com os alertas Wazuh já classificados por
ml_anomalies.build_ml_anomalies_report() (regra + ML lado a lado), para
responder, por tentativa de ataque: foi detetado? por regra, por ML, por
ambos, ou por nenhum? em quanto tempo (MTTD)?

Onda 2 acrescenta a rede (network_detections.py, via network_monitor.py)
como um 3º método de deteção independente do Wazuh — cada tentativa de
ataque ganha detected_by_network/network_detection_types/
mttd_network_seconds/coverage_gap, e cada bucket de by_scenario/overall
ganha detected_by_network_only/detected_by_windows_only/
detected_by_both_sources/detected_by_neither, para expor tentativas que só
a rede viu (pontos cegos do lado Windows/Wazuh).

Módulo puro (como lifecycle.py/rbac.py/admin_activity.py/ml_anomalies.py):
não faz I/O nem chamadas de rede, só processa listas já obtidas. Nunca
lança exceção sobre dados malformados — entradas inválidas são ignoradas
ou desviadas para not_executed/unknown_scenario, nunca descartadas em
silêncio.
"""

from datetime import datetime, timedelta, timezone

DEFAULT_WINDOW_SECONDS = 300


def _parse_timestamp(raw_timestamp: str | None) -> datetime | None:
    """Mesma convenção do resto do projeto (lifecycle.py/feature_extractor.py):
    aceita o sufixo 'Z', assume UTC quando não há fuso indicado, devolve
    None em vez de lançar exceção para timestamps malformados."""
    if not raw_timestamp or not isinstance(raw_timestamp, str):
        return None
    normalized = raw_timestamp.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def parse_launched_attacks(attack_log: list[dict], scenarios: dict) -> tuple[list, list, list, list]:
    """Separa o attack_log em (tentativas, not_executed, unknown_scenario,
    invalid_entries). `tentativas` = [(datetime, entrada)] ordenadas por
    tempo: só entradas com status "launched", cenário conhecido e timestamp
    válido. Partilhada com incident_engine para a regra nunca divergir."""
    parsed_attacks: list[tuple[datetime, dict]] = []
    not_executed: list[dict] = []
    unknown_scenario: list[dict] = []
    invalid_entries: list[dict] = []
    for entry in attack_log or []:
        if not isinstance(entry, dict):
            invalid_entries.append(entry)
            continue
        if entry.get("status") != "launched":
            not_executed.append(entry)
            continue
        scenario_name = entry.get("scenario")
        if scenario_name not in scenarios:
            unknown_scenario.append(entry)
            continue
        ts = _parse_timestamp(entry.get("timestamp"))
        if ts is None:
            invalid_entries.append(entry)
            continue
        parsed_attacks.append((ts, entry))

    parsed_attacks.sort(key=lambda item: item[0])
    return parsed_attacks, not_executed, unknown_scenario, invalid_entries


def attack_windows(
    parsed_attacks: list[tuple[datetime, dict]], window_seconds: int = DEFAULT_WINDOW_SECONDS
) -> list[tuple[datetime, datetime, dict]]:
    """Janela de correlação de cada tentativa: `window_seconds` a partir do
    início, cortada pelo início da tentativa seguinte (o que vier primeiro)."""
    windows: list[tuple[datetime, datetime, dict]] = []
    for i, (ts, entry) in enumerate(parsed_attacks):
        window_end = ts + timedelta(seconds=window_seconds)
        if i + 1 < len(parsed_attacks):
            next_ts = parsed_attacks[i + 1][0]
            if next_ts < window_end:
                window_end = next_ts
        windows.append((ts, window_end, entry))
    return windows


def build_redblue_report(
    attack_log: list[dict],
    ml_results: list[dict],
    scenarios: dict,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    network_detections: list[dict] | None = None,
) -> dict:
    """Constrói o relatório de correlação Red vs Blue.

    Args:
        attack_log: entradas de scripts/attack_log.jsonl já lidas (ver
            feature_extractor.load_attack_log), cada uma com pelo menos
            timestamp/scenario/target/status.
        ml_results: a lista "results" já devolvida por
            ml_anomalies.build_ml_anomalies_report(), cada item com
            timestamp/agent_ip/windows_event_id/rule_flagged/ml_is_anomaly.
        scenarios: dict nome_do_cenário -> Scenario (ver
            attack_scenarios.SCENARIOS), usado para o event_ids e o
            mapeamento MITRE de cada cenário.
        window_seconds: duração máxima da janela de correlação por
            tentativa de ataque, cortada também pelo início da tentativa
            seguinte no log (o que vier primeiro).
        network_detections: deteções de rede já produzidas por
            network_detections.detect_network_anomalies (ou, em produção,
            acumuladas em tempo real por network_monitor._poll_once — ver
            main.network_detection_buffer), cada uma com pelo menos
            type/src_ip/dst_ip/timestamp. Opcional (None = retrocompatível,
            sem dimensão de rede) — quando presente, um match exige o mesmo
            target do ataque em src_ip OU dst_ip da deteção (um target
            vazio/None nunca corresponde, mesmo a uma deteção com
            dst_ip=None, como volume_spike) e o timestamp dentro da mesma
            janela usada para os alertas Wazuh.

    Returns:
        dict com attempts/by_scenario/overall/not_executed/unknown_scenario/
        invalid_entries. Nunca lança exceção; entradas malformadas (não-dict
        ou timestamp impossível de parsear) são desviadas para invalid_entries,
        nunca descartadas em silêncio.

        Cada attempt ganha (Onda 2) detected_by_network (bool),
        network_detection_types (lista ordenada dos tipos de deteção que
        corresponderam), mttd_network_seconds (None se nenhuma), e
        coverage_gap (True quando a rede detetou mas o Wazuh — regra/ML —
        não, ou seja, um ponto cego do lado Windows exposto só pela rede).

        Cada bucket de by_scenario e o overall ganham quatro contadores
        cruzando as duas dimensões de deteção: detected_by_network_only
        (só rede, nunca Windows — mesmo universo de coverage_gap),
        detected_by_windows_only (só Windows, sem rede),
        detected_by_both_sources (as duas) e detected_by_neither (nenhuma).
    """
    parsed_attacks, not_executed, unknown_scenario, invalid_entries = parse_launched_attacks(
        attack_log, scenarios
    )

    parsed_alerts: list[tuple[datetime, dict]] = []
    for result in ml_results or []:
        ts = _parse_timestamp(result.get("timestamp"))
        if ts is None:
            continue
        parsed_alerts.append((ts, result))

    parsed_network: list[tuple[datetime, dict]] = []
    for det in network_detections or []:
        ts = _parse_timestamp(det.get("timestamp"))
        if ts is None:
            continue
        parsed_network.append((ts, det))

    attempts: list[dict] = []
    for ts, window_end, entry in attack_windows(parsed_attacks, window_seconds):
        scenario_name = entry["scenario"]
        scenario = scenarios[scenario_name]
        target = entry.get("target")

        matches = [
            (alert_ts, result)
            for alert_ts, result in parsed_alerts
            if ts <= alert_ts <= window_end
            and result.get("agent_ip") == target
            and result.get("windows_event_id") in scenario.event_ids
        ]
        matches.sort(key=lambda item: item[0])

        detected = len(matches) > 0
        matched_by_rule = any(result.get("rule_flagged") for _, result in matches)
        matched_by_ml = any(result.get("ml_is_anomaly") for _, result in matches)
        if matched_by_rule and matched_by_ml:
            detected_by = "both"
        elif matched_by_rule:
            detected_by = "rule"
        elif matched_by_ml:
            detected_by = "ml"
        else:
            detected_by = "none"

        mttd_seconds = round((matches[0][0] - ts).total_seconds(), 2) if matches else None

        network_matches = [
            (net_ts, det)
            for net_ts, det in parsed_network
            if ts <= net_ts <= window_end and target and target in (det.get("src_ip"), det.get("dst_ip"))
        ]
        network_matches.sort(key=lambda item: item[0])
        detected_by_network = len(network_matches) > 0
        mttd_network_seconds = (
            round((network_matches[0][0] - ts).total_seconds(), 2) if network_matches else None
        )

        # A técnica/ferramenta realmente executada (quando o log as regista)
        # prevalece sobre a do cenário: vários ataques reais partilham o
        # mesmo cenário aproximado (Round 3 colapsou 12 técnicas em 5
        # cenários), e atribuir-lhes a técnica do cenário reportava MITRE
        # errado. A correspondência de alertas continua a usar os event_ids
        # do cenário.
        attempts.append({
            "attack_id": entry.get("id"),
            "scenario": scenario_name,
            "target": target,
            "tool": entry.get("tool") or scenario.tool,
            "timestamp": entry.get("timestamp"),
            "mitre_tactic": scenario.mitre_tactic,
            "mitre_technique": entry.get("technique") or scenario.mitre_technique,
            "detected": detected,
            "detected_by": detected_by,
            "mttd_seconds": mttd_seconds,
            "matched_event_ids": sorted({result.get("windows_event_id") for _, result in matches}),
            "matched_alert_count": len(matches),
            "detected_by_network": detected_by_network,
            "network_detection_types": sorted({det.get("type") for _, det in network_matches}),
            "mttd_network_seconds": mttd_network_seconds,
            "coverage_gap": detected_by_network and detected_by == "none",
        })

    by_scenario: dict[str, dict] = {}
    for att in attempts:
        name = att["scenario"]
        bucket = by_scenario.setdefault(name, {
            "attempts": 0, "detected": 0,
            "detected_by_rule": 0, "detected_by_ml": 0, "detected_by_both": 0,
            "detected_by_none": 0,
            "detected_by_network_only": 0, "detected_by_windows_only": 0,
            "detected_by_both_sources": 0, "detected_by_neither": 0,
            "_mttd_values": [],
        })
        bucket["attempts"] += 1
        if att["detected"]:
            bucket["detected"] += 1
            bucket["_mttd_values"].append(att["mttd_seconds"])
        if att["detected_by"] == "rule":
            bucket["detected_by_rule"] += 1
        elif att["detected_by"] == "ml":
            bucket["detected_by_ml"] += 1
        elif att["detected_by"] == "both":
            bucket["detected_by_both"] += 1
        else:
            bucket["detected_by_none"] += 1

        windows_detected = att["detected_by"] != "none"
        network_detected = att["detected_by_network"]
        if windows_detected and network_detected:
            bucket["detected_by_both_sources"] += 1
        elif windows_detected:
            bucket["detected_by_windows_only"] += 1
        elif network_detected:
            bucket["detected_by_network_only"] += 1
        else:
            bucket["detected_by_neither"] += 1

    for bucket in by_scenario.values():
        mttd_values = bucket.pop("_mttd_values")
        bucket["coverage_rate"] = round(bucket["detected"] / bucket["attempts"], 4) if bucket["attempts"] else 0.0
        bucket["avg_mttd_seconds"] = round(sum(mttd_values) / len(mttd_values), 2) if mttd_values else None

    total_attempts = len(attempts)
    total_detected = sum(1 for a in attempts if a["detected"])
    all_mttd = [a["mttd_seconds"] for a in attempts if a["mttd_seconds"] is not None]
    overall = {
        "total_attempts": total_attempts,
        "detected": total_detected,
        "coverage_rate": round(total_detected / total_attempts, 4) if total_attempts else 0.0,
        "avg_mttd_seconds": round(sum(all_mttd) / len(all_mttd), 2) if all_mttd else None,
        "detected_by_network_only": sum(1 for a in attempts if a["coverage_gap"]),
        "detected_by_windows_only": sum(
            1 for a in attempts if a["detected_by"] != "none" and not a["detected_by_network"]
        ),
        "detected_by_both_sources": sum(
            1 for a in attempts if a["detected_by"] != "none" and a["detected_by_network"]
        ),
        "detected_by_neither": sum(
            1 for a in attempts if a["detected_by"] == "none" and not a["detected_by_network"]
        ),
    }

    return {
        "attempts": attempts,
        "by_scenario": by_scenario,
        "overall": overall,
        "not_executed": not_executed,
        "unknown_scenario": unknown_scenario,
        "invalid_entries": invalid_entries,
    }
