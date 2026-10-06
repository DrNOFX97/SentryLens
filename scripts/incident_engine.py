"""
Motor de agrupamento de incidentes (R3). Módulo puro, como lifecycle.py/
redblue_correlator.py: sem I/O, sem SQLite, sem relógio — recebe evidências
normalizadas e o estado dos incidentes abertos e devolve decisões. Nunca
lança exceção sobre dados malformados: entradas inválidas devolvem None.

Evidência normalizada: {kind, key, ts, asset, severity, payload}
  kind     "wazuh_alert" | "network_detection"
  key      chave única de deduplicação ("alert:<_id>" / "net:<tipo>:...")
  ts       ISO-8601 com fuso
  asset    IP do ativo afetado (agent.ip / dst_ip)
  payload  alerta bruto do Wazuh ou deteção de rede
"""

import os

from event_catalog import classify_alert
from redblue_correlator import (
    DEFAULT_WINDOW_SECONDS,
    _parse_timestamp,
    attack_windows,
    parse_launched_attacks,
)

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
STATUSES = ("NEW", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED")
OPEN_STATUSES = ("NEW", "INVESTIGATING", "CONTAINED")
TRANSITIONS = {
    "NEW": ("INVESTIGATING", "CLOSED"),
    "INVESTIGATING": ("CONTAINED", "RESOLVED"),
    "CONTAINED": ("RESOLVED", "INVESTIGATING"),
    "RESOLVED": ("CLOSED", "INVESTIGATING"),
    "CLOSED": (),
}
NETWORK_SEVERITY = {"port_scan": "medium", "brute_force": "medium", "volume_spike": "low"}


def _int_env(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, default))
    except ValueError:
        return default
    return value if value > 0 else default


def _severity_env(name: str, default: str) -> str:
    value = os.getenv(name, default).strip().lower()
    return value if value in SEVERITY_ORDER else default


INCIDENT_GAP_SECONDS = _int_env("INCIDENT_GAP_SECONDS", 600)
INCIDENT_OPEN_MIN_SEVERITY = _severity_env("INCIDENT_OPEN_MIN_SEVERITY", "medium")

parse_timestamp = _parse_timestamp


def severity_rank(severity: str | None) -> int:
    return SEVERITY_ORDER.get(severity, 0)


def max_severity(a: str, b: str) -> str:
    return a if severity_rank(a) >= severity_rank(b) else b


def _windows_event_id(raw: dict) -> int | None:
    try:
        value = raw.get("data", {}).get("win", {}).get("system", {}).get("eventID")
        return int(value) if value is not None else None
    except (ValueError, TypeError, AttributeError):
        return None


def evidence_from_raw_alert(raw: dict) -> dict | None:
    """Alerta bruto do Indexer (`_source` + `_id`) -> evidência, ou None se
    faltar _id, timestamp válido ou agent.ip."""
    if not isinstance(raw, dict):
        return None
    alert_id = raw.get("_id")
    ts = _parse_timestamp(raw.get("@timestamp"))
    agent = raw.get("agent")
    asset = agent.get("ip") if isinstance(agent, dict) else None
    if not alert_id or ts is None or not asset:
        return None
    return {
        "kind": "wazuh_alert",
        "key": f"alert:{alert_id}",
        "ts": ts.isoformat(),
        "asset": asset,
        "severity": classify_alert(_windows_event_id(raw))["severity"],
        "payload": raw,
    }


def evidence_from_network_detection(det: dict) -> dict | None:
    """Deteção de rede (network_detections.detect_network_anomalies) ->
    evidência, ou None se faltar timestamp, tipo ou IPs. O ativo é o destino
    (o alvo do padrão); volume_spike não tem destino, usa a origem."""
    if not isinstance(det, dict):
        return None
    ts = _parse_timestamp(det.get("timestamp"))
    det_type = det.get("type")
    asset = det.get("dst_ip") or det.get("src_ip")
    if ts is None or not det_type or not asset:
        return None
    return {
        "kind": "network_detection",
        # Mesma granularidade (minuto) com que network_monitor._poll_once deduplica.
        "key": f"net:{det_type}:{det.get('src_ip')}:{det.get('dst_ip')}:{ts.isoformat()[:16]}",
        "ts": ts.isoformat(),
        "asset": asset,
        "severity": NETWORK_SEVERITY.get(det_type, "low"),
        "payload": det,
    }


def assign_evidence(
    evidence: dict,
    open_incidents: list[dict],
    already_known: bool = False,
    gap_seconds: int | None = None,
    min_open_severity: str | None = None,
) -> dict:
    """Decide o destino de uma evidência: duplicate | attach | open | ignore.

    open_incidents: [{id, asset, status, last_evidence_at}] — só os do mesmo
    ativo interessam. Anexa ao incidente aberto (NEW/INVESTIGATING/CONTAINED)
    do mesmo ativo mais recentemente ativo cuja última evidência esteja a
    <= gap segundos (em qualquer sentido). Senão abre incidente se for
    deteção de rede ou tiver severidade >= limiar; senão ignora."""
    gap = INCIDENT_GAP_SECONDS if gap_seconds is None else gap_seconds
    minimum = min_open_severity or INCIDENT_OPEN_MIN_SEVERITY

    if already_known:
        return {"action": "duplicate", "incident_id": None}

    ev_ts = _parse_timestamp(evidence.get("ts"))
    best = None
    best_last = None
    for inc in open_incidents:
        if inc.get("asset") != evidence.get("asset") or inc.get("status") not in OPEN_STATUSES:
            continue
        last = _parse_timestamp(inc.get("last_evidence_at"))
        if ev_ts is None or last is None:
            continue
        if abs((ev_ts - last).total_seconds()) <= gap and (best is None or last > best_last):
            best, best_last = inc, last
    if best is not None:
        return {"action": "attach", "incident_id": best["id"]}

    if evidence.get("kind") == "network_detection" or severity_rank(evidence.get("severity")) >= severity_rank(minimum):
        return {"action": "open", "incident_id": None}
    return {"action": "ignore", "incident_id": None}


def can_transition(current: str, target: str, note: str | None = None) -> tuple[bool, str | None]:
    """(ok, razão). Razões: "transicao_invalida", "nota_obrigatoria"
    (NEW -> CLOSED exige nota: falso positivo)."""
    if target not in TRANSITIONS.get(current, ()):
        return False, "transicao_invalida"
    if current == "NEW" and target == "CLOSED" and not (note or "").strip():
        return False, "nota_obrigatoria"
    return True, None


def available_transitions(current: str) -> tuple[str, ...]:
    return TRANSITIONS.get(current, ())


def compute_windows(attack_log: list, scenarios: dict, window_seconds: int = DEFAULT_WINDOW_SECONDS) -> list:
    """Janelas (inicio, fim, entrada) das tentativas lançadas do attack_log —
    a mesma regra de redblue_correlator (via parse_launched_attacks)."""
    parsed, _, _, _ = parse_launched_attacks(attack_log, scenarios)
    return attack_windows(parsed, window_seconds)


def link_attacks(evidence_ts: str, asset: str | None, windows: list) -> list[dict]:
    """Entradas do attack_log cuja janela contém a evidência e cujo target é o ativo."""
    ts = _parse_timestamp(evidence_ts)
    if ts is None or not asset:
        return []
    return [entry for start, end, entry in windows if entry.get("target") == asset and start <= ts <= end]


def attack_link_data(entry: dict, scenarios: dict) -> dict:
    """Dados do evento `attack_linked`. technique/tool do próprio log (R0)
    prevalecem; sem eles, os do cenário."""
    scenario = scenarios.get(entry.get("scenario"))
    attack_id = entry.get("id")
    ref = str(attack_id) if attack_id is not None else f"{entry.get('target')}@{entry.get('timestamp')}"
    return {
        "ref": ref,
        "attack_id": attack_id,
        "scenario": entry.get("scenario"),
        "technique": entry.get("technique") or (scenario.mitre_technique if scenario else None),
        "tool": entry.get("tool") or (scenario.tool if scenario else None),
        "attack_timestamp": entry.get("timestamp"),
    }
