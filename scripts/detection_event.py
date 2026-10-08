"""
Tipo comum de deteção (R7, Detection Engine): normaliza os 3 detetores
independentes (regra/Wazuh, ML, rede) para a MESMA forma, sem copiar o dado
de origem (`ref` apontador para o payload original, não cópia). Módulo
puro, como incident_engine.py/redblue_correlator.py: sem I/O, sem relógio,
nunca lança exceção sobre dados malformados — construtores inválidos
devolvem None.

Ver docs/superpowers/specs/2026-10-07-r7-detection-engine-design.md.

`incident_engine.py` e `redblue_correlator.py` continuam a produzir as SUAS
formas próprias (evidência de incidente, "attempt" de correlação) — este
módulo é a base de construção interna partilhada (ruling 3/4 da spec), não
um novo contrato externo que os substitua.
"""

from typing import Literal, TypedDict

from event_catalog import classify_alert
from redblue_correlator import _parse_timestamp

Source = Literal["rule", "ml", "network"]
Severity = Literal["high", "medium", "low", "info"]

SOURCES: tuple[Source, ...] = ("rule", "ml", "network")

# Fonte única de verdade para a severidade de cada tipo de deteção de rede
# (antes duplicado em incident_engine.py — ver ruling 3 da spec R7).
NETWORK_SEVERITY: dict[str, Severity] = {"port_scan": "medium", "brute_force": "medium", "volume_spike": "low"}


class DetectionEvent(TypedDict):
    source: Source
    severity: Severity
    asset: str | None
    ts: str  # ISO-8601 com fuso
    technique: str | None  # sempre None nos 3 construtores por agora (ver spec, ruling 2)
    confidence: float | None  # sempre None nos 3 construtores por agora (ver spec, ruling 2)
    ref: object  # apontador para o dado original, nunca cópia
    label: str
    description: str | None


def _make(
    source: Source, severity: Severity, asset: str | None, ts: str, label: str, *,
    technique: str | None = None, confidence: float | None = None,
    ref: object = None, description: str | None = None,
) -> DetectionEvent:
    return {
        "source": source, "severity": severity, "asset": asset, "ts": ts,
        "technique": technique, "confidence": confidence, "ref": ref,
        "label": label, "description": description,
    }


def _windows_event_id(raw: dict) -> int | None:
    try:
        value = raw.get("data", {}).get("win", {}).get("system", {}).get("eventID")
        return int(value) if value is not None else None
    except (ValueError, TypeError, AttributeError):
        return None


def from_rule_alert(raw: dict) -> DetectionEvent | None:
    """Alerta bruto do Wazuh Indexer (`_source`) -> DetectionEvent. None se
    faltar timestamp válido ou `agent.ip` — mesmo critério de validade que
    incident_engine.evidence_from_raw_alert usava, para as duas fontes
    nunca divergirem sobre o que conta como evidência válida."""
    if not isinstance(raw, dict):
        return None
    ts = _parse_timestamp(raw.get("@timestamp"))
    agent = raw.get("agent")
    asset = agent.get("ip") if isinstance(agent, dict) else None
    if ts is None or not asset:
        return None
    classification = classify_alert(_windows_event_id(raw))
    return _make(
        "rule", classification["severity"], asset, ts.isoformat(),
        classification["friendly_name"],
        ref=raw, description=classification.get("recommendation"),
    )


def from_ml_anomaly(result: dict) -> DetectionEvent | None:
    """Um item de ml_anomalies.build_ml_anomalies_report()["results"] ->
    DetectionEvent. Só as deteções reais (ml_is_anomaly=True) viram
    evento — uma linha "normal" não é uma deteção. None se faltar
    timestamp válido ou o veredito não for uma anomalia."""
    if not isinstance(result, dict) or not result.get("ml_is_anomaly"):
        return None
    ts = _parse_timestamp(result.get("timestamp"))
    if ts is None:
        return None
    score = result.get("ml_score")
    return _make(
        "ml", result.get("severity") or "info", result.get("agent_ip"), ts.isoformat(),
        "Anomalia ML (Isolation Forest)",
        ref=result,
        description=f"ml_score={score}" if isinstance(score, (int, float)) else None,
    )


def from_network_detection(det: dict) -> DetectionEvent | None:
    """Deteção de rede (network_detections.detect_network_anomalies) ->
    DetectionEvent. Asset é o destino (alvo do padrão); volume_spike não
    tem destino, usa a origem — mesmo critério de
    incident_engine.evidence_from_network_detection. None se faltar
    timestamp, tipo ou IPs."""
    if not isinstance(det, dict):
        return None
    ts = _parse_timestamp(det.get("timestamp"))
    det_type = det.get("type")
    asset = det.get("dst_ip") or det.get("src_ip")
    if ts is None or not det_type or not asset:
        return None
    src_ip, dst_ip = det.get("src_ip"), det.get("dst_ip")
    return _make(
        "network", NETWORK_SEVERITY.get(det_type, "low"), asset, ts.isoformat(),
        det_type, ref=det,
        description=f"{src_ip} -> {dst_ip}" if dst_ip else src_ip,
    )
