"""
Triagem EXPERIMENTAL de incidentes com o JEV (TypeSafe AI, System One).

Consultivo e opt-in: desligado por omissão, nunca altera o estado do
incidente nem a severidade das regras. O resultado só é devolvido ao
analista, que decide. Ver docs/API.md (POST /api/incidents/{id}/triage).

Privacidade: o JEV é um serviço externo. O `state` enviado é só agregado —
rótulos de evento, contagens, severidades e duração. Nunca IPs, contas,
hostnames nem o payload bruto dos alertas (`build_state`).

`confidence` do JEV mede a concentração da distribuição de probabilidades,
NÃO a probabilidade de a resposta estar certa (docs.typesafe.ai/confidence)
— por isso é sempre exposto em conjunto com as probabilidades e nunca usado
para agir automaticamente.

`build_state`/`parse_answers` são puros (testáveis sem rede); `triage`
é a única função com I/O e nunca lança — devolve códigos de erro estáveis,
nunca texto de exceção.
"""

import os
from collections import Counter

import httpx

from detection_event import from_rule_alert
from redblue_correlator import _parse_timestamp

API_URL = "https://api.typesafe.ai/v1/systemone"
MODEL = "jev-latest"
TIMEOUT_SECONDS = 10.0
MAX_LABELS = 10  # teto do tamanho do state (tokens = custo)

QUESTIONS = {
    "is_compromise": {
        "type": "noul",
        "instructions": "Does this set of events indicate a successful compromise (not just attempts)?",
    },
    "is_brute_force": {
        "type": "noul",
        "instructions": "Does this set of events indicate a brute-force or password-guessing pattern?",
    },
    "severity": {
        "type": "choice",
        "instructions": "Classify the overall severity of this security incident.",
        "criteria": {
            "info": "benign or noise, no action needed",
            "low": "minor, monitor only",
            "medium": "suspicious, investigate soon",
            "high": "likely compromise, act now",
        },
    },
}


def jev_enabled() -> bool:
    """Opt-in explícito: flag ligada E chave presente (fail-closed)."""
    return os.getenv("SENTRYLENS_JEV_ENABLED", "").strip().lower() in ("1", "true", "yes") \
        and bool(os.getenv("TYPESAFE_API_KEY", "").strip())


def _label(evidence: dict) -> str | None:
    payload = evidence.get("payload")
    if evidence.get("kind") == "wazuh_alert":
        event = from_rule_alert(payload) if isinstance(payload, dict) else None
        return event["label"] if event else None
    if evidence.get("kind") == "network_detection" and isinstance(payload, dict):
        return payload.get("type")
    return None


def build_state(incident: dict) -> dict:
    """Incidente (formato de IncidentStore.get_incident) -> state agregado e
    anonimizado para o JEV. Puro."""
    evidence = [e for e in incident.get("evidence", []) if isinstance(e, dict)]
    labels = Counter(filter(None, (_label(e) for e in evidence)))
    severities = Counter(e.get("severity") for e in evidence if e.get("severity"))
    stamps = sorted(t for t in (_parse_timestamp(e.get("ts")) for e in evidence) if t is not None)
    duration = round((stamps[-1] - stamps[0]).total_seconds()) if len(stamps) > 1 else 0
    return {
        "incident_severity": incident.get("severity"),
        "evidence_count": len(evidence),
        "duration_seconds": duration,
        "event_types": [{"label": k, "count": v} for k, v in labels.most_common(MAX_LABELS)],
        "evidence_severities": dict(severities),
        "sources": sorted({e.get("kind") for e in evidence if e.get("kind")}),
    }


def parse_answers(body: object) -> dict | None:
    """Resposta HTTP do JEV -> forma compacta, ou None se inesperada. Puro."""
    if not isinstance(body, dict) or not isinstance(body.get("answers"), dict):
        return None
    answers = body["answers"]
    result = {"model": body.get("model"), "answers": {}}
    for name, spec in QUESTIONS.items():
        a = answers.get(name)
        if not isinstance(a, dict):
            return None
        if spec["type"] == "noul":
            value = a.get("noul")
            if not isinstance(value, (int, float)):
                return None
            result["answers"][name] = {"probability": round(float(value), 3)}
        else:
            if a.get("choice") not in spec["criteria"] or not isinstance(a.get("probabilities"), dict):
                return None
            result["answers"][name] = {
                "choice": a["choice"],
                "confidence": a.get("confidence"),
                "probabilities": a["probabilities"],
            }
    return result


async def triage(incident: dict, client: httpx.AsyncClient | None = None) -> dict:
    """Pede ao JEV a triagem de um incidente. Nunca lança: devolve
    {"ok": True, ...} ou {"ok": False, "error": <código estável>}."""
    if not jev_enabled():
        return {"ok": False, "error": "jev_disabled"}
    payload = {"state": build_state(incident), "model": MODEL, "questions": QUESTIONS}
    headers = {"Authorization": f"Bearer {os.environ['TYPESAFE_API_KEY'].strip()}"}
    owns_client = client is None
    client = client or httpx.AsyncClient(timeout=TIMEOUT_SECONDS)
    try:
        response = await client.post(API_URL, json=payload, headers=headers)
    except httpx.HTTPError:
        return {"ok": False, "error": "jev_unreachable"}
    finally:
        if owns_client:
            await client.aclose()
    if response.status_code in (401, 403):
        return {"ok": False, "error": "jev_auth"}
    if response.status_code in (429, 529):
        return {"ok": False, "error": "jev_busy"}
    if response.status_code != 200:
        return {"ok": False, "error": "jev_error"}
    try:
        parsed = parse_answers(response.json())
    except ValueError:
        parsed = None
    if parsed is None:
        return {"ok": False, "error": "jev_bad_response"}
    return {"ok": True, **parsed}
