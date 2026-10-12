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
        "instructions": (
            "Does this set of security events indicate a SUCCESSFUL COMPROMISE (not just attempts)? "
            "Consider: multiple failed logons followed by a successful one (4624 after 4625), "
            "privilege escalation events (4672, 4728-4732, 4756), "
            "account creation/modification outside business hours, "
            "scheduled task creation (4698) with suspicious commands, "
            "lateral movement indicators (SMB session 5140/5145, RDP 4624 type 10), "
            "persistence mechanisms (run keys, services, WMI). "
            "A single failed logon is NOT a compromise. "
            "Brute force attempts without success are NOT a compromise."
        ),
    },
    "is_brute_force": {
        "type": "noul",
        "instructions": (
            "Does this set of events indicate a BRUTE-FORCE or PASSWORD-GUESSING pattern? "
            "Look for: high volume of Event ID 4625 (failed logon) from same source IP, "
            "multiple usernames tried against same target (password spray), "
            "repeated failures for same account (account lockout 4740), "
            "Kerberos pre-auth failures (4771), NTLM failures (4776), "
            "RDP brute force (4625 with logon type 10), "
            "SMB brute force (4625 with logon type 3). "
            "A few isolated failed logons are NOT brute force. "
            "Successful logons (4624) alone are NOT brute force."
        ),
    },
    "severity": {
        "type": "choice",
        "instructions": (
            "Classify the OVERALL severity of this security incident based on the evidence. "
            "Consider: impact if true positive, urgency of response, blast radius. "
            "CRITICAL: Active compromise confirmed, data exfiltration, ransomware, domain admin compromised. "
            "HIGH: Likely compromise, privilege escalation, lateral movement detected, critical asset affected. "
            "MEDIUM: Suspicious activity requiring investigation, brute force with some success, "
            "unusual admin activity, new persistence mechanism. "
            "LOW: Failed attempts only, policy violations, low-value asset, likely benign. "
            "INFO: Noise, false positive, expected administrative activity."
        ),
        "criteria": {
            "info": "Noise, false positive, expected admin activity — no action needed",
            "low": "Failed attempts only, policy violations, low-value asset — monitor only",
            "medium": "Suspicious activity, some success in brute force, unusual admin — investigate soon",
            "high": "Likely compromise, privilege escalation, lateral movement, critical asset — act now",
            "critical": "Confirmed compromise, data exfiltration, ransomware, domain admin — emergency response",
        },
    },
    "attack_type": {
        "type": "choice",
        "instructions": (
            "What is the PRIMARY attack type represented by these events? "
            "Choose the most specific matching category. "
            "If multiple types apply, choose the one with highest impact."
        ),
        "criteria": {
            "credential_access": "Brute force, password spray, credential dumping, Kerberoasting, pass-the-hash",
            "lateral_movement": "SMB/WinRM/PSRemoting/RDP lateral movement, scheduled tasks, WMI, DCOM",
            "privilege_escalation": "Token manipulation, bypass UAC, kernel exploits, group membership changes",
            "persistence": "Scheduled tasks, run keys, services, WMI subscriptions, DLL hijacking",
            "discovery": "Account enumeration, share enumeration, network scanning, AD reconnaissance",
            "collection": "Data staging, archive creation, email/clipboard collection",
            "exfiltration": "Data transfer out, cloud upload, C2 communication",
            "impact": "Ransomware, data destruction, service stop, encryption",
            "benign": "Expected admin activity, scheduled maintenance, user error, false positive",
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


def _mitre_techniques(incident: dict) -> list[str]:
    """Extract MITRE techniques from linked attacks in timeline."""
    techniques = set()
    for ev in incident.get("timeline", []) or []:
        if ev.get("kind") == "attack_linked":
            data = ev.get("data") or {}
            if data.get("technique"):
                techniques.add(data["technique"])
    return sorted(techniques)


def build_state(incident: dict) -> dict:
    """Incidente (formato de IncidentStore.get_incident) -> state agregado e
    anonimizado para o JEV. Puro."""
    evidence = [e for e in incident.get("evidence", []) if isinstance(e, dict)]
    labels = Counter(filter(None, (_label(e) for e in evidence)))
    severities = Counter(e.get("severity") for e in evidence if e.get("severity"))
    stamps = sorted(t for t in (_parse_timestamp(e.get("ts")) for e in evidence) if t is not None)
    duration = round((stamps[-1] - stamps[0]).total_seconds()) if len(stamps) > 1 else 0
    
    # Time context
    time_context = {}
    if stamps:
        first = stamps[0]
        time_context = {
            "first_event_hour_utc": first.hour,
            "first_event_day_of_week": first.weekday(),  # 0=Mon
            "is_business_hours_utc": 8 <= first.hour <= 18 and first.weekday() < 5,
        }
    
    # Sources breakdown
    sources = Counter(e.get("kind") for e in evidence if e.get("kind"))
    
    return {
        "incident_severity": incident.get("severity"),
        "evidence_count": len(evidence),
        "duration_seconds": duration,
        "event_types": [{"label": k, "count": v} for k, v in labels.most_common(MAX_LABELS)],
        "evidence_severities": dict(severities),
        "sources": dict(sources),
        "mitre_techniques": _mitre_techniques(incident),
        "asset": incident.get("asset"),
        "status": incident.get("status"),
        "time_context": time_context,
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
