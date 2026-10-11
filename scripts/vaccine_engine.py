"""
Motor de vaccines (Phase 12). Módulo puro, como attack_registry.py/
redblue_correlator.py: sem I/O, sem rede, sem relógio. Recebe a saída de
attack_registry.build_attack_registry (o registo de ataques já com veredito)
e devolve, para cada ataque not_detected/partial, uma "vaccine": uma proposta
de deteção rastreável até ao ataque que a originou.

Só PROPÕE. Nunca aplica nada no Wazuh, nunca executa nada, e nenhum campo
contém um comando. Nunca levanta exceção sobre dados malformados: verifica
tipos em cada acesso e conta o que não aproveita (considered.invalid,
skipped.*).

Não recalcula veredito, sensores esperados nem event_ids: lê-os do registo.
Ligação de VAC-02 à attack_library:
- os sensores esperados de onde sai missing_sensors são
  attack["expected"]["detection"], que attack_registry.expected_detection
  preenche com attack_library.get_expected_sensors(scenario) quando o log não
  traz `expected` (expected_source = "scenario_default"), ou com o `expected`
  do log (expected_source = "log");
- os event_ids da proposta rule vêm de SCENARIOS (attack_scenarios), via
  attack["expected"]["event_ids"];
- os nomes/severidades dos eventos vêm de event_catalog.classify_alert.

O id (vaccine_id) é um identificador determinístico: deteta troca ou
duplicação, mas NÃO autentica (mesmo aviso que o CLAUDE.md faz do SHA-256 dos
.pkl). Quem consegue editar o attack_log também consegue forjar um ataque.
"""

import hashlib
import re

from attack_registry import EXPECTED_SOURCES, VERDICTS, normalize_attack_id
from event_catalog import classify_alert
from redblue_correlator import DEFAULT_WINDOW_SECONDS

GENERATING_VERDICTS = ("not_detected", "partial")  # D-02: só estes geram vaccine
MIN_COUNT = 1  # D-06: uma ocorrência dentro da janela basta para a regra proposta

VACCINE_ID_RE = r"^vac-[0-9a-f]{12}$"
SKIP_REASONS = ("no_attack_id", "duplicate_id", "invalid_origin", "no_missing_sensors", "no_event_ids")

SCENARIO_RE = re.compile(r"^[a-z_]{1,64}$")
MITRE_TACTIC_RE = re.compile(r"^[A-Za-z][A-Za-z ]{0,63}$")
MITRE_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
INCIDENT_ID_RE = re.compile(r"^INC-\d{8}-\d+$")
LABEL_RE = re.compile(r"^[a-z_]{1,64}$")

# D-07: só texto em PT-PT, nunca comandos.
RECOMMENDATIONS = {
    "ml": "Rever o treino do modelo de anomalias: incluir este ataque e eventos semelhantes "
          "no conjunto de treino e reavaliar a versão antes de a ativar.",
    "network": "Rever a captura e as deteções de rede: confirmar que o tráfego deste ataque é "
               "capturado e considerar uma deteção por padrão de rede para este cenário.",
}

# Conjuntos de chaves fechadas (contrato com a Phase 13).
RESULT_KEYS = frozenset({"available", "reason", "vaccines", "total", "considered", "skipped", "alerts_truncated"})
VACCINE_KEYS = frozenset({"id", "verdict", "expected", "expected_source", "achieved", "missing_sensors",
                          "proposals", "origin"})
ORIGIN_KEYS = frozenset({"attack_id", "scenario", "mitre_tactic", "mitre_technique", "incident_ids", "evidence"})
EVIDENCE_KEYS = frozenset({"matched_event_ids", "matched_alert_count", "network_detection_types"})
PROPOSAL_KEYS = frozenset({"sensor", "rule", "events", "recommendation"})
RULE_KEYS = frozenset({"event_ids", "min_count", "window_seconds"})
EVENT_KEYS = frozenset({"event_id", "name", "severity"})


def vaccine_id(attack_id: int, missing_sensors: list[str]) -> str:
    """D-03: "vac-" + 12 hex de sha256('<attack_id>:<sensores em falta>').
    Sensores na ordem de EXPECTED_SOURCES, unidos por vírgula. Nunca usa o
    hash() embutido (salgado por processo) nem a ordem de um set."""
    ordered = [s for s in EXPECTED_SOURCES if s in missing_sensors]
    canonical = f"{attack_id}:{','.join(ordered)}"
    return "vac-" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]


def _positive_ints(value) -> list[int]:
    """Ints positivos (sem bool), ordem preservada, sem repetidos. Não-lista -> []."""
    if not isinstance(value, list):
        return []
    seen: list[int] = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int) or item <= 0:
            continue
        if item not in seen:
            seen.append(item)
    return seen


def _sensors(value) -> list[str]:
    """Só sensores conhecidos, pela ordem de EXPECTED_SOURCES. Não-lista -> []."""
    if not isinstance(value, list):
        return []
    return [s for s in EXPECTED_SOURCES if s in value]


def _as_dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _build_proposal(sensor: str, event_ids: list[int]) -> dict:
    """D-06/D-07: rule leva a regra proposta; ml/network só uma recomendação."""
    if sensor == "rule":
        events = []
        for event_id in event_ids:
            info = classify_alert(event_id)
            events.append({"event_id": event_id, "name": info["friendly_name"], "severity": info["severity"]})
        return {
            "sensor": "rule",
            "rule": {"event_ids": list(event_ids), "min_count": MIN_COUNT, "window_seconds": DEFAULT_WINDOW_SECONDS},
            "events": events,
            "recommendation": None,
        }
    return {"sensor": sensor, "rule": None, "events": None, "recommendation": RECOMMENDATIONS[sensor]}


def _build_origin(attack_id: int, attack: dict) -> dict:
    """VAC-03: referências ao ataque, nunca cópias de tool/target/source/
    operator/details nem dos dicts completos dos incidentes."""
    tactic = attack.get("mitre_tactic")
    technique = attack.get("mitre_technique")
    evidence = _as_dict(attack.get("evidence"))
    count = evidence.get("matched_alert_count")
    incident_ids: list[str] = []
    incidents = attack.get("incidents")
    for incident in incidents if isinstance(incidents, list) else []:
        raw_id = _as_dict(incident).get("id")
        if isinstance(raw_id, str) and INCIDENT_ID_RE.match(raw_id) and raw_id not in incident_ids:
            incident_ids.append(raw_id)
    detection_types = evidence.get("network_detection_types")
    return {
        "attack_id": attack_id,
        "scenario": attack.get("scenario"),
        "mitre_tactic": tactic if isinstance(tactic, str) and MITRE_TACTIC_RE.match(tactic) else None,
        "mitre_technique": technique if isinstance(technique, str) and MITRE_TECHNIQUE_RE.match(technique) else None,
        "incident_ids": incident_ids,
        "evidence": {
            "matched_event_ids": _positive_ints(evidence.get("matched_event_ids")),
            "matched_alert_count": count if isinstance(count, int) and not isinstance(count, bool) and count >= 0 else None,
            "network_detection_types": [t for t in detection_types if isinstance(t, str) and LABEL_RE.match(t)]
            if isinstance(detection_types, list) else [],
        },
    }


def build_vaccine_candidates(registry, correlation=None) -> dict:
    """Uma vaccine por ataque not_detected/partial do registo (D-02), do id de
    ataque mais alto para o mais baixo. `unknown` (incluindo o unknown por
    truncagem de alertas e por correlação indisponível) nunca gera."""
    attacks = _as_dict(registry).get("attacks")
    attacks = attacks if isinstance(attacks, list) else []
    considered = {"attacks": len(attacks), "detected": 0, "partial": 0, "not_detected": 0, "unknown": 0, "invalid": 0}
    skipped = {reason: 0 for reason in SKIP_REASONS}
    truncated = isinstance(correlation, dict) and correlation.get("alerts_truncated") is True
    vaccines: list[dict] = []

    # Pré-passagem: ids repetidos (qualquer veredito, como o registo faz). Uma
    # entrada é duplicada pela flag do registo ou por o seu id aparecer mais
    # de uma vez, por isso "nenhum duplicado gera" vale por construção.
    id_counts: dict[int, int] = {}
    for attack in attacks:
        entry_id = normalize_attack_id(attack.get("id")) if isinstance(attack, dict) else None
        if entry_id is not None:
            id_counts[entry_id] = id_counts.get(entry_id, 0) + 1

    for attack in attacks:
        actual = _as_dict(attack).get("actual") if isinstance(attack, dict) else None
        verdict = actual.get("verdict") if isinstance(actual, dict) else None
        if not isinstance(verdict, str) or verdict not in VERDICTS:
            considered["invalid"] += 1
            continue
        considered[verdict] += 1
        if actual.get("correlation_reason") == "alerts_truncated":
            truncated = True
        if verdict not in GENERATING_VERDICTS:
            continue

        # D-04: cada ataque gerador acaba numa vaccine ou num motivo contado.
        attack_id = normalize_attack_id(attack.get("id"))
        if attack_id is None:
            skipped["no_attack_id"] += 1
            continue
        if attack.get("duplicate_id") is True or id_counts.get(attack_id, 0) > 1:
            skipped["duplicate_id"] += 1
            continue
        scenario = attack.get("scenario")
        if not isinstance(scenario, str) or not SCENARIO_RE.match(scenario):
            skipped["invalid_origin"] += 1
            continue
        expected_block = _as_dict(attack.get("expected"))
        expected = _sensors(expected_block.get("detection"))
        achieved = _sensors(actual.get("achieved"))
        missing = [s for s in EXPECTED_SOURCES if s in expected and s not in achieved]  # D-01
        if not missing:
            skipped["no_missing_sensors"] += 1
            continue
        event_ids = _positive_ints(expected_block.get("event_ids"))
        if "rule" in missing and not event_ids:
            skipped["no_event_ids"] += 1
            continue
        source = expected_block.get("source")
        vaccines.append({
            "id": vaccine_id(attack_id, missing),
            "verdict": verdict,
            "expected": expected,
            "expected_source": source if source in ("log", "scenario_default") else None,
            "achieved": achieved,
            "missing_sensors": missing,
            "proposals": [_build_proposal(sensor, event_ids) for sensor in missing],
            "origin": _build_origin(attack_id, attack),
        })

    vaccines.sort(key=lambda v: v["origin"]["attack_id"], reverse=True)
    return {
        "available": True,
        "reason": None,
        "vaccines": vaccines,
        "total": len(vaccines),
        "considered": considered,
        "skipped": skipped,
        "alerts_truncated": truncated,
    }
