"""
Biblioteca de referência de ataques (R5). Catálogo só-leitura: nunca executa
nada, nunca contém um comando executável. Junta o metadata editorial de
scripts/attack_library.yaml (risco, pré-requisitos, sensores esperados,
cleanup, replayable, duração) com os campos já existentes em
attack_scenarios.SCENARIOS (event_ids, técnica/tática MITRE, ferramenta) por
scenario_name — a biblioteca não duplica esses campos, só os expõe.

Validação fail-fast e síncrona: load_attack_library() lê o YAML uma vez,
valida (ver validate_entry) e levanta ValueError com a lista de problemas se
algo for inválido ou incoerente com SCENARIOS; main.py deixa essa excepção
propagar no arranque, nunca serve uma biblioteca corrompida. Resultado em
cache em memória (mesmo padrão de rbac.load_rbac_baseline) — não relê a cada
pedido; reset_cache() existe só para os testes forçarem uma releitura.

Ver docs/superpowers/specs/2026-10-07-r5-attack-library-design.md.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import yaml

from attack_scenarios import SCENARIOS

DEFAULT_PATH = Path(__file__).parent / "attack_library.yaml"

RISK_LEVELS = ("low", "medium", "high")
EXPECTED_SOURCES = ("rule", "ml", "network")
DURATION_ESTIMATES = ("seconds", "minutes")
REQUIRED_FIELDS = (
    "name", "description", "risk", "prerequisites", "expected_sensors",
    "cleanup_steps", "replayable", "replayable_reason", "duration_estimate",
)
MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
ID_RE = re.compile(r"^[a-z_]{1,64}$")

_cache: dict[str, dict] | None = None
_cache_path: Path | None = None


def _resolve_path(path: str | os.PathLike | None) -> Path:
    """Caminho do YAML: argumento explícito > ATTACK_LIBRARY_PATH > default.
    Relativo é sempre relativo ao próprio ficheiro (nunca ao cwd)."""
    raw = path if path is not None else os.getenv("ATTACK_LIBRARY_PATH")
    if raw is None:
        return DEFAULT_PATH
    candidate = Path(raw)
    return candidate if candidate.is_absolute() else Path(__file__).parent / candidate


def validate_entry(name: str, entry, known_scenarios: dict) -> list[str]:
    """Problemas da entrada `name` (lista vazia se válida). Nunca levanta
    excepção — quem chama (load_attack_library) decide o que fazer com a
    lista. `known_scenarios` é um dict scenario_name -> Scenario, tipicamente
    attack_scenarios.SCENARIOS (injetável para testar isoladamente)."""
    if not isinstance(entry, dict):
        return [f"{name}: entrada não é um objeto"]

    problems: list[str] = []
    for field in REQUIRED_FIELDS:
        if field not in entry:
            problems.append(f"{name}: campo obrigatório em falta '{field}'")

    if "risk" in entry and entry["risk"] not in RISK_LEVELS:
        problems.append(f"{name}: risk '{entry.get('risk')}' fora de {RISK_LEVELS}")

    if "expected_sensors" in entry:
        sensors = entry["expected_sensors"]
        if not isinstance(sensors, list) or not sensors or any(s not in EXPECTED_SOURCES for s in sensors):
            problems.append(f"{name}: expected_sensors tem de ser lista não vazia dentro de {EXPECTED_SOURCES}")

    if "duration_estimate" in entry and entry["duration_estimate"] not in DURATION_ESTIMATES:
        problems.append(f"{name}: duration_estimate '{entry.get('duration_estimate')}' fora de {DURATION_ESTIMATES}")

    cleanup_ok = True
    if "cleanup_steps" in entry:
        steps = entry["cleanup_steps"]
        cleanup_ok = isinstance(steps, list) and len(steps) > 0 and all(
            isinstance(s, str) and s.strip() for s in steps
        )
        if not cleanup_ok:
            problems.append(f"{name}: cleanup_steps tem de ser uma lista não vazia de frases")

    if "replayable" in entry and not isinstance(entry["replayable"], bool):
        problems.append(f"{name}: replayable tem de ser booleano")

    if "replayable_reason" in entry and (
        not isinstance(entry["replayable_reason"], str) or not entry["replayable_reason"].strip()
    ):
        problems.append(f"{name}: replayable_reason tem de ser texto não vazio")

    # Incoerências risco/replayable/cleanup (ruling do utilizador, R5 decisão 2):
    # risco decidido à mão por entrada, mas o schema rejeita combinações
    # incoerentes.
    if entry.get("risk") == "low" and entry.get("replayable") is False:
        problems.append(f"{name}: risk 'low' incoerente com replayable=false")
    if entry.get("risk") == "low" and not cleanup_ok:
        problems.append(f"{name}: risk 'low' incoerente com cleanup_steps vazio/ausente")

    scenario = known_scenarios.get(name)
    if scenario is None:
        problems.append(f"{name}: sem par em attack_scenarios.SCENARIOS")
    else:
        technique = getattr(scenario, "mitre_technique", None)
        if not technique or not MITRE_RE.match(technique):
            problems.append(f"{name}: mitre_technique '{technique}' de SCENARIOS em formato inválido (esperado Txxxx ou Txxxx.xxx)")

    return problems


def load_attack_library(yaml_path: str | os.PathLike | None = None, *, use_cache: bool = True) -> dict[str, dict]:
    """Lê scripts/attack_library.yaml, valida e junta com
    attack_scenarios.SCENARIOS por scenario_name. Cache em memória por
    omissão; use_cache=False força reler (testes). Levanta ValueError com a
    lista de problemas se o YAML for ilegível, mal formado ou incoerente.

    Cenário em SCENARIOS sem entrada no YAML: aviso não-bloqueante em stderr,
    o arranque continua (R5, decisão 3). Entrada no YAML sem par em
    SCENARIOS: erro (ver validate_entry)."""
    global _cache, _cache_path
    resolved = _resolve_path(yaml_path)
    if use_cache and _cache is not None and _cache_path == resolved:
        return _cache

    try:
        with open(resolved, encoding="utf-8") as handle:
            raw = yaml.safe_load(handle)
    except FileNotFoundError as exc:
        raise ValueError([f"attack_library.yaml não encontrado em '{resolved}'"]) from exc
    except yaml.YAMLError as exc:
        raise ValueError([f"attack_library.yaml inválido (YAML malformado): {exc}"]) from exc

    if not isinstance(raw, dict):
        raise ValueError(["attack_library.yaml inválido: esperado um mapa scenario_name -> entrada no topo"])

    problems: list[str] = []
    for name, entry in raw.items():
        problems.extend(validate_entry(name, entry, SCENARIOS))

    for name in sorted(set(SCENARIOS) - set(raw)):
        print(
            f"[AVISO] attack_library: cenário '{name}' existe em attack_scenarios.SCENARIOS "
            "mas não tem entrada em attack_library.yaml — a documentar.",
            file=sys.stderr,
        )

    if problems:
        raise ValueError(problems)

    merged: dict[str, dict] = {}
    for name, entry in raw.items():
        scenario = SCENARIOS[name]
        merged[name] = {
            "id": name,
            "name": entry["name"],
            "description": entry["description"],
            "mitre_tactic": scenario.mitre_tactic,
            "mitre_technique": scenario.mitre_technique,
            "tool": scenario.tool,
            "event_ids": list(scenario.event_ids),
            "risk": entry["risk"],
            "prerequisites": entry["prerequisites"],
            "expected_sensors": list(entry["expected_sensors"]),
            "cleanup_steps": list(entry["cleanup_steps"]),
            "replayable": entry["replayable"],
            "replayable_reason": entry["replayable_reason"],
            "duration_estimate": entry["duration_estimate"],
        }

    if use_cache:
        _cache = merged
        _cache_path = resolved
    return merged


def reset_cache() -> None:
    """Só para testes: força a próxima load_attack_library() a reler o ficheiro."""
    global _cache, _cache_path
    _cache = None
    _cache_path = None


def get_library_entry(scenario_name: str) -> dict | None:
    """Entrada combinada de um cenário, ou None se não existir na biblioteca."""
    return load_attack_library().get(scenario_name)


def get_expected_sensors(scenario_name: str) -> list[str]:
    """Default de 'sensores esperados' por cenário, usado pelo attack_registry
    (R4) quando o attack_log não trouxer `expected` próprio. Cenário sem
    entrada na biblioteca -> [] (quem chama decide o fallback; nunca inventa
    um default aqui)."""
    entry = get_library_entry(scenario_name)
    return list(entry["expected_sensors"]) if entry else []


def build_attack_library() -> dict:
    """Payload de GET /api/attack-library: {entries: [...], total}, ordenado
    por id (scenario_name) para uma resposta estável."""
    entries = sorted(load_attack_library().values(), key=lambda e: e["id"])
    return {"entries": entries, "total": len(entries)}


def get_entry(scenario_id: str) -> dict | None:
    """Entrada combinada pelo id (scenario_name), usada por
    GET /api/attack-library/{id}. Alias de get_library_entry."""
    return get_library_entry(scenario_id)
