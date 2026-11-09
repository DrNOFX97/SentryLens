"""
Tabela técnica -> tática MITRE (R16, Phase 18). Módulo puro: lê o ficheiro
versionado scripts/mitre_techniques.yaml (nunca uma base de dados, D-00c) e
responde "a que táticas pertence esta técnica?" para quem consome
(resolvedor por alerta, cobertura MITRE).

Validação fail-fast e síncrona, como a Attack Library: load_mitre_techniques()
lê o YAML uma vez (só yaml.safe_load), valida e levanta ValueError com a lista
completa de problemas; main.py chama-a a nível de módulo e deixa a excepção
propagar, por isso o backend nunca arranca com uma tabela inválida. Resultado
em cache em memória; reset_cache() existe só para os testes.

O ATT&CK está fixado na v18.1 (ATTACK_VERSION): é a última versão com as 14
táticas Enterprise, incluindo "Defense Evasion", que é também o vocabulário
que o Wazuh do laboratório envia. A v19+ trocou-a por "Stealth" e acrescentou
"Defense Impairment"; mudar de versão é uma decisão futura.

A tática de um alerta e de um ataque vem SEMPRE desta tabela (tactics_for);
nada aqui reescreve o log de ataques.
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml

from attack_library import MITRE_RE as TECHNIQUE_RE
from attack_scenarios import SCENARIOS
from event_catalog import CRITICAL_EVENTS

ATTACK_VERSION = "v18.1"
DEFAULT_PATH = Path(__file__).parent / "mitre_techniques.yaml"
PATH_ENV_VAR = "MITRE_TECHNIQUES_PATH"

# As 14 táticas Enterprise da v18.1, na ordem da matriz.
ENTERPRISE_TACTICS = (
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
)
ENTRY_FIELDS = ("id", "name", "tactics")
NAME_MAX_LENGTH = 128

_cache: dict[str, dict] | None = None
_cache_path: Path | None = None


def _resolve_path(path: str | os.PathLike | None) -> Path:
    """Caminho do YAML: argumento explícito > MITRE_TECHNIQUES_PATH > default.
    Relativo é sempre relativo à pasta do módulo (nunca ao cwd)."""
    raw = path if path is not None else os.getenv(PATH_ENV_VAR)
    if raw is None:
        return DEFAULT_PATH
    candidate = Path(raw)
    return candidate if candidate.is_absolute() else Path(__file__).parent / candidate


def validate_technique_entry(position: int, entry) -> list[str]:
    """Problemas da entrada na posição `position` (lista vazia se válida).
    Nunca levanta excepção; quem chama decide o que fazer com a lista."""
    if not isinstance(entry, dict):
        return [f"entrada #{position}: não é um objeto"]

    raw_id = entry.get("id")
    label = f"entrada #{position}" + (f" ({raw_id})" if isinstance(raw_id, str) else "")
    problems: list[str] = []

    for field in ENTRY_FIELDS:
        if field not in entry:
            problems.append(f"{label}: campo obrigatório em falta '{field}'")

    if "id" in entry and (
        not isinstance(raw_id, str) or not TECHNIQUE_RE.fullmatch(raw_id)
    ):
        problems.append(f"{label}: id em formato inválido (esperado Txxxx ou Txxxx.xxx)")

    if "tactics" in entry:
        tactics = entry["tactics"]
        if not isinstance(tactics, list) or not tactics:
            problems.append(f"{label}: tactics tem de ser uma lista não vazia")
        else:
            for tactic in tactics:
                if not isinstance(tactic, str) or tactic not in ENTERPRISE_TACTICS:
                    problems.append(f"{label}: tática fora das 14 Enterprise: {tactic!r}")
            if all(isinstance(t, str) for t in tactics) and len(set(tactics)) != len(tactics):
                problems.append(f"{label}: tactics tem uma tática repetida")

    return problems


def load_mitre_techniques(
    yaml_path: str | os.PathLike | None = None,
    *,
    use_cache: bool = True,
    scenarios=None,
    catalog=None,
) -> dict[str, dict]:
    """Lê scripts/mitre_techniques.yaml e valida. Devolve
    {id: {"id", "name", "tactics": tuple}}. Cache em memória por omissão;
    use_cache=False força reler (testes). Levanta ValueError com a lista de
    problemas se o ficheiro for ilegível, mal formado ou inválido.

    `scenarios`/`catalog` (por omissão SCENARIOS/CRITICAL_EVENTS) existem para
    os testes injetarem dados; quando algum é passado o resultado nunca vai
    para a cache."""
    global _cache, _cache_path
    injected = scenarios is not None or catalog is not None
    resolved = _resolve_path(yaml_path)
    if use_cache and not injected and _cache is not None and _cache_path == resolved:
        return _cache

    try:
        with open(resolved, encoding="utf-8") as handle:
            raw = yaml.safe_load(handle)
    except FileNotFoundError as exc:
        raise ValueError([f"mitre_techniques.yaml não encontrado em '{resolved}'"]) from exc
    except yaml.YAMLError as exc:
        raise ValueError([f"mitre_techniques.yaml inválido (YAML malformado): {exc}"]) from exc

    if not isinstance(raw, list) or not raw:
        raise ValueError(["mitre_techniques.yaml inválido: esperada uma lista não vazia de entradas no topo"])

    problems: list[str] = []
    for position, entry in enumerate(raw, start=1):
        problems.extend(validate_technique_entry(position, entry))

    if problems:
        raise ValueError(problems)

    table: dict[str, dict] = {}
    for entry in raw:
        table[entry["id"]] = {
            "id": entry["id"],
            "name": entry["name"],
            "tactics": tuple(entry["tactics"]),
        }

    if use_cache and not injected:
        _cache = table
        _cache_path = resolved
    return table


def reset_cache() -> None:
    """Só para testes: força a próxima load_mitre_techniques() a reler o ficheiro."""
    global _cache, _cache_path
    _cache = None
    _cache_path = None


def parent_of(technique_id) -> str | None:
    """Id base de uma técnica: 'T1053.005' -> 'T1053'; 'T1053' -> 'T1053'.
    Valor inválido ou que não é str -> None."""
    if not isinstance(technique_id, str) or not TECHNIQUE_RE.fullmatch(technique_id):
        return None
    return technique_id.split(".", 1)[0]


def tactics_for(technique_id, table: dict | None = None) -> list[str]:
    """Táticas de uma técnica: entrada própria, senão a do pai, senão [].
    Devolve sempre uma lista nova (nunca o tuplo da cache)."""
    if table is None:
        table = load_mitre_techniques()
    parent = parent_of(technique_id)
    if parent is None:
        return []
    entry = table.get(technique_id) or table.get(parent)
    return list(entry["tactics"]) if entry else []
