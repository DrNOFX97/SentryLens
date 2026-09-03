"""
Motor de deteção de desvios RBAC (Role Based Access Control) a partir dos
alertas de gestão de grupos do Active Directory recebidos via Wazuh.

Cruza eventos de adição/remoção de membros de grupo (Event IDs 4728, 4729,
4732, 4733, 4756, 4757) com um baseline de cargos versus grupos permitidos,
para identificar atribuições de privilégios fora do que está definido para
a função de cada utilizador.

O baseline segue o mesmo schema usado no laboratório AD/IAM de apoio
(projeto irmão `ad-iam-lab`):

    {
      "cargos": {
        "<Nome do Cargo>": {
          "departamento": "...",
          "grupos_permitidos": ["GG-...", "DL-..."],
          "grupos_proibidos": ["Domain Admins", ...],
          "nivel_risco": "baixo|medio|critico",
          "conta_associada": "administrativa"   # opcional
        }
      },
      "grupos_criticos": ["Domain Admins", "Enterprise Admins", ...]
    }
"""

import json

GROUP_ADD_EVENT_IDS: set[int] = {4728, 4732, 4756}
GROUP_REMOVE_EVENT_IDS: set[int] = {4729, 4733, 4757}
GROUP_MOVEMENT_EVENT_IDS: set[int] = GROUP_ADD_EVENT_IDS | GROUP_REMOVE_EVENT_IDS

CARGO_DESCONHECIDO = "cargo desconhecido"


def load_rbac_baseline(path: str) -> dict:
    """Lê e interpreta o ficheiro JSON de baseline RBAC em `path`.

    Não trata erros: `FileNotFoundError` (ficheiro inexistente) e
    `json.JSONDecodeError` (JSON inválido) propagam para quem chamar,
    que decide a resposta HTTP apropriada.
    """
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _extract_event_id(alert: dict) -> int | None:
    """Extrai o Windows Event ID (data.win.system.eventID) como inteiro.

    Devolve None se o campo não existir ou não for convertível, em vez
    de lançar exceção, para que o alerta seja simplesmente ignorado por
    `build_privileges_report`.
    """
    try:
        raw = alert.get("data", {}).get("win", {}).get("system", {}).get("eventID")
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def _extract_group_name(member_name: str) -> str:
    """Extrai o nome do grupo a partir do DN presente em `memberName`.

    Assume o formato LDAP típico do Active Directory, por exemplo
    "CN=GG-Financeira,OU=Seguranca,DC=nortada,DC=local", do qual se
    extrai a parte entre "CN=" e a primeira vírgula ("GG-Financeira").
    Se `memberName` não contiver "CN=" (formato inesperado), devolve a
    string tal como recebida, sem alterações.
    """
    if not member_name:
        return ""
    marker = "CN="
    idx = member_name.find(marker)
    if idx == -1:
        return member_name
    rest = member_name[idx + len(marker):]
    comma_idx = rest.find(",")
    return rest[:comma_idx] if comma_idx != -1 else rest


def build_privileges_report(
    alerts: list[dict],
    baseline: dict,
    user_to_cargo: dict[str, str] | None = None,
) -> dict:
    """Constrói o relatório de privilégios RBAC a partir dos alertas Wazuh.

    Função pura: não faz I/O nem chamadas de rede, apenas processa a lista
    `alerts` (formato dos alertas do Wazuh Indexer) e o `baseline` (dict já
    carregado, ver `load_rbac_baseline`).

    Considera apenas eventos de gestão de grupo global/local/universal:
    adições (4728, 4732, 4756) e remoções (4729, 4733, 4757). As remoções
    contam para `total_movements` e para `group_ranking`, mas nunca geram
    desvios (só as adições são avaliadas contra o baseline).

    Para cada adição, o cargo do utilizador afetado (`targetUserName`) é
    resolvido através de `user_to_cargo` (mapa utilizador -> nome do
    cargo). Se `user_to_cargo` for None ou o utilizador não constar do
    mapa, o cargo é tratado como "cargo desconhecido", o que por si só
    torna a adição um desvio (achado de auditoria, nunca ignorado).

    Uma adição é um desvio se:
      - o cargo for "cargo desconhecido"; ou
      - o grupo não constar de `grupos_permitidos` do cargo; ou
      - o grupo constar de `grupos_proibidos` do cargo.

    Adições a grupos listados em `grupos_criticos` do baseline entram
    sempre em `critical_additions`, independentemente do cargo permitir
    ou não esse grupo, para nunca esconder este tipo de evento.

    Devolve sempre uma estrutura bem formada, mesmo com `alerts` vazio ou
    sem eventos de grupo: nunca lança exceção.

    Args:
        alerts: lista de alertas no formato devolvido pelo Wazuh Indexer.
        baseline: dict do baseline RBAC (ver `load_rbac_baseline`).
        user_to_cargo: mapa opcional utilizador -> nome do cargo.

    Returns:
        dict com as chaves `total_movements`, `deviations`,
        `critical_additions` e `group_ranking`.
    """
    cargos = baseline.get("cargos", {}) if baseline else {}
    grupos_criticos = set(baseline.get("grupos_criticos", [])) if baseline else set()

    total_movements = 0
    deviations: list[dict] = []
    critical_additions: list[dict] = []
    group_counts: dict[str, int] = {}

    for alert in alerts or []:
        event_id = _extract_event_id(alert)
        if event_id not in GROUP_MOVEMENT_EVENT_IDS:
            continue

        total_movements += 1

        eventdata = alert.get("data", {}).get("win", {}).get("eventdata", {})
        member_name = eventdata.get("memberName", "")
        group = _extract_group_name(member_name)
        target_user = eventdata.get("targetUserName", "")
        subject_user = eventdata.get("subjectUserName", "")
        timestamp = alert.get("@timestamp", "")

        group_counts[group] = group_counts.get(group, 0) + 1

        if event_id not in GROUP_ADD_EVENT_IDS:
            # Remoção: só conta para o total e para o ranking, nunca é desvio.
            continue

        if group in grupos_criticos:
            critical_additions.append(
                {
                    "user": target_user,
                    "group": group,
                    "executed_by": subject_user,
                    "timestamp": timestamp,
                }
            )

        cargo_nome = user_to_cargo.get(target_user) if user_to_cargo else None
        if not cargo_nome:
            cargo_nome = CARGO_DESCONHECIDO

        reason: str | None = None
        if cargo_nome == CARGO_DESCONHECIDO:
            reason = "cargo desconhecido no baseline"
        else:
            cargo_info = cargos.get(cargo_nome, {})
            grupos_permitidos = set(cargo_info.get("grupos_permitidos", []))
            grupos_proibidos = set(cargo_info.get("grupos_proibidos", []))
            if group in grupos_proibidos:
                reason = "grupo explicitamente proibido para o cargo"
            elif group not in grupos_permitidos:
                reason = "grupo fora dos permitidos para o cargo"

        if reason is not None:
            deviations.append(
                {
                    "user": target_user,
                    "cargo": cargo_nome,
                    "group": group,
                    "reason": reason,
                    "executed_by": subject_user,
                    "timestamp": timestamp,
                }
            )

    group_ranking = [
        {"group": group, "count": count}
        for group, count in sorted(group_counts.items(), key=lambda item: item[1], reverse=True)
    ]

    return {
        "total_movements": total_movements,
        "deviations": deviations,
        "critical_additions": critical_additions,
        "group_ranking": group_ranking,
    }
