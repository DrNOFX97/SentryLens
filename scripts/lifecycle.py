"""
Relatório de ciclo de vida de contas de utilizador (Windows Security).

Este módulo é puro: não faz I/O, não acede à rede nem ao disco, não importa
`wazuh_client` nem `main`, e não sabe nada de FastAPI. Recebe uma lista de
alertas já obtidos por quem o chama (tipicamente o endpoint que consulta o
Wazuh Indexer) e devolve um dicionário com contagens, uma linha temporal
diária, a lista de eventos individuais relevantes e deteções de risco.

Event IDs de ciclo de vida cobertos nas contagens e na linha temporal:
    4720 - Conta criada        (created)
    4722 - Conta ativada       (activated)
    4725 - Conta desativada    (disabled)
    4726 - Conta eliminada     (deleted)
    4740 - Conta bloqueada     (locked)

Para as deteções de risco são também considerados:
    4624 - Logon com sucesso (usado na deteção de offboarding falhado)
    4728 - Membro adicionado a grupo global
    4732 - Membro adicionado a grupo local
    4756 - Membro adicionado a grupo universal

Assunções documentadas:
    - Fuso horário: os timestamps `@timestamp` são interpretados tal como
      vêm no alerta. Quando o timestamp não tem indicação explícita de
      fuso horário, assume-se UTC. As componentes de hora, dia da semana
      e data usadas nas deteções e na linha temporal são sempre as
      componentes "locais" do timestamp tal como recebido (não há
      conversão entre fusos horários), pelo que "fora de horário" e
      "mesmo dia" referem-se sempre à hora e data que o próprio evento
      traz.
    - Extração do grupo a partir do DN: campos `memberName` como
      `CN=Domain Admins,CN=Users,DC=exemplo,DC=local` são tratados como
      uma sequência de componentes separadas por vírgulas; extrai-se o
      valor da primeira componente `CN=...` (a parte entre `CN=` e a
      vírgula seguinte) e usa-se esse valor, comparado sem distinguir
      maiúsculas de minúsculas, para verificar se corresponde a um dos
      grupos críticos monitorizados.
    - Qualquer timestamp que não seja parseável, ou qualquer evento sem
      os campos necessários para uma deteção específica, é ignorado
      nessa deteção em concreto; nunca faz a função inteira falhar.
    - Valores de "severity": usa-se deliberadamente o slug ASCII sem
      acentuação ("critico", "medio", "alto", "baixo") em vez da palavra
      acentuada, por ser um valor de enumeração da API (não texto de
      leitura), consistente com a mesma convenção já usada no projeto
      irmão `ad-iam-lab` (campo `nivel_risco` do baseline RBAC) e em
      `admin_activity.py`. O texto de leitura (`name`, `explanation`)
      mantém sempre acentuação completa em português de Portugal.
"""

from __future__ import annotations

from datetime import datetime, time, timezone
from typing import Any

# Event IDs de ciclo de vida cobertos nas contagens, timeline e lista de eventos.
LIFECYCLE_EVENT_IDS: dict[int, str] = {
    4720: "created",
    4722: "activated",
    4725: "disabled",
    4726: "deleted",
    4740: "locked",
}

# Event IDs de adição a grupo (usados na deteção de escalada imediata).
GROUP_ADD_EVENT_IDS: frozenset[int] = frozenset({4728, 4732, 4756})

# Event ID de logon com sucesso (usado na deteção de offboarding falhado).
SUCCESSFUL_LOGON_EVENT_ID = 4624

# Grupos considerados críticos para efeitos de deteção de escalada de privilégios.
CRITICAL_GROUPS: frozenset[str] = frozenset(
    name.lower()
    for name in (
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Account Operators",
        "Backup Operators",
    )
)

WORK_DAY_START = time(8, 0)
WORK_DAY_END = time(20, 0)


def _extract_event_id(alert: dict[str, Any]) -> int | None:
    """Extrai o Event ID do Windows de um alerta, devolvendo None se ausente
    ou inválido. `eventID` vem sempre como string dentro de
    data.win.system, por isso a conversão para int é feita com cuidado.
    """
    try:
        raw = alert.get("data", {}).get("win", {}).get("system", {}).get("eventID")
    except AttributeError:
        return None
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _extract_eventdata_field(alert: dict[str, Any], field: str) -> str | None:
    """Extrai um campo de data.win.eventdata (ex: targetUserName,
    subjectUserName, memberName), devolvendo None se ausente ou vazio.
    """
    try:
        value = alert.get("data", {}).get("win", {}).get("eventdata", {}).get(field)
    except AttributeError:
        return None
    if not value:
        return None
    return str(value)


def _extract_agent_name(alert: dict[str, Any]) -> str | None:
    try:
        name = alert.get("agent", {}).get("name")
    except AttributeError:
        return None
    return name if name else None


def _parse_timestamp(raw_timestamp: str | None) -> datetime | None:
    """Faz parsing seguro de um `@timestamp`. Aceita o sufixo `Z` (UTC) tal
    como usado pelo Wazuh, e trata qualquer formato inesperado ou
    malformado devolvendo None em vez de lançar exceção. Se o timestamp
    não tiver informação de fuso horário, assume-se UTC.
    """
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


def _extract_group_name(member_name: str | None) -> str | None:
    """Extrai o nome do grupo a partir de um DN do tipo
    `CN=Domain Admins,CN=Users,DC=exemplo,DC=local`, devolvendo a parte
    entre `CN=` e a primeira vírgula. Devolve None se o formato não for
    reconhecido.
    """
    if not member_name:
        return None
    stripped = member_name.strip()
    if not stripped.upper().startswith("CN="):
        return None
    rest = stripped[3:]
    comma_index = rest.find(",")
    group = rest[:comma_index] if comma_index != -1 else rest
    group = group.strip()
    return group or None


def _empty_counts() -> dict[str, int]:
    return {"created": 0, "activated": 0, "disabled": 0, "deleted": 0, "locked": 0}


def build_lifecycle_report(alerts: list[dict[str, Any]], days: int) -> dict[str, Any]:
    """Constrói o relatório de ciclo de vida de contas a partir de uma lista
    de alertas já obtidos (não faz I/O nem sabe de onde vieram os alertas).

    Args:
        alerts: lista de alertas no formato devolvido pelo Wazuh Indexer
            (ver `test_with_mock.py` para a forma exata).
        days: número de dias que o chamador usou para obter `alerts`,
            incluído no relatório apenas para contexto informativo (esta
            função não filtra `alerts` por data, isso é responsabilidade
            de quem a chama).

    Returns:
        Um dicionário com as chaves:
            - "days": o valor de `days` recebido.
            - "counts": dict com as contagens de "created", "activated",
              "disabled", "deleted", "locked" no período.
            - "timeline": lista ordenada por data ascendente de
              {"date", "created", "activated", "disabled", "deleted",
              "locked"}, uma entrada por dia com pelo menos um evento
              relevante.
            - "events": lista de eventos individuais relevantes, cada um
              com "event_id", "timestamp", "target_user", "executed_by",
              "agent_name".
            - "detections": lista de deteções de risco, cada uma com
              "name", "severity" ("critico"|"alto"|"medio"|"baixo") e
              "explanation" em português de Portugal.

    Nunca lança exceção por falta de dados: se `alerts` for uma lista
    vazia (ou não tiver nenhum evento relevante), devolve uma estrutura
    vazia bem formada.
    """
    counts = _empty_counts()
    timeline_by_date: dict[str, dict[str, int]] = {}
    events: list[dict[str, Any]] = []

    # Registos usados só para construir as deteções de risco.
    disabled_records: list[dict[str, Any]] = []  # 4725
    logon_records: list[dict[str, Any]] = []  # 4624
    created_records: list[dict[str, Any]] = []  # 4720
    deleted_records: list[dict[str, Any]] = []  # 4726
    group_add_records: list[dict[str, Any]] = []  # 4728 / 4732 / 4756

    if isinstance(alerts, list):
        for alert in alerts:
            if not isinstance(alert, dict):
                continue

            event_id = _extract_event_id(alert)
            if event_id is None:
                continue

            timestamp_raw = alert.get("@timestamp")
            target_user = _extract_eventdata_field(alert, "targetUserName")
            executed_by = _extract_eventdata_field(alert, "subjectUserName")
            agent_name = _extract_agent_name(alert)
            parsed_ts = _parse_timestamp(timestamp_raw)

            if event_id in LIFECYCLE_EVENT_IDS:
                key = LIFECYCLE_EVENT_IDS[event_id]
                counts[key] += 1

                events.append(
                    {
                        "event_id": event_id,
                        "timestamp": timestamp_raw,
                        "target_user": target_user,
                        "executed_by": executed_by,
                        "agent_name": agent_name,
                    }
                )

                if parsed_ts is not None:
                    date_str = parsed_ts.date().isoformat()
                    day_entry = timeline_by_date.setdefault(
                        date_str, _empty_counts()
                    )
                    day_entry[key] += 1

            record = {
                "target_user": target_user,
                "executed_by": executed_by,
                "timestamp_raw": timestamp_raw,
                "timestamp": parsed_ts,
            }

            if event_id == 4725:
                disabled_records.append(record)
            elif event_id == SUCCESSFUL_LOGON_EVENT_ID:
                logon_records.append(record)
            elif event_id == 4720:
                created_records.append(record)
            elif event_id == 4726:
                deleted_records.append(record)
            elif event_id in GROUP_ADD_EVENT_IDS:
                member_name = _extract_eventdata_field(alert, "memberName")
                record["member_name"] = member_name
                record["group_name"] = _extract_group_name(member_name)
                group_add_records.append(record)

    timeline = [
        {"date": date_str, **day_counts}
        for date_str, day_counts in sorted(timeline_by_date.items())
    ]

    detections: list[dict[str, str]] = []
    detections.extend(_detect_offboarding_falhado(disabled_records, logon_records))
    detections.extend(_detect_conta_descartavel(created_records, deleted_records))
    detections.extend(_detect_criacao_fora_de_horario(created_records))
    detections.extend(_detect_escalada_imediata(created_records, group_add_records))

    return {
        "days": days,
        "counts": counts,
        "timeline": timeline,
        "events": events,
        "detections": detections,
    }


def _detect_offboarding_falhado(
    disabled_records: list[dict[str, Any]],
    logon_records: list[dict[str, Any]],
) -> list[dict[str, str]]:
    """Deteta "offboarding falhado": uma conta desativada (4725) que depois
    volta a fazer login com sucesso (4624). Gera uma deteção por cada par
    (desativação, login posterior) encontrado, para que se veja
    exatamente qual conta e quando aconteceu. Severidade: critico.
    """
    detections: list[dict[str, str]] = []

    for disabled in disabled_records:
        user = disabled["target_user"]
        disabled_ts = disabled["timestamp"]
        if not user or disabled_ts is None:
            continue

        for logon in logon_records:
            if logon["target_user"] != user:
                continue
            logon_ts = logon["timestamp"]
            if logon_ts is None:
                continue
            if logon_ts <= disabled_ts:
                continue

            detections.append(
                {
                    "name": "Offboarding falhado",
                    "severity": "critico",
                    "explanation": (
                        f"A conta '{user}' foi desativada em "
                        f"{disabled['timestamp_raw']}, mas registou um login com "
                        f"sucesso em {logon['timestamp_raw']}, depois da "
                        "desativação. Isto sugere que o processo de offboarding "
                        "falhou ou que a conta continua a ser utilizável apesar "
                        "de desativada."
                    ),
                }
            )

    return detections


def _detect_conta_descartavel(
    created_records: list[dict[str, Any]],
    deleted_records: list[dict[str, Any]],
) -> list[dict[str, str]]:
    """Deteta "conta descartável": criação (4720) e eliminação (4726) da
    mesma conta com menos de 24 horas de diferença entre os timestamps.
    Severidade: alto.
    """
    detections: list[dict[str, str]] = []

    for created in created_records:
        user = created["target_user"]
        created_ts = created["timestamp"]
        if not user or created_ts is None:
            continue

        for deleted in deleted_records:
            if deleted["target_user"] != user:
                continue
            deleted_ts = deleted["timestamp"]
            if deleted_ts is None:
                continue

            delta = abs((deleted_ts - created_ts).total_seconds())
            if delta >= 24 * 3600:
                continue

            hours = delta / 3600
            detections.append(
                {
                    "name": "Conta descartável",
                    "severity": "alto",
                    "explanation": (
                        f"A conta '{user}' foi criada em "
                        f"{created['timestamp_raw']} e eliminada em "
                        f"{deleted['timestamp_raw']}, com apenas "
                        f"{hours:.1f} horas de diferença. Este padrão é típico "
                        "de contas descartáveis criadas para uma atividade "
                        "pontual e depois removidas para dificultar a "
                        "investigação."
                    ),
                }
            )

    return detections


def _detect_criacao_fora_de_horario(
    created_records: list[dict[str, Any]],
) -> list[dict[str, str]]:
    """Deteta criação de conta (4720) fora do horário laboral habitual:
    antes das 08:00, depois das 20:00, ou num sábado/domingo, usando as
    componentes de hora e dia da semana do timestamp tal como recebido
    (ver assunção de fuso horário no docstring do módulo). Severidade:
    medio.
    """
    detections: list[dict[str, str]] = []

    for created in created_records:
        user = created["target_user"]
        created_ts = created["timestamp"]
        if not user or created_ts is None:
            continue

        local_time = created_ts.time()
        weekday = created_ts.weekday()  # 0 = segunda, 5 = sabado, 6 = domingo

        reasons: list[str] = []
        if local_time < WORK_DAY_START:
            reasons.append("antes das 08:00")
        if local_time > WORK_DAY_END:
            reasons.append("depois das 20:00")
        if weekday >= 5:
            dia = "sábado" if weekday == 5 else "domingo"
            reasons.append(f"num {dia}")

        if not reasons:
            continue

        motivo = " e ".join(reasons)
        detections.append(
            {
                "name": "Criação fora de horário",
                "severity": "medio",
                "explanation": (
                    f"A conta '{user}' foi criada em "
                    f"{created['timestamp_raw']}, {motivo}, fora do horário "
                    "laboral habitual. Criações de contas fora de horas pode "
                    "indicar atividade não supervisionada ou não autorizada."
                ),
            }
        )

    return detections


def _detect_escalada_imediata(
    created_records: list[dict[str, Any]],
    group_add_records: list[dict[str, Any]],
) -> list[dict[str, str]]:
    """Deteta "criação com escalada imediata": uma conta criada (4720) que
    no mesmo dia é adicionada a um grupo crítico (4728/4732/4756 com
    memberName correspondente a um dos grupos críticos monitorizados).
    A comparação de dia usa a data (AAAA-MM-DD) extraída do timestamp tal
    como recebido, sem conversão de fuso horário. Severidade: alto.
    """
    detections: list[dict[str, str]] = []

    for created in created_records:
        user = created["target_user"]
        created_ts = created["timestamp"]
        if not user or created_ts is None:
            continue
        created_date = created_ts.date()

        for group_add in group_add_records:
            if group_add["target_user"] != user:
                continue
            group_add_ts = group_add["timestamp"]
            if group_add_ts is None:
                continue
            if group_add_ts.date() != created_date:
                continue

            group_name = group_add.get("group_name")
            if not group_name or group_name.lower() not in CRITICAL_GROUPS:
                continue

            detections.append(
                {
                    "name": "Criação com escalada imediata",
                    "severity": "alto",
                    "explanation": (
                        f"A conta '{user}' foi criada em "
                        f"{created['timestamp_raw']} e no mesmo dia foi "
                        f"adicionada ao grupo crítico '{group_name}' em "
                        f"{group_add['timestamp_raw']}. Escalar privilégios "
                        "logo após a criação de uma conta é um padrão comum em "
                        "movimentos laterais e criação de contas persistentes "
                        "por atacantes."
                    ),
                }
            )

    return detections
