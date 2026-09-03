"""
Relatório de atividade de contas administrativas a partir de alertas Wazuh.

Este módulo constrói, de forma pura e sem qualquer I/O ou rede, um relatório
de atividade de contas consideradas administrativas com base numa lista de
alertas Wazuh já normalizados (o formato de alerta é o mesmo usado em
test_with_mock.py e devolvido por WazuhIndexerClient.get_recent_alerts).

Limitações importantes, documentadas aqui para quem consumir este módulo:

1. A identificação de contas administrativas por adesão a grupo crítico
   (Domain Admins, Enterprise Admins, Schema Admins, Account Operators,
   Backup Operators) é uma correlação LOCAL aos alertas recebidos (eventos
   4728/4732/4756 dentro do próprio `alerts`), nunca uma consulta real ao
   Active Directory. O Wazuh não expõe pertença a grupos fora dos eventos
   de auditoria que já chegaram como alerta, por isso uma conta pode ser
   administrativa no AD sem que este módulo o saiba, se o evento de adesão
   ao grupo não estiver dentro da janela de alertas fornecida.

2. A deteção "Violação de separação de contas" assume que o nome do
   agente identifica se a máquina é um servidor ou um controlador de
   domínio através da presença da substring "SERVER" ou "DC"
   (case-insensitive) no nome do agente. Esta é uma heurística de
   convenção de nomenclatura: se os servidores do ambiente não seguirem
   esta convenção, a deteção produz falsos negativos (um servidor
   legítimo pode ser tratado como estação de trabalho e gerar uma
   violação inexistente).

3. A deteção "Conta administrativa sem atividade" depende inteiramente
   da janela temporal de `alerts` passada por quem chama esta função. A
   função não faz qualquer consulta adicional para confirmar inatividade;
   se `alerts` cobrir uma janela mais curta que `reference_days`, esta
   deteção pode gerar falsos positivos (a conta parece inativa apenas
   porque não foi fornecido histórico suficiente). Para resultados
   fiáveis, `alerts` deve cobrir, idealmente, pelo menos `reference_days`
   dias.

4. "Atividade fora de horário" usa a hora e o dia da semana tal como vem
   no campo @timestamp do alerta (interpretado em UTC, sem qualquer
   conversão para fuso horário local) - a mesma assunção usada no painel
   de ciclo de vida: assume-se que o timestamp já reflete a hora relevante
   para efeitos de horário laboral, sem conversão de fuso horário
   adicional.

5. Timestamps malformados ou em falta são ignorados de forma segura (nunca
   levantam exceção); o evento correspondente é simplesmente excluído dos
   cálculos que dependem de data/hora.

6. Um evento cuja conta relevante (ver `_relevant_account`) não possa ser
   determinada (campos em falta) não é contabilizado em `event_counts`
   (nem como admin, nem como normal), para não inflacionar nenhuma das
   duas contagens com dados desconhecidos.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

CRITICAL_GROUPS: set[str] = {
    "domain admins",
    "enterprise admins",
    "schema admins",
    "account operators",
    "backup operators",
}

# Traduções amigáveis para os valores de logonType usados nas explicações
# das deteções. 2 = interativo local, 10 = RDP (RemoteInteractive).
_LOGON_TYPE_LABELS: dict[int, str] = {
    2: "interativo local",
    10: "RDP (RemoteInteractive)",
}

_GROUP_MEMBERSHIP_EVENT_IDS: set[int] = {4728, 4732, 4756}


def _get(source: Any, *keys: str, default: Any = None) -> Any:
    """Navega por chaves aninhadas de um dict de forma segura, devolvendo
    `default` se qualquer nível do caminho não existir ou não for um dict.
    """
    current = source
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
    return current if current is not None else default


def _parse_event_id(alert: dict) -> int | None:
    """Extrai e converte data.win.system.eventID para int, sem rebentar em
    valores malformados ou em falta."""
    raw = _get(alert, "data", "win", "system", "eventID")
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _parse_logon_type(raw: Any) -> int | None:
    """logonType vem como string no eventdata; converte para int com
    tratamento de erro, devolvendo None se não for possível."""
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _parse_timestamp(raw: Any) -> datetime | None:
    """Faz parsing seguro de @timestamp (ISO 8601, normalmente terminado
    em 'Z'). Devolve None em vez de lançar exceção para timestamps
    malformados, vazios ou em falta."""
    if not isinstance(raw, str) or not raw:
        return None
    value = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _extract_group_name(member_name: Any) -> str | None:
    """Extrai o nome do grupo de um Distinguished Name do tipo
    'CN=Domain Admins,CN=Users,DC=exemplo,DC=local' (a parte depois de
    'CN=' e antes da primeira vírgula). Devolve None se memberName não
    tiver a forma esperada."""
    if not isinstance(member_name, str) or "CN=" not in member_name:
        return None
    after_cn = member_name.split("CN=", 1)[1]
    group_name = after_cn.split(",", 1)[0].strip()
    return group_name or None


def _relevant_account(event_id: int | None, eventdata: dict) -> str | None:
    """Determina qual utilizador é relevante para efeitos de contagem em
    `event_counts`, conforme o tipo de evento:

    - 4624 (logon com sucesso): o evento é sempre sobre a conta que fez o
      logon, por isso usa-se sempre targetUserName.
    - 4728/4732/4756 (adesão a grupo): a conta relevante é a que foi
      adicionada ao grupo (targetUserName), não quem executou a alteração.
    - Restantes eventos: usa-se subjectUserName (quem executou a ação) e,
      na sua ausência, targetUserName como aproximação razoável.
    """
    target = eventdata.get("targetUserName")
    subject = eventdata.get("subjectUserName")
    if event_id == 4624:
        return target
    if event_id in _GROUP_MEMBERSHIP_EVENT_IDS:
        return target
    return subject or target


def _is_admin_by_prefix(username: str | None, admin_prefix: str) -> bool:
    if not username:
        return False
    return username.lower().startswith(admin_prefix.lower())


def build_admin_activity_report(
    alerts: list[dict],
    admin_prefix: str = "adm.",
    reference_days: int = 60,
    now: datetime | None = None,
) -> dict:
    """Constrói um relatório de atividade de contas administrativas a
    partir de uma lista de alertas Wazuh já normalizados.

    Função pura: não faz I/O, não acede à rede nem à Active Directory (ver
    limitações 1 a 6 no docstring do módulo). Nunca lança exceção por
    causa de dados malformados, incompletos ou em falta; nesses casos
    ignora o campo ou o evento em causa em vez de rebentar.

    Uma conta é considerada administrativa se, e só se:
      (a) o nome de utilizador (targetUserName ou subjectUserName,
          conforme o evento) começa por `admin_prefix`, comparado sem
          distinção de maiúsculas/minúsculas; OU
      (b) apareceu como targetUserName num evento 4728/4732/4756 cujo
          memberName corresponde a um dos grupos críticos definidos em
          CRITICAL_GROUPS (comparação pelo nome extraído do DN, sem
          distinção de maiúsculas/minúsculas). Este conjunto é construído
          a partir do próprio `alerts` recebido, antes de qualquer outra
          classificação (ver limitação 1 no docstring do módulo).

    Args:
        alerts: lista de alertas no formato devolvido por
            WazuhIndexerClient.get_recent_alerts (ver test_with_mock.py).
        admin_prefix: prefixo (comparado sem distinção de
            maiúsculas/minúsculas) que identifica contas administrativas
            pelo nome de utilizador, por omissão "adm.".
        reference_days: número de dias sem eventos a partir do qual uma
            conta administrativa é considerada "sem atividade" (ver
            limitação 3 no docstring do módulo).
        now: instante de referência usado para calcular "sem atividade".
            Por omissão usa datetime.now(timezone.utc); útil para tornar
            os testes determinísticos.

    Returns:
        dict com as chaves:
          - admin_accounts: lista ordenada dos utilizadores identificados
            como administrativos.
          - event_counts: dict {"admin": int, "normal": int} (ver
            limitação 6 no docstring do módulo para eventos sem conta
            determinável).
          - special_privileges_by_user: dict {utilizador: contagem} de
            eventos 4672 por conta administrativa.
          - special_privileges_by_hour: dict {"0".."23": contagem},
            distribuição por hora do dia (UTC) dos eventos 4672 agregados
            entre todas as contas administrativas.
          - scheduled_tasks: lista de {"user", "timestamp", "agent_name"}
            para eventos 4698 de contas administrativas.
          - processes: lista de {"user", "timestamp", "agent_name"} para
            eventos 4688 de contas administrativas, apenas quando o
            evento tem informação suficiente para identificar o
            utilizador.
          - detections: lista de {"name", "severity", "explanation"} em
            português de Portugal.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    empty_hour_distribution: dict[str, int] = {str(hour): 0 for hour in range(24)}

    if not alerts:
        return {
            "admin_accounts": [],
            "event_counts": {"admin": 0, "normal": 0},
            "special_privileges_by_user": {},
            "special_privileges_by_hour": dict(empty_hour_distribution),
            "scheduled_tasks": [],
            "processes": [],
            "detections": [],
        }

    # --- Passo 1: construir o conjunto de utilizadores vistos em grupo
    # crítico, a partir do próprio `alerts` (correlação local, ver
    # limitação 1 no docstring do módulo), antes de classificar o resto.
    critical_group_users: set[str] = set()
    for alert in alerts:
        event_id = _parse_event_id(alert)
        if event_id not in _GROUP_MEMBERSHIP_EVENT_IDS:
            continue
        eventdata = _get(alert, "data", "win", "eventdata", default={})
        group_name = _extract_group_name(eventdata.get("memberName"))
        if group_name and group_name.lower() in CRITICAL_GROUPS:
            target = eventdata.get("targetUserName")
            if target:
                critical_group_users.add(target.lower())

    def is_admin(username: str | None) -> bool:
        if not username:
            return False
        return _is_admin_by_prefix(username, admin_prefix) or username.lower() in critical_group_users

    # --- Passo 2: percorrer os alertas e agregar tudo o resto. ---
    admin_accounts_seen: dict[str, str] = {}  # chave em minúsculas -> forma original (primeira ocorrência)
    event_counts = {"admin": 0, "normal": 0}
    special_privileges_by_user: dict[str, int] = {}
    special_privileges_by_hour: dict[str, int] = dict(empty_hour_distribution)
    scheduled_tasks: list[dict[str, Any]] = []
    processes: list[dict[str, Any]] = []

    separation_violations: list[dict[str, Any]] = []
    unexpected_privileges: list[dict[str, Any]] = []
    outside_hours_accounts: dict[str, str] = {}  # chave em minúsculas -> forma original
    last_seen_by_admin: dict[str, datetime] = {}

    def remember_admin(username: str) -> str:
        key = username.lower()
        if key not in admin_accounts_seen:
            admin_accounts_seen[key] = username
        return admin_accounts_seen[key]

    for alert in alerts:
        event_id = _parse_event_id(alert)
        eventdata = _get(alert, "data", "win", "eventdata", default={})
        agent_name = _get(alert, "agent", "name", default="") or ""
        timestamp_raw = alert.get("@timestamp")
        timestamp = _parse_timestamp(timestamp_raw)

        relevant = _relevant_account(event_id, eventdata)
        if relevant:
            if is_admin(relevant):
                event_counts["admin"] += 1
                remember_admin(relevant)
            else:
                event_counts["normal"] += 1

        # Atualiza a última atividade conhecida de qualquer conta admin
        # que apareça no evento, como alvo ou como sujeito, para a
        # deteção de inatividade e para a deteção de fora de horário.
        if timestamp is not None:
            for candidate in (eventdata.get("targetUserName"), eventdata.get("subjectUserName")):
                if candidate and is_admin(candidate):
                    canonical = remember_admin(candidate)
                    key = canonical.lower()
                    if key not in last_seen_by_admin or timestamp > last_seen_by_admin[key]:
                        last_seen_by_admin[key] = timestamp

                    hour = timestamp.hour
                    weekday = timestamp.weekday()  # 0=segunda ... 5=sábado, 6=domingo
                    if hour < 8 or hour >= 20 or weekday >= 5:
                        outside_hours_accounts.setdefault(key, canonical)

        # --- 4672: privilégios especiais ---
        if event_id == 4672:
            privileged_user = eventdata.get("subjectUserName") or eventdata.get("targetUserName")
            if privileged_user and is_admin(privileged_user):
                canonical = remember_admin(privileged_user)
                special_privileges_by_user[canonical] = special_privileges_by_user.get(canonical, 0) + 1
                if timestamp is not None:
                    special_privileges_by_hour[str(timestamp.hour)] += 1
            elif privileged_user:
                unexpected_privileges.append(
                    {
                        "name": "Privilégio inesperado",
                        "severity": "alto",
                        "explanation": (
                            f"O utilizador '{privileged_user}' recebeu privilégios "
                            f"especiais (evento 4672) sem ser identificado como conta "
                            f"administrativa, nem pelo prefixo '{admin_prefix}' nem por "
                            f"adesão a um grupo crítico observada nos alertas fornecidos."
                        ),
                    }
                )

        # --- 4698: tarefas agendadas criadas ---
        if event_id == 4698:
            task_user = eventdata.get("subjectUserName") or eventdata.get("targetUserName")
            if task_user and is_admin(task_user):
                remember_admin(task_user)
                scheduled_tasks.append(
                    {
                        "user": task_user,
                        "timestamp": timestamp_raw,
                        "agent_name": agent_name,
                    }
                )

        # --- 4688: processos criados (só inclui se houver conta identificável) ---
        if event_id == 4688:
            process_user = eventdata.get("subjectUserName") or eventdata.get("targetUserName")
            if process_user and is_admin(process_user):
                remember_admin(process_user)
                processes.append(
                    {
                        "user": process_user,
                        "timestamp": timestamp_raw,
                        "agent_name": agent_name,
                    }
                )

        # --- Deteção: violação de separação de contas ---
        if event_id == 4624:
            target_user = eventdata.get("targetUserName")
            logon_type = _parse_logon_type(eventdata.get("logonType"))
            if target_user and is_admin(target_user) and logon_type in (2, 10):
                agent_upper = agent_name.upper()
                if "SERVER" not in agent_upper and "DC" not in agent_upper:
                    remember_admin(target_user)
                    separation_violations.append(
                        {
                            "name": "Violação de separação de contas",
                            "severity": "alto",
                            "explanation": (
                                f"A conta administrativa '{target_user}' fez logon "
                                f"({_LOGON_TYPE_LABELS.get(logon_type, str(logon_type))}) "
                                f"no agente '{agent_name}', que não aparenta ser um "
                                f"servidor nem um controlador de domínio (o nome do "
                                f"agente não contém 'SERVER' nem 'DC'). Contas "
                                f"administrativas não deveriam fazer logon interativo "
                                f"em estações de trabalho comuns."
                            ),
                        }
                    )

    # --- Deteção: conta administrativa sem atividade recente ---
    inactivity_detections: list[dict[str, Any]] = []
    for key, last_seen in last_seen_by_admin.items():
        display_name = admin_accounts_seen.get(key, key)
        age_days = (now - last_seen).days
        if age_days > reference_days:
            inactivity_detections.append(
                {
                    "name": "Conta administrativa sem atividade",
                    "severity": "medio",
                    "explanation": (
                        f"A conta administrativa '{display_name}' não tem eventos há "
                        f"{age_days} dias (último evento em {last_seen.isoformat()}), "
                        f"acima do limite configurado de {reference_days} dias. Esta "
                        f"deteção depende da janela temporal de alertas fornecida a "
                        f"esta função; se essa janela for mais curta do que "
                        f"{reference_days} dias, este resultado pode ser um falso "
                        f"positivo."
                    ),
                }
            )

    # --- Deteção: atividade fora de horário (agregada por conta) ---
    outside_hours_detections: list[dict[str, Any]] = [
        {
            "name": "Atividade fora de horário",
            "severity": "medio",
            "explanation": (
                f"A conta administrativa '{display_name}' tem pelo menos um evento "
                f"registado fora do horário laboral (antes das 08:00, depois das "
                f"20:00, ou ao fim de semana), considerando a hora do timestamp do "
                f"alerta tal como recebida, sem conversão de fuso horário local."
            ),
        }
        for display_name in outside_hours_accounts.values()
    ]

    detections: list[dict[str, Any]] = []
    detections.extend(separation_violations)
    detections.extend(inactivity_detections)
    detections.extend(outside_hours_detections)
    detections.extend(unexpected_privileges)

    return {
        "admin_accounts": sorted(admin_accounts_seen.values(), key=str.lower),
        "event_counts": event_counts,
        "special_privileges_by_user": special_privileges_by_user,
        "special_privileges_by_hour": special_privileges_by_hour,
        "scheduled_tasks": scheduled_tasks,
        "processes": processes,
        "detections": detections,
    }
