"""
Testes de regressao dos 3 paineis novos da Fase 2 (lifecycle, privileges,
admin-activity), sem precisar do laboratorio Wazuh real ligado. Mocka a
resposta de WazuhIndexerClient.get_recent_alerts e valida, atraves dos
endpoints reais /api/lifecycle e /api/privileges, e da funcao pura
build_admin_activity_report, as 4 deteccoes de risco de cada painel mais o
caso vazio (sem alertas) nos 3 endpoints.

Mesmo estilo de teste do ficheiro irmao test_with_mock.py: TestClient(main.app),
main.app.router.on_startup.clear() para nao arrancar o loop de monitorizacao
de sistema, AsyncMock para mockar o cliente do Wazuh Indexer, e a funcao
check(label, condition) que acumula falhas e faz sys.exit(1) no fim se houver
alguma.

Correr:
    python test_new_panels.py
"""

import sys
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock

from fastapi.testclient import TestClient

import main
from admin_activity import build_admin_activity_report

# Desliga o startup event (loop de monitorizacao de sistema da Fase 2) - estes
# testes validam so os paineis de lifecycle/privileges/admin-activity, nao
# devem tocar em psutil/speedtest nem escrever no system_alerts_history.json
# real.
main.app.router.on_startup.clear()

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def _alert(
    timestamp: str,
    event_id: int,
    eventdata: dict[str, str] | None = None,
    agent_name: str = "WIN-PC01",
    rule_id: str = "60000",
    level: int = 8,
) -> dict[str, Any]:
    """Constroi um alerta mock no formato devolvido pelo Wazuh Indexer (ver
    test_with_mock.py para a forma exata), parametrizado pelos campos que
    cada deteccao dos 3 paineis novos realmente le.
    """
    return {
        "@timestamp": timestamp,
        "agent": {"name": agent_name, "ip": "10.0.0.9"},
        "rule": {"id": rule_id, "description": f"Windows event {event_id}", "level": level},
        "data": {"win": {"system": {"eventID": str(event_id)}, "eventdata": eventdata or {}}},
        "full_log": f"Mock event {event_id}",
    }


# ---------------------------------------------------------------------------
# Cenario 2: painel Lifecycle - uma ocorrencia de cada uma das 4 deteccoes
# de lifecycle.py. Cada deteccao usa um utilizador proprio para nao haver
# contaminacao cruzada entre deteccoes (ex: o utilizador da "conta
# descartavel" nao aparece em mais nenhum outro evento).
# ---------------------------------------------------------------------------
LIFECYCLE_ALERTS: list[dict[str, Any]] = [
    # Offboarding falhado: conta desativada (4725) e depois faz login com
    # sucesso (4624) apos a desativacao.
    _alert("2026-08-01T10:00:00Z", 4725, {"targetUserName": "offboard.user"}),
    _alert("2026-08-02T10:00:00Z", 4624, {"targetUserName": "offboard.user"}),
    # Conta descartavel: criada (4720) e eliminada (4726) com menos de 24h
    # de diferenca.
    _alert("2026-08-03T09:00:00Z", 4720, {"targetUserName": "discard.user"}),
    _alert("2026-08-03T15:00:00Z", 4726, {"targetUserName": "discard.user"}),
    # Criacao fora de horario: conta criada as 02:00 (antes das 08:00).
    _alert("2026-08-04T02:00:00Z", 4720, {"targetUserName": "offhours.user"}),
    # Criacao com escalada imediata: conta criada e, no mesmo dia, adicionada
    # ao grupo critico "Domain Admins".
    _alert("2026-08-05T09:00:00Z", 4720, {"targetUserName": "escalate.user"}),
    _alert(
        "2026-08-05T11:00:00Z",
        4728,
        {
            "targetUserName": "escalate.user",
            "subjectUserName": "admin.it",
            "memberName": "CN=Domain Admins,CN=Users,DC=exemplo,DC=local",
        },
    ),
]

# ---------------------------------------------------------------------------
# Cenario 3: painel Privileges. O endpoint /api/privileges chama
# build_privileges_report(raw_alerts, baseline) SEM user_to_cargo (ver
# main.py), pelo que, dentro deste endpoint, TODOS os utilizadores caem em
# "cargo desconhecido" e TODAS as adicoes geram sempre desvio com a razao
# "cargo desconhecido no baseline" - independentemente do grupo a que sao
# adicionados corresponder ou nao aos grupos_permitidos de um cargo real do
# rbac_baseline.example.json. Por isso as 3 adicoes abaixo (uma a um grupo
# fora dos permitidos de um cargo real, uma a um grupo critico, e uma a um
# grupo qualquer para um utilizador sem cargo mapeavel) geram, todas elas,
# a mesma razao de desvio quando passam pelo endpoint. A adicao ao grupo
# critico entra tambem em critical_additions, independentemente do desvio.
# Inclui-se ainda uma remocao, que conta para total_movements e para o
# ranking de grupos mas nunca gera desvio.
# ---------------------------------------------------------------------------
PRIVILEGES_ALERTS: list[dict[str, Any]] = [
    # Adicao a um grupo fora dos grupos_permitidos do cargo real "Tecnico de
    # Suporte" (que so permite GG-IT-Suporte e DL-Partilha-IT-Leitura).
    _alert(
        "2026-08-10T09:00:00Z",
        4732,
        {
            "targetUserName": "tech.support",
            "subjectUserName": "admin.rh",
            "memberName": "CN=GG-RH-Confidencial,OU=Grupos,DC=nortada,DC=local",
        },
    ),
    # Adicao a um grupo critico (Domain Admins).
    _alert(
        "2026-08-11T09:00:00Z",
        4728,
        {
            "targetUserName": "sysadmin.new",
            "subjectUserName": "admin.it",
            "memberName": "CN=Domain Admins,CN=Users,DC=nortada,DC=local",
        },
    ),
    # Adicao de um utilizador que nao ha como mapear a nenhum cargo.
    _alert(
        "2026-08-12T09:00:00Z",
        4756,
        {
            "targetUserName": "ghost.user",
            "subjectUserName": "admin.it",
            "memberName": "CN=GG-Random-Group,OU=Grupos,DC=nortada,DC=local",
        },
    ),
    # Remocao: conta para total_movements e group_ranking, nunca e desvio.
    _alert(
        "2026-08-13T09:00:00Z",
        4733,
        {
            "targetUserName": "old.tech",
            "subjectUserName": "admin.it",
            "memberName": "CN=GG-IT-Suporte,OU=Grupos,DC=nortada,DC=local",
        },
    ),
]

# ---------------------------------------------------------------------------
# Cenario 4: painel Admin Activity - uma ocorrencia de cada uma das 4
# deteccoes de admin_activity.py. A deteccao "Conta administrativa sem
# atividade" depende do instante de referencia `now`: em vez de passar pelo
# endpoint /api/admin-activity (onde `now` seria sempre datetime.now()),
# chama-se build_admin_activity_report diretamente com um `now` fixo, para o
# teste ser deterministico e nao depender da data em que corre.
# ---------------------------------------------------------------------------
ADMIN_ACTIVITY_NOW = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)

ADMIN_ACTIVITY_ALERTS: list[dict[str, Any]] = [
    # Violacao de separacao de contas: conta "adm." faz logon interativo
    # local (logonType 2) numa maquina cujo nome nao contem "SERVER" nem "DC".
    _alert(
        "2026-08-31T10:00:00Z",
        4624,
        {"targetUserName": "adm.violation", "logonType": "2"},
        agent_name="WORKSTATION07",
    ),
    # Conta administrativa sem atividade: ultimo evento muito antigo face a
    # ADMIN_ACTIVITY_NOW (mais de reference_days=60 dias de diferenca).
    _alert("2026-01-01T09:00:00Z", 4672, {"subjectUserName": "adm.inactive"}),
    # Atividade fora de horario: processo criado as 03:00 (antes das 08:00).
    _alert(
        "2026-08-30T03:00:00Z",
        4688,
        {"subjectUserName": "adm.offhours"},
    ),
    # Privilegio inesperado: utilizador sem prefixo "adm." e sem adesao a
    # grupo critico observada recebe privilegios especiais (evento 4672).
    _alert("2026-08-30T10:00:00Z", 4672, {"subjectUserName": "regular.user"}),
]


def run() -> None:
    client = TestClient(main.app)

    # --- 1. Caso vazio nos 3 endpoints ---
    main.indexer_client.get_recent_alerts = AsyncMock(return_value=[])

    resp_lifecycle_empty = client.get("/api/lifecycle")
    check("GET /api/lifecycle (vazio) devolve 200", resp_lifecycle_empty.status_code == 200)
    lifecycle_empty = resp_lifecycle_empty.json()
    check(
        "Lifecycle vazio tem counts todos a zero, sem timeline/events/detections",
        lifecycle_empty["counts"] == {"created": 0, "activated": 0, "disabled": 0, "deleted": 0, "locked": 0}
        and lifecycle_empty["timeline"] == []
        and lifecycle_empty["events"] == []
        and lifecycle_empty["detections"] == [],
    )

    resp_privileges_empty = client.get("/api/privileges")
    check("GET /api/privileges (vazio) devolve 200", resp_privileges_empty.status_code == 200)
    privileges_empty = resp_privileges_empty.json()
    check(
        "Privileges vazio nao tem movimentos, desvios, adicoes criticas nem ranking",
        privileges_empty["total_movements"] == 0
        and privileges_empty["deviations"] == []
        and privileges_empty["critical_additions"] == []
        and privileges_empty["group_ranking"] == [],
    )

    resp_admin_empty = client.get("/api/admin-activity")
    check("GET /api/admin-activity (vazio) devolve 200", resp_admin_empty.status_code == 200)
    admin_empty = resp_admin_empty.json()
    check(
        "Admin Activity vazio nao tem contas admin, tarefas, processos nem deteccoes",
        admin_empty["admin_accounts"] == []
        and admin_empty["event_counts"] == {"admin": 0, "normal": 0}
        and admin_empty["special_privileges_by_user"] == {}
        and admin_empty["scheduled_tasks"] == []
        and admin_empty["processes"] == []
        and admin_empty["detections"] == [],
    )
    check(
        "Admin Activity vazio tem distribuicao horaria com as 24 horas a zero",
        admin_empty["special_privileges_by_hour"] == {str(h): 0 for h in range(24)},
    )

    # --- 2. Painel Lifecycle: uma ocorrencia de cada deteccao ---
    main.indexer_client.get_recent_alerts = AsyncMock(return_value=LIFECYCLE_ALERTS)

    resp_lifecycle = client.get("/api/lifecycle")
    check("GET /api/lifecycle devolve 200", resp_lifecycle.status_code == 200)
    lifecycle = resp_lifecycle.json()
    lifecycle_names = {d["name"] for d in lifecycle["detections"]}
    check(
        "Lifecycle deteta 'Offboarding falhado'",
        "Offboarding falhado" in lifecycle_names,
    )
    check(
        "Lifecycle deteta 'Conta descartavel'",
        "Conta descartável" in lifecycle_names,
    )
    check(
        "Lifecycle deteta 'Criacao fora de horario'",
        "Criação fora de horário" in lifecycle_names,
    )
    check(
        "Lifecycle deteta 'Criacao com escalada imediata'",
        "Criação com escalada imediata" in lifecycle_names,
    )

    # --- 3. Painel Privileges: desvio, grupo critico e cargo desconhecido ---
    main.indexer_client.get_recent_alerts = AsyncMock(return_value=PRIVILEGES_ALERTS)

    resp_privileges = client.get("/api/privileges")
    check("GET /api/privileges devolve 200", resp_privileges.status_code == 200)
    privileges = resp_privileges.json()

    check(
        "Privileges conta as 4 movimentacoes (3 adicoes + 1 remocao)",
        privileges["total_movements"] == 4,
    )
    check(
        "Privileges gera exatamente 3 desvios (so as adicoes contam)",
        len(privileges["deviations"]) == 3,
    )
    check(
        "Todos os desvios tem a razao 'cargo desconhecido no baseline' "
        "(o endpoint nao passa user_to_cargo a build_privileges_report)",
        all(d["reason"] == "cargo desconhecido no baseline" for d in privileges["deviations"]),
    )
    check(
        "Privileges regista a adicao ao grupo critico 'Domain Admins' em critical_additions",
        any(c["group"] == "Domain Admins" and c["user"] == "sysadmin.new" for c in privileges["critical_additions"]),
    )
    check(
        "Privileges tem group_ranking com as 4 movimentacoes",
        sum(g["count"] for g in privileges["group_ranking"]) == 4,
    )

    # --- 4. Painel Admin Activity: uma ocorrencia de cada deteccao ---
    # Chamada direta a funcao pura (ver comentario acima de ADMIN_ACTIVITY_NOW),
    # sem passar pelo endpoint, para fixar `now` de forma deterministica.
    admin_activity = build_admin_activity_report(
        ADMIN_ACTIVITY_ALERTS, admin_prefix="adm.", now=ADMIN_ACTIVITY_NOW
    )
    admin_names = {d["name"] for d in admin_activity["detections"]}
    check(
        "Admin Activity deteta 'Violacao de separacao de contas'",
        "Violação de separação de contas" in admin_names,
    )
    check(
        "Admin Activity deteta 'Conta administrativa sem atividade'",
        "Conta administrativa sem atividade" in admin_names,
    )
    check(
        "Admin Activity deteta 'Atividade fora de horario'",
        "Atividade fora de horário" in admin_names,
    )
    check(
        "Admin Activity deteta 'Privilegio inesperado'",
        "Privilégio inesperado" in admin_names,
    )

    print()
    if failures:
        print(f"❌ {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("✅ Todos os testes passaram")
    sys.exit(0)


if __name__ == "__main__":
    run()
