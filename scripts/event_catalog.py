"""
Catálogo de Event IDs críticos do Windows Security e respetivas recomendações.

Esta é a mesma lógica de classificação usada no log_analyzer_real.py (Fase 1),
agora reaproveitada aqui para que o dashboard fale a mesma linguagem em toda
a stack: análise de ficheiro estático (Fase 1) e análise ao vivo via Wazuh
(Fase 2) classificam os eventos exatamente da mesma forma.
"""

CRITICAL_EVENTS: dict[int, dict[str, str]] = {
    4625: {"name": "Failed Logon", "severity": "high"},
    4672: {"name": "Special Privileges Assigned", "severity": "high"},
    4698: {"name": "Scheduled Task Created", "severity": "high"},
    4699: {"name": "Scheduled Task Deleted", "severity": "medium"},
    4700: {"name": "Scheduled Task Disabled", "severity": "low"},
    4701: {"name": "Scheduled Task Updated", "severity": "medium"},
    4702: {"name": "Scheduled Task Renamed", "severity": "low"},
    4703: {"name": "Scheduled Task Enabled", "severity": "low"},
    4704: {"name": "User Right Assigned", "severity": "high"},
    4720: {"name": "User Account Created", "severity": "medium"},
    4722: {"name": "User Account Enabled", "severity": "low"},
    4723: {"name": "Password Change Attempt", "severity": "low"},
    4724: {"name": "Password Reset Attempt", "severity": "medium"},
    4726: {"name": "User Account Deleted", "severity": "high"},
    4728: {"name": "Member Added to Global Group", "severity": "high"},
    4732: {"name": "Member Added to Local Group", "severity": "medium"},
    4756: {"name": "Member Added to Universal Group", "severity": "high"},
    4738: {"name": "User Account Changed", "severity": "medium"},
    4797: {"name": "User Account Locked Out", "severity": "medium"},
    4713: {"name": "Kerberos Policy Changed", "severity": "high"},
    4719: {"name": "Security Policy Changed", "severity": "high"},
    5140: {"name": "Network Share Accessed", "severity": "low"},
    5145: {"name": "Network Share Permission Checked", "severity": "low"},
}

RECOMMENDATIONS: dict[int, str] = {
    4625: "Implementar bloqueio de conta após N falhas. Investigar origem dos IPs. Considerar MFA.",
    4672: "Verificar legitimidade. Auditar todas as ações do utilizador com privilégios especiais.",
    4698: "Validar criador da tarefa. Verificar conteúdo. Comparar com whitelist.",
    4699: "Verificar se era uma tarefa crítica. Investigar quem a eliminou.",
    4700: "Revisar se desativação foi autorizada.",
    4701: "Auditoria de mudanças. Verificar se conteúdo da tarefa é suspeito.",
    4720: "Validar criação de conta. Verificar propósito. Monitorar atividade inicial.",
    4722: "Verificar se reativação foi autorizada.",
    4723: "Atividade normal. Monitorar padrões de mudanças forçadas.",
    4724: "Investigar contexto. Validar se foi alteração autorizada.",
    4726: "CRÍTICO: investigar imediatamente. Verificar se foi intencional.",
    4728: "Validar adição ao grupo Domain Admins. Revisar autorização.",
    4732: "Auditar adição a grupo. Validar escalada de privilégios.",
    4756: "Revisar adição a grupo Universal. Verificar impacto de segurança.",
    4738: "Auditar mudanças na conta. Verificar configurações de segurança.",
    4797: "Bloquear conta suspeita. Investigar tentativas de logon.",
    4713: "CRÍTICO: alteração na política Kerberos. Investigar imediatamente.",
    4719: "CRÍTICO: alteração na política de segurança. Revisar e reverter se necessário.",
    5140: "Monitorar acesso a partilhas. Validar se é apropriado.",
    5145: "Análise de acesso. Considerar restrição se não autorizado.",
}


def classify_alert(win_event_id: int | None) -> dict[str, str]:
    """Devolve nome amigável, severidade e recomendação para um Event ID."""
    if win_event_id is None or win_event_id not in CRITICAL_EVENTS:
        return {
            "friendly_name": "Evento não catalogado",
            "severity": "info",
            "recommendation": "Consultar documentação Wazuh para este rule.id.",
        }

    info = CRITICAL_EVENTS[win_event_id]
    return {
        "friendly_name": info["name"],
        "severity": info["severity"],
        "recommendation": RECOMMENDATIONS.get(win_event_id, "Investigar e tomar ação apropriada."),
    }
