"""
Catálogo de Event IDs críticos do Windows Security e respetivas recomendações.

Esta é a mesma lógica de classificação usada no log_analyzer_real.py (Fase 1),
agora reaproveitada aqui para que o dashboard fale a mesma linguagem em toda
a stack: análise de ficheiro estático (Fase 1) e análise ao vivo via Wazuh
(Fase 2) classificam os eventos exatamente da mesma forma. Cada evento inclui
agora também uma categoria, para permitir agrupar e filtrar alertas por tipo.
"""

CRITICAL_EVENTS: dict[int, dict[str, str]] = {
    4625: {"name": "Failed Logon", "severity": "high", "category": "autenticacao"},
    4672: {"name": "Special Privileges Assigned", "severity": "high", "category": "atividade_privilegiada"},
    4698: {"name": "Scheduled Task Created", "severity": "high", "category": "tarefas_agendadas"},
    4699: {"name": "Scheduled Task Deleted", "severity": "medium", "category": "tarefas_agendadas"},
    4700: {"name": "Scheduled Task Disabled", "severity": "low", "category": "tarefas_agendadas"},
    4701: {"name": "Scheduled Task Updated", "severity": "medium", "category": "tarefas_agendadas"},
    4702: {"name": "Scheduled Task Renamed", "severity": "low", "category": "tarefas_agendadas"},
    4703: {"name": "Scheduled Task Enabled", "severity": "low", "category": "tarefas_agendadas"},
    4704: {"name": "User Right Assigned", "severity": "high", "category": "politica_seguranca"},
    4720: {"name": "User Account Created", "severity": "medium", "category": "ciclo_de_vida"},
    4722: {"name": "User Account Enabled", "severity": "low", "category": "ciclo_de_vida"},
    4723: {"name": "Password Change Attempt", "severity": "low", "category": "ciclo_de_vida"},
    4724: {"name": "Password Reset Attempt", "severity": "medium", "category": "ciclo_de_vida"},
    4726: {"name": "User Account Deleted", "severity": "high", "category": "ciclo_de_vida"},
    4728: {"name": "Member Added to Global Group", "severity": "high", "category": "gestao_de_grupos"},
    4732: {"name": "Member Added to Local Group", "severity": "medium", "category": "gestao_de_grupos"},
    4756: {"name": "Member Added to Universal Group", "severity": "high", "category": "gestao_de_grupos"},
    4738: {"name": "User Account Changed", "severity": "medium", "category": "ciclo_de_vida"},
    4797: {"name": "Blank Password Query Attempt", "severity": "medium", "category": "autenticacao"},
    4713: {"name": "Kerberos Policy Changed", "severity": "high", "category": "politica_seguranca"},
    4719: {"name": "Security Policy Changed", "severity": "high", "category": "politica_seguranca"},
    5140: {"name": "Network Share Accessed", "severity": "low", "category": "acesso_rede"},
    5145: {"name": "Network Share Permission Checked", "severity": "low", "category": "acesso_rede"},
    4725: {"name": "User Account Disabled", "severity": "medium", "category": "ciclo_de_vida"},
    4729: {"name": "Member Removed from Global Group", "severity": "medium", "category": "gestao_de_grupos"},
    4733: {"name": "Member Removed from Local Group", "severity": "low", "category": "gestao_de_grupos"},
    4740: {"name": "User Account Locked Out", "severity": "medium", "category": "ciclo_de_vida"},
    4757: {"name": "Member Removed from Universal Group", "severity": "medium", "category": "gestao_de_grupos"},
    4767: {"name": "User Account Unlocked", "severity": "low", "category": "ciclo_de_vida"},
    4624: {"name": "Successful Logon", "severity": "low", "category": "autenticacao"},
    4688: {"name": "Process Created", "severity": "medium", "category": "atividade_privilegiada"},
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
    4797: "Investigar porque razão uma conta está a ser verificada quanto a password em branco. Pode indicar reconhecimento de contas mal configuradas.",
    4713: "CRÍTICO: alteração na política Kerberos. Investigar imediatamente.",
    4719: "CRÍTICO: alteração na política de segurança. Revisar e reverter se necessário.",
    5140: "Monitorar acesso a partilhas. Validar se é apropriado.",
    5145: "Análise de acesso. Considerar restrição se não autorizado.",
    4725: "Verificar se a desativação da conta foi autorizada. Investigar se coincide com atividade suspeita.",
    4729: "Auditar remoção do grupo. Validar se a perda de acesso foi intencional.",
    4733: "Verificar contexto da remoção. Confirmar se foi realizada por administrador legítimo.",
    4740: "Investigar causa do bloqueio. Pode indicar ataque de força bruta em curso.",
    4757: "Revisar remoção do grupo Universal. Verificar impacto nas permissões associadas.",
    4767: "Confirmar que o desbloqueio foi solicitado e autorizado pelo utilizador.",
    4624: "Atividade normal. Correlacionar com origem e horário para detetar anomalias.",
    4688: "Validar processo criado. Comparar com whitelist e investigar linha de comando suspeita.",
}


def classify_alert(win_event_id: int | None) -> dict[str, str]:
    """Devolve nome amigável, severidade, categoria e recomendação para um Event ID."""
    if win_event_id is None or win_event_id not in CRITICAL_EVENTS:
        return {
            "friendly_name": "Evento não catalogado",
            "severity": "info",
            "category": "geral",
            "recommendation": "Consultar documentação Wazuh para este rule.id.",
        }

    info = CRITICAL_EVENTS[win_event_id]
    return {
        "friendly_name": info["name"],
        "severity": info["severity"],
        "category": info.get("category", "geral"),
        "recommendation": RECOMMENDATIONS.get(win_event_id, "Investigar e tomar ação apropriada."),
    }
