"""
Motor de avaliação de conformidade regulatória (RGPD, NIS2, AI Act) por
alerta. Módulo puro (mesmo padrão dos outros módulos de domínio do
projeto: lifecycle.py, rbac.py, admin_activity.py): recebe o alerta já
enriquecido (mesma forma de um item de /api/alerts — ver _enrich_alert em
main.py), o perfil da organização (get_org_profile()) e o catálogo de
regras (load_compliance_rules()) — nunca fala com o Wazuh nem decide
sozinho de onde vêm os dados, para poder ser testado com dicts fixos.

Cada norma devolve SEMPRE um veredito — nunca omite uma verificação em
silêncio, mesmo quando o resultado é "verificado_e_nao_aplicavel".
"""

import os

import yaml

_RULES_PATH = os.path.join(os.path.dirname(__file__), "compliance_rules.yaml")


def load_compliance_rules(path: str = _RULES_PATH) -> dict:
    """Carrega o catálogo de regras do YAML. path é parametrizável só para facilitar testes com um YAML alternativo."""
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def evaluate_alert_compliance(alert: dict, org_profile: dict, rules: dict) -> dict:
    """
    Devolve {"rgpd": {...}, "nis2": {...}, "ai_act": {...}}, cada valor
    {"estado": "aplicavel" | "verificado_e_nao_aplicavel", "justificacao": str}.
    """
    category = alert.get("category")
    severity = alert.get("severity")

    # RGPD — aplicável se a categoria do alerta envolve identidade/utilizadores
    if category in rules["rgpd"]["categorias_aplicaveis"]:
        rgpd = {"estado": "aplicavel", "justificacao": rules["rgpd"]["justificacao_aplicavel"]}
    else:
        rgpd = {"estado": "verificado_e_nao_aplicavel", "justificacao": rules["rgpd"]["justificacao_nao_aplicavel"]}

    # NIS2 — depende do estatuto da entidade E da severidade do alerta (classificação agregada de incidente)
    if not org_profile.get("estatuto_nis2_aplicavel"):
        nis2 = {
            "estado": "verificado_e_nao_aplicavel",
            "justificacao": rules["nis2"]["justificacao_nao_aplicavel_estatuto"],
        }
    elif severity in rules["nis2"]["severidades_incidente_significativo"]:
        nis2 = {"estado": "aplicavel", "justificacao": rules["nis2"]["justificacao_aplicavel"]}
    else:
        nis2 = {
            "estado": "verificado_e_nao_aplicavel",
            "justificacao": rules["nis2"]["justificacao_nao_aplicavel_severidade"],
        }

    # AI Act — depende só do perfil (a organização opera ou não um sistema de IA)
    if org_profile.get("tem_componentes_ia_ativos"):
        ai_act = {"estado": "aplicavel", "justificacao": rules["ai_act"]["justificacao_aplicavel"]}
    else:
        ai_act = {"estado": "verificado_e_nao_aplicavel", "justificacao": rules["ai_act"]["justificacao_nao_aplicavel"]}

    return {"rgpd": rgpd, "nis2": nis2, "ai_act": ai_act}
