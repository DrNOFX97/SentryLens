"""
Perfil da organização usado pelo motor de conformidade
(compliance_evaluator.py). Fixo por agora — o CET não é uma empresa real,
por isso o perfil é hardcoded, não vem de nenhuma base de dados/formulário
externo. Lido sempre através de get_org_profile(), nunca do dict
diretamente, para poder ser substituído mais tarde (ex: por uma pesquisa
real de enquadramento NIS2 a partir do NIPC/CAE de uma empresa real) sem
tocar no motor de avaliação.
"""

_ORG_PROFILE = {
    "nome": "SentryLens (laboratório CET)",
    "estatuto_nis2_aplicavel": False,
    "processa_dados_pessoais": True,
    "tem_componentes_ia_ativos": True,
}


def get_org_profile() -> dict:
    """Devolve uma cópia do perfil (nunca a referência interna, para chamadores não conseguirem mutar o estado global por engano)."""
    return dict(_ORG_PROFILE)
