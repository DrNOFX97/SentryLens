"""
Classificação NIS2 sugerida a partir de dados JÁ CONHECIDOS de uma empresa
(CAE, colaboradores, faturação) — NÃO faz pesquisa automática em sites
externos (Racius, informacaoempresarial.pt); isso fica documentado como
passo manual (ver README), decisão consciente para não construir um
scraper frágil e não-verificável contra sites de terceiros.

LIMITAÇÃO DE CONHECIMENTO (não jurídica): o Decreto-Lei n.º 125/2025
(transposição nacional da NIS2 em Portugal, em vigor desde 2026-04-03)
entrou em vigor depois do conhecimento treinado deste código. O
mapeamento setor→CAE abaixo usa as categorias de setor da Diretiva (UE)
2022/2555 (NIS2), conhecimento estável e anterior a essa data, cruzadas
com prefixos de 2 dígitos (divisão) da CAE-Rev.3 portuguesa como
aproximação de boa-fé — NÃO é uma transcrição do diploma nacional. Por
isso esta função NUNCA devolve um veredito definitivo, só indícios com
grau de confiança, terminando sempre com a mesma nota: "classificação
sugerida, a confirmar junto do CNCS — não é aconselhamento jurídico".
"""

LIMIAR_COLABORADORES = 50
LIMIAR_FATURACAO_EUR = 10_000_000

# Prefixos de divisão (2 dígitos) da CAE-Rev.3 -> setor NIS2 aproximado.
# "confianca": "alta" (divisão mapeia de forma quase inequívoca a um único
# setor NIS2), "media" (divisão ampla/ambígua, cobre vários subsectores só
# alguns dos quais NIS2), "baixa" (setor adjacente, relação indireta).
_CAE_SETOR_NIS2 = {
    "35": {"setor": "Energia", "categoria": "essencial", "confianca": "alta"},
    "36": {"setor": "Água potável", "categoria": "essencial", "confianca": "alta"},
    "37": {"setor": "Águas residuais", "categoria": "essencial", "confianca": "alta"},
    "38": {"setor": "Gestão de resíduos", "categoria": "importante", "confianca": "media"},
    "49": {"setor": "Transportes (terrestre)", "categoria": "essencial", "confianca": "alta"},
    "50": {"setor": "Transportes (marítimo/fluvial)", "categoria": "essencial", "confianca": "alta"},
    "51": {"setor": "Transportes (aéreo)", "categoria": "essencial", "confianca": "alta"},
    "52": {"setor": "Transportes (armazenagem/apoio)", "categoria": "essencial", "confianca": "media"},
    "53": {"setor": "Serviços postais e de courier", "categoria": "importante", "confianca": "alta"},
    "61": {"setor": "Infraestrutura digital (telecomunicações)", "categoria": "essencial", "confianca": "alta"},
    "62": {"setor": "Infraestrutura digital / prestador de serviços digitais (programação/consultoria informática)", "categoria": "essencial", "confianca": "media"},
    "63": {"setor": "Infraestrutura digital (processamento de dados, alojamento, portais web)", "categoria": "essencial", "confianca": "media"},
    "64": {"setor": "Banca", "categoria": "essencial", "confianca": "alta"},
    "65": {"setor": "Seguros e fundos de pensões (adjacente a infraestruturas do mercado financeiro)", "categoria": "essencial", "confianca": "baixa"},
    "66": {"setor": "Atividades auxiliares de serviços financeiros e de seguros", "categoria": "essencial", "confianca": "baixa"},
    "84": {"setor": "Administração pública", "categoria": "essencial", "confianca": "media"},
    "86": {"setor": "Saúde humana", "categoria": "essencial", "confianca": "alta"},
    "72": {"setor": "Investigação científica", "categoria": "importante", "confianca": "media"},
}

# Exceções que se aplicam independentemente da dimensão (ver auditoria/
# callout já documentado no Notion do projeto).
_EXCECOES_CONHECIDAS = {
    "fornecedor_confianca_qualificado",
    "registo_dominio",
    "telecomunicacoes",
    "administracao_publica",
}


def _match_cae_sector(cae: str | None) -> dict | None:
    if not cae:
        return None
    prefixo = cae.strip()[:2]
    return _CAE_SETOR_NIS2.get(prefixo)


def _cumpre_criterio_dimensao(colaboradores: int | None, faturacao_eur: float | None) -> bool | None:
    """None = dados insuficientes para decidir; não assume nada na ausência de dados."""
    if colaboradores is None and faturacao_eur is None:
        return None
    excede_colaboradores = colaboradores is not None and colaboradores > LIMIAR_COLABORADORES
    excede_faturacao = faturacao_eur is not None and faturacao_eur > LIMIAR_FATURACAO_EUR
    return excede_colaboradores or excede_faturacao


def lookup_nis2_classification(
    *,
    nipc: str | None = None,
    cae_principal: str,
    cae_secundarios: list[str] | None = None,
    colaboradores: int | None = None,
    faturacao_eur: float | None = None,
    excecao_conhecida: str | None = None,
) -> dict:
    """
    Devolve indícios de classificação NIS2 para uma empresa, a partir de
    dados já conhecidos (não faz nenhuma pesquisa online). NUNCA um
    veredito definitivo — sempre com grau de confiança e a nota final.

    excecao_conhecida (opcional): uma de _EXCECOES_CONHECIDAS — se
    fornecida, a entidade é tratada como sujeita à NIS2 independentemente
    da dimensão (colaboradores/faturação), conforme as exceções já
    documentadas para o critério de dimensão. Um valor não reconhecido é
    ignorado (fica None no resultado, com uma nota a dizer que não foi
    reconhecido), não levanta exceção.
    """
    setor_info = _match_cae_sector(cae_principal)
    if setor_info is None:
        for cae in (cae_secundarios or []):
            setor_info = _match_cae_sector(cae)
            if setor_info:
                break

    excecao_valida = excecao_conhecida if excecao_conhecida in _EXCECOES_CONHECIDAS else None
    excecao_nao_reconhecida = bool(excecao_conhecida) and excecao_conhecida not in _EXCECOES_CONHECIDAS

    if excecao_valida:
        cumpre_dimensao = True
    else:
        cumpre_dimensao = _cumpre_criterio_dimensao(colaboradores, faturacao_eur)

    aplicavel_sugerido = None
    if setor_info is not None and cumpre_dimensao is not None:
        aplicavel_sugerido = cumpre_dimensao

    justificacao_partes = []
    if setor_info:
        justificacao_partes.append(
            f"CAE indica setor '{setor_info['setor']}' (categoria {setor_info['categoria']}, confiança {setor_info['confianca']})."
        )
    else:
        justificacao_partes.append("Nenhum CAE fornecido corresponde a um setor NIS2 conhecido nesta aproximação.")
    if excecao_valida:
        justificacao_partes.append(f"Exceção conhecida aplicada ('{excecao_valida}') — aplica-se independentemente da dimensão.")
    elif excecao_nao_reconhecida:
        justificacao_partes.append(f"Exceção '{excecao_conhecida}' não reconhecida nesta versão — ignorada.")
    elif cumpre_dimensao is None:
        justificacao_partes.append("Dados de dimensão insuficientes (colaboradores/faturação) para avaliar o critério de dimensão.")
    else:
        justificacao_partes.append(
            f"Critério de dimensão {'cumprido' if cumpre_dimensao else 'não cumprido'} (> {LIMIAR_COLABORADORES} colaboradores ou > {LIMIAR_FATURACAO_EUR:,.0f} EUR de faturação)."
        )

    return {
        "nipc": nipc,
        "cae_consultado": cae_principal,
        "setor_sugerido": setor_info["setor"] if setor_info else None,
        "categoria_sugerida": setor_info["categoria"] if setor_info else None,
        "confianca_setor": setor_info["confianca"] if setor_info else "nenhuma",
        "cumpre_criterio_dimensao": cumpre_dimensao,
        "excecao_aplicada": excecao_valida,
        "aplicavel_sugerido": aplicavel_sugerido,
        "justificacao": " ".join(justificacao_partes),
        "fontes": [
            "Diretiva (UE) 2022/2555 (NIS2) — categorias de setor, Anexos I e II",
            "CAE-Rev.3 (Classificação Portuguesa de Atividades Económicas)",
        ],
        "nota_final": "Classificação sugerida, a confirmar junto do CNCS — não é aconselhamento jurídico.",
    }
