"""
Testes de regressão do módulo de classificação NIS2 sugerida
(nis2_lookup.py) e do endpoint GET /api/nis2-lookup (main.py), sem
precisar do laboratório Wazuh real ligado.

Cobre:
1. `lookup_nis2_classification` isolada (importada direto de
   nis2_lookup.py, sem FastAPI): match de setor por CAE, prioridade do
   CAE principal sobre os secundários, critério de dimensão (limiares
   estritos), exceções conhecidas vs. desconhecidas, nota_final e fontes
   estáveis em todos os casos.
2. Endpoint GET /api/nis2-lookup via TestClient: sucesso, uso do CAE
   secundário, parâmetro obrigatório em falta e autenticação obrigatória.

Mesmo estilo dos outros ficheiros de teste standalone do projeto: função
check(label, condition), print [OK]/[FALHOU] por caso, sys.exit(1) no fim
se houver falhas.

Correr:
    python test_nis2_lookup.py
"""

import os
import sys

os.environ.setdefault("SENTRYLENS_API_KEY", "chave-de-teste-nao-usar-em-producao")

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def run_isolated_tests() -> None:
    try:
        from nis2_lookup import LIMIAR_COLABORADORES, LIMIAR_FATURACAO_EUR, lookup_nis2_classification
    except ModuleNotFoundError as e:
        check(f"import nis2_lookup falhou (ainda não está pronto?): {e}", False)
        return
    except ImportError as e:
        check(f"import de nis2_lookup falhou: {e}", False)
        return

    resultados_para_nota_final = []

    # --- Caso 1: setor conhecido ("62" -> Infraestrutura digital / TI) + dimensão que cumpre ---
    r1 = lookup_nis2_classification(cae_principal="6201", colaboradores=200)
    resultados_para_nota_final.append(r1)
    check("Caso 1: setor_sugerido não é None", r1["setor_sugerido"] is not None)
    check(
        "Caso 1: confianca_setor é uma string válida (alta/media/baixa)",
        r1["confianca_setor"] in ("alta", "media", "baixa"),
    )
    check("Caso 1: cumpre_criterio_dimensao == True", r1["cumpre_criterio_dimensao"] is True)
    check("Caso 1: aplicavel_sugerido == True", r1["aplicavel_sugerido"] is True)

    # --- Caso 2: CAE não mapeado (retalho, "47") ---
    r2 = lookup_nis2_classification(cae_principal="4711", colaboradores=10)
    resultados_para_nota_final.append(r2)
    check("Caso 2: setor_sugerido is None (CAE não mapeado)", r2["setor_sugerido"] is None)
    check("Caso 2: confianca_setor == 'nenhuma'", r2["confianca_setor"] == "nenhuma")
    check(
        "Caso 2: aplicavel_sugerido is None mesmo com dimensão conhecida (falta o setor)",
        r2["aplicavel_sugerido"] is None,
    )

    # --- Caso 3: exceção conhecida ignora dimensão em falta ---
    r3 = lookup_nis2_classification(cae_principal="6110", excecao_conhecida="telecomunicacoes")
    resultados_para_nota_final.append(r3)
    check("Caso 3: cumpre_criterio_dimensao == True (via exceção)", r3["cumpre_criterio_dimensao"] is True)
    check("Caso 3: excecao_aplicada == 'telecomunicacoes'", r3["excecao_aplicada"] == "telecomunicacoes")
    check("Caso 3: aplicavel_sugerido == True", r3["aplicavel_sugerido"] is True)

    # --- Caso 4: setor bate, dimensão não cumpre (ambos abaixo dos limiares) ---
    r4 = lookup_nis2_classification(cae_principal="3511", colaboradores=10, faturacao_eur=1_000_000)
    resultados_para_nota_final.append(r4)
    check("Caso 4: cumpre_criterio_dimensao == False", r4["cumpre_criterio_dimensao"] is False)
    check("Caso 4: aplicavel_sugerido == False", r4["aplicavel_sugerido"] is False)

    # --- Caso 5: dimensão desconhecida, sem exceção ---
    r5 = lookup_nis2_classification(cae_principal="6110")
    resultados_para_nota_final.append(r5)
    check("Caso 5: cumpre_criterio_dimensao is None", r5["cumpre_criterio_dimensao"] is None)
    check("Caso 5: aplicavel_sugerido is None", r5["aplicavel_sugerido"] is None)

    # --- Caso 6: cae_secundarios só é usado se cae_principal não bater ---
    r6 = lookup_nis2_classification(cae_principal="4711", cae_secundarios=["9999", "6401"])
    resultados_para_nota_final.append(r6)
    check(
        "Caso 6: setor_sugerido reflete o CAE secundário que bateu ('Banca', via '6401' -> '64')",
        r6["setor_sugerido"] == "Banca",
    )

    # --- Caso 7: exceção não reconhecida é ignorada sem rebentar ---
    r7 = lookup_nis2_classification(cae_principal="6110", excecao_conhecida="isto_nao_existe")
    resultados_para_nota_final.append(r7)
    check("Caso 7: excecao_aplicada is None (exceção não reconhecida)", r7["excecao_aplicada"] is None)

    # --- nota_final presente e idêntica em TODOS os casos acima ---
    nota_esperada = "Classificação sugerida, a confirmar junto do CNCS — não é aconselhamento jurídico."
    check(
        "nota_final é sempre a mesma string, em todos os casos",
        all(r.get("nota_final") == nota_esperada for r in resultados_para_nota_final),
    )

    # --- fontes é uma lista não vazia de strings, em todos os casos ---
    check(
        "fontes é uma lista não vazia de strings, em todos os casos",
        all(
            isinstance(r.get("fontes"), list)
            and len(r["fontes"]) > 0
            and all(isinstance(f, str) for f in r["fontes"])
            for r in resultados_para_nota_final
        ),
    )

    # --- Limiares exatos: > estrito, não >= ---
    r_limiar_colab = lookup_nis2_classification(cae_principal="3511", colaboradores=LIMIAR_COLABORADORES)
    check(
        "colaboradores == LIMIAR_COLABORADORES (exato) NÃO cumpre o critério (estritamente >)",
        r_limiar_colab["cumpre_criterio_dimensao"] is False,
    )
    r_limiar_fat = lookup_nis2_classification(cae_principal="3511", faturacao_eur=LIMIAR_FATURACAO_EUR)
    check(
        "faturacao_eur == LIMIAR_FATURACAO_EUR (exato) NÃO cumpre o critério (estritamente >)",
        r_limiar_fat["cumpre_criterio_dimensao"] is False,
    )


def run_endpoint_tests() -> None:
    try:
        import main
    except Exception as e:
        check(f"import main falhou: {e}", False)
        return

    if not hasattr(main.app, "routes") or not any(
        getattr(r, "path", None) == "/api/nis2-lookup" for r in main.app.routes
    ):
        check("Endpoint /api/nis2-lookup existe em main.py", False)
        return

    main.app.router.on_startup.clear()

    from fastapi.testclient import TestClient

    client_autenticado = TestClient(main.app, headers={"X-API-Key": os.environ["SENTRYLENS_API_KEY"]})
    client_sem_auth = TestClient(main.app)

    # --- Sucesso: setor conhecido + dimensão que cumpre ---
    resp = client_autenticado.get("/api/nis2-lookup", params={"cae_principal": "6201", "colaboradores": 200})
    check("GET /api/nis2-lookup (autenticado, caso simples) devolve 200", resp.status_code == 200)
    if resp.status_code == 200:
        body = resp.json()
        check("Corpo: setor_sugerido preenchido", body.get("setor_sugerido") is not None)
        check("Corpo: aplicavel_sugerido == true", body.get("aplicavel_sugerido") is True)

    # --- CAE secundário usado quando o principal não bate ---
    resp2 = client_autenticado.get(
        "/api/nis2-lookup",
        params={"cae_principal": "4711", "cae_secundarios": "9999,6401"},
    )
    check("GET /api/nis2-lookup (cae_secundarios) devolve 200", resp2.status_code == 200)
    if resp2.status_code == 200:
        body2 = resp2.json()
        check(
            "Corpo: setor_sugerido reflete o CAE secundário que bateu ('Banca')",
            body2.get("setor_sugerido") == "Banca",
        )

    # --- cae_principal em falta (obrigatório) ---
    resp3 = client_autenticado.get("/api/nis2-lookup")
    check(
        f"GET /api/nis2-lookup sem cae_principal devolve 422 (status real: {resp3.status_code})",
        resp3.status_code == 422,
    )

    # --- Sem autenticação -> 401 ---
    resp4 = client_sem_auth.get("/api/nis2-lookup", params={"cae_principal": "6201"})
    check("GET /api/nis2-lookup sem X-API-Key devolve 401", resp4.status_code == 401)


def run() -> None:
    print("--- 1. lookup_nis2_classification (nis2_lookup.py) ---")
    run_isolated_tests()
    print()
    print("--- 2. Endpoint GET /api/nis2-lookup (main.py) ---")
    run_endpoint_tests()

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")
    sys.exit(0)


if __name__ == "__main__":
    run()
