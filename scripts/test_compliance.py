"""
Testes de regressão da camada de conformidade regulatória (Fase 7 — RGPD,
NIS2, AI Act), sem precisar do laboratório Wazuh real ligado.

Cobre:
1. `evaluate_alert_compliance` (compliance_evaluator.py) isoladamente, com
   `load_compliance_rules()` real (o YAML de regras não é mockado).
2. `get_org_profile()` (org_profile.py) — devolve sempre uma cópia.
3. `append_compliance_history` (history_store.py) — escreve o JSONL de
   auditoria de conformidade.
4. Endpoint `GET /api/compliance` (main.py) via TestClient, com
   WazuhIndexerClient mockado: sucesso, agregação do summary e
   autenticação obrigatória.
5. `render_compliance_section` (report_generator.py) — HTML com KPIs e
   escaping de XSS.
6. Endpoint `GET /api/export/report` — confirma que a secção de
   conformidade está integrada no relatório exportado.

Mesmo estilo dos outros ficheiros de teste standalone do projeto: função
check(label, condition), print [OK]/[FALHOU] por caso, sys.exit(1) no fim
se houver falhas.

Correr:
    python test_compliance.py
"""

import json
import os
import sys
import tempfile
from unittest.mock import AsyncMock

os.environ.setdefault("SENTRYLENS_API_KEY", "chave-de-teste-nao-usar-em-producao")

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


# --- Dados mock realistas (mesmo formato cru do Wazuh usado em test_with_mock.py) ---

MOCK_ALERTS_RAW = [
    # evento 4625 (Failed Logon) -> categoria autenticacao, severidade high
    {
        "@timestamp": "2026-09-14T10:00:00Z",
        "agent": {"name": "WIN-PC01", "ip": "10.0.0.5"},
        "rule": {"id": "60122", "description": "Multiple failed logons", "level": 10},
        "data": {
            "win": {
                "system": {"eventID": "4625"},
                "eventdata": {"targetUserName": "admin"},
            }
        },
        "full_log": "Failed logon attempt for user admin",
    },
    # evento não catalogado -> categoria geral, severidade info (baixa, não critical/high)
    {
        "@timestamp": "2026-09-14T11:00:00Z",
        "agent": {"name": "WIN-PC01", "ip": "10.0.0.5"},
        "rule": {"id": "1001", "description": "Generic event", "level": 3},
        "data": {"win": {"system": {"eventID": "9999"}}},
        "full_log": "Some generic event",
    },
]


def run_evaluator_tests() -> None:
    try:
        from compliance_evaluator import evaluate_alert_compliance, load_compliance_rules
    except ModuleNotFoundError as e:
        check(f"import compliance_evaluator falhou (ainda não está pronto?): {e}", False)
        return
    except ImportError as e:
        check(f"import de compliance_evaluator falhou: {e}", False)
        return

    try:
        rules = load_compliance_rules()
        rules_carregadas = True
    except Exception as e:
        rules = {}
        rules_carregadas = False
        print(f"        excecao ao carregar compliance_rules.yaml: {e}")
    check("load_compliance_rules() carrega o YAML sem exceção", rules_carregadas)
    if not rules_carregadas:
        return
    check(
        "compliance_rules.yaml tem as 3 chaves esperadas (rgpd/nis2/ai_act)",
        all(chave in rules for chave in ("rgpd", "nis2", "ai_act")),
    )

    alerta_autenticacao_high = {"category": "autenticacao", "severity": "high"}
    alerta_acesso_rede_low = {"category": "acesso_rede", "severity": "low"}

    perfil_nis2_ia_ativos = {
        "nome": "Org Teste",
        "estatuto_nis2_aplicavel": True,
        "processa_dados_pessoais": True,
        "tem_componentes_ia_ativos": True,
    }
    perfil_sem_nis2_sem_ia = {
        "nome": "Org Teste",
        "estatuto_nis2_aplicavel": False,
        "processa_dados_pessoais": True,
        "tem_componentes_ia_ativos": False,
    }

    # --- Caso 1: autenticacao/high, perfil com NIS2 + IA ativos -> tudo aplicavel ---
    resultado_1 = evaluate_alert_compliance(alerta_autenticacao_high, perfil_nis2_ia_ativos, rules)
    check(
        "Caso 1: RGPD aplicavel (categoria autenticacao)",
        resultado_1["rgpd"]["estado"] == "aplicavel",
    )
    check(
        "Caso 1: NIS2 aplicavel (estatuto NIS2=True + severity=high)",
        resultado_1["nis2"]["estado"] == "aplicavel",
    )
    check(
        "Caso 1: AI Act aplicavel (tem_componentes_ia_ativos=True)",
        resultado_1["ai_act"]["estado"] == "aplicavel",
    )

    # --- Caso 2: acesso_rede/low, mesmo perfil -> RGPD e NIS2 não aplicáveis, AI Act aplicavel ---
    resultado_2 = evaluate_alert_compliance(alerta_acesso_rede_low, perfil_nis2_ia_ativos, rules)
    check(
        "Caso 2: RGPD verificado_e_nao_aplicavel (categoria acesso_rede não está na lista)",
        resultado_2["rgpd"]["estado"] == "verificado_e_nao_aplicavel",
    )
    check(
        "Caso 2: NIS2 verificado_e_nao_aplicavel (severity=low, abaixo do limiar)",
        resultado_2["nis2"]["estado"] == "verificado_e_nao_aplicavel",
    )
    check(
        "Caso 2: AI Act continua aplicavel (depende só do perfil, não do alerta)",
        resultado_2["ai_act"]["estado"] == "aplicavel",
    )

    # --- Caso 3: autenticacao/high, mas perfil sem NIS2 e sem IA -> RGPD aplicavel, resto não ---
    resultado_3 = evaluate_alert_compliance(alerta_autenticacao_high, perfil_sem_nis2_sem_ia, rules)
    check(
        "Caso 3: RGPD continua aplicavel (só depende da categoria do alerta)",
        resultado_3["rgpd"]["estado"] == "aplicavel",
    )
    check(
        "Caso 3: NIS2 verificado_e_nao_aplicavel (estatuto_nis2_aplicavel=False no perfil)",
        resultado_3["nis2"]["estado"] == "verificado_e_nao_aplicavel",
    )
    check(
        "Caso 3: AI Act verificado_e_nao_aplicavel (tem_componentes_ia_ativos=False no perfil)",
        resultado_3["ai_act"]["estado"] == "verificado_e_nao_aplicavel",
    )

    # --- Justificação nunca fica em branco, em nenhum dos 3 casos ---
    for i, resultado in enumerate((resultado_1, resultado_2, resultado_3), start=1):
        for norma in ("rgpd", "nis2", "ai_act"):
            justificacao = resultado[norma].get("justificacao")
            check(
                f"Caso {i}: justificacao de {norma} é uma string não vazia",
                isinstance(justificacao, str) and len(justificacao.strip()) > 0,
            )


def run_org_profile_tests() -> None:
    try:
        from org_profile import get_org_profile
    except ModuleNotFoundError as e:
        check(f"import org_profile falhou (ainda não está pronto?): {e}", False)
        return
    except ImportError as e:
        check(f"import get_org_profile de org_profile falhou: {e}", False)
        return

    perfil = get_org_profile()
    check(
        "get_org_profile() devolve um dict com as 4 chaves esperadas",
        isinstance(perfil, dict)
        and all(
            chave in perfil
            for chave in (
                "nome",
                "estatuto_nis2_aplicavel",
                "processa_dados_pessoais",
                "tem_componentes_ia_ativos",
            )
        ),
    )

    valores_originais = dict(perfil)

    # Muta o dict devolvido -> não deve afetar chamadas futuras (é uma cópia)
    perfil["nome"] = "NOME MUTADO PARA TESTE"
    perfil["estatuto_nis2_aplicavel"] = not perfil["estatuto_nis2_aplicavel"]
    perfil["tem_componentes_ia_ativos"] = not perfil["tem_componentes_ia_ativos"]

    perfil_novo = get_org_profile()
    check(
        "get_org_profile() devolve uma CÓPIA — mutar o dict devolvido não afeta chamadas futuras",
        perfil_novo == valores_originais,
    )
    check(
        "get_org_profile() confirma perfil fixo: estatuto_nis2_aplicavel=False",
        perfil_novo["estatuto_nis2_aplicavel"] is False,
    )
    check(
        "get_org_profile() confirma perfil fixo: tem_componentes_ia_ativos=True",
        perfil_novo["tem_componentes_ia_ativos"] is True,
    )


def run_history_store_tests() -> None:
    try:
        from history_store import append_compliance_history, history_file_path
    except ModuleNotFoundError as e:
        check(f"import history_store falhou (ainda não está pronto?): {e}", False)
        return
    except ImportError as e:
        check(f"import append_compliance_history/history_file_path de history_store falhou: {e}", False)
        return

    tmp_dir = tempfile.mkdtemp()

    alerta_mock = {"timestamp": "2026-09-14T10:00:00Z", "windows_event_id": 4625}
    compliance_result_mock = {
        "rgpd": {"estado": "aplicavel", "justificacao": "j1"},
        "nis2": {"estado": "verificado_e_nao_aplicavel", "justificacao": "j2"},
        "ai_act": {"estado": "aplicavel", "justificacao": "j3"},
    }

    try:
        append_compliance_history(alerta_mock, compliance_result_mock, tmp_dir)
        gravou_sem_excecao = True
    except Exception as e:
        gravou_sem_excecao = False
        print(f"        excecao em append_compliance_history: {e}")
    check("append_compliance_history não levanta exceção", gravou_sem_excecao)
    if not gravou_sem_excecao:
        return

    path_esperado = history_file_path(tmp_dir, "2026-09-14", "compliance")
    check("Ficheiro compliance.jsonl foi criado no path esperado", os.path.isfile(path_esperado))
    if not os.path.isfile(path_esperado):
        return

    with open(path_esperado, "r", encoding="utf-8") as f:
        linhas = [linha for linha in f.read().splitlines() if linha.strip()]

    check("Ficheiro tem exatamente 1 linha", len(linhas) == 1)
    if not linhas:
        return

    linha = linhas[0]
    check("Linha começa com a chave 'date' (primeiro campo do objeto)", linha.startswith('{"date"'))

    try:
        registo = json.loads(linha)
        parseou_json = True
    except json.JSONDecodeError as e:
        registo = {}
        parseou_json = False
        print(f"        excecao ao fazer parse da linha JSONL: {e}")
    check("Linha é JSON válido", parseou_json)
    if not parseou_json:
        return

    check("event_id gravado corretamente (4625)", registo.get("event_id") == 4625)
    check("rgpd_estado gravado corretamente", registo.get("rgpd_estado") == "aplicavel")
    check("nis2_estado gravado corretamente", registo.get("nis2_estado") == "verificado_e_nao_aplicavel")
    check("ai_act_estado gravado corretamente", registo.get("ai_act_estado") == "aplicavel")


def run_endpoint_tests() -> None:
    try:
        import main
    except Exception as e:
        check(f"import main falhou: {e}", False)
        return

    if not hasattr(main.app, "routes") or not any(
        getattr(r, "path", None) == "/api/compliance" for r in main.app.routes
    ):
        check("Endpoint /api/compliance existe em main.py", False)
        return

    main.app.router.on_startup.clear()

    from fastapi.testclient import TestClient

    main.indexer_client.get_recent_alerts = AsyncMock(return_value=MOCK_ALERTS_RAW)

    client_autenticado = TestClient(main.app, headers={"X-API-Key": os.environ["SENTRYLENS_API_KEY"]})

    resp = client_autenticado.get("/api/compliance")
    check("GET /api/compliance (autenticado) devolve 200", resp.status_code == 200)
    if resp.status_code != 200:
        return

    body = resp.json()
    check("total bate com o nº de alertas mockados (2)", body.get("total") == len(MOCK_ALERTS_RAW))
    check("org_profile está presente na resposta", isinstance(body.get("org_profile"), dict))

    summary = body.get("summary", {})
    check(
        "summary tem as 3 normas (rgpd/nis2/ai_act)",
        all(norma in summary for norma in ("rgpd", "nis2", "ai_act")),
    )
    for norma in ("rgpd", "nis2", "ai_act"):
        contagens = summary.get(norma, {})
        soma = contagens.get("aplicavel", 0) + contagens.get("verificado_e_nao_aplicavel", 0)
        check(
            f"summary[{norma}] soma ao total de alertas ({len(MOCK_ALERTS_RAW)})",
            soma == len(MOCK_ALERTS_RAW),
        )

    alerts_resp = body.get("alerts", [])
    check("alerts tem o mesmo nº de itens que o total", len(alerts_resp) == len(MOCK_ALERTS_RAW))
    check(
        "cada item de alerts tem uma chave 'compliance' com as 3 normas",
        len(alerts_resp) > 0
        and all(
            "compliance" in item
            and all(norma in item["compliance"] for norma in ("rgpd", "nis2", "ai_act"))
            for item in alerts_resp
        ),
    )

    # --- Sem autenticação -> 401 ---
    client_sem_auth = TestClient(main.app)
    resp_sem_auth = client_sem_auth.get("/api/compliance")
    check("GET /api/compliance sem X-API-Key devolve 401", resp_sem_auth.status_code == 401)


def run_report_generator_tests() -> None:
    try:
        from report_generator import render_compliance_section
    except ModuleNotFoundError as e:
        check(f"import render_compliance_section falhou (ainda não está pronto - depende do MT2?): {e}", False)
        return
    except ImportError as e:
        check(f"import render_compliance_section de report_generator falhou: {e}", False)
        return

    org_profile_mock = {
        "nome": "SentryLens (laboratório CET)",
        "estatuto_nis2_aplicavel": False,
        "processa_dados_pessoais": True,
        "tem_componentes_ia_ativos": True,
    }

    alerta_normal = {
        "timestamp": "2026-09-14T10:00:00Z",
        "friendly_name": "Failed Logon",
    }
    veredito_normal = {
        "rgpd": {"estado": "aplicavel", "justificacao": "j1"},
        "nis2": {"estado": "verificado_e_nao_aplicavel", "justificacao": "j2"},
        "ai_act": {"estado": "aplicavel", "justificacao": "j3"},
    }

    alerta_malicioso = {
        "timestamp": "2026-09-14T11:00:00Z",
        "friendly_name": "<script>alert(1)</script>",
    }
    veredito_malicioso = {
        "rgpd": {"estado": "aplicavel", "justificacao": "j1"},
        "nis2": {"estado": "aplicavel", "justificacao": "j2"},
        "ai_act": {"estado": "verificado_e_nao_aplicavel", "justificacao": "j3"},
    }

    compliance_results = [(alerta_normal, veredito_normal), (alerta_malicioso, veredito_malicioso)]

    try:
        html = render_compliance_section(compliance_results, org_profile_mock)
        gerou_sem_excecao = True
    except Exception as e:
        html = ""
        gerou_sem_excecao = False
        print(f"        excecao em render_compliance_section: {e}")
    check("render_compliance_section não levanta exceção", gerou_sem_excecao)
    check("render_compliance_section devolve string não vazia", isinstance(html, str) and len(html) > 0)
    check("HTML contém o rótulo 'aplicavel'", "aplicavel" in html)
    check("HTML contém o rótulo 'verificado_e_nao_aplicavel'", "verificado_e_nao_aplicavel" in html)

    check(
        "XSS (friendly_name): tag <script> literal NÃO aparece no HTML",
        "<script>alert(1)</script>" not in html,
    )
    check(
        "XSS (friendly_name): versão escapada (&lt;script&gt;) está presente",
        "&lt;script&gt;" in html,
    )

    # --- XSS via org_profile["nome"] (achado da ronda 1 de revisão AAA:
    # só friendly_name estava coberto, mas o nome da organização também é
    # texto dinâmico embutido no HTML via _esc()) ---
    org_profile_malicioso = {
        **org_profile_mock,
        "nome": "<script>alert(2)</script>",
    }
    try:
        html_org_malicioso = render_compliance_section(
            [(alerta_normal, veredito_normal)], org_profile_malicioso
        )
        gerou_org_sem_excecao = True
    except Exception as e:
        html_org_malicioso = ""
        gerou_org_sem_excecao = False
        print(f"        excecao em render_compliance_section com nome malicioso: {e}")
    check("render_compliance_section com org_profile malicioso não levanta exceção", gerou_org_sem_excecao)
    check(
        "XSS (org_profile.nome): tag <script> literal NÃO aparece no HTML",
        "<script>alert(2)</script>" not in html_org_malicioso,
    )
    check(
        "XSS (org_profile.nome): versão escapada (&lt;script&gt;) está presente",
        "&lt;script&gt;alert(2)&lt;/script&gt;" in html_org_malicioso,
    )

    # --- Lista vazia não deve levantar exceção ---
    try:
        html_vazio = render_compliance_section([], org_profile_mock)
        gerou_vazio_sem_excecao = True
    except Exception as e:
        html_vazio = ""
        gerou_vazio_sem_excecao = False
        print(f"        excecao em render_compliance_section com lista vazia: {e}")
    check("render_compliance_section([], ...) não levanta exceção", gerou_vazio_sem_excecao)
    check("render_compliance_section([], ...) devolve string não vazia", isinstance(html_vazio, str) and len(html_vazio) > 0)


def run_export_report_integration_tests() -> None:
    try:
        import main
    except Exception as e:
        check(f"import main falhou: {e}", False)
        return

    if not hasattr(main.app, "routes") or not any(
        getattr(r, "path", None) == "/api/export/report" for r in main.app.routes
    ):
        check("Endpoint /api/export/report existe em main.py", False)
        return

    main.app.router.on_startup.clear()

    from fastapi.testclient import TestClient

    main.indexer_client.get_recent_alerts = AsyncMock(return_value=MOCK_ALERTS_RAW)
    main.manager_client.get_agents = AsyncMock(return_value=[
        {
            "id": "001", "name": "WIN-PC01", "ip": "10.0.0.5", "status": "active",
            "os": {"name": "Windows 11"}, "lastKeepAlive": "2026-09-14T13:00:00Z",
        }
    ])
    main.manager_client.get_agents_summary = AsyncMock(
        return_value={"connection": {"active": 1, "disconnected": 0, "never_connected": 0, "total": 1}}
    )

    client_autenticado = TestClient(main.app, headers={"X-API-Key": os.environ["SENTRYLENS_API_KEY"]})
    resp = client_autenticado.get("/api/export/report")
    check("GET /api/export/report (autenticado) devolve 200", resp.status_code == 200)
    if resp.status_code != 200:
        return

    texto = resp.text.lower()
    check(
        "Relatório exportado menciona conformidade/RGPD/NIS2 nalgum sítio (secção de conformidade integrada)",
        any(termo in texto for termo in ("conformidade", "rgpd", "nis2", "ai act", "ai_act")),
    )


def run() -> None:
    print("--- 1. evaluate_alert_compliance (compliance_evaluator.py) ---")
    run_evaluator_tests()
    print()
    print("--- 2. get_org_profile (org_profile.py) ---")
    run_org_profile_tests()
    print()
    print("--- 3. append_compliance_history (history_store.py) ---")
    run_history_store_tests()
    print()
    print("--- 4. Endpoint GET /api/compliance (main.py) ---")
    run_endpoint_tests()
    print()
    print("--- 5. render_compliance_section (report_generator.py) [depende do MT2] ---")
    run_report_generator_tests()
    print()
    print("--- 6. Integração GET /api/export/report [depende do MT2] ---")
    run_export_report_integration_tests()

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")
    sys.exit(0)


if __name__ == "__main__":
    run()
