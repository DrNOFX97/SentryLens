"""
Testes de regressão do gerador de relatório HTML exportável (Fase 10).

Cobre dois aspetos:
1. `generate_html_report` (report_generator.py) isoladamente, sem FastAPI —
   caso completo, caso degradado (todas as fontes None) e, principalmente,
   escaping de XSS em texto dinâmico vindo do Wazuh (full_log, agent_name,
   rule_description) — mesma classe de vulnerabilidade já corrigida em
   app.js.
2. O endpoint `GET /api/export/report` (main.py) via TestClient, com
   WazuhIndexerClient/WazuhManagerClient mockados: sucesso, autenticação
   obrigatória, e resiliência a falha parcial de uma das 4 fontes.

Mesmo estilo dos outros ficheiros de teste standalone do projeto: função
check(label, condition), print [OK]/[FALHOU] por caso, sys.exit(1) no fim
se houver falhas.

Correr:
    python test_report_generator.py
"""

import os
import re
import sys
from datetime import datetime
from unittest.mock import AsyncMock

os.environ.setdefault("SENTRYLENS_API_KEY", "chave-de-teste-nao-usar-em-producao")

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


# --- Dados mock realistas (mesma forma dos endpoints reais — ver test_with_mock.py) ---

MOCK_STATS = {
    "window_hours": 24,
    "total_alerts": 9,
    "by_severity": {"high": 7, "info": 2},
    "by_category": {"autenticacao": 7, "ciclo_de_vida": 1, "geral": 1},
    "top_events": [
        {"event_id": 4625, "name": "Failed Logon", "count": 7},
        {"event_id": 4726, "name": "Account Deleted", "count": 1},
    ],
    "by_agent": {"WIN-PC01": 8, "WIN-PC02": 1},
}

MOCK_ALERTS = {
    "total": 2,
    "alerts": [
        {
            "timestamp": "2026-08-28T10:00:00Z",
            "agent_name": "WIN-PC01",
            "windows_event_id": 4625,
            "friendly_name": "Failed Logon",
            "severity": "high",
            "category": "autenticacao",
            "rule_description": "Multiple failed logons",
            "full_log": "Failed logon attempt for user admin",
            "recommendation": "Investigar tentativas de login falhadas.",
        },
        {
            "timestamp": "2026-08-28T12:00:00Z",
            "agent_name": "WIN-PC01",
            "windows_event_id": 4726,
            "friendly_name": "Account Deleted",
            "severity": "high",
            "category": "ciclo_de_vida",
            "rule_description": "Account deleted",
            "full_log": "User account deleted",
            "recommendation": "Confirmar se a eliminação foi autorizada.",
        },
    ],
}

MOCK_AGENTS = {
    "agents": [
        {
            "id": "001",
            "name": "WIN-PC01",
            "ip": "10.0.0.5",
            "status": "active",
            "os": "Windows 11",
            "last_keep_alive": "2026-08-28T13:00:00Z",
        },
        {
            "id": "002",
            "name": "WIN-PC02",
            "ip": "10.0.0.6",
            "status": "disconnected",
            "os": "Windows 10",
            "last_keep_alive": "2026-08-28T09:00:00Z",
        },
    ],
    "summary": {"connection": {"active": 1, "disconnected": 1, "never_connected": 0, "total": 2}},
}

MOCK_SYSTEM_SPECS = {
    "cpu": {
        "model": "Intel(R) Core(TM) i7",
        "physical_cores": 8,
        "logical_cores": 16,
        "frequency_mhz": 3600.0,
        "usage_percent": 12.5,
    },
    "ram": {"total_gb": 32.0, "used_gb": 10.2, "usage_percent": 31.9},
    "disk": [
        {"mountpoint": "C:\\", "total_gb": 512.0, "used_gb": 200.0, "usage_percent": 39.1},
    ],
    "network": {"hostname": "SENTRYLENS-PC", "ip": "10.0.0.10"},
    "network_speed": {"download_mbps": 300.0, "upload_mbps": 40.0},
    "timestamp": "2026-09-14T00:00:00Z",
}


def run_generator_tests() -> None:
    try:
        from report_generator import generate_html_report
    except ModuleNotFoundError as e:
        check(f"import report_generator falhou (ainda não está pronto?): {e}", False)
        return
    except ImportError as e:
        check(f"import generate_html_report de report_generator falhou: {e}", False)
        return

    common_kwargs = {
        "generated_at": "2026-09-14T00:00:00Z",
        "hours": 24,
    }

    # --- Caso completo ---
    try:
        html_completo = generate_html_report(
            stats=MOCK_STATS,
            alerts=MOCK_ALERTS,
            agents=MOCK_AGENTS,
            system_specs=MOCK_SYSTEM_SPECS,
            **common_kwargs,
        )
        gerou_sem_excecao = True
    except Exception as e:
        html_completo = ""
        gerou_sem_excecao = False
        print(f"        excecao no caso completo: {e}")
    check("Caso completo: generate_html_report não levanta exceção", gerou_sem_excecao)
    check("Caso completo: devolve string não vazia", isinstance(html_completo, str) and len(html_completo) > 0)
    check(
        "Caso completo: contém <!DOCTYPE html ou <html",
        ("<!DOCTYPE html" in html_completo) or ("<html" in html_completo.lower()),
    )
    check(
        "Caso completo: contém o total de alertas (9) dos stats mock",
        "9" in html_completo,
    )
    check(
        "Caso completo: contém pelo menos um nome de agente/evento dos dados mock",
        ("WIN-PC01" in html_completo) or ("Failed Logon" in html_completo),
    )

    # --- Caso degradado: todas as fontes None ---
    try:
        html_degradado = generate_html_report(
            stats=None,
            alerts=None,
            agents=None,
            system_specs=None,
            **common_kwargs,
        )
        gerou_degradado_sem_excecao = True
    except Exception as e:
        html_degradado = ""
        gerou_degradado_sem_excecao = False
        print(f"        excecao no caso degradado: {e}")
    check("Caso degradado: generate_html_report não levanta exceção com tudo None", gerou_degradado_sem_excecao)
    check(
        "Caso degradado: ainda devolve uma string HTML válida",
        isinstance(html_degradado, str)
        and (("<!DOCTYPE html" in html_degradado) or ("<html" in html_degradado.lower())),
    )
    check(
        "Caso degradado: indica indisponibilidade (ex: 'indispon', 'N/A', 'sem dados')",
        any(
            marcador in html_degradado.lower()
            for marcador in ("indispon", "n/a", "sem dados", "não disponível", "nao disponivel", "falhou")
        ),
    )

    # --- Segurança: escaping de XSS ---
    # Nota: report_generator._render_alerts() não inclui full_log na tabela
    # (só timestamp/agent_name/windows_event_id/friendly_name/severity/
    # rule_description) — por isso os 2 campos de texto livre vindo do
    # Wazuh testados aqui são agent_name e rule_description, que são os
    # que efetivamente aparecem no HTML gerado.
    alerta_malicioso_agent_name = {
        "timestamp": "2026-08-28T14:00:00Z",
        "agent_name": "<script>alert('xss')</script>",
        "windows_event_id": 4625,
        "friendly_name": "Failed Logon",
        "severity": "high",
        "category": "autenticacao",
        "rule_description": "Multiple failed logons",
        "full_log": "Failed logon attempt",
        "recommendation": "Investigar.",
    }
    alerta_malicioso_rule_description = {
        "timestamp": "2026-08-28T15:00:00Z",
        "agent_name": "WIN-PC01",
        "windows_event_id": 4625,
        "friendly_name": "Failed Logon",
        "severity": "high",
        "category": "autenticacao",
        "rule_description": '<img src=x onerror=alert(2)>',
        "full_log": "Failed logon attempt",
        "recommendation": "Investigar.",
    }
    alerts_maliciosos = {
        "total": 2,
        "alerts": [alerta_malicioso_agent_name, alerta_malicioso_rule_description],
    }

    try:
        html_xss = generate_html_report(
            stats=MOCK_STATS,
            alerts=alerts_maliciosos,
            agents=MOCK_AGENTS,
            system_specs=MOCK_SYSTEM_SPECS,
            **common_kwargs,
        )
        gerou_xss_sem_excecao = True
    except Exception as e:
        html_xss = ""
        gerou_xss_sem_excecao = False
        print(f"        excecao no caso XSS: {e}")
    check("Caso XSS: generate_html_report não levanta exceção", gerou_xss_sem_excecao)

    check(
        "XSS (agent_name): tag <script> literal NÃO aparece no HTML",
        "<script>alert('xss')</script>" not in html_xss,
    )
    check(
        "XSS (agent_name): versão escapada (&lt;script&gt;) está presente",
        "&lt;script&gt;" in html_xss,
    )
    check(
        "XSS (rule_description): <img src=x onerror=...> literal NÃO aparece no HTML",
        "<img src=x onerror=alert(2)>" not in html_xss,
    )
    check(
        "XSS (rule_description): versão escapada (&lt;img) está presente",
        "&lt;img" in html_xss,
    )

    # --- compliance_html vazio (default) não introduz lixo visível ---
    check(
        "compliance_html='' (default) não introduz 'None' visível no HTML",
        "None" not in html_completo,
    )

    # --- Truncagem de alertas em excesso (só testa se o gerador implementar) ---
    try:
        import inspect

        codigo_fonte = inspect.getsource(generate_html_report.__globals__.get("generate_html_report", generate_html_report))
    except Exception:
        codigo_fonte = ""

    import report_generator as _rg_module

    with open(_rg_module.__file__, "r", encoding="utf-8") as f:
        codigo_fonte_completo = f.read()

    implementa_truncagem = any(
        termo in codigo_fonte_completo.lower()
        for termo in (
            "truncad", "truncat", "[:max", "limite de alertas",
            "mais alertas não mostrados", "max_alerts_rows", "mais recentes de",
        )
    )
    if implementa_truncagem:
        total_gerado = 600
        muitos_alertas = {
            "total": total_gerado,
            "alerts": [
                {
                    "timestamp": f"2026-08-28T10:{i % 60:02d}:00Z",
                    "agent_name": "WIN-PC01",
                    "windows_event_id": 4625,
                    "friendly_name": "Failed Logon",
                    "severity": "high",
                    "category": "autenticacao",
                    "rule_description": f"Multiple failed logons #{i}",
                    "full_log": "Failed logon attempt",
                    "recommendation": "Investigar.",
                }
                for i in range(total_gerado)
            ],
        }
        html_muitos = generate_html_report(
            stats=MOCK_STATS,
            alerts=muitos_alertas,
            agents=MOCK_AGENTS,
            system_specs=MOCK_SYSTEM_SPECS,
            **common_kwargs,
        )
        linhas_de_alerta_mostradas = html_muitos.count("Multiple failed logons #")
        check(
            f"Truncagem: HTML com {total_gerado} alertas não lista todas as linhas ({linhas_de_alerta_mostradas} mostradas)",
            linhas_de_alerta_mostradas < total_gerado,
        )
    else:
        print("        (sem truncagem implementada em report_generator.py — teste não aplicável, ignorado)")


def run_endpoint_tests() -> None:
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

    main.indexer_client.get_recent_alerts = AsyncMock(return_value=[
        {
            "@timestamp": "2026-08-28T10:00:00Z",
            "agent": {"name": "WIN-PC01", "ip": "10.0.0.5"},
            "rule": {"id": "60122", "description": "Multiple failed logons", "level": 10},
            "data": {
                "win": {
                    "system": {"eventID": "4625"},
                    "eventdata": {"targetUserName": "admin"},
                }
            },
            "full_log": "Failed logon attempt",
        }
    ])
    main.manager_client.get_agents = AsyncMock(return_value=[
        {
            "id": "001", "name": "WIN-PC01", "ip": "10.0.0.5", "status": "active",
            "os": {"name": "Windows 11"}, "lastKeepAlive": "2026-08-28T13:00:00Z",
        }
    ])
    main.manager_client.get_agents_summary = AsyncMock(
        return_value={"connection": {"active": 1, "disconnected": 0, "never_connected": 0, "total": 1}}
    )

    client_autenticado = TestClient(main.app, headers={"X-API-Key": os.environ["SENTRYLENS_API_KEY"]})

    # --- Sucesso ---
    resp = client_autenticado.get("/api/export/report")
    check("GET /api/export/report (autenticado) devolve 200", resp.status_code == 200)
    content_type = resp.headers.get("content-type", "")
    check("Content-Type começa por text/html", content_type.startswith("text/html"))

    content_disposition = resp.headers.get("content-disposition", "")
    check("Content-Disposition contém 'attachment'", "attachment" in content_disposition)

    data_esperada = datetime.utcnow().strftime("%Y-%m-%d")
    nome_esperado_regex = re.compile(r"\d{4}-\d{2}-\d{2}-relatorio\.html")
    check(
        "Content-Disposition tem nome de ficheiro no formato AAAA-MM-DD-relatorio.html",
        bool(nome_esperado_regex.search(content_disposition)),
    )
    check(
        f"Content-Disposition usa a data de hoje UTC ({data_esperada})",
        data_esperada in content_disposition,
    )
    check(
        "Corpo da resposta contém <html ou <!DOCTYPE html",
        ("<html" in resp.text.lower()) or ("<!DOCTYPE html" in resp.text),
    )

    # --- Sem autenticação -> 401 ---
    client_sem_auth = TestClient(main.app)
    resp_sem_auth = client_sem_auth.get("/api/export/report")
    check("GET /api/export/report sem X-API-Key devolve 401", resp_sem_auth.status_code == 401)

    client_auth_errada = TestClient(main.app, headers={"X-API-Key": "chave-errada"})
    resp_auth_errada = client_auth_errada.get("/api/export/report")
    check("GET /api/export/report com X-API-Key errado devolve 401", resp_auth_errada.status_code == 401)

    # --- Falha parcial (Wazuh Manager em baixo) não derruba o endpoint ---
    main.manager_client.get_agents = AsyncMock(side_effect=Exception("Wazuh Manager em baixo"))
    resp_falha_parcial = client_autenticado.get("/api/export/report")
    check(
        "Falha só em get_agents: endpoint ainda devolve 200 (relatório parcial)",
        resp_falha_parcial.status_code == 200,
    )
    if resp_falha_parcial.status_code != 200:
        print(
            f"        ACHADO: falha parcial numa das 4 fontes propaga-se e devolve "
            f"{resp_falha_parcial.status_code} em vez de 200 — endpoint não isola as "
            f"falhas de cada fonte com try/except independente, como esperado pelo contrato."
        )

    # repõe o mock funcional para não afetar testes futuros (se este módulo for reimportado)
    main.manager_client.get_agents = AsyncMock(return_value=[
        {
            "id": "001", "name": "WIN-PC01", "ip": "10.0.0.5", "status": "active",
            "os": {"name": "Windows 11"}, "lastKeepAlive": "2026-08-28T13:00:00Z",
        }
    ])


def run() -> None:
    run_generator_tests()
    run_endpoint_tests()

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")
    sys.exit(0)


if __name__ == "__main__":
    run()
