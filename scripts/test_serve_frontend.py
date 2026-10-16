"""
Testes do servidor estático do frontend (serve_frontend.py), em especial do
/config.js que entrega a API key ao dashboard.

Sobe um HTTPServer real numa porta efémera (127.0.0.1) e fala com ele via
http.client, porque os casos interessantes dependem de cabeçalhos que o
browser define (Host, Sec-Fetch-Site) e que um cliente de alto nível
tenderia a esconder. Nunca toca no scripts/.env real: ENV_PATH aponta para
um ficheiro temporário.

Segue o estilo de test_with_mock.py: standalone, check()/[OK]/[FALHOU],
sys.exit(1) em caso de falha.

Correr:
    python test_serve_frontend.py
"""

import http.client
import os
import re
import sys
import tempfile
import threading
from http.server import HTTPServer
from pathlib import Path

import serve_frontend

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def get(port: int, path: str, headers: dict | None = None) -> tuple[int, dict, str]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    # putheader manual para controlar Host (http.client põe o seu por omissão).
    conn.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
    sent = dict(headers or {})
    sent.setdefault("Host", f"127.0.0.1:{port}")
    for name, value in sent.items():
        conn.putheader(name, value)
    conn.endheaders()
    resp = conn.getresponse()
    body = resp.read().decode("utf-8", errors="replace")
    result = (resp.status, {k.lower(): v for k, v in resp.getheaders()}, body)
    conn.close()
    return result


def run() -> None:
    os.environ.pop(serve_frontend.API_KEY_VAR, None)
    tmp = tempfile.TemporaryDirectory()
    env_file = Path(tmp.name) / ".env"
    env_file.write_text('OUTRA=1\nSENTRYLENS_API_KEY="abc\\"123"\n', encoding="utf-8")
    serve_frontend.ENV_PATH = env_file

    server = HTTPServer(("127.0.0.1", 0), serve_frontend.FrontendHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    try:
        # --- load_api_key / build_config_js (funções puras) ---
        env_file.write_text("SENTRYLENS_API_KEY=chave-do-env\n", encoding="utf-8")
        check("load_api_key lê o .env", serve_frontend.load_api_key() == "chave-do-env")
        os.environ[serve_frontend.API_KEY_VAR] = "chave-da-variavel"
        check("variável de ambiente tem prioridade sobre o .env",
              serve_frontend.load_api_key() == "chave-da-variavel")
        del os.environ[serve_frontend.API_KEY_VAR]
        env_file.write_text("OUTRA=1\n", encoding="utf-8")
        check("sem chave em lado nenhum -> string vazia (não falha)", serve_frontend.load_api_key() == "")
        env_file.unlink()
        check("sem .env -> string vazia (não falha)", serve_frontend.load_api_key() == "")
        js = serve_frontend.build_config_js('a"b\\c</script>').decode("utf-8")
        check("build_config_js escapa aspas/barras via JSON",
              js == 'window.SENTRYLENS_CONFIG = { apiKey: "a\\"b\\\\c</script>" };\n')

        # --- /config.js via HTTP ---
        env_file.write_text("SENTRYLENS_API_KEY=k-123\n", encoding="utf-8")
        status, headers, body = get(port, "/config.js", {"Sec-Fetch-Site": "same-origin"})
        check("/config.js same-origin -> 200 com a chave do .env", status == 200 and 'apiKey: "k-123"' in body)
        check("/config.js é JavaScript", headers.get("content-type", "").startswith("application/javascript"))
        check("/config.js tem Cache-Control: no-store", headers.get("cache-control") == "no-store")
        check("/config.js tem X-Content-Type-Options: nosniff", headers.get("x-content-type-options") == "nosniff")

        # Fail-closed: sem Sec-Fetch-Site (browser antigo / curl) só passa com Referer do mesmo origin.
        status, _, body = get(port, "/config.js")
        check("/config.js sem Sec-Fetch-Site nem Referer -> 403 sem a chave", status == 403 and "k-123" not in body)
        status, _, body = get(port, "/config.js", {"Referer": f"http://127.0.0.1:{port}/index.html"})
        check("/config.js sem Sec-Fetch-Site, Referer do mesmo origin -> 200", status == 200 and "k-123" in body)
        status, _, body = get(port, "/config.js", {"Referer": "https://evil.example.com/page"})
        check("/config.js sem Sec-Fetch-Site, Referer de outro site -> 403", status == 403 and "k-123" not in body)
        status, _, body = get(port, "/config.js", {"Referer": f"http://127.0.0.1:{port + 1}/"})
        check("/config.js sem Sec-Fetch-Site, Referer de outra porta local -> 403", status == 403 and "k-123" not in body)
        status, _, body = get(port, "/config.js", {"Sec-Fetch-Site": "cross-site", "Referer": f"http://127.0.0.1:{port}/"})
        check("Sec-Fetch-Site cross-site prevalece sobre um Referer same-origin -> 403", status == 403)

        for site in ("cross-site", "same-site", "none"):
            status, _, body = get(port, "/config.js", {"Sec-Fetch-Site": site})
            check(f"/config.js com Sec-Fetch-Site={site} -> 403 sem a chave", status == 403 and "k-123" not in body)

        # --- Host (DNS rebinding) ---
        status, _, body = get(port, "/config.js", {"Host": "evil.example.com", "Sec-Fetch-Site": "same-origin"})
        check("Host não-loopback -> 421 sem a chave", status == 421 and "k-123" not in body)
        status, _, _ = get(port, "/index.html", {"Host": "evil.example.com"})
        check("Host não-loopback também recusa ficheiros estáticos", status == 421)
        status, _, _ = get(port, "/config.js", {"Host": f"localhost:{port}", "Sec-Fetch-Site": "same-origin"})
        check("Host localhost:porta é aceite", status == 200)

        # --- whitelist continua intacta ---
        status, _, _ = get(port, "/index.html")
        check("/index.html continua a ser servido", status == 200)
        status, headers, _ = get(port, "/incidents.js")
        check("/incidents.js é servido como JavaScript", status == 200 and headers.get("content-type", "").startswith("application/javascript"))
        status, headers, _ = get(port, "/live_soc.js")
        check("/live_soc.js é servido como JavaScript", status == 200 and headers.get("content-type", "").startswith("application/javascript"))
        status, headers, _ = get(port, "/attack_registry.js")
        check("/attack_registry.js é servido como JavaScript", status == 200 and headers.get("content-type", "").startswith("application/javascript"))
        status, headers, _ = get(port, "/attack_library.js")
        check("/attack_library.js é servido como JavaScript", status == 200 and headers.get("content-type", "").startswith("application/javascript"))
        status, headers, _ = get(port, "/ui_helpers.js")
        check("/ui_helpers.js é servido como JavaScript", status == 200 and headers.get("content-type", "").startswith("application/javascript"))
        status, headers, _ = get(port, "/router.js")
        check("/router.js é servido como JavaScript", status == 200 and headers.get("content-type", "").startswith("application/javascript"))

        status, headers, _ = get(port, "/api.js")
        check("/api.js é servido como JavaScript", status == 200 and headers.get("content-type", "").startswith("application/javascript"))
        status, headers, _ = get(port, "/state.js")
        check("/state.js é servido como JavaScript", status == 200 and headers.get("content-type", "").startswith("application/javascript"))
        status, headers, _ = get(port, "/network_soc.js")
        check("/network_soc.js é servido como JavaScript", status == 200 and headers.get("content-type", "").startswith("application/javascript"))
        status, headers, _ = get(port, "/detections.js")
        check("/detections.js é servido como JavaScript", status == 200 and headers.get("content-type", "").startswith("application/javascript"))
        status, headers, _ = get(port, "/metrics.js")
        check("/metrics.js é servido como JavaScript", status == 200 and headers.get("content-type", "").startswith("application/javascript"))
        status, headers, _ = get(port, "/ml_models.js")
        check("/ml_models.js é servido como JavaScript", status == 200 and headers.get("content-type", "").startswith("application/javascript"))
        status, headers, _ = get(port, "/ml_evaluation.js")
        check("/ml_evaluation.js é servido como JavaScript", status == 200 and headers.get("content-type", "").startswith("application/javascript"))
        status, headers, _ = get(port, "/vaccines.js")
        check("/vaccines.js é servido como JavaScript", status == 200 and headers.get("content-type", "").startswith("application/javascript"))
        status, headers, _ = get(port, "/soc_team.js")
        check("/soc_team.js é servido como JavaScript", status == 200 and headers.get("content-type", "").startswith("application/javascript"))
        status, headers, _ = get(port, "/overview.js")
        check("/overview.js é servido como JavaScript", status == 200 and headers.get("content-type", "").startswith("application/javascript"))
        status, headers, _ = get(port, "/vendor/chart.umd.min.js")
        check("/vendor/chart.umd.min.js é servido como JavaScript", status == 200 and headers.get("content-type", "").startswith("application/javascript"))
        for fonte in ("inter-latin", "jetbrains-mono-latin", "space-grotesk-latin"):
            status, headers, _ = get(port, f"/vendor/fonts/{fonte}.woff2")
            check(f"/vendor/fonts/{fonte}.woff2 é servido como font/woff2", status == 200 and headers.get("content-type") == "font/woff2")
        status, _, _ = get(port, "/vendor/")
        check("/vendor/ (listagem) dá 404", status == 404)
        status, _, _ = get(port, "/vendor/fonts/../../scripts/.env")
        check("travessia a partir de /vendor/ dá 404", status == 404)
        status, _, _ = get(port, "/scripts/.env")
        check("/scripts/.env continua a dar 404", status == 404)
        status, _, _ = get(port, "/.env")
        check("/.env continua a dar 404", status == 404)
        status, _, _ = get(port, "/config.js?x=1")
        check("/config.js com query string não é uma rota (404)", status == 404)
    finally:
        server.shutdown()
        server.server_close()
        tmp.cleanup()


def check_static_frontend() -> None:
    """
    Protege a sidebar e a forma de ml_models.js/ml_evaluation.js contra
    regressões que o servidor não apanha: se alguém voltar a pôr
    data-planned="R9" num botão, reintroduzir um nome global colidente, ou
    tirar um código de erro da tabela PT, a aba fica em branco sem nenhum
    teste vermelho.
    """
    index_html = (serve_frontend.PROJECT_ROOT / "index.html").read_text(encoding="utf-8")
    ml_models_js = (serve_frontend.PROJECT_ROOT / "ml_models.js").read_text(encoding="utf-8")
    ml_evaluation_js = (serve_frontend.PROJECT_ROOT / "ml_evaluation.js").read_text(encoding="utf-8")

    for marker in ('data-tab="ml-models"', 'data-tab="ml-evaluation"',
                   'id="tab-ml-models"', 'id="tab-ml-evaluation"',
                   '<script src="ml_models.js"></script>',
                   '<script src="ml_evaluation.js"></script>'):
        check(f"index.html contém {marker}", marker in index_html)

    # D-09: a Evaluation só funciona se ml_evaluation.js carregar DEPOIS de
    # ml_models.js — é lá que estão mlmErrorText e mlmCodeFromResponse.
    check("index.html carrega ml_evaluation.js depois de ml_models.js",
          index_html.index('<script src="ml_evaluation.js"></script>')
          > index_html.index('<script src="ml_models.js"></script>'))

    # A tabela de Evaluation tem de ter as SEIS colunas que o helper desenha
    # (colspan="6" nas linhas de estado vazio, de aviso e de "Sem avaliação").
    thead = re.search(r'<table id="mlm-eval-table">.*?</thead>', index_html, re.S)
    check("a tabela de Evaluation tem seis <th>",
          bool(thead) and len(re.findall(r"<th>", thead.group(0))) == 6)
    check('o corpo da tabela de Evaluation usa colspan="6"',
          '<td colspan="6" class="empty-state">A carregar...</td>' in index_html)
    check('o cabeçalho da tabela de Evaluation declara as seis colunas',
          bool(thead) and all(coluna in thead.group(0) for coluna in (
              ">Versão<", ">Ativa<", ">Dataset<", ">Origem<", ">ML (", ">Regras (")))

    # O bloco de concordância ao vivo (D-10): select de janela, aviso e corpo.
    for marker in ('id="mle-live-block"', 'id="mle-live-hours"',
                   'id="mle-live-notice"', 'id="mle-live-body"',
                   'for="mle-live-hours"'):
        check(f"index.html contém {marker}", marker in index_html)
    check("o select da janela só oferece janelas dentro do ge=1/le=168 da rota",
          all(f'value="{h}"' in index_html for h in (1, 24, 72, 168)))
    check("o botão de recarregar da Evaluation continua a ser mlm-eval-reload",
          'id="mlm-eval-reload"' in index_html)
    # O bloco ao vivo fica DENTRO do mesmo section da tabela: um section novo
    # duplicaria o banner do renderPanelError por cima do bloco.
    painel = re.search(r'<section class="panel" id="ml-evaluation-panel">(.*?)</section>',
                       index_html, re.S)
    check("o bloco ao vivo está dentro do mesmo painel da tabela",
          bool(painel) and 'id="mle-live-body"' in painel.group(1)
          and 'id="mlm-eval-table"' in painel.group(1))

    check("index.html já não tem nenhum marcador de planeado R9", 'data-planned="R9"' not in index_html)

    for tab in ("ml-models", "ml-evaluation"):
        linhas = [l for l in index_html.splitlines() if f'data-tab="{tab}"' in l]
        check(f"o botão {tab} deixou de ser planeado",
              bool(linhas) and not any("is-planned" in l for l in linhas))

    linhas_training = [l for l in index_html.splitlines() if 'data-label="Training"' in l]
    check("o botão Training foi removido do sidebar (treino está em 📦 Models, D-07)",
          not linhas_training)

    declaracoes = re.findall(
        r"^(?:const|let|var|class|function|async function)\s+([A-Za-z_$][\w$]*)",
        ml_models_js, re.M)
    colisoes = [n for n in declaracoes if not n.startswith(("mlm", "MLM_"))]
    check("todos os identificadores de topo de ml_models.js têm prefixo mlm/MLM_", not colisoes)
    if colisoes:
        print(f"       nomes sem prefixo: {colisoes}")

    # D-09: os dois ficheiros partilham um só escopo global no browser, por
    # isso nenhum identificador de topo de ml_evaluation.js pode repetir um de
    # ml_models.js (ou de app.js) — a colisão partiria o browser inteiro.
    declaracoes_mle = re.findall(
        r"^(?:const|let|var|class|function|async function)\s+([A-Za-z_$][\w$]*)",
        ml_evaluation_js, re.M)
    sem_prefixo = [n for n in declaracoes_mle if not n.startswith(("mle", "MLE_"))]
    check("todos os identificadores de topo de ml_evaluation.js têm prefixo mle/MLE_",
          not sem_prefixo)
    if sem_prefixo:
        print(f"       nomes sem prefixo: {sem_prefixo}")

    reutilizados = {"MLM_ERROR_TEXT", "MLM_GENERIC_ERROR", "mlmErrorText",
                    "mlmCodeFromResponse", "mlmCell", "mlmRefresh", "mlmInit",
                    "mlmRequest", "mlmIsShown", "escapeHtml", "API_BASE",
                    "API_KEY", "renderPanelError"}
    # Intersecção com TUDO o que ml_models.js declara de topo (não só a lista
    # de globais conhecidos): um nome mlm*/MLM_* novo que aparecesse nos dois
    # ficheiros partiria o browser inteiro na mesma (Pitfall 9).
    declaracoes_mlm = set(re.findall(
        r"^(?:const|let|var|class|function|async function)\s+([A-Za-z_$][\w$]*)",
        ml_models_js, re.M))
    repetidos = sorted(reutilizados.intersection(declaracoes_mle))
    colisao_mlm = sorted(declaracoes_mlm.intersection(declaracoes_mle))
    check("ml_evaluation.js não redeclara nada de ml_models.js ou app.js",
          not repetidos)
    if repetidos:
        print(f"       nomes redeclarados: {repetidos}")
    check("ml_evaluation.js não repete nenhum identificador de topo de ml_models.js",
          not colisao_mlm)
    if colisao_mlm:
        print(f"       colisoes com ml_models.js: {colisao_mlm}")
    check("ml_evaluation.js não volta a ter mlmBuildEvalRows/mlmRenderEvaluation/mlmEvalTab",
          not any(x in ml_evaluation_js for x in ("mlmBuildEvalRows", "mlmRenderEvaluation", "mlmEvalTab")))
    check("ml_models.js deixou de ter a Evaluation (D-09)",
          not any(x in ml_models_js for x in ("mlmBuildEvalRows", "mlmRenderEvaluation", "mlmEvalTab")))

    codigos = ("invalid_version_id", "active_not_found", "metadata_missing", "metadata_invalid",
               "artifact_missing", "hash_mismatch", "already_adopted", "no_legacy_model",
               "registry_unavailable")
    em_falta = [c for c in codigos if c not in ml_models_js]
    check("ml_models.js traduz os 9 códigos de erro de D-06", not em_falta)
    if em_falta:
        print(f"       códigos em falta: {em_falta}")


if __name__ == "__main__":
    run()
    check_static_frontend()
    if failures:
        print(f"\n[FALHOU] {len(failures)} teste(s) falharam:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("\n[OK] Todos os testes passaram")
