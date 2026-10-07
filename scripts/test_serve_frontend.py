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


if __name__ == "__main__":
    run()
    if failures:
        print(f"\n[FALHOU] {len(failures)} teste(s) falharam:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("\n[OK] Todos os testes passaram")
