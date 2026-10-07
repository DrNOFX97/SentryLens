"""
Servidor estático mínimo para o frontend do SentryLens.

Ao contrário de `python -m http.server`, só serve os ficheiros do
frontend por uma whitelist explícita — nunca a árvore toda do
repositório. Isto interessa porque o repositório também contém
scripts/.env com credenciais reais do Wazuh; servir a raiz do projeto
tornava esse ficheiro descarregável por qualquer pedido HTTP direto
(um GET direto não precisa de contornar CORS — isso só protege
leituras via fetch() cross-origin, não navegação/download direto).

Liga só a 127.0.0.1 — nunca à rede local — consistente com a decisão
de CORS do backend (loopback-only, ver scripts/main.py).

/config.js é gerado a pedido (não é um ficheiro) e entrega ao browser a
SENTRYLENS_API_KEY de scripts/.env, para o dashboard não precisar de a ter
colada no app.js. Como um <script src> cross-origin consegue ler globais do
script que carrega (ao estilo JSONP), uma página maliciosa aberta noutro
separador podia ir buscar a chave a http://127.0.0.1:5500/config.js. Por
isso o /config.js é fail-closed: só responde com Sec-Fetch-Site:
same-origin ou, em browsers antigos que não enviam esse cabeçalho, com um
Referer do mesmo origin (o Host do próprio pedido). Sem nenhum dos dois —
incluindo curl, que já pode ler o .env diretamente — recusa. Todos os
pedidos com Host que não seja loopback são recusados (DNS rebinding).
"""

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = Path(__file__).resolve().parent / ".env"
API_KEY_VAR = "SENTRYLENS_API_KEY"
LOOPBACK_HOSTS = {"127.0.0.1", "localhost"}

ALLOWED_FILES = {
    "/": "index.html",
    "/index.html": "index.html",
    "/app.js": "app.js",
    "/redblue.js": "redblue.js",
    "/incidents.js": "incidents.js",
    "/style.css": "style.css",
    "/logo.png": "logo.png",
    "/favicon.png": "favicon.png",
}

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".png": "image/png",
}


def load_api_key() -> str:
    """Variável de ambiente primeiro, senão a linha SENTRYLENS_API_KEY= de
    scripts/.env. Lida a cada pedido, para rodar a chave não exigir reiniciar
    este servidor. Devolve "" se não existir (o dashboard fica a 401, como
    antes — nunca falha o arranque)."""
    from_env = os.environ.get(API_KEY_VAR, "").strip()
    if from_env:
        return from_env
    try:
        for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith(API_KEY_VAR + "="):
                return line.split("=", 1)[1].strip().strip("\"'")
    except OSError:
        pass
    return ""


def build_config_js(api_key: str) -> bytes:
    # json.dumps garante escape correto de aspas/barras na chave.
    return ("window.SENTRYLENS_CONFIG = { apiKey: " + json.dumps(api_key) + " };\n").encode("utf-8")


def _host_is_loopback(host_header: str) -> bool:
    host = host_header.rsplit(":", 1)[0] if ":" in host_header else host_header
    return host in LOOPBACK_HOSTS


class FrontendHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if not _host_is_loopback(self.headers.get("Host", "")):
            self.send_error(421, "Misdirected Request")
            return

        if self.path == "/config.js":
            self._serve_config()
            return

        filename = ALLOWED_FILES.get(self.path)
        if filename is None:
            self.send_error(404, "Not Found")
            return

        try:
            data = (PROJECT_ROOT / filename).read_bytes()
        except OSError:
            self.send_error(404, "Not Found")
            return

        content_type = CONTENT_TYPES.get(Path(filename).suffix, "application/octet-stream")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _is_same_origin_request(self) -> bool:
        """Fail-closed. Sec-Fetch-Site não pode ser forjado por uma página
        (é um cabeçalho proibido para JS), por isso quando existe decide
        sozinho. Quando falta (browser antigo), só aceita um Referer cujo
        origin seja o Host deste pedido — uma página atacante que suprima o
        Referer (referrerpolicy=no-referrer) é recusada, não aceite."""
        site = self.headers.get("Sec-Fetch-Site")
        if site is not None:
            return site == "same-origin"
        referer = self.headers.get("Referer")
        if not referer:
            return False
        return urlparse(referer).netloc == self.headers.get("Host", "")

    def _serve_config(self):
        if not self._is_same_origin_request():
            self.send_error(403, "Forbidden")
            return
        data = build_config_js(load_api_key())
        self.send_response(200)
        self.send_header("Content-Type", CONTENT_TYPES[".js"])
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        pass  # silencioso — o wrapper PowerShell já redireciona stdout/stderr para frontend.log


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5500
    server = HTTPServer(("127.0.0.1", port), FrontendHandler)
    server.serve_forever()
