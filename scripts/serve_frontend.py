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
"""

import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

ALLOWED_FILES = {
    "/": "index.html",
    "/index.html": "index.html",
    "/app.js": "app.js",
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


class FrontendHandler(BaseHTTPRequestHandler):
    def do_GET(self):
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

    def log_message(self, format, *args):
        pass  # silencioso — o wrapper PowerShell já redireciona stdout/stderr para frontend.log


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5500
    server = HTTPServer(("127.0.0.1", port), FrontendHandler)
    server.serve_forever()
