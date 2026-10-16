"""
Testes estáticos do frontend e de higiene do repositório (sem browser e sem
backend). Verificam ficheiros do projeto tal como estão em disco ou no git,
para apanhar regressões de segurança que os testes de API não cobrem.

Secções atuais:
- gitignore: os logs do backend (que podem conter API keys em query strings)
  ficam fora do git.

Segue o estilo de test_serve_frontend.py: standalone, check()/[OK]/[FALHOU],
sys.exit(1) em caso de falha. Não importa main.py, por isso não precisa do
backend nem do laboratório Wazuh.

Correr:
    python test_frontend_static.py
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

failures: list[str] = []


def check(label: str, cond: bool) -> None:
    print(f"[{'OK   ' if cond else 'FALHOU'}] {label}")
    if not cond:
        failures.append(label)


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def section_gitignore() -> None:
    for name in ["scripts/backend.log", "scripts/backend.log.err",
                 "scripts/backend.log-PC-Vicente.err", "scripts/frontend.log",
                 "scripts/x.err"]:
        r = subprocess.run(["git", "check-ignore", "-q", name], cwd=ROOT)
        check(f"{name} ignorado pelo git", r.returncode == 0)


def section_header() -> None:
    app = read("app.js")
    check("setStatus removido", "function setStatus" not in app)
    check("cabeçalho lê /api/siem/health", 'refreshHeaderStatus' in app and '/api/siem/health' in app)
    check("subtítulo não afirma ligação", "ligado ao Wazuh em tempo real" not in read("index.html"))
    check("estilo status-warn existe", ".status-warn" in read("style.css"))


if __name__ == "__main__":
    section_gitignore()
    section_header()
    if failures:
        print(f"\n{len(failures)} falha(s).")
        sys.exit(1)
    print("\nTodos os testes estáticos passaram.")
