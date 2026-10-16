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

import re
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


def section_system() -> None:
    css = read("style.css")
    block = re.search(r"\.progress-fill\s*\{([^}]*)\}", css).group(1)
    check(".progress-fill começa com largura 0", re.search(r"width:\s*0", block) is not None)
    check(".progress-fill sem verde por omissão", "#27ae60" not in block)
    body = re.search(r"async function loadSystemPanel\(\)\s*\{(.*?)\n\}", read("app.js"), re.S).group(1)
    check("loadSystemPanel tem try/catch", "try {" in body and "catch" in body)
    check("nenhum .toFixed direto sobre specs.*", re.search(r"specs\.[a-z_.]+\.toFixed", body) is None)


def section_no_inline_handlers() -> None:
    for rel in ["index.html", *sorted(p.name for p in ROOT.glob("*.js"))]:
        txt = read(rel)
        check(f"{rel} sem handlers inline", re.search(r"\son[a-z]+\s*=", txt) is None)
    soc = read("soc_team.js")
    check("soc_team.js sem ações por implementar", "não implementad" not in soc)
    check("soc_team.js sem window.* para handlers", "window.deactivateAnalyst" not in soc)
    check("botões da tabela de analistas por data-action", 'data-action="deactivate"' in soc)


if __name__ == "__main__":
    section_gitignore()
    section_header()
    section_system()
    section_no_inline_handlers()
    if failures:
        print(f"\n{len(failures)} falha(s).")
        sys.exit(1)
    print("\nTodos os testes estáticos passaram.")
