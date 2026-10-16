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


def section_modals() -> None:
    css = read("style.css")
    check(".modal[hidden] esconde", re.search(r"\.modal\[hidden\]\s*\{[^}]*display:\s*none", css) is not None)
    check("regra morta .modal.hidden removida", ".modal.hidden" not in css)
    html = read("index.html")
    check("3 modais com role=dialog", html.count('role="dialog"') == 3 and html.count('aria-modal="true"') == 3)
    for name in ("analyst", "shift", "escalation"):
        check(f"modal {name} com aria-labelledby", html.count(f'aria-labelledby="{name}-modal-title"') == 1)
    check("inputs ocultos órfãos removidos", "shift-modal-id" not in html and "escalation-modal-id" not in html)
    soc = read("soc_team.js")
    check("Escape fecha modal", "Escape" in soc)
    check("stOpenModal/stCloseModal definidos", "function stOpenModal(" in soc and "function stCloseModal(" in soc)
    check("sem modal.hidden = direto", re.search(r"modal\.hidden\s*=|-modal\"\)\.hidden\s*=", soc) is None)


def section_ml_anomalies() -> None:
    check("nota ML sem afirmação fixa de dados sintéticos", "Modelo treinado sobre dados sintéticos" not in read("index.html"))
    check("ml_score não usa toFixed direto", "r.ml_score.toFixed" not in read("app.js"))


def section_soc_filters() -> None:
    soc = read("soc_team.js")
    check("nome bloqueado ao editar analista", re.search(r'analyst-name"\)\.disabled\s*=\s*true', soc) is not None)
    check("nome desbloqueado ao abrir", re.search(r'analyst-name"\)\.disabled\s*=\s*false', soc) is not None)
    check("filtro de estado usa slAnalystActiveFilter", "slAnalystActiveFilter(" in soc)
    check("resumo por tier usa slTierWindowHours", "slTierWindowHours(" in soc)
    check("sem active_only forçado a true para Todos", 'active === "" ? "true"' not in soc)
    check("badges escapam o fallback", "escapeHtml(String(labels[tier] || tier))" in soc and "escapeHtml(String(labels[role] || role))" in soc)


if __name__ == "__main__":
    section_gitignore()
    section_header()
    section_system()
    section_no_inline_handlers()
    section_modals()
    section_ml_anomalies()
    section_soc_filters()
    if failures:
        print(f"\n{len(failures)} falha(s).")
        sys.exit(1)
    print("\nTodos os testes estáticos passaram.")
