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


def section_header_extras() -> None:
    check("cabeçalho distingue 401", "slHeaderErrorStatus(err)" in read("app.js"))
    check("rodapé sem afirmação de tempo real",
          "Ligação em tempo real ao Wazuh" not in read("index.html")
          and "SentryLens — Fase 2 do projeto CET.</p>" in read("index.html"))
    m = re.search(r"function applyHash\(\)\s*\{(.*?)\n\}", read("app.js"), re.S)
    body = m.group(1) if m else ""
    check("applyHash protege decodeURIComponent com try",
          "try {" in body and "decodeURIComponent" in body
          and body.index("try {") < body.index("decodeURIComponent")
          and body.index("decodeURIComponent") < body.index("catch"))


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
    body = re.search(r"async function loadAnalysts\(\)\s*\{(.*?)\n\}", soc, re.S).group(1)
    check("select de turnos recebe a lista sem filtro Inativos",
          "updateShiftAnalystSelect(received)" in body
          and "updateShiftAnalystSelect(stAnalystsCache)" not in body
          and body.index("updateShiftAnalystSelect(") < body.index("onlyInactive"))
    check("badges escapam o fallback", "escapeHtml(String(labels[tier] || tier))" in soc and "escapeHtml(String(labels[role] || role))" in soc)


def section_incidents_filter() -> None:
    check("sem CURRENT_USER", "CURRENT_USER" not in read("incidents.js"))
    check("sem opção __mine__", "__mine__" not in read("index.html"))
    check("sem ramo __mine__ em incidents.js", "__mine__" not in read("incidents.js"))
    check("filtro carrega analistas ativos", "/api/soc/analysts?active_only=true" in read("incidents.js"))


def section_ml_models() -> None:
    html = read("index.html")
    check("parágrafo do treino aparece uma vez", html.count("O botão treina a partir do próprio dashboard") == 1)
    check("origem por omissão não é 'real'", '<option value="real" selected>' not in html)
    check("origem por omissão é 'unknown'", '<option value="unknown" selected>' in html)
    check("sem escape duplo no resultado do treino",
          re.search(r"mlmRenderTrainResult\([^;]*escapeHtml\(", read("ml_models.js"), re.S) is None)
    check("sem escapeHtml no resultado do treino", "escapeHtml(resultado.texto)" not in read("ml_models.js"))


def section_cleanups() -> None:
    ev = read("ml_evaluation.js")
    check("mleRenderEvaluation declarada uma vez", ev.count("function mleRenderEvaluation(") == 1)
    check("comparação vazia com colspan 8", 'colspan="7"' not in ev)
    check("activateTab escapa o hash", "CSS.escape(tabName)" in read("app.js"))
    check("nota Red vs Blue atualizada", "não regista ações de resposta" not in read("redblue.js"))
    check("Live SOC distingue 401", "API key inválida" in read("live_soc.js"))
    css = read("style.css")
    for dead in ["row-gap", "mle-verdict", "tier-badge-inline", "role-badge-inline", ".status-badge"]:
        check(f"CSS morto removido: {dead}", dead not in css)
    check("detalhe da Attack Library mostra o painel no erro",
          re.search(r"function alibShowDetailError[\s\S]{0,300}hidden\s*=\s*false", read("attack_library.js")) is not None)


if __name__ == "__main__":
    section_gitignore()
    section_header()
    section_header_extras()
    section_system()
    section_no_inline_handlers()
    section_modals()
    section_ml_anomalies()
    section_soc_filters()
    section_incidents_filter()
    section_ml_models()
    section_cleanups()
    if failures:
        print(f"\n{len(failures)} falha(s).")
        sys.exit(1)
    print("\nTodos os testes estáticos passaram.")
