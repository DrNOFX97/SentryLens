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
    app = read("shell.js")
    check("setStatus removido", "function setStatus" not in app)
    check("cabeçalho lê /api/siem/health", 'refreshHeaderStatus' in app and '/api/siem/health' in app)
    check("subtítulo não afirma ligação", "ligado ao Wazuh em tempo real" not in read("index.html"))
    check("estilo status-warn existe", ".status-warn" in read("style.css"))


def section_header_extras() -> None:
    check("cabeçalho distingue 401", "slHeaderErrorStatus(err)" in read("shell.js"))
    check("rodapé sem afirmação de tempo real",
          "Ligação em tempo real ao Wazuh" not in read("index.html")
          and "SentryLens — Fase 2 do projeto CET.</p>" in read("index.html"))
    m = re.search(r"function applyHash\(\)\s*\{(.*?)\n\}", read("shell.js"), re.S)
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
    body = re.search(r"async function loadSystemPanel\(\)\s*\{(.*?)\n\}", read("system.js"), re.S).group(1)
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
    check("ml_score não usa toFixed direto", "r.ml_score.toFixed" not in read("ml-anomalies.js"))


def section_soc_filters() -> None:
    soc = read("soc_team.js")
    check("nome bloqueado ao editar analista", re.search(r'analyst-name"\)\.disabled\s*=\s*true', soc) is not None)
    check("nome desbloqueado ao abrir", re.search(r'analyst-name"\)\.disabled\s*=\s*false', soc) is not None)
    check("filtro de estado usa slAnalystActiveFilter", "slAnalystActiveFilter(" in soc)
    check("resumo por tier usa a janela global (slEffectiveWindow)", "slEffectiveWindow(windowSelect.value, 720)" in soc)
    check("sem active_only forçado a true para Todos", 'active === "" ? "true"' not in soc)
    body = re.search(r"async function loadAnalysts\(\)\s*\{(.*?)\n\}", soc, re.S).group(1)
    check("select de turnos recebe a lista sem filtro Inativos",
          "updateShiftAnalystSelect(received)" in body
          and "updateShiftAnalystSelect(stAnalystsCache)" not in body
          and body.index("updateShiftAnalystSelect(") < body.index("onlyInactive"))
    check("badges escapam o fallback", "htmlT`<span class=\"inc-status ${cls[tier]}\">${String(labels[tier] || tier)}</span>`" in soc
          and "htmlT`<span class=\"inc-status ${cls[role]}\">${String(labels[role] || role)}</span>`" in soc)


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
    check("activateTab não monta seletores CSS com o hash", "querySelector(`.nav-item[data-tab" not in read("shell.js"))
    check("nota Red vs Blue atualizada", "não regista ações de resposta" not in read("redblue.js"))
    check("Live SOC distingue 401", "API key inválida" in read("live_soc.js"))
    css = read("style.css")
    for dead in ["row-gap", "mle-verdict", "tier-badge-inline", "role-badge-inline", ".status-badge"]:
        check(f"CSS morto removido: {dead}", dead not in css)
    check("detalhe da Attack Library mostra o painel no erro",
          re.search(r"function alibShowDetailError[\s\S]{0,300}hidden\s*=\s*false", read("attack_library.js")) is not None)


def section_offline() -> None:
    """O dashboard tem de abrir sem internet: nada de https:// externo em index.html/style.css."""
    import hashlib, base64
    index = read("index.html")
    css = read("style.css")
    for nome, texto in (("index.html", index), ("style.css", css)):
        check(f"{nome} sem referências http(s):// externas em src/href/url()",
              re.search(r"""(?:src|href)\s*=\s*["']https?://|url\(\s*["']?https?://|@import\s+["']?https?://""", texto) is None)
    check("index.html não referencia Google Fonts nem CDNs",
          not any(h in index for h in ("fonts.googleapis.com", "fonts.gstatic.com", "cdnjs.cloudflare.com", "jsdelivr", "unpkg.com")))
    check("Chart.js carregado de vendor/", '<script src="vendor/chart.umd.min.js"></script>' in index)
    chart = (ROOT / "vendor" / "chart.umd.min.js").read_bytes()
    digest = "sha384-" + base64.b64encode(hashlib.sha384(chart).digest()).decode()
    check("vendor/chart.umd.min.js é o Chart.js 4.5.1 original (sha384 do cdnjs)",
          digest == "sha384-jb8JQMbMoBUzgWatfe6COACi2ljcDdZQ2OxczGA3bGNeWe+6DChMTBJemed7ZnvJ")
    for familia, ficheiro in (("Inter", "inter-latin"), ("JetBrains Mono", "jetbrains-mono-latin"),
                              ("Space Grotesk", "space-grotesk-latin")):
        check(f"@font-face local para {familia}",
              re.search(r"@font-face\s*\{[^}]*font-family:\s*'" + familia + r"'[^}]*vendor/fonts/" + ficheiro + r"\.woff2", css) is not None)
        data = (ROOT / "vendor" / "fonts" / (ficheiro + ".woff2")).read_bytes()
        check(f"{ficheiro}.woff2 é um woff2 válido (magic wOF2)", data[:4] == b"wOF2")
    serve = read("scripts/serve_frontend.py")
    for rota in ("/vendor/chart.umd.min.js", "/vendor/fonts/inter-latin.woff2",
                 "/vendor/fonts/jetbrains-mono-latin.woff2", "/vendor/fonts/space-grotesk-latin.woff2",
                 '".woff2": "font/woff2"'):
        check(f"serve_frontend.py contém {rota}", rota in serve)


def section_nav_w51() -> None:
    """W5.1: menu com no máximo 22 entradas, sem itens planeados, página Roadmap."""
    index = read("index.html")
    shell = read("shell.js")
    nav = re.search(r'<nav class="sidebar".*?</nav>', index, re.S).group(0)
    entradas = re.findall(r'<button class="nav-item[^"]*"[^>]*>', nav)
    check(f"menu com no máximo 22 entradas ({len(entradas)})", 0 < len(entradas) <= 22)
    check("nenhuma entrada is-planned / data-planned / nav-badge",
          "is-planned" not in index and "data-planned" not in index and "nav-badge" not in nav)
    check("secção #tab-planned removida", 'id="tab-planned"' not in index and "tab-planned" not in shell)
    check("página Roadmap presente", 'id="tab-roadmap"' in index and 'data-tab="roadmap"' in nav)
    secoes = set(re.findall(r'<div class="tab-content[^"]*" id="tab-([\w-]+)"', index))
    tabs = set(re.findall(r'data-tab="([\w-]+)"', nav))
    for b in re.findall(r'data-tabs="([^"]+)"', nav):
        tabs.update(b.split())
    tabs.update(re.findall(r'class="subnav-item" data-tab="([\w-]+)"', index))
    check("todo o data-tab do menu tem secção #tab-<id>", bool(tabs) and tabs <= secoes)
    check("toda a secção tem entrada de menu ou sub-navegação", secoes <= tabs)
    for t in ("live-soc", "agents", "attack-registry", "attack-timeline", "ml-models", "ml-evaluation",
              "mttd-mttr", "detection-coverage", "detection-rate"):
        check(f"sub-navegação alcança {t}", f'class="subnav-item" data-tab="{t}"' in index)
    check("cada entrada do menu tem cabeçalho de grupo (summary)",
          nav.count("<summary>") == nav.count('<details class="nav-group"'))
    check("exatamente uma entrada com aria-current inicial", nav.count('aria-current="page"') == 1)
    check("sub-navegação sem handlers inline", "onclick" not in index)


def section_ws_ticket_csp() -> None:
    """S2/S3: a chave nunca vai no URL de um WebSocket; sem JS inline (CSP)."""
    import re as _re
    for rel in ("realtime.js", "redblue.js"):
        txt = read(rel)
        check(f"{rel} não usa api_key= em URLs", "api_key=" not in txt)
        check(f"{rel} pede /api/ws-ticket antes de abrir o socket", "/api/ws-ticket" in txt)
        check(f"{rel} liga com ?ticket=", "?ticket=" in txt)
    for p in ROOT.glob("*.js"):
        if p.name in ("config.js",):
            continue
        check(f"{p.name} sem api_key= no código", "api_key=" not in p.read_text(encoding="utf-8"))
    index = read("index.html")
    inline = [m for m in _re.findall(r"<script([^>]*)>", index) if "src=" not in m]
    check("index.html sem <script> inline (CSP script-src 'self')", not inline)
    check("index.html sem javascript: URLs", "javascript:" not in index)


def section_language_and_window_w52_w53() -> None:
    """W5.2: menu e títulos em português. W5.3: um só seletor de janela."""
    index = read("index.html")
    nav = index[index.index('<nav class="sidebar"'):index.index("</nav>")]
    labels = [re.sub(r"<[^>]+>", "", m).strip() for m in re.findall(r'<button class="nav-item[^>]*>(.*?)</button>', nav, re.S)]
    ingles = {"Detections", "Attack Library", "Live Traffic", "Network Detections", "PCAP / Evidence", "Models", "Evaluation", "Candidates"}
    check("menu sem rótulos em inglês fora da lista de termos da indústria", not (ingles & set(labels)))
    titulos = [re.sub(r"<[^>]+>", "", m).strip() for m in re.findall(r"<h2[^>]*>(.*?)</h2>", index, re.S)]
    check("títulos de painel sem os nomes ingleses antigos", not (ingles | {"Attack Registry", "Attack Timeline", "Detection Coverage", "Detection Rate", "ML Anomalias"}) & set(titulos))
    check("sem seletor de período separado", "period-select" not in index and "novos painéis" not in index)
    check("um só seletor de janela, até 90 dias", index.count('<select id="window-select">') == 1 and 'value="2160"' in index)
    notas = re.findall(r'data-window-max="(\d+)"', index)
    check("abas dependentes da janela têm nota «A mostrar»", len(notas) >= 9 and set(notas) <= {"168", "720", "2160"})
    for rel in ("shell.js", "incidents.js", "attack_registry.js", "soc_team.js"):
        check(f"{rel} não usa periodSelect", "periodSelect" not in read(rel))


if __name__ == "__main__":
    section_ws_ticket_csp()
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
    section_offline()
    section_nav_w51()
    section_language_and_window_w52_w53()
    if failures:
        print(f"\n{len(failures)} falha(s).")
        sys.exit(1)
    print("\nTodos os testes estáticos passaram.")
