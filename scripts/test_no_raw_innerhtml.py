"""Contrato estático (Onda 7): nenhum *.js da raiz usa innerHTML, exceto html.js.

Escapar à mão com escapeHtml dentro de strings é frágil (já houve XSS).
O único ponto que atribui HTML é htmRender (html.js), que só aceita HtmlT/htmlRaw.
Standalone, sem pytest: imprime [OK]/[FALHOU] e termina com sys.exit(1) se falhar.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PERMITIDOS = {"html.js"}
falhas = []


def check(nome, ok):
    print(("[OK   ] " if ok else "[FALHOU] ") + nome)
    if not ok:
        falhas.append(nome)


for js in sorted(ROOT.glob("*.js")):
    if js.name in PERMITIDOS:
        continue
    usos = [i + 1 for i, linha in enumerate(js.read_text(encoding="utf-8").splitlines())
            if re.search(r"\binnerHTML\b|\binsertAdjacentHTML\b|\bouterHTML\b", linha)
            and not linha.lstrip().startswith(("//", "*", "/*"))]
    check(f"{js.name} sem innerHTML/insertAdjacentHTML (linhas: {usos})", not usos)

check("html.js existe e define htmRender", "function htmRender" in (ROOT / "html.js").read_text(encoding="utf-8"))

if falhas:
    print(f"\n[FALHOU] {len(falhas)} teste(s) falharam")
    sys.exit(1)
print("\n[OK] Todos os testes passaram")
