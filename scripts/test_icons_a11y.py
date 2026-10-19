"""Contrato estático de ícones SVG e modais acessíveis (W4.5, W4.7). Sem browser."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
html = (ROOT / "index.html").read_text(encoding="utf-8")
falhas = []


def check(ok, msg):
    print(("[OK] " if ok else "[FALHOU] ") + msg)
    if not ok:
        falhas.append(msg)


svgs = re.findall(r"<svg\b[^>]*class=\"icon[^\"]*\"[^>]*>", html)
check(len(svgs) > 30, f"existem ícones inline ({len(svgs)})")
check(all('aria-hidden="true"' in s for s in svgs), 'todo svg.icon tem aria-hidden="true"')
check(all('focusable="false"' in s for s in svgs), 'todo svg.icon tem focusable="false"')

symbols = set(re.findall(r"<symbol id=\"([^\"]+)\"", html))
usos = re.findall(r"<use href=\"#([^\"]+)\"", html)
check(bool(usos), "há <use href>")
check(all(u in symbols for u in usos), "todo <use href> aponta para um <symbol> existente: "
      + ", ".join(sorted(set(usos) - symbols)))
check(len(symbols) == len(re.findall(r"<symbol id=", html)), "ids de symbol sem duplicados")
check("http" not in "".join(re.findall(r"<use [^>]*>", html)), "nenhum <use> externo")

EMOJI = re.compile("[\U0001F000-\U0001FFFF\u2600-\u27BF\u2B00-\u2BFF\u2300-\u23FF]")
nav = re.search(r"<nav class=\"sidebar\".*?</nav>", html, re.S)
check(nav is not None and not EMOJI.search(nav.group(0)), "nenhum emoji no menu lateral")
for m in re.finditer(r"<(h[234]|button)\b[^>]*>(.*?)</\1>", html, re.S):
    txt = re.sub(r"<svg.*?</svg>", "", m.group(2), flags=re.S)
    if EMOJI.search(txt) and "ls-pause-btn" not in m.group(0):
        check(False, "emoji de interface em " + txt.strip()[:40])

for m in re.finditer(r"<div id=\"([^\"]+)\" class=\"modal\"", html):
    mid = m.group(1)
    corpo = html[m.end():m.end() + 400]
    check('role="dialog"' in corpo and 'aria-modal="true"' in corpo, f"{mid}: role=dialog e aria-modal")
    lab = re.search(r"aria-labelledby=\"([^\"]+)\"", corpo)
    check(bool(lab) and f'id="{lab.group(1)}"' in html, f"{mid}: aria-labelledby aponta para um id existente")

js = (ROOT / "soc_team.js").read_text(encoding="utf-8")
check('"Escape"' in js, "modais fecham com Esc")
check("stModalOpener" in js and ".focus()" in js, "modais devolvem o foco ao opener")
uih = (ROOT / "ui_helpers.js").read_text(encoding="utf-8")
check("slModalTabTarget" in uih and '"Tab"' in uih, "foco preso no modal (ui_helpers.js)")

sys.exit(1 if falhas else 0)
