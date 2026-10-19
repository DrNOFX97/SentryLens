"""
Contraste WCAG dos tokens de style.css (Onda 4, W4.1/W4.2) nos modos claro e escuro.

Le os tokens de :root, do bloco @media (prefers-color-scheme: dark) e do bloco
:root[data-theme="dark"], e verifica:
  - todos os pares texto/fundo >= 4.5:1 (texto normal);
  - texto grande e componentes de UI >= 3:1;
  - os dois blocos escuros sao identicos (o tema forcado e o automatico);
  - no maximo 30 linhas com cor hexadecimal em style.css, todas dentro de :root
    ou dos blocos do tema escuro;
  - nenhuma cor literal (hex, rgb, nome) fora dos tokens.

Sem dependencias externas. Correr (a partir de scripts/):
    python test_contrast.py
"""

import re
import sys
from pathlib import Path

CSS_PATH = Path(__file__).resolve().parent.parent / "style.css"

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


# --- WCAG ---------------------------------------------------------------------
def _lin(c: float) -> float:
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def _rgb(h: str) -> tuple[float, float, float]:
    return tuple(int(h[i:i + 2], 16) / 255 for i in (1, 3, 5))  # type: ignore[return-value]


def luminance(h: str) -> float:
    r, g, b = (_lin(c) for c in _rgb(h))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a: str, b: str) -> float:
    hi, lo = sorted((luminance(a), luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def blend(fg: str, bg: str, alpha: float) -> str:
    f, b = _rgb(fg), _rgb(bg)
    return "#" + "".join(f"{round((alpha * x + (1 - alpha) * y) * 255):02x}" for x, y in zip(f, b))


# --- leitura do CSS -----------------------------------------------------------
def strip_comments(css: str) -> str:
    return re.sub(r"/\*.*?\*/", "", css, flags=re.S)


def extract_block(css: str, header: str) -> str:
    start = css.index(header)
    open_ = css.index("{", start)
    depth = 0
    for i in range(open_, len(css)):
        if css[i] == "{":
            depth += 1
        elif css[i] == "}":
            depth -= 1
            if depth == 0:
                return css[open_ + 1:i]
    raise ValueError(header)


def parse_vars(block: str) -> dict[str, str]:
    return {m.group(1): m.group(2).strip() for m in re.finditer(r"(--[a-z0-9-]+)\s*:\s*([^;]+);", block)}


raw = CSS_PATH.read_text(encoding="utf-8")
css = strip_comments(raw)
root_block = extract_block(css, ":root {")
media_dark_block = extract_block(extract_block(css, "@media (prefers-color-scheme: dark)"), ':root:not([data-theme="light"])')
attr_dark_block = extract_block(css, ':root[data-theme="dark"]')

light = parse_vars(root_block)
dark_media = parse_vars(media_dark_block)
dark_attr = parse_vars(attr_dark_block)
dark = {**light, **dark_attr}

HEX = re.compile(r"^#[0-9a-fA-F]{6}$")

# Pares (texto, fundo, minimo, descricao). Minimo 4.5 texto normal, 3.0 texto grande/UI.
SEVS = ["critical", "high", "medium", "low", "info"]
PAIRS: list[tuple[str, str, float, str]] = []
for surf in ("--bg", "--surface", "--surface-sunken", "--surface-hover"):
    for txt in ("--text", "--text-secondary", "--text-muted", "--accent"):
        PAIRS.append((txt, surf, 4.5, f"{txt} sobre {surf}"))
    for s in SEVS:
        PAIRS.append((f"--sev-{s}-fg", surf, 4.5, f"--sev-{s}-fg sobre {surf}"))
for txt in ("--text", "--text-secondary"):
    PAIRS.append((txt, "--neutral-bg", 4.5, f"{txt} sobre --neutral-bg"))
PAIRS += [
    ("--on-accent", "--accent", 4.5, "texto do botao sobre --accent"),
    ("--on-accent", "--accent-hover", 4.5, "texto do botao sobre --accent-hover"),
    ("--accent-soft-fg", "--accent-soft", 4.5, "--accent-soft-fg sobre --accent-soft"),
    ("--text", "--accent-soft", 4.5, "--text sobre --accent-soft"),
    ("--on-btn-alt", "--btn-alt", 4.5, "texto do botao alternativo"),
    ("--on-neutral-solid", "--neutral-solid", 4.5, "texto sobre neutro solido"),
    ("--text", "--surface", 4.5, "--text sobre --surface"),
    # estados do cabecalho (fixos nos dois temas)
    ("--st-ok-fg", "--st-ok-bg", 4.5, "pilula ok"),
    ("--st-warn-fg", "--st-warn-bg", 4.5, "pilula aviso"),
    ("--st-error-fg", "--st-error-bg", 4.5, "pilula erro"),
    ("--st-unknown-fg", "--st-unknown-bg", 4.5, "pilula desconhecido"),
    # menu lateral e cabecalho (navy fixo)
    ("--nav-text", "--navy-950", 4.5, "texto do menu"),
    ("--nav-text", "--navy-800", 4.5, "texto do menu em hover"),
    ("--nav-muted", "--navy-950", 4.5, "item planeado do menu"),
    ("--nav-badge-fg", "--navy-950", 4.5, "contador do menu"),
    ("--cyan-400", "--navy-950", 4.5, "titulos de grupo do menu"),
    ("--on-navy", "--navy-800", 4.5, "texto ativo do menu"),
    ("--on-navy", "--navy-950", 4.5, "texto do cabecalho"),
    # componentes de UI e texto grande (>= 3:1)
    ("--border-input", "--surface", 3.0, "contorno de campos sobre --surface"),
    ("--border-input", "--surface-sunken", 3.0, "contorno de campos sobre --surface-sunken"),
    ("--accent", "--surface", 3.0, "anel de foco sobre --surface"),
]
for s in SEVS:
    PAIRS.append((f"--on-sev-{s}", f"--sev-{s}", 4.5, f"texto do badge {s} sobre o preenchimento"))
    PAIRS.append((f"--sev-{s}-fg", f"--sev-{s}-bg", 4.5, f"--sev-{s}-fg sobre --sev-{s}-bg"))
    PAIRS.append(("--text", f"--sev-{s}-bg", 4.5, f"--text sobre --sev-{s}-bg"))
    PAIRS.append((f"--sev-{s}", "--surface", 3.0, f"preenchimento {s} sobre --surface (UI)"))
    PAIRS.append((f"--sev-{s}", "--sev-%s-bg" % s, 3.0, f"preenchimento {s} sobre o proprio fundo suave (UI)"))


def get(tokens: dict[str, str], name: str) -> str | None:
    v = tokens.get(name)
    seen = 0
    while v and v.startswith("var(") and seen < 8:
        v = tokens.get(v[4:-1].strip())
        seen += 1
    return v


def run_pairs(mode: str, tokens: dict[str, str]) -> None:
    bad = 0
    for fg, bg, minimum, desc in PAIRS:
        a, b = get(tokens, fg), get(tokens, bg)
        if not (a and b and HEX.match(a) and HEX.match(b)):
            check(f"[{mode}] token em falta ou nao hexadecimal: {fg} / {bg}", False)
            bad += 1
            continue
        ratio = contrast(a, b)
        if ratio < minimum:
            check(f"[{mode}] {desc}: {ratio:.2f}:1 (minimo {minimum}:1)", False)
            bad += 1
    check(f"[{mode}] {len(PAIRS)} pares texto/fundo cumprem o contraste minimo", bad == 0)

    # contador do menu: texto sobre navy-950 com 8 % de branco por cima
    base = blend("#ffffff", get(tokens, "--navy-950") or "#000000", 0.08)
    r = contrast(get(tokens, "--nav-badge-fg") or "#000000", base)
    check(f"[{mode}] contador do menu sobre o fundo com 8% de branco: {r:.2f}:1", r >= 4.5)


run_pairs("claro", light)
run_pairs("escuro", dark)

# --- coerencia dos blocos escuros ----------------------------------------------
check("os dois blocos do tema escuro (media e data-theme) definem os mesmos tokens", dark_media == dark_attr)
check("o tema escuro redefine tokens de superficie, texto, acento e severidade",
      all(k in dark_attr for k in ("--surface", "--text", "--accent", "--sev-critical", "--sev-critical-fg", "--cat-1")))
check("modo escuro: as cores diferem das do claro", dark_attr.get("--surface") != light.get("--surface"))

# --- cores literais -------------------------------------------------------------
hex_lines = [i for i, line in enumerate(raw.splitlines(), 1) if re.search(r"#[0-9a-fA-F]{6}", line)]
check(f"no maximo 30 linhas com cor hexadecimal (encontradas {len(hex_lines)})", len(hex_lines) <= 30)

allowed_spans = []
for header in (":root {", '@media (prefers-color-scheme: dark)', ':root[data-theme="dark"]'):
    start = raw.index(header)
    open_ = raw.index("{", start)
    depth = 0
    for i in range(open_, len(raw)):
        if raw[i] == "{":
            depth += 1
        elif raw[i] == "}":
            depth -= 1
            if depth == 0:
                allowed_spans.append((start, i))
                break
outside = []
for m in re.finditer(r"#[0-9a-fA-F]{3,8}\b", raw):
    # ignora seletores de id (#inc-note-btn tem letras alem de a-f) e cores dentro dos blocos permitidos
    if any(a <= m.start() <= b for a, b in allowed_spans):
        continue
    ahead = raw[m.end():m.end() + 1]
    if ahead.isalnum() or ahead in "-_":
        continue
    outside.append(raw.count("\n", 0, m.start()) + 1)
check(f"nenhuma cor hexadecimal fora de :root e dos blocos escuros (linhas {outside[:8]})", not outside)

body = css[css.index("* {"):]
check("sem rgb()/rgba()/hsl() literais fora dos tokens", not re.search(r"\b(?:rgba?|hsla?)\(", body))
check("sem as cores literais 'white'/'black' como valor fora dos tokens", not re.search(r":\s*(?:white|black)\b", body))

# --- tipografia e movimento ------------------------------------------------------
check("sem text-transform: uppercase", "text-transform: uppercase" not in css)
sizes = set(re.findall(r"font-size:\s*([^;]+);", body))
check("todos os font-size usam a escala --fs-* (ou herdam)", all(s.strip().startswith("var(--fs-") or s.strip() in ("inherit", "100%") for s in sizes))
check("prefers-reduced-motion presente", "@media (prefers-reduced-motion: reduce)" in css)
check(".btn e .badge definidos", ".btn," in css and ".badge," in css)

if __name__ == "__main__":
    if failures:
        print(f"\n[FALHOU] {len(failures)} teste(s) falharam:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("\n[OK] Todos os testes passaram")
