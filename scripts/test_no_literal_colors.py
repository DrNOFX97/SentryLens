"""Falha se aparecer uma cor literal (hex ou rgb/rgba) em *.js da raiz (vendor/ excluido).
As cores vivem em tokens do style.css."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PATTERN = re.compile(r"#[0-9a-fA-F]{3,8}\b|rgba?\(")


def main():
    bad = []
    for f in sorted(ROOT.glob("*.js")):
        for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if PATTERN.search(line):
                bad.append(f"{f.name}:{n}: {line.strip()[:100]}")
                print(f"[FALHOU] {bad[-1]}")
    if bad:
        sys.exit(1)
    print("[OK] nenhuma cor literal em *.js da raiz")


if __name__ == "__main__":
    main()
