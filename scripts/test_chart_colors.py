"""Corre test_chart_colors.cjs (helpers de cor de ui_helpers.js em node:vm)."""
import shutil, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main():
    node = shutil.which("node")
    if not node:
        print("[FALHOU] node não encontrado no PATH")
        sys.exit(1)
    p = subprocess.run([node, str(Path(__file__).with_name("test_chart_colors.cjs")), str(ROOT / "ui_helpers.js")],
                       capture_output=True, text=True, encoding="utf-8", timeout=60)
    print(p.stdout, end=""); print(p.stderr, end="")
    sys.exit(p.returncode)


if __name__ == "__main__":
    main()
