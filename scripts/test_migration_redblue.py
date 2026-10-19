"""
Wrapper do teste Node da migração de redblue.js para api.js/state.js.

Correr (a partir de scripts/):
    python test_migration_redblue.py
"""

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def run() -> None:
    node = shutil.which("node")
    if node is None:
        check("node não encontrado no PATH — instala Node.js", False)
        return
    proc = subprocess.run(
        [node, str(Path(__file__).with_name("test_migration_redblue.cjs")),
         str(ROOT / "api.js"), str(ROOT / "state.js"), str(ROOT / "redblue.js")],
        capture_output=True, text=True, encoding="utf-8", timeout=60,
    )
    if proc.stdout:
        print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, end="")
    check("teste Node da migração de redblue.js", proc.returncode == 0)


if __name__ == "__main__":
    run()
    if failures:
        print(f"\n[FALHOU] {len(failures)} teste(s) falharam:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("\n[OK] Todos os testes passaram")
