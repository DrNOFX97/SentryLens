"""
Corre todos os scripts test_*.py (standalone, sem pytest) e imprime só
PASS/FAIL por ficheiro. O output completo de um teste que falhe é mostrado
no fim, para não gastar contexto com os que passam.

Uso (a partir de scripts/, com o venv ativo):
    python run_all_tests.py              # todos
    python run_all_tests.py incident     # só os que contêm "incident" no nome
"""

import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent


def run(path: Path) -> tuple[str, int, str]:
    proc = subprocess.run(
        [sys.executable, "-X", "utf8", str(path)], cwd=HERE,
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300,
    )
    return path.name, proc.returncode, proc.stdout + proc.stderr


def main() -> int:
    needle = sys.argv[1] if len(sys.argv) > 1 else ""
    files = sorted(p for p in HERE.glob("test_*.py") if needle in p.name)
    if not files:
        print(f"Nenhum teste corresponde a {needle!r}")
        return 1
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(run, files))
    failed = [r for r in results if r[1] != 0]
    for name, code, _ in results:
        print(f"{'PASS' if code == 0 else 'FAIL'} {name}")
    print(f"\n{len(results) - len(failed)}/{len(results)} ficheiros passaram")
    for name, _, out in failed:
        print(f"\n===== {name} (últimas linhas) =====")
        print("\n".join(out.splitlines()[-25:]))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
