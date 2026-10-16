"""
Wrapper do teste Node de soc_team.js (migração para apiRequest e state.js).

O run_all_tests.py só descobre test_*.py, por isso este ficheiro é a ponte
para scripts/test_migration_soc_team.cjs. Não importa `main` (não precisa do backend).
Sem `node` no PATH falha com mensagem explícita (fail-closed).

Correr (a partir de scripts/):
    python test_migration_soc_team.py
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
        check("node não encontrado no PATH — instala Node.js (necessário para testar soc_team.js)", False)
        return

    proc = subprocess.run(
        [node, str(Path(__file__).with_name("test_migration_soc_team.cjs")), str(ROOT / "api.js"), str(ROOT / "state.js"), str(ROOT / "soc_team.js")],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )
    if proc.stdout:
        print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, end="")
    check("teste Node de soc_team.js", proc.returncode == 0)


if __name__ == "__main__":
    run()
    if failures:
        print(f"\n[FALHOU] {len(failures)} teste(s) falharam:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("\n[OK] Todos os testes passaram")
