"""
Teste do validador de paletas (validate_palette.js, Onda 4 W4.2).

Corre o validador com Node: os tokens reais de style.css têm de passar nos modos
claro e escuro, a paleta «Flat UI» antiga de severidade tem de falhar (prova que
o validador deteta o problema que a auditoria apontou), e argumentos inválidos
saem com código 2. Sem `node` no PATH falha de propósito.

Correr (a partir de scripts/):
    python test_validate_palette.py
"""

import shutil
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).with_name("validate_palette.js")

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [NODE, str(SCRIPT), *args], capture_output=True, text=True, encoding="utf-8", timeout=60
    )


NODE = shutil.which("node")
if NODE is None:
    check("node não encontrado no PATH — instala Node.js (necessário para validate_palette.js)", False)
else:
    r = run()
    check("tokens de style.css: paleta categórica e rampa de severidade passam nos dois modos", r.returncode == 0)
    check("o relatório cobre os modos claro e escuro", "(light" in r.stdout and "(dark" in r.stdout)
    check("o relatório cobre a rampa de severidade", "severidade" in r.stdout)

    flat = "#e74c3c,#f39c12,#d4ac0d,#27ae60,#3498db"
    r = run(flat, "--mode", "light", "--profile", "severity", "--surface", "#ffffff")
    check("a rampa «Flat UI» antiga de severidade falha (Alto e Médio indistinguíveis)", r.returncode == 1)

    ok_light = "#7f1d1d,#c2410c,#b58900,#2e7d32,#1f6fb2"
    r = run(ok_light, "--mode", "light", "--profile", "severity", "--surface", "#ffffff")
    check("a rampa de severidade nova passa no modo claro", r.returncode == 0)

    cat = "#2a78d6,#eb6834,#1baf7a,#eda100,#e87ba4,#008300,#6250d6,#e34948"
    r = run(cat, "--mode", "light", "--surface", "#ffffff")
    check("paleta categórica de referência passa no modo claro", r.returncode == 0)

    r = run("#2a78d6,#2b79d7,#2c7ad8", "--mode", "light", "--surface", "#ffffff")
    check("três azuis quase iguais falham (visão normal)", r.returncode == 1)

    r = run("isto-nao-e-hex", "--mode", "light")
    check("cor inválida sai com código 2", r.returncode == 2)
    r = run(cat, "--mode", "rosa")
    check("modo inválido sai com código 2", r.returncode == 2)
    r = run(cat, "--nao-existe")
    check("flag desconhecida sai com código 2", r.returncode == 2)

if __name__ == "__main__":
    if failures:
        print(f"\n[FALHOU] {len(failures)} teste(s) falharam:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("\n[OK] Todos os testes passaram")
