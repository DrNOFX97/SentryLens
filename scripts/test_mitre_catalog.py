"""
Testes da tabela técnica -> tática MITRE (R16, Phase 18): módulo puro
mitre_catalog.py (carregamento, validação fail-fast, cache, tactics_for,
parent_of) e a chamada a nível de módulo em main.py.

Sem laboratório Wazuh. Sem pytest: imprime [OK   ]/[FALHOU] por caso.

Correr (a partir de scripts/):
    python test_mitre_catalog.py
"""

import os
import sys

os.environ.setdefault("SENTRYLENS_API_KEY", "test-key-mitre-catalog")

import main
import mitre_catalog as mc

main.app.router.on_startup.clear()

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def run_tracer() -> None:
    """Fatia fina de ponta a ponta: tabela real -> cache criada no arranque
    do main -> tactics_for/parent_of."""
    # Antes de qualquer reset_cache: prova que o main.py a carregou no arranque.
    check("arranque: a cache vem da tabela por omissão", mc._cache_path == mc.DEFAULT_PATH)
    check("arranque: a cache tem 17 técnicas", mc._cache is not None and len(mc._cache) == 17)

    check("tactics_for('T1110') == ['Credential Access']", mc.tactics_for("T1110") == ["Credential Access"])
    check("sub-técnica sem linha própria herda do pai (T1110.001)",
          mc.tactics_for("T1110.001") == ["Credential Access"])
    check("T1078 tem as 4 táticas",
          mc.tactics_for("T1078") == ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"])
    check("técnica sem entrada nem pai (T1059) -> []", mc.tactics_for("T1059") == [])

    check("parent_of('T1053.005') == 'T1053'", mc.parent_of("T1053.005") == "T1053")
    check("parent_of('T1053') == 'T1053'", mc.parent_of("T1053") == "T1053")
    check("parent_of('lixo') is None", mc.parent_of("lixo") is None)
    check("parent_of(None) is None", mc.parent_of(None) is None)

    first = mc.tactics_for("T1110")
    first.append("Impact")
    check("tactics_for devolve sempre uma lista nova", mc.tactics_for("T1110") == ["Credential Access"])


def run() -> None:
    run_tracer()


run()

if failures:
    print(f"\n{len(failures)} verificação(ões) falharam")
    sys.exit(1)
print("\nTodos os testes passaram")
