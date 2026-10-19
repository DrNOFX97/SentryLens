"""
Gate: nenhuma secção de teste morta em test_ml_training.py.

O `run()` chama as secções pela tupla `SECOES`, não por `secao_x()` directo
— por isso um gate que só procure Call nodes na AST não prova nada (foi o que
aconteceu na primeira versão deste gate: reportou 13 secções mortas que
estavam todas a correr, e depois reportou uma "órfã" que era a variável de
loop `secao_` do próprio `run()`).

Este gate lê a tupla `SECOES` da AST e compara as duas listas. Sai com 1 se
houver uma secção definida e não listada, ou listada e não definida.

Uso (a partir de scripts/):
    .venv/Scripts/python.exe -X utf8 gate_seccoes.py
"""

import ast
import sys
from pathlib import Path

ALVO = Path(__file__).resolve().parent / "test_ml_training.py"

arvore = ast.parse(ALVO.read_text(encoding="utf-8"))

definidas = {n.name for n in arvore.body
             if isinstance(n, ast.FunctionDef) and n.name.startswith("secao_")}

listadas: set[str] = set()
directas: set[str] = set()
for node in ast.walk(arvore):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        if node.func.id.startswith("secao_") and len(node.func.id) > len("secao_"):
            directas.add(node.func.id)
    if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "SECOES" for t in node.targets):
        listadas |= {e.id for e in ast.walk(node.value)
                     if isinstance(e, ast.Name) and e.id.startswith("secao_")}

mortas = sorted(d for d in definidas if d not in listadas and d not in directas)
orfas = sorted((listadas | directas) - definidas)

print(f"secções definidas: {len(definidas)}")
print(f"listadas em SECOES: {len(listadas)}")
print(f"mortas (definidas e nunca reached pelo run()): {mortas}")
print(f"órfãs (no SECOES mas não definidas): {orfas}")
print(f"chamadas directamente no código (fora do SECOES): {sorted(directas)}")

sys.exit(1 if mortas or orfas else 0)