"""
Testes de regressão da autenticação por API key (header `X-API-Key`,
variável de ambiente `SENTRYLENS_API_KEY`), sem precisar do laboratório
Wazuh real ligado. Usa /api/health como endpoint alvo por não precisar de
nenhum mock de WazuhIndexerClient/WazuhManagerClient.

Mesmo estilo dos outros ficheiros de teste standalone: função
check(label, condition), print [OK]/[FALHOU] por caso, sys.exit(1) no fim
se houver falhas.

Correr:
    python test_auth.py
"""

import os
import sys

os.environ["SENTRYLENS_API_KEY"] = "chave-valida-de-teste"

from fastapi.testclient import TestClient

import main

# Desliga o startup event (loop de monitorização de sistema da Fase 2) —
# mesmo padrão dos outros ficheiros de teste.
main.app.router.on_startup.clear()

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def run() -> None:
    client_sem_header = TestClient(main.app)
    client_header_errado = TestClient(main.app, headers={"X-API-Key": "chave-errada"})
    client_header_correto = TestClient(
        main.app, headers={"X-API-Key": os.environ["SENTRYLENS_API_KEY"]}
    )

    # --- Sem header X-API-Key -> 401 ---
    resp_sem_header = client_sem_header.get("/api/health")
    check("GET /api/health sem X-API-Key devolve 401", resp_sem_header.status_code == 401)

    # --- Header X-API-Key errado -> 401 ---
    resp_errado = client_header_errado.get("/api/health")
    check("GET /api/health com X-API-Key errado devolve 401", resp_errado.status_code == 401)

    # --- Header X-API-Key correto -> 200 ---
    resp_correto = client_header_correto.get("/api/health")
    check("GET /api/health com X-API-Key correto devolve 200", resp_correto.status_code == 200)

    # --- Mensagem de erro do 401 não expõe a key correta nem detalhes internos ---
    corpo_erro = resp_sem_header.text
    check(
        "Corpo do 401 não expõe a chave correta em texto",
        os.environ["SENTRYLENS_API_KEY"] not in corpo_erro,
    )
    corpo_erro_errado = resp_errado.text
    check(
        "Corpo do 401 (header errado) não expõe a chave correta em texto",
        os.environ["SENTRYLENS_API_KEY"] not in corpo_erro_errado,
    )

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")
    sys.exit(0)


if __name__ == "__main__":
    run()
