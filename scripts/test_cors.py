"""
Testes do CORS do backend (main.py): o browser faz um pedido prévio (OPTIONS)
antes de cada PATCH/POST com X-API-Key. Várias rotas do dashboard são PATCH
(atribuir analista, atribuir tier, SLA, editar analista); sem PATCH nos métodos
permitidos o browser recusa-as com "Sem ligação ao backend" e a Equipa SOC
nunca consegue atribuir nada. As origens continuam restritas a
localhost/127.0.0.1; métodos fora do necessário (DELETE, PUT) continuam recusados.

Correr (a partir de scripts/):
    python test_cors.py
"""

import os
import sys

from fastapi.testclient import TestClient

os.environ.setdefault("SENTRYLENS_API_KEY", "chave-de-teste-nao-usar-em-producao")

import main

main.app.router.on_startup.clear()

failures: list[str] = []

LOCAL = "http://127.0.0.1:5500"
URL = "/api/incidents/INC-20261026-001/team"


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def preflight(client: TestClient, method: str, origin: str = LOCAL):
    return client.options(URL, headers={
        "Origin": origin,
        "Access-Control-Request-Method": method,
        "Access-Control-Request-Headers": "x-api-key,content-type",
    })


client = TestClient(main.app)

for method in ("GET", "POST", "PATCH"):
    r = preflight(client, method)
    check(f"preflight {method} de {LOCAL} -> 200", r.status_code == 200)
    check(f"preflight {method} -> {method} nos métodos permitidos",
          method in r.headers.get("access-control-allow-methods", ""))
    check(f"preflight {method} -> origem devolvida", r.headers.get("access-control-allow-origin") == LOCAL)

for localhost in ("http://localhost:5500", "http://127.0.0.1:8080"):
    check(f"PATCH de {localhost} continua permitido", preflight(client, "PATCH", localhost).status_code == 200)

for metodo in ("DELETE", "PUT"):
    check(f"preflight {metodo} -> recusado (400)", preflight(client, metodo).status_code == 400)

for externa in ("https://evil.example", "http://192.168.1.50:5500", "http://127.0.0.1.evil.example"):
    r = preflight(client, "PATCH", externa)
    check(f"PATCH de origem externa {externa} -> sem Access-Control-Allow-Origin",
          "access-control-allow-origin" not in r.headers)

if failures:
    print(f"\n[FALHOU] {len(failures)} caso(s) falharam")
    sys.exit(1)
print("\n[OK] Todos os testes passaram")
