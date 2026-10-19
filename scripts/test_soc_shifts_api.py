"""
Testes de GET/POST /api/soc/shifts (aba Equipa SOC) com TestClient e base
SQLite temporária. Regressão: o frontend lista os turnos de "todos os
analistas" sem `analyst_id` e o endpoint respondia 422 (parâmetro obrigatório).

Correr (a partir de scripts/):
    python test_soc_shifts_api.py
"""

import os
import sys
import tempfile

os.environ.setdefault("SENTRYLENS_API_KEY", "test-key-soc-shifts")

from fastapi.testclient import TestClient

import main
from incident_store import IncidentStore

main.app.router.on_startup.clear()
client = TestClient(main.app)
HEADERS = {"X-API-Key": os.environ["SENTRYLENS_API_KEY"]}

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def run() -> None:
    tmp = tempfile.TemporaryDirectory()
    main.incident_store = IncidentStore(os.path.join(tmp.name, "i.sqlite3"))

    r = client.get("/api/soc/shifts")
    check("sem API key -> 401", r.status_code == 401)

    r = client.get("/api/soc/shifts", headers=HEADERS)
    check("sem analyst_id e sem turnos -> 200 com lista vazia (antes: 422)",
          r.status_code == 200 and r.json() == {"shifts": []})

    for analyst_id, name, tier in (("analyst-ana", "Ana", 1), ("analyst-rui", "Rui", 2)):
        r = client.post("/api/soc/analysts", headers=HEADERS, json={"id": analyst_id, "name": name, "tier": tier})
        check(f"cria o analista {name}", r.status_code == 200)

    def shift(analyst_id, start, end, role):
        return client.post("/api/soc/shifts", headers=HEADERS,
                           json={"analyst_id": analyst_id, "start_ts": start, "end_ts": end, "role": role})

    check("cria turno da Ana", shift("analyst-ana", "2026-10-15T08:00:00+00:00", "2026-10-15T16:00:00+00:00", "primary").status_code == 200)
    check("cria turno do Rui", shift("analyst-rui", "2026-10-14T08:00:00+00:00", "2026-10-14T16:00:00+00:00", "on_call").status_code == 200)

    # O frontend envia "/api/soc/shifts?" (query vazia) quando está em "Todos".
    for url in ("/api/soc/shifts", "/api/soc/shifts?"):
        r = client.get(url, headers=HEADERS)
        shifts = r.json().get("shifts", [])
        check(f"{url!r}: lista os turnos de todos os analistas, ordenados por início",
              r.status_code == 200 and [s["analyst_id"] for s in shifts] == ["analyst-rui", "analyst-ana"])

    shifts = client.get("/api/soc/shifts", headers=HEADERS).json()["shifts"]
    check("cada turno traz analyst_name e analyst_tier (a tabela do frontend usa-os)",
          [(s["analyst_name"], s["analyst_tier"]) for s in shifts] == [("Rui", 2), ("Ana", 1)])

    r = client.get("/api/soc/shifts?analyst_id=analyst-ana", headers=HEADERS)
    check("com analyst_id filtra só esse analista (e também traz o nome)",
          r.status_code == 200 and [(s["analyst_id"], s["analyst_name"]) for s in r.json()["shifts"]] == [("analyst-ana", "Ana")])

    r = client.get("/api/soc/shifts?analyst_id=analyst-inexistente", headers=HEADERS)
    check("analyst_id desconhecido -> 200 com lista vazia", r.status_code == 200 and r.json()["shifts"] == [])

    r = client.get("/api/soc/shifts?since=2026-10-15T00:00:00%2B00:00", headers=HEADERS)
    check("since exclui turnos que já terminaram antes",
          [s["analyst_id"] for s in r.json()["shifts"]] == ["analyst-ana"])
    r = client.get("/api/soc/shifts?until=2026-10-14T23:59:59%2B00:00", headers=HEADERS)
    check("until exclui turnos que só começam depois",
          [s["analyst_id"] for s in r.json()["shifts"]] == ["analyst-rui"])
    r = client.get("/api/soc/shifts?analyst_id=" + "x" * 129, headers=HEADERS)
    check("analyst_id demasiado longo -> 422", r.status_code == 422)

    legacy = main.incident_store.get_shifts_for_analyst("analyst-ana")
    check("get_shifts_for_analyst continua a funcionar (sem junção quebrada)",
          [s["analyst_id"] for s in legacy] == ["analyst-ana"])

    tmp.cleanup()

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")


if __name__ == "__main__":
    run()
