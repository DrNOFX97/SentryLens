"""Testa GET /api/redblue/attack-log contra o attack_log.jsonl REAL
(scripts/attack_log.jsonl) — sem mocks: a rota só lê um ficheiro e um dict
de cenários, por isso não há nada para simular."""

import os
import sys

os.environ.setdefault("SENTRYLENS_API_KEY", "test-key-attack-log")

from fastapi.testclient import TestClient

import main
from attack_scenarios import SCENARIOS
from feature_extractor import load_attack_log

main.app.router.on_startup.clear()
client = TestClient(main.app)
HEADERS = {"X-API-Key": os.environ["SENTRYLENS_API_KEY"]}

failures = 0


def check(name: str, condition: bool) -> None:
    global failures
    if condition:
        print(f"[OK   ] {name}")
    else:
        failures += 1
        print(f"[FALHOU] {name}")


resp = client.get("/api/redblue/attack-log")
check("sem X-API-Key devolve 401", resp.status_code == 401)

resp = client.get("/api/redblue/attack-log", headers=HEADERS)
check("com X-API-Key devolve 200", resp.status_code == 200)
body = resp.json()

real_entries = load_attack_log(main.ATTACK_LOG_PATH)
check("entries é exatamente o conteúdo do attack_log.jsonl real", body["entries"] == real_entries)
check("total == len(entries)", body["total"] == len(real_entries))
check("scenarios tem exatamente os cenários de attack_scenarios.SCENARIOS", set(body["scenarios"]) == set(SCENARIOS))
check(
    "cada cenário expõe o MITRE real de SCENARIOS",
    all(
        body["scenarios"][name]["mitre_technique"] == s.mitre_technique
        and body["scenarios"][name]["mitre_tactic"] == s.mitre_tactic
        for name, s in SCENARIOS.items()
    ),
)
check(
    "nenhum cenário expõe build_command (não serializável / interno)",
    all("build_command" not in v for v in body["scenarios"].values()),
)

if failures:
    print(f"\n[FALHOU] {failures} caso(s)")
    sys.exit(1)
print("\n[OK] Todos os testes passaram")
