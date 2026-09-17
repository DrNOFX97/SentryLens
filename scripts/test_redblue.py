"""
Testes de regressão do motor de correlação Red vs Blue (Fase 11, Onda 1),
em duas partes:
  1. build_redblue_report() isolada (sem Wazuh, sem HTTP) — casos de
     correspondência/janela/exclusão.
  2. GET /api/redblue/metrics via TestClient (acrescentado na Task 4).

Segue o estilo de test_with_mock.py: script standalone, check()/[OK]/
[FALHOU], sys.exit(1) em caso de falha.

Correr:
    python test_redblue.py
"""

import sys

from attack_scenarios import SCENARIOS
from redblue_correlator import build_redblue_report

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def attack(scenario: str, target: str, timestamp: str, status: str = "launched") -> dict:
    return {"timestamp": timestamp, "scenario": scenario, "target": target, "tool": "x", "status": status, "details": {}}


def ml_result(timestamp: str, agent_ip: str, event_id: int, rule_flagged: bool = False, ml_is_anomaly: bool = False) -> dict:
    return {
        "timestamp": timestamp, "agent_ip": agent_ip, "windows_event_id": event_id,
        "rule_flagged": rule_flagged, "ml_is_anomaly": ml_is_anomaly,
    }


def run() -> None:
    # --- Caso 1: alerta correspondente dentro da janela -> detected=True ---
    attacks = [attack("brute_force_rdp", "192.168.1.20", "2026-09-14T10:00:00+00:00")]
    results = [ml_result("2026-09-14T10:00:10+00:00", "192.168.1.20", 4625, rule_flagged=True)]
    report = build_redblue_report(attacks, results, SCENARIOS)
    check("1 tentativa processada", len(report["attempts"]) == 1)
    a = report["attempts"][0]
    check("caso 1: detected=True", a["detected"] is True)
    check("caso 1: detected_by='rule'", a["detected_by"] == "rule")
    check("caso 1: mttd_seconds=10.0", a["mttd_seconds"] == 10.0)
    check("caso 1: mitre_technique vem do SCENARIOS", a["mitre_technique"] == "T1110")

    # --- Caso 2: sem qualquer alerta correspondente -> detected=False ---
    attacks2 = [attack("smb_enum", "192.168.1.21", "2026-09-14T11:00:00+00:00")]
    report2 = build_redblue_report(attacks2, [], SCENARIOS)
    a2 = report2["attempts"][0]
    check("caso 2: detected=False", a2["detected"] is False)
    check("caso 2: detected_by='none'", a2["detected_by"] == "none")
    check("caso 2: mttd_seconds=None", a2["mttd_seconds"] is None)

    # --- Caso 3: dois ataques próximos, janela do 1º cortada pelo 2º ---
    attacks3 = [
        attack("smb_enum", "192.168.1.22", "2026-09-14T12:00:00+00:00"),
        attack("blank_password_check", "192.168.1.22", "2026-09-14T12:01:00+00:00"),  # +60s
    ]
    # alerta de smb_enum chega aos +90s -> fora da janela do 1º ataque (cortada aos +60s pelo 2º)
    results3 = [ml_result("2026-09-14T12:01:30+00:00", "192.168.1.22", 5140)]
    report3 = build_redblue_report(attacks3, results3, SCENARIOS)
    check("caso 3: 1º ataque não detetado (janela cortada pelo 2º ataque)",
          report3["attempts"][0]["detected"] is False)

    # --- Caso 4: IP do agente não bate com o alvo -> não conta ---
    attacks4 = [attack("smb_enum", "192.168.1.23", "2026-09-14T13:00:00+00:00")]
    results4 = [ml_result("2026-09-14T13:00:05+00:00", "10.0.0.99", 5140)]
    report4 = build_redblue_report(attacks4, results4, SCENARIOS)
    check("caso 4: IP errado não conta como deteção", report4["attempts"][0]["detected"] is False)

    # --- Caso 5: Event ID fora de scenario.event_ids -> não conta ---
    attacks5 = [attack("smb_enum", "192.168.1.24", "2026-09-14T14:00:00+00:00")]
    results5 = [ml_result("2026-09-14T14:00:05+00:00", "192.168.1.24", 4625)]  # 4625 não é event_id de smb_enum
    report5 = build_redblue_report(attacks5, results5, SCENARIOS)
    check("caso 5: Event ID fora do cenário não conta", report5["attempts"][0]["detected"] is False)

    # --- Caso 6: status != "launched" -> not_executed, fora de attempts/overall ---
    attacks6 = [attack("smb_enum", "192.168.1.25", "2026-09-14T15:00:00+00:00", status="skipped")]
    report6 = build_redblue_report(attacks6, [], SCENARIOS)
    check("caso 6: entrada skipped vai para not_executed", len(report6["not_executed"]) == 1)
    check("caso 6: entrada skipped não entra em attempts", report6["attempts"] == [])
    check("caso 6: overall.total_attempts=0", report6["overall"]["total_attempts"] == 0)

    # --- Caso 7: nome de cenário desconhecido -> unknown_scenario ---
    attacks7 = [attack("cenario_inexistente", "192.168.1.26", "2026-09-14T16:00:00+00:00")]
    report7 = build_redblue_report(attacks7, [], SCENARIOS)
    check("caso 7: cenário desconhecido vai para unknown_scenario", len(report7["unknown_scenario"]) == 1)
    check("caso 7: cenário desconhecido não entra em attempts", report7["attempts"] == [])

    # --- Caso 8: entradas vazias -> estrutura vazia bem formada, nunca lança ---
    empty_report = build_redblue_report([], [], SCENARIOS)
    check("caso 8: attempts=[] com input vazio", empty_report["attempts"] == [])
    check("caso 8: by_scenario={} com input vazio", empty_report["by_scenario"] == {})
    check("caso 8: overall com zeros e mttd None", empty_report["overall"] == {
        "total_attempts": 0, "detected": 0, "coverage_rate": 0.0, "avg_mttd_seconds": None,
    })

    # --- Agregação por cenário ---
    check("by_scenario['brute_force_rdp'] agrega o caso 1 corretamente", report["by_scenario"]["brute_force_rdp"] == {
        "attempts": 1, "detected": 1, "detected_by_rule": 1, "detected_by_ml": 0, "detected_by_both": 0,
        "coverage_rate": 1.0, "avg_mttd_seconds": 10.0,
    })

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")
    sys.exit(0)


if __name__ == "__main__":
    run()
