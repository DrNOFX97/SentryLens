"""
Testes do catálogo de eventos do Microsoft Defender (event_catalog.py):
DEFENDER_EVENTS é um catálogo à parte, consultado só quando o canal do
alerta é o do Defender. Sem I/O.
Ver docs/superpowers/specs/2026-10-26-defender-events-design.md.

Correr (a partir de scripts/):
    python test_defender_catalog.py
"""

import sys

from event_catalog import CRITICAL_EVENTS, DEFENDER_CHANNEL, DEFENDER_EVENTS, classify_alert

failures: list[str] = []

NAO_CATALOGADO = "Evento não catalogado"
GENERICA = "Investigar e tomar ação apropriada."
ROTINA = r"HKLM\SOFTWARE\Microsoft\Windows Defender\CoreService\WdConfigHash = 0xBCF68827"


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def run_catalogo() -> None:
    c = classify_alert(1116, DEFENDER_CHANNEL)
    check("1116 no canal do Defender -> high", c["severity"] == "high")
    check("1116 -> categoria protecao_endpoint", c["category"] == "protecao_endpoint")
    check("1116 -> nome amigável", c["friendly_name"] == "Defender: Malware Detected")

    esperado = {1117: "low", 1118: "high", 1119: "high", 5001: "high", 5008: "high"}
    for event_id, severidade in esperado.items():
        c = classify_alert(event_id, DEFENDER_CHANNEL)
        check(f"{event_id} -> {severidade}", c["severity"] == severidade)
        check(f"{event_id} tem recomendação própria",
              bool(c["recommendation"]) and c["recommendation"] != GENERICA)
    check("5001 -> nome amigável", classify_alert(5001, DEFENDER_CHANNEL)["friendly_name"] == "Defender: Real-Time Protection Disabled")
    check("5007 -> nome amigável", classify_alert(5007, DEFENDER_CHANNEL)["friendly_name"] == "Defender: Configuration Changed")

    check("o canal compara-se sem distinguir maiúsculas",
          classify_alert(1116, DEFENDER_CHANNEL.upper())["severity"] == "high")


def run_colisao_de_canal() -> None:
    check("1116 sem canal -> não catalogado", classify_alert(1116)["friendly_name"] == NAO_CATALOGADO)
    check("1116 no canal Application -> não catalogado", classify_alert(1116, "Application")["friendly_name"] == NAO_CATALOGADO)
    check("1000 no canal Application -> não catalogado", classify_alert(1000, "Application")["friendly_name"] == NAO_CATALOGADO)
    check("1000 no canal do Defender -> não catalogado (não está no catálogo)",
          classify_alert(1000, DEFENDER_CHANNEL)["friendly_name"] == NAO_CATALOGADO)


def run_compatibilidade() -> None:
    for args in ((4625,), (4625, "Security")):
        c = classify_alert(*args)
        check(f"classify_alert{args} igual ao comportamento atual",
              c["friendly_name"] == "Failed Logon" and c["severity"] == "high")
    check("classify_alert(None) continua não catalogado", classify_alert(None)["friendly_name"] == NAO_CATALOGADO)


def run_5007() -> None:
    def sev(eventdata) -> str:
        return classify_alert(5007, DEFENDER_CHANNEL, eventdata)["severity"]

    base = r"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring"
    check("5007 de rotina (WdConfigHash) -> info", sev({"newValue": ROTINA}) == "info")
    check("5007 a mexer em Exclusions -> high",
          sev({"newValue": r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\temp = 0x0"}) == "high")
    check("5007 DisableRealtimeMonitoring = 0x1 -> high", sev({"newValue": base + " = 0x1"}) == "high")
    check("5007 DisableRealtimeMonitoring = 0x0 -> info", sev({"newValue": base + " = 0x0"}) == "info")
    for valor in (None, {}, {"newValue": None}, "x", 42):
        check(f"5007 com eventdata={valor!r} -> info, sem exceção", sev(valor) == "info")


def run_disjuntos() -> None:
    # Protege model_registry.catalog_sha256 e o event_id_encoded do ML.
    check("DEFENDER_EVENTS e CRITICAL_EVENTS são disjuntos",
          set(DEFENDER_EVENTS) & set(CRITICAL_EVENTS) == set())


run_catalogo()
run_colisao_de_canal()
run_compatibilidade()
run_5007()
run_disjuntos()

if failures:
    print(f"\n[FALHOU] {len(failures)} caso(s) falharam")
    sys.exit(1)
print("\n[OK] Todos os testes passaram")
