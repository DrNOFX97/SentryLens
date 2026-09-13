"""
Testes de regressão para os thresholds de sistema (CPU/RAM/disco/rede) —
`system_monitor.THRESHOLDS` / `system_monitor._current_metric_levels()` — e
para o endpoint que os expõe, `GET /api/system/thresholds`.

Não precisa do laboratório Wazuh ligado (a parte de `system_monitor` é pura
lógica local; a parte do endpoint usa `TestClient` como os outros testes do
projeto).

Mesmo estilo dos outros ficheiros de teste standalone: função
check(label, condition), print [OK]/[FALHOU] por caso, sys.exit(1) no fim
se houver falhas.

Correr:
    cd scripts
    python test_system_monitor.py
"""

import os
import sys

import system_monitor
from system_monitor import THRESHOLDS, _current_metric_levels

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def run_thresholds_unit_tests() -> None:
    # --- THRESHOLDS tem as 4 chaves, cada uma com warning/critical numéricos ---
    for metric in ("cpu", "ram", "disk", "network"):
        check(f"THRESHOLDS tem chave '{metric}'", metric in THRESHOLDS)
        check(
            f"THRESHOLDS['{metric}'] tem 'warning' e 'critical' numéricos",
            isinstance(THRESHOLDS[metric].get("warning"), (int, float))
            and isinstance(THRESHOLDS[metric].get("critical"), (int, float)),
        )

    # --- CPU (novo nesta fase): quanto mais alto pior ---
    cpu_critico = _current_metric_levels(
        {"cpu": {"usage_percent": 97}, "ram": {"usage_percent": 10}, "disk": [], "network_speed": None}
    )
    check("CPU a 97% (> critical=95) dá 'critico'", cpu_critico.get("cpu") == "critico")

    cpu_aviso = _current_metric_levels(
        {"cpu": {"usage_percent": 82}, "ram": {"usage_percent": 10}, "disk": [], "network_speed": None}
    )
    check("CPU a 82% (entre warning=80 e critical=95) dá 'aviso'", cpu_aviso.get("cpu") == "aviso")

    cpu_normal = _current_metric_levels(
        {"cpu": {"usage_percent": 50}, "ram": {"usage_percent": 10}, "disk": [], "network_speed": None}
    )
    check("CPU a 50% (< warning=80) dá None", cpu_normal.get("cpu") is None)

    # --- RAM (lógica pré-existente, sem cobertura até agora) ---
    ram_critico = _current_metric_levels(
        {"cpu": {"usage_percent": 10}, "ram": {"usage_percent": 96}, "disk": [], "network_speed": None}
    )
    check("RAM a 96% (> critical=95) dá 'critico'", ram_critico.get("ram") == "critico")

    ram_aviso = _current_metric_levels(
        {"cpu": {"usage_percent": 10}, "ram": {"usage_percent": 90}, "disk": [], "network_speed": None}
    )
    check("RAM a 90% (entre warning=85 e critical=95) dá 'aviso'", ram_aviso.get("ram") == "aviso")

    ram_normal = _current_metric_levels(
        {"cpu": {"usage_percent": 10}, "ram": {"usage_percent": 50}, "disk": [], "network_speed": None}
    )
    check("RAM a 50% (< warning=85) dá None", ram_normal.get("ram") is None)

    # --- Disco: 2 discos, um acima do threshold, outro normal ---
    disk_levels = _current_metric_levels(
        {
            "cpu": {"usage_percent": 10},
            "ram": {"usage_percent": 10},
            "disk": [
                {"mountpoint": "C:\\", "usage_percent": 95},
                {"mountpoint": "D:\\", "usage_percent": 20},
            ],
            "network_speed": None,
        }
    )
    check("Disco: existe chave 'disk:C:\\'", "disk:C:\\" in disk_levels)
    check("Disco: existe chave 'disk:D:\\'", "disk:D:\\" in disk_levels)
    check("Disco C:\\ a 95% (> critical=90) dá 'critico'", disk_levels.get("disk:C:\\") == "critico")
    check("Disco D:\\ a 20% (normal) dá None", disk_levels.get("disk:D:\\") is None)

    # --- Rede: inverso de CPU/RAM/disco (quanto mais baixo pior) ---
    rede_critica = _current_metric_levels(
        {
            "cpu": {"usage_percent": 10},
            "ram": {"usage_percent": 10},
            "disk": [],
            "network_speed": {"download_mbps": 300, "upload_mbps": 300},
        }
    )
    check(
        "Rede a 300 Mbps (< critical=500) dá 'critico' em download e upload",
        rede_critica.get("network_download") == "critico" and rede_critica.get("network_upload") == "critico",
    )

    rede_normal = _current_metric_levels(
        {
            "cpu": {"usage_percent": 10},
            "ram": {"usage_percent": 10},
            "disk": [],
            "network_speed": {"download_mbps": 900, "upload_mbps": 900},
        }
    )
    check(
        "Rede a 900 Mbps (> warning=700) dá None em download e upload",
        rede_normal.get("network_download") is None and rede_normal.get("network_upload") is None,
    )

    # --- network_speed ausente não deve rebentar nem gerar entradas de rede ---
    sem_network_speed_none = _current_metric_levels(
        {"cpu": {"usage_percent": 10}, "ram": {"usage_percent": 10}, "disk": [], "network_speed": None}
    )
    check(
        "network_speed=None não gera 'network_download'/'network_upload'",
        "network_download" not in sem_network_speed_none and "network_upload" not in sem_network_speed_none,
    )

    sem_network_speed_key = _current_metric_levels(
        {"cpu": {"usage_percent": 10}, "ram": {"usage_percent": 10}, "disk": []}
    )
    check(
        "network_speed em falta (sem a chave) não rebenta e não gera entradas de rede",
        "network_download" not in sem_network_speed_key and "network_upload" not in sem_network_speed_key,
    )


def run_endpoint_tests() -> None:
    os.environ.setdefault("SENTRYLENS_API_KEY", "chave-valida-de-teste")

    from fastapi.testclient import TestClient

    import main

    # Desliga o startup event (loop de monitorização de sistema da Fase 2) —
    # mesmo padrão dos outros ficheiros de teste.
    main.app.router.on_startup.clear()

    client_com_key = TestClient(main.app, headers={"X-API-Key": os.environ["SENTRYLENS_API_KEY"]})
    client_sem_key = TestClient(main.app)

    resp_ok = client_com_key.get("/api/system/thresholds")
    check("GET /api/system/thresholds com X-API-Key correto devolve 200", resp_ok.status_code == 200)

    body = resp_ok.json() if resp_ok.status_code == 200 else {}
    for metric in ("cpu", "ram", "disk", "network"):
        check(f"Corpo JSON tem chave '{metric}'", metric in body)
        entry = body.get(metric, {})
        check(
            f"'{metric}' tem 'warning' e 'critical' no corpo JSON",
            isinstance(entry, dict) and "warning" in entry and "critical" in entry,
        )

    resp_sem_key = client_sem_key.get("/api/system/thresholds")
    check(
        "GET /api/system/thresholds sem X-API-Key devolve 401",
        resp_sem_key.status_code == 401,
    )


def run() -> None:
    run_thresholds_unit_tests()
    run_endpoint_tests()

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")
    sys.exit(0)


if __name__ == "__main__":
    run()
