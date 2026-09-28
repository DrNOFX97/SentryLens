"""
Testes de regressão de scripts/network_detections.py (Fase 11, Onda 2) —
deteção de padrões suspeitos (port scan, força bruta, pico de volume) a
partir só de metadados de pacotes. Funções puras, sem I/O.

Correr:
    python test_network_detections.py
"""

import sys
from datetime import datetime, timedelta, timezone

from network_detections import RULES, detect_network_anomalies

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


BASE = datetime(2026, 9, 28, 12, 0, 0, tzinfo=timezone.utc)


def pkt(offset_seconds: float, src_ip: str, dst_ip: str, dst_port: int | None) -> dict:
    ts = BASE + timedelta(seconds=offset_seconds)
    return {
        "timestamp": ts.isoformat(), "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": 50000, "dst_port": dst_port, "protocol": "TCP", "length": 66,
    }


def run() -> None:
    # --- Caso 1: port scan (>= 15 portas distintas do mesmo par src/dst na janela) ---
    packets_scan = [pkt(i, "192.168.1.170", "192.168.1.20", 4000 + i) for i in range(16)]
    dets = detect_network_anomalies(packets_scan)
    check("port scan detetado com 16 portas distintas", any(d["type"] == "port_scan" for d in dets))
    scan_det = next(d for d in dets if d["type"] == "port_scan")
    check(
        "port scan regista src_ip/dst_ip corretos",
        scan_det["src_ip"] == "192.168.1.170" and scan_det["dst_ip"] == "192.168.1.20",
    )

    # --- Caso 2: abaixo do limiar -> sem deteção ---
    packets_ok = [pkt(i, "192.168.1.170", "192.168.1.20", 4000 + i) for i in range(5)]
    check("sem deteção abaixo do limiar de portas", detect_network_anomalies(packets_ok) == [])

    # --- Caso 3: brute force (>= 20 pacotes mesmo par src/dst/porta na janela) ---
    packets_bf = [pkt(i * 0.5, "192.168.1.170", "192.168.1.21", 3389) for i in range(20)]
    dets_bf = detect_network_anomalies(packets_bf)
    check("brute force detetado com 20 ligações à mesma porta", any(d["type"] == "brute_force" for d in dets_bf))

    # --- Caso 4: volume spike (>= 500 pacotes do mesmo src_ip na janela) ---
    packets_vol = [pkt(i * 0.01, "192.168.1.170", "192.168.1.22", 445) for i in range(500)]
    dets_vol = detect_network_anomalies(packets_vol)
    check("volume spike detetado com 500 pacotes", any(d["type"] == "volume_spike" for d in dets_vol))

    # --- Caso 5: pacotes fora da janela (demasiado antigos) não contam ---
    packets_old_and_new = (
        [pkt(i, "192.168.1.170", "192.168.1.23", 4000 + i) for i in range(16)]
        + [pkt(-3600 + i, "192.168.1.170", "192.168.1.23", 5000 + i) for i in range(20)]
    )
    dets_window = detect_network_anomalies(packets_old_and_new)
    scan_det_window = next(d for d in dets_window if d["type"] == "port_scan")
    check("pacotes fora da janela não contam para o limiar", scan_det_window["detail"]["distinct_ports"] == 16)

    # --- Caso 6: pacote malformado (sem src_ip) é ignorado sem rebentar ---
    packets_malformed = [{"timestamp": BASE.isoformat(), "dst_ip": "192.168.1.20", "dst_port": 80}]
    check("pacote sem src_ip é ignorado sem lançar exceção", detect_network_anomalies(packets_malformed) == [])

    # --- Caso 7: lista vazia -> [] ---
    check("lista vazia devolve []", detect_network_anomalies([]) == [])

    # --- Caso 8: limiares customizados via parâmetro rules ---
    custom_rules = {**RULES, "port_scan": {"distinct_ports": 3, "window_seconds": 30}}
    packets_small_scan = [pkt(i, "192.168.1.170", "192.168.1.24", 4000 + i) for i in range(4)]
    check(
        "limiar customizado deteta scan pequeno que o default ignoraria",
        any(d["type"] == "port_scan" for d in detect_network_anomalies(packets_small_scan, rules=custom_rules)),
    )

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")
    sys.exit(0)


if __name__ == "__main__":
    run()
