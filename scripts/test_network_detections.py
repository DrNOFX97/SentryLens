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


def pkt(
    offset_seconds: float, src_ip: str, dst_ip: str, dst_port: int | None,
    syn: bool | None = None, ack: bool | None = None, src_port: int = 50000,
) -> dict:
    ts = BASE + timedelta(seconds=offset_seconds)
    packet = {
        "timestamp": ts.isoformat(), "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": src_port, "dst_port": dst_port, "protocol": "TCP", "length": 66,
    }
    # syn/ack None = captura antiga (9 colunas), sem flags TCP -> chaves ausentes.
    if syn is not None:
        packet["tcp_syn"] = syn
        packet["tcp_ack"] = bool(ack)
    return packet


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

    # --- Caso 9: scan real (200 SYN do atacante + 200 RST/ACK de resposta do alvo,
    # captura de 2026-09-29): só o atacante é port_scan e as respostas do alvo
    # não geram um brute_force invertido alvo -> atacante ---
    kali, vm = "192.168.1.170", "192.168.1.143"
    packets_real_scan = []
    for i in range(200):
        packets_real_scan.append(pkt(i * 0.001, kali, vm, i + 1, syn=True, ack=False, src_port=57789))
        packets_real_scan.append(pkt(i * 0.001 + 0.0005, vm, kali, 57789, syn=False, ack=True, src_port=i + 1))
    dets_real = detect_network_anomalies(packets_real_scan)
    scans = [d for d in dets_real if d["type"] == "port_scan"]
    check("scan real: um único port_scan, do atacante para o alvo",
          len(scans) == 1 and scans[0]["src_ip"] == kali and scans[0]["dst_ip"] == vm)
    check("scan real: 200 portas distintas contadas só pelos SYN", scans[0]["detail"]["distinct_ports"] == 200)
    check("scan real: respostas RST/ACK do alvo não geram brute_force invertido",
          not any(d["type"] == "brute_force" for d in dets_real))

    # --- Caso 10: SYN+ACK (resposta de serviço aberto) não conta como tentativa ---
    packets_synack = [pkt(i * 0.5, vm, kali, 40000, syn=True, ack=True) for i in range(30)]
    check("SYN+ACK repetido não conta para brute_force",
          not any(d["type"] == "brute_force" for d in detect_network_anomalies(packets_synack)))

    # --- Caso 11: SYN puro repetido continua a ser brute_force com flags presentes ---
    packets_syn_bf = [pkt(i * 0.5, kali, vm, 3389, syn=True, ack=False) for i in range(20)]
    check("20 SYN à mesma porta com flags continuam a ser brute_force",
          any(d["type"] == "brute_force" for d in detect_network_anomalies(packets_syn_bf)))

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")
    sys.exit(0)


if __name__ == "__main__":
    run()
