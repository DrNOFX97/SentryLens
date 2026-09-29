"""
Deteção de padrões suspeitos em tráfego de rede (Fase 11, Onda 2), a partir
só de metadados de pacotes (sem payload) — port scan, força bruta e picos de
volume, com limiares fixos e explícitos (mesmo espírito de event_catalog.py:
regras simples, sem modelo a treinar).

Módulo puro: recebe a lista de pacotes já parseados por network_monitor.py
(cada um com timestamp/src_ip/dst_ip/src_port/dst_port/protocol/length) e
devolve as deteções encontradas na janela mais recente de cada regra. Nunca
lança exceção sobre dados malformados — pacotes sem os campos mínimos são
ignorados individualmente.

Limitação deliberada: sem rastreio de sessão/ligação TCP (só há pacotes
soltos), "brute_force" conta pacotes por (src_ip, dst_ip, dst_port) como
proxy de tentativas de ligação — impreciso para TCP real (uma única ligação
gera vários pacotes), mas suficiente para o objetivo de laboratório: expor
um padrão de repetição óbvio, não medir tentativas com precisão forense.
"""

from datetime import datetime, timedelta, timezone

RULES = {
    "port_scan": {"distinct_ports": 15, "window_seconds": 30},
    "brute_force": {"connections": 20, "window_seconds": 30},
    "volume_spike": {"packets": 500, "window_seconds": 10},
}


def _parse_timestamp(raw_timestamp: str | None) -> datetime | None:
    """Mesma convenção do resto do projeto (redblue_correlator.py/lifecycle.py):
    aceita o sufixo 'Z', assume UTC quando não há fuso indicado, devolve
    None em vez de lançar exceção para timestamps malformados."""
    if not raw_timestamp or not isinstance(raw_timestamp, str):
        return None
    normalized = raw_timestamp.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def detect_network_anomalies(packets: list[dict], rules: dict = RULES) -> list[dict]:
    """Analisa a lista de pacotes já parseados e devolve as deteções
    encontradas na janela mais recente de cada regra (a janela termina no
    timestamp mais recente presente em `packets`). Nunca lança exceção."""
    parsed: list[tuple[datetime, dict]] = []
    for p in packets or []:
        if not isinstance(p, dict):
            continue
        ts = _parse_timestamp(p.get("timestamp"))
        if ts is None or not p.get("src_ip") or not p.get("dst_ip"):
            continue
        parsed.append((ts, p))
    if not parsed:
        return []

    now = max(ts for ts, _ in parsed)
    detections: list[dict] = []

    # --- port_scan: mesmo par (src_ip, dst_ip), muitas portas de destino distintas ---
    cfg = rules["port_scan"]
    window_start = now - timedelta(seconds=cfg["window_seconds"])
    ports_by_pair: dict[tuple, set] = {}
    for ts, p in parsed:
        if ts < window_start or p.get("dst_port") is None:
            continue
        ports_by_pair.setdefault((p["src_ip"], p["dst_ip"]), set()).add(p["dst_port"])
    for (src_ip, dst_ip), ports in ports_by_pair.items():
        if len(ports) >= cfg["distinct_ports"]:
            detections.append({
                "type": "port_scan", "src_ip": src_ip, "dst_ip": dst_ip,
                "timestamp": now.isoformat(), "detail": {"distinct_ports": len(ports)},
            })

    # --- brute_force: mesmo trio (src_ip, dst_ip, dst_port), muitos pacotes ---
    cfg = rules["brute_force"]
    window_start = now - timedelta(seconds=cfg["window_seconds"])
    counts: dict[tuple, int] = {}
    for ts, p in parsed:
        if ts < window_start or p.get("dst_port") is None:
            continue
        key = (p["src_ip"], p["dst_ip"], p["dst_port"])
        counts[key] = counts.get(key, 0) + 1
    for (src_ip, dst_ip, dst_port), count in counts.items():
        if count >= cfg["connections"]:
            detections.append({
                "type": "brute_force", "src_ip": src_ip, "dst_ip": dst_ip,
                "timestamp": now.isoformat(), "detail": {"dst_port": dst_port, "connections": count},
            })

    # --- volume_spike: mesmo src_ip, muitos pacotes ---
    cfg = rules["volume_spike"]
    window_start = now - timedelta(seconds=cfg["window_seconds"])
    packet_counts: dict[str, int] = {}
    for ts, p in parsed:
        if ts < window_start:
            continue
        packet_counts[p["src_ip"]] = packet_counts.get(p["src_ip"], 0) + 1
    for src_ip, count in packet_counts.items():
        if count >= cfg["packets"]:
            detections.append({
                "type": "volume_spike", "src_ip": src_ip, "dst_ip": None,
                "timestamp": now.isoformat(), "detail": {"packets": count},
            })

    return detections
