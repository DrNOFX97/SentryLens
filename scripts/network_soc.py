"""
Resumos puros para os 3 painéis dedicados de rede (R6, Network SOC: "Live
Traffic", "Network Detections", "PCAP / Evidence") — ver
docs/superpowers/specs/2026-10-07-r6-network-soc-design.md.

Reaproveita os dados já recolhidos por network_monitor.py (pacotes) e
network_detections.py (padrões) sem reimplementar a captura nem a
deteção — mesma fonte que GET /api/redblue/network, só resumida para
painéis próprios. Cada função é pura (lista de dicts já parseados -> dict
de resumo), nunca lança exceção sobre dados malformados (pacotes/deteções
sem os campos esperados são ignorados individualmente), e limita sempre o
tamanho da resposta (top-N / "recent" capeado) mesmo que o buffer de
origem seja grande — um painel nunca devolve um objeto de tamanho
arbitrário.
"""

from collections import Counter

TOP_N = 10
RECENT_DETECTIONS_MAX = 50

EVIDENCE_NOTE = (
    "Evidência de metadados de rede (tipo, origem, destino, porta/detalhe), "
    "persistida em JSONL (historico/.../AAAA-MM-DD-network-detections.jsonl). "
    "Não é uma captura PCAP real nem inclui payload — network_monitor.py só lê "
    "os campos de cabeçalho exportados pelo tshark (-T fields: timestamps, "
    "IPs, portas, protocolo, flags TCP), nunca o conteúdo dos pacotes."
)


def summarize_packets(packets: list[dict]) -> dict:
    """
    Painel "Live Traffic": visão agregada do buffer de pacotes ao vivo —
    total, janela temporal coberta, contagem por protocolo e "top talkers"/
    portas de destino mais vistos (top 10 cada, nunca a lista completa de
    pacotes). Lista vazia/None -> zeros e listas vazias (nunca lança).
    """
    valid = [p for p in (packets or []) if isinstance(p, dict) and p.get("src_ip")]
    if not valid:
        return {
            "total": 0, "window_start": None, "window_end": None,
            "by_protocol": {}, "top_talkers": [], "top_ports": [],
        }

    timestamps = sorted(p["timestamp"] for p in valid if p.get("timestamp"))
    protocol_counts = Counter(p.get("protocol") or "?" for p in valid)
    talker_counts = Counter(p["src_ip"] for p in valid)
    port_counts = Counter(p["dst_port"] for p in valid if p.get("dst_port") is not None)

    return {
        "total": len(valid),
        "window_start": timestamps[0] if timestamps else None,
        "window_end": timestamps[-1] if timestamps else None,
        "by_protocol": dict(protocol_counts),
        "top_talkers": [{"src_ip": ip, "packets": n} for ip, n in talker_counts.most_common(TOP_N)],
        "top_ports": [{"port": port, "packets": n} for port, n in port_counts.most_common(TOP_N)],
    }


def summarize_detections(live_detections: list[dict], history: list[dict]) -> dict:
    """
    Painel "Network Detections": deteções "agora" (recomputadas sobre a
    janela curta mais recente, mesma fonte que detections em
    GET /api/redblue/network) vs histórico acumulado desde o arranque do
    backend (network_detection_buffer) — mesma distinção de
    get_redblue_network em main.py. "recent" é o histórico mais recente
    primeiro, capeado a RECENT_DETECTIONS_MAX (nunca a lista completa).
    """
    history_valid = [d for d in (history or []) if isinstance(d, dict)]
    live_valid = [d for d in (live_detections or []) if isinstance(d, dict)]
    by_type = Counter(d.get("type") or "?" for d in history_valid)
    recent = list(reversed(history_valid))[:RECENT_DETECTIONS_MAX]
    return {
        "live_count": len(live_valid),
        "history_count": len(history_valid),
        "by_type": dict(by_type),
        "recent": recent,
    }


def build_evidence_report(entries: list[dict], configured: bool) -> dict:
    """
    Painel "PCAP / Evidence": envolve as entradas já lidas de
    history_store.read_network_detection_history com o aviso fixo de que
    isto é evidência de metadados persistida, nunca uma exportação PCAP
    real (ver ruling 2 da spec R6). Nunca inventa entradas — lista vazia é
    um resultado válido ("Sem dados").
    """
    entries_valid = entries or []
    return {
        "configured": configured,
        "entries": entries_valid,
        "total": len(entries_valid),
        "payload_capture": False,
        "note": EVIDENCE_NOTE,
    }
