"""
Push de pacotes e deteções de rede novos via WebSocket (/ws/network),
Fase 11 (Onda 2). Mesmo padrão estrutural de websocket_alerts.py: lê a
fonte (aqui, o ficheiro de captura na VM via SSH em vez do Wazuh Indexer),
identifica o que é novo, difunde por WebSocket, devolve a lista para os
testes conseguirem verificar sem WebSockets reais.
"""

from __future__ import annotations

import asyncio
import logging
from collections import deque
from datetime import datetime, timezone

from fastapi import WebSocket

from network_detections import detect_network_anomalies

logger = logging.getLogger("sentrylens.network_monitor")

PACKET_BUFFER_MAX = 2000

_PROTO_NAMES = {"1": "ICMP", "6": "TCP", "17": "UDP"}


class NetworkConnectionManager:
    """Gere as ligações WebSocket ativas ao /ws/network."""

    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict) -> None:
        dead: list[WebSocket] = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead.append(connection)
        for connection in dead:
            self.disconnect(connection)


def _safe_int(raw: str) -> int | None:
    """
    int() sem lançar: um campo CSV do tshark não-numérico mas presente
    (raro, mas visto em capturas reais com campos truncados/corrompidos)
    não pode derrubar o resto do batch de linhas de _poll_once — devolve
    None nesse caso em vez de deixar o ValueError propagar.
    """
    try:
        return int(raw)
    except ValueError:
        return None


def _parse_fields_line(line: str) -> dict | None:
    """
    Faz parse de uma linha CSV produzida pelo tshark (-T fields -E
    separator=, -E quote=n, exatamente 9 campos, na ordem:
    frame.time_epoch,ip.src,ip.dst,ip.proto,frame.len,tcp.srcport,
    tcp.dstport,udp.srcport,udp.dstport — ver scripts/deploy/sentrylens-tshark.service).
    Devolve None (nunca lança) se a linha não tiver os 9 campos ou os
    campos obrigatórios (timestamp/src_ip/dst_ip) vierem vazios/inválidos.
    Campos numéricos opcionais (portas, comprimento) que vierem presentes
    mas não-numéricos não fazem a linha inteira falhar — ficam None (ou,
    no caso do comprimento, 0), em vez de lançar ValueError sobre o resto
    do batch em _poll_once.
    """
    fields = line.rstrip("\n").split(",")
    if len(fields) != 9:
        return None
    epoch, src_ip, dst_ip, proto, length, tcp_src, tcp_dst, udp_src, udp_dst = fields
    if not epoch or not src_ip or not dst_ip:
        return None
    try:
        ts = datetime.fromtimestamp(float(epoch), tz=timezone.utc)
    except ValueError:
        return None
    src_port = _safe_int(tcp_src) if tcp_src else (_safe_int(udp_src) if udp_src else None)
    dst_port = _safe_int(tcp_dst) if tcp_dst else (_safe_int(udp_dst) if udp_dst else None)
    return {
        "timestamp": ts.isoformat(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": _PROTO_NAMES.get(proto, proto or "?"),
        "length": _safe_int(length) if length else 0,
        "src_port": src_port,
        "dst_port": dst_port,
    }


async def _poll_once(
    ssh_client,
    manager: NetworkConnectionManager,
    packet_buffer: deque,
    offset_state: dict,
    seen_detections: set,
    remote_path: str,
    detection_buffer: deque,
) -> tuple[list[dict], list[dict]]:
    """
    Uma iteração do polling: lê as linhas novas do ficheiro de captura via
    SSH, faz parse de cada uma, acrescenta ao buffer, corre a deteção sobre
    o buffer atual, difunde pacotes e deteções novos por /ws/network, e
    devolve (pacotes_novos, deteções_novas) para os testes.

    Deduplicação de deteções por chave (tipo, src_ip, dst_ip, minuto) —
    evita repetir a mesma deteção a cada poll de 5s enquanto o padrão
    persiste, mesmo espírito do seen_ids em websocket_alerts.py.

    As deteções novas deste poll são também acumuladas em detection_buffer
    (bounded, mantido por quem chama — ver main.py), com o timestamp
    original em que foram vistas — ao contrário de all_detections acima
    (recomputado sobre o buffer de pacotes efémero), detection_buffer não
    perde deteções antigas só porque o "agora" do buffer de pacotes avançou.
    Quem precisa de correlação histórica (ex: /api/redblue/metrics) deve ler
    detection_buffer, nunca recomputar detect_network_anomalies a pedido.
    """
    raw_new, new_offset = await ssh_client.read_new_lines(remote_path, offset_state.get("offset", 0))
    offset_state["offset"] = new_offset

    new_packets: list[dict] = []
    for line in raw_new.splitlines():
        packet = _parse_fields_line(line)
        if packet is None:
            continue
        packet_buffer.append(packet)
        new_packets.append(packet)

    if new_packets and manager.active_connections:
        for packet in new_packets:
            await manager.broadcast({"type": "packet", "packet": packet})

    all_detections = detect_network_anomalies(list(packet_buffer))
    new_detections: list[dict] = []
    for det in all_detections:
        key = (det["type"], det["src_ip"], det["dst_ip"], det["timestamp"][:16])
        if key in seen_detections:
            continue
        seen_detections.add(key)
        new_detections.append(det)

    if len(seen_detections) > 5000:
        seen_detections.clear()

    detection_buffer.extend(new_detections)

    if new_detections and manager.active_connections:
        for det in new_detections:
            await manager.broadcast({"type": "network_detection", "detection": det})

    return new_packets, new_detections


async def network_poll_loop(
    ssh_client,
    manager: NetworkConnectionManager,
    packet_buffer: deque,
    remote_path: str,
    detection_buffer: deque,
    interval_seconds: int = 5,
) -> None:
    """Mesmo padrão de alert_poll_loop: try/except por iteração, nunca mata o loop."""
    offset_state: dict = {"offset": 0}
    seen_detections: set = set()
    while True:
        try:
            await _poll_once(
                ssh_client, manager, packet_buffer, offset_state, seen_detections, remote_path, detection_buffer,
            )
        except Exception:
            logger.exception("Falha ao fazer polling de rede para o WebSocket")
        await asyncio.sleep(interval_seconds)
