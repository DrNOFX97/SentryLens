"""
Testes de regressão de scripts/network_monitor.py (Fase 11, Onda 2) —
parsing das linhas do tshark, buffer e poll loop, sem VM nem SSH reais
(cliente SSH fake).

Correr:
    python test_network_monitor.py
"""

import asyncio
import sys
from collections import deque

from network_monitor import (
    NetworkConnectionManager,
    PACKET_BUFFER_MAX,
    _parse_fields_line,
    _poll_once,
    network_poll_loop,
)

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


class FakeSSHClient:
    """Fake simples: devolve os batches definidos em avanço, um por chamada."""

    def __init__(self, batches: list[tuple[str, int]]) -> None:
        self._batches = list(batches)

    async def read_new_lines(self, remote_path: str, since_offset: int) -> tuple[str, int]:
        return self._batches.pop(0)


def run_parse_tests() -> None:
    linha_tcp = "1758812760.123456,192.168.1.170,192.168.1.20,6,66,54321,3389,,"
    packet = _parse_fields_line(linha_tcp)
    check("linha TCP válida faz parse", packet is not None)
    check("src_ip correto", packet["src_ip"] == "192.168.1.170")
    check("dst_port vem de tcp.dstport (3389)", packet["dst_port"] == 3389)
    check("protocol resolvido para TCP", packet["protocol"] == "TCP")

    linha_udp = "1758812761.0,192.168.1.170,192.168.1.20,17,80,,,51820,53"
    packet_udp = _parse_fields_line(linha_udp)
    check("dst_port vem de udp.dstport quando tcp vazio", packet_udp["dst_port"] == 53)

    # --- formato antigo (9 colunas): sem flags -> tcp_syn/tcp_ack None ---
    check("9 colunas (captura antiga): tcp_syn None", packet["tcp_syn"] is None and packet["tcp_ack"] is None)

    # --- formato novo (11 colunas): + tcp.flags.syn, tcp.flags.ack ---
    syn = _parse_fields_line("1758812764.0,192.168.1.170,192.168.1.20,6,60,57789,80,,,1,0")
    check("11 colunas: SYN puro", syn is not None and syn["tcp_syn"] is True and syn["tcp_ack"] is False)
    check("11 colunas: dst_port continua a vir de tcp.dstport", syn["dst_port"] == 80)
    rst = _parse_fields_line("1758812764.1,192.168.1.20,192.168.1.170,6,54,80,57789,,,0,1")
    check("11 colunas: RST/ACK (syn=0, ack=1)", rst["tcp_syn"] is False and rst["tcp_ack"] is True)
    udp_flags = _parse_fields_line("1758812764.2,192.168.1.170,192.168.1.20,17,80,,,51820,53,,")
    check("11 colunas: UDP sem flags fica None", udp_flags["tcp_syn"] is None and udp_flags["tcp_ack"] is None)
    check("10 colunas (formato inválido) devolve None",
          _parse_fields_line("1758812764.0,192.168.1.170,192.168.1.20,6,60,57789,80,,,1") is None)

    check("linha com campos a menos devolve None", _parse_fields_line("1,2,3") is None)
    check("linha sem ip.src devolve None", _parse_fields_line("1758812760.0,,192.168.1.20,6,66,,,,") is None)
    check("epoch inválido devolve None", _parse_fields_line("nao-e-um-numero,192.168.1.1,192.168.1.2,6,66,,,,") is None)

    # --- D (Review Focus): campo numérico presente mas não-numérico não pode
    # lançar ValueError e derrubar o resto do batch em _poll_once ---
    linha_length_invalido = "1758812762.0,192.168.1.170,192.168.1.20,6,nao-e-numero,54321,3389,,"
    packet_length_invalido = _parse_fields_line(linha_length_invalido)
    check("frame.len não-numérico não lança, linha continua a fazer parse", packet_length_invalido is not None)
    check("length não-numérico fica None em vez de lançar", packet_length_invalido["length"] is None)

    linha_porta_invalida = "1758812763.0,192.168.1.170,192.168.1.20,6,66,nao-e-numero,3389,,"
    packet_porta_invalida = _parse_fields_line(linha_porta_invalida)
    check("tcp.srcport não-numérico não lança, linha continua a fazer parse", packet_porta_invalida is not None)
    check("src_port não-numérico fica None em vez de lançar", packet_porta_invalida["src_port"] is None)
    check("dst_port continua correto quando só src_port é inválido", packet_porta_invalida["dst_port"] == 3389)


def run_poll_once_tests() -> None:
    async def _run() -> None:
        manager = NetworkConnectionManager()
        packet_buffer: deque = deque(maxlen=PACKET_BUFFER_MAX)
        detection_buffer: deque = deque(maxlen=5000)
        offset_state = {"offset": 0}
        seen_detections: set = set()

        linhas = (
            "1758812760.0,192.168.1.170,192.168.1.20,6,66,54321,3389,,\n"
            "1758812761.0,192.168.1.170,192.168.1.20,6,66,54322,3390,,\n"
        )
        fake_ssh = FakeSSHClient([(linhas, 200)])
        new_packets, new_detections = await _poll_once(
            fake_ssh, manager, packet_buffer, offset_state, seen_detections, "/var/log/sentrylens/network.csv",
            detection_buffer,
        )
        check("_poll_once devolve os 2 pacotes novos", len(new_packets) == 2)
        check("offset_state atualizado para o novo offset", offset_state["offset"] == 200)
        check("buffer ficou com os 2 pacotes", len(packet_buffer) == 2)
        check("sem deteções ainda (só 2 pacotes, abaixo dos limiares)", new_detections == [])

        # --- Segunda chamada, sem linhas novas -> nada de novo, buffer inalterado ---
        fake_ssh_2 = FakeSSHClient([("", 200)])
        new_packets_2, _ = await _poll_once(
            fake_ssh_2, manager, packet_buffer, offset_state, seen_detections, "/var/log/sentrylens/network.csv",
            detection_buffer,
        )
        check("segunda chamada sem linhas novas devolve lista vazia", new_packets_2 == [])
        check("buffer continua com 2 pacotes", len(packet_buffer) == 2)

        # --- Terceira chamada: port scan (16 portas distintas do mesmo par src/dst) -> deteção nova ---
        linhas_scan = "".join(
            f"{1758812770 + i}.0,192.168.1.170,192.168.1.21,6,66,50000,{4000 + i},,\n" for i in range(16)
        )
        fake_ssh_3 = FakeSSHClient([(linhas_scan, 400)])
        _, new_detections_3 = await _poll_once(
            fake_ssh_3, manager, packet_buffer, offset_state, seen_detections, "/var/log/sentrylens/network.csv",
            detection_buffer,
        )
        check("port scan detetado após 16 portas distintas", any(d["type"] == "port_scan" for d in new_detections_3))
        check("deteção de port scan foi acumulada em detection_buffer", any(d["type"] == "port_scan" for d in detection_buffer))

        # --- Quarta chamada: mesmo padrão ainda ativo -> não repete a deteção (dedup) ---
        fake_ssh_4 = FakeSSHClient([("", 400)])
        _, new_detections_4 = await _poll_once(
            fake_ssh_4, manager, packet_buffer, offset_state, seen_detections, "/var/log/sentrylens/network.csv",
            detection_buffer,
        )
        check("deteção repetida no mesmo minuto não é re-emitida", new_detections_4 == [])

    asyncio.run(_run())


def run_detection_buffer_survives_now_moving_on() -> None:
    """
    Review Focus (Critical): a deteção original tem de continuar em
    detection_buffer mesmo depois de packet_buffer avançar para muito
    depois do padrão que a gerou — é exatamente o cenário real (utilizador
    corre cenários de ataque, espera uns minutos, só depois abre o
    dashboard) que quebrava a atribuição em /api/redblue/metrics quando
    as deteções eram recomputadas a pedido em vez de acumuladas no poll.
    """

    async def _run() -> None:
        manager = NetworkConnectionManager()
        packet_buffer: deque = deque(maxlen=PACKET_BUFFER_MAX)
        detection_buffer: deque = deque(maxlen=5000)
        offset_state = {"offset": 0}
        seen_detections: set = set()

        # --- Poll 1: port scan (16 portas distintas) em t~1758812770 -> deteção acumulada ---
        linhas_scan = "".join(
            f"{1758812770 + i}.0,192.168.1.170,192.168.1.21,6,66,50000,{4000 + i},,\n" for i in range(16)
        )
        fake_ssh_scan = FakeSSHClient([(linhas_scan, 300)])
        _, new_detections_scan = await _poll_once(
            fake_ssh_scan, manager, packet_buffer, offset_state, seen_detections, "/var/log/sentrylens/network.csv",
            detection_buffer,
        )
        check("poll do port scan gera 1+ deteções novas", len(new_detections_scan) > 0)
        check("deteção do port scan está em detection_buffer logo após o poll", len(detection_buffer) > 0)
        scan_detection_ts = detection_buffer[0]["timestamp"]

        # --- Poll 2, muito mais tarde: rajada de tráfego "de fundo" não relacionado,
        # com timestamp muito depois do scan -> "agora" do packet_buffer avança,
        # a janela de 30s de detect_network_anomalies deixa de conter o scan ---
        muito_mais_tarde = 1758812770 + 3600  # +1h
        linhas_fundo = "".join(
            f"{muito_mais_tarde + i}.0,192.168.1.50,192.168.1.99,6,66,60000,80,,\n" for i in range(5)
        )
        fake_ssh_fundo = FakeSSHClient([(linhas_fundo, 600)])
        await _poll_once(
            fake_ssh_fundo, manager, packet_buffer, offset_state, seen_detections, "/var/log/sentrylens/network.csv",
            detection_buffer,
        )

        check(
            "deteção original do port scan continua em detection_buffer depois do 'agora' avançar 1h",
            any(d["type"] == "port_scan" and d["timestamp"] == scan_detection_ts for d in detection_buffer),
        )

    asyncio.run(_run())


def run_loop_survives_ssh_error() -> None:
    """Review Focus: VM_SSH_HOST configurado mas a VM fica inatingível —
    o loop não pode derrubar o backend, tem de continuar a tentar."""

    async def _run() -> None:
        class RaisingSSHClient:
            def __init__(self) -> None:
                self.calls = 0

            async def read_new_lines(self, remote_path: str, since_offset: int) -> tuple[str, int]:
                self.calls += 1
                if self.calls == 1:
                    raise ConnectionError("VM inatingível (simulado)")
                return "", since_offset

        manager = NetworkConnectionManager()
        packet_buffer: deque = deque(maxlen=PACKET_BUFFER_MAX)
        detection_buffer: deque = deque(maxlen=5000)
        raising_client = RaisingSSHClient()
        task = asyncio.create_task(
            network_poll_loop(
                raising_client, manager, packet_buffer, "/x", detection_buffer, interval_seconds=0.01,
            )
        )
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        check("network_poll_loop sobrevive a uma falha SSH e continua a correr", raising_client.calls >= 2)

    asyncio.run(_run())


def run() -> None:
    run_parse_tests()
    run_poll_once_tests()
    run_detection_buffer_survives_now_moving_on()
    run_loop_survives_ssh_error()

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")
    sys.exit(0)


if __name__ == "__main__":
    run()
