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

    check("linha com campos a menos devolve None", _parse_fields_line("1,2,3") is None)
    check("linha sem ip.src devolve None", _parse_fields_line("1758812760.0,,192.168.1.20,6,66,,,,") is None)
    check("epoch inválido devolve None", _parse_fields_line("nao-e-um-numero,192.168.1.1,192.168.1.2,6,66,,,,") is None)


def run_poll_once_tests() -> None:
    async def _run() -> None:
        manager = NetworkConnectionManager()
        packet_buffer: deque = deque(maxlen=PACKET_BUFFER_MAX)
        offset_state = {"offset": 0}
        seen_detections: set = set()

        linhas = (
            "1758812760.0,192.168.1.170,192.168.1.20,6,66,54321,3389,,\n"
            "1758812761.0,192.168.1.170,192.168.1.20,6,66,54322,3390,,\n"
        )
        fake_ssh = FakeSSHClient([(linhas, 200)])
        new_packets, new_detections = await _poll_once(
            fake_ssh, manager, packet_buffer, offset_state, seen_detections, "/var/log/sentrylens/network.csv",
        )
        check("_poll_once devolve os 2 pacotes novos", len(new_packets) == 2)
        check("offset_state atualizado para o novo offset", offset_state["offset"] == 200)
        check("buffer ficou com os 2 pacotes", len(packet_buffer) == 2)
        check("sem deteções ainda (só 2 pacotes, abaixo dos limiares)", new_detections == [])

        # --- Segunda chamada, sem linhas novas -> nada de novo, buffer inalterado ---
        fake_ssh_2 = FakeSSHClient([("", 200)])
        new_packets_2, _ = await _poll_once(
            fake_ssh_2, manager, packet_buffer, offset_state, seen_detections, "/var/log/sentrylens/network.csv",
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
        )
        check("port scan detetado após 16 portas distintas", any(d["type"] == "port_scan" for d in new_detections_3))

        # --- Quarta chamada: mesmo padrão ainda ativo -> não repete a deteção (dedup) ---
        fake_ssh_4 = FakeSSHClient([("", 400)])
        _, new_detections_4 = await _poll_once(
            fake_ssh_4, manager, packet_buffer, offset_state, seen_detections, "/var/log/sentrylens/network.csv",
        )
        check("deteção repetida no mesmo minuto não é re-emitida", new_detections_4 == [])

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
        raising_client = RaisingSSHClient()
        task = asyncio.create_task(
            network_poll_loop(raising_client, manager, packet_buffer, "/x", interval_seconds=0.01)
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
    run_loop_survives_ssh_error()

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")
    sys.exit(0)


if __name__ == "__main__":
    run()
