"""
Testes de regressão de scripts/ssh_client.py (Fase 11, Onda 2) —
VMSSHClient, o único ponto de contacto SSH com a VM Wazuh. Mocka
asyncssh.connect por completo, sem precisar de nenhuma VM real ligada.

Correr:
    python test_ssh_client.py
"""

import asyncio
import sys
from unittest.mock import AsyncMock, MagicMock, patch

from ssh_client import VMSSHClient

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def _make_fake_conn(file_size: int, tail_output: str):
    """Fake de asyncssh.connect(...) como async context manager, com
    conn.run(...) a devolver stdout fixo consoante o comando (stat -c %s
    vs tail -c +N)."""
    fake_conn = MagicMock()

    async def _run(cmd: str, check: bool = True):
        result = MagicMock()
        result.stdout = f"{file_size}\n" if cmd.startswith("stat") else tail_output
        return result

    fake_conn.run = AsyncMock(side_effect=_run)

    fake_ctx = MagicMock()
    fake_ctx.__aenter__ = AsyncMock(return_value=fake_conn)
    fake_ctx.__aexit__ = AsyncMock(return_value=False)
    return fake_ctx


def _make_fake_conn_shell_semantics(file_size: int, tail_content_provider):
    """
    Fake mais fiel ao shell real: guarda os comandos executados (para os
    testes poderem verificar os offsets/limites pedidos) e, para o comando
    `tail ... | head -c N`, simula o `head -c N` a sério (corta o conteúdo
    devolvido por tail_content_provider(cmd) a N bytes) — em vez de devolver
    sempre a mesma string fixa como _make_fake_conn, que não conseguiria
    provar que o `head -c` está mesmo a limitar o output.
    """
    fake_conn = MagicMock()
    commands: list[str] = []

    async def _run(cmd: str, check: bool = True):
        commands.append(cmd)
        result = MagicMock()
        if cmd.startswith("stat"):
            result.stdout = f"{file_size}\n"
            return result
        full = tail_content_provider(cmd)
        if "head -c" in cmd:
            n = int(cmd.split("head -c", 1)[1].strip())
            result.stdout = full[:n]
        else:
            result.stdout = full
        return result

    fake_conn.run = AsyncMock(side_effect=_run)

    fake_ctx = MagicMock()
    fake_ctx.__aenter__ = AsyncMock(return_value=fake_conn)
    fake_ctx.__aexit__ = AsyncMock(return_value=False)
    return fake_ctx, commands


def run() -> None:
    async def _run_tests():
        client = VMSSHClient("192.168.1.100", "fernando", key_path=None)

        # --- Caso 1: ficheiro cresceu, offset avança, devolve só o conteúdo novo ---
        with patch("ssh_client.asyncssh.connect", return_value=_make_fake_conn(150, "linha nova 1\nlinha nova 2\n")):
            content, new_offset = await client.read_new_lines("/var/log/sentrylens/network.csv", since_offset=100)
        check("caso 1: devolve o conteúdo novo", content == "linha nova 1\nlinha nova 2\n")
        check("caso 1: novo offset == tamanho atual do ficheiro", new_offset == 150)

        # --- Caso 2: ficheiro mais pequeno que o offset conhecido (copytruncate rodou) -> reinício desde 0 ---
        with patch("ssh_client.asyncssh.connect", return_value=_make_fake_conn(50, "ficheiro inteiro\n")):
            content2, new_offset2 = await client.read_new_lines("/var/log/sentrylens/network.csv", since_offset=9999)
        check("caso 2: deteta rotação e lê desde offset 0", content2 == "ficheiro inteiro\n")
        check("caso 2: novo offset == tamanho do ficheiro rodado", new_offset2 == 50)

        # --- Caso 3: sem bytes novos (offset == tamanho atual) -> string vazia, offset inalterado ---
        with patch("ssh_client.asyncssh.connect", return_value=_make_fake_conn(200, "")):
            content3, new_offset3 = await client.read_new_lines("/var/log/sentrylens/network.csv", since_offset=200)
        check("caso 3: sem bytes novos devolve string vazia", content3 == "")
        check("caso 3: offset inalterado quando não há bytes novos", new_offset3 == 200)

        # --- Caso 4 (A - Review Focus): ficheiro cresce mais ainda ENTRE o stat e o
        # tail desta mesma chamada -> o tail tem de ficar limitado a
        # current_size - offset bytes (via head -c), nunca devolver mais do
        # que isso, para não reler no próximo poll os bytes escritos nesse
        # intervalo ---
        def provider_race(cmd: str) -> str:
            # Simula o remoto já ter 80 bytes novos disponíveis (o ficheiro
            # cresceu mais entre o stat=150 e este tail), mas o head -c do
            # próprio comando é que tem de cortar isto, não o Python.
            return "x" * 80

        fake_ctx4, commands4 = _make_fake_conn_shell_semantics(150, provider_race)
        with patch("ssh_client.asyncssh.connect", return_value=fake_ctx4):
            content4, new_offset4 = await client.read_new_lines("/var/log/sentrylens/network.csv", since_offset=100)
        check("caso 4: conteúdo devolvido fica limitado a current_size - offset (50), não aos 80 disponíveis", len(content4) == 50)
        check("caso 4: novo offset continua a ser current_size (150)", new_offset4 == 150)
        check("caso 4: comando tail inclui 'head -c 50' para bounding no remoto", any("head -c 50" in c for c in commands4))

        # --- Caso 5 (B - Review Focus): primeiro read (since_offset=0) com
        # ficheiro grande -> não lê o ficheiro inteiro, fica limitado a
        # max_initial_read_bytes, lido a partir do fim ---
        def provider_full(cmd: str) -> str:
            return "y" * 1000

        fake_ctx5, commands5 = _make_fake_conn_shell_semantics(5000, provider_full)
        with patch("ssh_client.asyncssh.connect", return_value=fake_ctx5):
            content5, new_offset5 = await client.read_new_lines(
                "/var/log/sentrylens/network.csv", since_offset=0, max_initial_read_bytes=1000,
            )
        check("caso 5: primeiro read fica limitado a max_initial_read_bytes (1000)", len(content5) == 1000)
        check("caso 5: novo offset == tamanho atual do ficheiro (5000)", new_offset5 == 5000)
        check(
            "caso 5: tail arranca a partir de current_size - max_initial_read_bytes (offset 4000, tail -c +4001), não do byte 0",
            any("tail -c +4001 " in c for c in commands5),
        )

    asyncio.run(_run_tests())

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")
    sys.exit(0)


if __name__ == "__main__":
    run()
