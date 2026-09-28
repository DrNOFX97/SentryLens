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

    asyncio.run(_run_tests())

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")
    sys.exit(0)


if __name__ == "__main__":
    run()
