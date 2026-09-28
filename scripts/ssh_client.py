"""
Único ponto de contacto SSH com a VM Wazuh (Fase 11, Onda 2) — nenhum outro
módulo abre ligações SSH diretamente, mesmo papel que wazuh_client.py tem
para HTTP. Usado só por network_monitor.py, para ler o ficheiro de captura
de rede que o tshark vai escrevendo na VM (ver scripts/deploy/).
"""

import asyncssh


class VMSSHClient:
    """
    known_hosts=None desliga a verificação de host key SSH — mesma
    filosofia de WAZUH_VERIFY_SSL=false em wazuh_client.py: o laboratório
    usa infraestrutura própria sem PKI formal, decisão intencional, não um
    esquecimento.
    """

    def __init__(self, host: str, user: str, key_path: str | None = None) -> None:
        self._host = host
        self._user = user
        self._key_path = key_path

    async def read_new_lines(self, remote_path: str, since_offset: int) -> tuple[str, int]:
        """
        Lê só os bytes novos de remote_path a partir de since_offset. Se o
        ficheiro atual for mais pequeno que since_offset (logrotate com
        copytruncate rodou entre dois polls), trata como reinício: lê o
        ficheiro inteiro a partir de 0. Devolve (conteúdo_novo, novo_offset)
        — string vazia e o mesmo offset se não houver bytes novos.

        Risco aceite: se a rotação acontecer exatamente entre o `stat` e o
        `tail` desta mesma chamada (não entre polls), o `tail` pode ler a
        partir de um offset já inválido para o ficheiro truncado — o poll
        seguinte deteta o tamanho reduzido e autocorrige. Uma iteração
        perdida ocasional é aceitável para uma ferramenta de laboratório.
        """
        async with asyncssh.connect(
            self._host,
            username=self._user,
            client_keys=[self._key_path] if self._key_path else None,
            known_hosts=None,
        ) as conn:
            size_result = await conn.run(f"stat -c %s {remote_path}", check=True)
            current_size = int(size_result.stdout.strip())

            offset = since_offset if current_size >= since_offset else 0
            if current_size == offset:
                return "", offset

            result = await conn.run(f"tail -c +{offset + 1} {remote_path}", check=True)
            return result.stdout, current_size
