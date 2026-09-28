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

    #: Limite do primeiro read (since_offset == 0), seja no arranque do
    #: backend ou logo a seguir a uma rotação detetada (ver read_new_lines).
    #: Sem isto, o primeiro poll depois de o backend arrancar leria o
    #: ficheiro de captura inteiro (potencialmente um dia inteiro de tshark,
    #: ou mais sob inundação de tráfego) numa única chamada SSH antes de
    #: qualquer eviction para os últimos 2000 pacotes em memória.
    MAX_INITIAL_READ_BYTES = 1_000_000

    def __init__(self, host: str, user: str, key_path: str | None = None) -> None:
        self._host = host
        self._user = user
        self._key_path = key_path

    async def read_new_lines(
        self, remote_path: str, since_offset: int, max_initial_read_bytes: int | None = None,
    ) -> tuple[str, int]:
        """
        Lê só os bytes novos de remote_path a partir de since_offset. Se o
        ficheiro atual for mais pequeno que since_offset (logrotate com
        copytruncate rodou entre dois polls), trata como reinício: lê o
        ficheiro inteiro a partir de 0 (sujeito ao cap abaixo). Devolve
        (conteúdo_novo, novo_offset) — string vazia e o mesmo offset se não
        houver bytes novos.

        Quando since_offset == 0 (primeiro poll de sempre, ou logo a seguir
        a uma rotação) e o ficheiro atual excede max_initial_read_bytes
        (default MAX_INITIAL_READ_BYTES), o read é limitado às últimas
        max_initial_read_bytes do ficheiro em vez do ficheiro inteiro — o
        offset devolvido continua a ser current_size, como sempre.

        O `tail` é limitado a `current_size - offset` bytes (via `head -c`)
        porque current_size vem de um `stat` anterior, numa chamada SSH
        separada — se o ficheiro crescer entre o `stat` e o `tail` (o tshark
        escreve continuamente, isto acontece com regularidade), um `tail`
        sem esse limite leria também os bytes escritos nesse intervalo, que
        seriam depois lidos outra vez (e reparseados/recontados/redifundidos)
        no poll seguinte, já cobertos pelo novo offset.
        """
        cap = max_initial_read_bytes if max_initial_read_bytes is not None else self.MAX_INITIAL_READ_BYTES

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

            if offset == 0 and current_size > cap:
                offset = current_size - cap

            read_len = current_size - offset
            result = await conn.run(f"tail -c +{offset + 1} {remote_path} | head -c {read_len}", check=True)
            return result.stdout, current_size
