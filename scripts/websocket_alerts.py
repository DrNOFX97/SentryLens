"""
Push de alertas novos via WebSocket (/ws/alerts), com fallback para polling
já assumido pelo frontend caso a ligação WebSocket falhe.

Módulo puro (não importa main.py), no mesmo padrão dos outros módulos de
domínio do projeto (lifecycle.py, rbac.py, admin_activity.py): recebe os
alertas já obtidos do Wazuh (via indexer_client) e uma função de
enriquecimento (_enrich_alert de main.py), sem falar HTTP com o Wazuh
diretamente — isso é responsabilidade exclusiva de wazuh_client.py.
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import WebSocket

logger = logging.getLogger("sentrylens.websocket_alerts")


class ConnectionManager:
    """Gere as ligações WebSocket ativas ao /ws/alerts."""

    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict) -> None:
        """Envia a todos os clientes ligados; remove os que já morreram."""
        dead: list[WebSocket] = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead.append(connection)
        for connection in dead:
            self.disconnect(connection)


async def _poll_once(
    indexer_client,
    manager: "ConnectionManager",
    enrich_fn,
    seen_ids: set[str],
    hours: int = 1,
    size: int = 200,
    on_new_alerts=None,
) -> list[dict]:
    """
    Uma iteração do polling: busca alertas recentes, identifica os que ainda
    não foram vistos (por `_id`), enriquece-os com enrich_fn (mesma função
    _enrich_alert já usada pelos endpoints REST), faz broadcast de cada um
    como {"type": "new_alert", "alert": <enriquecido>} se houver clientes
    ligados, e devolve a lista dos alertas novos enriquecidos (para os
    testes conseguirem verificar sem depender de WebSockets reais).

    on_new_alerts (opcional): callback síncrono chamado com a lista de
    alertas novos enriquecidos (pode ser vazia nunca é chamada — só quando
    há pelo menos 1), sempre que houver alertas novos, independentemente de
    haver clientes WebSocket ligados. Corre num executor (run_in_executor)
    para não bloquear o loop de eventos com I/O síncrono (ex: escrita em
    disco pela Fase 9 — persistência de histórico). Erros no callback nunca
    derrubam o polling (mesmo padrão try/except do resto do módulo).

    Válvula de segurança simples: se seen_ids crescer demasiado (uptime
    muito longo), limpa-o por completo em vez de manter uma estrutura mais
    complexa tipo LRU — um raro re-broadcast pontual é inofensivo aqui (só
    desencadeia um refresh no frontend), e este é um projeto de laboratório
    de um único utilizador, não precisa de mais do que isto.
    """
    alerts = await indexer_client.get_recent_alerts(hours=hours, size=size)

    if len(seen_ids) > 20000:
        seen_ids.clear()

    new_alerts: list[dict] = []
    for alert in alerts:
        alert_id = alert.get("_id")
        if alert_id is None or alert_id in seen_ids:
            continue
        seen_ids.add(alert_id)
        new_alerts.append(enrich_fn(alert))

    if new_alerts and manager.active_connections:
        for enriched in new_alerts:
            await manager.broadcast({"type": "new_alert", "alert": enriched})

    if new_alerts and on_new_alerts is not None:
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, on_new_alerts, new_alerts)
        except Exception:
            logger.exception("Falha no callback on_new_alerts")

    return new_alerts


async def alert_poll_loop(
    indexer_client,
    manager: "ConnectionManager",
    enrich_fn,
    interval_seconds: int = 10,
    on_new_alerts=None,
) -> None:
    """
    Corre para sempre em background (mesmo padrão de _system_monitor_loop em
    main.py: try/except por iteração, nunca deixa uma exceção matar o loop).
    """
    seen_ids: set[str] = set()
    while True:
        try:
            await _poll_once(indexer_client, manager, enrich_fn, seen_ids, on_new_alerts=on_new_alerts)
        except Exception:
            logger.exception("Falha ao fazer polling de alertas para o WebSocket")
        await asyncio.sleep(interval_seconds)
