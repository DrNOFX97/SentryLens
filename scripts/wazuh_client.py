"""
Cliente para as APIs do Wazuh.

O Wazuh expõe DUAS APIs distintas e é um erro comum tentar tudo numa só:

1. Manager API (porta 55000)
   - Gestão de agentes, estado do cluster, configuração
   - Autenticação: JWT (token expira em 15 min por default)
   - NÃO tem os alertas em si — só metadados operacionais

2. Indexer API (porta 9200 — é OpenSearch por baixo)
   - Onde os alertas realmente vivem (índices wazuh-alerts-*)
   - Autenticação: Basic Auth (utilizador/password do indexer)
   - Aqui fazemos queries estilo OpenSearch/Elasticsearch DSL

Este módulo trata das duas e expõe funções simples para o resto da app.
"""

import time
from datetime import datetime, timedelta
from typing import Any

import httpx


class WazuhManagerClient:
    """Cliente para a Manager API (agentes, estado do sistema)."""

    def __init__(self, base_url: str, user: str, password: str, verify_ssl: bool = False):
        self.base_url = base_url.rstrip("/")
        self.user = user
        self.password = password
        self.verify_ssl = verify_ssl
        self._token: str | None = None
        self._token_expires_at: float = 0

    async def _get_token(self) -> str:
        """Obtém (ou reutiliza) um JWT válido. Renova ~1 min antes de expirar."""
        if self._token and time.time() < self._token_expires_at - 60:
            return self._token

        async with httpx.AsyncClient(verify=self.verify_ssl) as client:
            response = await client.post(
                f"{self.base_url}/security/user/authenticate?raw=true",
                auth=(self.user, self.password),
                timeout=10,
            )
            response.raise_for_status()
            self._token = response.text
            self._token_expires_at = time.time() + 900  # 15 min default
            return self._token

    async def _request(self, method: str, endpoint: str, **kwargs) -> dict:
        token = await self._get_token()
        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient(verify=self.verify_ssl) as client:
            response = await client.request(
                method,
                f"{self.base_url}{endpoint}",
                headers=headers,
                timeout=15,
                **kwargs,
            )
            response.raise_for_status()
            return response.json()

    async def get_agents(self) -> list[dict]:
        """Lista todos os agentes e o seu estado (active/disconnected/never_connected)."""
        data = await self._request("GET", "/agents?pretty=true")
        return data.get("data", {}).get("affected_items", [])

    async def get_agents_summary(self) -> dict:
        """Resumo rápido: quantos agentes ativos, desligados, etc."""
        data = await self._request("GET", "/agents/summary/status")
        return data.get("data", {})

    async def get_manager_status(self) -> dict:
        """Estado dos serviços internos do manager (wazuh-db, analysisd, etc.)."""
        data = await self._request("GET", "/manager/status")
        return data.get("data", {}).get("affected_items", [{}])[0]


class WazuhIndexerClient:
    """Cliente para o Indexer (OpenSearch) — é aqui que estão os alertas."""

    def __init__(self, base_url: str, user: str, password: str, verify_ssl: bool = False):
        self.base_url = base_url.rstrip("/")
        self.user = user
        self.password = password
        self.verify_ssl = verify_ssl

    async def _search(self, index: str, query: dict) -> dict:
        async with httpx.AsyncClient(verify=self.verify_ssl) as client:
            response = await client.post(
                f"{self.base_url}/{index}/_search",
                auth=(self.user, self.password),
                json=query,
                timeout=15,
            )
            response.raise_for_status()
            return response.json()

    async def get_recent_alerts(
        self,
        hours: int = 24,
        min_level: int = 0,
        size: int = 200,
        agent_name: str | None = None,
    ) -> list[dict]:
        """
        Vai buscar alertas recentes ao índice wazuh-alerts-*.

        hours: janela temporal a considerar
        min_level: filtra por nível mínimo de severidade do Wazuh (0-16)
        agent_name: opcional, filtra por um agente específico
        """
        since = (datetime.utcnow() - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")

        must_clauses: list[dict] = [
            {"range": {"@timestamp": {"gte": since}}},
            {"range": {"rule.level": {"gte": min_level}}},
        ]
        if agent_name:
            must_clauses.append({"match": {"agent.name": agent_name}})

        query = {
            "size": size,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {"bool": {"must": must_clauses}},
        }

        result = await self._search("wazuh-alerts-*", query)
        hits = result.get("hits", {}).get("hits", [])
        return [hit["_source"] for hit in hits]

    async def get_alert_stats(self, hours: int = 24) -> dict:
        """Agregação: contagem de alertas por nível de severidade e por rule.id."""
        since = (datetime.utcnow() - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")

        query = {
            "size": 0,
            "query": {"range": {"@timestamp": {"gte": since}}},
            "aggs": {
                "by_level": {"terms": {"field": "rule.level", "size": 20}},
                "by_rule": {
                    "terms": {"field": "rule.id", "size": 15},
                    "aggs": {"sample": {"top_hits": {"size": 1}}},
                },
                "by_agent": {"terms": {"field": "agent.name", "size": 20}},
            },
        }

        result = await self._search("wazuh-alerts-*", query)
        return result.get("aggregations", {})
