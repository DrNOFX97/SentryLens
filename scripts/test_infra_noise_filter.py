"""Filtro de ruído de infraestrutura em WazuhIndexerClient.get_recent_alerts.

Sem o laboratório: _search é substituído por um AsyncMock e inspecionamos a
query enviada. Também confirma que o Attack Registry pede o filtro.
"""
import asyncio
import os
import sys
from unittest.mock import AsyncMock

os.environ.setdefault("SENTRYLENS_API_KEY", "test-key")
sys.path.insert(0, os.path.dirname(__file__))

import wazuh_client
from wazuh_client import INFRA_NOISE_AGENT_ID, INFRA_NOISE_RULE_IDS, WazuhIndexerClient

FALHAS = 0


def check(label, cond):
    global FALHAS
    print(("[OK]" if cond else "[FALHOU]"), label)
    if not cond:
        FALHAS += 1


def query_enviada(**kwargs):
    client = WazuhIndexerClient("https://x:9200", "u", "p")
    client._search = AsyncMock(return_value={"hits": {"hits": []}})
    asyncio.run(client.get_recent_alerts(**kwargs))
    return client._search.call_args.args[1]["query"]["bool"]


default = query_enviada(hours=1)
check("por omissão não exclui nada (todos os painéis antigos iguais)", "must_not" not in default)

filtrada = query_enviada(hours=1, exclude_infra_noise=True)
excl = filtrada.get("must_not", [{}])[0].get("bool", {}).get("must", [])
check("must_not restringe ao agente da VM Wazuh",
      {"term": {"agent.id": INFRA_NOISE_AGENT_ID}} in excl)
check("must_not restringe às regras de sessão SSH/PAM",
      {"terms": {"rule.id": list(INFRA_NOISE_RULE_IDS)}} in excl)
check("agente e regras na mesma cláusula (AND): sshd 5715 noutro agente continua visível",
      len(excl) == 2)
check("o filtro de tempo continua presente", any("range" in c and "@timestamp" in c["range"]
                                                    for c in filtrada["must"]))
check("ids do ruído: 000 + 5501/5502/5715",
      INFRA_NOISE_AGENT_ID == "000" and set(INFRA_NOISE_RULE_IDS) == {"5501", "5502", "5715"})

src = open(os.path.join(os.path.dirname(__file__), "main.py"), encoding="utf-8").read()
check("Attack Registry pede exclude_infra_noise=True",
      "size=ATTACK_ALERTS_SIZE, exclude_infra_noise=True" in src)

sys.exit(1 if FALHAS else 0)
