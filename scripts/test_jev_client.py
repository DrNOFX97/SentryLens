"""
Testes de jev_client.py (triagem experimental via JEV). Sem rede: HTTP
mockado com httpx.MockTransport. Corre a partir de scripts/.
"""

import asyncio
import json
import os
import sys

import httpx

import jev_client

failures = 0


def check(name: str, ok: bool) -> None:
    global failures
    print(f"[{'OK' if ok else 'FALHOU'}] {name}")
    if not ok:
        failures += 1


SECRET_IP = "10.20.30.40"
INCIDENT = {
    "severity": "high",
    "evidence": [
        {"kind": "wazuh_alert", "ts": "2026-10-08T10:00:00Z", "severity": "medium", "asset": SECRET_IP,
         "payload": {"@timestamp": "2026-10-08T10:00:00Z", "agent": {"ip": SECRET_IP, "name": "srv-secreto"},
                     "data": {"win": {"system": {"eventID": "4625"}, "eventdata": {"targetUserName": "conta.secreta"}}}}},
        {"kind": "network_detection", "ts": "2026-10-08T10:01:00Z", "severity": "medium", "asset": SECRET_IP,
         "payload": {"type": "port_scan", "src_ip": "203.0.113.9", "dst_ip": SECRET_IP, "timestamp": "2026-10-08T10:01:00Z"}},
    ],
}

GOOD_BODY = {
    "model": "jev-1.13.0",
    "answers": {
        "is_compromise": {"type": "noul", "noul": 0.62},
        "is_brute_force": {"type": "noul", "noul": 0.9},
        "severity": {"type": "choice", "choice": "medium", "confidence": 0.48,
                     "probabilities": {"info": 0.07, "low": 0.06, "medium": 0.61, "high": 0.26}},
    },
}

# --- build_state: agregado e anonimizado ---
state = jev_client.build_state(INCIDENT)
dump = json.dumps(state)
check("state não contém IPs, hostnames nem contas", not any(x in dump for x in (SECRET_IP, "203.0.113.9", "srv-secreto", "conta.secreta")))
check("state tem contagem e duração", state["evidence_count"] == 2 and state["duration_seconds"] == 60)
check("state tem rótulos de evento", {e["label"] for e in state["event_types"]} >= {"port_scan"})
check("incidente vazio/malformado não rebenta", jev_client.build_state({})["evidence_count"] == 0
      and jev_client.build_state({"evidence": ["lixo", None]})["evidence_count"] == 0)

# --- parse_answers ---
parsed = jev_client.parse_answers(GOOD_BODY)
check("parse_answers resposta válida", parsed is not None and parsed["answers"]["severity"]["choice"] == "medium"
      and parsed["answers"]["is_compromise"]["probability"] == 0.62)
check("parse_answers rejeita choice fora do critério",
      jev_client.parse_answers({"answers": {**GOOD_BODY["answers"], "severity": {"choice": "critical", "probabilities": {}}}}) is None)
check("parse_answers rejeita lixo", all(jev_client.parse_answers(x) is None for x in (None, [], {}, {"answers": []}, {"answers": {}})))

# --- jev_enabled: fail-closed ---
for k in ("SENTRYLENS_JEV_ENABLED", "TYPESAFE_API_KEY"):
    os.environ.pop(k, None)
check("desligado por omissão", not jev_client.jev_enabled())
os.environ["SENTRYLENS_JEV_ENABLED"] = "true"
check("flag sem chave continua desligado", not jev_client.jev_enabled())
os.environ["TYPESAFE_API_KEY"] = "chave-de-teste"
check("flag + chave liga", jev_client.jev_enabled())


async def run(handler) -> dict:
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        return await jev_client.triage(INCIDENT, client)


seen = {}


def ok_handler(request: httpx.Request) -> httpx.Response:
    seen["auth"] = request.headers.get("authorization")
    seen["body"] = request.content.decode()
    return httpx.Response(200, json=GOOD_BODY)


result = asyncio.run(run(ok_handler))
check("triage ok devolve respostas", result.get("ok") is True and result["answers"]["severity"]["choice"] == "medium")
check("envia Bearer com a chave", seen["auth"] == "Bearer chave-de-teste")
check("corpo enviado sem IPs", SECRET_IP not in seen["body"] and "203.0.113.9" not in seen["body"])

for status, code in ((401, "jev_auth"), (429, "jev_busy"), (529, "jev_busy"), (500, "jev_error")):
    r = asyncio.run(run(lambda req, s=status: httpx.Response(s, text="segredo interno")))
    check(f"HTTP {status} -> {code}, sem texto da resposta", r == {"ok": False, "error": code})


def boom(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("detalhe interno 10.0.0.1")


r = asyncio.run(run(boom))
check("rede em baixo -> jev_unreachable, sem texto de exceção", r == {"ok": False, "error": "jev_unreachable"})
r = asyncio.run(run(lambda req: httpx.Response(200, text="não é json")))
check("200 com corpo inválido -> jev_bad_response", r == {"ok": False, "error": "jev_bad_response"})

os.environ.pop("SENTRYLENS_JEV_ENABLED")
r = asyncio.run(run(ok_handler))
check("desligado nunca chama a rede", r == {"ok": False, "error": "jev_disabled"})

sys.exit(1 if failures else 0)
