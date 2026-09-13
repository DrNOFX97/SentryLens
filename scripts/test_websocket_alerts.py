"""
Testes de regressão do WebSocket /ws/alerts (push de alertas novos, com
fallback para polling assumido pelo frontend), sem precisar do laboratório
Wazuh real ligado.

Cobre dois aspetos independentes:
  1. Autenticação do endpoint /ws/alerts (query param api_key), usando
     TestClient(main.app).websocket_connect(...).
  2. _poll_once (websocket_alerts.py), a função pura que deteta alertas
     novos por _id e os enriquece via main._enrich_alert — testada
     diretamente, sem WebSockets, com um indexer_client fake.

ACHADO IMPORTANTE, JÁ CORRIGIDO (histórico, mantido porque explica o
desenho dos testes abaixo): a primeira versão de main.py aplicava
`dependencies=[Depends(require_api_key)]` a nível de app no construtor do
FastAPI(...), e essa lista aplica-se a TODAS as rotas, incluindo
@app.websocket — confirmado a correr localmente nesta versão instalada
(fastapi==0.115.0 / starlette==0.38.6). Como um cliente WebSocket real de
browser nunca consegue enviar o header X-API-Key (só query params), a
`HTTPException(401)` levantada durante a resolução de dependencies do
WebSocket não virava um close ASGI válido: a ligação ficava pendurada para
sempre em vez de ser recusada — nenhum cliente real conseguia ligar-se.

Corrigido: a dependency deixou de estar no construtor do FastAPI(...) e
passou a ser aplicada individualmente a cada rota REST
(`dependencies=_REQUIRE_API_KEY` em cada `@app.get`/`@app.post` de
main.py) — `/ws/alerts` fica de fora dessa lista de propósito e usa só a
sua própria verificação por query param `api_key`. Os testes abaixo
confirmam agora o caminho feliz (liga com sucesso) em vez de só o achado.

Os testes de ligação continuam a correr cada tentativa numa thread
`daemon=True` com `join(timeout)` como rede de segurança de regressão: se
alguém reintroduzir a dependency a nível de app (ou qualquer outra causa de
hang no handshake), a suite falha explicitamente em vez de bloquear para
sempre à espera de uma ligação que nunca se resolve.

Mesmo estilo dos outros ficheiros de teste standalone do projeto: função
check(label, condition), print [OK]/[FALHOU] por caso, sys.exit(1) no fim
se houver falhas.

Correr:
    python test_websocket_alerts.py
"""

import asyncio
import os
import sys
import threading

os.environ.setdefault("SENTRYLENS_API_KEY", "chave-de-teste-nao-usar-em-producao")

from fastapi.testclient import TestClient

import main
from websocket_alerts import ConnectionManager, _poll_once

# Desliga o startup event (loop de monitorização de sistema + loop de
# polling do WebSocket) — mesmo padrão dos outros ficheiros de teste.
main.app.router.on_startup.clear()

failures: list[str] = []

CONNECT_TIMEOUT_S = 6.0


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def alert(alert_id, event_id: int = 4624, ts: str = "2026-09-01T09:00:00Z") -> dict:
    """Alerta mock no mesmo formato usado noutros ficheiros de teste do projeto."""
    d = {
        "@timestamp": ts,
        "agent": {"name": "WIN-PC01", "ip": "192.168.1.5"},
        "rule": {"id": "1", "description": "x", "level": 5},
        "data": {"win": {"system": {"eventID": str(event_id)}, "eventdata": {"targetUserName": "jsilva", "ipAddress": "192.168.1.10"}}},
        "full_log": "x",
    }
    if alert_id is not None:
        d["_id"] = alert_id
    return d


class FakeIndexerClient:
    """Fake simples com só get_recent_alerts, mockado por teste."""

    def __init__(self, alerts: list) -> None:
        self._alerts = alerts

    async def get_recent_alerts(self, hours: int = 1, size: int = 200):
        return self._alerts


def _attempt_connect(url: str, headers: dict | None = None, timeout: float = CONNECT_TIMEOUT_S) -> dict:
    """
    Tenta ligar a um WebSocket com timeout, correndo a tentativa numa thread
    daemon: TestClient.websocket_connect() pode nunca devolver controlo (ver
    achado documentado no topo do ficheiro), e um teste que bloqueia para
    sempre é pior do que um teste que falha. Devolve um dict com:
      - "connected": True se a ligação foi aceite sem exceção
      - "exception": a exceção levantada, se houver
      - "hung": True se não resolveu dentro do timeout
    """
    result: dict = {"connected": False, "exception": None, "hung": False}
    client = TestClient(main.app, headers=headers or {})

    def _run() -> None:
        try:
            with client.websocket_connect(url) as ws:
                result["connected"] = True
        except Exception as e:  # noqa: BLE001 - queremos capturar qualquer exceção para diagnóstico
            result["exception"] = e

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        result["hung"] = True
    return result


def run_connection_tests() -> None:
    api_key = os.environ["SENTRYLENS_API_KEY"]

    # --- Sem api_key -> ligação devia ser recusada (close 1008) ---
    r1 = _attempt_connect("/ws/alerts")
    check(
        "Ligação a /ws/alerts sem api_key não fica autenticada/aceite "
        + ("(nota: bloqueou/hang em vez de close(1008) limpo - ver achado no topo do ficheiro)" if r1["hung"] else ""),
        not r1["connected"],
    )

    # --- api_key errada -> ligação devia ser recusada (close 1008) ---
    r2 = _attempt_connect("/ws/alerts?api_key=chave-errada")
    check(
        "Ligação a /ws/alerts com api_key errada não fica autenticada/aceite "
        + ("(nota: bloqueou/hang em vez de close(1008) limpo - ver achado no topo do ficheiro)" if r2["hung"] else ""),
        not r2["connected"],
    )

    # --- api_key correta -> ligação devia ser aceite ---
    # Este é o caminho real usado por um cliente WebSocket de browser (só
    # query param, sem header X-API-Key - browsers não conseguem enviar
    # headers arbitrários no handshake de WebSocket).
    r3 = _attempt_connect(f"/ws/alerts?api_key={api_key}")
    check(
        "Ligação a /ws/alerts com api_key correta (só query param, sem X-API-Key) "
        "é aceite dentro do timeout"
        + (" -- FALHA REAL: bloqueia indefinidamente, ver achado documentado no topo do ficheiro" if r3["hung"] else ""),
        r3["connected"] and not r3["hung"],
    )

    # --- Regressão: enviar também um header X-API-Key (que um browser real
    # nunca envia num handshake de WebSocket) não deve ter nenhum efeito —
    # confirma que /ws/alerts continua fora de qualquer dependency a nível
    # de app e depende só da sua própria verificação por query param.
    r4 = _attempt_connect(f"/ws/alerts?api_key={api_key}", headers={"X-API-Key": api_key})
    check(
        "Ligação com X-API-Key extra (ignorado) + api_key correto continua aceite",
        r4["connected"] and not r4["hung"],
    )


def run_poll_once_tests() -> None:
    async def _run() -> None:
        manager = ConnectionManager()
        seen_ids: set[str] = set()

        # --- 2 alertas novos, ids diferentes -> devolve os 2 enriquecidos ---
        fake_indexer = FakeIndexerClient(
            [alert("abc123", ts="2026-09-01T09:00:00Z"), alert("def456", ts="2026-09-01T09:01:00Z")]
        )
        result_1 = await _poll_once(fake_indexer, manager, main._enrich_alert, seen_ids)
        check("_poll_once devolve os 2 alertas novos", len(result_1) == 2)
        check(
            "alertas devolvidos estão enriquecidos (têm friendly_name/severity)",
            all("friendly_name" in a and "severity" in a for a in result_1),
        )
        check("seen_ids ficou com os 2 ids novos", seen_ids == {"abc123", "def456"})

        # --- Mesma chamada, mesmo seen_ids -> já vistos, devolve vazio ---
        result_2 = await _poll_once(fake_indexer, manager, main._enrich_alert, seen_ids)
        check("_poll_once com os mesmos ids já vistos devolve lista vazia", result_2 == [])

        # --- Alerta sem _id (None ou chave em falta) é ignorado sem rebentar ---
        alerta_sem_id_none = alert(None, ts="2026-09-01T09:02:00Z")
        alerta_sem_id_ausente = alert("novo789", ts="2026-09-01T09:03:00Z")
        del alerta_sem_id_ausente["_id"]
        fake_indexer_sem_id = FakeIndexerClient([alerta_sem_id_none, alerta_sem_id_ausente])
        seen_ids_2: set[str] = set()
        result_3 = await _poll_once(fake_indexer_sem_id, manager, main._enrich_alert, seen_ids_2)
        check(
            "Alertas sem _id (None ou chave em falta) são ignorados sem rebentar",
            result_3 == [] and seen_ids_2 == set(),
        )

    asyncio.run(_run())


def run() -> None:
    run_connection_tests()
    run_poll_once_tests()

    print()
    exit_code = 0
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        exit_code = 1
    else:
        print("[OK] Todos os testes passaram")

    # os._exit em vez de sys.exit: o achado documentado no topo do ficheiro
    # é precisamente um hang de WebSocket numa thread não-daemon interna do
    # portal do TestClient; por segurança garantimos saída imediata do
    # processo em vez de confiar no shutdown normal do interpretador (que
    # esperaria por threads não-daemon adormecidas). Fazemos flush manual
    # primeiro porque os._exit() não passa pela limpeza normal do stdio.
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(exit_code)


if __name__ == "__main__":
    run()
