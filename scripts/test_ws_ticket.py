"""
Testes dos tickets de WebSocket (S2): POST /api/ws-ticket + ?ticket= em
/ws/alerts e /ws/network. A API key já não vai no URL do WebSocket.

Cobre: REST sem/com chave errada -> 401; ticket válido liga (alerts e
network); reutilizado falha; expirado falha; desconhecido/sem ticket falha;
?api_key= na query já não serve (nem a chave certa); a chave nunca aparece
na resposta do ticket; tickets são distintos e o teto de pendentes responde 429.

Correr:  python test_ws_ticket.py
"""

import os
import sys
import threading

os.environ["SENTRYLENS_API_KEY"] = "chave-de-teste-ws-ticket"

from fastapi.testclient import TestClient

import main

main.app.router.on_startup.clear()

KEY = os.environ["SENTRYLENS_API_KEY"]
failures: list[str] = []


def check(label: str, cond: bool) -> None:
    print(f"[{'OK   ' if cond else 'FALHOU'}] {label}")
    if not cond:
        failures.append(label)


client = TestClient(main.app)


def new_ticket() -> str:
    return client.post("/api/ws-ticket", headers={"X-API-Key": KEY}).json()["ticket"]


def connects(url: str, timeout: float = 6.0) -> bool:
    """True se o handshake é aceite e fica aberto (uma recusa 1008 levanta)."""
    out = {"ok": False}

    def _run() -> None:
        try:
            with TestClient(main.app).websocket_connect(url):
                out["ok"] = True
        except Exception:  # noqa: BLE001 - qualquer recusa conta como "não liga"
            pass

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout)
    return out["ok"] and not t.is_alive()


def run() -> None:
    # --- REST ---
    check("POST /api/ws-ticket sem API key -> 401", client.post("/api/ws-ticket").status_code == 401)
    check("POST /api/ws-ticket com chave errada -> 401",
          client.post("/api/ws-ticket", headers={"X-API-Key": "errada"}).status_code == 401)
    r = client.post("/api/ws-ticket", headers={"X-API-Key": KEY})
    body = r.json()
    check("POST /api/ws-ticket com chave -> 200 com ticket e expires_in",
          r.status_code == 200 and isinstance(body.get("ticket"), str) and body.get("expires_in") == main.WS_TICKET_TTL_SECONDS)
    check("o ticket é opaco (não contém a API key) e tem entropia", KEY not in body["ticket"] and len(body["ticket"]) >= 32)
    check("dois tickets são distintos", new_ticket() != new_ticket())
    check("GET /api/ws-ticket não existe (405)", client.get("/api/ws-ticket", headers={"X-API-Key": KEY}).status_code == 405)
    check("REST sem API key continua 401 (ex.: /api/alerts)", client.get("/api/alerts").status_code == 401)

    # --- /ws/alerts ---
    t = new_ticket()
    check("/ws/alerts com ticket válido liga", connects(f"/ws/alerts?ticket={t}"))
    check("/ws/alerts com o mesmo ticket (reutilizado) falha", not connects(f"/ws/alerts?ticket={t}"))
    check("/ws/alerts sem ticket falha", not connects("/ws/alerts"))
    check("/ws/alerts com ticket desconhecido falha", not connects("/ws/alerts?ticket=desconhecido"))
    check("/ws/alerts com ticket vazio falha", not connects("/ws/alerts?ticket="))
    check("/ws/alerts com ?api_key= correto já não serve", not connects(f"/ws/alerts?api_key={KEY}"))
    check("/ws/alerts com a chave no parâmetro ticket não serve", not connects(f"/ws/alerts?ticket={KEY}"))

    # --- expirado ---
    t = new_ticket()
    main._ws_tickets[t] = main.time.monotonic() - 1  # força a expiração
    check("/ws/alerts com ticket expirado falha", not connects(f"/ws/alerts?ticket={t}"))
    check("o ticket expirado é apagado ao ser tentado", t not in main._ws_tickets)

    # --- /ws/network ---
    t = new_ticket()
    check("/ws/network com ticket válido liga", connects(f"/ws/network?ticket={t}"))
    check("/ws/network com o mesmo ticket (reutilizado) falha", not connects(f"/ws/network?ticket={t}"))
    check("/ws/network sem ticket falha", not connects("/ws/network"))
    check("/ws/network com ?api_key= correto já não serve", not connects(f"/ws/network?api_key={KEY}"))
    t = new_ticket()
    main._ws_tickets[t] = main.time.monotonic() - 1
    check("/ws/network com ticket expirado falha", not connects(f"/ws/network?ticket={t}"))

    # --- fail-closed sem chave configurada ---
    t = new_ticket()
    saved = main.SENTRYLENS_API_KEY
    main.SENTRYLENS_API_KEY = ""
    try:
        check("sem SENTRYLENS_API_KEY configurada nenhum ticket liga", not connects(f"/ws/alerts?ticket={t}"))
    finally:
        main.SENTRYLENS_API_KEY = saved

    # --- teto de pendentes e limpeza ---
    main._ws_tickets.clear()
    for _ in range(main.WS_TICKET_MAX_PENDING):
        new_ticket()
    check("acima do teto de tickets pendentes -> 429",
          client.post("/api/ws-ticket", headers={"X-API-Key": KEY}).status_code == 429)
    for k in list(main._ws_tickets):
        main._ws_tickets[k] = main.time.monotonic() - 1
    check("tickets expirados são limpos e libertam o teto",
          client.post("/api/ws-ticket", headers={"X-API-Key": KEY}).status_code == 200 and len(main._ws_tickets) == 1)


if __name__ == "__main__":
    run()
    if failures:
        print(f"\n[FALHOU] {len(failures)} teste(s) falharam:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("\n[OK] Todos os testes passaram")
