"""
Testes da rota de decisão do R12 (Phase 16): POST /api/vaccines/{id}/decision.
Stores (vaccines e incidentes) temporários, sem a app a falar com o Wazuh. As
vaccines vêm do motor verdadeiro (vaccine_engine) sobre ataques montados à mão,
as mesmas fixtures de test_vaccine_decision_store.py.

Cobre o tracer (aprovar e rejeitar por HTTP ponta a ponta, aviso de que nada foi
aplicado no Wazuh, 401, uma recusa por família) e as recusas (corpo fora do
contrato, teto de bytes, analista, store, métodos, id do caminho), sempre com a
prova de que nada fica gravado.

Correr (a partir de scripts/):
    python test_vaccine_decision_api.py
"""

import ast
import json
import os
import pathlib
import re
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

os.environ.setdefault("SENTRYLENS_API_KEY", "test-key-vaccine-decision-api")

from fastapi.testclient import TestClient

import main
import vaccine_engine
from incident_store import IncidentStore
from vaccine_store import VaccineStore

main.app.router.on_startup.clear()
client = TestClient(main.app)
HEADERS = {"X-API-Key": os.environ["SENTRYLENS_API_KEY"]}

NOW = datetime.now(timezone.utc)
STAMP = NOW.isoformat()

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def ts(seconds_ago: int) -> str:
    return (NOW - timedelta(seconds=seconds_ago)).isoformat()


def make_attack(attack_id, verdict, expected, achieved, scenario="smb_enum", event_ids=(5140, 5145),
                duplicate_id=False, expected_source="scenario_default", correlation_reason=None,
                technique="T1135") -> dict:
    """Dict com a mesma forma de um ataque de build_attack_registry."""
    return {
        "id": attack_id,
        "duplicate_id": duplicate_id,
        "timestamp": ts(100),
        "scenario": scenario,
        "mitre_tactic": "Discovery",
        "mitre_technique": technique,
        "expected": {"detection": list(expected), "source": expected_source, "event_ids": list(event_ids)},
        "actual": {"verdict": verdict, "correlation_reason": correlation_reason, "achieved": list(achieved)},
        "evidence": {"matched_event_ids": [], "matched_alert_count": 0, "network_detection_types": [],
                     "incident_count": 0},
        "incidents": [],
    }


def engine_vaccine(attack: dict) -> dict:
    return vaccine_engine.build_vaccine_candidates({"attacks": [attack]})["vaccines"][0]


vA = engine_vaccine(make_attack(2, "partial", ["rule", "ml"], ["rule"]))
vB = engine_vaccine(make_attack(2, "not_detected", ["rule", "ml"], []))
vC = engine_vaccine(make_attack(3, "partial", ["rule", "ml"], ["rule"], scenario="lateral_movement_schtasks",
                                event_ids=(4672, 4698), technique="T1053"))
ID_A, ID_B, ID_C = "vac-ed793c0b3437", "vac-5fe3861aa2a3", "vac-bd617cce8054"


def rows_of(path: str) -> list[tuple]:
    if not os.path.exists(path):
        return []
    conn = sqlite3.connect(path)
    try:
        return conn.execute("SELECT * FROM vaccines ORDER BY id").fetchall()
    finally:
        conn.close()


def has_decisions_table(path: str) -> bool:
    conn = sqlite3.connect(path)
    try:
        return conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'vaccine_decisions'"
                            ).fetchone() is not None
    finally:
        conn.close()


def decision_rows(path: str) -> list[tuple]:
    """As 7 colunas de vaccine_decisions (sem `id`) pela ordem de inserção; [] se a tabela ou o ficheiro não existirem."""
    if not os.path.exists(path) or not has_decisions_table(path):
        return []
    conn = sqlite3.connect(path)
    try:
        return conn.execute("SELECT vaccine_id, decision, decided_by, decided_by_name, decided_at, reason, "
                            "previous_state FROM vaccine_decisions ORDER BY id").fetchall()
    finally:
        conn.close()


def seed_store(path: str) -> VaccineStore:
    """Store com vA e vC e depois vB: A fica substituída por B (mesmo ataque 2)."""
    store = VaccineStore(path)
    store.upsert_batch([vA, vC], STAMP)
    store.upsert_batch([vB], STAMP)
    return store


def seed_analysts(store: IncidentStore) -> None:
    store.create_analyst("analyst-eddie", "Eddie", 1, None, STAMP)
    store.create_analyst("analyst-jeremy", "Jeremy", 2, None, STAMP)
    store.create_analyst("analyst-mike", "Mike", 1, None, STAMP)
    store.deactivate_analyst("analyst-mike")
    store.create_analyst("analyst-obrien", "O'Brien", 1, None, STAMP)


def wire(tmp: str, name: str = "v.sqlite3") -> str:
    """Liga a app a stores temporários (vaccines semeadas, analistas criados). Devolve o caminho do store."""
    path = os.path.join(tmp, name)
    main.vaccine_store = seed_store(path)
    main.incident_store = IncidentStore(os.path.join(tmp, f"i-{name}"))
    seed_analysts(main.incident_store)
    return path


def post(vaccine_id: str, body=None, *, content: bytes | None = None, headers=HEADERS):
    url = f"/api/vaccines/{vaccine_id}/decision"
    if content is not None:
        return client.post(url, headers={**headers, "Content-Type": "application/json"}, content=content)
    return client.post(url, headers=headers, json=body)


def all_keys(value) -> set:
    """Todas as chaves de dicts, a qualquer profundidade."""
    found: set = set()
    if isinstance(value, dict):
        for key, inner in value.items():
            found.add(key)
            found |= all_keys(inner)
    elif isinstance(value, list):
        for inner in value:
            found |= all_keys(inner)
    return found


def run_tracer() -> None:
    original_vaccines, original_incidents = main.vaccine_store, main.incident_store
    tmp = tempfile.TemporaryDirectory()
    try:
        path = wire(tmp.name)
        check("fixtures: ids literais do motor", (vA["id"], vB["id"], vC["id"]) == (ID_A, ID_B, ID_C))

        # --- a rota: uma só, só POST, API key na própria rota ---
        routes = [r for r in main.app.routes if getattr(r, "path", "") == "/api/vaccines/{vaccine_id}/decision"]
        check("main.app.routes tem exatamente uma rota de decisão, só POST",
              len(routes) == 1 and routes[0].methods == {"POST"})
        check("a rota de decisão tem require_api_key nas dependencies da própria rota",
              len(routes) == 1 and any(getattr(d, "dependency", None) is main.require_api_key
                                       for d in routes[0].dependencies))

        # --- 401 sem chave e com chave errada, nada gravado ---
        body = {"decision": "approved", "analyst_id": "analyst-eddie"}
        r = client.post(f"/api/vaccines/{ID_C}/decision", json=body)
        check("sem X-API-Key -> 401", r.status_code == 401)
        r = client.post(f"/api/vaccines/{ID_C}/decision", json=body, headers={"X-API-Key": "errada"})
        check("chave errada -> 401", r.status_code == 401)
        check("401: nada gravado", decision_rows(path) == [])

        # --- aprovar ---
        before = datetime.now(timezone.utc)
        r = post(ID_C, body)
        after = datetime.now(timezone.utc)
        data = r.json() if r.status_code == 200 else {}
        check("aprovar: 200 com chaves exatamente {vaccine, notice}", r.status_code == 200 and set(data) == {"vaccine", "notice"})
        vaccine = data.get("vaccine", {})
        decision = vaccine.get("decision") or {}
        check("aprovar: vaccine.id, state approved", vaccine.get("id") == ID_C and vaccine.get("state") == "approved")
        check("aprovar: decision com as 4 chaves, decided_by e nome do incident_store, reason None",
              set(decision) == {"decided_by", "decided_by_name", "decided_at", "reason"}
              and decision.get("decided_by") == "analyst-eddie" and decision.get("decided_by_name") == "Eddie"
              and decision.get("reason") is None)
        try:
            decided_at = datetime.fromisoformat(decision.get("decided_at", ""))
            instant_ok = decided_at.utcoffset() == timedelta(0) and before <= decided_at <= after
        except ValueError:
            instant_ok = False
        check("aprovar: decided_at é ISO 8601 offset 0 gerado no servidor, entre antes e depois do pedido", instant_ok)
        notice = data.get("notice", "")
        check("o aviso diz 'aceite pelo analista' e 'não aplicada no Wazuh'",
              "aceite pelo analista" in notice and "não aplicada no Wazuh" in notice)
        check("nenhuma chave da resposta, a qualquer profundidade, é applied ou active",
              not ({"applied", "active"} & all_keys(data)))
        r = client.get(f"/api/vaccines/{ID_C}", headers=HEADERS)
        check("GET de detalhe a seguir devolve a mesma vaccine", r.status_code == 200 and r.json() == {"vaccine": vaccine})
        check("vaccine_decisions tem exatamente a linha da aprovação",
              decision_rows(path) == [(ID_C, "approved", "analyst-eddie", "Eddie", decision.get("decided_at"), None, "proposed")])

        # --- rejeitar ---
        r = post(ID_B, {"decision": "rejected", "analyst_id": "analyst-jeremy", "reason": "Regra ruidosa"})
        vaccine = r.json().get("vaccine", {}) if r.status_code == 200 else {}
        decision = vaccine.get("decision") or {}
        check("rejeitar: 200, state rejected, reason e nome Jeremy",
              r.status_code == 200 and vaccine.get("state") == "rejected" and decision.get("reason") == "Regra ruidosa"
              and decision.get("decided_by_name") == "Jeremy" and decision.get("decided_by") == "analyst-jeremy")

        # --- uma recusa por família, cada uma com detail string e nada gravado ---
        def refused(label: str, vaccine_id: str, body, status: int, code: str) -> None:
            rows_before, decisions_before = rows_of(path), decision_rows(path)
            r = post(vaccine_id, body)
            check(f"{label}: {status} {code}", r.status_code == status and r.json() == {"detail": code})
            check(f"{label}: nada gravado", rows_of(path) == rows_before and decision_rows(path) == decisions_before)

        refused("chave extra decided_by_name", ID_A, {**body, "decided_by_name": "Mallory"}, 422, "invalid_body")
        refused("decisão 'applied'", ID_A, {"decision": "applied", "analyst_id": "analyst-eddie"}, 422, "invalid_decision")
        refused("analista inexistente", ID_A, {"decision": "approved", "analyst_id": "analyst-ninguem"}, 422, "analyst_not_found")
        refused("vaccine inexistente", "vac-000000000000", body, 404, "entry_not_found")
        refused("repetir a aprovação", ID_C, body, 409, "already_decided")

        # --- id do caminho mal formado: o handler com âmbito da rota ---
        rows_before, decisions_before = rows_of(path), decision_rows(path)
        r = post("abc", body)
        check("id mal formado com chave -> 422 {'detail': 'invalid_vaccine_id'} (string)",
              r.status_code == 422 and r.json() == {"detail": "invalid_vaccine_id"})
        check("id mal formado: nada gravado", rows_of(path) == rows_before and decision_rows(path) == decisions_before)
        r = post("abc", body, headers={})
        check("id mal formado sem chave -> 401 (a chave ganha)", r.status_code == 401)
        r = client.get("/api/vaccines/abc", headers=HEADERS)
        check("GET /api/vaccines/abc continua 422 com detail em lista (handler por omissão)",
              r.status_code == 422 and isinstance(r.json().get("detail"), list))
    finally:
        main.vaccine_store, main.incident_store = original_vaccines, original_incidents
        tmp.cleanup()


def run_refusals() -> None:
    original_vaccines, original_incidents = main.vaccine_store, main.incident_store
    tmp = tempfile.TemporaryDirectory()
    try:
        path = wire(tmp.name)
        good = {"decision": "approved", "analyst_id": "analyst-eddie"}
        rejected = {"decision": "rejected", "analyst_id": "analyst-eddie"}

        def refused(label: str, vaccine_id: str, body=None, status: int = 422, code: str = "invalid_body", *,
                    content: bytes | None = None, headers=HEADERS) -> None:
            """Um pedido recusado: status, body exatamente {'detail': código}, detail string estável, nada gravado."""
            rows_before, decisions_before = rows_of(path), decision_rows(path)
            r = post(vaccine_id, body, content=content, headers=headers)
            try:
                payload = r.json()
            except ValueError:
                payload = None
            detail = payload.get("detail") if isinstance(payload, dict) else None
            check(f"{label}: {status} {code}", r.status_code == status and payload == {"detail": code})
            check(f"{label}: detail é string estável",
                  isinstance(detail, str) and re.fullmatch(r"[a-z_]{1,64}", detail) is not None)
            check(f"{label}: nada gravado", rows_of(path) == rows_before and decision_rows(path) == decisions_before)

        # --- corpo fora do contrato ---
        for label, raw in (("corpo vazio", b""), ("null", b"null"), ("lista", b"[]"), ("string", b'"approved"'),
                           ("número", b"42"), ("JSON partido", b'{"decision": "appro'),
                           ("UTF-8 inválido", b"\xff\xfe"),
                           ("chave duplicada",
                            b'{"decision": "approved", "decision": "rejected", "analyst_id": "analyst-eddie"}')):
            refused(label, ID_C, content=raw)
        for extra in ("decided_by_name", "decided_by", "decided_at", "state", "vaccine_id", "previous_state", "applied"):
            refused(f"chave extra {extra}", ID_C, {**good, extra: "x"})
        refused("sem decision", ID_C, {"analyst_id": "analyst-eddie"})
        refused("sem analyst_id", ID_C, {"decision": "approved"})
        for value in (1, None, ["approved"]):
            refused(f"decision {value!r}", ID_C, {**good, "decision": value})
        for value in (7, None):
            refused(f"analyst_id {value!r}", ID_C, {**good, "analyst_id": value})
        for value in (5, {"x": 1}, True):
            refused(f"reason {value!r}", ID_C, {**good, "reason": value})
        deep = b"[" * 3000 + b"]" * 3000
        deep_body = b'{"decision": "approved", "analyst_id": "analyst-eddie", "reason": ' + deep + b"}"
        check("o aninhamento profundo cabe abaixo do teto", len(deep_body) < main.VACCINE_DECISION_BODY_MAX_BYTES)
        refused("aninhamento profundo em reason", ID_C, content=deep_body)
        # chave duplicada em qualquer nível (dentro de um valor aninhado) também é ambígua
        refused("chave duplicada aninhada", ID_C,
                content=b'{"decision": "approved", "analyst_id": "analyst-eddie", "reason": {"a": 1, "a": 2}}')

        # --- teto do corpo ---
        limit = main.VACCINE_DECISION_BODY_MAX_BYTES
        base = json.dumps(good).encode()
        padded = base + b" " * (limit - len(base))
        check("o corpo acolchoado tem exatamente o teto", len(padded) == limit)
        fresh = wire(tmp.name, "teto.sqlite3")
        r = post(ID_C, content=padded)
        check("corpo válido de exatamente o teto -> 200", r.status_code == 200)
        check("corpo de exatamente o teto: a decisão ficou gravada", len(decision_rows(fresh)) == 1)
        fresh = wire(tmp.name, "teto2.sqlite3")
        r = post(ID_C, content=padded + b" ")
        check("teto mais 1 byte -> 422 invalid_body", r.status_code == 422 and r.json() == {"detail": "invalid_body"})
        check("teto mais 1 byte: nada gravado", decision_rows(fresh) == [])
        r = post(ID_C, content=b"x" * 100_000)
        check("100 KB -> 422 invalid_body", r.status_code == 422 and r.json() == {"detail": "invalid_body"})

        def chunks():
            for _ in range(100):
                yield b" " * 1024

        r = client.post(f"/api/vaccines/{ID_C}/decision", headers={**HEADERS, "Content-Type": "application/json"},
                        content=chunks())
        check("100 KB por partes (sem Content-Length) -> 422 invalid_body",
              r.status_code == 422 and r.json() == {"detail": "invalid_body"})
        check("o corpo recusado por tamanho não gravou nada", decision_rows(fresh) == [])
        fresh = wire(tmp.name, "emoji.sqlite3")
        longest = json.dumps({**good, "reason": "\U0001F600" * 500}, ensure_ascii=True).encode()
        r = post(ID_C, content=longest)
        check(f"motivo de 500 emoji (ensure_ascii, {len(longest)} bytes) -> 200: o teto nunca recusa um corpo válido",
              len(longest) <= limit and r.status_code == 200)
        fresh = wire(tmp.name, "r500.sqlite3")
        r = post(ID_C, {**good, "reason": "a" * 500})
        check("reason de 500 caracteres com approved -> 200", r.status_code == 200)

        # --- a partir daqui, de novo o store principal intacto ---
        path = wire(tmp.name, "principal.sqlite3")
        real_vaccines, real_incidents = main.vaccine_store, main.incident_store

        # --- analyst_id mal formado: 422 invalid_author sem consultar a base ---
        for bad in ("Eddie", "analyst-A", "analyst-", "analyst-eddie\n", ""):
            refused(f"analyst_id {bad!r}", ID_C, {**good, "analyst_id": bad}, 422, "invalid_author")
        spy = MagicMock()
        main.incident_store = spy
        post(ID_C, {**good, "analyst_id": "Eddie"})
        check("analyst_id mal formado: get_analyst não foi chamado", spy.get_analyst.called is False)
        main.incident_store = real_incidents

        # --- valores validados por validate_request ---
        for bad in ("applied", "APPROVED", ""):
            refused(f"decision {bad!r}", ID_C, {**good, "decision": bad}, 422, "invalid_decision")
        refused("rejected sem reason", ID_C, rejected, 422, "reason_required")
        refused("rejected com reason null", ID_C, {**rejected, "reason": None}, 422, "reason_required")
        refused("rejected com reason em branco", ID_C, {**rejected, "reason": "   "}, 422, "reason_required")
        refused("reason de 501 caracteres", ID_C, {**rejected, "reason": "a" * 501}, 422, "invalid_reason")
        refused("reason com quebra de linha", ID_C, {**rejected, "reason": "a\nb"}, 422, "invalid_reason")
        refused("reason com override bidi", ID_C, {**rejected, "reason": "a\u202eb"}, 422, "invalid_reason")

        # --- analista ---
        refused("analista inexistente", ID_C, {**good, "analyst_id": "analyst-ninguem"}, 422, "analyst_not_found")
        refused("analista inativo", ID_C, {**good, "analyst_id": "analyst-mike"}, 422, "analyst_inactive")
        refused("nome fora do charset (O'Brien)", ID_C, {**good, "analyst_id": "analyst-obrien"}, 422, "invalid_author")
        broken_incidents = MagicMock()
        broken_incidents.get_analyst.side_effect = sqlite3.OperationalError("db partida C:\\segredo\\incidents.sqlite3")
        main.incident_store = broken_incidents
        spy_vaccines = MagicMock(wraps=real_vaccines)
        main.vaccine_store = spy_vaccines
        r = post(ID_C, good)
        leaked = [w for w in ("db partida", "segredo", ".sqlite3", "Traceback") if w in r.text]
        check("base de analistas em baixo -> 503 incidents_unavailable sem fuga",
              r.status_code == 503 and r.json() == {"detail": "incidents_unavailable"} and leaked == [])
        check("base de analistas em baixo: decide_vaccine não foi chamado e a vaccine continua por decidir",
              spy_vaccines.decide_vaccine.called is False and decision_rows(path) == [])
        main.incident_store, main.vaccine_store = real_incidents, real_vaccines

        # --- store ---
        refused("vaccine substituída", ID_A, good, 409, "vaccine_superseded")
        r = post(ID_C, good)
        check("aprovar a vaccine C -> 200", r.status_code == 200)
        refused("aprovar de novo a já aprovada", ID_C, good, 409, "already_decided")
        refused("rejeitar a já aprovada", ID_C,
                {"decision": "rejected", "analyst_id": "analyst-jeremy", "reason": "Mudei de ideias"},
                409, "already_decided")
        refused("vaccine inexistente", "vac-000000000000", good, 404, "entry_not_found")
        missing = os.path.join(tmp.name, "nao_existe.sqlite3")
        main.vaccine_store = VaccineStore(missing)
        r = post(ID_C, good)
        check("store inexistente -> 404 entry_not_found", r.status_code == 404 and r.json() == {"detail": "entry_not_found"})
        check("store inexistente: o ficheiro continua a não existir", not os.path.exists(missing))
        main.vaccine_store = real_vaccines

        # --- 503 do store de vaccines ---
        leak_words = ("db partida", "payload corrompido", "segredo", ".sqlite3", "Traceback")
        for exc in (sqlite3.OperationalError("db partida C:\\segredo\\vaccines.sqlite3"),
                    ValueError("payload corrompido C:\\segredo")):
            broken = MagicMock()
            broken.decide_vaccine.side_effect = exc
            main.vaccine_store = broken
            r = post(ID_B, {"decision": "rejected", "analyst_id": "analyst-jeremy", "reason": "x"})
            check(f"decide_vaccine com {type(exc).__name__} -> 503 store_unavailable sem fuga",
                  r.status_code == 503 and r.json() == {"detail": "store_unavailable"}
                  and [w for w in leak_words if w in r.text] == [])
        reread_failures = (
            ("releitura com sqlite3.Error", {"side_effect": sqlite3.OperationalError("db partida C:\\segredo")}),
            ("releitura com ValueError", {"side_effect": ValueError("payload corrompido")}),
            ("releitura sem vaccine", {"return_value": None}),
        )
        for label, behaviour in reread_failures:
            broken = MagicMock()
            broken.decide_vaccine.return_value = {}
            broken.get_vaccine.configure_mock(**behaviour)
            main.vaccine_store = broken
            r = post(ID_B, {"decision": "rejected", "analyst_id": "analyst-jeremy", "reason": "x"})
            check(f"{label} -> 503 store_unavailable sem fuga",
                  r.status_code == 503 and r.json() == {"detail": "store_unavailable"}
                  and [w for w in leak_words if w in r.text] == [])
        main.vaccine_store = real_vaccines
        check("os 503 não gravaram nada além da aprovação de C", len(decision_rows(path)) == 1)

        # --- métodos ---
        rows_before, decisions_before = rows_of(path), decision_rows(path)
        url = f"/api/vaccines/{ID_B}/decision"
        for method in ("GET", "PUT", "PATCH", "DELETE"):
            r = client.request(method, url, headers=HEADERS, json=good)
            check(f"{method} com chave -> 405", r.status_code == 405)
            r = client.request(method, url, json=good)
            check(f"{method} sem chave -> 405 ou 401, nunca 2xx", r.status_code in (405, 401))
        check("os outros métodos não gravaram nada", rows_of(path) == rows_before and decision_rows(path) == decisions_before)

        # --- id do caminho mal formado ---
        for bad in ("abc", "vac-XYZ", "VAC-0123456789ab", "vac-0123456789AB", "vac-0123456789ab0"):
            refused(f"id {bad} com corpo válido", bad, good, 422, "invalid_vaccine_id")
            refused(f"id {bad} com corpo inválido", bad, {**good, "decided_at": "x"}, 422, "invalid_vaccine_id")
            r = post(bad, good, headers={})
            check(f"id {bad} sem chave -> 401", r.status_code == 401)

        # --- os outros 422 da app não mudam ---
        for url in ("/api/vaccines/abc", "/api/vaccines?limit=0"):
            r = client.get(url, headers=HEADERS)
            check(f"GET {url} continua 422 com detail em lista",
                  r.status_code == 422 and isinstance(r.json().get("detail"), list))

        # --- função pura ---
        parse = main._parse_vaccine_decision_body
        check("_parse: corpo válido", parse(b'{"decision":"approved","analyst_id":"analyst-eddie"}')
              == ({"decision": "approved", "analyst_id": "analyst-eddie", "reason": None}, None))
        check("_parse: lista -> invalid_body", parse(b"[]") == (None, "invalid_body"))
        check("_parse: analyst_id mal formado -> invalid_author",
              parse(b'{"decision":"approved","analyst_id":"Eddie"}') == (None, "invalid_author"))
    finally:
        main.vaccine_store, main.incident_store = original_vaccines, original_incidents
        tmp.cleanup()


# --- Varrimento "nada aplica nem executa" (D-14) -----------------------------
# Tudo por AST: comentários e docstrings não contam. As funções scan_* e
# handler_problems são puras (recebem código-fonte) para o autoteste as poder
# exercitar contra violações plantadas.
SCRIPTS_DIR = pathlib.Path(__file__).resolve().parent

FORBIDDEN_IMPORT_ROOTS = frozenset({
    "subprocess", "ssh_client", "paramiko", "asyncssh", "wazuh_client", "httpx", "requests", "socket",
    "urllib", "http", "pty", "shlex", "multiprocessing", "ctypes",
})
FORBIDDEN_NAMES = frozenset({
    "subprocess", "ssh_client", "VMSSHClient", "vm_ssh_client", "manager_client", "WazuhManagerClient", "paramiko",
})
# No fecho de funções locais (ex.: _build_attack_registry) o Indexer pode ser lido,
# por isso só estas raízes são proibidas.
CLOSURE_FORBIDDEN_ROOTS = frozenset({"manager_client", "vm_ssh_client", "VMSSHClient", "subprocess"})
OS_EXEC_CALLS = frozenset({"system", "popen", "posix_spawn", "posix_spawnp", "startfile", "fork", "forkpty"})
DYNAMIC_CALLS = frozenset({"__import__", "import_module", "eval", "exec"})

HANDLER_NAME = "decide_vaccine_route"
HANDLER_STORE_ALLOWED = {"decide_vaccine", "get_vaccine"}
HANDLER_INCIDENT_ALLOWED = {"get_analyst"}
HANDLER_FORBIDDEN_NAMES = frozenset({"indexer_client", "manager_client", "vm_ssh_client", "ws_manager",
                                     "network_ws_manager"})
ROUTES_STORE_ALLOWED = {"list_vaccines", "count_by_state", "get_vaccine", "decide_vaccine"}
EXPECTED_VACCINE_FUNCTIONS = {
    "_run_vaccine_cycle", "_vaccine_cycle_body", "_vaccine_loop", "_start_vaccine_loop", "list_vaccines",
    "get_vaccine", "decide_vaccine_route", "_parse_vaccine_decision_body", "_read_vaccine_decision_body",
    "_vaccine_decision_refusal", "_vaccine_decision_validation_error",
}
EXPECTED_VACCINE_PATHS = {"/api/vaccines", "/api/vaccines/{vaccine_id}", "/api/vaccines/{vaccine_id}/decision"}


def _root_name(node) -> str | None:
    """Nome na raiz de uma cadeia a.b.c (ou None se a raiz não é um Name)."""
    while isinstance(node, ast.Attribute):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _process_call(node: ast.Call) -> str | None:
    """os.system/os.popen/os.spawn*/os.exec*/asyncio.create_subprocess_* (ou o nome importado sozinho)."""
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        if func.value.id == "os" and (func.attr in OS_EXEC_CALLS or func.attr.startswith(("spawn", "exec"))):
            return f"os.{func.attr}"
        if func.value.id == "asyncio" and func.attr.startswith("create_subprocess_"):
            return f"asyncio.{func.attr}"
    if isinstance(func, ast.Name) and func.id.startswith("create_subprocess_"):
        return func.id
    return None


def _dynamic_call(node: ast.Call) -> str | None:
    func = node.func
    name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
    return name if name in DYNAMIC_CALLS else None


def scan_subtree(root, where: str, mode: str) -> list[str]:
    """Violações numa subárvore. mode "full": imports, nomes e chamadas proibidos;
    mode "closure": acesso a manager_client/vm_ssh_client/VMSSHClient/subprocess e chamadas de processo."""
    found: list[str] = []
    for node in ast.walk(root):
        line = getattr(node, "lineno", 0)
        if mode == "full":
            if isinstance(node, ast.Import):
                found += [f"{where}:{line}: import {a.name}" for a in node.names
                          if a.name.split(".")[0] in FORBIDDEN_IMPORT_ROOTS]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                if node.module.split(".")[0] in FORBIDDEN_IMPORT_ROOTS:
                    found.append(f"{where}:{line}: from {node.module} import ...")
                elif node.module.split(".")[0] in ("os", "asyncio"):
                    found += [f"{where}:{line}: from {node.module} import {a.name}" for a in node.names
                              if a.name in OS_EXEC_CALLS or a.name.startswith(("spawn", "exec", "create_subprocess_"))]
            elif isinstance(node, ast.Name) and node.id in FORBIDDEN_NAMES:
                found.append(f"{where}:{line}: nome {node.id}")
            elif isinstance(node, ast.Call):
                what = _process_call(node) or _dynamic_call(node)
                if what:
                    found.append(f"{where}:{line}: chamada {what}")
        else:
            if isinstance(node, ast.Attribute) and _root_name(node) in CLOSURE_FORBIDDEN_ROOTS:
                found.append(f"{where}:{line}: acesso a {_root_name(node)}.{node.attr}")
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in CLOSURE_FORBIDDEN_ROOTS:
                    found.append(f"{where}:{line}: chamada {node.func.id}")
                what = _process_call(node)
                if what:
                    found.append(f"{where}:{line}: chamada {what}")
    return found


def scan_module(source: str, where: str = "<módulo>") -> list[str]:
    return scan_subtree(ast.parse(source), where, "full")


def _top_level_functions(tree: ast.Module) -> dict:
    return {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _route_path(func) -> str | None:
    """Primeiro argumento string do primeiro decorador-chamada (@app.get("/api/..."))."""
    for deco in func.decorator_list:
        if isinstance(deco, ast.Call) and deco.args and isinstance(deco.args[0], ast.Constant) \
                and isinstance(deco.args[0].value, str):
            return deco.args[0].value
    return None


def _is_vaccine_function(func) -> bool:
    path = _route_path(func)
    return "vaccine" in func.name.lower() or (path is not None and path.startswith("/api/vaccines"))


def _local_closure(seeds, funcs: dict) -> set:
    """Seeds mais todas as funções de topo do ficheiro que alcançam por referência a um nome (chamada ou argumento)."""
    seen, queue = set(seeds), list(seeds)
    while queue:
        for node in ast.walk(funcs[queue.pop()]):
            if isinstance(node, ast.Name) and node.id in funcs and node.id not in seen:
                seen.add(node.id)
                queue.append(node.id)
    return seen


def scan_main(source: str) -> tuple[list[str], set]:
    """(violações, nomes das funções de vaccines) de um main.py: regras completas nas funções de vaccines,
    regras de fecho nas funções locais que elas alcançam."""
    tree = ast.parse(source)
    funcs = _top_level_functions(tree)
    seeds = {name for name, func in funcs.items() if _is_vaccine_function(func)}
    found: list[str] = []
    for name in sorted(seeds):
        found += scan_subtree(funcs[name], name, "full")
    for name in sorted(_local_closure(seeds, funcs) - seeds):
        found += scan_subtree(funcs[name], name, "closure")
    return found, seeds


def _store_attrs(nodes, store: str) -> tuple[set, int]:
    """(atributos usados de `store`, nº de usos do nome sem atributo)."""
    attrs: set = set()
    attribute_uses = 0
    name_uses = 0
    for tree_node in nodes:
        for node in ast.walk(tree_node):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == store:
                attrs.add(node.attr)
                attribute_uses += 1
            elif isinstance(node, ast.Name) and node.id == store:
                name_uses += 1
    return attrs, name_uses - attribute_uses


def handler_problems(source: str, handler: str = HANDLER_NAME) -> list[str]:
    """Problemas do handler de decisão e dos auxiliares locais que alcança (D-08, D-14, D-15)."""
    tree = ast.parse(source)
    funcs = _top_level_functions(tree)
    if handler not in funcs:
        return [f"handler {handler} não encontrado"]
    nodes = [funcs[n] for n in _local_closure({handler}, funcs)]
    problems: list[str] = []
    vac_attrs, vac_bare = _store_attrs(nodes, "vaccine_store")
    inc_attrs, inc_bare = _store_attrs(nodes, "incident_store")
    if vac_attrs != HANDLER_STORE_ALLOWED:
        problems.append(f"métodos de vaccine_store {sorted(vac_attrs)} != {sorted(HANDLER_STORE_ALLOWED)}")
    if inc_attrs != HANDLER_INCIDENT_ALLOWED:
        problems.append(f"métodos de incident_store {sorted(inc_attrs)} != {sorted(HANDLER_INCIDENT_ALLOWED)}")
    if vac_bare or inc_bare:
        problems.append("um store é usado sem ser por atributo")
    lines: dict = {}
    for node in ast.walk(funcs[handler]):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "vaccine_store":
            lines.setdefault(node.attr, []).append(node.lineno)
    for method in sorted(HANDLER_STORE_ALLOWED):
        if len(lines.get(method, [])) != 1:
            problems.append(f"vaccine_store.{method} aparece {len(lines.get(method, []))} vez(es) no handler (esperada 1)")
    if len(lines.get("decide_vaccine", [])) == 1 and len(lines.get("get_vaccine", [])) == 1 \
            and lines["decide_vaccine"][0] >= lines["get_vaccine"][0]:
        problems.append("get_vaccine vem antes de decide_vaccine (D-08: decidir antes de reler)")
    for tree_node in nodes:
        for node in ast.walk(tree_node):
            if isinstance(node, ast.Name) and (node.id in HANDLER_FORBIDDEN_NAMES or node.id.startswith("append_")):
                problems.append(f"{tree_node.name}:{node.lineno}: nome {node.id}")
    problems += scan_subtree(funcs[handler], handler, "full")
    return problems


def run_no_apply() -> None:
    # --- autoteste: o varrimento apanha violações plantadas e deixa passar código limpo ---
    check("varrimento: autoteste, subprocess numa função _vaccine_* é apanhado",
          bool(scan_main("def _vaccine_probe():\n    subprocess.run(['x'])\n")[0]))
    check("varrimento: autoteste, manager_client numa rota de vaccines é apanhado",
          bool(scan_main("async def list_vaccines():\n    await manager_client.restart()\n")[0]))
    check("varrimento: autoteste, manager_client numa rota /api/vaccines* (nome neutro) é apanhado",
          bool(scan_main('@app.get("/api/vaccines/x")\nasync def probe():\n    await manager_client.restart()\n')[0]))
    check("varrimento: autoteste, os.system numa função auxiliar chamada por uma de vaccines é apanhado",
          bool(scan_main("def _helper():\n    os.system('x')\n\ndef _vaccine_probe():\n    _helper()\n")[0]))
    check("varrimento: autoteste, vm_ssh_client.run passado como argumento a um auxiliar é apanhado",
          bool(scan_main("def _helper():\n    run(vm_ssh_client.run)\n\ndef _vaccine_probe():\n    _helper()\n")[0]))
    check("varrimento: autoteste, import subprocess num módulo vaccine_* é apanhado",
          bool(scan_module("import subprocess\n")) and bool(scan_module("def f():\n    from socket import socket\n")))
    check("varrimento: autoteste, asyncio.create_subprocess_exec e os.execv são apanhados",
          bool(scan_module("async def f():\n    await asyncio.create_subprocess_exec('x')\n"))
          and bool(scan_module("def f():\n    os.execv('x', [])\n")))
    clean_main = ("def _helper(vm_ssh_client):\n    return vm_ssh_client is not None\n\n"
                  "def _vaccine_probe(a, b):\n    return a + b\n")
    clean_found, clean_seeds = scan_main(clean_main)
    check("varrimento: autoteste, fonte limpa não dá nenhuma violação (e uma comparação com None não conta)",
          clean_found == [] and clean_seeds == {"_vaccine_probe"} and scan_module("import re\nx = 1 + 2\n") == [])
    good_handler = ("async def decide_vaccine_route():\n    a = incident_store.get_analyst(1)\n"
                    "    vaccine_store.decide_vaccine(1)\n    return vaccine_store.get_vaccine(1)\n")
    check("varrimento: autoteste, handler conforme não dá problemas", handler_problems(good_handler) == [])
    check("varrimento: autoteste, handler com get_vaccine antes de decide_vaccine é apanhado",
          bool(handler_problems("async def decide_vaccine_route():\n    incident_store.get_analyst(1)\n"
                                "    vaccine_store.get_vaccine(1)\n    vaccine_store.decide_vaccine(1)\n")))
    check("varrimento: autoteste, handler com método de store a mais, ws_manager ou append_* é apanhado",
          bool(handler_problems(good_handler + "    vaccine_store.upsert_batch(1)\n"))
          and bool(handler_problems(good_handler + "    await ws_manager.broadcast(1)\n"))
          and bool(handler_problems(good_handler + "    append_alert_history(1)\n")))
    check("varrimento: autoteste, handler que chama um auxiliar local com manager_client é apanhado",
          bool(handler_problems("def _aux():\n    manager_client.x()\n\n" + good_handler.replace(
              "    a = ", "    _aux()\n    a = ", 1))))

    # --- módulos vaccine_*.py inteiros ---
    module_files = sorted(SCRIPTS_DIR.glob("vaccine_*.py"))
    names = {p.stem for p in module_files}
    check(f"varrimento: o glob vaccine_*.py encontra os quatro módulos {sorted(names)}",
          {"vaccine_decision", "vaccine_engine", "vaccine_ingest", "vaccine_store"} <= names)
    for path in module_files:
        violations = scan_module(path.read_text(encoding="utf-8"), path.name)
        check(f"varrimento: {path.name} sem imports, nomes nem chamadas que apliquem ou executem {violations}",
              violations == [])

    # --- funções de vaccines de main.py ---
    main_source = (SCRIPTS_DIR / "main.py").read_text(encoding="utf-8")
    violations, vaccine_functions = scan_main(main_source)
    check(f"varrimento: main.py, funções de vaccines e fecho local sem violações {violations}", violations == [])
    check(f"varrimento: main.py, o conjunto de funções de vaccines inclui as onze esperadas "
          f"(em falta: {sorted(EXPECTED_VACCINE_FUNCTIONS - vaccine_functions)})",
          EXPECTED_VACCINE_FUNCTIONS <= vaccine_functions)

    # --- handler de decisão ---
    problems = handler_problems(main_source)
    check(f"varrimento: handler de decisão só usa decide_vaccine, get_vaccine e get_analyst, por esta ordem, "
          f"sem Wazuh, WebSocket nem histórico {problems}", problems == [])
    main_funcs = _top_level_functions(ast.parse(main_source))
    route_funcs = [f for f in main_funcs.values() if (_route_path(f) or "").startswith("/api/vaccines")]
    route_nodes = [main_funcs[n] for n in _local_closure({f.name for f in route_funcs}, main_funcs)]
    route_attrs, route_bare = _store_attrs(route_nodes, "vaccine_store")
    check(f"varrimento: as rotas /api/vaccines* só usam {sorted(ROUTES_STORE_ALLOWED)} do vaccine_store "
          f"(usam {sorted(route_attrs)})", len(route_funcs) == 3 and route_attrs <= ROUTES_STORE_ALLOWED and route_bare == 0)

    # --- rotas registadas ---
    vac_routes = [r for r in main.app.routes if "vaccine" in getattr(r, "path", "").lower()]
    paths = {r.path for r in vac_routes}
    check(f"varrimento: as rotas com 'vaccine' no caminho são exatamente as três permitidas {sorted(paths)}",
          paths == EXPECTED_VACCINE_PATHS and len(vac_routes) == 3)
    check("varrimento: nenhuma rota de vaccines tem apply, deploy, activate, execute ou enable no caminho",
          not any(re.search(r"apply|deploy|activate|execute|enable", r.path, re.IGNORECASE) for r in vac_routes))
    methods_of = {r.path: set(getattr(r, "methods", None) or ()) for r in vac_routes}
    union = set().union(*methods_of.values()) if methods_of else set()
    check(f"varrimento: só a rota de decisão aceita POST e nenhuma aceita PUT, PATCH nem DELETE {methods_of}",
          union <= {"GET", "HEAD", "POST"}
          and [p for p, m in methods_of.items() if "POST" in m] == ["/api/vaccines/{vaccine_id}/decision"]
          and all(methods_of.values()))
    check("varrimento: todas as rotas de vaccines têm require_api_key nas dependencies da própria rota",
          all(any(getattr(d, "dependency", None) is main.require_api_key for d in r.dependencies)
              for r in vac_routes))

    # --- texto: aprovada não é aplicada ---
    notice = main.VACCINE_DECISION_NOTICE
    doc = " ".join((main.decide_vaccine_route.__doc__ or "").split())  # a docstring quebra linhas a meio de frases
    check("varrimento: VACCINE_DECISION_NOTICE diz 'aceite pelo analista' e 'não aplicada no Wazuh'",
          "aceite pelo analista" in notice and "não aplicada no Wazuh" in notice)
    check("varrimento: a docstring do handler diz 'aceite pelo analista', 'não aplica nada no Wazuh' e 'autodeclarada'",
          all(text in doc for text in ("aceite pelo analista", "não aplica nada no Wazuh", "autodeclarada")))


if __name__ == "__main__":
    run_tracer()
    print()
    run_refusals()
    print()
    run_no_apply()
    print()
    if failures:
        print(f"{len(failures)} verificação(ões) falharam:")
        for label in failures:
            print(f"  - {label}")
        sys.exit(1)
    print("Todas as verificações passaram.")
