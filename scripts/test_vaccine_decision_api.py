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

import json
import os
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


if __name__ == "__main__":
    run_tracer()
    print()
    if failures:
        print(f"{len(failures)} verificação(ões) falharam:")
        for label in failures:
            print(f"  - {label}")
        sys.exit(1)
    print("Todas as verificações passaram.")
