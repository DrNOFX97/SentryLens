"""
Testes do store de vaccines (Phase 13): vaccine_store sem a app FastAPI e sem
Wazuh. Cobre idempotência, reinício, imutabilidade garantida no próprio
ficheiro SQLite (CHECK e triggers), a razão da emenda A1 a D-04
(ON CONFLICT DO NOTHING em vez de INSERT OR IGNORE), a política superseded_by
(D-06/D-07, incluindo o vaivém A-B-A), os filtros do store e a resolução do
caminho (D-05). As vaccines vêm do motor verdadeiro (vaccine_engine) sobre
ataques montados à mão. Só IPs de documentação, se alguma vez houver.

Correr (a partir de scripts/):
    python test_vaccine_store.py
"""

import copy
import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta, timezone

import vaccine_engine
import vaccine_store
from vaccine_store import STORE_FIELDS, VaccineStore, resolve_db_path

NOW = datetime.now(timezone.utc)
NOW_ISO = NOW.isoformat()

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
    conn = sqlite3.connect(path)
    try:
        return conn.execute("SELECT * FROM vaccines ORDER BY id").fetchall()
    finally:
        conn.close()


def raises_integrity(path: str, sql: str, params=()) -> bool:
    conn = sqlite3.connect(path)
    try:
        conn.execute(sql, params)
        conn.commit()
        return False
    except sqlite3.IntegrityError:
        return True
    finally:
        conn.close()


def engine_form(v: dict) -> dict:
    return {k: val for k, val in v.items() if k not in STORE_FIELDS}


def ids(rows: list[dict]) -> list[str]:
    return [r["id"] for r in rows]


def run_fixtures() -> None:
    check("fixtures: ids literais do motor", (vA["id"], vB["id"], vC["id"]) == (ID_A, ID_B, ID_C))
    check("fixtures: as três passam validate_vaccine",
          all(vaccine_engine.validate_vaccine(v) == [] for v in (vA, vB, vC)))


def run_idempotency_and_restart() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "v.sqlite3")
        store = VaccineStore(path)
        check("1.ª gravação: inserted 1, existing 0", store.upsert_batch([vC], NOW_ISO) == {"inserted": 1, "existing": 0})
        check("2.ª gravação: inserted 0, existing 1", store.upsert_batch([vC], NOW_ISO) == {"inserted": 0, "existing": 1})
        check("SELECT COUNT(*) == 1", len(rows_of(path)) == 1)
        check("todas as linhas têm state 'proposed'", all(r[1] == "proposed" for r in rows_of(path)))

        # reinício: nova instância sobre o mesmo ficheiro
        fresh = VaccineStore(path)
        before = store.list_vaccines()
        check("reinício: list_vaccines igual", fresh.list_vaccines() == before)
        check("reinício: get_vaccine igual", fresh.get_vaccine(ID_C) == store.get_vaccine(ID_C))
        check("o payload lido, sem STORE_FIELDS, é a vaccine original", engine_form(fresh.get_vaccine(ID_C)) == vC)
        check("STORE_FIELDS acrescentados na leitura",
              set(fresh.get_vaccine(ID_C)) == set(vC) | set(STORE_FIELDS) and fresh.get_vaccine(ID_C)["created_at"] == NOW_ISO)

    # atomicidade: tudo ou nada
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "v.sqlite3")
        store = VaccineStore(path)
        bad = copy.deepcopy(vB)
        bad["id"] = "vac-aaaaaaaaaaaa"
        bad["verdict"] = "detected"
        bad["origin"]["attack_id"] = 9
        try:
            store.upsert_batch([vB, bad], NOW_ISO)
            raised = False
        except sqlite3.IntegrityError:
            raised = True
        check("atomicidade: lote com uma linha inválida levanta IntegrityError", raised)
        check("atomicidade: a vaccine boa do mesmo lote NÃO ficou gravada", rows_of(path) == [])


def run_immutability_and_a1() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "v.sqlite3")
        store = VaccineStore(path)
        store.upsert_batch([vC], NOW_ISO)
        snapshot = rows_of(path)
        for label, sql, params in (
            ("UPDATE state='applied'", "UPDATE vaccines SET state = 'applied' WHERE id = ?", (ID_C,)),
            ("UPDATE payload='{}'", "UPDATE vaccines SET payload = '{}' WHERE id = ?", (ID_C,)),
            ("UPDATE verdict='not_detected'", "UPDATE vaccines SET verdict = 'not_detected' WHERE id = ?", (ID_C,)),
            ("UPDATE created_at='x'", "UPDATE vaccines SET created_at = 'x' WHERE id = ?", (ID_C,)),
            ("DELETE", "DELETE FROM vaccines WHERE id = ?", (ID_C,)),
        ):
            check(f"imutável: {label} -> IntegrityError", raises_integrity(path, sql, params))
        check("imutável: conteúdo inalterado depois das tentativas", rows_of(path) == snapshot)
        check("superseded_by é a única coluna mutável: UPDATE superseded_by=NULL aceite",
              not raises_integrity(path, "UPDATE vaccines SET superseded_by = NULL WHERE id = ?", (ID_C,)))

        # A1: ON CONFLICT DO NOTHING deixa o CHECK falhar; INSERT OR IGNORE engoli-o
        insert = ("INSERT INTO vaccines (id, state, attack_id, scenario, verdict, payload, created_at) "
                  "VALUES (?, ?, 7, 'smb_enum', 'partial', '{}', 'x')")
        check("A1: ON CONFLICT DO NOTHING com state 'applied' -> IntegrityError",
              raises_integrity(path, insert + " ON CONFLICT(id) DO NOTHING", ("vac-111111111111", "applied")))
        mem = sqlite3.connect(":memory:")
        mem.executescript(vaccine_store.SCHEMA)
        cur = mem.execute(insert.replace("INSERT INTO", "INSERT OR IGNORE INTO"), ("vac-111111111111", "applied"))
        check("A1: INSERT OR IGNORE engole o CHECK (rowcount 0, sem erro): razão da emenda a D-04",
              cur.rowcount == 0)
        mem.close()
        check("json_valid: payload 'x' -> IntegrityError",
              raises_integrity(path, "INSERT INTO vaccines (id, attack_id, scenario, verdict, payload, created_at) "
                                     "VALUES ('vac-222222222222', 7, 'smb_enum', 'partial', 'x', 'x')"))
        check("id 'abc' -> IntegrityError",
              raises_integrity(path, "INSERT INTO vaccines (id, attack_id, scenario, verdict, payload, created_at) "
                                     "VALUES ('abc', 7, 'smb_enum', 'partial', '{}', 'x')"))
        check("nada disto acrescentou linhas", len(rows_of(path)) == 1 and rows_of(path) == snapshot)


def run_supersede() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "v.sqlite3")
        store = VaccineStore(path)
        check("lote vazio: inserted 0, existing 0", store.upsert_batch([], NOW_ISO) == {"inserted": 0, "existing": 0})
        check("lote vazio não cria nada", store.list_vaccines() == ([], 0, 0))
        store.upsert_batch([vC], NOW_ISO)
        store.upsert_batch([vA], NOW_ISO)
        check("A isolada: não é substituída", store.get_vaccine(ID_A)["superseded_by"] is None)
        store.upsert_batch([vB], NOW_ISO)

        a, b = store.get_vaccine(ID_A), store.get_vaccine(ID_B)
        check("D-06: A fica superseded_by B, state proposed, sem apagar",
              a["superseded_by"] == ID_B and a["state"] == "proposed" and engine_form(a) == vA)
        check("D-06: B (a atual) sem superseded_by", b["superseded_by"] is None)
        check("D-07: as escritas do ataque 2 não tocam em C (ataque 3)", store.get_vaccine(ID_C)["superseded_by"] is None)
        rows, total, store_total = store.list_vaccines()
        check("lista por omissão omite substituídas: C e B", ids(rows) == [ID_C, ID_B] and total == 2 and store_total == 3)
        rows, total, store_total = store.list_vaccines(include_superseded=True)
        check("include_superseded=True: C, B e A", ids(rows) == [ID_C, ID_B, ID_A] and total == 3 and store_total == 3)
        check("get_vaccine devolve também a substituída", store.get_vaccine(ID_A) is not None)

        # vaivém A-B-A
        check("vaivém: A de novo -> inserted 0, existing 1", store.upsert_batch([vA], NOW_ISO) == {"inserted": 0, "existing": 1})
        check("vaivém: A volta a ser a atual (superseded_by limpo)", store.get_vaccine(ID_A)["superseded_by"] is None)
        check("vaivém: B aponta para A", store.get_vaccine(ID_B)["superseded_by"] == ID_A)
        rows, total, store_total = store.list_vaccines()
        check("vaivém: lista tem A e C e não B, 3 linhas no total",
              sorted(ids(rows)) == sorted([ID_A, ID_C]) and total == 2 and store_total == 3)
        snapshot = rows_of(path)
        store.upsert_batch([vA], NOW_ISO)
        check("repetir o upsert de A não muda nada", rows_of(path) == snapshot)
        check("C nunca foi tocada", store.get_vaccine(ID_C)["superseded_by"] is None)

        # filtros e paginação (sobre A atual, B substituída, C atual)
        check("attack_id=3 -> [C]", ids(store.list_vaccines(attack_id=3)[0]) == [ID_C])
        check("technique=T1053 -> [C]", ids(store.list_vaccines(technique="T1053")[0]) == [ID_C])
        check("technique=T9999 -> ([], 0, 3)", store.list_vaccines(technique="T9999") == ([], 0, 3))
        page, page_total, _ = store.list_vaccines(limit=1, offset=1)
        check("limit=1, offset=1: uma linha e total igual ao sem paginação",
              len(page) == 1 and page_total == store.list_vaccines()[1])
        check("ordem por attack_id descendente (3 antes de 2)", ids(store.list_vaccines()[0]) == [ID_C, ID_A])
        check("attack_id=2 + include_superseded: A e B", sorted(ids(store.list_vaccines(attack_id=2, include_superseded=True)[0]))
              == sorted([ID_A, ID_B]))
        check("get_vaccine de id inexistente -> None", store.get_vaccine("vac-000000000000") is None)
        check("filtro com texto hostil só devolve vazio, nunca levanta",
              store.list_vaccines(technique="T1053' OR '1'='1") == ([], 0, 3))


def run_missing_file_and_path() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "v.sqlite3")
        store = VaccineStore(path)
        check("ficheiro inexistente: list_vaccines == ([], 0, 0)", store.list_vaccines() == ([], 0, 0))
        check("ficheiro inexistente: get_vaccine is None", store.get_vaccine(ID_A) is None)
        check("as leituras não criaram o ficheiro", not os.path.exists(path))
        store.upsert_batch([vA], NOW_ISO)
        check("o ficheiro nasce na primeira escrita", os.path.exists(path))
        os.remove(path)
        check("ficheiro apagado: leitura volta a ser vazia", store.list_vaccines() == ([], 0, 0))
        check("ficheiro apagado: gravar de novo recria o esquema",
              store.upsert_batch([vA], NOW_ISO) == {"inserted": 1, "existing": 0} and len(rows_of(path)) == 1)

    module_dir = os.path.dirname(os.path.abspath(vaccine_store.__file__))
    default = os.path.join(module_dir, "vaccines.sqlite3")
    check("resolve_db_path(None) == vaccines.sqlite3 na pasta do módulo", resolve_db_path(None) == default)
    check("resolve_db_path('') == vaccines.sqlite3 na pasta do módulo", resolve_db_path("") == default)
    original_cwd = os.getcwd()
    with tempfile.TemporaryDirectory() as tmp:
        try:
            os.chdir(tmp)
            relative = resolve_db_path("sub/x.sqlite3")
        finally:
            os.chdir(original_cwd)
        check("caminho relativo é resolvido contra a pasta do módulo, nunca o cwd",
              os.path.dirname(os.path.dirname(relative)) == module_dir and not relative.startswith(os.path.abspath(tmp)))
        absolute = os.path.join(tmp, "a", "..", "abs.sqlite3")
        check("caminho absoluto devolvido normalizado", resolve_db_path(absolute) == os.path.normpath(absolute))
    check("constantes de ambiente e de ficheiro",
          vaccine_store.DB_PATH_ENV == "SENTRYLENS_VACCINES_DB_PATH" and vaccine_store.DEFAULT_DB_FILENAME == "vaccines.sqlite3")


if __name__ == "__main__":
    run_fixtures()
    run_idempotency_and_restart()
    run_immutability_and_a1()
    run_supersede()
    run_missing_file_and_path()
    print()
    if failures:
        print(f"{len(failures)} verificação(ões) falharam:")
        for label in failures:
            print(f"  - {label}")
        sys.exit(1)
    print("Todas as verificações passaram.")
