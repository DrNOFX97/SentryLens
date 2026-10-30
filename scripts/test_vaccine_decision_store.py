"""
Testes do store de decisões do R12 (Phase 15): vaccine_store.decide_vaccine e a
leitura com estado derivado, sem a app FastAPI e sem Wazuh. Cobre o tracer
(aprovar e rejeitar ponta a ponta, o DDL do R11 intacto, ficheiro antigo sem a
tabela vaccine_decisions) e a validação da entrada antes de tocar no disco. As
vaccines vêm do motor verdadeiro (vaccine_engine) sobre ataques montados à mão.

Correr (a partir de scripts/):
    python test_vaccine_decision_store.py
"""

import ast
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone

import vaccine_decision
import vaccine_engine
import vaccine_store
from vaccine_decision import DECISION_RECORD_KEYS, VaccineDecisionError
from vaccine_store import STORE_FIELDS, VaccineStore

NOW = datetime.now(timezone.utc)
NOW_ISO = NOW.isoformat()
DECIDED_AT = "2026-10-29T12:00:00+00:00"

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

# DDL do R11 congelado (cópia exata do literal SCHEMA de scripts/vaccine_store.py no
# commit 7b7fd25): serve para provar que a tabela vaccines não muda e para criar
# ficheiros "antigos" sem vaccine_decisions.
R11_VACCINES_DDL = """
CREATE TABLE IF NOT EXISTS vaccines (
    id TEXT PRIMARY KEY CHECK (id GLOB 'vac-*' AND length(id) = 16),
    state TEXT NOT NULL DEFAULT 'proposed' CHECK (state = 'proposed'),
    attack_id INTEGER NOT NULL CHECK (attack_id BETWEEN 1 AND 999999999),
    scenario TEXT NOT NULL,
    mitre_technique TEXT,
    verdict TEXT NOT NULL CHECK (verdict IN ('not_detected', 'partial')),
    payload TEXT NOT NULL CHECK (json_valid(payload)),
    created_at TEXT NOT NULL,
    superseded_by TEXT CHECK (superseded_by IS NULL OR (superseded_by GLOB 'vac-*' AND length(superseded_by) = 16))
);
CREATE INDEX IF NOT EXISTS idx_vaccines_attack ON vaccines(attack_id);
CREATE INDEX IF NOT EXISTS idx_vaccines_technique ON vaccines(mitre_technique);
CREATE TRIGGER IF NOT EXISTS vaccines_no_delete BEFORE DELETE ON vaccines
BEGIN SELECT RAISE(ABORT, 'vaccines e append-only'); END;
CREATE TRIGGER IF NOT EXISTS vaccines_immutable
BEFORE UPDATE OF id, state, attack_id, scenario, mitre_technique, verdict, payload, created_at ON vaccines
BEGIN SELECT RAISE(ABORT, 'vaccines so aceita alterar superseded_by'); END;
"""


def rows_of(path: str) -> list[tuple]:
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
    """As 7 colunas de vaccine_decisions (sem `id`) pela ordem de inserção; [] se a tabela não existir."""
    if not has_decisions_table(path):
        return []
    conn = sqlite3.connect(path)
    try:
        return conn.execute("SELECT vaccine_id, decision, decided_by, decided_by_name, decided_at, reason, "
                            "previous_state FROM vaccine_decisions ORDER BY id").fetchall()
    finally:
        conn.close()


def make_r11_file(path: str, vaccines: list[dict]) -> None:
    """Ficheiro como o do R11: só o DDL congelado, sem vaccine_decisions."""
    conn = sqlite3.connect(path)
    try:
        conn.executescript(R11_VACCINES_DDL)
        for v in vaccines:
            origin = v["origin"]
            conn.execute(
                "INSERT INTO vaccines (id, attack_id, scenario, mitre_technique, verdict, payload, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (v["id"], origin["attack_id"], origin["scenario"], origin["mitre_technique"], v["verdict"],
                 json.dumps(v, ensure_ascii=False, sort_keys=True), NOW_ISO))
        conn.commit()
    finally:
        conn.close()


def decide_error(store: VaccineStore, **kwargs) -> str | None:
    """Código da VaccineDecisionError levantada, ou None se não levantou nenhuma."""
    try:
        store.decide_vaccine(**kwargs)
    except VaccineDecisionError as exc:
        return exc.code
    return None


def request(**overrides) -> dict:
    base = {"vaccine_id": ID_C, "decision": "approved", "decided_by": "analyst-soc1", "decided_by_name": "Eddie",
            "reason": None, "now_iso": DECIDED_AT}
    base.update(overrides)
    return base


def run_tracer() -> None:
    check("fixtures: ids literais do motor", (vA["id"], vB["id"], vC["id"]) == (ID_A, ID_B, ID_C))
    check("VACCINE_ID_RE do módulo puro igual ao do motor",
          vaccine_decision.VACCINE_ID_RE == vaccine_engine.VACCINE_ID_RE)
    check("STORE_FIELDS inclui decision", STORE_FIELDS == ("state", "superseded_by", "created_at", "decision"))
    check("R11_VACCINES_DDL congelado == VACCINES_SCHEMA do store", R11_VACCINES_DDL == vaccine_store.VACCINES_SCHEMA)
    check("SCHEMA == VACCINES_SCHEMA + DECISIONS_SCHEMA",
          vaccine_store.SCHEMA == vaccine_store.VACCINES_SCHEMA + vaccine_store.DECISIONS_SCHEMA)

    # --- aprovar ---
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "v.sqlite3")
        store = VaccineStore(path)
        store.upsert_batch([vC], NOW_ISO)
        before = store.get_vaccine(ID_C)
        check("antes de decidir: state proposed e decision None", before["state"] == "proposed" and before["decision"] is None)
        check("chaves da vaccine lida == chaves do motor + STORE_FIELDS",
              set(before) == vaccine_engine.VACCINE_KEYS | set(STORE_FIELDS))
        rows_before = rows_of(path)

        result = store.decide_vaccine(**request())
        expected_record = {"vaccine_id": ID_C, "decision": "approved", "decided_by": "analyst-soc1",
                           "decided_by_name": "Eddie", "decided_at": DECIDED_AT, "reason": None,
                           "previous_state": "proposed"}
        check("decide_vaccine devolve exatamente o registo", result == expected_record)
        check("chaves do registo pela ordem de DECISION_RECORD_KEYS", tuple(result) == DECISION_RECORD_KEYS)

        after = store.get_vaccine(ID_C)
        check("depois: state approved", after["state"] == "approved")
        check("depois: bloco decision",
              after["decision"] == {"decided_by": "analyst-soc1", "decided_by_name": "Eddie",
                                    "decided_at": DECIDED_AT, "reason": None})
        check("depois: superseded_by None e created_at igual", after["superseded_by"] is None
              and after["created_at"] == before["created_at"])
        check("a vaccine sem STORE_FIELDS continua igual a vC",
              {k: v for k, v in after.items() if k not in STORE_FIELDS} == vC)
        listed, total, store_total = store.list_vaccines()
        check("list_vaccines devolve a mesma entrada que get_vaccine",
              listed == [after] and total == 1 and store_total == 1)
        check("SQL direto: uma linha em vaccine_decisions",
              decision_rows(path) == [(ID_C, "approved", "analyst-soc1", "Eddie", DECIDED_AT, None, "proposed")])
        check("tabela vaccines igual antes e depois da decisão", rows_of(path) == rows_before)
        check("coluna state de vaccines continua proposed", all(r[1] == "proposed" for r in rows_of(path)))

    # --- rejeitar com motivo ---
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "v.sqlite3")
        store = VaccineStore(path)
        store.upsert_batch([vC, vB], NOW_ISO)
        rows_before = rows_of(path)
        store.decide_vaccine(**request(vaccine_id=ID_C))
        result = store.decide_vaccine(**request(vaccine_id=ID_B, decision="rejected", decided_by="analyst-soc2",
                                                decided_by_name="Jeremy", reason="  Falso positivo no laboratório  "))
        check("rejeitar: motivo gravado sem espaços nas pontas", result["reason"] == "Falso positivo no laboratório")
        b = store.get_vaccine(ID_B)
        check("rejeitar: state rejected", b["state"] == "rejected")
        check("rejeitar: bloco decision com o autor e o motivo",
              b["decision"] == {"decided_by": "analyst-soc2", "decided_by_name": "Jeremy", "decided_at": DECIDED_AT,
                                "reason": "Falso positivo no laboratório"})
        check("SQL direto: duas linhas pela ordem de inserção",
              decision_rows(path) == [(ID_C, "approved", "analyst-soc1", "Eddie", DECIDED_AT, None, "proposed"),
                                      (ID_B, "rejected", "analyst-soc2", "Jeremy", DECIDED_AT,
                                       "Falso positivo no laboratório", "proposed")])
        check("tabela vaccines igual antes e depois das duas decisões", rows_of(path) == rows_before)
        check("todas as linhas de vaccines continuam proposed", all(r[1] == "proposed" for r in rows_of(path)))

    # --- rejeitar sem motivo ---
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "v.sqlite3")
        store = VaccineStore(path)
        store.upsert_batch([vA], NOW_ISO)
        for label, reason in (("None", None), ("vazio", ""), ("só espaços", "   ")):
            code = None
            text = None
            try:
                store.decide_vaccine(**request(vaccine_id=ID_A, decision="rejected", reason=reason))
            except VaccineDecisionError as exc:
                code, text = exc.code, str(exc)
            check(f"rejeitar sem motivo ({label}) -> reason_required", code == "reason_required" and text == "reason_required")
        check("rejeitar sem motivo: nenhuma linha em vaccine_decisions", decision_rows(path) == [])
        check("rejeitar sem motivo: a vaccine continua proposed", store.get_vaccine(ID_A)["state"] == "proposed")

    # --- id inexistente / ficheiro inexistente ---
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "v.sqlite3")
        store = VaccineStore(path)
        store.upsert_batch([vA], NOW_ISO)
        check("id inexistente num ficheiro existente -> entry_not_found",
              decide_error(store, **request(vaccine_id="vac-000000000000")) == "entry_not_found")
        check("id inexistente: nada gravado", decision_rows(path) == [])

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "v.sqlite3")
        store = VaccineStore(path)
        check("ficheiro inexistente -> entry_not_found", decide_error(store, **request()) == "entry_not_found")
        check("ficheiro inexistente: continua a não existir", not os.path.exists(path))

    # --- ficheiro antigo, sem vaccine_decisions ---
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "v.sqlite3")
        make_r11_file(path, [vC])
        store = VaccineStore(path)
        old = store.get_vaccine(ID_C)
        check("ficheiro antigo: get_vaccine com state proposed e decision None",
              old is not None and old["state"] == "proposed" and old["decision"] is None)
        check("ficheiro antigo: list_vaccines == ([entrada], 1, 1)", store.list_vaccines() == ([old], 1, 1))
        check("ficheiro antigo: as leituras não criaram vaccine_decisions", has_decisions_table(path) is False)


def imported_modules(path: str) -> set[str]:
    """Primeiro componente dos módulos importados por um ficheiro (por AST)."""
    tree = ast.parse(open(path, encoding="utf-8").read())
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module.split(".")[0])
    return found


def run_validation_before_io() -> None:
    """Toda a entrada inválida falha antes de tocar no disco (D-08)."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "v.sqlite3")
        store = VaccineStore(path)
        check("ficheiro inexistente + vaccine_id inválido -> invalid_vaccine_id",
              decide_error(store, **request(vaccine_id="abc")) == "invalid_vaccine_id")
        check("ficheiro inexistente + vaccine_id inválido: o ficheiro não foi criado", not os.path.exists(path))
        for label, overrides, code in (
            ("decisão", {"decision": "applied"}, "invalid_decision"),
            ("autor (id)", {"decided_by": "soc1"}, "invalid_author"),
            ("autor (nome)", {"decided_by_name": "<b>x</b>"}, "invalid_author"),
            ("decided_at", {"now_iso": "ontem"}, "invalid_decided_at"),
            ("motivo em falta", {"decision": "rejected", "reason": None}, "reason_required"),
            ("motivo inválido", {"reason": "a\nb"}, "invalid_reason"),
        ):
            check(f"ficheiro inexistente + {label} inválido -> {code}", decide_error(store, **request(**overrides)) == code)
        check("nenhuma recusa de entrada criou o ficheiro", not os.path.exists(path))

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "v.sqlite3")
        make_r11_file(path, [vC])
        store = VaccineStore(path)
        check("ficheiro antigo + decisão 'applied' -> invalid_decision",
              decide_error(store, **request(decision="applied")) == "invalid_decision")
        check("ficheiro antigo: a tabela vaccine_decisions continua sem existir", has_decisions_table(path) is False)
        check("ficheiro antigo: motivo inválido também não cria a tabela",
              decide_error(store, **request(reason="x" * 501)) == "invalid_reason" and has_decisions_table(path) is False)
        store.decide_vaccine(**request())
        check("ficheiro antigo: a primeira decisão válida cria a tabela e grava",
              has_decisions_table(path) and len(decision_rows(path)) == 1)

    here = os.path.dirname(os.path.abspath(__file__))
    forbidden = {"incident_store", "incident_engine", "incident_ingest"}
    for name in ("vaccine_store.py", "vaccine_decision.py"):
        found = imported_modules(os.path.join(here, name))
        check(f"D-05: {name} não importa o store/motor de incidentes (importa {sorted(found)})",
              not (found & forbidden))


def run_refusals() -> None:
    """Recusas ponta a ponta (critério 3) e decisão que sobrevive à substituição (D-09)."""
    observed: set[str] = set()

    def refused(store: VaccineStore, path: str, label: str, expected: str, **overrides) -> None:
        """Tenta decidir, exige o código esperado e que nada tenha sido gravado (D-08)."""
        vaccines_before = rows_of(path) if os.path.exists(path) else None
        decisions_before = decision_rows(path) if os.path.exists(path) else None
        code = decide_error(store, **request(**overrides))
        if code is not None:
            observed.add(code)
        check(f"{label} -> {expected}", code == expected)
        if vaccines_before is not None:
            check(f"{label}: vaccines e vaccine_decisions ficam iguais",
                  rows_of(path) == vaccines_before and decision_rows(path) == decisions_before)

    # --- já decidida (mesma decisão ou outra) ---
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "v.sqlite3")
        store = VaccineStore(path)
        store.upsert_batch([vA], NOW_ISO)
        store.decide_vaccine(**request(vaccine_id=ID_A))
        rows_decided = decision_rows(path)
        refused(store, path, "decidir A rejected por outro analista", "already_decided", vaccine_id=ID_A,
                decision="rejected", decided_by="analyst-soc2", decided_by_name="Jeremy", reason="Mudei de ideias")
        refused(store, path, "decidir A approved outra vez", "already_decided", vaccine_id=ID_A)
        check("já decidida: continua uma só linha, a original", decision_rows(path) == rows_decided
              and len(rows_decided) == 1)
        a = store.get_vaccine(ID_A)
        check("já decidida: get_vaccine(A) continua approved por analyst-soc1",
              a["state"] == "approved" and a["decision"]["decided_by"] == "analyst-soc1")

        # --- D-09: substituída pelo gerador mantém a decisão ---
        store.upsert_batch([vB], NOW_ISO)
        a, b = store.get_vaccine(ID_A), store.get_vaccine(ID_B)
        check("D-09: A substituída continua approved com o bloco decision (Eddie)",
              a["state"] == "approved" and a["decision"]["decided_by_name"] == "Eddie"
              and a["superseded_by"] == ID_B)
        check("D-09: B nasce proposed, sem decisão e sem superseded_by",
              b["state"] == "proposed" and b["decision"] is None and b["superseded_by"] is None)
        check("D-09: list_vaccines() só traz B", [v["id"] for v in store.list_vaccines()[0]] == [ID_B])
        both = {v["id"]: v for v in store.list_vaccines(include_superseded=True)[0]}
        check("D-09: include_superseded traz A approved e B proposed",
              set(both) == {ID_A, ID_B} and both[ID_A]["state"] == "approved" and both[ID_B]["state"] == "proposed")
        refused(store, path, "decidir A (decidida e substituída)", "already_decided", vaccine_id=ID_A,
                decision="rejected", reason="Tarde demais")

        # --- vaivém A-B-A ---
        a_before = store.get_vaccine(ID_A)["decision"]
        store.upsert_batch([vA], NOW_ISO)
        a, b = store.get_vaccine(ID_A), store.get_vaccine(ID_B)
        check("vaivém: A volta a ser a atual e continua approved com o mesmo bloco decision",
              a["superseded_by"] is None and a["state"] == "approved" and a["decision"] == a_before)
        check("vaivém: B fica superseded_by A e proposed", b["superseded_by"] == ID_A and b["state"] == "proposed")
        refused(store, path, "decidir B (substituída e por decidir)", "vaccine_superseded", vaccine_id=ID_B)
        check("vaivém: decision_rows continua com a linha de A", decision_rows(path) == rows_decided)

        # --- reinício: VaccineStore nova sobre o mesmo ficheiro ---
        reopened = VaccineStore(path)
        check("reinício: decidir A -> already_decided",
              decide_error(reopened, **request(vaccine_id=ID_A)) == "already_decided")
        check("reinício: get_vaccine(A) igual ao da instância anterior",
              reopened.get_vaccine(ID_A) == store.get_vaccine(ID_A))
        observed.add("already_decided")

    # --- inexistente ---
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "v.sqlite3")
        store = VaccineStore(path)
        store.upsert_batch([vA], NOW_ISO)
        refused(store, path, "id inexistente num ficheiro existente", "entry_not_found", vaccine_id="vac-000000000000")

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "inexistente.sqlite3")
        refused(VaccineStore(path), path, "decisão válida sem ficheiro", "entry_not_found")
        check("sem ficheiro: continua a não existir", not os.path.exists(path))

    # --- motivo obrigatório pelo store ---
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "v.sqlite3")
        store = VaccineStore(path)
        store.upsert_batch([vC], NOW_ISO)
        refused(store, path, "rejeitar C com motivo só de espaços", "reason_required", decision="rejected", reason="   ")
        check("reason_required: decision_rows == []", decision_rows(path) == [])
        accepted = decide_error(store, **request(decision="rejected", decided_by="analyst-soc2",
                                                 decided_by_name="Jeremy", reason="Regra ruidosa"))
        check("a recusa não deixou nada pendurado: rejeitar C com motivo é aceite",
              accepted is None and store.get_vaccine(ID_C)["state"] == "rejected")

    expected_codes = {"already_decided", "vaccine_superseded", "entry_not_found", "reason_required"}
    check(f"quatro códigos distintos observados ({sorted(observed)})", observed == expected_codes)
    check("os quatro estão em ERROR_CODES", observed <= set(vaccine_decision.ERROR_CODES))
    check("already_decided e vaccine_superseded em CONFLICT_CODES",
          {"already_decided", "vaccine_superseded"} <= set(vaccine_decision.CONFLICT_CODES))
    check("entry_not_found em NOT_FOUND_CODES", "entry_not_found" in vaccine_decision.NOT_FOUND_CODES)


class TracingStore(VaccineStore):
    """VaccineStore que regista as instruções SQL de cada ligação de escrita. O
    executescript do esquema corre dentro do _connect original, antes do traço."""

    def __init__(self, db_path: str) -> None:
        super().__init__(db_path)
        self.statements: list[str] = []

    def _connect(self) -> sqlite3.Connection:
        conn = super()._connect()
        conn.set_trace_callback(self.statements.append)
        return conn


def run_threads(targets: list) -> bool:
    """Arranca as funções em threads, junta-as com timeout de 15 s; True se todas terminaram."""
    threads = [threading.Thread(target=target) for target in targets]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)
    return not any(thread.is_alive() for thread in threads)


def race_eight_threads(stores: list[VaccineStore]) -> tuple[list, list, bool]:
    """8 threads a decidir C ao mesmo tempo; devolve (sucessos, outros resultados, todas terminaram)."""
    barrier = threading.Barrier(8)
    guard = threading.Lock()
    successes: list[dict] = []
    others: list[str] = []

    def worker(n: int) -> None:
        barrier.wait(timeout=10)
        try:
            result = stores[n].decide_vaccine(**request(decided_by=f"analyst-t{n + 1}", decided_by_name=f"T{n + 1}"))
        except VaccineDecisionError as exc:
            with guard:
                others.append(exc.code)
        except Exception as exc:  # noqa: BLE001 - qualquer outra exceção é falha do teste
            with guard:
                others.append(type(exc).__name__)
        else:
            with guard:
                successes.append(result)

    finished = run_threads([lambda n=n: worker(n) for n in range(8)])
    return successes, others, finished


def run_generator_race(commit: bool) -> None:
    """Outra ligação (o gerador) segura o lock de escrita; decide_vaccine tem de esperar."""
    word = "COMMIT" if commit else "ROLLBACK"
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "v.sqlite3")
        store = VaccineStore(path)
        store.upsert_batch([vA, vC], NOW_ISO)
        outcome: list = []

        def worker() -> None:
            try:
                outcome.append(store.decide_vaccine(**request(vaccine_id=ID_A)))
            except VaccineDecisionError as exc:
                outcome.append(exc.code)
            except Exception as exc:  # noqa: BLE001
                outcome.append(type(exc).__name__)

        other = sqlite3.connect(path, timeout=10, isolation_level=None)
        thread = threading.Thread(target=worker)
        try:
            other.execute("BEGIN IMMEDIATE")
            if commit:
                other.execute("UPDATE vaccines SET superseded_by = 'vac-5fe3861aa2a3' WHERE id = 'vac-ed793c0b3437'")
            thread.start()
            time.sleep(0.3)
            check(f"corrida ({word}): decide_vaccine está à espera do lock de escrita", thread.is_alive())
            other.execute(word)
        finally:
            other.close()
        thread.join(timeout=15)
        check(f"corrida ({word}): a thread terminou", not thread.is_alive())
        if commit:
            check("corrida (COMMIT): vaccine_superseded, sem gravar",
                  outcome == ["vaccine_superseded"] and decision_rows(path) == [])
        else:
            check("corrida (ROLLBACK): a decisão passa e há 1 linha",
                  len(outcome) == 1 and isinstance(outcome[0], dict) and len(decision_rows(path)) == 1)


def run_concurrency() -> None:
    """D-06/D-07: BEGIN IMMEDIATE antes das leituras (ordem das instruções) e sob concorrência real."""
    # --- ordem das instruções ---
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "v.sqlite3")
        store = TracingStore(path)
        store.upsert_batch([vC], NOW_ISO)
        store.statements.clear()
        store.decide_vaccine(**request())
        stmts = list(store.statements)
        print(f"       traço (aceite): {stmts}")
        heads = ["PRAGMA foreign_keys = ON", "BEGIN IMMEDIATE", "SELECT superseded_by FROM vaccines",
                 "SELECT decision FROM vaccine_decisions", "INSERT INTO vaccine_decisions (", "COMMIT"]
        positions = [next((i for i, s in enumerate(stmts) if s.startswith(head)), -1) for head in heads]
        check("aceite: as 6 instruções existem e pela ordem pedida",
              -1 not in positions and positions == sorted(positions) and len(set(positions)) == 6)
        check("aceite: um único INSERT em vaccine_decisions",
              sum(s.startswith("INSERT INTO vaccine_decisions (") for s in stmts) == 1)
        check("aceite: nenhum UPDATE", not any(s.lstrip().upper().startswith("UPDATE") for s in stmts))
        check("aceite: BEGIN IMMEDIATE logo a seguir ao PRAGMA, antes de qualquer leitura",
              positions[1] == positions[0] + 1)

        store.statements.clear()
        code = decide_error(store, **request())
        stmts = list(store.statements)
        print(f"       traço (recusa): {stmts}")
        check("recusa no ficheiro: already_decided", code == "already_decided")
        check("recusa no ficheiro: BEGIN IMMEDIATE e ROLLBACK, sem INSERT nem COMMIT",
              "BEGIN IMMEDIATE" in stmts and "ROLLBACK" in stmts
              and not any(s.startswith("INSERT INTO vaccine_decisions") for s in stmts) and "COMMIT" not in stmts)

        store.statements.clear()
        code = decide_error(store, **request(decision="applied"))
        check("recusa na validação: invalid_decision e traço vazio (nenhuma ligação aberta)",
              code == "invalid_decision" and store.statements == [])

        store.statements.clear()
        store.upsert_batch([vA], NOW_ISO)
        check("o gerador não mudou: upsert_batch sem BEGIN IMMEDIATE nem PRAGMA foreign_keys",
              bool(store.statements) and not any(s.startswith("BEGIN IMMEDIATE") or s == "PRAGMA foreign_keys = ON"
                                                 for s in store.statements))

    # --- 8 threads ---
    for label, shared in (("instâncias separadas", False), ("mesma instância", True)):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "v.sqlite3")
            VaccineStore(path).upsert_batch([vC], NOW_ISO)
            if shared:
                stores = [VaccineStore(path)] * 8
            else:
                stores = [VaccineStore(path) for _ in range(8)]
            started = time.monotonic()
            successes, others, finished = race_eight_threads(stores)
            print(f"       8 threads ({label}): {len(successes)} sucesso, {others.count('already_decided')} "
                  f"already_decided, outros={[o for o in others if o != 'already_decided']}, "
                  f"{time.monotonic() - started:.2f}s")
            check(f"8 threads ({label}): todas terminaram", finished)
            check(f"8 threads ({label}): exatamente 1 sucesso", len(successes) == 1)
            check(f"8 threads ({label}): 7 already_decided e nenhuma outra exceção",
                  others == ["already_decided"] * 7)
            rows = decision_rows(path)
            check(f"8 threads ({label}): 1 linha, do vencedor",
                  len(rows) == 1 and len(successes) == 1 and rows[0][2] == successes[0]["decided_by"])

    # --- corrida com o gerador ---
    run_generator_race(commit=True)
    run_generator_race(commit=False)


def ids_of(rows: list[dict]) -> list[str]:
    return [v["id"] for v in rows]


def run_state_filter() -> None:
    """D-10/D-11/D-13: list_vaccines(state=...) filtra pelo estado derivado, com e sem a tabela de decisões."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "v.sqlite3")
        store = VaccineStore(path)
        store.upsert_batch([vA, vC], NOW_ISO)
        store.decide_vaccine(**request(vaccine_id=ID_C))
        store.decide_vaccine(**request(vaccine_id=ID_A, decision="rejected", decided_by="analyst-soc2",
                                       decided_by_name="Jeremy", reason="Regra ruidosa"))
        store.upsert_batch([vB], NOW_ISO)  # A substituída por B; A continua rejeitada

        rows, total, store_total = store.list_vaccines()
        check("sem state: comportamento de antes (C e B, total 2, store_total 3)",
              ids_of(rows) == [ID_C, ID_B] and total == 2 and store_total == 3)

        rows, total, store_total = store.list_vaccines(state="approved")
        check("state=approved -> ([C], 1, 3)", ids_of(rows) == [ID_C] and total == 1 and store_total == 3)
        rows, total, store_total = store.list_vaccines(state="proposed")
        check("state=proposed -> ([B], 1, 3)", ids_of(rows) == [ID_B] and total == 1 and store_total == 3)
        rows, total, store_total = store.list_vaccines(state="rejected")
        check("state=rejected por omissão (A está substituída) -> ([], 0, 3)",
              rows == [] and total == 0 and store_total == 3)
        rows, total, store_total = store.list_vaccines(state="rejected", include_superseded=True)
        check("state=rejected com include_superseded -> [A]", ids_of(rows) == [ID_A] and total == 1)
        rows, total, _ = store.list_vaccines(attack_id=2, state="rejected", include_superseded=True)
        check("attack_id=2 + rejected + include_superseded -> [A]", ids_of(rows) == [ID_A] and total == 1)
        rows, total, store_total = store.list_vaccines(attack_id=3, state="proposed")
        check("attack_id=3 + proposed -> ([], 0, 3)", rows == [] and total == 0 and store_total == 3)
        rows, total, _ = store.list_vaccines(state="approved", limit=1, offset=0)
        check("limit=1 com state=approved: uma linha e total 1", len(rows) == 1 and total == 1)

        for wanted in ("proposed", "approved", "rejected"):
            rows, _, _ = store.list_vaccines(state=wanted, include_superseded=True)
            check(f"cada linha com state={wanted} tem v['state'] == {wanted}",
                  bool(rows) and all(v["state"] == wanted for v in rows))

        before_vaccines, before_decisions = rows_of(path), decision_rows(path)
        for hostile in ("approved' OR '1'='1", "", "APPROVED", "proposed; DROP TABLE vaccines", "applied"):
            try:
                rows, total, store_total = store.list_vaccines(state=hostile, include_superseded=True)
                ok = rows == [] and total == 0 and store_total == 3
            except Exception as exc:  # noqa: BLE001
                print(f"       exceção: {type(exc).__name__}: {exc}")
                ok = False
            check(f"state hostil/desconhecido {hostile!r}: vazio, sem exceção", ok)
        check("depois dos filtros hostis as duas tabelas ficaram iguais",
              rows_of(path) == before_vaccines and decision_rows(path) == before_decisions)

    # --- ficheiro antigo (R11), sem vaccine_decisions ---
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "old.sqlite3")
        make_r11_file(path, [vA, vC])
        with open(path, "rb") as handle:
            original = handle.read()
        store = VaccineStore(path)
        rows, total, store_total = store.list_vaccines(state="proposed")
        check("ficheiro antigo: state=proposed -> [C, A], total 2",
              ids_of(rows) == [ID_C, ID_A] and total == 2 and store_total == 2)
        for wanted in ("approved", "rejected"):
            rows, total, store_total = store.list_vaccines(state=wanted)
            check(f"ficheiro antigo: state={wanted} -> ([], 0, 2)", rows == [] and total == 0 and store_total == 2)
        rows, total, store_total = store.list_vaccines(state="approved' OR '1'='1")
        check("ficheiro antigo: state hostil -> ([], 0, 2)", rows == [] and total == 0 and store_total == 2)
        rows, total, _ = store.list_vaccines()
        check("ficheiro antigo: list_vaccines() sem filtro funciona", ids_of(rows) == [ID_C, ID_A] and total == 2)
        vaccine = store.get_vaccine(ID_A)
        check("ficheiro antigo: get_vaccine funciona, proposed e sem decisão",
              vaccine is not None and vaccine["state"] == "proposed" and vaccine["decision"] is None)
        check("ficheiro antigo: sem tabela vaccine_decisions no fim", has_decisions_table(path) is False)
        with open(path, "rb") as handle:
            check("ficheiro antigo: bytes exatamente iguais depois das leituras", handle.read() == original)


def raises_integrity(path: str, sql: str, params=(), foreign_keys: bool = False) -> bool:
    """True se o SQL direto levanta sqlite3.IntegrityError (ligação nova por tentativa; o PRAGMA das
    chaves estrangeiras só se liga a pedido, como no store). Sem erro, a escrita fica confirmada."""
    conn = sqlite3.connect(path)
    try:
        if foreign_keys:
            conn.execute("PRAGMA foreign_keys = ON")
        conn.execute(sql, params)
        conn.commit()
        return False
    except sqlite3.IntegrityError:
        return True
    finally:
        conn.close()


def master_entries(conn: sqlite3.Connection) -> list[tuple]:
    """Entradas de sqlite_master da tabela vaccines (tabela, autoindex, índices, triggers), sql incluído."""
    return conn.execute("SELECT type, name, tbl_name, sql FROM sqlite_master WHERE tbl_name = 'vaccines' "
                        "ORDER BY type, name").fetchall()


def master_of(path: str) -> list[tuple]:
    conn = sqlite3.connect(path)
    try:
        return master_entries(conn)
    finally:
        conn.close()


INSERT_DECISION_SQL = ("INSERT INTO vaccine_decisions (vaccine_id, decision, decided_by, decided_by_name, "
                       "decided_at, reason, previous_state) VALUES (?, ?, ?, ?, ?, ?, ?)")
# Linha válida para A (que nestes testes fica por decidir): vaccine_id, decision, decided_by,
# decided_by_name, decided_at, reason, previous_state.
VALID_DECISION_ROW = [ID_A, "approved", "analyst-soc1", "Eddie", DECIDED_AT, None, "proposed"]


def row_with(index: int, value) -> list:
    row = list(VALID_DECISION_ROW)
    row[index] = value
    return row


def run_file_triggers_and_checks(tmp: str, path: str) -> None:
    """Tentativas por SQL direto contra o ficheiro montado em run_file_guarantees."""
    snap_vaccines, snap_decisions = rows_of(path), decision_rows(path)

    for column, value in (("decision", "rejected"), ("decided_by", "analyst-x"), ("decided_by_name", "Outro"),
                          ("decided_at", "2030-01-01T00:00:00+00:00"), ("reason", "novo motivo"),
                          ("previous_state", "proposed"), ("vaccine_id", ID_A)):
        check(f"trigger: UPDATE vaccine_decisions SET {column} -> IntegrityError",
              raises_integrity(path, f"UPDATE vaccine_decisions SET {column} = ? WHERE vaccine_id = ?",
                               (value, ID_C)))
    check("trigger: DELETE com WHERE vaccine_id -> IntegrityError",
          raises_integrity(path, "DELETE FROM vaccine_decisions WHERE vaccine_id = ?", (ID_C,)))
    check("trigger: DELETE sem WHERE -> IntegrityError", raises_integrity(path, "DELETE FROM vaccine_decisions"))
    check("UNIQUE: segundo INSERT simples para C -> IntegrityError",
          raises_integrity(path, INSERT_DECISION_SQL, row_with(0, ID_C)))

    # Controlos em cópias: as linhas válidas seriam aceites, por isso cada recusa abaixo
    # deve-se à única coisa errada que a linha tem.
    rejected_ok = row_with(1, "rejected")
    rejected_ok[5] = "Regra ruidosa"
    for name, row in (("approved", VALID_DECISION_ROW), ("rejected com motivo", rejected_ok)):
        copy_path = os.path.join(tmp, f"controlo-{name[:3]}.sqlite3")
        shutil.copyfile(path, copy_path)
        check(f"controlo: o INSERT válido ({name}) para A seria aceite (numa cópia)",
              not raises_integrity(copy_path, INSERT_DECISION_SQL, row))

    for label, row in (
        ("decision 'applied'", row_with(1, "applied")),
        ("previous_state 'approved'", row_with(6, "approved")),
        ("rejected sem motivo (NULL)", row_with(1, "rejected")),
        ("motivo vazio", row_with(5, "")),
        ("motivo só espaços", row_with(5, "   ")),
        ("motivo com 501 caracteres", row_with(5, "x" * 501)),
        ("decided_by 'Eddie'", row_with(2, "Eddie")),
        ("decided_by 'analyst-A'", row_with(2, "analyst-A")),
        ("decided_by 'analyst-'", row_with(2, "analyst-")),
        ("decided_by_name vazio", row_with(3, "")),
        ("decided_by_name com 129 caracteres", row_with(3, "n" * 129)),
        ("vaccine_id malformado 'abc'", row_with(0, "abc")),
    ):
        check(f"CHECK: {label} -> IntegrityError", raises_integrity(path, INSERT_DECISION_SQL, row))

    check("FK (PRAGMA foreign_keys = ON): vaccine_id inexistente -> IntegrityError",
          raises_integrity(path, INSERT_DECISION_SQL, row_with(0, "vac-999999999999"), foreign_keys=True))
    check("depois de todas as tentativas as duas tabelas ficaram iguais",
          rows_of(path) == snap_vaccines and decision_rows(path) == snap_decisions)

    # Contraste: a variante que ignora erros engoliria uma violação de CHECK (razão do INSERT simples).
    mem = sqlite3.connect(":memory:")
    mem.executescript(vaccine_store.SCHEMA)
    origin = vA["origin"]
    mem.execute("INSERT INTO vaccines (id, attack_id, scenario, mitre_technique, verdict, payload, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)", (ID_A, origin["attack_id"], origin["scenario"],
                                                 origin["mitre_technique"], vA["verdict"], "{}", NOW_ISO))
    cur = mem.execute(INSERT_DECISION_SQL.replace("INSERT INTO", "INSERT OR IGNORE INTO"), row_with(1, "applied"))
    check("contraste: INSERT OR IGNORE engole o CHECK (rowcount 0, sem erro): razão do INSERT simples",
          cur.rowcount == 0)
    mem.close()


def run_file_r11_intact(tmp: str, path: str) -> None:
    """vaccines do R11 igual no código e em sqlite_master (ficheiro novo e antigo), e continua imutável."""
    check("VACCINES_SCHEMA == R11_VACCINES_DDL (byte a byte)", vaccine_store.VACCINES_SCHEMA == R11_VACCINES_DDL)
    check("SCHEMA == VACCINES_SCHEMA + DECISIONS_SCHEMA",
          vaccine_store.SCHEMA == vaccine_store.VACCINES_SCHEMA + vaccine_store.DECISIONS_SCHEMA)
    check("'vaccine_decisions' não aparece em VACCINES_SCHEMA", "vaccine_decisions" not in vaccine_store.VACCINES_SCHEMA)

    base = sqlite3.connect(":memory:")
    base.executescript(R11_VACCINES_DDL)
    expected = master_entries(base)
    base.close()
    check("sqlite_master do R11: 6 entradas (tabela, autoindex com sql NULL, 2 índices, 2 triggers)",
          len(expected) == 6 and sum(1 for e in expected if e[3] is None) == 1)
    check("sqlite_master de vaccines: ficheiro novo (depois de upsert_batch e decide_vaccine) == só R11",
          master_of(path) == expected)
    old_path = os.path.join(tmp, "old.sqlite3")
    make_r11_file(old_path, [vA, vC])
    check("sqlite_master do ficheiro antigo antes de decidir == só R11", master_of(old_path) == expected)
    VaccineStore(old_path).decide_vaccine(**request())
    check("ficheiro antigo: a primeira decisão criou vaccine_decisions", has_decisions_table(old_path) is True)
    check("sqlite_master de vaccines: ficheiro antigo depois da primeira decisão == só R11",
          master_of(old_path) == expected)

    snap_vaccines, snap_decisions = rows_of(path), decision_rows(path)
    check("imutável: UPDATE vaccines SET state='approved' numa vaccine aprovada -> IntegrityError",
          raises_integrity(path, "UPDATE vaccines SET state = 'approved' WHERE id = ?", (ID_C,)))
    check("imutável: DELETE FROM vaccines numa vaccine aprovada -> IntegrityError",
          raises_integrity(path, "DELETE FROM vaccines WHERE id = ?", (ID_C,)))
    conn = sqlite3.connect(path)
    try:
        states = {row[0] for row in conn.execute("SELECT state FROM vaccines")}
    finally:
        conn.close()
    check("a coluna state de vaccines é 'proposed' em todas as linhas", states == {"proposed"})
    check("vaccines e vaccine_decisions inalteradas depois de tudo",
          rows_of(path) == snap_vaccines and decision_rows(path) == snap_decisions)


def run_closed_api_and_trace() -> None:
    """D-03: API pública fechada e nenhum caminho do store atualiza ou apaga uma decisão."""
    public = sorted(name for name in vars(VaccineStore) if not name.startswith("_"))
    check(f"API pública exatamente count_by_state, decide_vaccine, get_vaccine, list_vaccines, upsert_batch ({public})",
          public == ["count_by_state", "decide_vaccine", "get_vaccine", "list_vaccines", "upsert_batch"])
    with open(vaccine_store.__file__, encoding="utf-8") as handle:
        source = handle.read()
    check("o código do store não tem UPDATE nem DELETE FROM sobre vaccine_decisions",
          "UPDATE vaccine_decisions" not in source and "DELETE FROM vaccine_decisions" not in source)
    insert_sql = vaccine_store._INSERT_DECISION.upper()
    check("_INSERT_DECISION é simples (sem OR IGNORE, OR REPLACE nem ON CONFLICT)",
          insert_sql.startswith("INSERT INTO VACCINE_DECISIONS (")
          and not any(word in insert_sql for word in ("OR IGNORE", "OR REPLACE", "ON CONFLICT")))

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "v.sqlite3")
        store = TracingStore(path)
        store.upsert_batch([vA, vC], NOW_ISO)
        store.upsert_batch([vB], NOW_ISO)
        upsert_trace = list(store.statements)
        traces: dict[str, list[str]] = {}
        for label, kwargs, expected_code in (
            ("aceite", request(), None),
            ("recusada", request(), "already_decided"),
            ("inválida", request(decision="applied"), "invalid_decision"),
            ("de id inexistente", request(vaccine_id="vac-999999999999"), "entry_not_found"),
        ):
            store.statements.clear()
            code = decide_error(store, **kwargs)
            traces[label] = list(store.statements)
            check(f"traço: decide {label} -> {expected_code}", code == expected_code)
        everything = upsert_trace + [s for trace in traces.values() for s in trace]
        check("traço: nenhuma instrução começa por UPDATE vaccine_decisions nem por DELETE",
              not any(s.lstrip().upper().startswith(("UPDATE VACCINE_DECISIONS", "DELETE")) for s in everything))
        check("traço: as instruções UPDATE vêm só de upsert_batch (nenhuma nas decisões)",
              any(s.lstrip().upper().startswith("UPDATE") for s in upsert_trace)
              and not any(s.lstrip().upper().startswith("UPDATE") for trace in traces.values() for s in trace))
        inserts = [s for s in traces["aceite"] if s.startswith("INSERT INTO vaccine_decisions (")]
        check("traço: a decisão aceite tem exatamente um INSERT INTO vaccine_decisions (", len(inserts) == 1)
        check("traço: esse INSERT não contém OR IGNORE nem ON CONFLICT",
              len(inserts) == 1 and "OR IGNORE" not in inserts[0].upper() and "ON CONFLICT" not in inserts[0].upper())
        check("traço: recusada, inválida e de id inexistente não têm INSERT",
              not any(s.startswith("INSERT INTO vaccine_decisions") for label in
                      ("recusada", "inválida", "de id inexistente") for s in traces[label]))
        check("a decisão aceite ficou como única linha gravada", len(decision_rows(path)) == 1)


def file_fingerprint(path: str) -> tuple[bytes, int]:
    with open(path, "rb") as handle:
        content = handle.read()
    return content, os.stat(path).st_mtime_ns


def run_state_counts() -> None:
    """D-11: count_by_state() conta as vaccines atuais por estado derivado; None sem amostra; só leitura."""
    with tempfile.TemporaryDirectory() as tmp:
        missing = os.path.join(tmp, "nao_existe.sqlite3")
        check("ficheiro inexistente -> count_by_state() is None", VaccineStore(missing).count_by_state() is None)
        check("ficheiro inexistente: count_by_state não o cria", not os.path.exists(missing))

        empty = os.path.join(tmp, "vazio.sqlite3")
        conn = sqlite3.connect(empty)
        conn.executescript(vaccine_store.VACCINES_SCHEMA)
        conn.commit()
        conn.close()
        check("ficheiro só com o esquema e 0 linhas -> None", VaccineStore(empty).count_by_state() is None)

        old = os.path.join(tmp, "antigo.sqlite3")
        make_r11_file(old, [vA, vC])
        before = file_fingerprint(old)
        check("ficheiro antigo sem vaccine_decisions -> tudo proposed",
              VaccineStore(old).count_by_state() == {"proposed": 2, "approved": 0, "rejected": 0})
        check("ficheiro antigo: continua sem a tabela e igual byte a byte e mtime",
              not has_decisions_table(old) and file_fingerprint(old) == before)

        path = os.path.join(tmp, "v.sqlite3")
        store = VaccineStore(path)
        store.upsert_batch([vA, vC], NOW_ISO)
        store.decide_vaccine(**request(vaccine_id=ID_A))
        store.upsert_batch([vB], NOW_ISO)  # A aprovada e substituída por B
        check("A aprovada e substituída não conta (só as atuais): {proposed 2, approved 0, rejected 0}",
              store.count_by_state() == {"proposed": 2, "approved": 0, "rejected": 0})
        store.decide_vaccine(**request(vaccine_id=ID_C))
        store.decide_vaccine(**request(vaccine_id=ID_B, decision="rejected", decided_by="analyst-soc2",
                                       decided_by_name="Jeremy", reason="Regra ruidosa"))
        counts = store.count_by_state()
        check("C aprovada e B rejeitada -> {proposed 0, approved 1, rejected 1}",
              counts == {"proposed": 0, "approved": 1, "rejected": 1})
        check("as chaves vêm pela ordem de DERIVED_STATES", list(counts) == list(vaccine_decision.DERIVED_STATES))
        _, total, _ = store.list_vaccines()
        check("a soma das contagens é igual ao total de list_vaccines() sem filtros", sum(counts.values()) == total)
        before = file_fingerprint(path)
        store.count_by_state()
        check("count_by_state não altera bytes nem st_mtime_ns do ficheiro", file_fingerprint(path) == before)


def run_file_guarantees() -> None:
    """Critério 1 e D-01/D-02/D-03/D-07/D-12: as garantias valem no próprio ficheiro (SQL direto,
    sqlite_master, traço das instruções), não só no código do store."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "v.sqlite3")
        store = VaccineStore(path)
        store.upsert_batch([vA, vC], NOW_ISO)
        store.upsert_batch([vB], NOW_ISO)  # A substituída por B
        store.decide_vaccine(**request(vaccine_id=ID_C))
        store.decide_vaccine(**request(vaccine_id=ID_B, decision="rejected", decided_by="analyst-soc2",
                                       decided_by_name="Jeremy", reason="Regra ruidosa"))
        check("montagem: 3 vaccines e 2 decisões", len(rows_of(path)) == 3 and len(decision_rows(path)) == 2)
        run_file_triggers_and_checks(tmp, path)
        run_file_r11_intact(tmp, path)
    run_closed_api_and_trace()


def main() -> None:
    run_tracer()
    run_validation_before_io()
    run_refusals()
    run_concurrency()
    run_state_filter()
    run_file_guarantees()
    run_state_counts()


if __name__ == "__main__":
    main()
    print()
    if failures:
        print(f"{len(failures)} verificação(ões) falharam:")
        for label in failures:
            print(f"  - {label}")
        sys.exit(1)
    print("Todas as verificações passaram.")
