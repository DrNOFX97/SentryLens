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
import sqlite3
import sys
import tempfile
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


def main() -> None:
    run_tracer()
    run_validation_before_io()
    run_refusals()


if __name__ == "__main__":
    main()
    print()
    if failures:
        print(f"{len(failures)} verificação(ões) falharam:")
        for label in failures:
            print(f"  - {label}")
        sys.exit(1)
    print("Todas as verificações passaram.")
