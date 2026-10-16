"""
Testes da persistência SQLite de incidentes (R3). Cada caso usa uma base
temporária; nunca toca em scripts/incidents.sqlite3.

Correr (a partir de scripts/):
    python test_incident_store.py
"""

import os
import re
import sqlite3
import sys
import tempfile

from incident_store import INCIDENTS_ADDED_COLUMNS, SCHEMA, IncidentNotFound, IncidentStore, InvalidTransition

failures: list[str] = []
ASSET = "192.168.1.169"


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def ev(key, ts, severity="high", asset=ASSET, kind="wazuh_alert") -> dict:
    return {"kind": kind, "key": key, "ts": ts, "asset": asset, "severity": severity, "payload": {"k": key}}


def link(ref="7", attack_id=7, technique="T1003", ts="2026-10-06T10:00:00+00:00") -> dict:
    return {"ref": ref, "attack_id": attack_id, "scenario": "brute_force_rdp", "technique": technique,
            "tool": "mimikatz", "attack_timestamp": ts}


OLD_INCIDENTS_SCHEMA = """
CREATE TABLE incidents (
    id TEXT PRIMARY KEY, status TEXT NOT NULL, severity TEXT NOT NULL, asset TEXT NOT NULL,
    created_at TEXT NOT NULL, first_evidence_at TEXT NOT NULL, last_evidence_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX idx_incidents_status ON incidents(status);
"""


def run_migration() -> None:
    """Base criada antes das colunas de JEV/equipa SOC: tem de abrir sem 500,
    sem perder dados e sem falhar à segunda abertura."""
    tmp = tempfile.TemporaryDirectory()
    path = os.path.join(tmp.name, "antiga.sqlite3")
    conn = sqlite3.connect(path)
    conn.executescript(OLD_INCIDENTS_SCHEMA)
    conn.execute("INSERT INTO incidents VALUES ('INC-OLD-001','NEW','high','10.0.0.1',"
                 "'2026-10-01T10:00:00+00:00','2026-10-01T10:00:00+00:00','2026-10-01T10:00:00+00:00','2026-10-01T10:00:00+00:00')")
    conn.commit()
    conn.close()

    # A constante de migração tem de coincidir com as colunas do SCHEMA, senão
    # uma coluna nova no SCHEMA volta a partir as bases antigas.
    block = re.search(r"CREATE TABLE IF NOT EXISTS incidents \((.*?)\n\);", SCHEMA, re.S).group(1)
    schema_cols = {m.group(1) for m in re.finditer(r"^\s+(\w+)\s+(?:TEXT|INTEGER)", block, re.M)}
    old_cols = {"id", "status", "severity", "asset", "created_at", "first_evidence_at",
                "last_evidence_at", "updated_at"}
    check("INCIDENTS_ADDED_COLUMNS = colunas do SCHEMA que a base antiga não tem",
          set(INCIDENTS_ADDED_COLUMNS) == schema_cols - old_cols)

    store = IncidentStore(path)
    rows = store.list_incidents()
    check("migração: a base antiga abre e lista (antes dava 'no such column')",
          [r["id"] for r in rows] == ["INC-OLD-001"])
    check("migração: os dados existentes ficam intactos",
          rows[0]["status"] == "NEW" and rows[0]["severity"] == "high" and rows[0]["asset"] == "10.0.0.1")
    check("migração: as colunas novas existem e vêm vazias", rows[0]["assigned_to"] is None and rows[0]["sla_deadline"] is None)

    conn = sqlite3.connect(path)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(incidents)")}
    indexes = {r[1] for r in conn.execute("PRAGMA index_list(incidents)")}
    conn.close()
    check("migração: todas as colunas do SCHEMA estão na tabela", schema_cols <= cols)
    check("migração: o índice sobre assigned_to foi criado", "idx_incidents_assigned" in indexes)
    check("migração: a rota de métricas (list_for_metrics) também funciona", len(store.list_for_metrics()) == 1)
    check("migração: consegue criar um incidente novo depois",
          store.create_incident(ev("alert:m1", "2026-10-02T10:00:00+00:00", asset="10.0.0.2"),
                                "2026-10-02T10:00:00+00:00").startswith("INC-20261002"))

    again = IncidentStore(path)  # 2.ª abertura: não pode tentar voltar a acrescentar colunas
    check("migração: idempotente (2.ª abertura não falha)", len(again.list_incidents()) == 2)

    fresh = IncidentStore(os.path.join(tmp.name, "nova.sqlite3"))
    check("migração: base nova não é afetada", fresh.list_incidents() == [])
    tmp.cleanup()


def run() -> None:
    tmp = tempfile.TemporaryDirectory()
    path = os.path.join(tmp.name, "i.sqlite3")
    store = IncidentStore(path)
    check("construir o store não cria o ficheiro (lazy)", not os.path.exists(path))
    check("evidence_exists numa base nova é False", store.evidence_exists("x") is False)
    check("a 1.ª operação cria o ficheiro", os.path.exists(path))

    NOW = "2026-10-06T10:01:00+00:00"
    inc1 = store.create_incident(ev("alert:a1", "2026-10-06T10:01:00+00:00"), NOW)
    check("1.º id do dia é INC-20261006-001", inc1 == "INC-20261006-001")
    inc2 = store.create_incident(ev("alert:a2", "2026-10-06T10:02:00+00:00", asset="10.0.0.9"), NOW)
    check("2.º id do dia é INC-20261006-002", inc2 == "INC-20261006-002")
    inc3 = store.create_incident(ev("alert:a3", "2026-10-07T00:00:05+00:00", asset="10.0.0.8"), NOW)
    check("id usa o dia da 1.ª evidência (sequência recomeça)", inc3 == "INC-20261007-001")

    i = store.get_incident(inc1)
    check("incidente novo: estado NEW, severidade, ativo", i["status"] == "NEW" and i["severity"] == "high" and i["asset"] == ASSET)
    check("incidente novo: created_at = now", i["created_at"] == NOW)
    check("incidente novo: 1 evidência com payload", len(i["evidence"]) == 1 and i["evidence"][0]["payload"] == {"k": "alert:a1"})
    check("timeline inicial = created, evidence_added", [e["kind"] for e in i["timeline"]] == ["created", "evidence_added"])
    check("eventos automáticos têm actor system", all(e["actor"] == "system" for e in i["timeline"]))
    check("get_incident inexistente -> None", store.get_incident("INC-NAO-EXISTE") is None)
    check("evidence_exists após criar", store.evidence_exists("alert:a1") and not store.evidence_exists("alert:zz"))
    check("sem ataque ligado: mttd None, ttfr None, técnicas vazias",
          i["mttd_seconds"] is None and i["time_to_first_response_seconds"] is None and i["techniques"] == [])

    # --- attach_evidence ---
    store.attach_evidence(inc1, ev("alert:a4", "2026-10-06T10:00:30+00:00", severity="low"), "2026-10-06T10:02:00+00:00")
    i = store.get_incident(inc1)
    check("attach: first_evidence_at recua para a evidência mais antiga", i["first_evidence_at"] == "2026-10-06T10:00:30+00:00")
    check("attach: last_evidence_at mantém a mais recente", i["last_evidence_at"] == "2026-10-06T10:01:00+00:00")
    check("attach: severidade não desce", i["severity"] == "high")
    store.attach_evidence(inc1, ev("alert:a5", "2026-10-06T10:03:00+00:00", severity="critical"), "2026-10-06T10:03:00+00:00")
    i = store.get_incident(inc1)
    check("attach: severidade sobe para o máximo", i["severity"] == "critical")
    check("attach: last_evidence_at avança", i["last_evidence_at"] == "2026-10-06T10:03:00+00:00")
    changed = [e for e in i["timeline"] if e["kind"] == "severity_changed"]
    check("attach: evento severity_changed com from/to", len(changed) == 1 and changed[0]["data"] == {"from": "high", "to": "critical"})
    check("attach: 3 evidências (a1, a4, a5)", len(i["evidence"]) == 3)
    try:
        store.attach_evidence("INC-NAO-EXISTE", ev("alert:b1", "2026-10-06T10:03:00+00:00"), NOW)
        check("attach a incidente inexistente lança IncidentNotFound", False)
    except IncidentNotFound:
        check("attach a incidente inexistente lança IncidentNotFound", True)
    try:
        store.attach_evidence(inc1, ev("alert:a4", "2026-10-06T10:04:00+00:00"), NOW)
        check("key repetida é recusada (UNIQUE)", False)
    except sqlite3.IntegrityError:
        check("key repetida é recusada (UNIQUE)", True)

    # --- list_open_incidents ---
    opens = store.list_open_incidents(ASSET)
    check("list_open_incidents devolve só o ativo pedido", [o["id"] for o in opens] == [inc1])
    check("list_open_incidents expõe last_evidence_at", opens[0]["last_evidence_at"] == "2026-10-06T10:03:00+00:00")

    # --- link_attack e derivados ---
    check("link_attack novo devolve True", store.link_attack(inc1, link(), NOW) is True)
    check("link_attack repetido (mesmo ref) devolve False", store.link_attack(inc1, link(), NOW) is False)
    i = store.get_incident(inc1)
    check("derivados: attack_ids e techniques", i["attack_ids"] == [7] and i["techniques"] == ["T1003"])
    check("derivados: mttd = 1.ª evidência - ataque (30.5 s)", i["mttd_seconds"] == 30.0)

    # --- set_status / add_note ---
    store.set_status(inc1, "INVESTIGATING", None, "2026-10-06T10:01:30+00:00")
    i = store.get_incident(inc1)
    check("set_status: estado atualizado", i["status"] == "INVESTIGATING")
    sc = [e for e in i["timeline"] if e["kind"] == "status_changed"][0]
    check("set_status: evento com from/to e actor analyst",
          sc["actor"] == "analyst" and sc["data"] == {"from": "NEW", "to": "INVESTIGATING"})
    check("derivados: tempo até à 1.ª resposta (INVESTIGATING - 1.ª evidência)", i["time_to_first_response_seconds"] == 60.0)
    try:
        store.set_status(inc1, "NEW", None, NOW)
        check("transição inválida lança InvalidTransition", False)
    except InvalidTransition as e:
        check("transição inválida lança InvalidTransition(transicao_invalida)", e.reason == "transicao_invalida")
    try:
        store.set_status(inc2, "CLOSED", "  ", NOW)
        check("NEW->CLOSED sem nota lança nota_obrigatoria", False)
    except InvalidTransition as e:
        check("NEW->CLOSED sem nota lança nota_obrigatoria", e.reason == "nota_obrigatoria")
    store.set_status(inc2, "CLOSED", " falso positivo ", NOW)
    i2 = store.get_incident(inc2)
    check("NEW->CLOSED com nota: fechado e nota guardada sem espaços",
          i2["status"] == "CLOSED" and [e for e in i2["timeline"] if e["kind"] == "status_changed"][0]["data"]["note"] == "falso positivo")
    try:
        store.set_status("INC-NAO-EXISTE", "INVESTIGATING", None, NOW)
        check("set_status inexistente lança IncidentNotFound", False)
    except IncidentNotFound:
        check("set_status inexistente lança IncidentNotFound", True)
    check("incidente fechado deixa de estar em list_open_incidents", store.list_open_incidents("10.0.0.9") == [])

    store.add_note(inc1, "<script>alert(1)</script>", "2026-10-06T10:05:00+00:00")
    notes = [e for e in store.get_incident(inc1)["timeline"] if e["kind"] == "note_added"]
    check("add_note: evento note_added, actor analyst, texto guardado verbatim",
          len(notes) == 1 and notes[0]["actor"] == "analyst" and notes[0]["data"] == {"text": "<script>alert(1)</script>"})
    try:
        store.add_note("INC-NAO-EXISTE", "x", NOW)
        check("add_note inexistente lança IncidentNotFound", False)
    except IncidentNotFound:
        check("add_note inexistente lança IncidentNotFound", True)

    # --- timeline append-only imposta pela base de dados ---
    conn = store._connect()
    try:
        for label, sql in [("UPDATE", "UPDATE incident_events SET kind = 'x'"), ("DELETE", "DELETE FROM incident_events")]:
            try:
                with conn:
                    conn.execute(sql)
                check(f"incident_events recusa {label}", False)
            except sqlite3.DatabaseError:
                check(f"incident_events recusa {label}", True)
    finally:
        conn.close()

    # --- list_incidents / summary ---
    rows = store.list_incidents()
    check("list_incidents devolve os 3, mais recente primeiro", [r["id"] for r in rows] == [inc3, inc1, inc2])
    check("list_incidents inclui evidence_count e não inclui timeline",
          next(r for r in rows if r["id"] == inc1)["evidence_count"] == 3 and "timeline" not in rows[0])
    check("filtro por estado", [r["id"] for r in store.list_incidents(status="CLOSED")] == [inc2])
    check("filtro por severidade", [r["id"] for r in store.list_incidents(severity="critical")] == [inc1])
    check("filtro since exclui antigos", [r["id"] for r in store.list_incidents(since_iso="2026-10-07T00:00:00+00:00")] == [inc3])
    check("paginação limit/offset", [r["id"] for r in store.list_incidents(limit=1, offset=1)] == [inc1])
    s = store.summary()
    check("summary: total e by_status", s["total"] == 3 and s["by_status"] == {"NEW": 1, "INVESTIGATING": 1, "CLOSED": 1})
    check("summary: abertos e altos/críticos abertos", s["open"] == 2 and s["high_or_critical_open"] == 2)
    check("summary: by_severity", s["by_severity"] == {"critical": 1, "high": 2})
    check("summary: MTTD médio só dos que têm ataque ligado", s["avg_mttd_seconds"] == 30.0)
    check("summary: tempo médio até à 1.ª resposta", s["avg_time_to_first_response_seconds"] == 60.0)
    empty = IncidentStore(os.path.join(tmp.name, "vazio.sqlite3")).summary()
    check("summary de base vazia", empty["total"] == 0 and empty["open"] == 0 and empty["avg_mttd_seconds"] is None)

    tmp.cleanup()

    run_migration()

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")


if __name__ == "__main__":
    run()
