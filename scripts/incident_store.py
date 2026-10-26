"""
Persistência SQLite dos incidentes (R3) — separada de historico/index.sqlite3
de propósito: aquele índice é uma cache reconstruível a partir do JSONL,
enquanto aqui há estado e notas do analista que não podem ser perdidos.

Uma ligação por operação (sqlite3.connect(timeout=10)) e um RLock em volta
das sequências "ler abertos -> decidir -> gravar" (ver incident_ingest), porque
o ingest corre numa thread de executor e a API/backfill noutra. A timeline
(incident_events) é append-only: triggers recusam UPDATE e DELETE.
"""

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import timedelta

from incident_engine import OPEN_STATUSES, can_transition, max_severity, parse_timestamp

SCHEMA = """
-- SOC Team tables
CREATE TABLE IF NOT EXISTS soc_analysts (
    id TEXT PRIMARY KEY,           -- e.g., "analyst-001"
    name TEXT NOT NULL UNIQUE,     -- display name
    tier INTEGER NOT NULL,         -- 1, 2, or 3
    email TEXT,
    active INTEGER DEFAULT 1,      -- 1 = active, 0 = inactive
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_analysts_tier ON soc_analysts(tier);
CREATE INDEX IF NOT EXISTS idx_analysts_active ON soc_analysts(active);

CREATE TABLE IF NOT EXISTS soc_shifts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analyst_id TEXT NOT NULL REFERENCES soc_analysts(id),
    start_ts TEXT NOT NULL,        -- ISO 8601 with timezone
    end_ts TEXT NOT NULL,
    role TEXT NOT NULL,            -- 'primary', 'secondary', 'on_call'
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_shifts_analyst ON soc_shifts(analyst_id);
CREATE INDEX IF NOT EXISTS idx_shifts_time ON soc_shifts(start_ts, end_ts);

CREATE TABLE IF NOT EXISTS soc_escalation_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_tier INTEGER NOT NULL,    -- 1, 2, or 3
    to_tier INTEGER NOT NULL,      -- 2, 3, or null (no escalation)
    severity TEXT NOT NULL,        -- 'critical', 'high', 'medium', 'low', 'info'
    auto_escalate INTEGER DEFAULT 0, -- 1 = auto-escalate on SLA breach
    sla_minutes INTEGER,           -- SLA in minutes for this tier/severity
    created_at TEXT NOT NULL
);

-- Incidents table (extended with team fields)
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    asset TEXT NOT NULL,
    created_at TEXT NOT NULL,
    first_evidence_at TEXT NOT NULL,
    last_evidence_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    triage_json TEXT,              -- cached JEV triage result
    assigned_to TEXT,              -- analyst assigned to this incident
    assigned_team_tier INTEGER,    -- team tier responsible (1, 2, or 3)
    escalated_from_tier INTEGER,   -- tier this was escalated from (null if none)
    escalated_at TEXT,             -- when escalated
    sla_deadline TEXT              -- SLA deadline based on severity/tier
);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_asset_last ON incidents(asset, last_evidence_at);
CREATE INDEX IF NOT EXISTS idx_incidents_assigned ON incidents(assigned_to);
CREATE INDEX IF NOT EXISTS idx_incidents_team_tier ON incidents(assigned_team_tier);
CREATE INDEX IF NOT EXISTS idx_incidents_sla ON incidents(sla_deadline);

CREATE TABLE IF NOT EXISTS incident_evidence (
    rowid_ INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(id),
    key TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    ts TEXT NOT NULL,
    severity TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_incident ON incident_evidence(incident_id);
CREATE TABLE IF NOT EXISTS incident_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(id),
    ts TEXT NOT NULL,
    kind TEXT NOT NULL,
    actor TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_incident ON incident_events(incident_id);
CREATE TRIGGER IF NOT EXISTS incident_events_no_update BEFORE UPDATE ON incident_events
BEGIN SELECT RAISE(ABORT, 'incident_events e append-only'); END;
CREATE TRIGGER IF NOT EXISTS incident_events_no_delete BEFORE DELETE ON incident_events
BEGIN SELECT RAISE(ABORT, 'incident_events e append-only'); END;
"""


# Colunas de `incidents` acrescentadas depois do R3 (JEV e equipa SOC). Têm de
# coincidir com as do SCHEMA (test_incident_store.py verifica); servem só para
# migrar bases criadas antes delas existirem.
INCIDENTS_ADDED_COLUMNS = {
    "triage_json": "TEXT",
    "assigned_to": "TEXT",
    "assigned_team_tier": "INTEGER",
    "escalated_from_tier": "INTEGER",
    "escalated_at": "TEXT",
    "sla_deadline": "TEXT",
}


class IncidentNotFound(Exception):
    pass


class InvalidTransition(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class IncidentStore:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self.lock = threading.RLock()
        self._schema_ready = False

    # --- infraestrutura ---

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        if not self._schema_ready:
            # O lock evita que duas threads migrem ao mesmo tempo (o segundo
            # ALTER TABLE falharia com "duplicate column name").
            with self.lock:
                if not self._schema_ready:
                    self._migrate_incidents_columns(conn)
                    conn.executescript(SCHEMA)
                    self._schema_ready = True
        return conn

    @staticmethod
    def _migrate_incidents_columns(conn: sqlite3.Connection) -> None:
        """Acrescenta a uma tabela `incidents` antiga as colunas que o SCHEMA
        passou a ter. `CREATE TABLE IF NOT EXISTS` não toca numa tabela que já
        existe, por isso sem isto o `CREATE INDEX ... assigned_to` do SCHEMA
        falhava ("no such column") e todas as rotas de incidentes davam 500.
        Só acrescenta colunas (nunca remove nem altera dados); numa base nova a
        tabela ainda não existe e o SCHEMA cria-a já completa."""
        existing = {row[1] for row in conn.execute("PRAGMA table_info(incidents)")}
        if not existing:
            return
        for name, declaration in INCIDENTS_ADDED_COLUMNS.items():
            if name not in existing:
                # `name`/`declaration` vêm da constante acima, nunca de input.
                conn.execute(f"ALTER TABLE incidents ADD COLUMN {name} {declaration}")
        conn.commit()

    @contextmanager
    def _tx(self):
        conn = self._connect()
        try:
            with conn:  # commit no sucesso, rollback na exceção
                yield conn
        finally:
            conn.close()

    @staticmethod
    def _add_event(conn, incident_id: str, ts: str, kind: str, actor: str, data: dict) -> None:
        conn.execute(
            "INSERT INTO incident_events (incident_id, ts, kind, actor, data) VALUES (?, ?, ?, ?, ?)",
            (incident_id, ts, kind, actor, json.dumps(data, ensure_ascii=False)),
        )

    @staticmethod
    def _insert_evidence(conn, incident_id: str, evidence: dict) -> None:
        conn.execute(
            "INSERT INTO incident_evidence (incident_id, key, kind, ts, severity, payload) VALUES (?, ?, ?, ?, ?, ?)",
            (incident_id, evidence["key"], evidence["kind"], evidence["ts"], evidence["severity"],
             json.dumps(evidence["payload"], ensure_ascii=False)),
        )

    @staticmethod
    def _next_id(conn, day: str) -> str:
        prefix = f"INC-{day}-"
        count = conn.execute("SELECT COUNT(*) FROM incidents WHERE id LIKE ?", (prefix + "%",)).fetchone()[0]
        return f"{prefix}{count + 1:03d}"

    # --- leitura simples (usada pelo ingest) ---

    def evidence_exists(self, key: str) -> bool:
        with self._tx() as conn:
            return conn.execute("SELECT 1 FROM incident_evidence WHERE key = ?", (key,)).fetchone() is not None

    def list_open_incidents(self, asset: str) -> list[dict]:
        placeholders = ",".join("?" for _ in OPEN_STATUSES)
        with self._tx() as conn:
            rows = conn.execute(
                f"SELECT id, status, severity, asset, last_evidence_at FROM incidents "
                f"WHERE asset = ? AND status IN ({placeholders})",
                (asset, *OPEN_STATUSES),
            ).fetchall()
        return [dict(r) for r in rows]

    # --- escrita ---

    def create_incident(self, evidence: dict, now_iso: str) -> str:
        with self.lock, self._tx() as conn:
            day = parse_timestamp(evidence["ts"]).strftime("%Y%m%d")
            incident_id = self._next_id(conn, day)
            conn.execute(
                "INSERT INTO incidents (id, status, severity, asset, created_at, first_evidence_at, "
                "last_evidence_at, updated_at) VALUES (?, 'NEW', ?, ?, ?, ?, ?, ?)",
                (incident_id, evidence["severity"], evidence["asset"], now_iso,
                 evidence["ts"], evidence["ts"], now_iso),
            )
            self._insert_evidence(conn, incident_id, evidence)
            self._add_event(conn, incident_id, now_iso, "created", "system",
                            {"asset": evidence["asset"], "severity": evidence["severity"],
                             "first_evidence_at": evidence["ts"]})
            self._add_event(conn, incident_id, now_iso, "evidence_added", "system",
                            {"key": evidence["key"], "kind": evidence["kind"], "ts": evidence["ts"],
                             "severity": evidence["severity"]})
        return incident_id

    def attach_evidence(self, incident_id: str, evidence: dict, now_iso: str) -> None:
        with self.lock, self._tx() as conn:
            row = conn.execute(
                "SELECT severity, first_evidence_at, last_evidence_at FROM incidents WHERE id = ?", (incident_id,)
            ).fetchone()
            if row is None:
                raise IncidentNotFound(incident_id)
            self._insert_evidence(conn, incident_id, evidence)

            new_severity = max_severity(row["severity"], evidence["severity"])
            ev_ts = parse_timestamp(evidence["ts"])
            first = evidence["ts"] if ev_ts < parse_timestamp(row["first_evidence_at"]) else row["first_evidence_at"]
            last = evidence["ts"] if ev_ts > parse_timestamp(row["last_evidence_at"]) else row["last_evidence_at"]
            conn.execute(
                "UPDATE incidents SET severity = ?, first_evidence_at = ?, last_evidence_at = ?, updated_at = ? WHERE id = ?",
                (new_severity, first, last, now_iso, incident_id),
            )
            self._add_event(conn, incident_id, now_iso, "evidence_added", "system",
                            {"key": evidence["key"], "kind": evidence["kind"], "ts": evidence["ts"],
                             "severity": evidence["severity"]})
            if new_severity != row["severity"]:
                self._add_event(conn, incident_id, now_iso, "severity_changed", "system",
                                {"from": row["severity"], "to": new_severity})

    def link_attack(self, incident_id: str, link_data: dict, now_iso: str) -> bool:
        with self.lock, self._tx() as conn:
            rows = conn.execute(
                "SELECT data FROM incident_events WHERE incident_id = ? AND kind = 'attack_linked'", (incident_id,)
            ).fetchall()
            if any(json.loads(r["data"]).get("ref") == link_data["ref"] for r in rows):
                return False
            self._add_event(conn, incident_id, now_iso, "attack_linked", "system", link_data)
        return True

    def add_note(self, incident_id: str, text: str, now_iso: str) -> None:
        with self.lock, self._tx() as conn:
            if conn.execute("SELECT 1 FROM incidents WHERE id = ?", (incident_id,)).fetchone() is None:
                raise IncidentNotFound(incident_id)
            self._add_event(conn, incident_id, now_iso, "note_added", "analyst", {"text": text})
            conn.execute("UPDATE incidents SET updated_at = ? WHERE id = ?", (now_iso, incident_id))

    def save_triage(self, incident_id: str, triage_result: dict, now_iso: str) -> None:
        """Save JEV triage result to incident (cached)."""
        with self.lock, self._tx() as conn:
            if conn.execute("SELECT 1 FROM incidents WHERE id = ?", (incident_id,)).fetchone() is None:
                raise IncidentNotFound(incident_id)
            conn.execute(
                "UPDATE incidents SET triage_json = ?, updated_at = ? WHERE id = ?",
                (json.dumps(triage_result, ensure_ascii=False), now_iso, incident_id),
            )
            self._add_event(conn, incident_id, now_iso, "triage_performed", "jev", triage_result)

    def get_triage(self, incident_id: str) -> dict | None:
        """Get cached JEV triage result for incident."""
        with self._tx() as conn:
            row = conn.execute("SELECT triage_json FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            if row is None or row["triage_json"] is None:
                return None
            return json.loads(row["triage_json"])

    def assign_analyst(self, incident_id: str, analyst: str | None, now_iso: str) -> None:
        """Assign or unassign an analyst to an incident."""
        with self.lock, self._tx() as conn:
            row = conn.execute("SELECT assigned_to FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            if row is None:
                raise IncidentNotFound(incident_id)
            old_assignee = row["assigned_to"]
            conn.execute("UPDATE incidents SET assigned_to = ?, updated_at = ? WHERE id = ?",
                         (analyst, now_iso, incident_id))
            self._add_event(conn, incident_id, now_iso, "assignment_changed", "analyst",
                            {"from": old_assignee, "to": analyst})

    def set_status(self, incident_id: str, new_status: str, note: str | None, now_iso: str) -> None:
        with self.lock, self._tx() as conn:
            row = conn.execute("SELECT status FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            if row is None:
                raise IncidentNotFound(incident_id)
            ok, reason = can_transition(row["status"], new_status, note)
            if not ok:
                raise InvalidTransition(reason)
            data = {"from": row["status"], "to": new_status}
            if note and note.strip():
                data["note"] = note.strip()
            conn.execute("UPDATE incidents SET status = ?, updated_at = ? WHERE id = ?",
                         (new_status, now_iso, incident_id))
            self._add_event(conn, incident_id, now_iso, "status_changed", "analyst", data)

    # --- leitura completa ---

    @staticmethod
    def _timeline(conn, incident_id: str) -> list[dict]:
        rows = conn.execute(
            "SELECT id, ts, kind, actor, data FROM incident_events WHERE incident_id = ? ORDER BY id", (incident_id,)
        ).fetchall()
        return [{"id": r["id"], "ts": r["ts"], "kind": r["kind"], "actor": r["actor"],
                 "data": json.loads(r["data"])} for r in rows]

    @staticmethod
    def _derived(incident: dict, timeline: list[dict]) -> dict:
        links = [e["data"] for e in timeline if e["kind"] == "attack_linked"]
        attack_ids = [lk["attack_id"] for lk in links if lk.get("attack_id") is not None]
        techniques = sorted({lk["technique"] for lk in links if lk.get("technique")})

        mttd = None
        first_evidence = parse_timestamp(incident["first_evidence_at"])
        attack_times = [t for t in (parse_timestamp(lk.get("attack_timestamp")) for lk in links) if t is not None]
        if first_evidence is not None and attack_times:
            mttd = max(0.0, round((first_evidence - min(attack_times)).total_seconds(), 2))

        ttfr = None
        response = next((e for e in timeline if e["kind"] == "status_changed" and e["data"].get("to") == "INVESTIGATING"), None)
        if response is not None and first_evidence is not None:
            ttfr = round((parse_timestamp(response["ts"]) - first_evidence).total_seconds(), 2)

        return {"attack_ids": attack_ids, "techniques": techniques,
                "mttd_seconds": mttd, "time_to_first_response_seconds": ttfr}

    def get_incident(self, incident_id: str) -> dict | None:
        with self._tx() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            if row is None:
                return None
            incident = dict(row)
            evidence_rows = conn.execute(
                "SELECT key, kind, ts, severity, payload FROM incident_evidence WHERE incident_id = ? ORDER BY ts, rowid_",
                (incident_id,),
            ).fetchall()
            timeline = self._timeline(conn, incident_id)
        incident["evidence"] = [{"key": r["key"], "kind": r["kind"], "ts": r["ts"], "severity": r["severity"],
                                 "payload": json.loads(r["payload"])} for r in evidence_rows]
        incident["timeline"] = timeline
        incident.update(self._derived(incident, timeline))
        # Include cached triage if available
        if incident.get("triage_json"):
            incident["triage"] = json.loads(incident["triage_json"])
        return incident

    def list_incidents(self, status: str | None = None, severity: str | None = None,
                       since_iso: str | None = None, assigned_to: str | None = None,
                       assigned_team_tier: int | None = None,
                       limit: int = 100, offset: int = 0) -> list[dict]:
        clauses, params = [], []
        if status:
            clauses.append("i.status = ?")
            params.append(status)
        if severity:
            clauses.append("i.severity = ?")
            params.append(severity)
        if since_iso:
            clauses.append("i.last_evidence_at >= ?")
            params.append(since_iso)
        if assigned_to:
            clauses.append("i.assigned_to = ?")
            params.append(assigned_to)
        if assigned_team_tier is not None:
            clauses.append("i.assigned_team_tier = ?")
            params.append(assigned_team_tier)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._tx() as conn:
            rows = conn.execute(
                f"SELECT i.*, (SELECT COUNT(*) FROM incident_evidence e WHERE e.incident_id = i.id) AS evidence_count "
                f"FROM incidents i {where} ORDER BY i.last_evidence_at DESC, i.id DESC LIMIT ? OFFSET ?",
                (*params, limit, offset),
            ).fetchall()
            result = []
            for row in rows:
                incident = dict(row)
                incident.update(self._derived(incident, self._timeline(conn, incident["id"])))
                result.append(incident)
        return result

    def summary(self, since_iso: str | None = None) -> dict:
        incidents = self.list_incidents(since_iso=since_iso, limit=100000)
        by_status: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for inc in incidents:
            by_status[inc["status"]] = by_status.get(inc["status"], 0) + 1
            by_severity[inc["severity"]] = by_severity.get(inc["severity"], 0) + 1
        open_ones = [i for i in incidents if i["status"] in OPEN_STATUSES]
        mttds = [i["mttd_seconds"] for i in incidents if i["mttd_seconds"] is not None]
        ttfrs = [i["time_to_first_response_seconds"] for i in incidents if i["time_to_first_response_seconds"] is not None]
        return {
            "total": len(incidents),
            "by_status": by_status,
            "by_severity": by_severity,
            "open": len(open_ones),
            "high_or_critical_open": sum(1 for i in open_ones if i["severity"] in ("high", "critical")),
            "avg_mttd_seconds": round(sum(mttds) / len(mttds), 2) if mttds else None,
            "avg_time_to_first_response_seconds": round(sum(ttfrs) / len(ttfrs), 2) if ttfrs else None,
        }

    def list_for_metrics(self, since_iso: str | None = None) -> list[dict]:
        """Incidentes da janela com a sua timeline reduzida às transições de
        estado (R8: MTTR e falsos positivos). Só leitura; não carrega as
        evidências (payloads) como get_incident."""
        incidents = self.list_incidents(since_iso=since_iso, limit=100000)
        with self._tx() as conn:
            for incident in incidents:
                incident["timeline"] = [
                    e for e in self._timeline(conn, incident["id"]) if e["kind"] == "status_changed"
                ]
        return incidents

    # ============================================================
    # SOC Team Management
    # ============================================================

    # --- Analysts ---
    def create_analyst(self, analyst_id: str, name: str, tier: int, email: str | None, now_iso: str) -> None:
        """Create a new SOC analyst."""
        if tier not in (1, 2, 3):
            raise ValueError("tier must be 1, 2, or 3")
        with self.lock, self._tx() as conn:
            conn.execute(
                "INSERT INTO soc_analysts (id, name, tier, email, active, created_at) VALUES (?, ?, ?, ?, 1, ?)",
                (analyst_id, name, tier, email, now_iso),
            )

    def get_analyst(self, analyst_id: str) -> dict | None:
        with self._tx() as conn:
            row = conn.execute("SELECT * FROM soc_analysts WHERE id = ?", (analyst_id,)).fetchone()
            return dict(row) if row else None

    def get_analyst_by_name(self, name: str) -> dict | None:
        with self._tx() as conn:
            row = conn.execute("SELECT * FROM soc_analysts WHERE name = ?", (name,)).fetchone()
            return dict(row) if row else None

    def list_analysts(self, tier: int | None = None, active_only: bool = True) -> list[dict]:
        with self._tx() as conn:
            query = "SELECT * FROM soc_analysts"
            params = []
            clauses = []
            if active_only:
                clauses.append("active = 1")
            if tier is not None:
                clauses.append("tier = ?")
                params.append(tier)
            if clauses:
                query += " WHERE " + " AND ".join(clauses)
            query += " ORDER BY tier, name"
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    def update_analyst(self, analyst_id: str, tier: int | None = None, email: str | None = None, active: int | None = None) -> None:
        with self.lock, self._tx() as conn:
            updates = []
            params = []
            if tier is not None:
                if tier not in (1, 2, 3):
                    raise ValueError("tier must be 1, 2, or 3")
                updates.append("tier = ?")
                params.append(tier)
            if email is not None:
                updates.append("email = ?")
                params.append(email)
            if active is not None:
                updates.append("active = ?")
                params.append(active)
            if not updates:
                return
            params.append(analyst_id)
            conn.execute(f"UPDATE soc_analysts SET {', '.join(updates)} WHERE id = ?", params)

    def deactivate_analyst(self, analyst_id: str) -> None:
        self.update_analyst(analyst_id, active=0)

    # --- Shifts ---
    def create_shift(self, analyst_id: str, start_ts: str, end_ts: str, role: str, now_iso: str) -> int:
        """Create a shift for an analyst. role: 'primary', 'secondary', 'on_call'."""
        if role not in ("primary", "secondary", "on_call"):
            raise ValueError("role must be 'primary', 'secondary', or 'on_call'")
        with self.lock, self._tx() as conn:
            cur = conn.execute(
                "INSERT INTO soc_shifts (analyst_id, start_ts, end_ts, role, created_at) VALUES (?, ?, ?, ?, ?)",
                (analyst_id, start_ts, end_ts, role, now_iso),
            )
            return cur.lastrowid

    def get_shifts(self, analyst_id: str | None = None, since: str | None = None,
                   until: str | None = None) -> list[dict]:
        """Turnos, de um analista (`analyst_id`) ou de todos (None). Junta o nome
        e o tier do analista (`analyst_name`/`analyst_tier`), que a aba Equipa
        SOC mostra; um turno cujo analista já não exista fica com ambos a None
        em vez de desaparecer da lista."""
        query = ("SELECT s.*, a.name AS analyst_name, a.tier AS analyst_tier "
                 "FROM soc_shifts s LEFT JOIN soc_analysts a ON a.id = s.analyst_id")
        clauses, params = [], []
        if analyst_id:
            clauses.append("s.analyst_id = ?")
            params.append(analyst_id)
        if since:
            clauses.append("s.end_ts >= ?")
            params.append(since)
        if until:
            clauses.append("s.start_ts <= ?")
            params.append(until)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY s.start_ts, s.id"
        with self._tx() as conn:
            return [dict(r) for r in conn.execute(query, params).fetchall()]

    def get_shifts_for_analyst(self, analyst_id: str, since: str | None = None, until: str | None = None) -> list[dict]:
        return self.get_shifts(analyst_id, since, until)

    def get_current_on_call(self, tier: int, now_iso: str) -> list[dict]:
        """Get analysts currently on-call for a tier."""
        with self._tx() as conn:
            rows = conn.execute(
                """SELECT a.* FROM soc_analysts a
                   JOIN soc_shifts s ON s.analyst_id = a.id
                   WHERE a.tier = ? AND a.active = 1
                   AND s.role = 'on_call'
                   AND s.start_ts <= ? AND s.end_ts >= ?""",
                (tier, now_iso, now_iso),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_current_primary(self, tier: int, now_iso: str) -> list[dict]:
        """Get analysts currently on primary shift for a tier."""
        with self._tx() as conn:
            rows = conn.execute(
                """SELECT a.* FROM soc_analysts a
                   JOIN soc_shifts s ON s.analyst_id = a.id
                   WHERE a.tier = ? AND a.active = 1
                   AND s.role = 'primary'
                   AND s.start_ts <= ? AND s.end_ts >= ?""",
                (tier, now_iso, now_iso),
            ).fetchall()
            return [dict(r) for r in rows]

    # --- Escalation Rules ---
    def create_escalation_rule(self, from_tier: int, to_tier: int | None, severity: str,
                                auto_escalate: int, sla_minutes: int | None, now_iso: str) -> int:
        if from_tier not in (1, 2, 3) or (to_tier is not None and to_tier not in (1, 2, 3)):
            raise ValueError("tier must be 1, 2, or 3")
        if severity not in ("critical", "high", "medium", "low", "info"):
            raise ValueError("invalid severity")
        with self.lock, self._tx() as conn:
            cur = conn.execute(
                """INSERT INTO soc_escalation_rules (from_tier, to_tier, severity, auto_escalate, sla_minutes, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (from_tier, to_tier, severity, auto_escalate, sla_minutes, now_iso),
            )
            return cur.lastrowid

    def get_escalation_rules(self, from_tier: int | None = None, severity: str | None = None) -> list[dict]:
        with self._tx() as conn:
            query = "SELECT * FROM soc_escalation_rules"
            params = []
            clauses = []
            if from_tier is not None:
                clauses.append("from_tier = ?")
                params.append(from_tier)
            if severity is not None:
                clauses.append("severity = ?")
                params.append(severity)
            if clauses:
                query += " WHERE " + " AND ".join(clauses)
            query += " ORDER BY from_tier, severity"
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    def get_escalation_rule(self, from_tier: int, severity: str) -> dict | None:
        with self._tx() as conn:
            row = conn.execute(
                "SELECT * FROM soc_escalation_rules WHERE from_tier = ? AND severity = ?",
                (from_tier, severity),
            ).fetchone()
            return dict(row) if row else None

    # --- Team-based Incident Operations ---
    def auto_triage(self, incident_id: str, now_iso: str) -> dict:
        """Triagem automática de um incidente novo: Tier 1, com o analista
        principal do turno atual (o de menor id, se houver mais de um; nenhum
        se ninguém estiver de turno) e o SLA da regra de escalamento Tier 1 /
        severidade (sem regra, não inventa prazo). Não muda o estado: passar a
        INVESTIGATING é uma ação humana. Eventos com actor "system"."""
        with self.lock:
            with self._tx() as conn:
                row = conn.execute("SELECT severity FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            if row is None:
                raise IncidentNotFound(incident_id)
            primaries = sorted(self.get_current_primary(1, now_iso), key=lambda a: a["id"])
            analyst = primaries[0]["name"] if primaries else None
            self.assign_to_tier(incident_id, 1, analyst, now_iso, actor="system")
            rule = self.get_escalation_rule(1, row["severity"])
            deadline = None
            if rule and rule["sla_minutes"]:
                deadline = (parse_timestamp(now_iso) + timedelta(minutes=rule["sla_minutes"])).isoformat()
                self.set_sla_deadline(incident_id, deadline, now_iso)
        return {"tier": 1, "analyst": analyst, "sla_deadline": deadline}

    def assign_to_tier(self, incident_id: str, tier: int, analyst_id: str | None, now_iso: str,
                       actor: str = "analyst") -> None:
        """Assign incident to a team tier (and optionally an analyst)."""
        if tier not in (1, 2, 3):
            raise ValueError("tier must be 1, 2, or 3")
        with self.lock, self._tx() as conn:
            row = conn.execute("SELECT assigned_team_tier, assigned_to FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            if row is None:
                raise IncidentNotFound(incident_id)
            old_tier = row["assigned_team_tier"]
            old_analyst = row["assigned_to"]
            conn.execute(
                "UPDATE incidents SET assigned_team_tier = ?, assigned_to = ?, updated_at = ? WHERE id = ?",
                (tier, analyst_id, now_iso, incident_id),
            )
            self._add_event(conn, incident_id, now_iso, "team_assigned", actor,
                            {"from_tier": old_tier, "to_tier": tier, "from_analyst": old_analyst, "to_analyst": analyst_id})

    def escalate_incident(self, incident_id: str, to_tier: int, analyst_id: str | None, now_iso: str) -> None:
        """Escalate incident to a higher tier."""
        with self.lock, self._tx() as conn:
            row = conn.execute("SELECT assigned_team_tier, assigned_to FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            if row is None:
                raise IncidentNotFound(incident_id)
            from_tier = row["assigned_team_tier"]
            if from_tier is not None and to_tier <= from_tier:
                raise ValueError("escalation must be to a higher tier")
            conn.execute(
                "UPDATE incidents SET assigned_team_tier = ?, assigned_to = ?, escalated_from_tier = ?, escalated_at = ?, updated_at = ? WHERE id = ?",
                (to_tier, analyst_id, from_tier, now_iso, now_iso, incident_id),
            )
            self._add_event(conn, incident_id, now_iso, "escalated", "analyst",
                            {"from_tier": from_tier, "to_tier": to_tier, "analyst": analyst_id})

    def set_sla_deadline(self, incident_id: str, deadline_iso: str, now_iso: str) -> None:
        with self.lock, self._tx() as conn:
            if conn.execute("SELECT 1 FROM incidents WHERE id = ?", (incident_id,)).fetchone() is None:
                raise IncidentNotFound(incident_id)
            conn.execute("UPDATE incidents SET sla_deadline = ?, updated_at = ? WHERE id = ?",
                         (deadline_iso, now_iso, incident_id))
            self._add_event(conn, incident_id, now_iso, "sla_set", "system", {"deadline": deadline_iso})

    def get_sla_breaches(self, now_iso: str) -> list[dict]:
        """Get incidents with breached SLA (deadline passed, not resolved)."""
        with self._tx() as conn:
            rows = conn.execute(
                """SELECT * FROM incidents
                   WHERE sla_deadline IS NOT NULL
                   AND sla_deadline < ?
                   AND status NOT IN ('RESOLVED', 'CLOSED')""",
                (now_iso,),
            ).fetchall()
            return [dict(r) for r in rows]

    def list_incidents_by_tier(self, tier: int, status: str | None = None, since_iso: str | None = None,
                                limit: int = 100, offset: int = 0) -> list[dict]:
        """List incidents assigned to a specific tier."""
        return self.list_incidents(assigned_to=None, status=status, severity=None, since_iso=since_iso,
                                   assigned_team_tier=tier, limit=limit, offset=offset)

    def summary_by_tier(self, since_iso: str | None = None) -> dict:
        """Summary grouped by team tier."""
        incidents = self.list_incidents(since_iso=since_iso, limit=100000)
        by_tier: dict[int, dict] = {}
        for inc in incidents:
            tier = inc.get("assigned_team_tier") or 0
            if tier not in by_tier:
                by_tier[tier] = {"total": 0, "by_status": {}, "by_severity": {}, "open": 0}
            t = by_tier[tier]
            t["total"] += 1
            t["by_status"][inc["status"]] = t["by_status"].get(inc["status"], 0) + 1
            t["by_severity"][inc["severity"]] = t["by_severity"].get(inc["severity"], 0) + 1
            if inc["status"] in OPEN_STATUSES:
                t["open"] += 1
        return by_tier
