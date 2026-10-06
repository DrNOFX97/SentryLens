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

from incident_engine import OPEN_STATUSES, can_transition, max_severity, parse_timestamp

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    asset TEXT NOT NULL,
    created_at TEXT NOT NULL,
    first_evidence_at TEXT NOT NULL,
    last_evidence_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_asset_last ON incidents(asset, last_evidence_at);
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
            conn.executescript(SCHEMA)
            self._schema_ready = True
        return conn

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
        return incident

    def list_incidents(self, status: str | None = None, severity: str | None = None,
                       since_iso: str | None = None, limit: int = 100, offset: int = 0) -> list[dict]:
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
