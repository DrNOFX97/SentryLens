"""
Índice SQLite sobre o histórico de alertas (scripts/history_store.py) — só
os campos filtráveis (data, event_id, severidade, vereditos de
conformidade), cada linha a apontar para o ficheiro/offset onde está o
registo completo em alerts.jsonl/compliance.jsonl. Resolve consultas tipo
"todos os alertas RGPD aplicável entre março e maio" sem percorrer todas as
pastas por dia — proposta já desenhada na Fase 9, construída agora.

Um único ficheiro SQLite (<base_dir>/index.sqlite3), não um por dia —
SQLite lida bem com intervalos de datas arbitrários dentro de um único
ficheiro, e evita ter de fazer UNION entre centenas de ficheiros pequenos.
"""

import json
import os
import sqlite3


def _index_db_path(base_dir: str) -> str:
    return os.path.join(base_dir, "index.sqlite3")


def _connect(base_dir: str) -> sqlite3.Connection:
    os.makedirs(base_dir, exist_ok=True)
    conn = sqlite3.connect(_index_db_path(base_dir))
    _ensure_schema(conn)
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS history_index (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            time TEXT NOT NULL,
            event_id INTEGER,
            severity TEXT,
            rgpd_estado TEXT,
            nis2_estado TEXT,
            ai_act_estado TEXT,
            alerts_file TEXT NOT NULL,
            alerts_offset INTEGER NOT NULL,
            compliance_file TEXT,
            compliance_offset INTEGER
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_history_date ON history_index(date)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_history_severity ON history_index(severity)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_history_rgpd ON history_index(rgpd_estado)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_history_nis2 ON history_index(nis2_estado)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_history_ai_act ON history_index(ai_act_estado)")
    conn.commit()


def index_alert(
    base_dir: str,
    *,
    date: str,
    time: str,
    event_id: int | None,
    severity: str | None,
    rgpd_estado: str | None,
    nis2_estado: str | None,
    ai_act_estado: str | None,
    alerts_file: str,
    alerts_offset: int,
    compliance_file: str | None = None,
    compliance_offset: int | None = None,
) -> None:
    """Insere uma linha no índice. Chamado uma vez por alerta, logo a seguir a escrever alerts.jsonl + compliance.jsonl."""
    conn = _connect(base_dir)
    try:
        conn.execute(
            """
            INSERT INTO history_index
                (date, time, event_id, severity, rgpd_estado, nis2_estado, ai_act_estado,
                 alerts_file, alerts_offset, compliance_file, compliance_offset)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (date, time, event_id, severity, rgpd_estado, nis2_estado, ai_act_estado,
             alerts_file, alerts_offset, compliance_file, compliance_offset),
        )
        conn.commit()
    finally:
        conn.close()


def query_history_index(
    base_dir: str,
    *,
    date_from: str | None = None,
    date_to: str | None = None,
    severity: str | None = None,
    rgpd_estado: str | None = None,
    nis2_estado: str | None = None,
    ai_act_estado: str | None = None,
    limit: int = 200,
) -> list[dict]:
    """
    Consulta o índice com filtros opcionais (AND entre os fornecidos, nenhum
    filtro = tudo). date_from/date_to são strings "AAAA-MM-DD" comparadas
    lexicograficamente (funciona porque o formato já é ordenável). Devolve
    as linhas mais recentes primeiro (date DESC, time DESC), como dicts.
    """
    conn = _connect(base_dir)
    try:
        conn.row_factory = sqlite3.Row
        clauses: list[str] = []
        params: list = []
        if date_from:
            clauses.append("date >= ?")
            params.append(date_from)
        if date_to:
            clauses.append("date <= ?")
            params.append(date_to)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if rgpd_estado:
            clauses.append("rgpd_estado = ?")
            params.append(rgpd_estado)
        if nis2_estado:
            clauses.append("nis2_estado = ?")
            params.append(nis2_estado)
        if ai_act_estado:
            clauses.append("ai_act_estado = ?")
            params.append(ai_act_estado)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT * FROM history_index {where} ORDER BY date DESC, time DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def read_jsonl_at_offset(file_path: str, offset: int) -> dict | None:
    """Lê e faz parse de uma linha JSONL a partir de um offset em bytes conhecido (ver history_store.append_alert_history). Devolve None se o ficheiro não existir ou o offset for inválido."""
    if not os.path.exists(file_path):
        return None
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            f.seek(offset)
            line = f.readline()
            if not line:
                return None
            return json.loads(line)
    except (OSError, json.JSONDecodeError):
        return None
