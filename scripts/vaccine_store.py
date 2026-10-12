"""
Store SQLite das vaccines (Phase 13, VAC-05). Escrito só pelo ciclo do backend
(main._run_vaccine_cycle, D-01): as rotas GET só leem e abrem o ficheiro em
modo só-leitura, por isso um pedido nunca cria nem altera nada no disco (com o
ficheiro ainda inexistente respondem vazio).

O estado fixo `proposed` é garantido no próprio ficheiro, não só no código:
`CHECK (state = 'proposed')`, `CHECK (json_valid(payload))` e dois triggers que
recusam DELETE e qualquer UPDATE de uma coluna que não seja `superseded_by`
(metadado de substituição, D-06; não é um estado). Padrão de incident_store.py:
uma ligação por operação e um RLock em volta das escritas.

A escrita usa `INSERT ... ON CONFLICT(id) DO NOTHING` e não `INSERT OR IGNORE`
(emenda A1 a D-04): o segundo também engole em silêncio uma violação de CHECK
(rowcount 0, sem erro), o que anularia a garantia de estado; o primeiro só
ignora o conflito da chave primária e deixa um CHECK violado levantar
sqlite3.IntegrityError.

O id da vaccine é determinístico e deteta troca/duplicação, mas NÃO autentica
(mesmo aviso de vaccine_engine.py): quem consegue escrever no ficheiro também
consegue forjar linhas coerentes. Só stdlib; não importa a app.
"""

import json
import os
import pathlib
import sqlite3
import threading
from contextlib import contextmanager

DB_PATH_ENV = "SENTRYLENS_VACCINES_DB_PATH"
DEFAULT_DB_FILENAME = "vaccines.sqlite3"
# Campos que o store acrescenta à vaccine do motor ao ler (fora do contrato do motor).
STORE_FIELDS = ("state", "superseded_by", "created_at")

SCHEMA = """
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

_INSERT = (
    "INSERT INTO vaccines (id, attack_id, scenario, mitre_technique, verdict, payload, created_at) "
    "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING"
)


def resolve_db_path(raw: str | None) -> str:
    """D-05: vazio -> vaccines.sqlite3 ao lado deste módulo; relativo -> junto à
    pasta do módulo, nunca ao cwd; absoluto -> normalizado."""
    module_dir = os.path.dirname(os.path.abspath(__file__))
    if not raw:
        return os.path.join(module_dir, DEFAULT_DB_FILENAME)
    if os.path.isabs(raw):
        return os.path.normpath(raw)
    return os.path.normpath(os.path.join(module_dir, raw))


class VaccineStore:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self.lock = threading.RLock()

    # --- infraestrutura ---

    def _connect(self) -> sqlite3.Connection:
        """Ligação de escrita: cria o ficheiro e o esquema se for preciso (sem
        cache de esquema, para resistir a o ficheiro ser apagado em runtime)."""
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.executescript(SCHEMA)
        return conn

    @contextmanager
    def _tx(self):
        conn = self._connect()
        try:
            with conn:  # commit no sucesso, rollback na exceção
                yield conn
        finally:
            conn.close()

    @contextmanager
    def _read(self):
        """Ligação só-leitura; devolve None se o ficheiro ainda não existe (o
        método de leitura responde vazio sem criar nada)."""
        if not os.path.exists(self.db_path):
            yield None
            return
        conn = sqlite3.connect(pathlib.Path(self.db_path).resolve().as_uri() + "?mode=ro", uri=True, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    @staticmethod
    def _to_vaccine(row: sqlite3.Row) -> dict:
        """Payload do motor + campos do store. Erros (JSON corrompido, não-dict)
        propagam como ValueError; a rota mapeia-os para 503."""
        vaccine = json.loads(row["payload"])
        if not isinstance(vaccine, dict):
            raise ValueError("payload da vaccine nao e um objeto")
        for field in STORE_FIELDS:
            vaccine[field] = row[field]
        return vaccine

    # --- escrita (só o ciclo do backend) ---

    def upsert_batch(self, vaccines: list[dict], now_iso: str) -> dict:
        """Grava as vaccines numa só transação (tudo ou nada). Pré-condição: o
        chamador já validou cada uma com vaccine_engine.validate_vaccine."""
        counts = {"inserted": 0, "existing": 0}
        if not vaccines:
            return counts
        with self.lock, self._tx() as conn:
            for v in vaccines:
                origin = v["origin"]
                cur = conn.execute(_INSERT, (
                    v["id"], origin["attack_id"], origin["scenario"], origin["mitre_technique"], v["verdict"],
                    json.dumps(v, ensure_ascii=False, sort_keys=True), now_iso))
                counts["inserted" if cur.rowcount == 1 else "existing"] += 1
        return counts

    # --- leitura (só-leitura, nunca cria o ficheiro) ---

    def list_vaccines(self, *, limit: int = 200, offset: int = 0) -> tuple[list[dict], int, int]:
        """(linhas da página, total com os mesmos filtros, total de linhas do
        store). Parâmetros só por nome, de propósito: o bug de list_incidents foi
        um desalinhamento posicional."""
        with self._read() as conn:
            if conn is None:
                return [], 0, 0
            store_total = conn.execute("SELECT COUNT(*) FROM vaccines").fetchone()[0]
            total = store_total
            rows = conn.execute(
                "SELECT * FROM vaccines ORDER BY attack_id DESC, created_at DESC, id ASC LIMIT ? OFFSET ?",
                (limit, offset)).fetchall()
            return [self._to_vaccine(r) for r in rows], total, store_total

    def get_vaccine(self, vaccine_id: str) -> dict | None:
        with self._read() as conn:
            if conn is None:
                return None
            row = conn.execute("SELECT * FROM vaccines WHERE id = ?", (vaccine_id,)).fetchone()
            return self._to_vaccine(row) if row is not None else None
