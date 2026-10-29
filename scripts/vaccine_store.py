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

R12 (Phase 15): as decisões dos analistas vivem numa segunda tabela, só de
acréscimo, no mesmo ficheiro (`vaccine_decisions`). UNIQUE(vaccine_id) torna a
decisão final no próprio ficheiro e dois triggers recusam UPDATE e DELETE. O
estado lido é derivado (a decisão registada, ou `proposed`); a coluna `state` de
`vaccines` continua fixa em `proposed` e a tabela `vaccines` não muda. Um ficheiro
sem a tabela conta como "sem decisões" (a leitura nunca a cria; nasce na primeira
escrita). Aprovar não aplica nada no Wazuh: é só o registo da decisão.
"""

import json
import os
import pathlib
import sqlite3
import threading
from contextlib import contextmanager

from vaccine_decision import (DECISION_FIELDS, DECISION_RECORD_KEYS, VaccineDecisionError, check_transition,
                              derive_state, validate_request)

DB_PATH_ENV = "SENTRYLENS_VACCINES_DB_PATH"
DEFAULT_DB_FILENAME = "vaccines.sqlite3"
# Campos que o store acrescenta à vaccine do motor ao ler (fora do contrato do motor).
# `state` é derivado (a decisão registada, ou proposed); `decision` é o bloco da
# decisão (ou None).
STORE_FIELDS = ("state", "superseded_by", "created_at", "decision")

VACCINES_SCHEMA = """
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

# R12 (Phase 15): registo de decisões, só de acréscimo, no mesmo ficheiro. A tabela
# vaccines acima não muda um byte. UNIQUE(vaccine_id) torna a decisão final no
# próprio ficheiro; os triggers recusam UPDATE e DELETE.
DECISIONS_SCHEMA = """
CREATE TABLE IF NOT EXISTS vaccine_decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vaccine_id TEXT NOT NULL UNIQUE REFERENCES vaccines(id) CHECK (vaccine_id GLOB 'vac-*' AND length(vaccine_id) = 16),
    decision TEXT NOT NULL CHECK (decision IN ('approved', 'rejected')),
    decided_by TEXT NOT NULL CHECK (decided_by GLOB 'analyst-?*' AND decided_by NOT GLOB '*[^a-z0-9-]*' AND length(decided_by) <= 72),
    decided_by_name TEXT NOT NULL CHECK (length(decided_by_name) BETWEEN 1 AND 128),
    decided_at TEXT NOT NULL,
    reason TEXT CHECK (reason IS NULL OR (length(reason) BETWEEN 1 AND 500 AND length(trim(reason, char(32, 9, 10, 13))) > 0)),
    previous_state TEXT NOT NULL CHECK (previous_state = 'proposed'),
    CHECK (decision <> 'rejected' OR reason IS NOT NULL)
);
CREATE TRIGGER IF NOT EXISTS vaccine_decisions_no_update BEFORE UPDATE ON vaccine_decisions
BEGIN SELECT RAISE(ABORT, 'vaccine_decisions e append-only'); END;
CREATE TRIGGER IF NOT EXISTS vaccine_decisions_no_delete BEFORE DELETE ON vaccine_decisions
BEGIN SELECT RAISE(ABORT, 'vaccine_decisions e append-only'); END;
"""

SCHEMA = VACCINES_SCHEMA + DECISIONS_SCHEMA

_INSERT = (
    "INSERT INTO vaccines (id, attack_id, scenario, mitre_technique, verdict, payload, created_at) "
    "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING"
)

# INSERT simples, sem cláusula de conflito nem variante que ignore erros: uma
# decisão duplicada tem de falhar alto pela UNIQUE, nunca ser engolida (mesmo
# motivo da emenda A1 acima).
_INSERT_DECISION = (
    "INSERT INTO vaccine_decisions (vaccine_id, decision, decided_by, decided_by_name, decided_at, reason, "
    "previous_state) VALUES (?, ?, ?, ?, ?, ?, ?)"
)

# Fragmentos de leitura fixos, escolhidos pelo código conforme a tabela exista (D-10);
# nunca construídos a partir de dados do pedido.
_FROM_WITH_DECISIONS = " FROM vaccines v LEFT JOIN vaccine_decisions d ON d.vaccine_id = v.id"
_FROM_WITHOUT_DECISIONS = " FROM vaccines v"
# Expressão do estado derivado (D-11): a decisão registada, ou proposed.
_STATE_WITH_DECISIONS = "COALESCE(d.decision, 'proposed')"
_STATE_WITHOUT_DECISIONS = "'proposed'"
_COLUMNS_WITH_DECISIONS = (
    "SELECT v.*, d.decision AS d_decision, d.decided_by AS d_decided_by, d.decided_by_name AS d_decided_by_name, "
    "d.decided_at AS d_decided_at, d.reason AS d_reason"
)
_COLUMNS_WITHOUT_DECISIONS = (
    "SELECT v.*, NULL AS d_decision, NULL AS d_decided_by, NULL AS d_decided_by_name, "
    "NULL AS d_decided_at, NULL AS d_reason"
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
    def _tx_immediate(self):
        """Transação de escrita com BEGIN IMMEDIATE (D-06): tira o lock de escrita
        antes das leituras, por isso o gerador (upsert_batch, outra ligação) não
        consegue marcar superseded_by entre a verificação e o INSERT. O PRAGMA
        das chaves estrangeiras tem de correr antes do BEGIN (dentro de uma
        transação é ignorado); só é ligado nesta ligação (D-07)."""
        conn = self._connect()
        try:
            conn.execute("PRAGMA foreign_keys = ON")
            with conn:  # commit no sucesso, rollback na exceção
                conn.execute("BEGIN IMMEDIATE")
                yield conn
        finally:
            conn.close()

    @staticmethod
    def _has_decisions_table(conn: sqlite3.Connection) -> bool:
        return conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'vaccine_decisions'"
                            ).fetchone() is not None

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
        """Payload do motor + campos do store. Erros (JSON corrompido, não-dict,
        decisão registada inválida) propagam como ValueError; a rota mapeia-os
        para 503. `state` é derivado da decisão (D-09/D-11); a coluna `state` da
        tabela vaccines não é lida."""
        vaccine = json.loads(row["payload"])
        if not isinstance(vaccine, dict):
            raise ValueError("payload da vaccine nao e um objeto")
        vaccine["state"] = derive_state(row["d_decision"])
        vaccine["superseded_by"] = row["superseded_by"]
        vaccine["created_at"] = row["created_at"]
        vaccine["decision"] = (None if row["d_decision"] is None
                               else {field: row["d_" + field] for field in DECISION_FIELDS})
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
                # D-06: "a atual" de um ataque e sempre a ultima que o motor emitiu
                # (cobre partial <-> not_detected e o vaivem A-B-A). So superseded_by
                # muda; state nunca e tocado. Idempotente: sem mudanca, nao toca em linhas.
                conn.execute(
                    "UPDATE vaccines SET superseded_by = ? WHERE attack_id = ? AND id != ? "
                    "AND (superseded_by IS NULL OR superseded_by != ?)",
                    (v["id"], origin["attack_id"], v["id"], v["id"]))
                conn.execute("UPDATE vaccines SET superseded_by = NULL WHERE id = ? AND superseded_by IS NOT NULL",
                             (v["id"],))
        return counts

    def decide_vaccine(self, *, vaccine_id: str, decision: str, decided_by: str, decided_by_name: str,
                       reason: str | None, now_iso: str) -> dict:
        """Regista a decisão de um analista sobre uma vaccine (R12). Parâmetros só
        por nome (D-13); `now_iso` (UTC) vem do chamador. Verificação e escrita na
        mesma transação BEGIN IMMEDIATE (D-06): a vaccine existe, ainda não tem
        decisão e não foi substituída. Recusas e erros de SQLite fazem rollback
        (nada gravado) e propagam; nunca se converte uma exceção em texto. Só faz
        SELECT na tabela vaccines."""
        request = validate_request(vaccine_id=vaccine_id, decision=decision, decided_by=decided_by,
                                   decided_by_name=decided_by_name, reason=reason, now_iso=now_iso)
        if not os.path.exists(self.db_path):
            raise VaccineDecisionError("entry_not_found")
        with self.lock, self._tx_immediate() as conn:
            vaccine = conn.execute("SELECT superseded_by FROM vaccines WHERE id = ?",
                                   (request["vaccine_id"],)).fetchone()
            if vaccine is None:
                raise VaccineDecisionError("entry_not_found")
            decided = conn.execute("SELECT decision FROM vaccine_decisions WHERE vaccine_id = ?",
                                   (request["vaccine_id"],)).fetchone()
            current = derive_state(None if decided is None else decided["decision"])
            check_transition(current_state=current, decision=request["decision"],
                             superseded=vaccine["superseded_by"] is not None)
            conn.execute(_INSERT_DECISION, (
                request["vaccine_id"], request["decision"], request["decided_by"], request["decided_by_name"],
                request["decided_at"], request["reason"], current))
        record = {**request, "previous_state": current}
        return {key: record[key] for key in DECISION_RECORD_KEYS}

    # --- leitura (só-leitura, nunca cria o ficheiro) ---

    def list_vaccines(self, *, attack_id: int | None = None, technique: str | None = None,
                      include_superseded: bool = False, state: str | None = None, limit: int = 200,
                      offset: int = 0) -> tuple[list[dict], int, int]:
        """(linhas da página, total com os mesmos filtros, total de linhas do
        store sem filtros; este decide o `no_data` da rota). Parâmetros só por
        nome, de propósito: o bug de list_incidents foi um desalinhamento
        posicional. As cláusulas WHERE são fixas, escolhidas pelo código; os
        valores vão sempre por `?`, nunca interpolados. `state` filtra pelo
        estado derivado (proposed/approved/rejected; num ficheiro sem decisões
        tudo conta como proposed, D-10/D-11); o store não valida o valor: um
        valor desconhecido ou hostil vai por `?` e não casa com nada (a
        validação do parâmetro HTTP é da rota)."""
        clauses: list[str] = []
        params: list = []
        if attack_id is not None:
            clauses.append("v.attack_id = ?")
            params.append(attack_id)
        if technique is not None:
            clauses.append("v.mitre_technique = ?")
            params.append(technique)
        if not include_superseded:
            clauses.append("v.superseded_by IS NULL")
        with self._read() as conn:
            if conn is None:
                return [], 0, 0
            columns, source, state_expression = self._read_fragments(conn)
            if state is not None:
                clauses.append(state_expression + " = ?")
                params.append(state)
            where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
            store_total = conn.execute("SELECT COUNT(*) FROM vaccines").fetchone()[0]
            total = conn.execute("SELECT COUNT(*)" + source + where, params).fetchone()[0]
            rows = conn.execute(
                columns + source + where + " ORDER BY v.attack_id DESC, v.created_at DESC, v.id ASC LIMIT ? OFFSET ?",
                [*params, limit, offset]).fetchall()
            return [self._to_vaccine(r) for r in rows], total, store_total

    def get_vaccine(self, vaccine_id: str) -> dict | None:
        with self._read() as conn:
            if conn is None:
                return None
            columns, source, _ = self._read_fragments(conn)
            row = conn.execute(columns + source + " WHERE v.id = ?", (vaccine_id,)).fetchone()
            return self._to_vaccine(row) if row is not None else None

    def _read_fragments(self, conn: sqlite3.Connection) -> tuple[str, str, str]:
        """(colunas, FROM, expressão de estado) fixos, escolhidos juntos pela mesma
        verificação para não se desencontrarem: com LEFT JOIN a vaccine_decisions
        se a tabela existir; senão colunas NULL e estado literal 'proposed'
        (ficheiro do R11 = "sem decisões", D-10)."""
        if self._has_decisions_table(conn):
            return _COLUMNS_WITH_DECISIONS, _FROM_WITH_DECISIONS, _STATE_WITH_DECISIONS
        return _COLUMNS_WITHOUT_DECISIONS, _FROM_WITHOUT_DECISIONS, _STATE_WITHOUT_DECISIONS
