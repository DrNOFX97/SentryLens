"""
Liga o motor de vaccines ao store (Phase 13, VAC-05). Partes puras e
testáveis, sem acesso ao Wazuh: quem busca o registo e os alertas é
main._run_vaccine_cycle. Nunca grava o que não foi validado por
vaccine_engine.validate_vaccine, nem o que ainda não teve tempo de ser
detetado (A2: um ataque avaliado segundos depois de lançado sai not_detected
só porque os alertas ainda não chegaram, e a vaccine falsa ficaria para
sempre, D-07).
"""

import logging
import threading
from datetime import timedelta

from attack_registry import normalize_attack_id
from redblue_correlator import DEFAULT_WINDOW_SECONDS
from vaccine_engine import validate_vaccine

logger = logging.getLogger("sentrylens.vaccines")

DEFAULT_WINDOW_HOURS = 168  # A4: igual a /api/attacks
DEFAULT_SETTLE_SECONDS = 600  # A2: 2x a janela de correlação (300 s); valor não medido
MIN_SETTLE_SECONDS = DEFAULT_WINDOW_SECONDS
MAX_SETTLE_SECONDS = 86400
COUNT_KEYS = ("inserted", "existing", "rejected", "pending_settle", "outside_window")

DEFAULT_INTERVAL_SECONDS = 300  # D-02: um ciclo a cada 5 min
MIN_INTERVAL_SECONDS = 30  # evita um ciclo apertado por configuração errada
MAX_INTERVAL_SECONDS = 86400
GENERATOR_STATUSES = ("never_run", "ok", "no_data", "error")
GENERATOR_ERROR_CODES = (
    "indexer_unavailable", "ml_model_unavailable", "attack_outside_alert_window", "source_unavailable",
    "attack_log_unreadable", "incidents_unavailable", "store_unavailable", "unexpected_error",
)
GENERATOR_KEYS = frozenset({"status", "error_code", "last_run_at", "last_success_at", "alerts_truncated", "counts"})


def env_int(environ, name: str, default: int, minimum: int, maximum: int) -> int:
    """Inteiro de uma variável de ambiente. Ausente, vazio, não inteiro ou fora
    de [minimum, maximum] -> default com aviso. Nunca levanta nem derruba o arranque."""
    raw = environ.get(name)
    if raw is None or str(raw).strip() == "":
        return default
    try:
        value = int(str(raw).strip())
    except ValueError:
        logger.warning("%s invalida, a usar %s", name, default)
        return default
    if value < minimum or value > maximum:
        logger.warning("%s fora de [%s, %s], a usar %s", name, minimum, maximum, default)
        return default
    return value


def select_attack_ids(attacks, now, window_hours: int, settle_seconds: int, parse) -> dict:
    """Separa os ids de ataque do registo por idade. `settled`: dentro da janela
    e já mais velhos que settle_seconds; `pending_settle`: mais novos que isso.
    Mais antigos que a janela (ou sem id/timestamp válidos) ficam em nenhum.
    O registo é construído sobre o log inteiro (P1) e o corte aplica-se aqui."""
    settled: set[int] = set()
    pending: set[int] = set()
    settle_edge = now - timedelta(seconds=settle_seconds)
    window_edge = now - timedelta(hours=window_hours)
    for attack in attacks if isinstance(attacks, list) else []:
        if not isinstance(attack, dict):
            continue
        attack_id = normalize_attack_id(attack.get("id"))
        stamp = parse(attack.get("timestamp"))
        if attack_id is None or stamp is None:
            continue
        if stamp > settle_edge:
            pending.add(attack_id)
        elif stamp >= window_edge:
            settled.add(attack_id)
    return {"settled": settled, "pending_settle": pending}


def persist_vaccines(store, vaccines, attack_ids: dict, now_iso: str) -> dict:
    """Valida cada vaccine, separa as de ataques assentes e grava-as numa só
    transação. Devolve exatamente COUNT_KEYS."""
    counts = dict.fromkeys(COUNT_KEYS, 0)
    accepted: list[dict] = []
    settled = attack_ids.get("settled", set())
    pending = attack_ids.get("pending_settle", set())
    for vaccine in vaccines:
        problems = validate_vaccine(vaccine)
        if problems:
            counts["rejected"] += 1
            logger.warning("Vaccine rejeitada pela validacao: %s", ",".join(problems))
            continue
        attack_id = vaccine["origin"]["attack_id"]
        if attack_id in settled:
            accepted.append(vaccine)
        elif attack_id in pending:
            counts["pending_settle"] += 1
        else:
            counts["outside_window"] += 1
    if accepted:
        written = store.upsert_batch(accepted, now_iso)
        counts["inserted"] = written["inserted"]
        counts["existing"] = written["existing"]
    return counts


class VaccineLoopState:
    """Estado da última execução do ciclo, em memória (A5). Só guarda códigos
    estáveis: nunca texto de exceção, traceback ou caminho (D-03)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._state = self._initial()

    @staticmethod
    def _initial() -> dict:
        return {"status": "never_run", "error_code": None, "last_run_at": None,
                "last_success_at": None, "alerts_truncated": None, "counts": None}

    def record(self, now_iso, status, error_code=None, counts=None, alerts_truncated=None) -> None:
        if status not in ("ok", "no_data", "error"):
            status, error_code = "error", "unexpected_error"
        with self._lock:
            state = self._state
            state["last_run_at"] = now_iso
            if status == "error":
                state["status"] = "error"
                state["error_code"] = error_code if error_code in GENERATOR_ERROR_CODES else "unexpected_error"
                state["counts"] = None
            else:
                state["status"] = status
                state["error_code"] = None
                state["last_success_at"] = now_iso
                state["counts"] = ({k: counts.get(k) for k in COUNT_KEYS} if isinstance(counts, dict) else None)
            state["alerts_truncated"] = alerts_truncated if isinstance(alerts_truncated, bool) else None

    def snapshot(self) -> dict:
        with self._lock:
            copy = dict(self._state)
            copy["counts"] = dict(copy["counts"]) if copy["counts"] is not None else None
            return copy
