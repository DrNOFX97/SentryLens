"""
Regra de decisão das vaccines (R12, Phase 15). Módulo puro, como
vaccine_engine.py: sem I/O, sem SQLite, sem relógio, sem rede. Define a regra de
transição `proposed -> approved | rejected` (final: uma vaccine decidida nunca
volta atrás), os códigos de erro estáveis e a validação do pedido de decisão. O
store (vaccine_store.py) aplica-a dentro de uma transação.

"Aprovar não é aplicar": nenhuma função daqui aplica nada no Wazuh nem executa
comandos. Uma decisão é só "aceite" ou "recusada" pelo analista.

Os erros são sempre um código de um conjunto fechado (ERROR_CODES), nunca texto
de exceção. O autor só é validado no formato: que o analista existe e está ativo
é verificado pela rota (Phase 16), que tem acesso à Equipa SOC.
"""

import re
import unicodedata
from datetime import datetime, timedelta

INITIAL_STATE = "proposed"
DECISIONS = ("approved", "rejected")
DERIVED_STATES = ("proposed", "approved", "rejected")
TRANSITIONS = {"proposed": ("approved", "rejected"), "approved": (), "rejected": ()}

# Cópia própria (e não import de vaccine_engine, que arrastaria attack_registry e
# event_catalog para o store); o teste prova que é igual à do motor.
VACCINE_ID_RE = r"^vac-[0-9a-f]{12}$"
# Mesmo padrão de AnalystCreate.id em main.py (o teste prova que o literal lá está).
ANALYST_ID_RE = r"^analyst-[a-z0-9-]{1,64}$"
# Primeiro caracter letra ou dígito; resto letras/dígitos Unicode, espaço, ponto e hífen.
# Fora disto (incluindo < > & " ' e controlo) falha fechado.
ANALYST_NAME_RE = r"^[^\W_](?:[^\W_]|[ .\-])*$"
ANALYST_NAME_MAX_LENGTH = 128  # o max_length de AnalystCreate.name
REASON_MAX_LENGTH = 500
DECIDED_AT_MAX_LENGTH = 64
# Controlo, formatação (zero-width, overrides bidi), surrogates, uso privado,
# não atribuídos e separadores de linha/parágrafo: o motivo é uma linha de texto simples.
FORBIDDEN_REASON_CATEGORIES = ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp")

_VACCINE_ID = re.compile(VACCINE_ID_RE)
_ANALYST_ID = re.compile(ANALYST_ID_RE)
_ANALYST_NAME = re.compile(ANALYST_NAME_RE)

# Partição para a Phase 16 mapear para HTTP: 422 / 404 / 409.
INVALID_INPUT_CODES = ("invalid_vaccine_id", "invalid_decision", "invalid_author", "invalid_decided_at",
                       "reason_required", "invalid_reason")
NOT_FOUND_CODES = ("entry_not_found",)
CONFLICT_CODES = ("already_decided", "vaccine_superseded")
ERROR_CODES = INVALID_INPUT_CODES + NOT_FOUND_CODES + CONFLICT_CODES

# Bloco `decision` da leitura (D-11), campos do pedido e campos do registo devolvido.
DECISION_FIELDS = ("decided_by", "decided_by_name", "decided_at", "reason")
REQUEST_KEYS = ("vaccine_id", "decision", "decided_by", "decided_by_name", "decided_at", "reason")
DECISION_RECORD_KEYS = REQUEST_KEYS + ("previous_state",)


class VaccineDecisionError(Exception):
    """Recusa de uma decisão, identificada só por um código de ERROR_CODES.

    Não deriva de ValueError, de propósito: as rotas GET mapeiam ValueError
    (payload corrompido) para 503 store_unavailable, e uma recusa de decisão
    nunca deve cair aí. str(erro) é só o código."""

    def __init__(self, code: str) -> None:
        if code not in ERROR_CODES:
            raise ValueError("codigo de erro desconhecido")
        super().__init__(code)
        self.code = code


def derive_state(decision: str | None) -> str:
    """Estado atual a partir da decisão registada (ou None). Um valor fora de
    DECISIONS é uma linha corrompida: ValueError (a rota mapeia para 503)."""
    if decision is None:
        return INITIAL_STATE
    if decision in DECISIONS:
        return decision
    raise ValueError("decisao registada invalida")


def check_transition(*, current_state: str, decision: str, superseded: bool) -> str:
    """Estado novo se a transição é permitida; senão VaccineDecisionError.
    Uma vaccine já decidida e entretanto substituída responde already_decided
    (o estado é final antes de ser "antigo")."""
    if decision not in DECISIONS:
        raise VaccineDecisionError("invalid_decision")
    if current_state not in TRANSITIONS:
        raise ValueError("estado atual desconhecido")
    if decision not in TRANSITIONS[current_state]:
        raise VaccineDecisionError("already_decided")
    if superseded:
        raise VaccineDecisionError("vaccine_superseded")
    return decision


def validate_request(*, vaccine_id, decision, decided_by, decided_by_name, reason, now_iso) -> dict:
    """Valida o pedido de decisão e devolve um dict com exatamente REQUEST_KEYS.
    Tracer: valida a decisão e o motivo; as restantes validações, por ordem fixa,
    entram a seguir."""
    if not isinstance(decision, str) or decision not in DECISIONS:
        raise VaccineDecisionError("invalid_decision")
    if reason is not None:
        if not isinstance(reason, str):
            raise VaccineDecisionError("invalid_reason")
        reason = reason.strip() or None
    if reason is None and decision == "rejected":
        raise VaccineDecisionError("reason_required")
    return {"vaccine_id": vaccine_id, "decision": decision, "decided_by": decided_by,
            "decided_by_name": decided_by_name, "decided_at": now_iso, "reason": reason}
