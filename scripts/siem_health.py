"""
Saúde do SIEM (Roadmap v2, R2): função pura que transforma o que o Manager e o
Indexer devolveram (ou o erro de cada um) num relatório pronto para o painel
Live SOC. Sem I/O: main.py faz as chamadas e passa os resultados.

Nunca inventa números: componente em baixo -> campos dependentes a None.
"""

from datetime import datetime, timezone

WINDOW_MINUTES = 5
ALERTS_FETCH_SIZE = 500
STALE_AFTER_SECONDS = 300


def parse_wazuh_timestamp(value) -> datetime | None:
    """'2026-10-07T09:12:34.123+0000' / '...Z' / ISO -> datetime UTC (ou None)."""
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    elif len(text) > 5 and text[-5] in "+-" and text[-4:].isdigit():
        text = text[:-2] + ":" + text[-2:]
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _agents_block(summary: dict) -> dict:
    # /agents/summary/status devolve {"connection": {...}} em Wazuh 4.x;
    # aceita também o formato plano.
    source = summary.get("connection", summary) if isinstance(summary, dict) else {}
    keys = ("active", "disconnected", "never_connected", "pending")
    block = {k: int(source.get(k, 0) or 0) for k in keys}
    block["total"] = int(source.get("total", sum(block.values())) or 0)
    return block


def build_siem_health_report(
    agents_summary: dict | None,
    manager_error: str | None,
    alerts: list[dict] | None,
    indexer_error: str | None,
    now: datetime | None = None,
    window_minutes: int = WINDOW_MINUTES,
    fetch_size: int = ALERTS_FETCH_SIZE,
) -> dict:
    """
    agents_summary/manager_error: resultado do Manager OU um código de erro
    estável (ex. "timeout", "unreachable") — nunca texto cru de exceção, que
    pode revelar host/URL/portas.
    alerts/indexer_error: alertas crus recentes do Indexer (os `fetch_size`
    MAIS RECENTES, ordenados desc) OU o código de erro.

    Campos agregados: `status` ok|degraded|down (HTTP 200 não significa
    saudável); `stale` = Indexer ok mas sem alerta há mais de
    STALE_AFTER_SECONDS (ou nenhum na última hora) -> degraded; `truncated` =
    o Indexer devolveu o limite pedido, logo a taxa é um mínimo (>=).
    """
    now = now or datetime.now(timezone.utc)
    manager_ok = manager_error is None and agents_summary is not None
    indexer_ok = indexer_error is None and alerts is not None

    manager = {"status": "ok"} if manager_ok else {"status": "unavailable", "error": manager_error}
    indexer = {"status": "ok"} if indexer_ok else {"status": "unavailable", "error": indexer_error}

    last_alert_at = None
    lag = None
    per_minute = None
    in_window = None
    truncated = False
    stale = False
    if indexer_ok:
        truncated = len(alerts) >= fetch_size
        stamps = [t for t in (parse_wazuh_timestamp(a.get("@timestamp")) for a in alerts) if t]
        if stamps:
            newest = max(stamps)
            last_alert_at = newest.isoformat()
            lag = max(0.0, (now - newest).total_seconds())
        in_window = sum(1 for t in stamps if 0 <= (now - t).total_seconds() <= window_minutes * 60)
        per_minute = round(in_window / window_minutes, 2)
        stale = lag is None or lag > STALE_AFTER_SECONDS

    if not manager_ok and not indexer_ok:
        status = "down"
    elif not manager_ok or not indexer_ok or stale:
        status = "degraded"
    else:
        status = "ok"

    return {
        "generated_at": now.isoformat(),
        "status": status,
        "stale": stale,
        "truncated": truncated,
        "manager": manager,
        "indexer": indexer,
        "agents": _agents_block(agents_summary) if manager_ok else None,
        "last_alert_at": last_alert_at,
        "ingestion_lag_seconds": lag,
        "alerts_per_minute": per_minute,
        "alerts_in_window": in_window,
        "window_minutes": window_minutes,
    }
