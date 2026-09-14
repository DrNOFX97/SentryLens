"""
Persistência própria de histórico de alertas, para além dos 90 dias que o
Wazuh Indexer guarda (política de retenção do OpenSearch). Estrutura de
pastas: <base_dir>/AAAA/MM-mês/AAAA-MM-DD-alerts.jsonl — um ficheiro por
dia, formato JSONL append-only (um alerta por linha, nunca sobrescreve).

Não confundir com scripts/export_snapshot.py (snapshots de treino de ML da
Fase 6, mecanismo separado e já existente) — este módulo é para retenção
de longo prazo / auditoria, um registo simplificado por alerta, não a
feature completa usada para treino.
"""

import json
import os
from datetime import datetime

_MESES_PT = {
    1: "janeiro", 2: "fevereiro", 3: "março", 4: "abril", 5: "maio", 6: "junho",
    7: "julho", 8: "agosto", 9: "setembro", 10: "outubro", 11: "novembro", 12: "dezembro",
}


def history_file_path(base_dir: str, date_str: str, kind: str = "alerts") -> str:
    """
    date_str: "AAAA-MM-DD". Devolve o path completo do ficheiro JSONL do
    dia, criando as pastas ano/mês se ainda não existirem.
    """
    year, month, _day = date_str.split("-")
    month_name = _MESES_PT[int(month)]
    folder = os.path.join(base_dir, year, f"{month}-{month_name}")
    os.makedirs(folder, exist_ok=True)
    return os.path.join(folder, f"{date_str}-{kind}.jsonl")


def _alert_datetime(alert: dict) -> datetime:
    """
    Extrai data/hora do campo "timestamp" do alerta (ISO-8601, ex:
    "2026-09-13T14:32:07Z"). Sem timestamp válido, usa o momento atual
    (UTC) em vez de descartar o alerta silenciosamente.
    """
    ts = alert.get("timestamp")
    if ts:
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            pass
    return datetime.utcnow()


def append_alert_history(alert: dict, base_dir: str) -> tuple[str, int]:
    """
    Regista uma linha JSONL para este alerta (já enriquecido, mesma forma
    de um item de /api/alerts — ver _enrich_alert em main.py). "date" é
    sempre o primeiro campo do objeto (para o ficheiro ordenar bem
    cronologicamente mesmo aberto num editor de texto ou exportado).

    Devolve (path, offset) — o ficheiro e o offset em bytes onde a linha
    começa, usados por history_index.py para apontar o índice SQLite para
    o registo completo sem re-parsear o ficheiro inteiro (ver
    read_jsonl_at_offset).
    """
    dt = _alert_datetime(alert)
    date_str = dt.strftime("%Y-%m-%d")
    time_str = dt.strftime("%H:%M:%S")

    record = {
        "date": date_str,
        "time": time_str,
        "event_id": alert.get("windows_event_id"),
        "severity": alert.get("severity"),
        "friendly_name": alert.get("friendly_name"),
        "agent_name": alert.get("agent_name"),
        "rule_id": alert.get("rule_id"),
    }

    path = history_file_path(base_dir, date_str, "alerts")
    with open(path, "a", encoding="utf-8") as f:
        offset = f.tell()
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return path, offset


def append_alerts_history(alerts: list[dict], base_dir: str) -> None:
    """Aplica append_alert_history a cada alerta — é isto que main.py passa como on_new_alerts ao alert_poll_loop."""
    for alert in alerts:
        append_alert_history(alert, base_dir)


def append_compliance_history(alert: dict, compliance_result: dict, base_dir: str) -> tuple[str, int]:
    """
    Regista uma linha JSONL em <base_dir>/AAAA/MM-mês/AAAA-MM-DD-compliance.jsonl
    com o veredito de conformidade deste alerta (ver
    compliance_evaluator.evaluate_alert_compliance para a forma de
    compliance_result) — registo de auditoria persistido mesmo quando o
    veredito é "verificado_e_nao_aplicavel" em todas as normas; a
    verificação em si nunca é omitida em silêncio.

    Devolve (path, offset), mesmo propósito de append_alert_history.
    """
    dt = _alert_datetime(alert)
    date_str = dt.strftime("%Y-%m-%d")
    time_str = dt.strftime("%H:%M:%S")

    record = {
        "date": date_str,
        "time": time_str,
        "event_id": alert.get("windows_event_id"),
        "rgpd_estado": compliance_result.get("rgpd", {}).get("estado"),
        "nis2_estado": compliance_result.get("nis2", {}).get("estado"),
        "ai_act_estado": compliance_result.get("ai_act", {}).get("estado"),
    }

    path = history_file_path(base_dir, date_str, "compliance")
    with open(path, "a", encoding="utf-8") as f:
        offset = f.tell()
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return path, offset
