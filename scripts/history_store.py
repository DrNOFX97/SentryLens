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

# Teto de entradas devolvidas por read_network_detection_history (R6),
# capeado aqui (não só no parâmetro HTTP de main.py) — um pedido nunca
# consegue fazer este módulo carregar/devolver uma quantidade arbitrária
# de linhas do ficheiro.
NETWORK_EVIDENCE_MAX_LIMIT = 500


def history_file_path(base_dir: str, date_str: str, kind: str = "alerts", create: bool = True) -> str:
    """
    date_str: "AAAA-MM-DD". Devolve o path completo do ficheiro JSONL do
    dia. Com create=True (default, usado pelas funções de escrita), cria
    as pastas ano/mês se ainda não existirem; create=False (leitura, ver
    read_network_detection_history) não cria nada só por se consultar um
    dia sem dados.
    """
    year, month, _day = date_str.split("-")
    month_name = _MESES_PT[int(month)]
    folder = os.path.join(base_dir, year, f"{month}-{month_name}")
    if create:
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


def append_network_detection_history(detection: dict, base_dir: str) -> tuple[str, int]:
    """
    Regista uma linha JSONL por deteção de rede (ver
    network_detections.detect_network_anomalies) em
    <base_dir>/AAAA/MM-mês/AAAA-MM-DD-network-detections.jsonl,
    append-only — mesmo padrão de append_alert_history. Resolve a dívida
    registada em docs/ROADMAP_STATUS.md (R0): "deteções de rede só existem
    em memória, perdem-se no restart" (R6). "date"/"time" vêm do campo
    "timestamp" da própria deteção (reaproveita _alert_datetime, que só
    lê esse campo, não é específico de alertas), não do momento em que é
    persistida — fica cronologicamente correto mesmo com o callback a
    correr com atraso. É metadados só (tipo/origem/destino/detalhe) —
    nunca payload, nunca um dump PCAP real (ver network_soc.py).

    Devolve (path, offset), mesmo propósito de append_alert_history.
    """
    dt = _alert_datetime(detection)
    date_str = dt.strftime("%Y-%m-%d")
    time_str = dt.strftime("%H:%M:%S")

    record = {
        "date": date_str,
        "time": time_str,
        "type": detection.get("type"),
        "src_ip": detection.get("src_ip"),
        "dst_ip": detection.get("dst_ip"),
        "detail": detection.get("detail"),
    }

    path = history_file_path(base_dir, date_str, "network-detections")
    with open(path, "a", encoding="utf-8") as f:
        offset = f.tell()
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return path, offset


def append_network_detections_history(detections: list[dict], base_dir: str) -> None:
    """Aplica append_network_detection_history a cada deteção — é isto que
    main.py passa (a par de incident_ingest.ingest_network_detections) ao
    callback on_new_detections de network_poll_loop."""
    for detection in detections:
        append_network_detection_history(detection, base_dir)


def read_network_detection_history(base_dir: str, date_str: str | None = None, limit: int = 100) -> list[dict]:
    """
    Lê o ficheiro JSONL de deteções de rede persistidas de um dia (ver
    append_network_detection_history) — a "evidência" do painel PCAP/
    Evidence (R6), sempre só metadados, nunca payload/PCAP real.

    date_str: "AAAA-MM-DD"; None -> hoje (UTC). Devolve as últimas `limit`
    entradas (mais recente primeiro). `limit` é sempre capeado a
    NETWORK_EVIDENCE_MAX_LIMIT (o parâmetro HTTP em main.py já valida isto,
    mas este módulo nunca confia só no chamador). Ficheiro ausente, dia
    inválido, ou linha malformada -> [] / linha ignorada (nunca lança).
    """
    limit = max(1, min(limit, NETWORK_EVIDENCE_MAX_LIMIT))
    if date_str is None:
        date_str = datetime.utcnow().strftime("%Y-%m-%d")
    try:
        datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        return []

    path = history_file_path(base_dir, date_str, "network-detections", create=False)
    if not os.path.exists(path):
        return []

    records: list[dict] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        return []

    records.reverse()
    return records[:limit]
