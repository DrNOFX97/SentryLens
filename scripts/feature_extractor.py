"""
Extração de features para o painel de deteção de anomalias por ML
(Fase 6). MÓDULO ÚNICO E PARTILHADO entre treino (train_anomaly_model.py)
e inferência (ml_anomalies.py, via main.py) — a lógica de extração NÃO
pode divergir entre os dois caminhos, por isso ambos importam só daqui.

Não faz I/O de rede nem sabe nada de Wazuh HTTP — recebe sempre uma
lista de alertas já obtida (mesmo formato devolvido pelo Wazuh Indexer,
ver wazuh_client.WazuhIndexerClient.get_recent_alerts) e devolve
estruturas Python simples.

As 7 features, na ordem definida pelo contrato da Fase 6:
    1. hour_of_day               - hora do evento (0-23)
    2. day_of_week                - dia da semana (0=segunda ... 6=domingo)
    3. event_id_encoded            - Event ID codificado (posição ordinal
                                      entre os Event IDs conhecidos em
                                      event_catalog.CRITICAL_EVENTS;
                                      desconhecidos ficam no último bucket)
    4. failed_attempts_last_hour  - nº de falhas de logon (4625) do mesmo
                                      utilizador na hora anterior a este
                                      evento, incluindo-o a ele próprio se
                                      for também uma falha
    5. has_special_privileges     - 1 se a categoria do evento (segundo
                                      event_catalog) for "atividade_privilegiada"
    6. is_new_source_ip           - 1 se é a primeira vez que se vê este IP
                                      de origem para este utilizador
    7. severity_encoded            - severidade do event_catalog, ordinal
                                      (info=0, low=1, medium=2, high=3)

`is_attack` (rótulo verdadeiro, só para treino/avaliação) não faz parte
do vetor de features — é atribuído à parte por label_with_attack_log(),
por correspondência de timestamp com o log do attack_scenarios.py.
"""

import json
from datetime import datetime, timedelta, timezone

from event_catalog import CRITICAL_EVENTS, classify_alert

FEATURE_NAMES: list[str] = [
    "hour_of_day",
    "day_of_week",
    "event_id_encoded",
    "failed_attempts_last_hour",
    "has_special_privileges",
    "is_new_source_ip",
    "severity_encoded",
]

_EVENT_ID_ORDER: list[int] = sorted(CRITICAL_EVENTS.keys())
_EVENT_ID_INDEX: dict[int, int] = {eid: idx for idx, eid in enumerate(_EVENT_ID_ORDER)}
_UNKNOWN_EVENT_ID_BUCKET = len(_EVENT_ID_ORDER)

_SEVERITY_ORDER: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3}

FAILED_LOGON_EVENT_ID = 4625
FAILED_ATTEMPTS_WINDOW = timedelta(hours=1)


def _parse_timestamp(raw_timestamp: str | None) -> datetime | None:
    """Mesma convenção usada em lifecycle.py/admin_activity.py: aceita o
    sufixo 'Z', assume UTC quando não há fuso indicado, devolve None em
    vez de lançar exceção para timestamps malformados."""
    if not raw_timestamp or not isinstance(raw_timestamp, str):
        return None
    normalized = raw_timestamp.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _extract_event_id(alert: dict) -> int | None:
    try:
        raw = alert.get("data", {}).get("win", {}).get("system", {}).get("eventID")
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def _extract_target_user(alert: dict) -> str:
    return alert.get("data", {}).get("win", {}).get("eventdata", {}).get("targetUserName", "Unknown")


def _extract_source_ip(alert: dict) -> str:
    eventdata = alert.get("data", {}).get("win", {}).get("eventdata", {})
    return eventdata.get("ipAddress") or alert.get("agent", {}).get("ip", "-")


def _encode_event_id(event_id: int | None) -> int:
    if event_id is None or event_id not in _EVENT_ID_INDEX:
        return _UNKNOWN_EVENT_ID_BUCKET
    return _EVENT_ID_INDEX[event_id]


def extract_features(alerts: list[dict]) -> list[dict]:
    """Processa `alerts` em ordem cronológica e devolve uma lista de
    dicts de features (uma por alerta com timestamp e Event ID válidos;
    alertas sem qualquer um dos dois são ignorados, como no resto da
    stack). A ordem devolvida é a ordem cronológica, não a ordem de
    entrada.
    """
    parsed = []
    for alert in alerts:
        ts = _parse_timestamp(alert.get("@timestamp"))
        event_id = _extract_event_id(alert)
        if ts is None or event_id is None:
            continue
        parsed.append((ts, event_id, alert))
    parsed.sort(key=lambda item: item[0])

    failed_attempts_by_user: dict[str, list[datetime]] = {}
    seen_ips_by_user: dict[str, set[str]] = {}
    rows: list[dict] = []

    for ts, event_id, alert in parsed:
        user = _extract_target_user(alert)
        ip = _extract_source_ip(alert)
        classification = classify_alert(event_id)

        if event_id == FAILED_LOGON_EVENT_ID:
            failed_attempts_by_user.setdefault(user, []).append(ts)
        window_start = ts - FAILED_ATTEMPTS_WINDOW
        recent_failures = [t for t in failed_attempts_by_user.get(user, []) if window_start <= t <= ts]

        ip_set = seen_ips_by_user.setdefault(user, set())
        is_new_ip = ip not in ip_set
        ip_set.add(ip)

        rows.append({
            "timestamp": ts.isoformat(),
            "windows_event_id": event_id,
            "target_user": user,
            "source_ip": ip,
            "agent_name": alert.get("agent", {}).get("name", "Unknown"),
            "severity": classification["severity"],
            "rule_flagged": classification["severity"] == "high",
            "hour_of_day": ts.hour,
            "day_of_week": ts.weekday(),
            "event_id_encoded": _encode_event_id(event_id),
            "failed_attempts_last_hour": len(recent_failures),
            "has_special_privileges": 1 if classification["category"] == "atividade_privilegiada" else 0,
            "is_new_source_ip": 1 if is_new_ip else 0,
            "severity_encoded": _SEVERITY_ORDER.get(classification["severity"], 0),
        })

    return rows


def load_attack_log(path: str) -> list[dict]:
    """Lê o log JSONL do attack_scenarios.py. Ficheiro ausente/vazio
    devolve lista vazia em vez de lançar exceção (nem sempre há um
    ataque registado ao correr o pipeline)."""
    entries: list[dict] = []
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
    except FileNotFoundError:
        return []
    return entries


def label_with_attack_log(features: list[dict], attack_log: list[dict], window_seconds: int = 120) -> list[dict]:
    """Atribui is_attack (0/1) a cada linha de features por correspondência
    de timestamp: um evento é rotulado 1 se o seu timestamp cai dentro de
    [ataque.timestamp, ataque.timestamp + window_seconds] para qualquer
    entrada do log de ataques. Devolve uma NOVA lista (não modifica
    `features` in-place)."""
    windows = []
    for entry in attack_log:
        start = _parse_timestamp(entry.get("timestamp"))
        if start is None:
            continue
        windows.append((start, start + timedelta(seconds=window_seconds)))

    labeled = []
    for row in features:
        row_ts = _parse_timestamp(row["timestamp"])
        is_attack = any(start <= row_ts <= end for start, end in windows) if row_ts else False
        labeled.append({**row, "is_attack": 1 if is_attack else 0})
    return labeled


def vectorize(features: list[dict]) -> list[list[float]]:
    """Converte cada linha de features num vetor numérico, na ordem de
    FEATURE_NAMES — esta é a única função que o modelo/scaler devem ver."""
    return [[float(row[name]) for name in FEATURE_NAMES] for row in features]
