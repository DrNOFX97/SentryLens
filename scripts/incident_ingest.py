"""
Orquestração do ingest de incidentes (R3): liga as evidências normalizadas
(incident_engine, puro) à persistência (incident_store). Chamado em tempo
real pelos pollers de alertas e de rede (callbacks opcionais) e pelo backfill
manual (POST /api/incidents/backfill).

Todas as sequências "ler abertos -> decidir -> gravar" correm dentro de
store.lock, para o ingest (thread de executor) e o backfill (thread da API)
nunca duplicarem incidentes nem evidências.
"""

import logging
from datetime import datetime, timezone

import ml_anomalies
from feature_extractor import load_attack_log
from incident_engine import (
    assign_evidence,
    attack_link_data,
    compute_windows,
    evidence_from_network_detection,
    evidence_from_raw_alert,
    link_attacks,
    parse_timestamp,
)

logger = logging.getLogger("sentrylens.incidents")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ingest_evidences(store, evidences: list[dict], attack_log: list[dict], scenarios: dict,
                     now_iso: str | None = None) -> dict:
    """Processa evidências já normalizadas, por ordem de tempo (o resultado não
    depende da ordem de chegada). Devolve contagens opened/attached/duplicate/ignored."""
    now = now_iso or _now_iso()
    windows = compute_windows(attack_log, scenarios)
    counts = {"opened": 0, "attached": 0, "duplicate": 0, "ignored": 0}

    with store.lock:
        for evidence in sorted(evidences, key=lambda e: parse_timestamp(e["ts"])):
            decision = assign_evidence(
                evidence,
                store.list_open_incidents(evidence["asset"]),
                already_known=store.evidence_exists(evidence["key"]),
            )
            action = decision["action"]
            if action == "duplicate":
                counts["duplicate"] += 1
                continue
            if action == "ignore":
                counts["ignored"] += 1
                continue
            if action == "open":
                incident_id = store.create_incident(evidence, now)
                counts["opened"] += 1
            else:
                incident_id = decision["incident_id"]
                store.attach_evidence(incident_id, evidence, now)
                counts["attached"] += 1
            for entry in link_attacks(evidence["ts"], evidence["asset"], windows):
                store.link_attack(incident_id, attack_link_data(entry, scenarios), now)
    return counts


def _ingest(store, evidences: list[dict], invalid: int, attack_log_path: str, scenarios: dict,
            now_iso: str | None) -> dict:
    counts = ingest_evidences(store, evidences, load_attack_log(attack_log_path), scenarios, now_iso)
    counts["invalid"] = invalid
    return counts


def ingest_raw_alerts(store, raw_alerts: list, attack_log_path: str, scenarios: dict,
                      now_iso: str | None = None) -> dict:
    """Alertas brutos do Indexer (com _id). Alertas malformados contam em
    "invalid" e nunca lançam."""
    evidences, invalid = [], 0
    for raw in raw_alerts or []:
        evidence = evidence_from_raw_alert(raw)
        if evidence is None:
            invalid += 1
        else:
            evidences.append(evidence)
    return _ingest(store, evidences, invalid, attack_log_path, scenarios, now_iso)


def ingest_network_detections(store, detections: list, attack_log_path: str, scenarios: dict,
                              now_iso: str | None = None) -> dict:
    evidences, invalid = [], 0
    for det in detections or []:
        evidence = evidence_from_network_detection(det)
        if evidence is None:
            invalid += 1
        else:
            evidences.append(evidence)
    return _ingest(store, evidences, invalid, attack_log_path, scenarios, now_iso)


def ml_summary(raw_alerts: list[dict], model_dir: str) -> dict | None:
    """Resumo de ML ao nível do incidente, calculado sobre os alertas brutos do
    próprio incidente (a janela certa para as features, que dependem dos alertas
    à volta). None se não houver alertas ou se o modelo não existir/falhar —
    o incidente funciona sem ML."""
    if not raw_alerts:
        return None
    try:
        model, scaler = ml_anomalies.load_model(model_dir)
        report = ml_anomalies.build_ml_anomalies_report(raw_alerts, model, scaler)
    except FileNotFoundError:
        return None
    except Exception:
        logger.exception("Falha ao calcular o resumo de ML do incidente")
        return None
    return {"scored": report["total"], "ml_anomalies": report["ml_anomalies_count"],
            "rule_flagged": report["rule_flagged_count"]}
