"""
Dashboard de Cibersegurança — Backend FastAPI
Fase 2 do projeto CET — consome as APIs do Wazuh e serve dados prontos
para o frontend HTML/CSS.

Correr localmente:
    uvicorn main:app --reload --port 8001

Nota: a porta 8000 está ocupada neste PC pelo serviço Windows
"IBXDashboard" (httpd.exe/Apache), por isso 8001 é o default do projeto.

Depois abrir frontend/index.html no browser (ou servir via qualquer
servidor estático simples).
"""

import asyncio
import json
import logging
import os
import secrets
import sqlite3
import sys
from collections import Counter, deque
from datetime import datetime, timedelta, timezone
from typing import Annotated, Literal

# Windows redirects stdout/stderr para o codepage da consola por omissão,
# o que corrompe os acentos nos logs (ex: "Violações" -> "Viola��es") quando
# a saída é redirecionada para ficheiro. Forçamos UTF-8 explicitamente.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")

import httpx
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Path, Query, Response, WebSocket, WebSocketDisconnect
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, StringConstraints

import incident_ingest
import ml_anomalies
from admin_activity import build_admin_activity_report
from attack_registry import build_attack_registry, summarize as summarize_attacks
from attack_scenarios import SCENARIOS
from compliance_evaluator import evaluate_alert_compliance, load_compliance_rules
from event_catalog import classify_alert
from feature_extractor import load_attack_log
from history_index import index_alert, query_history_index, read_jsonl_at_offset
from history_store import append_alert_history, append_compliance_history
from incident_engine import available_transitions, parse_timestamp as incident_engine_parse
from incident_store import IncidentNotFound, IncidentStore, InvalidTransition
from lifecycle import build_lifecycle_report
from network_detections import detect_network_anomalies
from network_monitor import NetworkConnectionManager, PACKET_BUFFER_MAX, network_poll_loop
from nis2_lookup import lookup_nis2_classification
from org_profile import get_org_profile
from rbac import build_privileges_report, load_rbac_baseline
from redblue_correlator import build_redblue_report
from report_generator import generate_html_report, render_compliance_section
from siem_health import ALERTS_FETCH_SIZE, build_siem_health_report
from ssh_client import VMSSHClient
from system_monitor import (
    THRESHOLDS,
    check_thresholds,
    get_history,
    get_last_network_speed,
    get_specs,
    get_usage_history,
    measure_network_speed,
    record_usage_sample,
)
from wazuh_client import WazuhIndexerClient, WazuhManagerClient
from websocket_alerts import ConnectionManager, alert_poll_loop

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("sentrylens.system_monitor")

LOCAL_CHECK_INTERVAL_SECONDS = 30
NETWORK_CHECK_INTERVAL_SECONDS = 20 * 60

WAZUH_MANAGER_URL = os.getenv("WAZUH_MANAGER_URL", "https://localhost:55000")
WAZUH_MANAGER_USER = os.getenv("WAZUH_MANAGER_USER", "wazuh-wui")
WAZUH_MANAGER_PASSWORD = os.getenv("WAZUH_MANAGER_PASSWORD", "")

WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200")
WAZUH_INDEXER_USER = os.getenv("WAZUH_INDEXER_USER", "admin")
WAZUH_INDEXER_PASSWORD = os.getenv("WAZUH_INDEXER_PASSWORD", "")

# O lab usa o certificado autoassinado gerado pelo wazuh-install.sh, por isso
# a verificação TLS fica desligada por omissão (False). Se apontares para um
# Wazuh com certificado válido/CA confiável, define WAZUH_VERIFY_SSL=true.
WAZUH_VERIFY_SSL = os.getenv("WAZUH_VERIFY_SSL", "false").strip().lower() in ("1", "true", "yes")

# Caminho do ficheiro de baseline RBAC (cargos -> grupos permitidos/proibidos)
# usado pelo endpoint /api/privileges. Ver rbac.py para o schema esperado.
RBAC_BASELINE_PATH = os.getenv(
    "RBAC_BASELINE_PATH",
    os.path.join(os.path.dirname(__file__), "rbac_baseline.example.json"),
)

# Diretório com isolation_forest.pkl + scaler.pkl (ver train_anomaly_model.py),
# usado pelo endpoint /api/ml-anomalies.
ML_MODEL_DIR = os.getenv("ML_MODEL_DIR", os.path.join(os.path.dirname(__file__), "models"))

# Caminho do log de ataques da VM Kali (ver attack_scenarios.py), usado
# pelo endpoint /api/redblue/metrics (Fase 11).
ATTACK_LOG_PATH = os.getenv("ATTACK_LOG_PATH", os.path.join(os.path.dirname(__file__), "attack_log.jsonl"))

# SSH para a VM Wazuh (Fase 11, Onda 2) — só usado pela captura de rede via
# tshark. Funcionalidade opcional: sem VM_SSH_HOST definido,
# /api/redblue/network e /ws/network ficam "não configurados" em vez de
# derrubarem o backend — ao contrário de SENTRYLENS_API_KEY, que é
# fail-closed para tudo.
VM_SSH_HOST = os.getenv("VM_SSH_HOST", "")
VM_SSH_USER = os.getenv("VM_SSH_USER", "")
VM_SSH_KEY_PATH = os.getenv("VM_SSH_KEY_PATH", "") or None
NETWORK_CAPTURE_REMOTE_PATH = os.getenv("NETWORK_CAPTURE_REMOTE_PATH", "/var/log/sentrylens/network.csv")

# Diretório onde o histórico de alertas é persistido para além dos 90 dias
# de retenção do Wazuh Indexer (ver scripts/history_store.py).
SENTRYLENS_HISTORY_DIR = os.getenv(
    "SENTRYLENS_HISTORY_DIR", os.path.join(os.path.dirname(__file__), "historico")
)

# Base de dados dos incidentes (R3) — separada do índice de histórico, que é
# uma cache reconstruível; aqui há estado e notas do analista.
INCIDENTS_DB_PATH = os.getenv("INCIDENTS_DB_PATH", os.path.join(os.path.dirname(__file__), "incidents.sqlite3"))
# Teto de alertas por corrida de POST /api/incidents/backfill (o Indexer limita a 10000).
BACKFILL_MAX_ALERTS = 5000

# O CORS (configurado mais abaixo) já restringe as origens a loopback, mas
# isso não chega sozinho — foi por não haver autenticação nenhuma nos
# endpoints que a auditoria de 2026-08-31 teve de restringir o CORS em
# primeiro lugar. Por isso os endpoints /api/* passam a exigir também uma
# API key própria via header X-API-Key. Fail-closed deliberado: se a
# variável não estiver definida (ou vier vazia), TODOS os pedidos são
# recusados com 401 — nunca abrimos por omissão.
SENTRYLENS_API_KEY = os.getenv("SENTRYLENS_API_KEY", "")


async def require_api_key(x_api_key: str = Header(default="", alias="X-API-Key")) -> None:
    """
    Aplicada individualmente a cada rota REST /api/* via
    dependencies=_REQUIRE_API_KEY (nunca a nível de app — ver comentário
    junto ao FastAPI(...) sobre porque isso rebentaria /ws/alerts). Usa
    secrets.compare_digest (em vez de ==) para evitar timing attacks na
    comparação da key.
    """
    if not SENTRYLENS_API_KEY or not secrets.compare_digest(x_api_key, SENTRYLENS_API_KEY):
        raise HTTPException(status_code=401, detail="API key inválida ou em falta")


# dependencies=[Depends(...)] no construtor do FastAPI aplica-se a TODAS as
# rotas, incluindo @app.websocket (confirmado por teste dedicado ao
# implementar /ws/alerts) — o que rebentaria esse endpoint, porque um
# cliente WebSocket de browser real nunca consegue enviar o header
# X-API-Key, e a HTTPException(401) levantada durante a resolução de
# dependencies de um WebSocket não vira um close ASGI válido: a ligação
# fica pendurada para sempre em vez de ser recusada. Por isso a dependency
# deixou de estar aqui e passou a ser aplicada individualmente a cada rota
# REST (dependencies=[Depends(require_api_key)] em cada @app.get/@app.post
# abaixo) — /ws/alerts fica de fora de propósito e trata a sua própria
# autenticação (query param, ver o endpoint mais abaixo).
#
# As rotas automáticas de documentação (/docs, /redoc, /openapi.json) são
# adicionadas por dentro via add_route() e não herdariam a dependency de
# qualquer forma (armadilha semelhante, já resolvida antes desta). Continuam
# desligadas por completo — este dashboard não precisa de Swagger UI, e
# assim ficam mesmo inacessíveis (404), não só "escondidas".
app = FastAPI(
    title="SentryLens",
    description="SentryLens — análise de segurança Windows ligada ao Wazuh",
    version="2.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# Aplicada individualmente a cada rota REST abaixo (nunca a nível de app —
# ver comentário acima sobre o WebSocket).
_REQUIRE_API_KEY = [Depends(require_api_key)]

# O frontend (ficheiro estático) corre numa porta diferente do backend,
# por isso o CORS tem de ficar aberto entre portas — mas nunca a "*":
# com allow_origins=["*"] e zero autenticação nos endpoints, qualquer
# site que o browser tivesse aberto noutro separador conseguia ler
# alertas de segurança e specs da máquina via fetch() (auditoria de
# 2026-08-31). Restringido a loopback (qualquer porta em localhost/
# 127.0.0.1) — nenhuma origem externa consegue ler as respostas.
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

manager_client = WazuhManagerClient(
    WAZUH_MANAGER_URL, WAZUH_MANAGER_USER, WAZUH_MANAGER_PASSWORD, verify_ssl=WAZUH_VERIFY_SSL
)
indexer_client = WazuhIndexerClient(
    WAZUH_INDEXER_URL, WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD, verify_ssl=WAZUH_VERIFY_SSL
)

ws_manager = ConnectionManager()
network_ws_manager = NetworkConnectionManager()
packet_buffer: deque = deque(maxlen=PACKET_BUFFER_MAX)
# Deteções de rede acumuladas à medida que o polling as encontra (timestamp
# original preservado), em vez de recomputadas a pedido sobre packet_buffer
# — ver network_monitor._poll_once. Só assim /api/redblue/metrics consegue
# atribuir uma deteção de rede a um ataque histórico depois de o buffer de
# pacotes (janela curta) já ter avançado para além dele.
network_detection_buffer: deque = deque(maxlen=5000)
vm_ssh_client = VMSSHClient(VM_SSH_HOST, VM_SSH_USER, VM_SSH_KEY_PATH) if VM_SSH_HOST else None
incident_store = IncidentStore(INCIDENTS_DB_PATH)


def _extract_windows_event_id(alert: dict) -> int | None:
    """
    O Wazuh guarda o Event ID original do Windows dentro de data.win.system.eventID.
    Nem todos os alertas vêm de logs Windows, por isso tratamos a ausência
    do campo com normalidade.
    """
    try:
        raw = alert.get("data", {}).get("win", {}).get("system", {}).get("eventID")
        return int(raw) if raw is not None else None
    except (ValueError, TypeError):
        return None


def _enrich_alert(alert: dict) -> dict:
    """Junta a um alerta cru do Wazuh a nossa camada de classificação (Fase 1)."""
    win_event_id = _extract_windows_event_id(alert)
    classification = classify_alert(win_event_id)

    return {
        "timestamp": alert.get("@timestamp"),
        "agent_name": alert.get("agent", {}).get("name", "Unknown"),
        "agent_ip": alert.get("agent", {}).get("ip", "-"),
        "rule_id": alert.get("rule", {}).get("id"),
        "rule_description": alert.get("rule", {}).get("description"),
        "wazuh_level": alert.get("rule", {}).get("level"),
        "windows_event_id": win_event_id,
        "friendly_name": classification["friendly_name"],
        "severity": classification["severity"],
        "category": classification["category"],
        "recommendation": classification["recommendation"],
        "full_log": alert.get("full_log", ""),
    }


async def _system_monitor_loop() -> None:
    """
    Corre para sempre em background, independentemente de haver pedidos HTTP:
    CPU/RAM/disco a cada 30s, velocidade de rede a cada 20 minutos (a
    primeira medição de rede corre logo no arranque, para o dashboard já
    ter um valor assim que o backend fica de pé).
    """
    loop = asyncio.get_running_loop()
    seconds_since_network_check = NETWORK_CHECK_INTERVAL_SECONDS

    while True:
        try:
            specs = await loop.run_in_executor(None, get_specs)
            record_usage_sample(specs)

            network_speed = get_last_network_speed()
            if network_speed:
                specs["network_speed"] = network_speed

            result = await loop.run_in_executor(None, check_thresholds, specs)
            if result["active_violations"]:
                logger.warning(
                    "Violações de threshold activas: %s",
                    [f"{v['metric']}={v['level']}" for v in result["active_violations"]],
                )
            else:
                logger.info(
                    "specs ok — cpu=%.1f%% ram=%.1f%% disco=%s",
                    specs["cpu"]["usage_percent"],
                    specs["ram"]["usage_percent"],
                    [f"{d['mountpoint']}={d['usage_percent']:.1f}%" for d in specs["disk"]],
                )
        except Exception:
            logger.exception("Falha ao recolher/avaliar specs do sistema")

        seconds_since_network_check += LOCAL_CHECK_INTERVAL_SECONDS
        if seconds_since_network_check >= NETWORK_CHECK_INTERVAL_SECONDS:
            seconds_since_network_check = 0
            try:
                await loop.run_in_executor(None, measure_network_speed)
                logger.info("Medição de rede actualizada: %s", get_last_network_speed())
            except Exception:
                logger.exception("Falha na medição de velocidade de rede")

        await asyncio.sleep(LOCAL_CHECK_INTERVAL_SECONDS)


def _persist_new_alerts(alerts: list[dict]) -> None:
    """Callback do alert_poll_loop (Fase 8): persiste histórico bruto (Fase 9), o veredito de conformidade (Fase 7), e indexa ambos em SQLite (Fase 9 - índice) para consultas rápidas por data/severidade/conformidade."""
    org_profile = get_org_profile()
    rules = load_compliance_rules()
    for alert in alerts:
        alerts_path, alerts_offset = append_alert_history(alert, SENTRYLENS_HISTORY_DIR)
        result = evaluate_alert_compliance(alert, org_profile, rules)
        compliance_path, compliance_offset = append_compliance_history(alert, result, SENTRYLENS_HISTORY_DIR)
        # A data/hora efetivamente gravada pode divergir de alert.get("timestamp")
        # (fallback interno de history_store._alert_datetime para datetime.utcnow()
        # quando o timestamp vem em falta/inválido), por isso lemos o registo de
        # volta em vez de reprocessar o timestamp aqui — o índice nunca diverge
        # do que ficou realmente escrito no JSONL.
        written_record = read_jsonl_at_offset(alerts_path, alerts_offset) or {}
        index_alert(
            SENTRYLENS_HISTORY_DIR,
            date=written_record.get("date"),
            time=written_record.get("time"),
            event_id=alert.get("windows_event_id"),
            severity=alert.get("severity"),
            rgpd_estado=result["rgpd"]["estado"],
            nis2_estado=result["nis2"]["estado"],
            ai_act_estado=result["ai_act"]["estado"],
            alerts_file=alerts_path,
            alerts_offset=alerts_offset,
            compliance_file=compliance_path,
            compliance_offset=compliance_offset,
        )


def _ingest_incident_alerts(raw_alerts: list[dict]) -> None:
    """Callback de alert_poll_loop (R3): agrupa alertas brutos novos em incidentes."""
    counts = incident_ingest.ingest_raw_alerts(incident_store, raw_alerts, ATTACK_LOG_PATH, SCENARIOS)
    if counts["opened"] or counts["attached"]:
        logger.info("Incidentes (alertas): %s", counts)


def _ingest_incident_detections(detections: list[dict]) -> None:
    """Callback de network_poll_loop (R3): agrupa deteções de rede novas em incidentes."""
    counts = incident_ingest.ingest_network_detections(incident_store, detections, ATTACK_LOG_PATH, SCENARIOS)
    if counts["opened"] or counts["attached"]:
        logger.info("Incidentes (rede): %s", counts)


@app.on_event("startup")
async def _start_system_monitor() -> None:
    """Lança o loop de monitorização em background, sem bloquear o arranque do servidor."""
    app.state.system_monitor_task = asyncio.create_task(_system_monitor_loop())
    app.state.alert_ws_poll_task = asyncio.create_task(
        alert_poll_loop(
            indexer_client,
            ws_manager,
            _enrich_alert,
            on_new_alerts=_persist_new_alerts,
            on_new_raw_alerts=_ingest_incident_alerts,
        )
    )
    if vm_ssh_client is not None:
        app.state.network_ws_poll_task = asyncio.create_task(
            network_poll_loop(
                vm_ssh_client, network_ws_manager, packet_buffer, NETWORK_CAPTURE_REMOTE_PATH,
                network_detection_buffer,
                on_new_detections=_ingest_incident_detections,
            )
        )


@app.get("/api/health", dependencies=_REQUIRE_API_KEY)
async def health():
    """Confirma que o backend está de pé (não testa ligação ao Wazuh)."""
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


@app.get("/api/agents", dependencies=_REQUIRE_API_KEY)
async def get_agents():
    """Lista de agentes Wazuh e o seu estado atual."""
    try:
        agents = await manager_client.get_agents()
        summary = await manager_client.get_agents_summary()
        return {
            "agents": [
                {
                    "id": a.get("id"),
                    "name": a.get("name"),
                    "ip": a.get("ip"),
                    "status": a.get("status"),
                    "os": a.get("os", {}).get("name", "Unknown"),
                    "last_keep_alive": a.get("lastKeepAlive"),
                }
                for a in agents
            ],
            "summary": summary,
        }
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erro ao contactar Wazuh Manager: {e}")


def _siem_error_code(component: str, exc: Exception) -> str:
    """Código estável para o cliente; o detalhe (pode ter host/URL) só vai para o log."""
    logging.getLogger("sentrylens.siem_health").warning(
        "Falha ao contactar %s: %s: %s", component, type(exc).__name__, exc
    )
    return "timeout" if isinstance(exc, (asyncio.TimeoutError, httpx.TimeoutException)) else "unreachable"


@app.get("/api/siem/health", dependencies=_REQUIRE_API_KEY)
async def get_siem_health():
    """
    Saúde do SIEM (R2): estado Manager/Indexer, agentes, atraso de ingestão e
    taxa de alertas. Cada componente é consultado em separado — se um estiver
    em baixo, responde 200 com esse componente "unavailable" e os campos
    dependentes a null (nunca números inventados).
    """
    agents_summary, manager_error = None, None
    try:
        agents_summary = await manager_client.get_agents_summary()
    except Exception as e:
        manager_error = _siem_error_code("Manager", e)
    alerts, indexer_error = None, None
    try:
        alerts = await indexer_client.get_recent_alerts(hours=1, size=ALERTS_FETCH_SIZE)
    except Exception as e:
        indexer_error = _siem_error_code("Indexer", e)
    return build_siem_health_report(agents_summary, manager_error, alerts, indexer_error)


@app.get("/api/alerts", dependencies=_REQUIRE_API_KEY)
async def get_alerts(
    hours: int = Query(24, ge=1, le=168, description="Janela temporal em horas"),
    min_level: int = Query(0, ge=0, le=16, description="Nível mínimo de severidade Wazuh"),
    agent_name: str | None = Query(None, description="Filtrar por nome de agente"),
    severity: str | None = Query(None, description="Filtrar por severidade classificada (critical/high/medium/low)"),
    category: str | None = Query(
        None,
        description="Filtrar por categoria classificada (ciclo_de_vida/gestao_de_grupos/autenticacao/atividade_privilegiada/tarefas_agendadas/politica_seguranca/acesso_rede/geral)",
    ),
):
    """
    Alertas recentes, já enriquecidos com a classificação de Event ID
    (nome amigável, severidade, categoria, recomendação).
    """
    try:
        raw_alerts = await indexer_client.get_recent_alerts(
            hours=hours, min_level=min_level, agent_name=agent_name
        )
        enriched = [_enrich_alert(a) for a in raw_alerts]

        if severity:
            enriched = [a for a in enriched if a["severity"] == severity]
        if category:
            enriched = [a for a in enriched if a["category"] == category]

        return {"total": len(enriched), "alerts": enriched}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erro ao contactar Wazuh Indexer: {e}")


@app.get("/api/stats", dependencies=_REQUIRE_API_KEY)
async def get_stats(hours: int = Query(24, ge=1, le=168)):
    """
    Estatísticas agregadas para os KPIs do dashboard:
    total de alertas, contagem por severidade e por categoria classificada,
    top eventos.
    """
    try:
        raw_alerts = await indexer_client.get_recent_alerts(hours=hours, size=500)
        enriched = [_enrich_alert(a) for a in raw_alerts]

        severity_counts = Counter(a["severity"] for a in enriched)
        category_counts = Counter(a["category"] for a in enriched)
        event_counts = Counter(
            (a["windows_event_id"], a["friendly_name"])
            for a in enriched
            if a["windows_event_id"] is not None
        )
        agent_counts = Counter(a["agent_name"] for a in enriched)

        top_events = [
            {"event_id": eid, "name": name, "count": count}
            for (eid, name), count in event_counts.most_common(10)
        ]

        return {
            "window_hours": hours,
            "total_alerts": len(enriched),
            "by_severity": dict(severity_counts),
            "by_category": dict(category_counts),
            "top_events": top_events,
            "by_agent": dict(agent_counts),
        }
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erro ao contactar Wazuh Indexer: {e}")


@app.get("/api/brute-force", dependencies=_REQUIRE_API_KEY)
async def detect_brute_force(
    hours: int = Query(24, ge=1, le=168),
    threshold: int = Query(5, ge=1, description="Nº mínimo de falhas para gerar alerta"),
):
    """
    Deteção de força bruta: agrupa Event ID 4625 (Failed Logon) por
    utilizador-alvo e assinala quem excedeu o threshold.
    Mesma lógica do log_analyzer_real.py, aplicada aqui a dados ao vivo.
    """
    try:
        raw_alerts = await indexer_client.get_recent_alerts(hours=hours, size=1000)

        failed_logons: dict[str, list[dict]] = {}
        for alert in raw_alerts:
            win_id = _extract_windows_event_id(alert)
            if win_id == 4625:
                target_user = (
                    alert.get("data", {}).get("win", {}).get("eventdata", {}).get("targetUserName", "Unknown")
                )
                failed_logons.setdefault(target_user, []).append(alert)

        suspects = [
            {
                "user": user,
                "failed_attempts": len(attempts),
                "last_attempt": attempts[0].get("@timestamp"),
                "source_agent": attempts[0].get("agent", {}).get("name"),
            }
            for user, attempts in failed_logons.items()
            if len(attempts) >= threshold
        ]

        return {"window_hours": hours, "threshold": threshold, "suspects": suspects}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erro ao contactar Wazuh Indexer: {e}")


@app.get("/api/system/specs", dependencies=_REQUIRE_API_KEY)
async def get_system_specs():
    """Snapshot actual de CPU/RAM/disco/rede desta máquina + última medição de velocidade de rede."""
    loop = asyncio.get_running_loop()
    try:
        specs = await loop.run_in_executor(None, get_specs)
        specs["network_speed"] = get_last_network_speed()
        specs["timestamp"] = datetime.utcnow().isoformat()
        return specs
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao recolher specs do sistema: {e}")


@app.get("/api/system/thresholds", dependencies=_REQUIRE_API_KEY)
async def get_system_thresholds():
    """Expõe os thresholds de aviso/crítico usados para CPU/RAM/disco/rede — fonte única de verdade, para o frontend deixar de duplicar estes valores."""
    return THRESHOLDS


@app.get("/api/system/alerts", dependencies=_REQUIRE_API_KEY)
async def get_system_alerts():
    """Violações de threshold activas neste momento, com duração desde o início."""
    now = datetime.now(timezone.utc)
    history = get_history()
    active = []
    for entry in history:
        if entry["resolved_at"] is not None:
            continue
        started_at = datetime.fromisoformat(entry["started_at"])
        active.append({**entry, "duration_seconds": round((now - started_at).total_seconds(), 3)})
    return {"active_violations": active}


@app.get("/api/system/history", dependencies=_REQUIRE_API_KEY)
async def get_system_history():
    """Violações de threshold já resolvidas."""
    history = get_history()
    resolved = [e for e in history if e["resolved_at"] is not None]
    return {"history": resolved}


@app.get("/api/system/usage-history", dependencies=_REQUIRE_API_KEY)
async def get_system_usage_history():
    """
    Últimas amostras de uso de CPU/RAM/disco (buffer em memória do backend,
    alimentado pelo loop de background a cada 30s — ~1h de histórico).
    """
    return {"history": get_usage_history()}


@app.post("/api/system/speedtest", dependencies=_REQUIRE_API_KEY)
async def force_speedtest():
    """Força uma medição de velocidade de rede imediata (ignora a cache)."""
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(None, measure_network_speed)
        return result
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erro ao medir velocidade de rede: {e}")


@app.get("/api/lifecycle", dependencies=_REQUIRE_API_KEY)
async def get_lifecycle(days: int = Query(30, ge=1, le=90, description="Janela temporal em dias")):
    """Painel de ciclo de vida de contas: contagens, linha temporal e deteções de risco."""
    try:
        raw_alerts = await indexer_client.get_recent_alerts(hours=days * 24, size=2000)
        return build_lifecycle_report(raw_alerts, days)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erro ao contactar Wazuh Indexer: {e}")


@app.get("/api/privileges", dependencies=_REQUIRE_API_KEY)
async def get_privileges(days: int = Query(30, ge=1, le=90, description="Janela temporal em dias")):
    """Painel de desvios RBAC: privilégios atribuídos fora do baseline de cargos versus grupos."""
    try:
        baseline = load_rbac_baseline(RBAC_BASELINE_PATH)
    except FileNotFoundError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Baseline RBAC não encontrado em '{RBAC_BASELINE_PATH}': {e}",
        )
    except json.JSONDecodeError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Baseline RBAC inválido (JSON malformado) em '{RBAC_BASELINE_PATH}': {e}",
        )

    try:
        raw_alerts = await indexer_client.get_recent_alerts(hours=days * 24, size=2000)
        return build_privileges_report(raw_alerts, baseline)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erro ao contactar Wazuh Indexer: {e}")


@app.get("/api/admin-activity", dependencies=_REQUIRE_API_KEY)
async def get_admin_activity(days: int = Query(30, ge=1, le=90, description="Janela temporal em dias")):
    """Painel de atividade de contas administrativas: privilégios especiais, tarefas agendadas e deteções de risco."""
    try:
        raw_alerts = await indexer_client.get_recent_alerts(hours=days * 24, size=2000)
        return build_admin_activity_report(raw_alerts, admin_prefix=os.getenv("ADMIN_ACCOUNT_PREFIX", "adm."))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erro ao contactar Wazuh Indexer: {e}")


@app.get("/api/history/query", dependencies=_REQUIRE_API_KEY)
async def query_history(
    date_from: str | None = Query(None, description="Data inicial AAAA-MM-DD (inclusive)"),
    date_to: str | None = Query(None, description="Data final AAAA-MM-DD (inclusive)"),
    severity: str | None = Query(None, description="Filtrar por severidade (critical/high/medium/low/info)"),
    rgpd_estado: str | None = Query(None, description="aplicavel | verificado_e_nao_aplicavel"),
    nis2_estado: str | None = Query(None, description="aplicavel | verificado_e_nao_aplicavel"),
    ai_act_estado: str | None = Query(None, description="aplicavel | verificado_e_nao_aplicavel"),
    limit: int = Query(200, ge=1, le=1000),
):
    """
    Consulta o histórico persistido (Fase 9) via o índice SQLite, para
    além dos 90 dias que o Wazuh Indexer guarda — filtrável por data,
    severidade e vereditos de conformidade sem percorrer todas as pastas
    por dia. Exemplo: /api/history/query?date_from=2026-03-01&date_to=2026-05-31&rgpd_estado=aplicavel
    """
    rows = query_history_index(
        SENTRYLENS_HISTORY_DIR,
        date_from=date_from,
        date_to=date_to,
        severity=severity,
        rgpd_estado=rgpd_estado,
        nis2_estado=nis2_estado,
        ai_act_estado=ai_act_estado,
        limit=limit,
    )
    results = []
    for row in rows:
        full_record = read_jsonl_at_offset(row["alerts_file"], row["alerts_offset"]) or {}
        results.append({**row, **full_record})
    return {"total": len(results), "results": results}


@app.get("/api/compliance", dependencies=_REQUIRE_API_KEY)
async def get_compliance(hours: int = Query(24, ge=1, le=168, description="Janela temporal em horas")):
    """Verificação de conformidade (RGPD/NIS2/AI Act) por alerta recente, mais um resumo agregado e o perfil da organização usado."""
    try:
        raw_alerts = await indexer_client.get_recent_alerts(hours=hours, size=500)
        enriched = [_enrich_alert(a) for a in raw_alerts]
        org_profile = get_org_profile()
        rules = load_compliance_rules()

        summary = {
            "rgpd": {"aplicavel": 0, "verificado_e_nao_aplicavel": 0},
            "nis2": {"aplicavel": 0, "verificado_e_nao_aplicavel": 0},
            "ai_act": {"aplicavel": 0, "verificado_e_nao_aplicavel": 0},
        }
        results = []
        for alert in enriched:
            compliance = evaluate_alert_compliance(alert, org_profile, rules)
            for norma, veredito in compliance.items():
                summary[norma][veredito["estado"]] += 1
            results.append({**alert, "compliance": compliance})

        return {
            "window_hours": hours,
            "total": len(results),
            "org_profile": org_profile,
            "summary": summary,
            "alerts": results,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erro ao contactar Wazuh Indexer: {e}")


@app.get("/api/nis2-lookup", dependencies=_REQUIRE_API_KEY)
async def nis2_lookup(
    cae_principal: str = Query(..., description="CAE principal (ex: '6201' ou '62')"),
    cae_secundarios: str | None = Query(None, description="CAEs secundários separados por vírgula"),
    nipc: str | None = Query(None),
    colaboradores: int | None = Query(None, ge=0),
    faturacao_eur: float | None = Query(None, ge=0),
    excecao_conhecida: str | None = Query(None, description="fornecedor_confianca_qualificado | registo_dominio | telecomunicacoes | administracao_publica"),
):
    """
    Classificação NIS2 sugerida a partir de dados já conhecidos de uma
    empresa (não pesquisa nada online) — ver scripts/nis2_lookup.py para
    a limitação de conhecimento e a natureza não-definitiva do resultado.
    """
    secundarios = [c.strip() for c in cae_secundarios.split(",")] if cae_secundarios else None
    return lookup_nis2_classification(
        nipc=nipc,
        cae_principal=cae_principal,
        cae_secundarios=secundarios,
        colaboradores=colaboradores,
        faturacao_eur=faturacao_eur,
        excecao_conhecida=excecao_conhecida,
    )


@app.get("/api/ml-anomalies", dependencies=_REQUIRE_API_KEY)
async def get_ml_anomalies(hours: int = Query(24, ge=1, le=168, description="Janela temporal em horas")):
    """
    Deteção de anomalias por Machine Learning (Isolation Forest), lado a
    lado com a classificação por regras do event_catalog.py. Corre em
    paralelo com as regras — não as substitui.
    """
    try:
        model, scaler = ml_anomalies.load_model(ML_MODEL_DIR)
    except FileNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e))

    try:
        raw_alerts = await indexer_client.get_recent_alerts(hours=hours, size=1000)
        report = ml_anomalies.build_ml_anomalies_report(raw_alerts, model, scaler)
        report["window_hours"] = hours
        return report
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erro ao contactar Wazuh Indexer: {e}")


@app.get("/api/redblue/metrics", dependencies=_REQUIRE_API_KEY)
async def get_redblue_metrics(
    hours: int = Query(168, ge=1, le=168, description="Janela temporal em horas"),
    window_seconds: int = Query(300, ge=30, le=3600, description="Janela de correlação por ataque, em segundos"),
):
    """
    Motor de correlação Red vs Blue (Fase 11): cruza o log de ataques da
    VM Kali com os alertas já classificados por regra + ML, e (Onda 2) com
    as deteções de rede — por cenário de ataque: cobertura, MTTD, e se foi
    detetado por regra/ML/rede/combinação/nenhum.
    """
    try:
        model, scaler = ml_anomalies.load_model(ML_MODEL_DIR)
    except FileNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e))

    try:
        raw_alerts = await indexer_client.get_recent_alerts(hours=hours, size=1000)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erro ao contactar Wazuh Indexer: {e}")

    ml_report = ml_anomalies.build_ml_anomalies_report(raw_alerts, model, scaler)
    attack_log = load_attack_log(ATTACK_LOG_PATH)
    # Lê as deteções já acumuladas em tempo real (timestamp original
    # preservado) em vez de recomputar detect_network_anomalies sobre o
    # packet_buffer agora — esse recompute só veria a janela curta (<=30s)
    # mais recente, perdendo qualquer ataque histórico assim que o buffer de
    # pacotes avança. Ver network_monitor._poll_once/network_detection_buffer.
    network_dets = list(network_detection_buffer) if vm_ssh_client is not None else None
    report = build_redblue_report(
        attack_log, ml_report["results"], SCENARIOS, window_seconds=window_seconds, network_detections=network_dets,
    )
    report["window_hours"] = hours
    # O fetch de alertas está limitado a 1000 (newest-first): sinaliza-se se
    # esse teto foi atingido, para que uma cobertura subestimada por
    # truncagem não passe silenciosamente por deteção falhada.
    report["alerts_fetched"] = len(raw_alerts)
    report["alerts_truncated"] = len(raw_alerts) >= 1000
    report["network_capture_configured"] = vm_ssh_client is not None
    return report


@app.get("/api/redblue/network", dependencies=_REQUIRE_API_KEY)
async def get_redblue_network():
    """
    Snapshot do buffer de rede ao vivo (Fase 11, Onda 2) — últimos pacotes
    capturados na VM + deteções de padrões suspeitos. Devolve 200 com
    listas vazias e "configured": false se VM_SSH_HOST não estiver
    definido — nunca 500 por causa disso; continua a exigir X-API-Key como
    qualquer outra rota /api/*.

    "detections" é a vista ao vivo/atual — recomputada sobre a janela
    curta mais recente de packet_buffer, "o que se passa agora". Já
    "detection_history" é o conteúdo acumulado de network_detection_buffer
    — todas as deteções encontradas desde o arranque do backend, com o
    timestamp original em que foram vistas, não recomputadas — é a mesma
    fonte que /api/redblue/metrics usa para correlação histórica.
    """
    if vm_ssh_client is None:
        return {"configured": False, "packets": [], "detections": [], "detection_history": []}
    packets = list(packet_buffer)
    return {
        "configured": True,
        "packets": packets,
        "detections": detect_network_anomalies(packets),
        "detection_history": list(network_detection_buffer),
    }


@app.get("/api/redblue/attack-log", dependencies=_REQUIRE_API_KEY)
async def get_redblue_attack_log():
    """
    Log de ataques real (attack_log.jsonl, escrito por attack_scenarios.py na
    VM Kali) + o mapeamento MITRE de cada cenário (SCENARIOS) — o que o
    painel Red Team da aba Red vs Blue precisa e que /api/redblue/metrics
    não devolve (só devolve as tentativas dentro da janela de correlação,
    e sem a ferramenta usada). Ficheiro ausente/vazio → entries: [].
    """
    entries = load_attack_log(ATTACK_LOG_PATH)
    return {
        "entries": entries,
        "total": len(entries),
        "scenarios": {
            name: {
                "description": s.description,
                "tool": s.tool,
                "event_ids": s.event_ids,
                "mitre_tactic": s.mitre_tactic,
                "mitre_technique": s.mitre_technique,
            }
            for name, s in SCENARIOS.items()
        },
    }


# ---------------------------------------------------------------------------
# Incidentes (Roadmap v2, R3) — ver docs/superpowers/specs/2026-10-06-r3-incidentes-design.md
# ---------------------------------------------------------------------------

IncidentStatus = Literal["NEW", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"]
IncidentSeverity = Literal["info", "low", "medium", "high", "critical"]


class StatusChange(BaseModel):
    status: IncidentStatus
    note: str | None = Field(default=None, max_length=2000)


class IncidentNote(BaseModel):
    text: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2000)]


class BackfillRequest(BaseModel):
    days: int = Field(default=7, ge=1, le=90)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _incidents_call(func, *args):
    """Corre uma operação da base de incidentes fora do event loop. Erros SQLite
    viram 500 genérico: nunca expõem caminhos nem SQL."""
    try:
        return await run_in_threadpool(func, *args)
    except sqlite3.Error:
        logger.exception("Falha na base de dados de incidentes")
        raise HTTPException(status_code=500, detail="Erro interno ao aceder à base de incidentes")


async def _incident_detail(incident_id: str) -> dict | None:
    incident = await _incidents_call(incident_store.get_incident, incident_id)
    if incident is None:
        return None
    raw_alerts = [e["payload"] for e in incident["evidence"] if e["kind"] == "wazuh_alert"]
    incident["ml_summary"] = await run_in_threadpool(incident_ingest.ml_summary, raw_alerts, ML_MODEL_DIR)
    for evidence in incident["evidence"]:
        if evidence["kind"] == "wazuh_alert":
            evidence["alert"] = _enrich_alert(evidence["payload"])
            del evidence["payload"]
    incident["available_transitions"] = list(available_transitions(incident["status"]))
    return incident


@app.get("/api/incidents", dependencies=_REQUIRE_API_KEY)
async def list_incidents(
    status: IncidentStatus | None = Query(None),
    severity: IncidentSeverity | None = Query(None),
    hours: int = Query(168, ge=1, le=720, description="Janela temporal (última evidência), em horas"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    incidents = await _incidents_call(incident_store.list_incidents, status, severity, since, limit, offset)
    summary = await _incidents_call(incident_store.summary, since)
    return {"window_hours": hours, "incidents": incidents, "summary": summary}


@app.post("/api/incidents/backfill", dependencies=_REQUIRE_API_KEY)
async def backfill_incidents(body: BackfillRequest):
    """Reprocessa os alertas do Wazuh Indexer (retenção de 90 dias) com a mesma
    função pura do ingest em tempo real. Idempotente. Deteções de rede só
    existem em memória, por isso não entram."""
    try:
        raw_alerts = await indexer_client.get_recent_alerts(hours=body.days * 24, size=BACKFILL_MAX_ALERTS)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erro ao contactar Wazuh Indexer: {e}")
    counts = await _incidents_call(
        incident_ingest.ingest_raw_alerts, incident_store, raw_alerts, ATTACK_LOG_PATH, SCENARIOS
    )
    counts["fetched"] = len(raw_alerts)
    counts["truncated"] = len(raw_alerts) >= BACKFILL_MAX_ALERTS
    return counts


@app.get("/api/incidents/{incident_id}", dependencies=_REQUIRE_API_KEY)
async def get_incident(incident_id: str):
    incident = await _incident_detail(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incidente não encontrado")
    return incident


@app.post("/api/incidents/{incident_id}/status", dependencies=_REQUIRE_API_KEY)
async def change_incident_status(incident_id: str, body: StatusChange):
    try:
        await _incidents_call(incident_store.set_status, incident_id, body.status, body.note, _now_iso())
    except IncidentNotFound:
        raise HTTPException(status_code=404, detail="Incidente não encontrado")
    except InvalidTransition as e:
        if e.reason == "nota_obrigatoria":
            raise HTTPException(status_code=422, detail="Fechar um incidente NEW exige uma nota (falso positivo)")
        raise HTTPException(status_code=409, detail="Transição de estado inválida")
    return await _incident_detail(incident_id)


@app.post("/api/incidents/{incident_id}/notes", dependencies=_REQUIRE_API_KEY)
async def add_incident_note(incident_id: str, body: IncidentNote):
    try:
        await _incidents_call(incident_store.add_note, incident_id, body.text, _now_iso())
    except IncidentNotFound:
        raise HTTPException(status_code=404, detail="Incidente não encontrado")
    return await _incident_detail(incident_id)


# ---------------------------------------------------------------------------
# Attack Registry (Roadmap v2, R4) — ver docs/superpowers/specs/2026-10-07-r4-attack-registry-design.md
# ---------------------------------------------------------------------------

AttackVerdict = Literal["detected", "partial", "not_detected", "unknown"]
ATTACK_ALERTS_SIZE = 1000
ATTACK_MAX_HOURS = 720


class _OutsideAlertWindow(Exception):
    pass


async def _build_attack_registry(attack_log: list, hours: int | None) -> tuple[dict, dict, bool]:
    """Junta o attack_log com alertas (regra+ML), rede e incidentes. Falhas do
    Indexer/modelo ML não derrubam o registo: o veredito fica "unknown" e o
    código de erro estável vai em correlation.error_code (detalhe só no log).
    hours=None: ataque fora da janela de alertas suportada, sem correlação.
    Devolve (registo, correlation, incidents_available)."""
    correlation = {"available": False, "error_code": None, "alerts_fetched": 0,
                   "alerts_truncated": False, "network_capture_configured": vm_ssh_client is not None}
    ml_results: list[dict] = []
    try:
        if hours is None:
            raise _OutsideAlertWindow
        model, scaler = ml_anomalies.load_model(ML_MODEL_DIR)
    except _OutsideAlertWindow:
        correlation["error_code"] = "attack_outside_alert_window"
    except Exception:  # FileNotFoundError, OSError, ValueError, UnpicklingError, ...
        logger.exception("Attack Registry: modelo ML indisponível")
        correlation["error_code"] = "ml_model_unavailable"
    else:
        try:
            raw_alerts = await indexer_client.get_recent_alerts(hours=hours, size=ATTACK_ALERTS_SIZE)
        except Exception:
            logger.exception("Attack Registry: Wazuh Indexer indisponível")
            correlation["error_code"] = "indexer_unavailable"
        else:
            ml_results = ml_anomalies.build_ml_anomalies_report(raw_alerts, model, scaler)["results"]
            correlation.update(available=True, alerts_fetched=len(raw_alerts),
                               alerts_truncated=len(raw_alerts) >= ATTACK_ALERTS_SIZE)

    incidents_available = True
    incidents: list[dict] = []
    try:
        incidents = await run_in_threadpool(incident_store.list_incidents, None, None, None, 100000, 0)
    except sqlite3.Error:
        logger.exception("Attack Registry: base de incidentes indisponível")
        incidents_available = False

    network_dets = list(network_detection_buffer) if vm_ssh_client is not None else None
    registry = build_attack_registry(
        attack_log, SCENARIOS, ml_results, network_detections=network_dets, incidents=incidents,
        correlation_available=correlation["available"],
        alerts_truncated=correlation["alerts_truncated"],
    )
    return registry, correlation, incidents_available


async def _read_attack_log() -> list:
    try:
        return await run_in_threadpool(load_attack_log, ATTACK_LOG_PATH)
    except (OSError, UnicodeDecodeError):
        logger.exception("Attack Registry: não foi possível ler o log de ataques")
        raise HTTPException(status_code=500, detail="Erro interno ao ler o registo de ataques")


@app.get("/api/attacks", dependencies=_REQUIRE_API_KEY)
async def list_attacks(
    hours: int = Query(168, ge=1, le=ATTACK_MAX_HOURS, description="Janela temporal (timestamp do ataque), em horas"),
    technique: str | None = Query(None, pattern=r"^T\d{4}(\.\d{3})?$", description="Técnica MITRE, ex. T1110"),
    status: AttackVerdict | None = Query(None, description="Veredito esperado-vs-real"),
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Registo de ataques lançados, com esperado vs real e incidentes ligados."""
    attack_log = await _read_attack_log()
    registry, correlation, incidents_available = await _build_attack_registry(attack_log, hours)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    in_window = [
        a for a in registry["attacks"]
        if (ts := incident_engine_parse(a["timestamp"])) is not None and ts >= cutoff
    ]
    if technique:
        in_window = [a for a in in_window if a["mitre_technique"] == technique]
    summary = summarize_attacks(in_window)
    if status:
        in_window = [a for a in in_window if a["actual"]["verdict"] == status]
    return {
        "window_hours": hours,
        "total": len(in_window),
        "attacks": in_window[offset:offset + limit],
        "summary": summary,
        "skipped": registry["skipped"],
        "correlation": correlation,
        "incidents_available": incidents_available,
    }


@app.get("/api/attacks/{attack_id}", dependencies=_REQUIRE_API_KEY)
async def get_attack(attack_id: Annotated[str, Path(pattern=r"^[0-9]{1,9}$")]):
    """Detalhe de um ataque pelo id do log. 404 se não existir."""
    attack_log = await _read_attack_log()
    wanted = int(attack_id)
    entry_ts = None
    for entry in attack_log:
        if isinstance(entry, dict) and entry.get("id") == wanted and not isinstance(entry.get("id"), bool):
            parsed = incident_engine_parse(entry.get("timestamp"))
            if parsed is not None and (entry_ts is None or parsed < entry_ts):
                entry_ts = parsed
    if entry_ts is None:
        raise HTTPException(status_code=404, detail="Ataque não encontrado")
    age_hours = (datetime.now(timezone.utc) - entry_ts).total_seconds() / 3600
    hours = max(1, int(age_hours) + 2)
    registry, correlation, incidents_available = await _build_attack_registry(
        attack_log, hours if hours <= ATTACK_MAX_HOURS else None
    )
    # Ids duplicados: o detalhe é o primeiro por tempo (o mais antigo).
    matches = [a for a in registry["attacks"] if a["id"] == wanted]
    if matches:
        attack = min(matches, key=lambda a: incident_engine_parse(a["timestamp"]) or datetime.max.replace(tzinfo=timezone.utc))
        return {"attack": attack, "correlation": correlation, "incidents_available": incidents_available}
    raise HTTPException(status_code=404, detail="Ataque não encontrado")


@app.get("/api/export/report", dependencies=_REQUIRE_API_KEY)
async def export_report(hours: int = Query(24, ge=1, le=168, description="Janela temporal em horas")):
    """
    Gera um relatório HTML autónomo com o estado atual do dashboard
    (KPIs, alertas, agentes, sistema) e devolve-o como ficheiro para
    download — não depende do backend estar a correr para o reabrir
    depois. Reaproveita as mesmas funções internas dos endpoints já
    existentes (get_stats, get_alerts, get_agents, get_system_specs);
    cada uma pode falhar independentemente sem impedir o resto do
    relatório de se gerar.
    """
    stats = alerts = agents = system_specs = None
    try:
        stats = await get_stats(hours=hours)
    except HTTPException:
        pass
    try:
        alerts = await get_alerts(hours=hours)
    except HTTPException:
        pass
    try:
        agents = await get_agents()
    except HTTPException:
        pass
    try:
        system_specs = await get_system_specs()
    except HTTPException:
        pass

    compliance_html = ""
    if alerts is not None:
        try:
            org_profile = get_org_profile()
            rules = load_compliance_rules()
            compliance_results = [
                (a, evaluate_alert_compliance(a, org_profile, rules)) for a in alerts.get("alerts", [])
            ]
            compliance_html = render_compliance_section(compliance_results, org_profile)
        except Exception:
            compliance_html = ""

    html_content = generate_html_report(
        stats=stats,
        alerts=alerts,
        agents=agents,
        system_specs=system_specs,
        generated_at=datetime.utcnow().isoformat(),
        hours=hours,
        compliance_html=compliance_html,
    )

    filename = f"{datetime.utcnow().strftime('%Y-%m-%d')}-relatorio.html"
    return Response(
        content=html_content,
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.websocket("/ws/alerts")
async def websocket_alerts_endpoint(websocket: WebSocket) -> None:
    """
    Push de alertas novos aos clientes ligados. Autenticação própria via
    query param `api_key` (?api_key=...) — o handshake de WebSocket do
    browser não permite enviar headers HTTP arbitrários como X-API-Key, e
    dependencies=[Depends(...)] a nível de app pode não proteger
    automaticamente rotas @app.websocket (mesma família de armadilha que já
    mordeu /docs — ver git log). Verificação explícita e independente, com
    a mesma comparação segura (secrets.compare_digest) da autenticação REST.
    """
    api_key = websocket.query_params.get("api_key", "")
    if not SENTRYLENS_API_KEY or not secrets.compare_digest(api_key, SENTRYLENS_API_KEY):
        await websocket.close(code=1008)
        return

    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


@app.websocket("/ws/network")
async def websocket_network_endpoint(websocket: WebSocket) -> None:
    """
    Push de pacotes e deteções de rede novos (Fase 11, Onda 2). Mesma
    autenticação de /ws/alerts: query param api_key, secrets.compare_digest
    — ver o comentário junto a /ws/alerts para o porquê de não poder usar
    dependencies=[Depends(...)] aqui.
    """
    api_key = websocket.query_params.get("api_key", "")
    if not SENTRYLENS_API_KEY or not secrets.compare_digest(api_key, SENTRYLENS_API_KEY):
        await websocket.close(code=1008)
        return

    await network_ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        network_ws_manager.disconnect(websocket)
