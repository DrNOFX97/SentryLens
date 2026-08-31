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
import logging
import os
import sys
from collections import Counter
from datetime import datetime, timezone

# Windows redirects stdout/stderr para o codepage da consola por omissão,
# o que corrompe os acentos nos logs (ex: "Violações" -> "Viola��es") quando
# a saída é redirecionada para ficheiro. Forçamos UTF-8 explicitamente.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from event_catalog import classify_alert
from system_monitor import (
    check_thresholds,
    get_history,
    get_last_network_speed,
    get_specs,
    get_usage_history,
    measure_network_speed,
    record_usage_sample,
)
from wazuh_client import WazuhIndexerClient, WazuhManagerClient

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

app = FastAPI(
    title="SentryLens",
    description="SentryLens — análise de segurança Windows ligada ao Wazuh",
    version="2.0.0",
)

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


@app.on_event("startup")
async def _start_system_monitor() -> None:
    """Lança o loop de monitorização em background, sem bloquear o arranque do servidor."""
    app.state.system_monitor_task = asyncio.create_task(_system_monitor_loop())


@app.get("/api/health")
async def health():
    """Confirma que o backend está de pé (não testa ligação ao Wazuh)."""
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


@app.get("/api/agents")
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


@app.get("/api/alerts")
async def get_alerts(
    hours: int = Query(24, ge=1, le=168, description="Janela temporal em horas"),
    min_level: int = Query(0, ge=0, le=16, description="Nível mínimo de severidade Wazuh"),
    agent_name: str | None = Query(None, description="Filtrar por nome de agente"),
    severity: str | None = Query(None, description="Filtrar por severidade classificada (critical/high/medium/low)"),
):
    """
    Alertas recentes, já enriquecidos com a classificação de Event ID
    (nome amigável, severidade, recomendação).
    """
    try:
        raw_alerts = await indexer_client.get_recent_alerts(
            hours=hours, min_level=min_level, agent_name=agent_name
        )
        enriched = [_enrich_alert(a) for a in raw_alerts]

        if severity:
            enriched = [a for a in enriched if a["severity"] == severity]

        return {"total": len(enriched), "alerts": enriched}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erro ao contactar Wazuh Indexer: {e}")


@app.get("/api/stats")
async def get_stats(hours: int = Query(24, ge=1, le=168)):
    """
    Estatísticas agregadas para os KPIs do dashboard:
    total de alertas, contagem por severidade classificada, top eventos.
    """
    try:
        raw_alerts = await indexer_client.get_recent_alerts(hours=hours, size=500)
        enriched = [_enrich_alert(a) for a in raw_alerts]

        severity_counts = Counter(a["severity"] for a in enriched)
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
            "top_events": top_events,
            "by_agent": dict(agent_counts),
        }
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erro ao contactar Wazuh Indexer: {e}")


@app.get("/api/brute-force")
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


@app.get("/api/system/specs")
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


@app.get("/api/system/alerts")
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


@app.get("/api/system/history")
async def get_system_history():
    """Violações de threshold já resolvidas."""
    history = get_history()
    resolved = [e for e in history if e["resolved_at"] is not None]
    return {"history": resolved}


@app.get("/api/system/usage-history")
async def get_system_usage_history():
    """
    Últimas amostras de uso de CPU/RAM/disco (buffer em memória do backend,
    alimentado pelo loop de background a cada 30s — ~1h de histórico).
    """
    return {"history": get_usage_history()}


@app.post("/api/system/speedtest")
async def force_speedtest():
    """Força uma medição de velocidade de rede imediata (ignora a cache)."""
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(None, measure_network_speed)
        return result
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erro ao medir velocidade de rede: {e}")
