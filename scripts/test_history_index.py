"""
Testes de regressão de scripts/history_index.py (índice SQLite sobre o
histórico JSONL de alertas/conformidade — Fase 9) e da integração com
scripts/main.py (_persist_new_alerts a indexar, e o endpoint
GET /api/history/query).

3 partes:
  1. history_index.py isoladamente (sem FastAPI) — index_alert,
     query_history_index, read_jsonl_at_offset, usando também
     history_store.append_alert_history/append_compliance_history para o
     round-trip.
  2. main._persist_new_alerts (função já existente do backend, Fase 8) a
     também indexar cada alerta novo.
  3. Endpoint GET /api/history/query via TestClient.

Mesmo estilo dos outros ficheiros de teste standalone do projeto
(test_history_store.py, test_auth.py, test_new_panels.py): função
check(label, condition), print [OK]/[FALHOU] por caso, sys.exit(1) no fim
se houver falhas, tempfile.mkdtemp() para isolamento.

Correr:
    python test_history_index.py
"""

import os
import sys
import tempfile

os.environ.setdefault("SENTRYLENS_API_KEY", "chave-de-teste-nao-usar-em-producao")

from fastapi.testclient import TestClient

import history_index
import history_store
from compliance_evaluator import evaluate_alert_compliance, load_compliance_rules
from org_profile import get_org_profile

import main

# Desliga o startup event (loop de monitorização de sistema + poll de
# alertas da Fase 8) — mesmo padrão dos outros ficheiros de teste, estes
# testes não devem arrancar psutil/speedtest nem o poll real do Wazuh.
main.app.router.on_startup.clear()

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


# ---------------------------------------------------------------------------
# Parte 1: history_index.py isoladamente (sem FastAPI)
# ---------------------------------------------------------------------------

def _idx(base_dir, date, time_, event_id, severity, rgpd, nis2, ai_act,
         alerts_file="dummy-alerts.jsonl", alerts_offset=0,
         compliance_file=None, compliance_offset=None):
    """Atalho para indexar um registo mock, sem passar por ficheiros JSONL reais."""
    history_index.index_alert(
        base_dir,
        date=date,
        time=time_,
        event_id=event_id,
        severity=severity,
        rgpd_estado=rgpd,
        nis2_estado=nis2,
        ai_act_estado=ai_act,
        alerts_file=alerts_file,
        alerts_offset=alerts_offset,
        compliance_file=compliance_file,
        compliance_offset=compliance_offset,
    )


def run_part1() -> None:
    # --- 1a. Round-trip completo: history_store -> read_jsonl_at_offset -> index_alert -> query_history_index ---
    tmp1 = tempfile.mkdtemp()
    alerta = {
        "timestamp": "2026-09-13T14:32:07Z",
        "windows_event_id": 4625,
        "severity": "high",
        "friendly_name": "Failed Logon",
        "agent_name": "WIN-PC01",
        "rule_id": "60122",
        "category": "autenticacao",
    }
    org_profile = get_org_profile()
    rules = load_compliance_rules()
    compliance_result = evaluate_alert_compliance(alerta, org_profile, rules)

    alerts_path, alerts_offset = history_store.append_alert_history(alerta, tmp1)
    compliance_path, compliance_offset = history_store.append_compliance_history(
        alerta, compliance_result, tmp1
    )

    alert_record = history_index.read_jsonl_at_offset(alerts_path, alerts_offset)
    check(
        "read_jsonl_at_offset lê de volta o registo de alerta escrito",
        alert_record is not None
        and alert_record.get("date") == "2026-09-13"
        and alert_record.get("time") == "14:32:07"
        and alert_record.get("event_id") == 4625
        and alert_record.get("severity") == "high"
        and alert_record.get("friendly_name") == "Failed Logon"
        and alert_record.get("agent_name") == "WIN-PC01"
        and alert_record.get("rule_id") == "60122",
    )
    check(
        "\"date\" é a primeira chave do dict lido de volta (registo de alerta)",
        alert_record is not None and list(alert_record.keys())[0] == "date",
    )

    compliance_record = history_index.read_jsonl_at_offset(compliance_path, compliance_offset)
    check(
        "read_jsonl_at_offset lê de volta o registo de conformidade escrito",
        compliance_record is not None
        and compliance_record.get("date") == "2026-09-13"
        and compliance_record.get("time") == "14:32:07"
        and compliance_record.get("event_id") == 4625
        and compliance_record.get("rgpd_estado") == compliance_result["rgpd"]["estado"]
        and compliance_record.get("nis2_estado") == compliance_result["nis2"]["estado"]
        and compliance_record.get("ai_act_estado") == compliance_result["ai_act"]["estado"],
    )
    check(
        "\"date\" é a primeira chave do dict lido de volta (registo de conformidade)",
        compliance_record is not None and list(compliance_record.keys())[0] == "date",
    )

    history_index.index_alert(
        tmp1,
        date=alert_record["date"],
        time=alert_record["time"],
        event_id=alert_record["event_id"],
        severity=alert_record["severity"],
        rgpd_estado=compliance_record["rgpd_estado"],
        nis2_estado=compliance_record["nis2_estado"],
        ai_act_estado=compliance_record["ai_act_estado"],
        alerts_file=alerts_path,
        alerts_offset=alerts_offset,
        compliance_file=compliance_path,
        compliance_offset=compliance_offset,
    )
    resultados_rt = history_index.query_history_index(tmp1)
    check("query_history_index (sem filtros) devolve exatamente 1 registo", len(resultados_rt) == 1)
    if resultados_rt:
        r = resultados_rt[0]
        check(
            "Registo indexado bate com o que foi escrito (round-trip completo)",
            r.get("date") == "2026-09-13"
            and r.get("time") == "14:32:07"
            and r.get("event_id") == 4625
            and r.get("severity") == "high"
            and r.get("rgpd_estado") == compliance_result["rgpd"]["estado"]
            and r.get("nis2_estado") == compliance_result["nis2"]["estado"]
            and r.get("ai_act_estado") == compliance_result["ai_act"]["estado"]
            and r.get("alerts_file") == alerts_path
            and r.get("alerts_offset") == alerts_offset
            and r.get("compliance_file") == compliance_path
            and r.get("compliance_offset") == compliance_offset,
        )

    # --- 1b. Filtro por intervalo de datas ---
    tmp2 = tempfile.mkdtemp()
    _idx(tmp2, "2026-02-15", "10:00:00", 4625, "high", "aplicavel", "verificado_e_nao_aplicavel", "aplicavel")
    _idx(tmp2, "2026-04-10", "11:00:00", 4720, "critical", "aplicavel", "aplicavel", "aplicavel")
    _idx(tmp2, "2026-06-01", "12:00:00", 4726, "low", "verificado_e_nao_aplicavel", "verificado_e_nao_aplicavel", "verificado_e_nao_aplicavel")

    res_range = history_index.query_history_index(tmp2, date_from="2026-03-01", date_to="2026-05-31")
    check(
        "Filtro por intervalo de datas devolve só o registo do meio",
        len(res_range) == 1 and res_range[0].get("date") == "2026-04-10" and res_range[0].get("event_id") == 4720,
    )

    # --- 1c. Filtro por rgpd_estado/nis2_estado/ai_act_estado ---
    tmp3 = tempfile.mkdtemp()
    _idx(tmp3, "2026-05-01", "09:00:00", 1, "high", "aplicavel", "verificado_e_nao_aplicavel", "aplicavel")
    _idx(tmp3, "2026-05-02", "09:00:00", 2, "low", "verificado_e_nao_aplicavel", "aplicavel", "verificado_e_nao_aplicavel")

    res_rgpd_aplicavel = history_index.query_history_index(tmp3, rgpd_estado="aplicavel")
    check(
        "Filtro rgpd_estado=aplicavel devolve só o registo 1",
        len(res_rgpd_aplicavel) == 1 and res_rgpd_aplicavel[0].get("event_id") == 1,
    )
    res_rgpd_nao_aplicavel = history_index.query_history_index(tmp3, rgpd_estado="verificado_e_nao_aplicavel")
    check(
        "Filtro rgpd_estado=verificado_e_nao_aplicavel devolve só o registo 2",
        len(res_rgpd_nao_aplicavel) == 1 and res_rgpd_nao_aplicavel[0].get("event_id") == 2,
    )
    res_nis2_aplicavel = history_index.query_history_index(tmp3, nis2_estado="aplicavel")
    check(
        "Filtro nis2_estado=aplicavel devolve só o registo 2",
        len(res_nis2_aplicavel) == 1 and res_nis2_aplicavel[0].get("event_id") == 2,
    )
    res_ai_act_aplicavel = history_index.query_history_index(tmp3, ai_act_estado="aplicavel")
    check(
        "Filtro ai_act_estado=aplicavel devolve só o registo 1",
        len(res_ai_act_aplicavel) == 1 and res_ai_act_aplicavel[0].get("event_id") == 1,
    )

    # --- 1d. Combinação de filtros (AND, não OR) ---
    tmp4 = tempfile.mkdtemp()
    # r1: severity=high, rgpd=aplicavel | r2: severity=high, rgpd=nao_aplicavel | r3: severity=low, rgpd=aplicavel
    _idx(tmp4, "2026-07-01", "08:00:00", 101, "high", "aplicavel", "verificado_e_nao_aplicavel", "aplicavel")
    _idx(tmp4, "2026-07-02", "08:00:00", 102, "high", "verificado_e_nao_aplicavel", "verificado_e_nao_aplicavel", "aplicavel")
    _idx(tmp4, "2026-07-03", "08:00:00", 103, "low", "aplicavel", "verificado_e_nao_aplicavel", "aplicavel")

    res_severity_high = history_index.query_history_index(tmp4, severity="high")
    check("Filtro severity=high sozinho devolve 2 registos (101 e 102)", len(res_severity_high) == 2)
    res_rgpd_aplicavel_tmp4 = history_index.query_history_index(tmp4, rgpd_estado="aplicavel")
    check("Filtro rgpd_estado=aplicavel sozinho devolve 2 registos (101 e 103)", len(res_rgpd_aplicavel_tmp4) == 2)

    res_and = history_index.query_history_index(tmp4, severity="high", rgpd_estado="aplicavel")
    check(
        "Combinação severity=high + rgpd_estado=aplicavel devolve só a interseção (101)",
        len(res_and) == 1 and res_and[0].get("event_id") == 101,
    )

    # --- 1e. Filtro que não bate em nada ---
    res_vazio = history_index.query_history_index(tmp4, rgpd_estado="valor-que-nao-existe")
    check("Filtro que não bate em nada devolve lista vazia sem rebentar", res_vazio == [])

    # --- 1f. limit ---
    tmp5 = tempfile.mkdtemp()
    for i in range(1, 6):
        _idx(tmp5, f"2026-01-0{i}", "10:00:00", 200 + i, "medium", "aplicavel", "verificado_e_nao_aplicavel", "aplicavel")
    res_limit = history_index.query_history_index(tmp5, limit=2)
    check("limit=2 devolve só 2 registos de 5 indexados", len(res_limit) == 2)
    check(
        "limit devolve os mais recentes primeiro (date DESC)",
        len(res_limit) == 2 and res_limit[0]["date"] == "2026-01-05" and res_limit[1]["date"] == "2026-01-04",
    )

    # --- 1g. read_jsonl_at_offset com offset inválido / ficheiro inexistente ---
    tmp6 = tempfile.mkdtemp()
    alerta_pequeno = {"timestamp": "2026-01-01T00:00:00Z", "windows_event_id": 1, "severity": "low"}
    path_pequeno, _off_pequeno = history_store.append_alert_history(alerta_pequeno, tmp6)
    check(
        "read_jsonl_at_offset com offset muito além do fim do ficheiro devolve None",
        history_index.read_jsonl_at_offset(path_pequeno, 999999) is None,
    )
    check(
        "read_jsonl_at_offset com ficheiro inexistente devolve None",
        history_index.read_jsonl_at_offset(os.path.join(tmp6, "nao-existe.jsonl"), 0) is None,
    )

    # --- 1h. Dois base_dir diferentes usam índices SQLite isolados ---
    tmpA = tempfile.mkdtemp()
    tmpB = tempfile.mkdtemp()
    _idx(tmpA, "2026-08-01", "10:00:00", 301, "high", "aplicavel", "verificado_e_nao_aplicavel", "aplicavel")
    res_A = history_index.query_history_index(tmpA)
    res_B = history_index.query_history_index(tmpB)
    check("Indexar em tmpA não aparece ao consultar tmpB", res_A != [] and res_B == [])


# ---------------------------------------------------------------------------
# Parte 2: integração main._persist_new_alerts (também indexa agora)
# ---------------------------------------------------------------------------

def run_part2() -> tuple[str, dict]:
    tmp_persist = tempfile.mkdtemp()
    main.SENTRYLENS_HISTORY_DIR = tmp_persist

    alerta_mock = {
        "timestamp": "2026-04-05T09:15:30Z",
        "agent_name": "WIN-PC02",
        "agent_ip": "10.0.0.20",
        "rule_id": "60122",
        "rule_description": "Multiple failed logons",
        "wazuh_level": 10,
        "windows_event_id": 4625,
        "friendly_name": "Falha de Autenticação",
        "severity": "high",
        "category": "autenticacao",
        "recommendation": "Investigar tentativas de acesso.",
        "full_log": "Mock failed logon",
    }

    main._persist_new_alerts([alerta_mock])

    org_profile = get_org_profile()
    rules = load_compliance_rules()
    esperado = evaluate_alert_compliance(alerta_mock, org_profile, rules)

    resultados = history_index.query_history_index(tmp_persist)
    encontrados = [r for r in resultados if r.get("event_id") == 4625]
    check("_persist_new_alerts indexou exatamente 1 registo para o alerta mock", len(encontrados) == 1)

    registo = encontrados[0] if encontrados else {}
    check(
        "Veredito RGPD indexado bate com evaluate_alert_compliance",
        registo.get("rgpd_estado") == esperado["rgpd"]["estado"],
    )
    check(
        "Veredito NIS2 indexado bate com evaluate_alert_compliance",
        registo.get("nis2_estado") == esperado["nis2"]["estado"],
    )
    check(
        "Veredito AI Act indexado bate com evaluate_alert_compliance",
        registo.get("ai_act_estado") == esperado["ai_act"]["estado"],
    )

    if registo:
        alert_readback = history_index.read_jsonl_at_offset(registo["alerts_file"], registo["alerts_offset"])
        check(
            "date/time no índice batem com os gravados em alerts.jsonl",
            alert_readback is not None
            and alert_readback.get("date") == registo.get("date")
            and alert_readback.get("time") == registo.get("time"),
        )

    return tmp_persist, alerta_mock


# ---------------------------------------------------------------------------
# Parte 3: endpoint GET /api/history/query via TestClient
# ---------------------------------------------------------------------------

def run_part3() -> None:
    tmp_ep = tempfile.mkdtemp()
    main.SENTRYLENS_HISTORY_DIR = tmp_ep

    alertas = [
        {
            "timestamp": "2026-01-10T08:00:00Z",
            "agent_name": "WIN-A",
            "agent_ip": "10.0.0.1",
            "rule_id": "60122",
            "rule_description": "Failed logon",
            "wazuh_level": 10,
            "windows_event_id": 4625,
            "friendly_name": "Falha de Autenticação",
            "severity": "high",
            "category": "autenticacao",
            "recommendation": "Investigar.",
            "full_log": "log a",
        },
        {
            "timestamp": "2026-03-15T09:00:00Z",
            "agent_name": "WIN-B",
            "agent_ip": "10.0.0.2",
            "rule_id": "60100",
            "rule_description": "Account created",
            "wazuh_level": 8,
            "windows_event_id": 4720,
            "friendly_name": "Conta Criada",
            "severity": "critical",
            "category": "ciclo_de_vida",
            "recommendation": "Validar necessidade.",
            "full_log": "log b",
        },
        {
            "timestamp": "2026-05-20T10:00:00Z",
            "agent_name": "WIN-C",
            "agent_ip": "10.0.0.3",
            "rule_id": "60200",
            "rule_description": "Audit log cleared",
            "wazuh_level": 12,
            "windows_event_id": 1102,
            "friendly_name": "Log de Auditoria Limpo",
            "severity": "low",
            "category": "politica_seguranca",
            "recommendation": "Investigar quem limpou o log.",
            "full_log": "log c",
        },
    ]
    main._persist_new_alerts(alertas)

    client_sem_auth = TestClient(main.app)
    client = TestClient(main.app, headers={"X-API-Key": os.environ["SENTRYLENS_API_KEY"]})

    # --- Sem filtros ---
    resp = client.get("/api/history/query")
    check("GET /api/history/query sem filtros devolve 200", resp.status_code == 200)
    body = resp.json() if resp.status_code == 200 else {}
    check("total bate com os 3 alertas inseridos (sem filtros)", body.get("total") == 3)
    resultados = body.get("results", [])
    check("results tem 3 itens (sem filtros)", len(resultados) == 3)
    item_4625 = next((r for r in resultados if r.get("event_id") == 4625), None)
    check(
        "Item do resultado tem friendly_name/agent_name/rule_id lidos de volta do JSONL",
        item_4625 is not None
        and item_4625.get("friendly_name") == "Falha de Autenticação"
        and item_4625.get("agent_name") == "WIN-A"
        and item_4625.get("rule_id") == "60122",
    )

    # --- Filtro por intervalo de datas (só o alerta de 2026-03-15) ---
    resp_range = client.get("/api/history/query", params={"date_from": "2026-02-01", "date_to": "2026-04-01"})
    check("GET /api/history/query com date_from/date_to devolve 200", resp_range.status_code == 200)
    body_range = resp_range.json() if resp_range.status_code == 200 else {}
    check(
        "Filtro de intervalo de datas devolve só o alerta 4720",
        body_range.get("total") == 1
        and len(body_range.get("results", [])) == 1
        and body_range["results"][0].get("event_id") == 4720,
    )

    # --- Filtro por rgpd_estado=aplicavel (autenticacao + ciclo_de_vida, não politica_seguranca) ---
    resp_rgpd = client.get("/api/history/query", params={"rgpd_estado": "aplicavel"})
    check("GET /api/history/query com rgpd_estado devolve 200", resp_rgpd.status_code == 200)
    body_rgpd = resp_rgpd.json() if resp_rgpd.status_code == 200 else {}
    ids_rgpd = {r.get("event_id") for r in body_rgpd.get("results", [])}
    check(
        "Filtro rgpd_estado=aplicavel devolve só os 2 alertas com categoria aplicável",
        body_rgpd.get("total") == 2 and ids_rgpd == {4625, 4720},
    )

    # --- Sem autenticação -> 401 ---
    resp_sem_auth = client_sem_auth.get("/api/history/query")
    check("GET /api/history/query sem X-API-Key devolve 401", resp_sem_auth.status_code == 401)


def run() -> None:
    run_part1()
    run_part2()
    run_part3()

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")
    sys.exit(0)


if __name__ == "__main__":
    run()
