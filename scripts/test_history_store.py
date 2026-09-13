"""
Testes unitários de scripts/history_store.py — persistência própria de
histórico de alertas em JSONL, organizada em <base_dir>/AAAA/MM-mês/
AAAA-MM-DD-<kind>.jsonl. Não depende de main.py/FastAPI/Wazuh: são só
testes sobre ficheiros, usando tempfile.mkdtemp() para um diretório
isolado por execução (não precisa de limpeza no fim, é temporário do SO).

Mesmo estilo dos outros ficheiros de teste standalone: função
check(label, condition), print [OK]/[FALHOU] por caso, sys.exit(1) no fim
se houver falhas.

Correr:
    python test_history_store.py
"""

import json
import os
import sys
import tempfile
from pathlib import Path

from history_store import (
    append_alert_history,
    append_alerts_history,
    history_file_path,
)

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def run() -> None:
    # --- 1. history_file_path gera o path esperado ---
    tmp1 = tempfile.mkdtemp()
    path1 = history_file_path(tmp1, "2026-09-13", "alerts")
    parts = Path(path1).parts
    check(
        "history_file_path termina em 2026/09-setembro/2026-09-13-alerts.jsonl",
        parts[-3:] == ("2026", "09-setembro", "2026-09-13-alerts.jsonl"),
    )

    # --- 2. history_file_path cria as pastas ---
    check(
        "history_file_path cria o diretório do ficheiro",
        os.path.isdir(os.path.dirname(path1)),
    )

    # --- 3. Nome do mês em português correto, incluindo acentos ---
    tmp2 = tempfile.mkdtemp()
    path_marco = history_file_path(tmp2, "2026-03-15", "alerts")
    check(
        "Março gera pasta 03-março (acento correto)",
        Path(path_marco).parts[-2] == "03-março",
    )
    path_setembro = history_file_path(tmp2, "2026-09-01", "alerts")
    check(
        "Setembro gera pasta 09-setembro (sem bug de mês fixo)",
        Path(path_setembro).parts[-2] == "09-setembro",
    )

    # --- 4. append_alert_history escreve uma linha JSON válida ---
    tmp4 = tempfile.mkdtemp()
    alerta_completo = {
        "timestamp": "2026-09-13T14:32:07Z",
        "windows_event_id": 4625,
        "severity": "high",
        "friendly_name": "Failed Logon",
        "agent_name": "WIN-PC01",
        "rule_id": "60122",
    }
    append_alert_history(alerta_completo, tmp4)
    path4 = history_file_path(tmp4, "2026-09-13", "alerts")
    with open(path4, "r", encoding="utf-8") as f:
        linhas4 = f.readlines()
    check("append_alert_history escreve exatamente 1 linha", len(linhas4) == 1)
    record4 = json.loads(linhas4[0])
    check("record.date == 2026-09-13", record4.get("date") == "2026-09-13")
    check("record.time == 14:32:07", record4.get("time") == "14:32:07")
    check("record.event_id == 4625", record4.get("event_id") == 4625)
    check("record.severity == high", record4.get("severity") == "high")
    check(
        "record.friendly_name == Failed Logon",
        record4.get("friendly_name") == "Failed Logon",
    )
    check("record.agent_name == WIN-PC01", record4.get("agent_name") == "WIN-PC01")
    check("record.rule_id == 60122", record4.get("rule_id") == "60122")
    check(
        "\"date\" é a primeira chave do dict",
        list(record4.keys())[0] == "date",
    )

    # --- 5. Append acumula, não sobrescreve ---
    tmp5 = tempfile.mkdtemp()
    for rule_id in ("1001", "1002", "1003"):
        append_alert_history(
            {
                "timestamp": "2026-09-13T10:00:00Z",
                "windows_event_id": 4625,
                "severity": "high",
                "rule_id": rule_id,
            },
            tmp5,
        )
    path5 = history_file_path(tmp5, "2026-09-13", "alerts")
    with open(path5, "r", encoding="utf-8") as f:
        linhas5 = f.readlines()
    check("Append acumula 3 linhas em vez de sobrescrever", len(linhas5) == 3)
    check(
        "Todas as 3 linhas são JSON válido",
        all(_is_valid_json(linha) for linha in linhas5),
    )

    # --- 6. Timestamp em falta ou inválido não rebenta ---
    tmp6 = tempfile.mkdtemp()
    try:
        append_alert_history({"windows_event_id": 4625, "severity": "high"}, tmp6)
        sem_excecao_sem_timestamp = True
    except Exception:
        sem_excecao_sem_timestamp = False
    check(
        "append_alert_history sem 'timestamp' não levanta exceção",
        sem_excecao_sem_timestamp,
    )

    # Encontra o ficheiro criado (data de hoje, nome desconhecido a priori)
    ficheiros6 = list(Path(tmp6).rglob("*.jsonl"))
    check("Um ficheiro .jsonl foi criado sem timestamp", len(ficheiros6) == 1)
    if ficheiros6:
        record6 = json.loads(ficheiros6[0].read_text(encoding="utf-8").splitlines()[0])
        check(
            "record.date existe e é string não vazia (sem timestamp)",
            isinstance(record6.get("date"), str) and record6.get("date") != "",
        )
        check(
            "record.time existe e é string não vazia (sem timestamp)",
            isinstance(record6.get("time"), str) and record6.get("time") != "",
        )
        check("record.event_id == 4625 (sem timestamp)", record6.get("event_id") == 4625)
        check("record.severity == high (sem timestamp)", record6.get("severity") == "high")
        check(
            "record.agent_name é None quando ausente (sem timestamp)",
            record6.get("agent_name") is None,
        )
        check(
            "record.friendly_name é None quando ausente (sem timestamp)",
            record6.get("friendly_name") is None,
        )
        check(
            "record.rule_id é None quando ausente (sem timestamp)",
            record6.get("rule_id") is None,
        )

    tmp6b = tempfile.mkdtemp()
    try:
        append_alert_history(
            {"timestamp": "isto-nao-e-uma-data", "windows_event_id": 4625, "severity": "high"},
            tmp6b,
        )
        sem_excecao_timestamp_invalido = True
    except Exception:
        sem_excecao_timestamp_invalido = False
    check(
        "append_alert_history com timestamp inválido não levanta exceção",
        sem_excecao_timestamp_invalido,
    )
    ficheiros6b = list(Path(tmp6b).rglob("*.jsonl"))
    check("Um ficheiro .jsonl foi criado com timestamp inválido", len(ficheiros6b) == 1)
    if ficheiros6b:
        record6b = json.loads(ficheiros6b[0].read_text(encoding="utf-8").splitlines()[0])
        check(
            "record.date existe e é string não vazia (timestamp inválido)",
            isinstance(record6b.get("date"), str) and record6b.get("date") != "",
        )
        check(
            "record.time existe e é string não vazia (timestamp inválido)",
            isinstance(record6b.get("time"), str) and record6b.get("time") != "",
        )

    # --- 7. append_alerts_history (batch) escreve N linhas para N alertas ---
    tmp7 = tempfile.mkdtemp()
    alertas7 = [
        {"timestamp": "2026-09-13T08:00:00Z", "windows_event_id": 4625, "rule_id": "a"},
        {"timestamp": "2026-09-13T09:00:00Z", "windows_event_id": 4625, "rule_id": "b"},
        {"timestamp": "2026-09-13T10:00:00Z", "windows_event_id": 4625, "rule_id": "c"},
    ]
    append_alerts_history(alertas7, tmp7)
    path7 = history_file_path(tmp7, "2026-09-13", "alerts")
    with open(path7, "r", encoding="utf-8") as f:
        linhas7 = f.readlines()
    check("append_alerts_history escreve 3 linhas para 3 alertas", len(linhas7) == 3)

    # --- 8. Dois dias diferentes geram dois ficheiros diferentes ---
    tmp8 = tempfile.mkdtemp()
    append_alerts_history(
        [
            {"timestamp": "2026-09-13T23:00:00Z", "windows_event_id": 4625, "rule_id": "dia13"},
            {"timestamp": "2026-09-14T01:00:00Z", "windows_event_id": 4625, "rule_id": "dia14"},
        ],
        tmp8,
    )
    path8_dia13 = history_file_path(tmp8, "2026-09-13", "alerts")
    path8_dia14 = history_file_path(tmp8, "2026-09-14", "alerts")
    check(
        "Dois dias diferentes produzem dois ficheiros .jsonl distintos",
        path8_dia13 != path8_dia14
        and os.path.isfile(path8_dia13)
        and os.path.isfile(path8_dia14),
    )
    with open(path8_dia13, "r", encoding="utf-8") as f:
        check("Ficheiro do dia 13 tem 1 linha", len(f.readlines()) == 1)
    with open(path8_dia14, "r", encoding="utf-8") as f:
        check("Ficheiro do dia 14 tem 1 linha", len(f.readlines()) == 1)

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")
    sys.exit(0)


def _is_valid_json(linha: str) -> bool:
    try:
        json.loads(linha)
        return True
    except json.JSONDecodeError:
        return False


if __name__ == "__main__":
    run()
