"""
Gera os ficheiros de dados de treino/avaliação usados por
train_anomaly_model.py enquanto o laboratório Wazuh real não produz
dados suficientes (ver nota de desvio no README: substitui o
`sample_events_real.xml` do contrato original, que nunca existiu neste
repositório, por um fixture JSON no formato que o Wazuh Indexer
realmente devolve).

Determinístico (sem random) para que o dataset gerado seja sempre igual
e o relatório de métricas em ml_training_report.json seja reprodutível.

Corre-se uma única vez (ou sempre que se quiser reconstruir os
fixtures):
    python _generate_sample_ml_data.py
"""

import json
from pathlib import Path

OUTPUT_EVENTS = Path(__file__).parent / "sample_events_real.json"
OUTPUT_ATTACK_LOG = Path(__file__).parent / "sample_attack_log.jsonl"


def _event(event_id: int, ts: str, agent: str = "WIN-PC01", agent_ip: str = "192.168.1.5",
           user: str | None = None, ip: str | None = None, level: int = 5) -> dict:
    eventdata = {}
    if user is not None:
        eventdata["targetUserName"] = user
    if ip is not None:
        eventdata["ipAddress"] = ip
    return {
        "@timestamp": ts,
        "agent": {"name": agent, "ip": agent_ip},
        "rule": {"id": str(1000 + event_id), "description": f"Event {event_id}", "level": level},
        "data": {"win": {"system": {"eventID": str(event_id)}, "eventdata": eventdata}},
        "full_log": f"Synthetic event {event_id}",
    }


def build_events() -> list[dict]:
    events: list[dict] = []

    # --- Atividade normal: logons de sucesso em horário de expediente ---
    normal_logons = [
        ("mcosta", "192.168.1.10", "2026-09-01T09:0{}:00Z"),
        ("jsilva", "192.168.1.11", "2026-09-01T09:1{}:00Z"),
        ("adm.rsantos", "192.168.1.12", "2026-09-01T08:3{}:00Z"),
    ]
    for user, ip, ts_template in normal_logons:
        for i in range(3):
            events.append(_event(4624, ts_template.format(i), user=user, ip=ip, level=3))

    events.append(_event(4720, "2026-09-01T10:00:00Z", user="novo.colaborador", level=5))
    events.append(_event(4738, "2026-09-01T10:05:00Z", user="mcosta", level=5))
    events.append(_event(5140, "2026-09-01T11:00:00Z", user="jsilva", ip="192.168.1.11", level=3))
    events.append(_event(5140, "2026-09-01T11:05:00Z", user="jsilva", ip="192.168.1.11", level=3))
    events.append(_event(4725, "2026-09-01T15:00:00Z", user="ex.colaborador", level=5))
    events.append(_event(4767, "2026-09-01T15:30:00Z", user="mcosta", level=3))

    # --- Cenário de ataque A: força bruta RDP contra 'convidado', 03:00 ---
    for i in range(6):
        events.append(_event(4625, f"2026-09-02T03:0{i}:00Z", user="convidado", ip="203.0.113.50", level=10))
    events.append(_event(4740, "2026-09-02T03:06:00Z", user="convidado", ip="203.0.113.50", level=10))

    # --- Cenário de ataque B: pós-comprometimento fora de horário, 03:14 ---
    events.append(_event(4672, "2026-09-02T03:14:00Z", user="adm.rsantos", ip="203.0.113.50", level=12))
    events.append(_event(4698, "2026-09-02T03:15:00Z", user="adm.rsantos", ip="203.0.113.50", level=12))

    # --- Mais atividade normal noutro dia, para dar volume à classe normal ---
    for i in range(8):
        events.append(_event(4624, f"2026-09-03T{9 + i // 2}:0{(i % 2) * 3}0:00Z", user="mcosta", ip="192.168.1.10", level=3))
    for i in range(4):
        events.append(_event(4624, f"2026-09-03T1{i}:00:00Z", user="jsilva", ip="192.168.1.11", level=3))

    return events


def build_attack_log() -> list[dict]:
    return [
        {
            "timestamp": "2026-09-02T03:00:00+00:00",
            "scenario": "brute_force_rdp",
            "target": "203.0.113.50",
            "tool": "hydra",
            "status": "launched",
            "details": {"returncode": 0, "command": "hydra ... rdp://192.168.1.5"},
        },
        {
            "timestamp": "2026-09-02T03:14:00+00:00",
            "scenario": "lateral_movement_schtasks",
            "target": "192.168.1.5",
            "tool": "crackmapexec",
            "status": "launched",
            "details": {"returncode": 0, "command": "crackmapexec smb ..."},
        },
    ]


def main() -> None:
    events = build_events()
    with open(OUTPUT_EVENTS, "w", encoding="utf-8") as handle:
        json.dump(events, handle, ensure_ascii=False, indent=2)

    attack_log = build_attack_log()
    with open(OUTPUT_ATTACK_LOG, "w", encoding="utf-8") as handle:
        for entry in attack_log:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")

    print(f"{len(events)} eventos escritos em {OUTPUT_EVENTS}")
    print(f"{len(attack_log)} entradas de ataque escritas em {OUTPUT_ATTACK_LOG}")


if __name__ == "__main__":
    main()
