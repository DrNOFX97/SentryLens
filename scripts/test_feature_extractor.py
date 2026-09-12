"""
Testes de regressão do feature_extractor.py, isolado (sem Wazuh, sem
modelo treinado). Segue o estilo de test_with_mock.py: script standalone,
check()/[OK]/[FALHOU], sys.exit(1) em caso de falha.

Correr:
    python test_feature_extractor.py
"""

import sys

from event_catalog import CRITICAL_EVENTS
from feature_extractor import FEATURE_NAMES, extract_features, label_with_attack_log, load_attack_log, vectorize

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def alert(event_id: int, ts: str, user: str = "jsilva", ip: str = "192.168.1.10", agent_ip: str = "192.168.1.5") -> dict:
    return {
        "@timestamp": ts,
        "agent": {"name": "WIN-PC01", "ip": agent_ip},
        "rule": {"id": "1", "description": "x", "level": 5},
        "data": {"win": {"system": {"eventID": str(event_id)}, "eventdata": {"targetUserName": user, "ipAddress": ip}}},
        "full_log": "x",
    }


def run() -> None:
    # --- hour_of_day / day_of_week ---
    feats = extract_features([alert(4624, "2026-09-10T14:05:00Z")])  # 2026-09-10 is a Thursday
    check("extract_features devolve 1 linha para 1 alerta", len(feats) == 1)
    check("hour_of_day extraído corretamente (14h)", feats[0]["hour_of_day"] == 14)
    check("day_of_week extraído corretamente (Thursday = 3)", feats[0]["day_of_week"] == 3)

    # --- event_id_encoded é determinístico e vem do event_catalog partilhado ---
    known_order = sorted(CRITICAL_EVENTS.keys())
    feats_4625 = extract_features([alert(4625, "2026-09-10T14:05:00Z")])
    check("event_id_encoded(4625) == posição de 4625 em CRITICAL_EVENTS ordenado",
          feats_4625[0]["event_id_encoded"] == known_order.index(4625))

    feats_unknown = extract_features([alert(9999, "2026-09-10T14:05:00Z")])
    check("event_id_encoded para Event ID desconhecido usa o bucket 'outro' (len(known_order))",
          feats_unknown[0]["event_id_encoded"] == len(known_order))

    # --- failed_attempts_last_hour ---
    burst = [alert(4625, f"2026-09-10T10:0{i}:00Z", user="admin") for i in range(5)]
    burst_feats = extract_features(burst)
    check("1ª falha do burst conta 1 (inclui-se a si própria)", burst_feats[0]["failed_attempts_last_hour"] == 1)
    check("5ª falha do burst conta 5 (todas dentro da mesma hora)", burst_feats[4]["failed_attempts_last_hour"] == 5)

    other_user = alert(4625, "2026-09-10T10:02:00Z", user="guest")
    mixed_feats = extract_features(burst[:2] + [other_user])
    check("utilizador diferente não herda a contagem de outro utilizador",
          mixed_feats[-1]["failed_attempts_last_hour"] == 1)

    far_apart = [alert(4625, "2026-09-10T08:00:00Z", user="admin"), alert(4625, "2026-09-10T10:00:00Z", user="admin")]
    far_feats = extract_features(far_apart)
    check("falha 2h depois não conta a falha anterior (fora da janela de 1h)",
          far_feats[1]["failed_attempts_last_hour"] == 1)

    # --- has_special_privileges ---
    priv_feats = extract_features([alert(4672, "2026-09-10T14:05:00Z")])
    check("4672 (atividade_privilegiada) marca has_special_privileges=1", priv_feats[0]["has_special_privileges"] == 1)
    non_priv_feats = extract_features([alert(4624, "2026-09-10T14:05:00Z")])
    check("4624 (autenticacao) marca has_special_privileges=0", non_priv_feats[0]["has_special_privileges"] == 0)

    # --- is_new_source_ip ---
    same_user_diff_ip = [
        alert(4624, "2026-09-10T09:00:00Z", user="mcosta", ip="10.0.0.1"),
        alert(4624, "2026-09-10T09:05:00Z", user="mcosta", ip="10.0.0.1"),
        alert(4624, "2026-09-10T09:10:00Z", user="mcosta", ip="10.0.0.2"),
    ]
    ip_feats = extract_features(same_user_diff_ip)
    check("1º IP visto para o utilizador é sempre 'novo'", ip_feats[0]["is_new_source_ip"] == 1)
    check("repetir o mesmo IP não é 'novo'", ip_feats[1]["is_new_source_ip"] == 0)
    check("IP diferente para o mesmo utilizador volta a ser 'novo'", ip_feats[2]["is_new_source_ip"] == 1)

    # --- severity_encoded ---
    high_feats = extract_features([alert(4726, "2026-09-10T09:00:00Z")])  # 4726 = high
    low_feats = extract_features([alert(4624, "2026-09-10T09:00:00Z")])  # 4624 = low
    check("severidade 'high' codifica maior que 'low'", high_feats[0]["severity_encoded"] > low_feats[0]["severity_encoded"])

    # --- rule_flagged reflete a classificação de severidade alta ---
    check("rule_flagged é True para eventos 'high'", high_feats[0]["rule_flagged"] is True)
    check("rule_flagged é False para eventos 'low'", low_feats[0]["rule_flagged"] is False)

    # --- ordem/consistência do vetor ---
    check("FEATURE_NAMES tem 7 features, na ordem do contrato", FEATURE_NAMES == [
        "hour_of_day", "day_of_week", "event_id_encoded", "failed_attempts_last_hour",
        "has_special_privileges", "is_new_source_ip", "severity_encoded",
    ])
    vectors = vectorize(ip_feats)
    check("vectorize devolve um vetor por linha, do tamanho de FEATURE_NAMES",
          len(vectors) == len(ip_feats) and all(len(v) == len(FEATURE_NAMES) for v in vectors))

    # --- label_with_attack_log ---
    events = [
        alert(4625, "2026-09-10T10:00:00Z", user="convidado"),
        alert(4625, "2026-09-10T10:01:00Z", user="convidado"),
        alert(4624, "2026-09-10T12:00:00Z", user="mcosta"),  # fora de qualquer janela de ataque
    ]
    features = extract_features(events)
    attack_log = [{"timestamp": "2026-09-10T10:00:00+00:00", "scenario": "brute_force_rdp", "target": "x", "tool": "hydra", "status": "launched", "details": {}}]
    labeled = label_with_attack_log(features, attack_log, window_seconds=120)
    check("evento dentro da janela de ataque fica is_attack=1", labeled[0]["is_attack"] == 1 and labeled[1]["is_attack"] == 1)
    check("evento fora da janela de ataque fica is_attack=0", labeled[2]["is_attack"] == 0)

    # --- load_attack_log lê JSONL ---
    import tempfile, os
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False, encoding="utf-8") as tmp:
        tmp.write('{"timestamp": "2026-09-10T10:00:00+00:00", "scenario": "x", "target": "y", "tool": "z", "status": "launched", "details": {}}\n')
        tmp_path = tmp.name
    loaded = load_attack_log(tmp_path)
    os.unlink(tmp_path)
    check("load_attack_log lê uma entrada por linha", len(loaded) == 1 and loaded[0]["scenario"] == "x")

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")
    sys.exit(0)


if __name__ == "__main__":
    run()
