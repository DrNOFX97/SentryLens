"""
Testes de soc_metrics (R8): MTTD/MTTR, cobertura e taxa de deteção (função
pura). Sem laboratório Wazuh nem base de dados.

Correr (a partir de scripts/):
    python test_soc_metrics.py
"""

import sys

from soc_metrics import build_metrics_report, duration_block, median, percentile_nearest_rank

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def att(scenario, technique, detected_by="none", net=False, mttd=None, mttd_net=None, detected=None):
    return {
        "scenario": scenario, "mitre_technique": technique,
        "detected": (detected_by != "none") if detected is None else detected,
        "detected_by": detected_by, "detected_by_network": net,
        "mttd_seconds": mttd, "mttd_network_seconds": mttd_net,
    }


def report(attempts, not_executed=(), unknown=(), invalid=()):
    return {"attempts": list(attempts), "not_executed": list(not_executed),
            "unknown_scenario": list(unknown), "invalid_entries": list(invalid)}


def inc(status, first="2026-10-09T10:00:00+00:00", events=(), ttfr=None):
    return {
        "status": status, "first_evidence_at": first, "time_to_first_response_seconds": ttfr,
        "timeline": [{"kind": "status_changed", "ts": ts, "data": {"from": f, "to": t}} for (ts, f, t) in events],
    }


def run() -> None:
    # --- estatística base ---
    check("mediana ímpar", median([3, 1, 2]) == 2)
    check("mediana par", median([1, 2, 3, 4]) == 2.5)
    check("mediana vazia -> None", median([]) is None)
    check("p90 nearest-rank de 4 valores = 4", percentile_nearest_rank([1, 2, 3, 4], 90) == 4)
    check("p90 de 1 valor = o valor", percentile_nearest_rank([7], 90) == 7)
    b = duration_block([7], 5)
    check("n=1: mediana=p90=média e small_sample",
          b["n"] == 1 and b["median_s"] == 7 and b["p90_s"] == 7 and b["avg_s"] == 7 and b["small_sample"] is True)
    b0 = duration_block([None, None], 5)
    check("sem amostra: available False, reason no_data, valores None (nunca 0)",
          b0["available"] is False and b0["reason"] == "no_data" and b0["median_s"] is None and b0["n"] == 0)

    # --- fontes em baixo ---
    r = build_metrics_report(None, None, 168, min_sample=5)
    check("fontes em baixo: mttd/coverage/rate/mttr com source_unavailable",
          all(r[k]["available"] is False and r[k]["reason"] == "source_unavailable"
              for k in ("mttd", "coverage", "rate", "mttr")))
    check("fontes em baixo: FP indisponível",
          r["rate"]["false_positives"]["available"] is False and r["rate"]["false_positives"]["pct"] is None)
    check("relatório traz window_hours, min_sample e definições",
          r["window_hours"] == 168 and r["min_sample"] == 5 and set(r["definitions"]) >= {"mttd", "mttr", "fp", "fn"})

    # --- truncagem dos alertas: a taxa passa a ser um limite inferior ---
    check("alerts_truncated por omissao False", build_metrics_report(report([]), [], 168)["alerts_truncated"] is False)
    check("alerts_truncated propaga-se", build_metrics_report(report([]), [], 168, alerts_truncated=True)["alerts_truncated"] is True)

    # --- fontes ok mas vazias ---
    r = build_metrics_report(report([]), [], 168, min_sample=5)
    check("vazio: mttd no_data", r["mttd"]["available"] is False and r["mttd"]["reason"] == "no_data")
    check("vazio: rate sem divisão por zero, detection_pct None",
          r["rate"]["launched"] == 0 and r["rate"]["detection_pct"] is None)
    check("vazio: cobertura no_data", r["coverage"]["available"] is False and r["coverage"]["reason"] == "no_data")
    check("vazio: mttr open_count 0 e sem mediana", r["mttr"]["open_count"] == 0 and r["mttr"]["median_s"] is None)

    # --- MTTD: deteção mais cedo de qualquer fonte; não sinalizado fora ---
    attempts = [
        att("s1", "T1", "rule", mttd=10),
        att("s1", "T1", "ml", mttd=20),
        att("s2", "T2", "none", net=True, mttd_net=5),
        att("s3", "T3", "rule", net=True, mttd=30, mttd_net=12),
        att("s4", "T4", "none", mttd=3, detected=True),   # alerta não sinalizado: não é deteção
        att("s5", "T5", "none"),                            # não detetado
    ]
    r = build_metrics_report(report(attempts), [], 168, min_sample=2)
    m = r["mttd"]
    check("MTTD: n=4 (rule, ml, só-rede, rule+rede->12)", m["n"] == 4)
    check("MTTD: tempos [10,20,5,12] -> mediana 11.0", m["median_s"] == 11.0)
    check("MTTD: p90 nearest-rank = 20", m["p90_s"] == 20)
    check("MTTD: média 11.75", m["avg_s"] == 11.75)
    check("MTTD: n>=min_sample -> small_sample False", m["small_sample"] is False)
    check("MTTD por cenário s1: n=2, mediana 15", m["by_scenario"]["s1"]["n"] == 2 and m["by_scenario"]["s1"]["median_s"] == 15.0)
    check("MTTD por cenário s5 (nunca detetado): no_data", m["by_scenario"]["s5"]["available"] is False)

    # --- cobertura ---
    r = build_metrics_report(report(attempts), [], 168, min_sample=2)
    c = r["coverage"]
    check("cobertura de cenários: 3/5 (s1,s2,s3)", c["scenarios"]["covered"] == 3 and c["scenarios"]["total"] == 5)
    check("cobertura de cenários pct 60.0", c["scenarios"]["pct"] == 60.0)
    check("lacunas de cenário: s4 (só alerta não sinalizado) e s5", c["gaps"]["scenarios"] == ["s4", "s5"])
    check("lacunas de técnica: T4, T5", c["gaps"]["techniques"] == ["T4", "T5"])
    mixed = [att("s1", "T1", "rule", mttd=1), att("s1", "T1", "none")]
    check("cenário detetado numa tentativa e falhado noutra conta como coberto",
          build_metrics_report(report(mixed), [], 168)["coverage"]["scenarios"]["covered"] == 1)

    # --- taxa de deteção ---
    rate_attempts = [
        att("a", "T1", "rule", mttd=1), att("a", "T1", "ml", mttd=1), att("b", "T2", "both", mttd=1),
        att("c", "T3", "none", net=True, mttd_net=2), att("d", "T4", "none"),
    ]
    r = build_metrics_report(report(rate_attempts, not_executed=["x"], unknown=["y", "z"]), [], 168, min_sample=5)
    rt = r["rate"]
    check("taxa: 5 lançados, 4 detetados, 1 não detetado",
          rt["launched"] == 5 and rt["detected"] == 4 and rt["not_detected"] == 1)
    check("taxa: false_negatives == not_detected", rt["false_negatives"] == 1)
    check("taxa: 80.0 %", rt["detection_pct"] == 80.0)
    check("taxa por fonte: rule1 ml1 network1 multiple1",
          rt["by_source"] == {"rule": 1, "ml": 1, "network": 1, "multiple": 1})
    check("taxa: excluded conta not_executed/unknown/invalid fora do denominador",
          rt["excluded"] == {"not_executed": 1, "unknown_scenario": 2, "invalid_entries": 0})
    check("taxa: 5 lançados com min_sample=5 -> small_sample False", rt["small_sample"] is False)
    check("taxa: 3 lançados com min_sample=5 -> small_sample True",
          build_metrics_report(report(rate_attempts[:3]), [], 168, min_sample=5)["rate"]["small_sample"] is True)

    # --- MTTR e FP ---
    t0 = "2026-10-09T10:00:00+00:00"
    incidents = [
        inc("RESOLVED", t0, [("2026-10-09T10:01:00+00:00", "NEW", "INVESTIGATING"),
                             ("2026-10-09T10:05:00+00:00", "INVESTIGATING", "RESOLVED")], ttfr=60),
        inc("CLOSED", t0, [("2026-10-09T10:02:00+00:00", "NEW", "INVESTIGATING"),
                           ("2026-10-09T10:10:00+00:00", "INVESTIGATING", "RESOLVED"),
                           ("2026-10-09T10:20:00+00:00", "RESOLVED", "CLOSED")], ttfr=120),
        inc("INVESTIGATING", t0, [("2026-10-09T10:01:00+00:00", "NEW", "INVESTIGATING")], ttfr=60),
        inc("CLOSED", t0, [("2026-10-09T10:03:00+00:00", "NEW", "CLOSED")]),                       # falso positivo
        inc("INVESTIGATING", t0, [("2026-10-09T10:01:00+00:00", "NEW", "INVESTIGATING"),            # reaberto
                                  ("2026-10-09T10:04:00+00:00", "INVESTIGATING", "RESOLVED"),
                                  ("2026-10-09T10:06:00+00:00", "RESOLVED", "INVESTIGATING")]),
        inc("RESOLVED", t0, [("2026-10-09T10:01:00+00:00", "NEW", "INVESTIGATING"),                 # 2 resoluções: conta a última
                             ("2026-10-09T10:04:00+00:00", "INVESTIGATING", "RESOLVED"),
                             ("2026-10-09T10:05:00+00:00", "RESOLVED", "INVESTIGATING"),
                             ("2026-10-09T10:15:00+00:00", "INVESTIGATING", "RESOLVED")]),
    ]
    r = build_metrics_report(report([]), incidents, 168, min_sample=2)
    mr = r["mttr"]
    check("MTTR: 3 resolvidos (300, 600, 900 s)", mr["n"] == 3 and mr["median_s"] == 600.0 and mr["avg_s"] == 600.0)
    check("MTTR: p90 = 900", mr["p90_s"] == 900.0)
    check("MTTR: abertos (INVESTIGATING x2) contados à parte", mr["open_count"] == 2)
    check("1.ª resposta: n=3 (60,120,60) mediana 60", mr["first_response"]["n"] == 3 and mr["first_response"]["median_s"] == 60.0)
    fp = r["rate"]["false_positives"]
    check("FP: 1 em 2 fechados (o outro CLOSED veio de RESOLVED)", fp["n"] == 1 and fp["closed_total"] == 2)
    check("FP: pct 50.0 com amostra suficiente", fp["pct"] == 50.0 and fp["small_sample"] is False)
    fp5 = build_metrics_report(report([]), incidents, 168, min_sample=5)["rate"]["false_positives"]
    check("FP: abaixo do mínimo de amostra não calcula pct", fp5["pct"] is None and fp5["small_sample"] is True)

    # --- timestamps inválidos não rebentam ---
    bad = [inc("RESOLVED", "lixo", [("2026-10-09T10:05:00+00:00", "INVESTIGATING", "RESOLVED")])]
    check("MTTR com first_evidence_at inválido é ignorado (sem exceção)",
          build_metrics_report(report([]), bad, 168)["mttr"]["n"] == 0)


if __name__ == "__main__":
    run()
    if failures:
        print(f"\n{len(failures)} caso(s) falharam.")
        sys.exit(1)
    print("\nTodos os casos passaram.")
