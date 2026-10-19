"""
Consistência do MTTD entre painéis (U5/P4 da auditoria do frontend).

Fonte única: GET /api/metrics (soc_metrics.build_metrics_report), mediana de
min(deteção por regra/ML, deteção por rede) por tentativa, janela hours=168.
Overview, Incidentes, Red vs Blue e Métricas lêem todos este bloco.

Cobre (sem Wazuh, tudo mockado):
  - a API devolve o mesmo MTTD para a mesma janela, em chamadas repetidas e
    com ou sem o parâmetro `hours` explícito;
  - a rota coincide com build_metrics_report sobre o mesmo relatório;
  - a fórmula inclui a rede (min das fontes), ao contrário da média de
    /api/redblue/metrics (só regra/ML) que o Red vs Blue usava antes;
  - o teste node:vm (test_mttd_consistency.cjs) que carrega os 4 módulos.

Correr (a partir de scripts/):
    python test_mttd_consistency.py
"""

import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

os.environ.setdefault("SENTRYLENS_API_KEY", "chave-de-teste-nao-usar-em-producao")

from fastapi.testclient import TestClient

import main
import soc_metrics
from incident_store import IncidentStore
from redblue_correlator import build_redblue_report
from attack_scenarios import SCENARIOS

main.app.router.on_startup.clear()

ROOT = Path(__file__).resolve().parent.parent
failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


NOW = datetime.now(timezone.utc)
TARGET = "192.168.1.20"


def iso(delta_seconds: float) -> str:
    return (NOW + timedelta(seconds=delta_seconds)).isoformat()


ATTACK = {"timestamp": iso(-3600), "scenario": "brute_force_rdp", "target": TARGET,
          "tool": "hydra", "status": "launched", "details": {}}
ML_RESULT = {"timestamp": iso(-3600 + 90), "agent_ip": TARGET, "windows_event_id": 4625,
             "rule_flagged": True, "ml_is_anomaly": False}


def wire(store, network=None) -> None:
    main.indexer_client = MagicMock()
    main.indexer_client.get_recent_alerts = AsyncMock(return_value=[])
    main.ml_anomalies.load_model = lambda _dir: (None, None)
    main.ml_anomalies.build_ml_anomalies_report = lambda alerts, model, scaler: {"results": [ML_RESULT]}
    main.load_attack_log = lambda _path: [ATTACK]
    main.vm_ssh_client = None
    main.incident_store = store


def run() -> None:
    import tempfile

    store = IncidentStore(os.path.join(tempfile.mkdtemp(), "i.sqlite3"))
    wire(store)
    client = TestClient(main.app, headers={"X-API-Key": os.environ["SENTRYLENS_API_KEY"]})

    first = client.get("/api/metrics?hours=168").json()
    again = client.get("/api/metrics?hours=168").json()
    default = client.get("/api/metrics").json()
    check("MTTD = 90 s (1.º alerta sinalizado - ataque)", first["mttd"]["median_s"] == 90.0)
    check("mesma janela, chamadas repetidas -> mesmo MTTD", first["mttd"] == again["mttd"])
    check("hours omitido == hours=168 (todos os painéis usam 168)", first["mttd"] == default["mttd"]
          and first["window_hours"] == default["window_hours"] == 168)

    # A rota == função pura sobre o mesmo relatório Red vs Blue.
    report = build_redblue_report([ATTACK], [ML_RESULT], SCENARIOS, network_detections=None)
    pure = soc_metrics.build_metrics_report(report, [], 168)
    check("rota == soc_metrics.build_metrics_report (mesmo median_s e n)",
          first["mttd"]["median_s"] == pure["mttd"]["median_s"] and first["mttd"]["n"] == pure["mttd"]["n"])

    # Fórmula: a rede conta (mínimo entre fontes). Antes o Red vs Blue fazia a
    # média de mttd_seconds (só regra/ML) e dava 90 s aqui; o correto é 30 s.
    attempt = {"scenario": "brute_force_rdp", "mitre_technique": "T1110", "detected": True,
               "detected_by": "rule", "mttd_seconds": 90.0,
               "detected_by_network": True, "mttd_network_seconds": 30.0}
    net = soc_metrics.build_metrics_report({"attempts": [attempt]}, [], 168)
    check("MTTD usa a deteção mais cedo (rede 30 s < regra 90 s)", net["mttd"]["median_s"] == 30.0)

    # Sem amostra: None (o frontend mostra «—»), nunca 0.
    empty = soc_metrics.build_metrics_report({"attempts": []}, [], 168)
    check("sem amostra: median_s None e available False", empty["mttd"]["median_s"] is None
          and empty["mttd"]["available"] is False)

    # Contrato estático: os 4 painéis passam por slMttdView (nada de médias locais).
    for name, needle in (("overview.js", "slMttdView"), ("incidents.js", "slMttdView"),
                         ("redblue.js", "slMttdView"), ("metrics.js", "slMttdView")):
        text = (ROOT / name).read_text(encoding="utf-8")
        check(f"{name} usa slMttdView", needle in text)
    check("incidents.js já não mostra summary.avg_mttd_seconds no KPI",
          'incSetText("kpi-inc-mttd"' not in (ROOT / "incidents.js").read_text(encoding="utf-8"))
    check("redblue.js já não mostra sum.avgMttd no KPI",
          'rbSetText("kpi-rb-mttd"' not in (ROOT / "redblue.js").read_text(encoding="utf-8"))

    # Teste node:vm sobre os módulos reais.
    node = shutil.which("node")
    if node is None:
        check("node não encontrado no PATH — instala Node.js", False)
        return
    proc = subprocess.run([node, str(Path(__file__).with_name("test_mttd_consistency.cjs")), str(ROOT)],
                          capture_output=True, text=True, encoding="utf-8", timeout=60)
    sys.stdout.write(proc.stdout)
    if proc.stderr:
        sys.stdout.write(proc.stderr)
    check("test_mttd_consistency.cjs passou (4 painéis, mesmo valor)", proc.returncode == 0)


if __name__ == "__main__":
    run()
    if failures:
        print(f"\n[FALHOU] {len(failures)} teste(s) falharam")
        sys.exit(1)
    print("\n[OK] Todos os testes passaram")
