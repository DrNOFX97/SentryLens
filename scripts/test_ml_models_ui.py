"""
Wrapper dos testes de UI do registo de modelos (ml_models.js e
ml_evaluation.js).

O run_all_tests.py só descobre test_*.py, por isso este ficheiro é a ponte
para o teste Node scripts/test_ml_models_ui.cjs: monta um registo real num
directório temporário, pede-o a GET /api/ml/models com TestClient e escreve
as respostas em report_v1.json / report_empty.json / report_legacy.json, que
o .cjs usa como fixtures. Assim os helpers puros de ml_models.js são testados
contra o JSON verdadeiro da rota, não contra um JSON escrito à mão.

A quarta fixture, report_evaluated.json, é o fecho do caminho da Fase 2: num
registo temporário com duas versões, o comando `python model_registry.py
evaluate v1` é corrido A SÉRIO (com pickles reais e o motor de avaliação
completo) e só depois é pedida a rota. O stdout do comando vai para
evaluate_stdout.txt, para o .cjs poder confirmar que a linha da tabela mostra
as mesmas percentagens que o CLI imprimiu.

Nunca toca no scripts/models real. Sem `node` no PATH falha com mensagem
explícita (fail-closed) — nunca passa em silêncio.

As três fixtures ml_report_ok.json / ml_report_vazio.json /
ml_report_truncado.json são as respostas REAIS de GET /api/ml-anomalies nos
três estados da janela (com amostra / vazia / a encher o tecto de 1000
alertas), com o Indexer mockado e o modelo treinado em memória — o bloco de
concordância ao vivo (D-10) é testado contra a rota, não contra um JSON
escrito à mão.

Correr (a partir de scripts/):
    python test_ml_models_ui.py
"""

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock

os.environ.setdefault("SENTRYLENS_API_KEY", "chave-de-teste-nao-usar-em-producao")

import joblib
from fastapi.testclient import TestClient

import main
from feature_extractor import extract_features, vectorize
from train_anomaly_model import train_model

main.app.router.on_startup.clear()

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def make_version(root, vid, model_bytes=b"fake-model", scaler_bytes=b"fake-scaler") -> Path:
    """models/vN/ com os dois .pkl e um metadata.json coerente (schema 1)."""
    version_dir = Path(root) / vid
    version_dir.mkdir(parents=True, exist_ok=True)
    (version_dir / "isolation_forest.pkl").write_bytes(model_bytes)
    (version_dir / "scaler.pkl").write_bytes(scaler_bytes)
    meta = {
        "schema_version": 1,
        "version": vid,
        "origin": "adopted",
        "adopted": True,
        "created_at": "2026-10-09T21:00:00+00:00",
        "trained_at": "2026-09-14T15:40:00+00:00",
        "trained_at_estimated": True,
        "model_type": "IsolationForest",
        "parameters": None,
        "dataset": {"name": None, "size": None, "attacks": None, "synthetic": None},
        "library_versions": None,
        "artifacts": {
            "isolation_forest.pkl": {
                "sha256": hashlib.sha256(model_bytes).hexdigest(),
                "size_bytes": len(model_bytes),
            },
            "scaler.pkl": {
                "sha256": hashlib.sha256(scaler_bytes).hexdigest(),
                "size_bytes": len(scaler_bytes),
            },
        },
        "evaluation": None,
    }
    (version_dir / "metadata.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return version_dir


def make_legacy(root) -> Path:
    """Os dois .pkl soltos em models/ — o "legado", sem metadados (REG-02)."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    (root / "isolation_forest.pkl").write_bytes(b"fake-model")
    (root / "scaler.pkl").write_bytes(b"fake-scaler")
    return root


# Alertas mockados no mesmo formato do Wazuh Indexer.
def alerta(event_id: int, ts: str, user: str = "jsilva", ip: str = "192.168.1.10") -> dict:
    return {
        "@timestamp": ts,
        "agent": {"name": "WIN-PC01", "ip": "192.168.1.5"},
        "rule": {"id": "1", "description": "x", "level": 5},
        "data": {"win": {"system": {"eventID": str(event_id)},
                         "eventdata": {"targetUserName": user, "ipAddress": ip}}},
        "full_log": "x",
    }


MOCK_ALERTS = (
    [alerta(4624, f"2026-09-01T09:0{i}:00Z", user="mcosta") for i in range(4)]
    + [alerta(4625, f"2026-09-02T03:0{i}:00Z", user="convidado", ip="203.0.113.50")
       for i in range(6)]
)


def real_model_bytes() -> tuple[bytes, bytes]:
    """Bytes de .pkl verdadeiros: um IsolationForest minúsculo treinado sobre
    os MOCK_ALERTS, dumpado para BytesIO. Sem isto o `evaluate` a sério não
    teria o que carregar."""
    model, scaler = train_model(
        vectorize(extract_features(MOCK_ALERTS)), contamination=0.3, random_state=1)
    buf_model, buf_scaler = io.BytesIO(), io.BytesIO()
    joblib.dump(model, buf_model)
    joblib.dump(scaler, buf_scaler)
    return buf_model.getvalue(), buf_scaler.getvalue()


# Tecto do pedido ao Indexer: o mesmo de get_recent_alerts(size=1000) em
# main.py, e o mesmo critério de alerts_truncated.
TETO_ALERTAS = 1000


def ml_anomalies_fixtures(client, out_dir) -> None:
    """Escreve as três respostas de GET /api/ml-anomalies que o bloco de
    concordância ao vivo consome.

    O Indexer NUNCA é chamado: `main.indexer_client.get_recent_alerts` é
    trocado por um AsyncMock (o mesmo padrão de test_ml_anomalies.py) e o
    modelo é injectado em ml_anomalies._model/_scaler, portanto nada nesta
    função depende do laboratório estar ligado. O cliente e o modelo são
    restaurados num finally — a mutação não pode escapar para os outros
    pedidos do processo.
    """
    import ml_anomalies

    original_indexer = main.indexer_client.get_recent_alerts
    original_model, original_scaler = ml_anomalies._model, ml_anomalies._scaler
    modelo, scaler = train_model(
        vectorize(extract_features(MOCK_ALERTS)), contamination=0.3, random_state=1)
    ml_anomalies._model, ml_anomalies._scaler = modelo, scaler

    casos = (
        ("ml_report_ok.json", MOCK_ALERTS, len(MOCK_ALERTS), False),
        ("ml_report_vazio.json", [], 0, False),
        ("ml_report_truncado.json",
         [dict(MOCK_ALERTS[0]) for _ in range(TETO_ALERTAS)], TETO_ALERTAS, True),
    )
    try:
        for nome, alertas, esperado_total, esperada_truncagem in casos:
            main.indexer_client.get_recent_alerts = AsyncMock(return_value=alertas)
            resp = client.get("/api/ml-anomalies")
            check(f"GET /api/ml-anomalies ({nome}) -> 200", resp.status_code == 200)
            corpo = resp.json()
            Path(out_dir, nome).write_text(
                json.dumps(corpo, ensure_ascii=False, indent=2), encoding="utf-8")
            check(f"{nome}: total == {esperado_total}", corpo.get("total") == esperado_total)
            check(f"{nome}: alerts_fetched == {esperado_total}",
                  corpo.get("alerts_fetched") == esperado_total)
            check(f"{nome}: alerts_truncated é {esperada_truncagem}",
                  corpo.get("alerts_truncated") is esperada_truncagem)
            check(f"{nome}: agree_count + diverge_count == total",
                  corpo.get("agree_count", 0) + corpo.get("diverge_count", 0)
                  == corpo.get("total"))
    finally:
        main.indexer_client.get_recent_alerts = original_indexer
        ml_anomalies._model, ml_anomalies._scaler = original_model, original_scaler


def run() -> None:
    node = shutil.which("node")
    if node is None:
        check("node não encontrado no PATH — instala Node.js (necessário para testar ml_models.js)", False)
        return

    original_dir = main.ML_MODEL_DIR
    client = TestClient(main.app, headers={"X-API-Key": os.environ["SENTRYLENS_API_KEY"]})

    try:
        with tempfile.TemporaryDirectory() as reg_tmp, tempfile.TemporaryDirectory() as out_dir:
            com_v1 = Path(reg_tmp) / "com-v1"
            make_version(com_v1, "v1")
            (com_v1 / "ACTIVE").write_text("v1\n", encoding="utf-8")
            legado = make_legacy(Path(reg_tmp) / "legado")
            vazia = Path(reg_tmp) / "vazia"
            vazia.mkdir()

            for nome, pasta in (("report_v1.json", com_v1),
                                ("report_legacy.json", legado),
                                ("report_empty.json", vazia)):
                main.ML_MODEL_DIR = str(pasta)
                resp = client.get("/api/ml/models")
                check(f"GET /api/ml/models ({nome}) -> 200", resp.status_code == 200)
                Path(out_dir, nome).write_text(
                    json.dumps(resp.json(), ensure_ascii=False, indent=2), encoding="utf-8"
                )

            main.ML_MODEL_DIR = original_dir

            # Quarta fixture: o `evaluate` corrido A SÉRIO, com pickles reais.
            # Sem o check explícito do código de saída, o .cjs acabaria a
            # testar um fixture inventado — que é pior do que não testar.
            avaliado = Path(reg_tmp) / "avaliado"
            model_bytes, scaler_bytes = real_model_bytes()
            make_version(avaliado, "v1", model_bytes=model_bytes, scaler_bytes=scaler_bytes)
            make_version(avaliado, "v2", model_bytes=model_bytes, scaler_bytes=scaler_bytes)
            (avaliado / "ACTIVE").write_text("v1\n", encoding="utf-8")
            eventos = Path(reg_tmp) / "eventos.json"
            eventos.write_text(json.dumps(MOCK_ALERTS, ensure_ascii=False), encoding="utf-8")
            log = Path(reg_tmp) / "attack_log.jsonl"
            log.write_text(json.dumps({"timestamp": "2026-09-02T03:05:00Z",
                                       "type": "brute_force"}) + "\n", encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, "-X", "utf8",
                 str(Path(__file__).with_name("model_registry.py")),
                 "evaluate", "v1",
                 "--events", str(eventos), "--attack-log", str(log),
                 "--models-dir", str(avaliado), "--dataset-origin", "real"],
                capture_output=True, text=True, encoding="utf-8",
                cwd=str(Path(__file__).resolve().parent), timeout=180,
            )
            check(f"CLI 'evaluate v1' no registo temporário -> código 0 (stderr: {proc.stderr.strip()[:200]})",
                  proc.returncode == 0)
            Path(out_dir, "evaluate_stdout.txt").write_text(proc.stdout, encoding="utf-8")
            check("o stdout do evaluate traz percentagens para comparar com a tabela",
                  "%" in proc.stdout)

            main.ML_MODEL_DIR = str(avaliado)
            resp = client.get("/api/ml/models")
            check("GET /api/ml/models (report_evaluated.json) -> 200", resp.status_code == 200)
            corpo = resp.json()
            Path(out_dir, "report_evaluated.json").write_text(
                json.dumps(corpo, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            por_id = {v.get("id"): v for v in corpo.get("versions") or []}
            check("a v1 ficou com avaliação gravada",
                  bool((por_id.get("v1") or {}).get("evaluation")))
            check("a v2 ficou sem avaliação (avaliou-se a versão pedida, D-02)",
                  (por_id.get("v2") or {}).get("evaluation") is None)

            main.ML_MODEL_DIR = original_dir

            # --- Fixtures de treino (R10) ---
            # Se a rota ainda não existir, falha com mensagem explícita (fail-closed).
            # Nunca escreve um fixture de substituição.
            treino = Path(reg_tmp) / "treino"
            treino.mkdir(parents=True, exist_ok=True)
            make_version(treino, "v1", model_bytes=model_bytes, scaler_bytes=scaler_bytes)
            (treino / "ACTIVE").write_text("v1\n", encoding="utf-8")
            main.ML_MODEL_DIR = str(treino)
            main.indexer_client.get_recent_alerts = AsyncMock(return_value=MOCK_ALERTS)
            original_indexer = main.indexer_client.get_recent_alerts
            try:
                ok = client.post("/api/ml/train",
                                 json={"dataset": "sample_fixture", "dataset_origin": "synthetic"},
                                 headers={"X-API-Key": os.environ["SENTRYLENS_API_KEY"]})
                if ok.status_code in (404, 405):
                    print("[FALHOU] POST /api/ml/train não existe — a frente de backend do R10 ainda não foi executada", file=sys.stderr)
                    sys.exit(1)
                check("POST /api/ml/train -> 200", ok.status_code == 200)
                if ok.status_code == 200:
                    Path(out_dir, "train_ok.json").write_text(
                        json.dumps(ok.json(), ensure_ascii=False, indent=2), encoding="utf-8"
                    )
                    body = ok.json()
                    check("train_ok.json tem version/active/loaded",
                          all(k in body for k in ("version", "active", "loaded")))
                    # GET /api/ml/models logo a seguir ao treino -> train_pos_treino.json
                    resp_pos = client.get("/api/ml/models")
                    check("GET /api/ml/models (train_pos_treino.json) -> 200", resp_pos.status_code == 200)
                    Path(out_dir, "train_pos_treino.json").write_text(
                        json.dumps(resp_pos.json(), ensure_ascii=False, indent=2), encoding="utf-8"
                    )
                    # GET /api/ml/models depois do treino -> report_treinado.json (para o 11-03)
                    # Só quando o metadata.json trouxer feature_stats — caso contrário
                    # o wrapper regista como sem feature_stats e o .cjs usa os casos sintéticos.
                    resp_treinado = client.get("/api/ml/models")
                    report_treinado = resp_treinado.json()
                    tem_feature_stats = False
                    for v in report_treinado.get("versions", []):
                        meta = v.get("metadata", {})
                        if meta and isinstance(meta.get("dataset", {}).get("feature_stats"), dict):
                            tem_feature_stats = True
                            break
                    if tem_feature_stats:
                        Path(out_dir, "report_treinado.json").write_text(
                            json.dumps(report_treinado, ensure_ascii=False, indent=2), encoding="utf-8"
                        )
                        check("report_treinado.json gravado com feature_stats", True)
                    else:
                        check("report_treinado.json: sem feature_stats (o .cjs usa casos sintéticos)", True)

                # Caso inválido: dataset fora do Literal -> 422 (detail é lista do FastAPI)
                mau = client.post("/api/ml/train",
                                  json={"dataset": "inventado"},
                                  headers={"X-API-Key": os.environ["SENTRYLENS_API_KEY"]})
                check("POST /api/ml/train com dataset fora do Literal -> 422", mau.status_code == 422)
                check("o 422 não devolve um código de ERROR_CODES em detail (é a lista do FastAPI)",
                      not (isinstance(mau.json().get("detail"), str)))
                Path(out_dir, "train_422.json").write_text(
                    json.dumps(mau.json(), ensure_ascii=False, indent=2), encoding="utf-8"
                )
            finally:
                main.indexer_client.get_recent_alerts = original_indexer
            main.ML_MODEL_DIR = original_dir

            # As três janelas de /api/ml-anomalies: com amostra, vazia e a
            # encher o tecto de 1000 alertas (o caso alerts_truncated).
            ml_anomalies_fixtures(client, out_dir)

            proc = subprocess.run(
                [node, str(Path(__file__).with_name("test_ml_models_ui.cjs")), out_dir],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=60,
            )
            if proc.stdout:
                print(proc.stdout, end="")
            if proc.stderr:
                print(proc.stderr, end="")
            check("teste Node de ml_models.js + ml_evaluation.js", proc.returncode == 0)
    finally:
        main.ML_MODEL_DIR = original_dir


if __name__ == "__main__":
    run()
    if failures:
        print(f"\n[FALHOU] {len(failures)} teste(s) falharam:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("\n[OK] Todos os testes passaram")