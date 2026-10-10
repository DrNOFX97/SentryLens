"""
Wrapper dos testes de UI do registo de modelos (ml_models.js).

O run_all_tests.py só descobre test_*.py, por isso este ficheiro é a ponte
para o teste Node scripts/test_ml_models_ui.cjs: monta um registo real num
directório temporário, pede-o a GET /api/ml/models com TestClient e escreve
as respostas em report_v1.json / report_empty.json, que o .cjs usa como
fixtures. Assim os helpers puros de ml_models.js são testados contra o JSON
verdadeiro da rota, não contra um JSON escrito à mão.

Nunca toca no scripts/models real. Sem `node` no PATH falha com mensagem
explícita (fail-closed) — nunca passa em silêncio.

Correr (a partir de scripts/):
    python test_ml_models_ui.py
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("SENTRYLENS_API_KEY", "chave-de-teste-nao-usar-em-producao")

from fastapi.testclient import TestClient

import main

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
            check("teste Node de ml_models.js", proc.returncode == 0)
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