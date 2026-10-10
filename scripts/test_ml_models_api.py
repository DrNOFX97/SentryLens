"""
Testes de GET /api/ml/models (rota do registo de modelos, R9) via TestClient.

Nada aqui toca no scripts/models real: todo o disco vive num
tempfile.TemporaryDirectory(). As fixtures gravam os dois .pkl com bytes
arbitrários e um metadata.json coerente com o schema 1 do SKELETON.md, com
SHA-256 e size_bytes calculados a sério — assim continuam válidas quando o
01-02 passar a verificar os hashes antes de carregar.

Correr (a partir de scripts/):
    python test_ml_models_api.py
"""

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("SENTRYLENS_API_KEY", "chave-de-teste-nao-usar-em-producao")

from fastapi.testclient import TestClient

import main
import model_registry

main.app.router.on_startup.clear()

API_KEY = os.environ["SENTRYLENS_API_KEY"]
HEADERS = {"X-API-Key": API_KEY}

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def make_version(root, vid, model_bytes=b"fake-model", scaler_bytes=b"fake-scaler", **meta_overrides) -> Path:
    """Cria models/vN/ com os dois .pkl e um metadata.json válido (schema 1)."""
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
    meta.update(meta_overrides)
    (version_dir / "metadata.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return version_dir


def write_active(root, text, encoding="utf-8") -> None:
    (Path(root) / "ACTIVE").write_bytes(text.encode(encoding))


def no_leaks(label: str, resp, tmp_name: str) -> None:
    """Nenhuma resposta pode conter o caminho temporário nem um traceback."""
    body = resp.text
    check(f"{label}: sem caminho temporário na resposta", tmp_name not in body)
    check(f"{label}: sem caminho resolvido na resposta", str(Path(tmp_name).resolve()) not in body)
    check(f"{label}: sem traceback na resposta", "Traceback" not in body)


def run() -> None:
    client = TestClient(main.app, headers=HEADERS)
    sem_key = TestClient(main.app)

    original_dir = main.ML_MODEL_DIR
    with tempfile.TemporaryDirectory() as tmp:
        tmp_root = Path(tmp)

        def usar(pasta) -> None:
            main.ML_MODEL_DIR = str(pasta)

        # (a) autenticação — a rota leva dependencies=_REQUIRE_API_KEY no
        # próprio decorador, não a nível de app (CLAUDE.md).
        usar(tmp_root)
        resp = sem_key.get("/api/ml/models")
        check("(a) sem X-API-Key -> 401", resp.status_code == 401)
        resp = TestClient(main.app, headers={"X-API-Key": "chave-errada"}).get("/api/ml/models")
        check("(a) X-API-Key errada -> 401", resp.status_code == 401)

        # (b) pasta inexistente -> 200 com o relatório vazio
        usar(tmp_root / "nao-existe")
        resp = client.get("/api/ml/models")
        body = resp.json() if resp.status_code == 200 else {}
        check("(b) pasta inexistente -> 200", resp.status_code == 200)
        check("(b) active null", body.get("active") is None)
        check("(b) active_error null", body.get("active_error") is None)
        check("(b) loaded null", body.get("loaded") is None)
        check("(b) total 0", body.get("total") == 0)
        check("(b) versions []", body.get("versions") == [])

        # (c) pasta vazia -> o mesmo relatório vazio
        vazia = tmp_root / "vazia"
        vazia.mkdir()
        usar(vazia)
        resp = client.get("/api/ml/models")
        body = resp.json() if resp.status_code == 200 else {}
        check("(c) pasta vazia -> 200", resp.status_code == 200)
        check(
            "(c) pasta vazia: relatório vazio",
            body.get("active") is None
            and body.get("active_error") is None
            and body.get("total") == 0
            and body.get("versions") == [],
        )

        # (d) v1 + ACTIVE "v1\n"
        uma = tmp_root / "uma"
        make_version(uma, "v1")
        write_active(uma, "v1\n")
        usar(uma)
        resp = client.get("/api/ml/models")
        body = resp.json() if resp.status_code == 200 else {}
        check("(d) v1 ativa -> 200", resp.status_code == 200)
        check("(d) active == 'v1'", body.get("active") == "v1")
        check("(d) active_error null", body.get("active_error") is None)
        check("(d) total 1", body.get("total") == 1)
        versoes = body.get("versions") or []
        v1 = versoes[0] if versoes else {}
        check("(d) versions[0].id == 'v1'", v1.get("id") == "v1")
        check("(d) versions[0].kind == 'versioned'", v1.get("kind") == "versioned")
        check("(d) versions[0].active true", v1.get("active") is True)
        check("(d) versions[0].status == 'ok'", v1.get("status") == "ok")
        check("(d) versions[0].error_code null", v1.get("error_code") is None)
        check("(d) metadata.version == 'v1'", (v1.get("metadata") or {}).get("version") == "v1")
        check("(d) chave 'evaluation' presente e None", "evaluation" in v1 and v1.get("evaluation") is None)
        check("(d) total == len(versions)", body.get("total") == len(versoes))
        no_leaks("(d)", resp, tmp_root.name)

        # (e) v1 + v2, ACTIVE v1 -> ordem decrescente, só a v1 ativa
        duas = tmp_root / "duas"
        make_version(duas, "v1")
        make_version(duas, "v2")
        write_active(duas, "v1")
        usar(duas)
        resp = client.get("/api/ml/models")
        body = resp.json() if resp.status_code == 200 else {}
        ids = [v.get("id") for v in body.get("versions") or []]
        check("(e) versões por número decrescente", ids == ["v2", "v1"])
        v2 = (body.get("versions") or [{}])[0]
        check("(e) v2 não está ativa", v2.get("id") == "v2" and v2.get("active") is False)
        check("(e) active continua 'v1'", body.get("active") == "v1")
        no_leaks("(e)", resp, tmp_root.name)

        # (f) uma versão sem metadata.json e outra com JSON inválido não
        # derrubam a lista.
        quebradas = tmp_root / "quebradas"
        make_version(quebradas, "v1")
        v3 = quebradas / "v3"
        v3.mkdir(parents=True, exist_ok=True)
        (v3 / "isolation_forest.pkl").write_bytes(b"x")
        (v3 / "scaler.pkl").write_bytes(b"y")
        v4 = make_version(quebradas, "v4")
        (v4 / "metadata.json").write_text("{nao-json", encoding="utf-8")
        write_active(quebradas, "v1")
        usar(quebradas)
        resp = client.get("/api/ml/models")
        body = resp.json() if resp.status_code == 200 else {}
        check("(f) versões com problema não derrubam a resposta -> 200", resp.status_code == 200)
        por_id = {v.get("id"): v for v in body.get("versions") or []}
        check("(f) v3 sem metadata.json -> metadata_missing",
              por_id.get("v3", {}).get("status") == "metadata_missing")
        check("(f) v3 error_code == status", por_id.get("v3", {}).get("error_code") == "metadata_missing")
        check("(f) v3 metadata null", por_id.get("v3", {}).get("metadata") is None)
        check("(f) v4 com JSON inválido -> metadata_invalid",
              por_id.get("v4", {}).get("status") == "metadata_invalid")
        check("(f) v4 error_code == status", por_id.get("v4", {}).get("error_code") == "metadata_invalid")
        check("(f) v1 continua válida na mesma resposta", por_id.get("v1", {}).get("status") == "ok")
        no_leaks("(f)", resp, tmp_root.name)

        # (g) ACTIVE inválido -> active null com código estável, sem 500
        traversal = tmp_root / "traversal"
        traversal.mkdir()
        write_active(traversal, "../x")
        usar(traversal)
        resp = client.get("/api/ml/models")
        body = resp.json() if resp.status_code == 200 else {}
        check("(g) ACTIVE '../x' -> 200", resp.status_code == 200)
        check("(g) ACTIVE '../x' -> active null", body.get("active") is None)
        check("(g) ACTIVE '../x' -> active_error invalid_version_id",
              body.get("active_error") == "invalid_version_id")
        no_leaks("(g) '../x'", resp, tmp_root.name)

        inexistente = tmp_root / "aponta-para-nada"
        make_version(inexistente, "v1")
        write_active(inexistente, "v9")
        usar(inexistente)
        resp = client.get("/api/ml/models")
        body = resp.json() if resp.status_code == 200 else {}
        check("(g) ACTIVE 'v9' sem pasta -> active_error active_not_found",
              resp.status_code == 200 and body.get("active") is None
              and body.get("active_error") == "active_not_found")
        no_leaks("(g) 'v9'", resp, tmp_root.name)

        write_active(inexistente, "v1", encoding="utf-16")
        resp = client.get("/api/ml/models")
        body = resp.json() if resp.status_code == 200 else {}
        check("(g) ACTIVE em UTF-16 -> active_error invalid_version_id",
              resp.status_code == 200 and body.get("active") is None
              and body.get("active_error") == "invalid_version_id")
        no_leaks("(g) UTF-16", resp, tmp_root.name)

        grande = tmp_root / "active-gigante"
        make_version(grande, "v1")
        write_active(grande, "v1" + " " * 200)
        resp = client.get("/api/ml/models")
        body = resp.json() if resp.status_code == 200 else {}
        check("(g) ACTIVE com mais de 64 bytes -> active_error invalid_version_id",
              resp.status_code == 200 and body.get("active_error") == "invalid_version_id")
        no_leaks("(g) ACTIVE gigante", resp, tmp_root.name)

        # (i) mesmo código, mesmo estado: registry_unavailable é 503 tanto
        # vindo de um ModelRegistryError como de uma exceção inesperada, e
        # nenhuma das duas vaza a mensagem.
        original_report = model_registry.build_models_report

        def explodir(_models_dir, loaded=None):
            raise RuntimeError("C:/segredo/models boom")

        model_registry.build_models_report = explodir
        try:
            resp = client.get("/api/ml/models")
            check("(i) exceção inesperada -> 503", resp.status_code == 503)
            check("(i) exceção inesperada -> detail registry_unavailable",
                  resp.json().get("detail") == "registry_unavailable")
            check("(i) exceção inesperada: sem 'segredo' nem 'boom'",
                  "segredo" not in resp.text and "boom" not in resp.text)
            check("(i) exceção inesperada: sem traceback", "Traceback" not in resp.text)

            def indisponivel(_models_dir, loaded=None):
                raise model_registry.ModelRegistryError("registry_unavailable")

            model_registry.build_models_report = indisponivel
            resp = client.get("/api/ml/models")
            check("(i) ModelRegistryError('registry_unavailable') -> 503", resp.status_code == 503)
            check("(i) ModelRegistryError('registry_unavailable') -> mesmo detail",
                  resp.json().get("detail") == "registry_unavailable")
        finally:
            model_registry.build_models_report = original_report

    main.ML_MODEL_DIR = original_dir


if __name__ == "__main__":
    try:
        run()
    finally:
        main.ML_MODEL_DIR = os.getenv("ML_MODEL_DIR", os.path.join(os.path.dirname(__file__), "models"))

    if failures:
        print(f"\n[FALHOU] {len(failures)} teste(s) falharam:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("\n[OK] Todos os testes passaram")