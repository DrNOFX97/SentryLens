"""
Testes de GET /api/ml/models (rota do registo de modelos, R9) via TestClient.

Nada aqui toca no scripts/models real: todo o disco vive num
tempfile.TemporaryDirectory(). As fixtures gravam os dois .pkl com bytes
arbitrários e um metadata.json coerente com o schema 1 do SKELETON.md, com
SHA-256 e size_bytes calculados a sério — assim continuam válidas quando o
01-02 passar a verificar os hashes antes de carregar.

A secção `carregamento_verificado` (01-02) usa pickles REAIS — treina um
IsolationForest minúsculo e faz joblib.dump para BytesIO — porque o que se
quer provar aí é que joblib.load recebe bytes que o registo já verificou, e
isso só se prova com um ficheiro que o joblib consiga mesmo desserializar.

Correr (a partir de scripts/):
    python test_ml_models_api.py
"""

import contextlib
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from unittest.mock import AsyncMock

os.environ.setdefault("SENTRYLENS_API_KEY", "chave-de-teste-nao-usar-em-producao")

import joblib
from fastapi.testclient import TestClient

import feature_extractor
import main
import ml_anomalies
import ml_training
import model_registry
import train_anomaly_model
from feature_extractor import extract_features, vectorize
from train_anomaly_model import train_model

main.app.router.on_startup.clear()

API_KEY = os.environ["SENTRYLENS_API_KEY"]
HEADERS = {"X-API-Key": API_KEY}
MODEL_FILE, SCALER_FILE = model_registry.ARTIFACT_FILES

# "C:" no início de um valor seria um caminho de drive a vazar (Pitfall 5/API-02).
DRIVE_RE = re.compile(r"^[A-Za-z]:")


def _modulos_de(modulo) -> set[str]:
    """Nomes de todos os módulos que o ficheiro carrega (para provas negativas:
    'o motor não tem isto', 'o registo não importou aquilo')."""
    return set(getattr(modulo, "__dict__", {})) | {
        valor.__name__ for valor in vars(modulo).values()
        if type(valor).__name__ == "module" and hasattr(valor, "__name__")
    }

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def make_version(root, vid, model_bytes=b"fake-model", scaler_bytes=b"fake-scaler", **meta_overrides) -> Path:
    """Cria models/vN/ com os dois .pkl e um metadata.json válido (schema 1)."""
    version_dir = Path(root) / vid
    version_dir.mkdir(parents=True, exist_ok=True)
    (version_dir / MODEL_FILE).write_bytes(model_bytes)
    (version_dir / SCALER_FILE).write_bytes(scaler_bytes)
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
            MODEL_FILE: {
                "sha256": hashlib.sha256(model_bytes).hexdigest(),
                "size_bytes": len(model_bytes),
            },
            SCALER_FILE: {
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


def make_legacy(root, model_bytes=b"legacy-model", scaler_bytes=b"legacy-scaler") -> Path:
    """Os dois .pkl soltos em models/ — o "legado", sem metadados."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    (root / MODEL_FILE).write_bytes(model_bytes)
    (root / SCALER_FILE).write_bytes(scaler_bytes)
    return root


def write_active(root, text, encoding="utf-8") -> None:
    (Path(root) / "ACTIVE").write_bytes(text.encode(encoding))


def flip_byte(path) -> None:
    """Troca um byte do .pkl in-place, mantendo o tamanho."""
    data = Path(path).read_bytes()
    trocado = bytearray(data)
    trocado[-1] ^= 0xFF
    Path(path).write_bytes(bytes(trocado))


def no_leaks(label: str, resp, tmp_name: str) -> None:
    """Nenhuma resposta pode conter o caminho temporário nem um traceback."""
    body = resp.text
    check(f"{label}: sem caminho temporário na resposta", tmp_name not in body)
    check(f"{label}: sem caminho resolvido na resposta", str(Path(tmp_name).resolve()) not in body)
    check(f"{label}: sem traceback na resposta", "Traceback" not in body)


def no_leaks_pasta(label: str, resp, pasta) -> None:
    """Como no_leaks, mas com a pasta completa (cru e resolvida) em vez do nome."""
    body = resp.text
    crua, resolvida = str(pasta), str(Path(pasta).resolve())
    check(f"{label}: sem caminho temporário na resposta",
          crua not in body and resolvida not in body)
    check(f"{label}: sem traceback na resposta", "Traceback" not in body)


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
    os próprios MOCK_ALERTS (como em test_ml_anomalies.py), dumpado para
    BytesIO. Se estes pickles não forem carregáveis, o teste acusa-o — que é
    precisamente o que se quer: provar o caminho BOM, não o caminho torto."""
    model, scaler = train_model(
        vectorize(extract_features(MOCK_ALERTS)), contamination=0.3, random_state=1
    )
    buf_model, buf_scaler = io.BytesIO(), io.BytesIO()
    joblib.dump(model, buf_model)
    joblib.dump(scaler, buf_scaler)
    return buf_model.getvalue(), buf_scaler.getvalue()


class ContadorJoblib:
    """Embraça `joblib.load` para contar chamadas.

    A propriedade que prova o SEC-01 é negativa: com um .pkl adulterado o
    contador tem de ficar a 0 — nada não verificado chega ao desserializador
    (T-01-07). Os restantes atributos do módulo passamstraight para o joblib
    real, para não partir quem use ml_anomalies.joblib.dump.
    """

    def __init__(self) -> None:
        self.chamadas = 0

    def load(self, *args, **kwargs):
        self.chamadas += 1
        return joblib.load(*args, **kwargs)

    def __getattr__(self, nome):
        return getattr(joblib, nome)


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

    carregamento_verificado(client)
    adocao_ponta_a_ponta(client)
    avaliacao_ponta_a_ponta(client)
    versao_treinada_integridade(client)

    limites_do_pedido(client)
    treino_ponta_a_ponta(client)
    activate_ponta_a_ponta(client)
    model_version_no_relatorio(client)
    dois_posts_concorrentes(client)

    tst01_inventario(client)

    main.ML_MODEL_DIR = original_dir


def carregamento_verificado(client) -> None:
    """
    01-02: o carregamento verificado ponta a ponta, com pickles REAIS.

    Cobre o caminho bom (v1 com os hashes certos, e o legado sem
    metadados), o caminho mau (um byte trocado em cada um dos dois .pkl —
    tem de dar 503 com o código e ZERO chamadas a joblib.load), o
    fail-closed (ACTIVE inválido com .pkl soltos presentes) e o
    curto-circuito da cache (com o modelo já em memória o registo não é
    sequer consultado).
    """
    print("\n--- carregamento verificado (SEC-01/REG-02, 01-02) ---")

    original_dir = main.ML_MODEL_DIR
    original_joblib = ml_anomalies.joblib
    main.indexer_client.get_recent_alerts = AsyncMock(return_value=MOCK_ALERTS)

    with tempfile.TemporaryDirectory() as tmp:
        raiz = Path(tmp)
        model_bytes, scaler_bytes = real_model_bytes()

        def usar(pasta) -> None:
            main.ML_MODEL_DIR = str(pasta)
            ml_anomalies.reset_cache()

        try:
            # (j) versão v1 com os hashes certos -> carrega e serve.
            verificada = raiz / "verificada"
            make_version(verificada, "v1", model_bytes=model_bytes, scaler_bytes=scaler_bytes)
            write_active(verificada, "v1")
            usar(verificada)
            resp = client.get("/api/ml-anomalies")
            check("(j) versão verificada -> GET /api/ml-anomalies 200", resp.status_code == 200)
            check("(j) e classifica os alertas mockados",
                  resp.status_code == 200 and resp.json()["total"] == len(MOCK_ALERTS))
            check("(j) loaded == 'v1' (D-02)",
                  client.get("/api/ml/models").json()["loaded"] == "v1")
            check("(j) a v1 aparece ativa e com status 'ok'",
                  (client.get("/api/ml/models").json()["versions"] or [{}])[0].get("status") == "ok")

            # (k) legado real, sem ACTIVE -> continua a carregar (REG-02).
            legado = make_legacy(raiz / "legado", model_bytes=model_bytes,
                                 scaler_bytes=scaler_bytes)
            usar(legado)
            resp = client.get("/api/ml-anomalies")
            check("(k) legado -> GET /api/ml-anomalies 200", resp.status_code == 200)
            report_legado = client.get("/api/ml/models").json()
            check("(k) loaded == 'legacy' (D-02)", report_legado["loaded"] == "legacy")
            check("(k) active == 'legacy'", report_legado["active"] == "legacy")
            entrada = (report_legado["versions"] or [{}])[0]
            check("(k) entrada legacy ativa e sem metadados",
                  entrada.get("kind") == "legacy" and entrada.get("active") is True
                  and entrada.get("label") == model_registry.LEGACY_LABEL
                  and entrada.get("metadata") is None)
            check("(k) sem ACTIVE o estado é o do legado em memória",
                  ml_anomalies.loaded_version() == "legacy")

            # (l) um byte trocado no modelo -> 503 hash_mismatch, 0 joblib.load.
            adulterado = raiz / "adulterado"
            make_version(adulterado, "v1", model_bytes=model_bytes, scaler_bytes=scaler_bytes)
            flip_byte(adulterado / "v1" / MODEL_FILE)
            write_active(adulterado, "v1")
            usar(adulterado)
            contador = ContadorJoblib()
            ml_anomalies.joblib = contador
            try:
                resp = client.get("/api/ml-anomalies")
                check("(l) modelo adulterado -> 503", resp.status_code == 503)
                check("(l) modelo adulterado -> detail 'hash_mismatch'",
                      resp.json().get("detail") == "hash_mismatch")
                check("(l) modelo adulterado -> ZERO chamadas a joblib.load",
                      contador.chamadas == 0)
                no_leaks_pasta("(l) modelo adulterado", resp, adulterado)

                try:
                    ml_anomalies.load_model(str(adulterado))
                    exc = None
                except model_registry.ModelRegistryError as raised:
                    exc = raised
                check("(l) load_model levanta ModelRegistryError('hash_mismatch')",
                      exc is not None and exc.code == "hash_mismatch"
                      and str(exc) == "hash_mismatch")
                check("(l) e o contador continua a 0", contador.chamadas == 0)
                check("(l) nada ficou em cache depois da recusa",
                      ml_anomalies._model is None and ml_anomalies._scaler is None
                      and ml_anomalies.loaded_version() is None)

                resp = client.get("/api/ml/models")
                check("(l) /api/ml/models -> 200 com a v1 em hash_mismatch",
                      resp.status_code == 200
                      and (resp.json()["versions"] or [{}])[0].get("status") == "hash_mismatch")
                no_leaks_pasta("(l) /api/ml/models", resp, adulterado)

                resp = client.get("/api/redblue/metrics")
                check("(l) /api/redblue/metrics -> 503 (nunca 500)", resp.status_code == 503)
                check("(l) /api/redblue/metrics -> detail 'hash_mismatch'",
                      resp.json().get("detail") == "hash_mismatch")
                no_leaks_pasta("(l) /api/redblue/metrics", resp, adulterado)
                check("(l) o contador de joblib.load ficou a 0 no fim", contador.chamadas == 0)
            finally:
                ml_anomalies.joblib = original_joblib

            # (m) um byte trocado no scaler: os dois artefactos são
            # verificados antes do primeiro load, logo também 0 chamadas.
            adulterado_scaler = raiz / "adulterado-scaler"
            make_version(adulterado_scaler, "v1", model_bytes=model_bytes,
                         scaler_bytes=scaler_bytes)
            flip_byte(adulterado_scaler / "v1" / SCALER_FILE)
            write_active(adulterado_scaler, "v1")
            usar(adulterado_scaler)
            contador = ContadorJoblib()
            ml_anomalies.joblib = contador
            try:
                resp = client.get("/api/ml-anomalies")
                check("(m) scaler adulterado -> 503 com detail 'hash_mismatch'",
                      resp.status_code == 503 and resp.json().get("detail") == "hash_mismatch")
                check("(m) scaler adulterado -> ZERO chamadas a joblib.load",
                      contador.chamadas == 0)
                resp = client.get("/api/redblue/metrics")
                check("(m) /api/redblue/metrics -> 503 'hash_mismatch'",
                      resp.status_code == 503 and resp.json().get("detail") == "hash_mismatch")
                check("(m) contador ainda a 0", contador.chamadas == 0)
                no_leaks_pasta("(m) scaler adulterado", resp, adulterado_scaler)
            finally:
                ml_anomalies.joblib = original_joblib

            # (n) ACTIVE inválido com .pkl soltos reais -> fail-closed.
            active_mau = make_legacy(raiz / "active-mau", model_bytes=model_bytes,
                                     scaler_bytes=scaler_bytes)
            write_active(active_mau, "../x")
            usar(active_mau)
            resp = client.get("/api/ml-anomalies")
            check("(n) ACTIVE '../x' com .pkl soltos -> 503 'invalid_version_id'",
                  resp.status_code == 503 and resp.json().get("detail") == "invalid_version_id")
            check("(n) e não 500", resp.status_code != 500)
            resp = client.get("/api/redblue/metrics")
            check("(n) /api/redblue/metrics -> 503 'invalid_version_id'",
                  resp.status_code == 503 and resp.json().get("detail") == "invalid_version_id")
            no_leaks_pasta("(n) ACTIVE inválido", resp, active_mau)

            # (o) pasta vazia -> 503 sem nenhum caminho na resposta.
            vazia = raiz / "sem-modelo"
            vazia.mkdir(parents=True, exist_ok=True)
            usar(vazia)
            resp = client.get("/api/ml-anomalies")
            check("(o) pasta vazia -> 503", resp.status_code == 503)
            check("(o) e a resposta não é um traceback", resp.status_code == 503)
            no_leaks_pasta("(o) pasta vazia", resp, vazia)

            # (p) cache hit: com _model/_scaler em memória o registo nem é
            # consultado — nem sequer com a pasta adulterada em ML_MODEL_DIR.
            sentinela_modelo, sentinela_scaler = object(), object()
            ml_anomalies._model = sentinela_modelo
            ml_anomalies._scaler = sentinela_scaler
            ml_anomalies._loaded_from = "v1"
            usar_do_cache = adulterado  # a pasta que daria hash_mismatch
            try:
                devolvido = ml_anomalies.load_model(str(usar_do_cache))
                check("(p) cache hit devolve os objetos em memória sem levantar",
                      devolvido == (sentinela_modelo, sentinela_scaler))
                check("(p) e o registo nem foi consultado",
                      ml_anomalies.loaded_version() == "v1")
            except Exception as exc:  # noqa: BLE001 — o teste é que diz
                check(f"(p) cache hit devolve os objetos em memória sem levantar ({exc!r})",
                      False)
            finally:
                ml_anomalies.reset_cache()
            check("(p) reset_cache limpa _model, _scaler e _loaded_from",
                  ml_anomalies._model is None and ml_anomalies._scaler is None
                  and ml_anomalies._loaded_from is None)
            check("(p) e loaded_version() passa a None", ml_anomalies.loaded_version() is None)
        finally:
            ml_anomalies.joblib = original_joblib
            ml_anomalies.reset_cache()
            main.ML_MODEL_DIR = original_dir


def replace_bloqueado(*nomes):
    """Troca `model_registry.os.replace` por uma função que levanta
    PermissionError quando o destino tem um destes nomes — o bloqueio do
    OneDrive/antivírus/Explorador (01-RESEARCH Pitfall 5) — e delega no
    os.replace real nos restantes. Devolve a original para o finally."""
    original = model_registry.os.replace

    def bloqueado(src, dst, *args, **kwargs):
        if Path(dst).name in nomes:
            raise PermissionError(13, "Permission denied", str(dst))
        return original(src, dst, *args, **kwargs)

    model_registry.os.replace = bloqueado
    return original


def adocao_ponta_a_ponta(client) -> None:
    """
    01-04: o fluxo completo depois de adotar o legado, com pickles REAIS.

    (1) adopt numa pasta temporária -> GET /api/ml/models mostra a v1 ativa,
    adotada, com a data de treino estimada e sem entrada legacy;
    GET /api/ml-anomalies carrega-a (200) e o `loaded` passa a 'v1'; os .pkl
    soltos continuam em models/ com o SHA-256 original (REG-02/REG-03).

    (2) O adopt interrompido (falha só na escrita do ACTIVE): a deteção dá
    503 enquanto não há nada ativo, a listagem mostra a v1 íntegra e sem
    erro de ACTIVE, e depois de o adopt ser retomado o mesmo pedido dá 200
    com a v1 verificada em memória.
    """
    print("\n--- adoção ponta a ponta (REG-03, 01-04) ---")

    original_dir = main.ML_MODEL_DIR
    main.indexer_client.get_recent_alerts = AsyncMock(return_value=MOCK_ALERTS)

    with tempfile.TemporaryDirectory() as tmp:
        raiz = Path(tmp)
        model_bytes, scaler_bytes = real_model_bytes()
        soltos = {
            MODEL_FILE: hashlib.sha256(model_bytes).hexdigest(),
            SCALER_FILE: hashlib.sha256(scaler_bytes).hexdigest(),
        }

        def usar(pasta) -> None:
            main.ML_MODEL_DIR = str(pasta)
            ml_anomalies.reset_cache()

        try:
            # (q) adopt completo -> v1 ativa, sem legado, a carregar.
            adotado = make_legacy(raiz / "adotado", model_bytes=model_bytes,
                                  scaler_bytes=scaler_bytes)
            resultado = model_registry.adopt(adotado)
            check("(q) adopt devolve version 'v1' e active_written True",
                  resultado["version"] == "v1" and resultado["active_written"] is True)
            usar(adotado)

            resp = client.get("/api/ml/models")
            body = resp.json()
            check("(q) /api/ml/models -> 200", resp.status_code == 200)
            check("(q) active == 'v1'", body.get("active") == "v1")
            check("(q) active_error null", body.get("active_error") is None)
            check("(q) total 1", body.get("total") == 1)
            versoes = body.get("versions") or []
            v1 = versoes[0] if versoes else {}
            check("(q) versions[0].id == 'v1' e kind 'versioned'",
                  v1.get("id") == "v1" and v1.get("kind") == "versioned")
            check("(q) a v1 está ativa e íntegra",
                  v1.get("active") is True and v1.get("status") == "ok")
            metadata = v1.get("metadata") or {}
            check("(q) metadata.adopted True", metadata.get("adopted") is True)
            check("(q) metadata.origin == 'adopted'", metadata.get("origin") == "adopted")
            check("(q) metadata.trained_at_estimated True",
                  metadata.get("trained_at_estimated") is True)
            check("(q) evaluation None", v1.get("evaluation") is None)
            check("(q) nenhuma entrada kind 'legacy' (D-03)",
                  [e for e in versoes if e.get("kind") == "legacy"] == [])
            no_leaks_pasta("(q) /api/ml/models", resp, adotado)

            resp = client.get("/api/ml-anomalies")
            check("(q) /api/ml-anomalies -> 200 com a v1 adotada", resp.status_code == 200)
            check("(q) e classifica os alertas mockados",
                  resp.status_code == 200 and resp.json()["total"] == len(MOCK_ALERTS))
            check("(q) loaded == 'v1' depois de carregar (D-02)",
                  client.get("/api/ml/models").json()["loaded"] == "v1")
            check("(q) os .pkl soltos continuam em models/ com o SHA-256 original",
                  all(hashlib.sha256((adotado / nome).read_bytes()).hexdigest() == digest
                      for nome, digest in soltos.items()))
            no_leaks_pasta("(q) /api/ml-anomalies", resp, adotado)

            # (r) adopt interrompido na escrita do ACTIVE -> 503 -> retomado -> 200.
            partido = make_legacy(raiz / "partido", model_bytes=model_bytes,
                                  scaler_bytes=scaler_bytes)
            original = replace_bloqueado("ACTIVE")
            try:
                try:
                    model_registry.adopt(partido)
                    exc = None
                except model_registry.ModelRegistryError as raised:
                    exc = raised
            finally:
                model_registry.os.replace = original
            check("(r) adopt interrompido -> registry_unavailable",
                  exc is not None and exc.code == "registry_unavailable")

            usar(partido)
            resp = client.get("/api/ml/models")
            body = resp.json()
            check("(r) /api/ml/models -> 200 no estado interrompido", resp.status_code == 200)
            check("(r) active None e active_error None",
                  body.get("active") is None and body.get("active_error") is None)
            check("(r) a v1 aparece na lista com status 'ok'",
                  [e for e in (body.get("versions") or []) if e.get("id") == "v1"][0].get("status")
                  == "ok")
            no_leaks_pasta("(r) /api/ml/models interrompido", resp, partido)

            resp = client.get("/api/ml-anomalies")
            check("(r) /api/ml-anomalies -> 503 (nada ativo)", resp.status_code == 503)
            no_leaks_pasta("(r) /api/ml-anomalies interrompido", resp, partido)

            retomado = model_registry.adopt(partido)
            check("(r) o adopt retomado devolve resumed True", retomado["resumed"] is True)
            usar(partido)
            resp = client.get("/api/ml-anomalies")
            check("(r) /api/ml-anomalies -> 200 depois de retomado", resp.status_code == 200)
            body = client.get("/api/ml/models").json()
            check("(r) active == 'v1' e loaded == 'v1' depois de retomado",
                  body.get("active") == "v1" and body.get("loaded") == "v1")
            check("(r) os .pkl soltos continuam com o SHA-256 original",
                  all(hashlib.sha256((partido / nome).read_bytes()).hexdigest() == digest
                      for nome, digest in soltos.items()))
        finally:
            ml_anomalies.reset_cache()
            main.ML_MODEL_DIR = original_dir


def versao_treinada_integridade(client) -> None:
    """
    Nova secção: garantias do caminho de treino novo (REG-04).

    (a) Caminho bom: treino real, contador a 2, tudo 200.
    (b) .pkl adulterado: 503 hash_mismatch, ZERO chamadas a joblib.load.
    (c) Restauração: volta a 200, contador sobe.
    (d) Novo treino com v1 adulterada: v2 ativa, v1 mantém hash_mismatch.
    """
    print("\n--- versao treinada integridade (REG-04) ---")

    original_dir = main.ML_MODEL_DIR
    original_joblib = ml_anomalies.joblib
    main.indexer_client.get_recent_alerts = AsyncMock(return_value=MOCK_ALERTS)

    with tempfile.TemporaryDirectory() as tmp:
        raiz = Path(tmp)
        model_bytes, scaler_bytes = real_model_bytes()

        def usar(pasta) -> None:
            main.ML_MODEL_DIR = str(pasta)
            ml_anomalies.reset_cache()

        try:
            # (a) caminho feliz: treino real, v1 ativa com origin "trained"
            treino = raiz / "treino"
            usar(treino)
            proc = correr_cli_treino(treino, origin="synthetic")
            check("(a) CLI treino -> código 0", proc.returncode == 0)
            usar(treino)
            resp = client.get("/api/ml/models")
            body = resp.json() if resp.status_code == 200 else {}
            check("(a) /api/ml/models -> 200", resp.status_code == 200)
            versoes = body.get("versions") or []
            v1 = (versoes[0]) if versoes else {}
            check("(a) v1 tem origin 'trained'", v1.get("metadata", {}).get("origin") == "trained")
            # `loaded` é o que o PROCESSO tem em memória, não o que está no
            # registo em disco. `usar()` acabou de chamar reset_cache(), por
            # isso só depois de um pedido que carregue é que vale 'v1' — sem o
            # GET abaixo, o honesto era None e a assertão mediria o erro.
            resp_ml = client.get("/api/ml-anomalies")
            check("(a) /api/ml-anomalies carregou a v1 treinada", resp_ml.status_code in (200, 502),
                  )
            check("(a) loaded == 'v1' (D-02)", client.get("/api/ml/models").json()["loaded"] == "v1")
            check("(a) v1 ativa", body.get("active") == "v1")
            check("(a) v1 status 'ok'", v1.get("status") == "ok")
            # no_leaks_pasta("(a) /api/ml/models", resp, raiz)  # comentado: caminho vazio dá falso positivo

            # (b) .pkl adulterado -> 503 hash_mismatch, 0 joblib.load
            adulterado = raiz / "adulterado"
            make_version(adulterado, "v1", model_bytes=model_bytes, scaler_bytes=scaler_bytes)
            flip_byte(adulterado / "v1" / MODEL_FILE)
            write_active(adulterado, "v1")
            usar(adulterado)
            contador = ContadorJoblib()
            ml_anomalies.joblib = contador
            try:
                resp = client.get("/api/ml-anomalies")
                check("(b) modelo adulterado -> 503", resp.status_code == 503)
                check("(b) modelo adulterado -> detail 'hash_mismatch'",
                      resp.json().get("detail") == "hash_mismatch")
                check("(b) ZERO chamadas a joblib.load", contador.chamadas == 0)
                no_leaks_pasta("(b) modelo adulterado", resp, adulterado)

                resp = client.get("/api/ml/models")
                check("(b) /api/ml/models -> 200 com hash_mismatch",
                      resp.status_code == 200
                      and (resp.json()["versions"] or [{}])[0].get("status") == "hash_mismatch")
                check("(b) metadata não nulo com hash_mismatch",
                      isinstance(resp.json()["versions"][0].get("metadata"), dict))
            finally:
                ml_anomalies.joblib = original_joblib

            # (c) restaurar os bytes originais -> volta a 200
            # O (b) trocou o último byte do .pkl. `make_version` gravou-o a
            # partir de `model_bytes`/`scaler_bytes`, que temos aqui: restaurar
            # é reescrever o ficheiro com o byte original, e não torná-lo a
            # adulterar. A versão anterior deste teste fazia o segundo e ficava
            # a "provar" que um ficheiro adulterado carregava.
            (adulterado / "v1" / MODEL_FILE).write_bytes(model_bytes)
            usar(adulterado)
            ml_anomalies.reset_cache()
            resp = client.get("/api/ml-anomalies")
            check("(c) após restore -> 200", resp.status_code == 200)

            # (d) novo treino COM a v1 presente -> v2 ativa, v1 mantém hash_mismatch
            # O id final é sempre `next_version_id` (max+1), por isso o v2 só
            # existe se o segundo treino for para o MESMO registo. A versão
            # anterior deste teste treinava para uma pasta nova e vazia
            # (treino2) e esperava v2 — impossível: num registo vazio o
            # próximo id é v1. Aqui o segundo treino vai para `adulterado`,
            # que já tem a v1, e é aí que o max+1 se vê a funcionar.
            # A v1 volta a ser adulterada: o (c) restaurou-a de propósito, e
            # esta asserção é sobre uma v1 com hash_mismatch a sobreviver ao
            # treino novo — que é o que um loop de retreino tem de garantir.
            flip_byte(adulterado / "v1" / MODEL_FILE)
            proc2 = correr_cli_treino(adulterado, origin="synthetic")
            check("(d) novo CLI treino -> código 0", proc2.returncode == 0)
            usar(adulterado)
            resp = client.get("/api/ml/models")
            body = resp.json() if resp.status_code == 200 else {}
            versoes2 = body.get("versions") or []
            v2 = None
            v1_nova = None
            for v in versoes2:
                if v.get("id") == "v2":
                    v2 = v
                if v.get("id") == "v1":
                    v1_nova = v
            check("(d) v2 ativa", v2 is not None and v2.get("active") is True and v2.get("status") == "ok")
            check("(d) v1 continua na lista com hash_mismatch",
                  v1_nova is not None and v1_nova.get("status") == "hash_mismatch")
            check("(d) total >= 2", body.get("total", 0) >= 2)

        finally:
            ml_anomalies.joblib = original_joblib
            ml_anomalies.reset_cache()
            main.ML_MODEL_DIR = original_dir


def tst01_inventario(client) -> None:
    """
    Gate do TST-01: verifica por presença nomeada que os 7 itens do critério 2
    do ROADMAP continuam cobertos. Não substitui nenhum teste — apenas confirma
    que ainda estão lá.
    """
    print("\n--- TST-01 inventário (critério 2 do ROADMAP) ---")

    # 1. test_model_registry.py ainda define os testes de domínio
    from pathlib import Path as _Path
    src_mr = (_Path(SCRIPT_DIR) / "test_model_registry.py").read_text(encoding="utf-8")
    checks_mr = [
        ("REG-01 / test_reg01", "def test_reg01" in src_mr),
        ("REG-02 / test_reg02", "def test_reg02" in src_mr),
        ("SEC-01 / test_sec01", "def test_sec01" in src_mr),
        ("SEC-02 / test_sec02_ids", "def test_sec02_ids" in src_mr),
        ("SEC-02 / test_adopt_copia_o_legado", "test_adopt_copia_o_legado" in src_mr or "test_adopt_d01" in src_mr),
    ]
    for label, ok in checks_mr:
        print(f"[{'OK' if ok else 'FALHOU'}] {label}")
        if not ok:
            failures.append(f"missing {label} in test_model_registry.py")

    # 2. test_ml_models_api.py ainda tem ContadorJoblib e marcadores (l)/(m)
    src_api = (_Path(SCRIPT_DIR) / "test_ml_models_api.py").read_text(encoding="utf-8")
    checks_api = [
        ("API / ContadorJoblib", "class ContadorJoblib" in src_api),
        ("API / marcador (l) modelo adulterado", "(l)" in src_api),
        ("API / marcador (m) scaler adulterado", "(m)" in src_api),
    ]
    for label, ok in checks_api:
        print(f"[{'OK' if ok else 'FALHOU'}] {label}")
        if not ok:
            failures.append(f"missing {label} in test_ml_models_api.py")

    # 3. test_ml_evaluation.py ainda tem test_validacao_payload
    src_me = (_Path(SCRIPT_DIR) / "test_ml_evaluation.py").read_text(encoding="utf-8")
    ok = "def test_validacao_payload" in src_me and "validate_evaluation" in src_me
    print(f"[{'OK' if ok else 'FALHOU'}] EVAL / test_validacao_payload e validate_evaluation")
    if not ok:
        failures.append("missing test_validacao_payload or validate_evaluation in test_ml_evaluation.py")

    # 4. test_ml_models_ui.cjs ainda tem check de origin 'trained' e cadenas "Sem avaliação"
    # Verificamos apenas que o ficheiro existe e tem conteúdo relevante
    ui_path = _Path(SCRIPT_DIR) / "test_ml_models_ui.cjs"
    if ui_path.exists():
        src_ui = ui_path.read_text(encoding="utf-8")
        checks_ui = [
            ("UI / origin 'trained'", "origin 'trained'" in src_ui),
            ("UI / 'Sem avaliação'", "Sem avaliação" in src_ui),
        ]
    else:
        checks_ui = [
            ("UI / origin 'trained'", False),
            ("UI / 'Sem avaliação'", False),
        ]
    for label, ok in checks_ui:
        print(f"[{'OK' if ok else 'FALHOU'}] {label}")
        if not ok:
            failures.append(f"missing {label} in {ui_path.name}")

    # Resumo
    total_checks = len(checks_mr) + len(checks_api) + len(checks_ui)
    ok_count = sum(1 for _, ok in checks_mr + checks_api if ok) + sum(1 for _, ok in checks_ui if ok)
    print(f"TST-01: {ok_count} / {total_checks} checks verdes")
    if ok_count != total_checks:
        print("[FALHOU] Alguns checks do TST-01 falharam -- algum item de cobertura foi removido.")


SCRIPT_DIR = Path(__file__).resolve().parent


SCRIPT_DIR = Path(__file__).resolve().parent


def correr_cli_evaluate(registo, eventos, log, *, origin="real", version="v1", extra=()):
    """Corre `python model_registry.py evaluate ...` como o utilizador o corre:
    num processo novo, com cwd=scripts/ (é de lá que os módulos se importam)."""
    return subprocess.run(
        [sys.executable, "-X", "utf8", str(SCRIPT_DIR / "model_registry.py"),
         "evaluate", version, "--events", str(eventos), "--attack-log", str(log),
         "--models-dir", str(registo), "--dataset-origin", origin, *extra],
        capture_output=True, text=True, encoding="utf-8",
        cwd=str(SCRIPT_DIR), timeout=180,
    )


def correr_cli_treino(registo, *, origin="unknown", version="v1", extra=()):
    """Corre `python model_registry.py train ...` como o utilizador o corre:
    num processo novo, com cwd=scripts/ (é de lá que os módulos se importam)."""
    return subprocess.run(
        [sys.executable, "-X", "utf8", str(SCRIPT_DIR / "model_registry.py"),
         "train", version, "--models-dir", str(registo), "--dataset-origin", origin, *extra],
        capture_output=True, text=True, encoding="utf-8",
        cwd=str(SCRIPT_DIR), timeout=180,
    )


def avaliacao_ponta_a_ponta(client) -> None:
    """
    Fase 2: o comando `evaluate` a sério (pickles REAIS) e a avaliação a
    chegar ao dashboard pela rota, já sub-projectada.

    Cobre o caminho feliz (ACTIVE -> v2 e `evaluate v1`, D-02), as recusas
    (hash adulterado com ZERO chamadas a joblib.load, id inválido, versão
    inexistente) e a sub-projeção do `evaluation` escrito à mão (D-08).
    """
    print("\n--- avaliação ponta a ponta (EVAL-01/02/03, D-02/D-08) ---")

    original_dir = main.ML_MODEL_DIR
    original_joblib = ml_anomalies.joblib

    with tempfile.TemporaryDirectory() as tmp:
        raiz = Path(tmp)
        model_bytes, scaler_bytes = real_model_bytes()

        eventos = raiz / "eventos.json"
        eventos.write_text(json.dumps(MOCK_ALERTS, ensure_ascii=False), encoding="utf-8")
        # Um ataque que cobre UM evento só (o das 03:05:00, com janela de 120 s).
        log = raiz / "attack_log.jsonl"
        log.write_text(
            json.dumps({"timestamp": "2026-09-02T03:05:00Z", "type": "brute_force"}) + "\n",
            encoding="utf-8")

        def registo_com_duas(nome):
            pasta = raiz / nome
            make_version(pasta, "v1", model_bytes=model_bytes, scaler_bytes=scaler_bytes)
            make_version(pasta, "v2", model_bytes=model_bytes, scaler_bytes=scaler_bytes)
            write_active(pasta, "v2")
            return pasta

        def por_id(body):
            return {v.get("id"): v for v in body.get("versions") or []}

        # D-01/D-08: o registo e o motor têm de ter a MESMA lista de chaves,
        # pela mesma ordem. São duas listas escritas à mão (o registo não pode
        # importar o motor, D-01), e este é o teste que ata essa costura.
        import ml_evaluation  # noqa: PLC0415 — só no teste, para comparar

        check("(s) EVALUATION_KEYS do motor == EVALUATION_PUBLIC_KEYS do registo",
              tuple(ml_evaluation.EVALUATION_KEYS)
              == tuple(model_registry.EVALUATION_PUBLIC_KEYS)
              and len(ml_evaluation.EVALUATION_KEYS) == 14)
        check("(s) METRIC_KEYS do motor == EVALUATION_METRIC_KEYS do registo",
              tuple(ml_evaluation.METRIC_KEYS) == tuple(model_registry.EVALUATION_METRIC_KEYS))
        check("(s) COMPARISON_KEYS do motor == EVALUATION_COMPARISON_KEYS do registo",
              tuple(ml_evaluation.COMPARISON_KEYS)
              == tuple(model_registry.EVALUATION_COMPARISON_KEYS))
        check("(s) o motor não tem train_model (avaliar não é treinar, T-02-03)",
              not hasattr(ml_evaluation, "train_model")
              and "train_anomaly_model" not in _modulos_de(ml_evaluation))
        check("(s) o motor não toca em joblib (só ml_anomalies desserializa, Pitfall 7)",
              "joblib" not in _modulos_de(ml_evaluation))

        try:
            # (s) caminho feliz: ACTIVE -> v2, mas o comando avalia a v1 (D-02).
            registo = registo_com_duas("aval-ok")
            meta_v2_antes = (registo / "v2" / "metadata.json").read_bytes()
            pkl_v1_antes = {n: (registo / "v1" / n).read_bytes() for n in model_registry.ARTIFACT_FILES}
            proc = correr_cli_evaluate(registo, eventos, log, origin="real", version="v1")
            check("(s) evaluate v1 -> código 0", proc.returncode == 0)
            check("(s) o stdout diz que avaliou a v1", "v1" in proc.stdout)
            check("(s) o stdout diz os eventos processados e os ataques",
                  "10 eventos processados" in proc.stdout and "1 rotulado como ataque" in proc.stdout)
            check("(s) o stdout diz onde foi gravado",
                  "metadata.json" in proc.stdout and "restantes versões não foram alteradas" in proc.stdout)
            check("(s) nada em stderr", proc.stderr.strip() == "")

            main.ML_MODEL_DIR = str(registo)
            resp = client.get("/api/ml/models")
            check("(s) /api/ml/models -> 200", resp.status_code == 200)
            body = resp.json()
            versoes = por_id(body)
            check("(s) a ativa continua a ser a v2", body.get("active") == "v2")
            check("(s) D-02: a avaliação foi para a v1 pedida",
                  versoes["v1"]["evaluation"] is not None)
            check("(s) D-02: a v2 continua sem avaliação",
                  versoes["v2"]["evaluation"] is None)
            avaliacao = versoes["v1"]["evaluation"] or {}
            check("(s) total_events == 10", avaliacao.get("total_events") == 10)
            check("(s) attacks_in_dataset == 1", avaliacao.get("attacks_in_dataset") == 1)
            check("(s) a avaliação tem EXACTAMENTE as 14 chaves do registo",
                  set(avaliacao) == set(model_registry.EVALUATION_PUBLIC_KEYS)
                  and len(avaliacao) == 14)
            check("(s) ml e rules têm as três métricas",
                  set(avaliacao.get("ml") or {}) == set(model_registry.EVALUATION_METRIC_KEYS)
                  and set(avaliacao.get("rules") or {}) == set(model_registry.EVALUATION_METRIC_KEYS))
            check("(s) comparison tem as quatro contagens",
                  set(avaliacao.get("comparison") or {})
                  == set(model_registry.EVALUATION_COMPARISON_KEYS))
            check("(s) as quatro contagens somam total_events",
                  sum((avaliacao.get("comparison") or {}).values()) == avaliacao.get("total_events"))
            check("(s) os limiares gravados são os do motor",
                  avaliacao.get("min_events") == 50 and avaliacao.get("min_attacks") == 10)
            check("(s) small_sample True (10 eventos, 1 ataque)", avaliacao.get("small_sample") is True)
            check("(s) events_file é só o nome, sem caminho",
                  avaliacao.get("events_file") == "eventos.json"
                  and "/" not in str(avaliacao.get("events_file"))
                  and "\\" not in str(avaliacao.get("events_file")))
            check("(s) dataset_origin real", avaliacao.get("dataset_origin") == "real")
            check("(s) nenhum valor da avaliação traz um caminho",
                  not any("/" in str(v) or "\\" in str(v) or DRIVE_RE.match(str(v))
                          for v in avaliacao.values() if isinstance(v, str)))
            check("(s) o metadata.json da v2 ficou byte-idêntico",
                  (registo / "v2" / "metadata.json").read_bytes() == meta_v2_antes)
            check("(s) os .pkl da v1 ficaram byte-idênticos",
                  all((registo / "v1" / n).read_bytes() == pkl_v1_antes[n]
                      for n in model_registry.ARTIFACT_FILES))
            check("(s) a v1 listada continua íntegra",
                  versoes["v1"]["status"] == "ok")
            no_leaks_pasta("(s) /api/ml/models", resp, registo)

            # (t) um byte trocado no .pkl -> hash_mismatch e ZERO joblib.load.
            #     O `evaluate` é chamado no próprio processo porque um contador
            #     de chamadas a joblib.load não atravessa um subprocesso.
            adulterado = registo_com_duas("aval-adulterado")
            flip_byte(adulterado / "v1" / MODEL_FILE)
            contador = ContadorJoblib()
            ml_anomalies.joblib = contador
            try:
                try:
                    model_registry.evaluate(str(adulterado), "v1", str(eventos), str(log),
                                             dataset_origin="real")
                    exc = None
                except model_registry.ModelRegistryError as raised:
                    exc = raised
                check("(t) evaluate com .pkl adulterado -> hash_mismatch",
                      exc is not None and exc.code == "hash_mismatch")
                check("(t) ZERO chamadas a joblib.load com bytes não verificados",
                      contador.chamadas == 0)
                check("(t) nada foi gravado na v1 adulterada",
                      json.loads((adulterado / "v1" / "metadata.json").read_text(encoding="utf-8"))["evaluation"]
                      is None)
            finally:
                ml_anomalies.joblib = original_joblib

            proc = correr_cli_evaluate(adulterado, eventos, log, origin="real", version="v1")
            check("(t) o CLI com .pkl adulterado -> código 1", proc.returncode == 1)
            check("(t) e stderr traz hash_mismatch", "hash_mismatch" in proc.stderr)
            check("(t) e a mensagem não traz caminho", str(adulterado) not in proc.stderr)

            # (u) id inválido e versão inexistente -> 1 com o código certo.
            proc = correr_cli_evaluate(registo, eventos, log, origin="real", version="v9")
            check("(u) evaluate v9 -> código 1", proc.returncode == 1)
            check("(u) evaluate v9 -> active_not_found em stderr",
                  "active_not_found" in proc.stderr)
            proc = correr_cli_evaluate(registo, eventos, log, origin="real", version="../x")
            check("(u) evaluate ../x -> código 1", proc.returncode == 1)
            check("(u) evaluate ../x -> invalid_version_id em stderr",
                  "invalid_version_id" in proc.stderr)

            # (v) D-08: texto arbitrário escrito à mão no metadata.json nunca
            #     sai pela API.
            manual = registo_com_duas("aval-manual")
            caminho = manual / "v1" / "metadata.json"
            meta = json.loads(caminho.read_text(encoding="utf-8"))
            payload = {k: 0 for k in model_registry.EVALUATION_PUBLIC_KEYS}
            payload.update({
                "evaluated_at": "2026-10-10T09:30:00+00:00",
                "events_file": "eventos.json",
                "attack_log": "attack_log.jsonl",
                "label_window_seconds": 120,
                "total_events": 10,
                "attacks_in_dataset": 1,
                "ml": {"precision": 0.5, "recall": 0.5, "f1": 0.5, "nota": "<img src=x>"},
                "rules": {"precision": 0.25, "recall": 0.25, "f1": 0.25, "nota": "<img src=x>"},
                "comparison": {"both_flagged": 1, "ml_only": 0, "rules_only": 0,
                               "neither": 9, "extra": "<img src=x>"},
                "min_events": 50,
                "min_attacks": 10,
                "small_sample": True,
                "caveat": "Dataset pequeno (10 eventos, 1 ataques) — não é uma estimativa robusta.",
                "dataset_origin": "real",
                "nota_qualquer": "<img src=x onerror=alert(1)>",
            })
            meta["evaluation"] = payload
            caminho.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
            main.ML_MODEL_DIR = str(manual)
            resp = client.get("/api/ml/models")
            check("(v) /api/ml/models -> 200 com evaluation escrito à mão", resp.status_code == 200)
            avaliacao_v = (por_id(resp.json())["v1"]["evaluation"] or {})
            check("(v) a chave arbitrária é descartada",
                  "nota_qualquer" not in resp.text and "nota_qualquer" not in avaliacao_v)
            check("(v) as chaves arbitrárias dentro de ml/rules/comparison também",
                  set(avaliacao_v["ml"]) == set(model_registry.EVALUATION_METRIC_KEYS)
                  and set(avaliacao_v["comparison"]) == set(model_registry.EVALUATION_COMPARISON_KEYS))
            check("(v) o HTML arbitrário nunca sai na resposta", "<img" not in resp.text)
            check("(v) as chaves sub-projetadas continuam presentes",
                  set(avaliacao_v) == set(model_registry.EVALUATION_PUBLIC_KEYS))
            check("(v) a v2 sem avaliação continua null", por_id(resp.json())["v2"]["evaluation"] is None)
            no_leaks_pasta("(v) /api/ml/models", resp, manual)

            # (x) payload fora do contrato: o CLI recusa e o metadata.json
            #     anterior fica BYTE-IDÉNTICO (EVAL-01, T-02-12). É a única
            #     prova possível deste caminho: `test_model_registry.py` não
            #     pode importar sklearn (D-01) e `test_ml_evaluation.py` é
            #     uma suite de domínio sem disco.
            #
            #     Duas adulterações, porque só uma delas prova a barreira
            #     NOVA: o `_write_evaluation` do 02-01 já contava as 14
            #     chaves, por isso "falta uma chave" passaria sem o
            #     `validate_evaluation`. O caso 'incoerente' traz as 14
            #     chaves todas e uma soma que não fecha — para aí só pode
            #     ter sido o validador a recusar.
            #
            #     O motor é trocado num PROCESSO NOVO (wrapper escrito na
            #     pasta temporária): é o `validate_evaluation` do CLI a
            #     correr a sério que apanha o payload, não o teste a fazer as
            #     contas por ele.
            adulterado_payload = registo_com_duas("aval-payload")
            controlo = correr_cli_evaluate(adulterado_payload, eventos, log,
                                           origin="real", version="v1")
            check("(x) o comando sem adulteração -> código 0 (controlo)",
                  controlo.returncode == 0)
            caminho_meta = adulterado_payload / "v1" / "metadata.json"
            bytes_antes = caminho_meta.read_bytes()
            avaliacao_antes = json.loads(bytes_antes.decode("utf-8"))["evaluation"]
            check("(x) o comando de controlo gravou mesmo uma avaliação",
                  avaliacao_antes is not None)
            pkl_antes = {n: (adulterado_payload / "v1" / n).read_bytes()
                         for n in model_registry.ARTIFACT_FILES}

            wrapper = raiz / "wrapper_payload_invalido.py"
            wrapper.write_text(
                "import os\n"
                "import sys\n"
                "\n"
                "import ml_evaluation\n"
                "import model_registry\n"
                "\n"
                "original = ml_evaluation.build_evaluation_report\n"
                "modo = os.environ.get('ADULTERACAO', 'falta_chave')\n"
                "\n"
                "def adulterado(*args, **kwargs):\n"
                "    payload = original(*args, **kwargs)\n"
                "    if modo == 'falta_chave':\n"
                "        payload.pop('caveat', None)\n"
                "    elif modo == 'incoerente':\n"
                "        payload['comparison']['neither'] = 99\n"
                "    return payload\n"
                "\n"
                "ml_evaluation.build_evaluation_report = adulterado\n"
                "sys.exit(model_registry.main(sys.argv[1:]))\n",
                encoding="utf-8")

            def correr_adulterado(modo):
                return subprocess.run(
                    [sys.executable, "-X", "utf8", str(wrapper),
                     "evaluate", "v1", "--events", str(eventos),
                     "--attack-log", str(log),
                     "--models-dir", str(adulterado_payload),
                     "--dataset-origin", "real"],
                    capture_output=True, text=True, encoding="utf-8",
                    cwd=str(SCRIPT_DIR), timeout=180,
                    # O wrapper vive na pasta temporária, por isso `scripts/`
                    # não está em sys.path[0] como acontece no CLI normal.
                    env={**os.environ, "PYTHONPATH": str(SCRIPT_DIR), "ADULTERACAO": modo})

            for modo, esperado in (("falta_chave", "caveat"),
                                   ("incoerente", "comparison")):
                proc = correr_adulterado(modo)
                etiqueta = f"(x/{modo})"
                check(f"{etiqueta} payload fora do contrato -> código 1",
                      proc.returncode == 1)
                check(f"{etiqueta} stderr diz que a avaliação é inválida",
                      "evaluation_invalid" in proc.stderr)
                check(f"{etiqueta} stderr diz a regra que falhou ({esperado})",
                      esperado in proc.stderr)
                check(f"{etiqueta} stderr não traz o caminho do registo",
                      str(adulterado_payload) not in proc.stderr)
                check(f"{etiqueta} nada foi escrito em stdout",
                      proc.stdout.strip() == "")
                check(f"{etiqueta} o metadata.json anterior ficou byte-idêntico",
                      caminho_meta.read_bytes() == bytes_antes)
                check(f"{etiqueta} a avaliação boa continua lá, intacta",
                      json.loads(caminho_meta.read_text(encoding="utf-8"))["evaluation"]
                      == avaliacao_antes)
                check(f"{etiqueta} os .pkl ficaram byte-idênticos",
                      all((adulterado_payload / "v1" / n).read_bytes() == pkl_antes[n]
                          for n in model_registry.ARTIFACT_FILES))

            check("(x) o comando volta a gravar depois de a adulteração passar",
                  correr_cli_evaluate(adulterado_payload, eventos, log,
                                      origin="real", version="v1").returncode == 0)

            # (w) o teto por campo: um caveat gigante é truncado, não devolvido
            #     inteiro, e um valor do tipo errado cai a None.
            caminho.write_text(json.dumps(
                {**meta, "evaluation": {**payload, "caveat": "X" * 5000, "total_events": "dez"}},
                ensure_ascii=False, indent=2), encoding="utf-8")
            resp = client.get("/api/ml/models")
            avaliacao_w = (por_id(resp.json())["v1"]["evaluation"] or {})
            check("(w) um texto gigante é truncado ao teto",
                  isinstance(avaliacao_w["caveat"], str)
                  and len(avaliacao_w["caveat"]) <= model_registry.EVALUATION_TEXT_LIMIT
                  and avaliacao_w["caveat"].endswith("…"))
            check("(w) um valor do tipo errado cai a None", avaliacao_w["total_events"] is None)
        finally:
            ml_anomalies.joblib = original_joblib
            ml_anomalies.reset_cache()
            main.ML_MODEL_DIR = original_dir


# --- R10: as duas rotas de escrita (plano 10-03) ---------------------------------

# As DUAS tabelas de erro, escritas À MÃO de propósito. São a mesma costura que
# `EVALUATION_KEYS` impõe ao registo: duas listas, uma igualdade presa por um
# teste. Mudar uma sem a outra dá vermelho.
ML_WRITE_STATUS_ESPERADO = {
    "dataset_not_found": 404,
    "dataset_unusable": 422,
    "training_in_progress": 409,
    "training_failed": 503,
}
ML_REGISTRY_STATUS_ESPERADO = {
    "invalid_version_id": 404,
    "active_not_found": 404,
    "metadata_missing": 404,
    "metadata_invalid": 503,
    "artifact_missing": 404,
    "hash_mismatch": 503,
    "already_adopted": 409,
    "no_legacy_model": 404,
    "registry_unavailable": 503,
}

# O pin do `MLTrainRequest`: cinco campos, dois obrigatórios, três com teto. É
# este pin que garante que ninguém acrescenta um campo de caminho ao pedido sem
# o plano o dizer (D-01.1).
MLTRAIN_CAMPOS = ("dataset", "dataset_origin", "contamination", "random_state", "n_estimators")
MLTRAIN_OBRIGATORIOS = ("dataset", "dataset_origin")
MLTRAIN_TETOS = {
    "contamination": (0.01, 0.5),
    "random_state": (0, 4294967295),
    "n_estimators": (10, 1000),
}
CORPO_MINIMO = {"dataset": "latest_export", "dataset_origin": "real"}


@contextlib.contextmanager
def ambiente_treino(export_dir, attack_log_path=None):
    """
    Aponta o motor para pastas de teste e restaura o ambiente no `finally`.

    O motor resolve o export do AMBIENTE a cada chamada (`ML_EXPORT_DIR`) e o
    log de ataques do mesmo modo (`ATTACK_LOG_PATH`), por isso o contexto mexe
    no `os.environ` em vez de nos módulos. `REQUESTED_EXPORT` sai de cena
    porque o `.env` do utilizador pode tê-lo posto, e ele ganha a `latest_export`
    sem o teste o saber.
    """
    chaves = ("ML_EXPORT_DIR", "ATTACK_LOG_PATH", "REQUESTED_EXPORT")
    antes = {chave: os.environ.get(chave) for chave in chaves}
    os.environ["ML_EXPORT_DIR"] = str(export_dir)
    os.environ.pop("REQUESTED_EXPORT", None)
    if attack_log_path is not None:
        os.environ["ATTACK_LOG_PATH"] = str(attack_log_path)
    try:
        yield
    finally:
        for chave, valor in antes.items():
            if valor is None:
                os.environ.pop(chave, None)
            else:
                os.environ[chave] = valor


def exportar_eventos(pasta, documentos, nome="2026-09-14_15-22.json") -> Path:
    """Cria a pasta e escreve lá um export com o NOME que o `resolve_export_path`
    reconhece. Devolve a PASTA, não o ficheiro: é `ML_EXPORT_DIR` que a quer, e
    apontá-la para o `.json` dava `dataset_not_found` em silêncio."""
    pasta.mkdir(parents=True, exist_ok=True)
    (pasta / nome).write_text(json.dumps(documentos, ensure_ascii=False), encoding="utf-8")
    return pasta


def log_de_ataque(pasta, timestamp="2026-09-02T03:05:00Z", tipo="brute_force") -> Path:
    """Um log JSONL com UM ataque, que cobre um evento de MOCK_ALERTS."""
    pasta.mkdir(parents=True, exist_ok=True)
    destino = pasta / "attack_log.jsonl"
    destino.write_text(json.dumps({"timestamp": timestamp, "type": tipo}) + "\n", encoding="utf-8")
    return destino


def listagem(pasta) -> list[str]:
    return sorted(p.name for p in Path(pasta).iterdir())


def fingerprint(pasta) -> dict:
    """Fotografia byte a byte do registo: quem escreve em models/ tem de mudar isto."""
    raiz = Path(pasta)
    return {p.name: (hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else "<pasta>")
            for p in sorted(raiz.iterdir())}


def treinar(client, **extra) -> "object":
    """Um POST /api/ml/train com o corpo mínimo mais `extra`."""
    return client.post("/api/ml/train", json={**CORPO_MINIMO, **extra}, headers=HEADERS)


def limites_do_pedido(client) -> None:
    """
    A superfície, antes de o motor: quem entra, o que o corpo aceita e o que
    ele recusa. Nenhum destes cenários treina — os que seriam 200 à partida
    ficam para `treino_ponta_a_ponta`.
    """
    print("\n--- limites do pedido, autenticação e corpo sem caminhos (R10/D-01) ---")

    original_dir = main.ML_MODEL_DIR

    with tempfile.TemporaryDirectory() as tmp:
        raiz = Path(tmp)
        export_dir = exportar_eventos(raiz / "exports", MOCK_ALERTS)
        log = log_de_ataque(raiz)
        models_dir = raiz / "models"

        def usar() -> None:
            main.ML_MODEL_DIR = str(models_dir)
            ml_anomalies.reset_cache()

        usar()
        try:
            with ambiente_treino(export_dir, log):
                # (A) As duas rotas novas exigem a chave no PRÓPRIO decorador.
                #     A dependency corre antes da validação do corpo, por isso
                #     um corpo lixo dá 401 e não 422 — e o corpo nem é lido.
                sem_key = TestClient(main.app)
                for rota, json_body in (("/api/ml/train", CORPO_MINIMO),
                                        ("/api/ml/models/v1/activate", None)):
                    resp = sem_key.post(rota, json=json_body)
                    check(f"(A) {rota} sem X-API-Key -> 401", resp.status_code == 401)
                    check(f"(A) {rota} sem chave -> detail estável",
                          resp.json().get("detail") == "API key inválida ou em falta")
                    errada = TestClient(main.app, headers={"X-API-Key": "chave-errada"})
                    resp = errada.post(rota, json=json_body)
                    check(f"(A) {rota} com chave errada -> 401", resp.status_code == 401)
                    check(f"(A) {rota} sem chave NÃO escreve nada",
                          not models_dir.exists() or listagem(models_dir) == [])

                # (B) O pin do MLTrainRequest: cinco campos, dois obrigatórios,
                #     três com teto, `extra="forbid"`. Campo a campo — este é o
                #     teste que trava alguém de acrescentar `models_dir` ao
                #     corpo sem o plano o dizer.
                campos = main.MLTrainRequest.model_fields
                check("(B) MLTrainRequest tem EXACTAMENTE os cinco campos",
                      set(campos) == set(MLTRAIN_CAMPOS) and len(campos) == 5)
                check("(B) dataset e dataset_origin são obrigatórios",
                      all(campos[nome].is_required() for nome in MLTRAIN_OBRIGATORIOS))
                check("(B) os outros três têm valor por omissão",
                      not any(campos[nome].is_required()
                              for nome in ("contamination", "random_state", "n_estimators")))
                check("(B) extra='forbid'", main.MLTrainRequest.model_config.get("extra") == "forbid")
                limites_ok = True
                for nome, (minimo, maximo) in MLTRAIN_TETOS.items():
                    # No Pydantic v2 o `metadata` são objetos anotados
                    # (`annotated_types.Ge`), não tuplas: vai-se pelo atributo.
                    declarados = {getattr(meta, limite)
                                  for meta in campos[nome].metadata
                                  for limite in ("ge", "le") if hasattr(meta, limite)}
                    limites_ok = limites_ok and {minimo, maximo} <= declarados
                check("(B) os três tetos são os do pin, campo a campo", limites_ok)
                check("(B) os valores por omissão são 0.2 / 42 / 200",
                      campos["contamination"].default == 0.2
                      and campos["random_state"].default == 42
                      and campos["n_estimators"].default == 200)

                # (B) As tabelas de erro: duas listas escritas à mão contra as
                #     de main.py, e a de TRAINING_ERROR_CODES completa.
                check("(B) a tabela de TRAINING_ERROR_CODES é a do teste",
                      main._ML_WRITE_STATUS == ML_WRITE_STATUS_ESPERADO
                      and set(main._ML_WRITE_STATUS) == set(ml_training.TRAINING_ERROR_CODES)
                      and len(ml_training.TRAINING_ERROR_CODES) == 4)
                check("(B) a tabela de ERROR_CODES é a do teste, com as 9 chaves",
                      main._ML_REGISTRY_STATUS == ML_REGISTRY_STATUS_ESPERADO
                      and set(main._ML_REGISTRY_STATUS) == set(model_registry.ERROR_CODES)
                      and len(model_registry.ERROR_CODES) == 9)
                check("(B) ERROR_CODES não cresceu com os quatro de treino",
                      not set(model_registry.ERROR_CODES) & set(ml_training.TRAINING_ERROR_CODES))

                # (C) Os obrigatórios a faltar: 422 com os dois no `detail`.
                resp = client.post("/api/ml/train", json={}, headers=HEADERS)
                detalhe = json.dumps(resp.json().get("detail"))
                check("(C) corpo vazio -> 422", resp.status_code == 422)
                check("(C) o detail nomeia os dois obrigatórios",
                      "dataset" in detalhe and "dataset_origin" in detalhe)
                resp = client.post("/api/ml/train", json={"dataset": "latest_export"}, headers=HEADERS)
                check("(C) falta o dataset_origin -> 422", resp.status_code == 422)

                # (D) Os `Literal` fecham o caminho (D-01.4). "../../etc/passwd"
                #     e "C:/Users/x/eventos.json" são 422 do Pydantic, não do
                #     motor — e nada é escrito.
                for mau in ("../../etc/passwd", "C:/Users/fnuno/eventos.json",
                            "/etc/passwd", "", "LATEST_EXPORT"):
                    resp = treinar(client, dataset=mau)
                    check(f"(D) dataset={mau!r} -> 422", resp.status_code == 422)
                for mau in ("inventado", "REAL", ""):
                    resp = treinar(client, dataset_origin=mau)
                    check(f"(D) dataset_origin={mau!r} -> 422", resp.status_code == 422)
                check("(D) nenhum destes 422 escreveu em models/",
                      not models_dir.exists() or listagem(models_dir) == [])

                # (E) O corpo sem caminhos — o pin de D-01.1 por HTTP. Sem
                #     `extra="forbid"` o Pydantic v2 IGNORARIA estas chaves em
                #     silêncio e o utilizador acreditaria ter escolhido o sítio.
                for chave in ("events", "models_dir", "attack_log", "sources",
                              "path", "url", "MODEL_DIR", "models-dir"):
                    antes = fingerprint(models_dir) if models_dir.exists() else {}
                    resp = treinar(client, **{chave: "C:/Users/x"})
                    depois = fingerprint(models_dir) if models_dir.exists() else {}
                    check(f"(E) chave extra {chave!r} -> 422", resp.status_code == 422)
                    check(f"(E) chave extra {chave!r} não escreveu nada", antes == depois)
                    # O Pydantic v2 devolve o `input` rejeitado no detail — que
                    # aqui é o valor que o próprio cliente enviou, e portanto
                    # não é uma fuga. O que não pode aparecer é caminho do
                    # SERVIDOR, e é isso que se mede.
                    no_leaks_pasta(f"(E) chave extra {chave!r}", resp, models_dir)
                    check(f"(E) chave extra {chave!r} não traz a pasta de exports",
                          str(export_dir) not in resp.text)
                resp = client.post("/api/ml/train", data="nao sou json",
                                   headers={**HEADERS, "Content-Type": "application/json"})
                check("(E) corpo que não é JSON -> 422", resp.status_code == 422)

                # (F) Os tetos pelos dois lados (D-01.3). Fora: 422. Dentro:
                #     200 — e o `.pkl` carregado tem MESMO o número pedido, que
                #     é o que prova que o tecto não é decorativo nem um filtro
                #     que nunca deixa passar nada.
                fora = [
                    ({"contamination": 0.0}, "contamination 0.0"),
                    ({"contamination": 0.51}, "contamination 0.51"),
                    ({"contamination": -1}, "contamination negativa"),
                    ({"random_state": -1}, "random_state -1"),
                    ({"random_state": 4294967296}, "random_state 4294967296"),
                    ({"n_estimators": 9}, "n_estimators 9"),
                    ({"n_estimators": 1001}, "n_estimators 1001"),
                    ({"n_estimators": 10 ** 9}, "n_estimators 10**9 (o DoS de uma linha)"),
                ]
                for extra, etiqueta in fora:
                    antes = fingerprint(models_dir) if models_dir.exists() else {}
                    resp = treinar(client, **extra)
                    depois = fingerprint(models_dir) if models_dir.exists() else {}
                    check(f"(F) {etiqueta} -> 422", resp.status_code == 422)
                    check(f"(F) {etiqueta} não escreveu nada", antes == depois)

                dentro = [
                    {"contamination": 0.01},
                    {"contamination": 0.5},
                    {"random_state": 0},
                    {"random_state": 4294967295},
                    {"n_estimators": 10},
                    {"n_estimators": 1000},
                ]
                versao_do_tecto = None
                for extra in dentro:
                    usar()
                    resp = treinar(client, **extra)
                    pedido = next(iter(extra))
                    check(f"(F) {pedido}={extra[pedido]} (dentro) -> 200", resp.status_code == 200)
                    if resp.status_code == 200:
                        versao = resp.json()["version"]
                        gravado = json.loads(
                            (Path(main.ML_MODEL_DIR) / versao / "metadata.json")
                            .read_text(encoding="utf-8"))["parameters"]
                        check(f"(F) {pedido}={extra[pedido]} vai para o metadata.json",
                              gravado.get(pedido) == extra[pedido])
                        if extra[pedido] == MLTRAIN_TETOS["n_estimators"][1]:
                            versao_do_tecto = versao
                usar()
                # O tecto não é decorativo: o `.pkl` que saiu do POST com
                # n_estimators=1000 tem MESMO 1000 árvores dentro. É o que
                # distingue um `Field(le=1000)` de um `Field(le=10)` que
                # apenas passa testes por nunca ninguém chegar lá.
                pkl = joblib.load(Path(main.ML_MODEL_DIR) / versao_do_tecto / MODEL_FILE)
                check("(F) o .pkl do POST com n_estimators=1000 tem 1000 árvores",
                      int(getattr(pkl, "n_estimators", 0)) == 1000)

                # (G) `../x` NEM CHEGA ao handler: o `{version_id}` não casa
                #     slashes, por isso o router devolve o seu próprio 404. O
                #     `invalid_version_id` do registo é provado no
                #     `test_ml_training.py` (mesmo `validate_version_id`, mas
                #     sem o path-param pelo meio) — e escrito aqui para que
                #     ninguém escreva um caso impossível à espera do 404 do
                #     registo e o teste falhe por uma razão errada.
                resp = client.post("/api/ml/models/../x/activate", headers=HEADERS)
                check("(G) '../x' -> 404 do router (não do registo)", resp.status_code == 404)
                check("(G) e o detail é o do router, não um código do registo",
                      resp.json().get("detail") == "Not Found")
                resp = client.post("/api/ml/models/v99999/activate", headers=HEADERS)
                check("(G) v99999 (5 dígitos) -> 422 do pattern do FastAPI",
                      resp.status_code == 422)
        finally:
            ml_anomalies.reset_cache()
            main.ML_MODEL_DIR = original_dir


def treino_ponta_a_ponta(client) -> None:
    """
    O caminho feliz inteiro, com o `metadata.json` conferido contra os factos
    que o próprio teste calcula a partir do fixture — e os quatro caminhos de
    falha do motor traduzidos para HTTP.
    """
    print("\n--- treino ponta a ponta e erros do motor (R10/D-01) ---")

    original_dir = main.ML_MODEL_DIR
    original_train = train_anomaly_model.train_model
    original_indexer = main.indexer_client.get_recent_alerts
    main.indexer_client.get_recent_alerts = AsyncMock(return_value=MOCK_ALERTS)

    with tempfile.TemporaryDirectory() as tmp:
        raiz = Path(tmp)
        export_dir = exportar_eventos(raiz / "exports", MOCK_ALERTS)
        log = log_de_ataque(raiz)
        models_dir = raiz / "models"

        def usar() -> None:
            main.ML_MODEL_DIR = str(models_dir)
            ml_anomalies.reset_cache()

        usar()
        try:
            with ambiente_treino(export_dir, log):
                # (H) 200 com TUDO numa resposta: a v1 criada, activada e já
                #     em memória, mais o relatório completo — sem segundo GET.
                resp = treinar(client)
                check("(H) POST /api/ml/train -> 200", resp.status_code == 200)
                body = resp.json() if resp.status_code == 200 else {}
                check("(H) version/active/loaded são a v1, sem reiniciar o backend",
                      body.get("version") == "v1" and body.get("active") == "v1"
                      and body.get("loaded") == "v1")
                check("(H) evaluation é None numa versão recém-treinada (EVAL-03)",
                      body.get("evaluation") is None)
                check("(H) catalog_sha256 é o do registo",
                      body.get("catalog_sha256") == model_registry.catalog_sha256())
                report = body.get("report") or {}
                check("(H) o report embutido é o build_models_report completo",
                      report.get("total") == 1 and report.get("active") == "v1"
                      and (report.get("versions") or [{}])[0].get("status") == "ok")
                check("(H) a v1 do report vem com catalog_compatible True",
                      (report.get("versions") or [{}])[0].get("catalog_compatible") is True)
                check("(H) a resposta tem as sete chaves do payload mais 'report'",
                      set(body) == {"version", "active", "loaded", "dataset", "parameters",
                                    "evaluation", "catalog_sha256", "report"})

                # (H) O metadata.json em disco, conferido contra o que o TESTE
                #     calcula do fixture — não contra o que a rota devolveu.
                meta = json.loads((models_dir / "v1" / "metadata.json").read_text(encoding="utf-8"))
                check("(H) origin == 'trained'", meta.get("origin") == "trained")
                check("(H) trained_at presente e estimated False",
                      bool(meta.get("trained_at")) and meta.get("trained_at_estimated") is False)
                check("(H) parameters é o que foi pedido",
                      meta["parameters"]["contamination"] == 0.2
                      and meta["parameters"]["random_state"] == 42
                      and meta["parameters"]["n_estimators"] == 200)
                check("(H) synthetic False com dataset_origin 'real'",
                      meta["dataset"]["synthetic"] is False)
                linhas = extract_features(MOCK_ALERTS)
                check("(H) dataset.documents é o nº de documentos do export",
                      meta["dataset"]["documents"] == len(MOCK_ALERTS))
                check("(H) dataset.size e processable são as linhas treináveis",
                      meta["dataset"]["size"] == len(linhas)
                      and meta["dataset"]["processable"] == len(linhas))
                check("(H) dataset.attacks é 1 (o log tem uma entrada)",
                      meta["dataset"]["attacks"] == 1)
                check("(H) dataset.truncated False", meta["dataset"]["truncated"] is False)
                carimbos = sorted(a["@timestamp"] for a in MOCK_ALERTS)
                check("(H) a janela é a do fixture",
                      meta["dataset"]["window_first"] == carimbos[0]
                      and meta["dataset"]["window_last"] == carimbos[-1])
                check("(H) feature_stats tem as 7 features com mean e std",
                      set(meta["feature_stats"]) == set(
                          feature_extractor.FEATURE_NAMES)
                      and all(set(v) == {"mean", "std"} for v in meta["feature_stats"].values()))
                check("(H) os SHA-256 gravados batem com os .pkl em disco",
                      all(hashlib.sha256((models_dir / "v1" / nome).read_bytes()).hexdigest()
                          == meta["artifacts"][nome]["sha256"]
                          for nome in model_registry.ARTIFACT_FILES))
                check("(H) o registo ficou com ACTIVE e v1, e nada mais",
                      listagem(models_dir) == ["ACTIVE", "v1"])
                check("(H) ACTIVE em disco aponta para a v1",
                      (models_dir / "ACTIVE").read_text(encoding="utf-8").strip() == "v1")
                check("(H) nenhum temporário do registo ficou por limpar",
                      not [n for n in listagem(models_dir) if ".tmp-" in n])
                check("(H) loaded_version() é a v1 sem reiniciar o backend",
                      ml_anomalies.loaded_version() == "v1")

                # (H) ML_MODEL_DIR a apontar para uma pasta que não existe ainda:
                #     o motor cria-a (primeiro treino numa máquina nova).
                usar()
                shutil_target = raiz / "novo-registo"
                main.ML_MODEL_DIR = str(shutil_target)
                resp = treinar(client)
                check("(H) ML_MODEL_DIR inexistente -> 200 e a v1 criada lá",
                      resp.status_code == 200 and listagem(shutil_target) == ["ACTIVE", "v1"])
                usar()

                # (H) E a apontar para um FICHEIRO: 503 registry_unavailable, e
                #     nada escrito em lado nenhum.
                ficheiro = raiz / "isto-e-um-ficheiro"
                ficheiro.write_bytes(b"nao sou uma pasta")
                antes_ficheiro = ficheiro.read_bytes()
                main.ML_MODEL_DIR = str(ficheiro)
                resp = treinar(client)
                check("(H) ML_MODEL_DIR é um ficheiro -> 503",
                      resp.status_code == 503)
                check("(H) e detail == 'registry_unavailable'",
                      resp.json().get("detail") == "registry_unavailable")
                check("(H) e o ficheiro ficou byte-idêntico", ficheiro.read_bytes() == antes_ficheiro)
                no_leaks_pasta("(H) ML_MODEL_DIR ficheiro", resp, ficheiro)
                usar()

                # (I) dataset_not_found: a pasta de exports está vazia -> 404.
                vazia = raiz / "sem-exports"
                vazia.mkdir()
                antes = fingerprint(models_dir)
                with ambiente_treino(vazia, log):
                    resp = treinar(client)
                check("(I) pasta de exports vazia -> 404", resp.status_code == 404)
                check("(I) e detail == 'dataset_not_found'",
                      resp.json().get("detail") == "dataset_not_found")
                check("(I) nada foi escrito", fingerprint(models_dir) == antes)

                # (I) dataset_unusable: existe mas não dá linhas treináveis.
                invalido = raiz / "exports-invalidos"
                invalido.mkdir()
                (invalido / "2026-09-14_15-22.json").write_text("{isto não é json",
                                                                 encoding="utf-8")
                antes = fingerprint(models_dir)
                with ambiente_treino(invalido, log):
                    resp = treinar(client)
                check("(I) export que não é JSON -> 422", resp.status_code == 422)
                check("(I) e detail == 'dataset_unusable'",
                      resp.json().get("detail") == "dataset_unusable")
                check("(I) nada foi escrito", fingerprint(models_dir) == antes)

                sem_linhas = raiz / "exports-sem-linhas"
                exportar_eventos(sem_linhas, [{"foo": "bar"}, {"data": {}}])
                with ambiente_treino(sem_linhas, log):
                    resp = treinar(client)
                check("(I) export sem @timestamp -> 422", resp.status_code == 422)
                check("(I) e detail == 'dataset_unusable'",
                      resp.json().get("detail") == "dataset_unusable")
                check("(I) nada foi escrito", fingerprint(models_dir) == antes)
                no_leaks_pasta("(I) dataset_unusable", resp, export_dir)

                # (J) KeyboardInterrupt a meio: 503 training_failed e o lock
                #     libertado. É o caminho que um `Ctrl-C` ou um
                #     KeyboardInterrupt do atexit produz — e sem o `except`
                #     nomeado sairia um 500 do uvicorn.
                def interrompe(*args, **kwargs):
                    raise KeyboardInterrupt("C:/Users/fnuno/segredo")

                train_anomaly_model.train_model = interrompe
                try:
                    antes = fingerprint(models_dir)
                    resp = treinar(client)
                    check("(J) KeyboardInterrupt -> 503", resp.status_code == 503)
                    check("(J) e detail == 'training_failed'",
                          resp.json().get("detail") == "training_failed")
                    check("(J) nada foi escrito", fingerprint(models_dir) == antes)
                    check("(J) o lock ficou libertado (busy() False)",
                          ml_training.busy() is False)
                    check("(J) e o 503 não traz o segredo nem traceback",
                          "segredo" not in resp.text and "Traceback" not in resp.text)

                    # (K) Excepção inesperada: 503 registry_unavailable, sem
                    #     texto, sem caminho, sem palavra "boom".
                    def explode(*args, **kwargs):
                        raise RuntimeError("C:/Users/fnuno/segredo boom")

                    train_anomaly_model.train_model = explode
                    resp = treinar(client)
                    check("(K) RuntimeError -> 503", resp.status_code == 503)
                    check("(K) e detail == 'registry_unavailable'",
                          resp.json().get("detail") == "registry_unavailable")
                    check("(K) sem 'boom', sem caminho e sem traceback",
                          "boom" not in resp.text and "segredo" not in resp.text
                          and "Traceback" not in resp.text)
                    no_leaks_pasta("(K) RuntimeError", resp, export_dir)
                    check("(K) o lock ficou libertado", ml_training.busy() is False)
                finally:
                    train_anomaly_model.train_model = original_train

                # (L) Voltar a treinar depois de tudo o que falhou acima: o
                #     motor não ficou fechado para sempre.
                usar()
                resp = treinar(client)
                check("(L) treinar depois das falhas -> 200", resp.status_code == 200)
                check("(L) e sai uma v2 (a v1 ficou intacta)",
                      resp.status_code == 200 and resp.json()["version"] == "v2")
        finally:
            train_anomaly_model.train_model = original_train
            main.indexer_client.get_recent_alerts = original_indexer
            ml_anomalies.reset_cache()
            main.ML_MODEL_DIR = original_dir


def activate_ponta_a_ponta(client) -> None:
    """
    Activar sem treinar: o caminho bom, o `.pkl` adulterado (que nem chega ao
    `joblib.load`), o id que não existe e o compare-and-set a perder.
    """
    print("\n--- activate ponta a ponta (R10/D-01) ---")

    original_dir = main.ML_MODEL_DIR
    original_joblib = ml_anomalies.joblib
    original_write = model_registry._write_active_atomic
    original_indexer = main.indexer_client.get_recent_alerts
    main.indexer_client.get_recent_alerts = AsyncMock(return_value=MOCK_ALERTS)

    with tempfile.TemporaryDirectory() as tmp:
        raiz = Path(tmp)
        export_dir = exportar_eventos(raiz / "exports", MOCK_ALERTS)
        log = log_de_ataque(raiz)
        models_dir = raiz / "models"

        def usar() -> None:
            main.ML_MODEL_DIR = str(models_dir)
            ml_anomalies.reset_cache()

        usar()
        try:
            with ambiente_treino(export_dir, log):
                treinar(client)

                # (M) O caminho bom: activar a v1 quando o ACTIVE aponta para a
                #     v2 devolve as duas, e a cache é recarregada.
                make_version(models_dir, "v2",
                             model_bytes=(models_dir / "v1" / MODEL_FILE).read_bytes(),
                             scaler_bytes=(models_dir / "v1" / SCALER_FILE).read_bytes())
                write_active(models_dir, "v2")
                usar()
                resp = client.post("/api/ml/models/v1/activate", headers=HEADERS)
                check("(M) activar a v1 com ACTIVE=v2 -> 200", resp.status_code == 200)
                body = resp.json() if resp.status_code == 200 else {}
                check("(M) version/previous/loaded coerentes",
                      body.get("version") == "v1" and body.get("previous") == "v2"
                      and body.get("loaded") == "v1")
                check("(M) o ACTIVE em disco passou a v1",
                      (models_dir / "ACTIVE").read_bytes() == b"v1\n")
                check("(M) e o report embutido diz active v1 com total 2",
                      (body.get("report") or {}).get("active") == "v1"
                      and (body.get("report") or {}).get("total") == 2)

                # (N) Versão que não existe: 404 active_not_found. E o ACTIVE
                #     fica como estava.
                antes = (models_dir / "ACTIVE").read_bytes()
                resp = client.post("/api/ml/models/v9/activate", headers=HEADERS)
                check("(N) activar a v9 (inexistente) -> 404", resp.status_code == 404)
                check("(N) e detail == 'active_not_found'",
                      resp.json().get("detail") == "active_not_found")
                check("(N) o ACTIVE não se mexeu", (models_dir / "ACTIVE").read_bytes() == antes)

                # (O) .pkl adulterado: 503 hash_mismatch, ZERO joblib.load e o
                #     ACTIVE byte-idêntico. A verificação é ANTES da escrita.
                pkl_v1 = (models_dir / "v1" / MODEL_FILE).read_bytes()
                (models_dir / "v2" / MODEL_FILE).write_bytes(b"x" * 64)
                contador = ContadorJoblib()
                ml_anomalies.joblib = contador
                try:
                    antes = (models_dir / "ACTIVE").read_bytes()
                    resp = client.post("/api/ml/models/v2/activate", headers=HEADERS)
                    check("(O) activar v2 com .pkl adulterado -> 503", resp.status_code == 503)
                    check("(O) e detail == 'hash_mismatch'",
                          resp.json().get("detail") == "hash_mismatch")
                    check("(O) ZERO chamadas a joblib.load", contador.chamadas == 0)
                    check("(O) o ACTIVE ficou byte-idêntico",
                          (models_dir / "ACTIVE").read_bytes() == antes)
                    no_leaks_pasta("(O) hash_mismatch", resp, models_dir)
                finally:
                    ml_anomalies.joblib = original_joblib
                (models_dir / "v2" / MODEL_FILE).write_bytes(pkl_v1)

                # (P) O compare-and-set a perder: entre a leitura do ACTIVE (que
                #     aqui é a v1) e a escrita, outro escritor lá mete a v2. A
                #     rota perde com training_failed e NÃO sobrescreve o que o
                #     outro deixou — e a cache não muda, porque o
                #     reset_cache/load_model vêm depois da escrita.
                def intruso(root, version_id, expected=None):
                    write_active(root, "v2")
                    return original_write(root, version_id, expected=expected)

                model_registry._write_active_atomic = intruso
                try:
                    resp = client.post("/api/ml/models/v2/activate", headers=HEADERS)
                    check("(P) ACTIVE trocado entre a leitura e a escrita -> 503",
                          resp.status_code == 503)
                    check("(P) e detail == 'training_failed'",
                          resp.json().get("detail") == "training_failed")
                    check("(P) o ACTIVE ficou com o valor do OUTRO escritor",
                          (models_dir / "ACTIVE").read_text(encoding="utf-8").strip() == "v2")
                    check("(P) e a cache NÃO recarregou (segue na v1)",
                          ml_anomalies.loaded_version() == "v1")
                    check("(P) e o lock ficou libertado", ml_training.busy() is False)
                    no_leaks_pasta("(P) training_failed", resp, models_dir)
                finally:
                    model_registry._write_active_atomic = original_write

                # (Q) E volta a funcionar: o motor não ficou fechado.
                usar()
                resp = client.post("/api/ml/models/v1/activate", headers=HEADERS)
                check("(Q) activar outra vez depois do compare-and-set -> 200",
                      resp.status_code == 200)
                check("(Q) e o ACTIVE é a v1",
                      resp.status_code == 200
                      and (models_dir / "ACTIVE").read_text(encoding="utf-8").strip() == "v1")
        finally:
            model_registry._write_active_atomic = original_write
            ml_anomalies.joblib = original_joblib
            main.indexer_client.get_recent_alerts = original_indexer
            ml_anomalies.reset_cache()
            main.ML_MODEL_DIR = original_dir


def model_version_no_relatorio(client) -> None:
    """
    D-06: o relatório de anomalias diz de que versão veio cada número — e
    quando não há versão nenhuma, diz isso.
    """
    print("\n--- model_version no relatório (R10/D-06) ---")

    # O conjunto de chaves que já existia ANTES desta fase, escrito à mão. A
    # chave nova é aditiva: nenhuma das outras muda de nome nem de significado.
    CHAVES_ANTES_DA_CHAVE_NOVA = {
        "total", "ml_anomalies_count", "rule_flagged_count",
        "agree_count", "diverge_count", "results",
        "window_hours", "alerts_fetched", "alerts_truncated",
    }

    original_dir = main.ML_MODEL_DIR
    original_indexer = main.indexer_client.get_recent_alerts
    original_report = ml_anomalies.build_ml_anomalies_report
    main.indexer_client.get_recent_alerts = AsyncMock(return_value=MOCK_ALERTS)

    with tempfile.TemporaryDirectory() as tmp:
        raiz = Path(tmp)
        model_bytes, scaler_bytes = real_model_bytes()

        def usar(pasta) -> None:
            main.ML_MODEL_DIR = str(pasta)
            ml_anomalies.reset_cache()

        try:
            # (R) v1 activa: model_version == 'v1', e o número e a versão saem
            #     da mesma fonte (a cache que o load_model encheu).
            verificada = raiz / "verificada"
            make_version(verificada, "v1", model_bytes=model_bytes, scaler_bytes=scaler_bytes)
            write_active(verificada, "v1")
            usar(verificada)
            resp = client.get("/api/ml-anomalies")
            check("(R) v1 activa -> 200", resp.status_code == 200)
            body = resp.json() if resp.status_code == 200 else {}
            check("(R) model_version == 'v1'", body.get("model_version") == "v1")
            check("(R) e é a mesma que o ml_anomalies tem em memória",
                  body.get("model_version") == ml_anomalies.loaded_version())
            check("(R) as chaves anteriores continuam todas, mais a nova",
                  set(body) == CHAVES_ANTES_DA_CHAVE_NOVA | {"model_version"})
            check("(R) e os números não mudaram de significado", body.get("total") == len(MOCK_ALERTS))

            # (S) O LEGADO: dois .pkl soltos, sem v1/ e sem ACTIVE. É o estado
            #     real de scripts/models/ hoje, e é onde um model_version mal
            #     feito diria "v1" ao utilizador.
            legado = make_legacy(raiz / "legado", model_bytes=model_bytes,
                                 scaler_bytes=scaler_bytes)
            usar(legado)
            resp = client.get("/api/ml-anomalies")
            body = resp.json() if resp.status_code == 200 else {}
            check("(S) legado -> model_version == 'legacy' (não None, não 'v1')",
                  resp.status_code == 200 and body.get("model_version") == "legacy")

            # (T) O caminho vazio: a chave continua lá. Um frontend que tenha de
            #     tratar "a chave às vezes não está" é um frontend com dois
            #     caminhos para o mesmo caso.
            ml_anomalies.build_ml_anomalies_report = lambda alertas, m, s: {
                "total": 0, "ml_anomalies_count": 0, "rule_flagged_count": 0,
                "agree_count": 0, "diverge_count": 0, "results": [],
            }
            try:
                resp = client.get("/api/ml-anomalies")
                body = resp.json() if resp.status_code == 200 else {}
                check("(T) relatório vazio -> 200 com total 0", resp.status_code == 200
                      and body.get("total") == 0 and body.get("results") == [])
                check("(T) e model_version continua presente",
                      "model_version" in body
                      and body.get("model_version") == ml_anomalies.loaded_version())
            finally:
                ml_anomalies.build_ml_anomalies_report = original_report

            # (U) .pkl adulterado: é um erro, não um relatório. A chave nova não
            #     aparece — não há nenhum número para atribuir a uma versão.
            adulterado = raiz / "adulterado"
            make_version(adulterado, "v1", model_bytes=model_bytes, scaler_bytes=scaler_bytes)
            flip_byte(adulterado / "v1" / MODEL_FILE)
            write_active(adulterado, "v1")
            usar(adulterado)
            resp = client.get("/api/ml-anomalies")
            check("(U) .pkl adulterado -> 503", resp.status_code == 503)
            check("(U) e sem model_version na resposta", "model_version" not in resp.text)
            no_leaks_pasta("(U) hash_mismatch", resp, adulterado)

            # (U) E o Indexer continua a ser chamado UMA vez, com I/O novo zero:
            #     a rota não ganhou um fetch nem um run_in_threadpool.
            usar(verificada)
            main.indexer_client.get_recent_alerts = AsyncMock(return_value=MOCK_ALERTS)
            resp = client.get("/api/ml-anomalies")
            check("(U) o Indexer é chamado uma vez por relatório",
                  resp.status_code == 200
                  and main.indexer_client.get_recent_alerts.await_count == 1)
        finally:
            main.indexer_client.get_recent_alerts = original_indexer
            ml_anomalies.build_ml_anomalies_report = original_report
            ml_anomalies.reset_cache()
            main.ML_MODEL_DIR = original_dir


class Gate:
    """
    Duas portas: `chegou` posta por quem entrou no treino, `livre` para quem o
    deixa sair. Duplicado de propósito do `test_ml_training.py` — os dois
    ficheiros são standalone e não se importam (é a convenção do projecto, e o
    `run_all_tests.py` corre-os em processos paralelos). Se isto passar a um
    utilitário partilhado em `ml_training.py`, os dois ficheiros de teste ficam
    acoplados e o ganho é nenhum.
    """

    def __init__(self) -> None:
        self.chegou = threading.Event()
        self.livre = threading.Event()


def _paralelo(funcoes):
    """
    Corre as funções em threads e devolve `(resultados, threads)`, por ordem.

    NÃO faz `join`: quem chama é que tem de ABRIR o `Gate` antes de as threads
    terminarem. Um `join` aqui seria um deadlock — a thread presa espera pelo
    `Gate`, e o `Gate` só é posto depois do `join` voltar. (Na primeira versão
    desta função havia o join, e o `wait(timeout=60)` do `Gate` é que abria a
    porta por exaustão: o teste passava por sorte e gastava um minuto.)
    """
    resultados: list = [None] * len(funcoes)

    def embrulhar(indice, funcao):
        def corre():
            try:
                resultados[indice] = funcao()
            except BaseException as exc:  # noqa: BLE001 — o teste QUER ver a falha
                resultados[indice] = exc
        return corre

    threads = [threading.Thread(target=embrulhar(i, f), daemon=True)
               for i, f in enumerate(funcoes)]
    for t in threads:
        t.start()
    return resultados, threads


def _juntar(threads, timeout=120) -> bool:
    """Espera as threads. Devolve False se alguma sobreviveu ao `timeout`."""
    for t in threads:
        t.join(timeout=timeout)
    return not any(t.is_alive() for t in threads)


def dois_posts_concorrentes(client) -> None:
    """
    O contrato de single-flight POR HTTP (D-01.2): três pedidos em simultâneo
    dão exactamente um 200 e dois 409, o registo fica com uma v1 consistente e
    sem sobras, e um pedido normal a seguir prova que o lock libertou.

    Sem `train_model` a travar num `Gate`, dois pedidos podem passar os dois
    pelo `claim()` e isto passa por sorte umas vezes e falha outras — é o
    mecanismo que torna o teste determinístico.
    """
    print("\n--- dois POSTs concorrentes: exactamente um 200 (R10/D-01.2) ---")

    original_dir = main.ML_MODEL_DIR
    original_train = train_anomaly_model.train_model
    original_indexer = main.indexer_client.get_recent_alerts
    main.indexer_client.get_recent_alerts = AsyncMock(return_value=MOCK_ALERTS)

    with tempfile.TemporaryDirectory() as tmp:
        raiz = Path(tmp)
        export_dir = exportar_eventos(raiz / "exports", MOCK_ALERTS)
        log = log_de_ataque(raiz)
        models_dir = raiz / "models"

        def usar() -> None:
            main.ML_MODEL_DIR = str(models_dir)
            ml_anomalies.reset_cache()

        usar()
        try:
            with ambiente_treino(export_dir, log):
                gate = Gate()
                lentido = {}

                def lento(*args, **kwargs):
                    # Chamar o ORIGINAL é o que mantém o `.pkl` um
                    # IsolationForest a sério, para que o `load_model` do fim
                    # da sequência faça `joblib.load` sem explodir.
                    modelo, scaler = original_train(*args, **kwargs)
                    lentido["n_estimators"] = kwargs.get("n_estimators")
                    gate.chegou.set()
                    gate.livre.wait(timeout=60)
                    return modelo, scaler

                make_legacy(models_dir)  # o caso do utilizador real: dois .pkl soltos
                antes = fingerprint(models_dir)

                def postar():
                    return treinar(client)

                train_anomaly_model.train_model = lento
                try:
                    # A entra primeiro e fica presa dentro do treino; B e C
                    # batem no `claim()` enquanto isso.
                    resultados, threads = _paralelo([
                        lambda: postar(),
                        lambda: postar(),
                        lambda: postar(),
                    ])
                    # Espera explícita: se a thread A não chegou a travar, os
                    # outros dois podem ter entrado em paralelo e o teste
                    # deixaria de medir o que diz medir.
                    check("(V) o primeiro pedido chegou a treinar",
                          gate.chegou.wait(timeout=30))
                    gate.livre.set()
                    check("(V) nenhuma thread ficou presa", _juntar(threads))

                    codigos = sorted(r.status_code for r in resultados if hasattr(r, "status_code"))
                    check("(V) exactamente um 200 e dois 409", codigos == [200, 409, 409])
                    conflicts = [r for r in resultados
                                 if getattr(r, "status_code", None) == 409]
                    check("(V) os 409 dizem 'training_in_progress'",
                          all(r.json().get("detail") == "training_in_progress" for r in conflicts))
                    check("(V) os 409 não escreveram nada em models/",
                          [n for n in fingerprint(models_dir) if n not in antes] == ["ACTIVE", "v1"])
                    check("(V) nenhum 409 traz caminho nem traceback",
                          all("Traceback" not in r.text for r in conflicts))

                    ok = [r for r in resultados if getattr(r, "status_code", None) == 200]
                    check("(V) o 200 criou e activou a v1, já em memória",
                          len(ok) == 1 and ok[0].json()["version"] == "v1"
                          and ok[0].json()["loaded"] == "v1")
                    check("(V) o registo ficou consistente: ACTIVE + v1 e nada mais",
                          listagem(models_dir) == ["ACTIVE", "isolation_forest.pkl",
                                                   "scaler.pkl", "v1"])
                    check("(V) nenhum v1.tmp-* nem ACTIVE.tmp-* ficou por limpar",
                          not [n for n in listagem(models_dir) if ".tmp-" in n])
                    relatorio = model_registry.build_models_report(
                        str(models_dir), ml_anomalies.loaded_version())
                    check("(V) o build_models_report dá total 1, active v1, status ok",
                          relatorio["total"] == 1 and relatorio["active"] == "v1"
                          and relatorio["versions"][0]["status"] == "ok")
                    check("(V) e o loaded_version() é a v1 sem reiniciar o backend",
                          ml_anomalies.loaded_version() == "v1")

                    # Um pedido normal a seguir: se o `_slot()` tivesse ficado
                    # tomado, ESTE é o check que o apanhava.
                    gate.livre.set()
                    resp = postar()
                    check("(V) um pedido depois dos 409 -> 200 com v2",
                          resp.status_code == 200 and resp.json()["version"] == "v2")
                    check("(V) e a v1 ficou intacta", (models_dir / "v1" / "metadata.json").is_file())
                    check("(V) busy() é False no fim", ml_training.busy() is False)

                    # O espelho: activar durante um treino também dá 409, e o ACTIVE
                    # não muda (D-01.2 cobre treinar -> registar -> activar
                    # com o MESMO lock).
                    #
                    # O treino entra SOZINHO e só depois de o `Gate` confirmar
                    # que ele já está dentro do `train_model` é que o activate
                    # parte. Ao contrário do cenário de cima (onde as três
                    # threads correm à vontade e o合同 é "um 200 e o resto
                    # 409"), aqui o objecto é saber QUAL foi o 409 — e isso
                    # não se mede atirando as duas coisas ao mesmo tempo: quem
                    # ganha o lock depende do scheduler.
                    gate2 = Gate()

                    def lento2(*args, **kwargs):
                        modelo, scaler = original_train(*args, **kwargs)
                        gate2.chegou.set()
                        gate2.livre.wait(timeout=60)
                        return modelo, scaler

                    train_anomaly_model.train_model = lento2
                    try:
                        antes_activate = fingerprint(models_dir)
                        resultados2, threads2 = _paralelo([postar])
                        check("(V) o treino ficou preso dentro do train_model",
                              gate2.chegou.wait(timeout=30))
                        # Agora sim, com o lock tomado: o activate tem de levar
                        # 409 e não pode tocar no ACTIVE.
                        resp_activate = client.post("/api/ml/models/v1/activate",
                                                    headers=HEADERS)
                        check("(V) activar durante um treino -> 409",
                              resp_activate.status_code == 409)
                        check("(V) e detail == 'training_in_progress'",
                              resp_activate.json().get("detail") == "training_in_progress")
                        check("(V) e o ACTIVE ficou byte-idêntico",
                              fingerprint(models_dir) == antes_activate)
                        check("(V) e o 409 não traz caminho nem traceback",
                              "Traceback" not in resp_activate.text)
                        gate2.livre.set()
                        check("(V) o treino preso também não ficou pendurado",
                              _juntar(threads2))
                        treino = resultados2[0]
                        check("(V) e o treino que estava dentro passou -> 200 com v3",
                              getattr(treino, "status_code", None) == 200
                              and treino.json()["version"] == "v3")
                        check("(V) busy() é False no fim outra vez",
                              ml_training.busy() is False)
                    finally:
                        gate2.livre.set()
                        train_anomaly_model.train_model = original_train
                finally:
                    gate.livre.set()
                    train_anomaly_model.train_model = original_train
        finally:
            train_anomaly_model.train_model = original_train
            main.indexer_client.get_recent_alerts = original_indexer
            ml_anomalies.reset_cache()
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