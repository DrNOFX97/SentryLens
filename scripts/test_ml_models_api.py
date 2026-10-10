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

import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock

os.environ.setdefault("SENTRYLENS_API_KEY", "chave-de-teste-nao-usar-em-producao")

import joblib
from fastapi.testclient import TestClient

import main
import ml_anomalies
import model_registry
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