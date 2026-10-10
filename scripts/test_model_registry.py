"""
Testes de domínio do registo de modelos (scripts/model_registry.py) — marco
R9. Cobrem REG-01, REG-02, SEC-01 e SEC-02 sem pipeline nenhum: este módulo
não importa joblib, nem ml_anomalies, nem FastAPI, e nunca desserializa nada
— só lê os .pkl para os comparar com o SHA-256 do metadata.json.

Nada toca no scripts/models real: todo o disco vive num
tempfile.TemporaryDirectory() (fora do OneDrive, ver 01-RESEARCH Pitfall 5) e
os `.pkl` das fixtures são bytes arbitrários — um hash sobre bytes inventados
exercita exatamente o mesmo caminho de código que um hash sobre um pickle
real, sem trazer um desserializador para dentro do teste de domínio.

Correr (a partir de scripts/):
    python test_model_registry.py
"""

import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import model_registry

try:  # o console do Windows pode não ser UTF-8 (ver CLAUDE.md, reconfigure)
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

MODEL_FILE, SCALER_FILE = model_registry.ARTIFACT_FILES

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def skip(label: str, why: str) -> None:
    """O SO recusou as duas formas de link — não é falha (ver 01-02-PLAN)."""
    print(f"[SKIP ] {label} — {why}")


def secao(titulo: str) -> None:
    print(f"\n--- {titulo} ---")


# --- Fixtures -----------------------------------------------------------------


def make_version(root, vid, model_bytes=b"fake-model", scaler_bytes=b"fake-scaler",
                 model_sha=None, scaler_sha=None, **meta_overrides) -> Path:
    """Cria models/vN/ com os dois .pkl e um metadata.json válido (schema 1).

    SHA-256 e size_bytes são calculados a sério, para a versão passar a
    verificação de integridade sem qualquer ajuste à mão. `model_sha`/
    `scaler_sha` servem para escrever um hash EXPECTADO diferente do ficheiro
    (minúsculas ou maiúsculas, 63 caracteres, ...).
    """
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
                "sha256": model_sha or hashlib.sha256(model_bytes).hexdigest(),
                "size_bytes": len(model_bytes),
            },
            SCALER_FILE: {
                "sha256": scaler_sha or hashlib.sha256(scaler_bytes).hexdigest(),
                "size_bytes": len(scaler_bytes),
            },
        },
        "evaluation": None,
    }
    meta.update(meta_overrides)
    (version_dir / model_registry.METADATA_FILE).write_text(
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


def write_active(root, data) -> None:
    """Escreve models/ACTIVE em bytes crus, para controlar a codificação."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    (Path(root) / model_registry.ACTIVE_FILE).write_bytes(data)


def flip_byte(path) -> None:
    """Troca um byte do ficheiro in-place, mantendo o tamanho."""
    data = Path(path).read_bytes()
    trocado = bytearray(data)
    trocado[-1] ^= 0xFF
    Path(path).write_bytes(bytes(trocado))


def versoes_por_id(report) -> dict:
    return {v.get("id"): v for v in report.get("versions") or []}


def entradas_legacy(report) -> list:
    return [v for v in report.get("versions") or [] if v.get("kind") == "legacy"]


def espera_erro(func, *args, codigo=None, **kwargs):
    """Chama func e devolve a ModelRegistryError levantada (ou None)."""
    try:
        func(*args, **kwargs)
    except model_registry.ModelRegistryError as exc:
        return exc
    return None


# --- REG-01: listar versões e a ativa -----------------------------------------


def test_reg01(tmp: Path) -> None:
    secao("REG-01 — versões listadas, ativa marcada, metadados projetados")

    root = tmp / "reg01"
    make_version(root, "v1")
    make_version(root, "v2", chave_desconhecida="nao-deve-vazar")
    write_active(root, "v1\n")
    report = model_registry.build_models_report(root)

    check("REG-01: active == 'v1'", report["active"] == "v1")
    check("REG-01: active_error is None", report["active_error"] is None)
    check("REG-01: versões por número decrescente",
          [v["id"] for v in report["versions"]] == ["v2", "v1"])
    check("REG-01: total == len(versions)", report["total"] == len(report["versions"]) == 2)
    por_id = versoes_por_id(report)
    check("REG-01: v1 marcada ativa", por_id["v1"]["active"] is True)
    check("REG-01: v2 não marcada ativa", por_id["v2"]["active"] is False)
    check("REG-01: kind 'versioned'", por_id["v1"]["kind"] == "versioned")
    check("REG-01: status 'ok' e error_code None",
          por_id["v1"]["status"] == "ok" and por_id["v1"]["error_code"] is None)
    check("REG-01: evaluation None", por_id["v1"]["evaluation"] is None)

    metadata = por_id["v2"]["metadata"] or {}
    check("REG-01: metadata tem todas as METADATA_PUBLIC_KEYS",
          set(metadata) == set(model_registry.METADATA_PUBLIC_KEYS))
    check("REG-01: metadata não expõe uma chave desconhecida do metadata.json",
          "chave_desconhecida" not in metadata)
    check("REG-01: artifacts só com os nomes constantes",
          set(metadata.get("artifacts") or {}) == set(model_registry.ARTIFACT_FILES))

    check("REG-01: loaded=None por omissão", report["loaded"] is None)
    check("REG-01: loaded é repassado tal e qual (D-02)",
          model_registry.build_models_report(root, loaded="v1")["loaded"] == "v1")

    # Pasta vazia e pasta inexistente: o mesmo relatório, 200 na rota.
    vazia = tmp / "reg01-vazia"
    vazia.mkdir(parents=True, exist_ok=True)
    report_vazia = model_registry.build_models_report(vazia)
    check("REG-01: pasta vazia -> lista vazia",
          report_vazia == {"active": None, "active_error": None, "loaded": None,
                           "total": 0, "versions": []})
    report_inexistente = model_registry.build_models_report(tmp / "reg01-nao-existe")
    check("REG-01: pasta inexistente -> lista vazia, sem erro",
          report_inexistente["total"] == 0 and report_inexistente["versions"] == []
          and report_inexistente["active"] is None)


# --- REG-02 / D-03: o legado --------------------------------------------------


def test_reg02(tmp: Path) -> None:
    secao("REG-02 — o legado aparece como 'legado, sem metadados' e continua ativo")

    root = make_legacy(tmp / "reg02")
    report = model_registry.build_models_report(root)

    check("REG-02: active == 'legacy'", report["active"] == "legacy")
    check("REG-02: active_error is None", report["active_error"] is None)
    check("REG-02: uma entrada só", report["total"] == 1)
    legado = (report["versions"] or [{}])[0]
    check("REG-02: id None", legado.get("id") is None)
    check("REG-02: kind 'legacy'", legado.get("kind") == "legacy")
    check("REG-02: label LEGACY_LABEL", legado.get("label") == model_registry.LEGACY_LABEL)
    check("REG-02: status 'no_metadata'", legado.get("status") == "no_metadata")
    check("REG-02: error_code None", legado.get("error_code") is None)
    check("REG-02: metadata None", legado.get("metadata") is None)
    check("REG-02: evaluation None", legado.get("evaluation") is None)
    check("REG-02: active True", legado.get("active") is True)

    ficheiros = legado.get("files") or {}
    check("REG-02: files com os dois nomes",
          set(ficheiros) == set(model_registry.ARTIFACT_FILES))
    check("REG-02: size_bytes do modelo certo",
          ficheiros[MODEL_FILE]["size_bytes"] == len(b"legacy-model"))
    check("REG-02: size_bytes do scaler certo",
          ficheiros[SCALER_FILE]["size_bytes"] == len(b"legacy-scaler"))
    modificado = ficheiros[MODEL_FILE]["modified_at"]
    check("REG-02: modified_at em ISO-8601 com fuso",
          isinstance(modificado, str) and modificado.endswith("+00:00"))
    try:
        datetime.fromisoformat(modificado)
        parseia = True
    except ValueError:
        parseia = False
    check("REG-02: modified_at é um ISO-8601 válido", parseia)

    # D-03: com v1 adotada o legado desaparece da lista.
    com_v1 = make_legacy(tmp / "reg02-com-v1")
    make_version(com_v1, "v1")
    write_active(com_v1, "v1")
    report_v1 = model_registry.build_models_report(com_v1)
    check("D-03: legado + v1 + ACTIVE v1 -> nenhuma entrada legacy",
          entradas_legacy(report_v1) == [])
    check("D-03: e a v1 é a ativa",
          report_v1["active"] == "v1"
          and versoes_por_id(report_v1)["v1"]["active"] is True)

    # ACTIVE inválido com o legado em modo fallback: fail-closed — o ACTIVE
    # manda, e a entrada do legado aparece mas não como ativa.
    com_active_mau = make_legacy(tmp / "reg02-active-mau")
    write_active(com_active_mau, "../x")
    report_mau = model_registry.build_models_report(com_active_mau)
    check("REG-02: ACTIVE inválido + legado -> active null",
          report_mau["active"] is None)
    check("REG-02: ACTIVE inválido + legado -> active_error preenchido",
          report_mau["active_error"] == "invalid_version_id")
    legado_mau = entradas_legacy(report_mau)
    check("REG-02: ACTIVE inválido + legado -> entrada legacy presente mas inativa",
          len(legado_mau) == 1 and legado_mau[0]["active"] is False)

    # Legado com v1 mas sem ACTIVE: nada está ativo, o legado sai da lista.
    com_v1_sem_active = make_legacy(tmp / "reg02-v1-sem-active")
    make_version(com_v1_sem_active, "v1")
    report_sem_active = model_registry.build_models_report(com_v1_sem_active)
    check("D-03: legado + v1 sem ACTIVE -> nenhuma entrada legacy",
          entradas_legacy(report_sem_active) == [])
    check("D-03: legado + v1 sem ACTIVE -> active None",
          report_sem_active["active"] is None
          and report_sem_active["active_error"] is None)


# --- SEC-01: integridade SHA-256 antes de qualquer carregamento ----------------


def test_sec01(tmp: Path) -> None:
    secao("SEC-01 — SHA-256 conferido antes de devolver bytes ao carregamento")

    model_bytes, scaler_bytes = b"modelo-real-bytes", b"scaler-real-bytes"

    # 1. tudo certaininho -> verificado, bytes idênticos aos dos ficheiros.
    ok = tmp / "sec01-ok"
    make_version(ok, "v1", model_bytes=model_bytes, scaler_bytes=scaler_bytes)
    write_active(ok, "v1")
    report = model_registry.build_models_report(ok)
    check("SEC-01: hashes certos -> status 'ok'",
          versoes_por_id(report)["v1"]["status"] == "ok")
    fonte = model_registry.resolve_active_artifacts(ok)
    check("SEC-01: resolve_active_artifacts -> version 'v1'", fonte.version == "v1")
    check("SEC-01: resolve_active_artifacts -> verified True", fonte.verified is True)
    check("SEC-01: devolve exatamente os bytes do ficheiro do modelo",
          fonte.model_bytes == model_bytes)
    check("SEC-01: devolve exatamente os bytes do ficheiro do scaler",
          fonte.scaler_bytes == scaler_bytes)
    check("SEC-01: sha256_file bate com os bytes do ficheiro",
          model_registry.sha256_file(ok / "v1" / MODEL_FILE)
          == hashlib.sha256(model_bytes).hexdigest())

    # 2. um byte trocado no modelo.
    adulterado = tmp / "sec01-adulterado"
    make_version(adulterado, "v1", model_bytes=model_bytes, scaler_bytes=scaler_bytes)
    flip_byte(adulterado / "v1" / MODEL_FILE)
    report_ad = model_registry.build_models_report(adulterado)
    v1_ad = versoes_por_id(report_ad)["v1"]
    check("SEC-01: byte trocado no modelo -> status hash_mismatch",
          v1_ad["status"] == "hash_mismatch")
    check("SEC-01: byte trocado no modelo -> error_code hash_mismatch",
          v1_ad["error_code"] == "hash_mismatch")
    check("SEC-01: hash_mismatch mantém os metadados visíveis (SKELETON)",
          isinstance(v1_ad["metadata"], dict))

    # 3. um byte trocado no scaler (o modelo passa, o scaler não).
    adulterado_scaler = tmp / "sec01-adulterado-scaler"
    make_version(adulterado_scaler, "v1", model_bytes=model_bytes,
                 scaler_bytes=scaler_bytes)
    flip_byte(adulterado_scaler / "v1" / SCALER_FILE)
    check("SEC-01: byte trocado no scaler -> hash_mismatch na listagem",
          versoes_por_id(model_registry.build_models_report(adulterado_scaler))["v1"]["status"]
          == "hash_mismatch")

    # 4. scaler apagado.
    sem_scaler = tmp / "sec01-sem-scaler"
    make_version(sem_scaler, "v1", model_bytes=model_bytes, scaler_bytes=scaler_bytes)
    (sem_scaler / "v1" / SCALER_FILE).unlink()
    check("SEC-01: scaler apagado -> status artifact_missing",
          versoes_por_id(model_registry.build_models_report(sem_scaler))["v1"]["status"]
          == "artifact_missing")

    # 5. ACTIVE a apontar para a versão adulterada -> recusa no carregamento,
    #    com código estável e sem caminho na mensagem.
    write_active(adulterado, "v1")
    write_active(adulterado_scaler, "v1")
    write_active(sem_scaler, "v1")
    for rotulo, pasta, codigo in (
        ("modelo adulterado", adulterado, "hash_mismatch"),
        ("scaler adulterado", adulterado_scaler, "hash_mismatch"),
        ("scaler em falta", sem_scaler, "artifact_missing"),
    ):
        exc = espera_erro(model_registry.resolve_active_artifacts, pasta)
        check(f"SEC-01: {rotulo} -> ModelRegistryError({codigo})",
              exc is not None and exc.code == codigo)
        check(f"SEC-01: {rotulo} -> str(exc) é o código, sem caminho",
              exc is not None and str(exc) == exc.code
              and str(pasta) not in str(exc)
              and str(pasta.resolve()) not in str(exc))

    # 6. hash em maiúsculas no metadata.json é aceite.
    maiusculas = tmp / "sec01-maiusculas"
    make_version(maiusculas, "v1", model_bytes=model_bytes, scaler_bytes=scaler_bytes,
                 model_sha=hashlib.sha256(model_bytes).hexdigest().upper(),
                 scaler_sha=hashlib.sha256(scaler_bytes).hexdigest().upper())
    write_active(maiusculas, "v1")
    check("SEC-01: sha256 em maiúsculas aceite na listagem",
          versoes_por_id(model_registry.build_models_report(maiusculas))["v1"]["status"] == "ok")
    fonte_maiusculas = model_registry.resolve_active_artifacts(maiusculas)
    check("SEC-01: sha256 em maiúsculas aceite no carregamento",
          fonte_maiusculas.verified is True and fonte_maiusculas.model_bytes == model_bytes)

    # 7. sha256 com 63 caracteres -> metadata_invalid (forma, não conteúdo).
    curto = tmp / "sec01-hash-curto"
    make_version(curto, "v1", model_bytes=model_bytes, scaler_bytes=scaler_bytes,
                 model_sha=hashlib.sha256(model_bytes).hexdigest()[:63])
    check("SEC-01: sha256 com 63 caracteres -> metadata_invalid na listagem",
          versoes_por_id(model_registry.build_models_report(curto))["v1"]["status"]
          == "metadata_invalid")
    write_active(curto, "v1")
    exc_curto = espera_erro(model_registry.resolve_active_artifacts, curto)
    check("SEC-01: sha256 com 63 caracteres -> metadata_invalid no carregamento",
          exc_curto is not None and exc_curto.code == "metadata_invalid")

    # 8. read_verified_bytes recusa um nome que não seja uma constante de
    #    ARTIFACT_FILES — nenhum caminho se constrói a partir de texto externo.
    v_ok = tmp / "sec01-ok" / "v1"
    meta_ok = json.loads((v_ok / model_registry.METADATA_FILE).read_text(encoding="utf-8"))
    digest = meta_ok["artifacts"][MODEL_FILE]["sha256"]
    check("SEC-01: read_verified_bytes devolve os bytes verificados",
          model_registry.read_verified_bytes(v_ok, MODEL_FILE, digest) == model_bytes)
    check("SEC-01: read_verified_bytes aceita o hash em maiúsculas",
          model_registry.read_verified_bytes(v_ok, MODEL_FILE, digest.upper()) == model_bytes)
    exc_nome = espera_erro(model_registry.read_verified_bytes, v_ok, "../../secrets.pkl", digest)
    check("SEC-01: read_verified_bytes recusa um nome fora de ARTIFACT_FILES",
          exc_nome is not None and exc_nome.code == "metadata_invalid")
    exc_nome_falta = espera_erro(model_registry.read_verified_bytes, v_ok, "outro.pkl", digest)
    check("SEC-01: read_verified_bytes recusa 'outro.pkl'",
          exc_nome_falta is not None and exc_nome_falta.code == "metadata_invalid")
    exc_hash = espera_erro(model_registry.read_verified_bytes, v_ok, MODEL_FILE, "0" * 64)
    check("SEC-01: read_verified_bytes com hash errado -> hash_mismatch",
          exc_hash is not None and exc_hash.code == "hash_mismatch")
    exc_falta = espera_erro(model_registry.read_verified_bytes,
                            sem_scaler / "v1", SCALER_FILE, digest)
    check("SEC-01: read_verified_bytes com ficheiro em falta -> artifact_missing",
          exc_falta is not None and exc_falta.code == "artifact_missing")


# --- SEC-02: ids e ACTIVE à prova de path traversal ---------------------------


def test_sec02_ids(tmp: Path) -> None:
    secao("SEC-02 — validate_version_id recusa tudo o que não seja v[0-9]{1,4}")

    for valor in ("../x", "..\\x", "v1\n", "v1 ", "v12345", "V1", "", "C:/Windows",
                  "v1/..", "v1\tlixo", "v" + "\u0663", "xv1", "v1.0", None, 1, b"v1"):
        exc = espera_erro(model_registry.validate_version_id, valor)
        check(f"SEC-02: validate_version_id({valor!r}) -> invalid_version_id",
              exc is not None and exc.code == "invalid_version_id")

    for valor in ("v0", "v1", "v9999"):
        try:
            devolvido = model_registry.validate_version_id(valor)
        except model_registry.ModelRegistryError:
            devolvido = None
        check(f"SEC-02: validate_version_id({valor!r}) aceite", devolvido == valor)

    root = tmp / "sec02-ids"
    make_version(root, "v1")
    exc_dir = espera_erro(model_registry.resolve_version_dir, model_registry._root(root), "../x")
    check("SEC-02: resolve_version_dir(root, '../x') -> invalid_version_id",
          exc_dir is not None and exc_dir.code == "invalid_version_id")
    pasta = model_registry.resolve_version_dir(model_registry._root(root), "v1")
    check("SEC-02: resolve_version_dir(root, 'v1') devolve a pasta", pasta.name == "v1")


def test_sec02_active(tmp: Path) -> None:
    secao("SEC-02 — ACTIVE inválido nunca resolve fora de models/")

    invalidos = {
        "'../x'": b"../x",
        "'..\\x'": "..\\x".encode("utf-8"),
        "'C:/Windows'": b"C:/Windows",
        "'v12345'": b"v12345",
        "UTF-16 de 'v1'": "v1".encode("utf-16"),
        "65 bytes": b"v1" + b" " * 63,
        "'v1\\nlixo'": b"v1\nlixo",
        "vazio": b"",
    }
    for n, (rotulo, bruto) in enumerate(invalidos.items()):
        root = tmp / f"sec02-active-{n:02d}"
        make_version(root, "v1")
        write_active(root, bruto)
        report = model_registry.build_models_report(root)
        check(f"SEC-02: ACTIVE {rotulo} -> active null",
              report["active"] is None)
        check(f"SEC-02: ACTIVE {rotulo} -> active_error invalid_version_id",
              report["active_error"] == "invalid_version_id")
        exc = espera_erro(model_registry.resolve_active_artifacts, root)
        check(f"SEC-02: ACTIVE {rotulo} -> carregamento recusa com invalid_version_id",
              exc is not None and exc.code == "invalid_version_id")

    for n, (rotulo, bruto) in enumerate({
        "BOM UTF-8 + 'v1'": "\ufeffv1".encode("utf-8"),
        "'v1\\r\\n'": b"v1\r\n",
    }.items()):
        root = tmp / f"sec02-ok-{n:02d}"
        make_version(root, "v1")
        write_active(root, bruto)
        report = model_registry.build_models_report(root)
        check(f"SEC-02: ACTIVE {rotulo} -> ativa a v1",
              report["active"] == "v1" and report["active_error"] is None)

    sem_pasta = tmp / "sec02-active-sem-pasta"
    make_version(sem_pasta, "v1")
    write_active(sem_pasta, "v9")
    report_v9 = model_registry.build_models_report(sem_pasta)
    check("SEC-02: ACTIVE 'v9' sem pasta -> active_error active_not_found",
          report_v9["active"] is None
          and report_v9["active_error"] == "active_not_found")

    # ACTIVE inválido NÃO pode cair para o legado, mesmo com .pkl soltos
    # presentes em models/ (fail-closed).
    com_legado = make_legacy(tmp / "sec02-legacy-active-mau")
    write_active(com_legado, "../x")
    exc = espera_erro(model_registry.resolve_active_artifacts, com_legado)
    check("SEC-02: ACTIVE '../x' com legado presente não cai para o legado",
          exc is not None and exc.code == "invalid_version_id")


def test_sec02_junction(tmp: Path) -> None:
    secao("SEC-02 — vN como junction/symlink para fora de models/")

    with tempfile.TemporaryDirectory() as outro:
        fora = Path(outro) / "fora-de-models"
        make_version(fora, "v1")  # metadata.json válido, mas FUERA de models/

        root = tmp / "sec02-junction"
        root.mkdir(parents=True, exist_ok=True)
        link = root / "v7"
        tipo = None
        try:
            os.symlink(str(fora), str(link), target_is_directory=True)
            tipo = "symlink"
        except (OSError, NotImplementedError, AttributeError, NotImplementedError):
            try:
                import _winapi
                # Assinatura real: CreateJunction(link_path, target_path).
                _winapi.CreateJunction(str(link), str(fora))
                tipo = "junction"
            except Exception as exc:  # sem privilégios no Windows
                tipo = None
                skip("SEC-02: junction/symlink vN",
                     f"o SO recusou os.symlink e _winapi.CreateJunction ({type(exc).__name__})")

        if tipo is not None:
            try:
                report = model_registry.build_models_report(root)
                v7 = versoes_por_id(report).get("v7") or {}
                check(f"SEC-02: v7 ({tipo}) fora de models/ -> status invalid_version_id",
                      v7.get("status") == "invalid_version_id")
                check(f"SEC-02: v7 ({tipo}) fora de models/ -> metadata None",
                      v7.get("metadata") is None)
                write_active(root, "v7")
                report_active = model_registry.build_models_report(root)
                check(f"SEC-02: ACTIVE 'v7' ({tipo}) -> active_error invalid_version_id",
                      report_active["active"] is None
                      and report_active["active_error"] == "invalid_version_id")
                exc = espera_erro(model_registry.resolve_active_artifacts, root)
                check(f"SEC-02: carregamento com ACTIVE 'v7' ({tipo}) recusa",
                      exc is not None and exc.code == "invalid_version_id")
            finally:
                # Remover o link ANTES do cleanup: um rmtree de uma junction
                # apagaria o conteúdo do alvo.
                if tipo == "symlink" and link.is_symlink():
                    os.unlink(link)
                elif link.exists():
                    os.rmdir(link)
            check(f"SEC-02: o alvo do link sobreviveu à limpeza ({tipo})", fora.is_dir())


# --- _root e a pasta por omissão ----------------------------------------------


def test_root_e_inexistente(tmp: Path) -> None:
    secao("Pasta por omissão e pasta inexistente")

    omissao = tmp / "default-models"
    make_version(omissao, "v1")
    write_active(omissao, "v1")
    original = model_registry.DEFAULT_MODELS_DIR
    try:
        model_registry.DEFAULT_MODELS_DIR = omissao
        # "" é o que main.ML_MODEL_DIR vale com a linha `ML_MODEL_DIR=` vazia
        # do .env.example: tem de resolver para a pasta por omissão, nunca
        # para o cwd (que aqui é scripts/ e não tem v1/).
        report = model_registry.build_models_report("")
        check("_root: build_models_report('') usa DEFAULT_MODELS_DIR, não o cwd",
              report["active"] == "v1"
              and [v["id"] for v in report["versions"]] == ["v1"])
        check("_root: build_models_report(None) usa DEFAULT_MODELS_DIR",
              model_registry.build_models_report(None)["active"] == "v1")
        fonte = model_registry.resolve_active_artifacts("")
        check("_root: resolve_active_artifacts('') usa DEFAULT_MODELS_DIR",
              fonte.version == "v1" and fonte.verified is True)

        inexistente = tmp / "nao-existe-mesmo"
        report_vazio = model_registry.build_models_report(inexistente)
        check("Pasta inexistente: listagem vazia, sem exceção",
              report_vazio["total"] == 0 and report_vazio["versions"] == [])
        try:
            model_registry.resolve_active_artifacts(inexistente)
            falhou = None
        except FileNotFoundError as exc:
            falhou = exc
        except model_registry.ModelRegistryError as exc:
            falhou = exc
        check("Pasta inexistente: resolve_active_artifacts -> FileNotFoundError",
              isinstance(falhou, FileNotFoundError))
        check("Pasta inexistente: a mensagem não contém o caminho",
              falhou is not None and isinstance(falhou, FileNotFoundError)
              and str(inexistente) not in str(falhou)
              and str(inexistente.resolve()) not in str(falhou)
              and "Traceback" not in str(falhou))

        # Pasta vazia no carregamento: mesma mensagem, sem caminho.
        vazia = tmp / "vazia-para-carregar"
        vazia.mkdir(parents=True, exist_ok=True)
        try:
            model_registry.resolve_active_artifacts(vazia)
            erro_vazia = None
        except FileNotFoundError as exc:
            erro_vazia = exc
        check("Pasta vazia: FileNotFoundError com mensagem acionável e sem caminho",
              isinstance(erro_vazia, FileNotFoundError)
              and str(vazia) not in str(erro_vazia)
              and "train_anomaly_model.py" in str(erro_vazia))
    finally:
        model_registry.DEFAULT_MODELS_DIR = original


# --- REG-03: adopt — cópia atómica, ACTIVE só se não existir, retoma --------

# Data de treino "estimada" determinística: o adopt deriva-a do mtime de
# isolation_forest.pkl (SKELETON.md), por isso os testes fixam-no em vez de
# depender do relógio do sistema.
MTIME_FIXO = datetime(2026, 9, 14, 15, 40, tzinfo=timezone.utc)


def fixar_mtime(root) -> float:
    """Fixa o mtime dos dois .pkl soltos (shutil.utime) e devolve-o."""
    alvo = MTIME_FIXO.timestamp()
    for nome in model_registry.ARTIFACT_FILES:
        os.utime(Path(root) / nome, (alvo, alvo))
    return alvo


def fotografar(root) -> dict:
    """
    Fotografia dos dois `.pkl` soltos: SHA-256, tamanho e mtime. É a prova de
    T-01-17 — o adopt só os lê, e o teste compara esta fotografia antes e
    depois (inclusive no caminho de falha e no de retoma).
    """
    foto = {}
    for nome in model_registry.ARTIFACT_FILES:
        path = Path(root) / nome
        st = path.stat()
        foto[nome] = {
            "sha256": model_registry.sha256_file(path),
            "size_bytes": st.st_size,
            "mtime": st.st_mtime,
        }
    return foto


def restos(root, prefixo) -> list:
    """Nomes que começam por `prefixo` em `root` — nenhuma pasta `v1.tmp-*`
    nem ficheiro `ACTIVE.tmp-*` pode sobrar de um adopt."""
    return [n for n in os.listdir(root) if n.startswith(prefixo)]


def replace_bloqueado(*nomes):
    """
    Troca `model_registry.os.replace` por uma função que levanta
    PermissionError quando o destino tem um destes nomes — é o bloqueio do
    OneDrive/antivírus/Explorador (Pitfall 5) — e delega no os.replace real
    nos restantes destinos. Devolve a função original para o `finally` a
    restaurar.
    """
    original = model_registry.os.replace

    def bloqueado(src, dst, *args, **kwargs):
        if Path(dst).name in nomes:
            raise PermissionError(13, "Permission denied", str(dst))
        return original(src, dst, *args, **kwargs)

    model_registry.os.replace = bloqueado
    return original


def test_adopt_copia_o_legado(tmp: Path) -> None:
    secao("REG-03 — adopt copia o legado para v1, escreve ACTIVE e não toca nos originais")

    root = make_legacy(tmp / "reg03-ok", model_bytes=b"modelo-adotado", scaler_bytes=b"scaler-adotado")
    mtime = fixar_mtime(root)
    antes = fotografar(root)

    resultado = model_registry.adopt(root)
    v1 = Path(root) / "v1"

    check("REG-03: devolve version 'v1'", resultado["version"] == "v1")
    check("REG-03: devolve resumed False", resultado["resumed"] is False)
    check("REG-03: devolve active_written True", resultado["active_written"] is True)

    meta = json.loads((v1 / model_registry.METADATA_FILE).read_text(encoding="utf-8"))
    check("REG-03: schema_version == 1", meta["schema_version"] == model_registry.SCHEMA_VERSION)
    check("REG-03: version == 'v1'", meta["version"] == "v1")
    check("REG-03: origin == 'adopted'", meta["origin"] == "adopted")
    check("REG-03: adopted is True", meta["adopted"] is True)
    check("REG-03: trained_at == mtime de isolation_forest.pkl em UTC",
          meta["trained_at"] == datetime.fromtimestamp(mtime, timezone.utc).isoformat())
    check("REG-03: trained_at_estimated is True", meta["trained_at_estimated"] is True)
    check("REG-03: model_type 'IsolationForest'", meta["model_type"] == "IsolationForest")
    check("REG-03: parameters None", meta["parameters"] is None)
    check("REG-03: dataset com os quatro campos a None",
          meta["dataset"] == {"name": None, "size": None, "attacks": None, "synthetic": None})
    check("REG-03: library_versions None", meta["library_versions"] is None)
    check("REG-03: evaluation None", meta["evaluation"] is None)
    try:
        datetime.fromisoformat(meta["created_at"])
        criado_valido = True
    except ValueError:
        criado_valido = False
    check("REG-03: created_at é um ISO-8601 válido", criado_valido)

    artefatos = meta["artifacts"]
    check("REG-03: artifacts só com os dois nomes constantes",
          set(artefatos) == set(model_registry.ARTIFACT_FILES))
    for nome in model_registry.ARTIFACT_FILES:
        check(f"REG-03: artifacts[{nome}].sha256 é o do original",
              artefatos[nome]["sha256"] == antes[nome]["sha256"])
        check(f"REG-03: artifacts[{nome}].size_bytes é o do original",
              artefatos[nome]["size_bytes"] == antes[nome]["size_bytes"])
        check(f"REG-03: a cópia de {nome} tem os mesmos bytes",
              (v1 / nome).read_bytes() == (Path(root) / nome).read_bytes())
        check(f"REG-03: a cópia de {nome} tem o mtime do original (copy2)",
              (v1 / nome).stat().st_mtime == mtime)

    check("REG-03: os originais ficam com SHA-256, tamanho e mtime iguais",
          fotografar(root) == antes)
    check("REG-03: os originais continuam em models/",
          all((Path(root) / n).is_file() for n in model_registry.ARTIFACT_FILES))
    check("REG-03: ACTIVE contém exactamente b'v1\\n'",
          (Path(root) / model_registry.ACTIVE_FILE).read_bytes() == b"v1\n")

    report = model_registry.build_models_report(root)
    check("REG-03: report active == 'v1'", report["active"] == "v1")
    check("REG-03: report total == 1", report["total"] == 1)
    entrada = versoes_por_id(report)["v1"]
    check("REG-03: a v1 listada tem status 'ok' e error_code None",
          entrada["status"] == "ok" and entrada["error_code"] is None)
    check("REG-03: a v1 listada está ativa", entrada["active"] is True)
    check("REG-03: os metadados públicos trazem adopted e trained_at_estimated",
          (entrada["metadata"] or {}).get("adopted") is True
          and (entrada["metadata"] or {}).get("trained_at_estimated") is True)
    check("REG-03: nenhuma entrada legacy depois do adopt (D-03)",
          entradas_legacy(report) == [])

    fonte = model_registry.resolve_active_artifacts(root)
    check("REG-03: resolve_active_artifacts -> v1 verificada",
          fonte.version == "v1" and fonte.verified is True)
    check("REG-03: os bytes devolvidos são os do original",
          fonte.model_bytes == b"modelo-adotado" and fonte.scaler_bytes == b"scaler-adotado")

    check("REG-03: não sobra nenhuma pasta v1.tmp-*", restos(root, "v1.tmp-") == [])
    check("REG-03: não sobra nenhum ficheiro ACTIVE.tmp-*", restos(root, "ACTIVE.tmp-") == [])

    # Segundo adopt sobre um adopt completo: nada é escrito.
    ativo_antes = (Path(root) / model_registry.ACTIVE_FILE).read_bytes()
    meta_antes = (v1 / model_registry.METADATA_FILE).read_bytes()
    exc = espera_erro(model_registry.adopt, root)
    check("REG-03: segundo adopt -> already_adopted",
          exc is not None and exc.code == "already_adopted")
    check("REG-03: o segundo adopt não mexe no ACTIVE",
          (Path(root) / model_registry.ACTIVE_FILE).read_bytes() == ativo_antes)
    check("REG-03: o segundo adopt não mexe no metadata.json",
          (v1 / model_registry.METADATA_FILE).read_bytes() == meta_antes)
    check("REG-03: os originais continuam iguais depois do segundo adopt",
          fotografar(root) == antes)


def test_adopt_d01(tmp: Path) -> None:
    secao("D-01 — adopt cria a v1 mas não altera um ACTIVE já existente")

    root = make_legacy(tmp / "reg03-d01")
    make_version(root, "v2")  # outra versão, já ativa
    write_active(root, b"v2\n")
    ativo_antes = (root / model_registry.ACTIVE_FILE).read_bytes()
    antes = fotografar(root)

    resultado = model_registry.adopt(root)
    check("D-01: a v1 foi criada a partir do legado", (root / "v1" / MODEL_FILE).is_file())
    check("D-01: active_written False", resultado["active_written"] is False)
    check("D-01: resumed False", resultado["resumed"] is False)
    check("D-01: os bytes do ACTIVE ficaram exatamente iguais",
          (root / model_registry.ACTIVE_FILE).read_bytes() == ativo_antes)
    check("D-01: o ACTIVE continua a apontar para v2",
          model_registry.build_models_report(root)["active"] == "v2")
    check("D-01: os originais ficaram intactos", fotografar(root) == antes)
    check("D-01: não sobrou nenhum temporário",
          restos(root, "v1.tmp-") == [] and restos(root, "ACTIVE.tmp-") == [])

    exc = espera_erro(model_registry.adopt, root)
    check("D-01: adopt seguinte -> already_adopted (o ACTIVE existe)",
          exc is not None and exc.code == "already_adopted")
    check("D-01: e o ACTIVE continua exatamente igual",
          (root / model_registry.ACTIVE_FILE).read_bytes() == ativo_antes)
    check("D-01: os originais continuam intactos", fotografar(root) == antes)


def test_adopt_pre_condicoes(tmp: Path) -> None:
    secao("REG-03 — sem os dois .pkl soltos: no_legacy_model")

    vazia = tmp / "reg03-vazia"
    vazia.mkdir(parents=True)
    exc = espera_erro(model_registry.adopt, vazia)
    check("REG-03: pasta vazia -> no_legacy_model",
          exc is not None and exc.code == "no_legacy_model")

    inexistente = tmp / "reg03-nao-existe"
    exc = espera_erro(model_registry.adopt, inexistente)
    check("REG-03: pasta inexistente -> no_legacy_model",
          exc is not None and exc.code == "no_legacy_model")

    so_modelo = tmp / "reg03-so-modelo"
    so_modelo.mkdir(parents=True)
    (so_modelo / MODEL_FILE).write_bytes(b"so-o-modelo")
    exc = espera_erro(model_registry.adopt, so_modelo)
    check("REG-03: só isolation_forest.pkl -> no_legacy_model",
          exc is not None and exc.code == "no_legacy_model")

    so_scaler = tmp / "reg03-so-scaler"
    so_scaler.mkdir(parents=True)
    (so_scaler / SCALER_FILE).write_bytes(b"so-o-scaler")
    exc = espera_erro(model_registry.adopt, so_scaler)
    check("REG-03: só scaler.pkl -> no_legacy_model",
          exc is not None and exc.code == "no_legacy_model")

    check("REG-03: nenhuma tentativa criou v1 nem ACTIVE",
          not (so_modelo / "v1").exists()
          and not (so_scaler / model_registry.ACTIVE_FILE).exists()
          and not (vazia / model_registry.ACTIVE_FILE).exists())
    check("REG-03: e nenhuma deixou temporários",
          not any(restos(p, "v1.tmp-") or restos(p, "ACTIVE.tmp-")
                  for p in (vazia, so_modelo, so_scaler)))


def test_adopt_falha_a_criar_a_v1(tmp: Path) -> None:
    secao("REG-03/T-01-18 — os.replace bloqueado ao criar a v1: registry_unavailable sem lixo")

    root = make_legacy(tmp / "reg03-os-replace")
    antes = fotografar(root)
    original = replace_bloqueado("v1")
    try:
        exc = espera_erro(model_registry.adopt, root)
    finally:
        model_registry.os.replace = original

    check("REG-03: os.replace bloqueado -> registry_unavailable",
          exc is not None and exc.code == "registry_unavailable")
    check("REG-03: models/v1 não existe", not (root / "v1").exists())
    check("REG-03: não sobra nenhuma pasta v1.tmp-*", restos(root, "v1.tmp-") == [])
    check("REG-03: não foi criado nenhum ACTIVE", not (root / model_registry.ACTIVE_FILE).exists())
    check("REG-03: não sobrou nenhum ACTIVE.tmp-*", restos(root, "ACTIVE.tmp-") == [])
    check("REG-03: os originais estão intactos", fotografar(root) == antes)

    # Desbloqueado, o mesmo adopt completa sem nada ter ficado a meio.
    resultado = model_registry.adopt(root)
    check("REG-03: voltar a correr o adopt conclui",
          resultado["version"] == "v1" and resultado["resumed"] is False
          and (root / model_registry.ACTIVE_FILE).read_bytes() == b"v1\n")
    check("REG-03: e os originais continuam intactos", fotografar(root) == antes)


def test_adopt_falha_so_no_active_e_retoma(tmp: Path) -> None:
    secao("T-01-23 — adopt interrompido na escrita do ACTIVE e a retoma pelo próprio adopt")

    root = make_legacy(tmp / "reg03-retoma")
    antes = fotografar(root)
    original = replace_bloqueado(model_registry.ACTIVE_FILE)
    try:
        exc = espera_erro(model_registry.adopt, root)
    finally:
        model_registry.os.replace = original

    check("retoma: falha só na escrita do ACTIVE -> registry_unavailable",
          exc is not None and exc.code == "registry_unavailable")
    v1 = root / "v1"
    check("retoma: a v1 ficou criada", (v1 / MODEL_FILE).is_file() and (v1 / SCALER_FILE).is_file())
    check("retoma: a v1 tem metadata válido e íntegro",
          model_registry._verify_artifacts(v1, model_registry.load_metadata(v1, "v1")) == "ok")
    check("retoma: o ACTIVE não existe", not (root / model_registry.ACTIVE_FILE).exists())
    check("retoma: não sobrou nenhum ACTIVE.tmp-*", restos(root, "ACTIVE.tmp-") == [])
    check("retoma: não sobrou nenhuma pasta v1.tmp-*", restos(root, "v1.tmp-") == [])
    check("retoma: _active_state == (None, None)",
          model_registry._active_state(model_registry._root(root)) == (None, None))
    try:
        model_registry.resolve_active_artifacts(root)
        erro = None
    except FileNotFoundError as exc_fn:
        erro = exc_fn
    check("retoma: resolve_active_artifacts -> FileNotFoundError (estado partido)",
          isinstance(erro, FileNotFoundError))
    check("retoma: a mensagem não contém o caminho",
          erro is not None and str(root) not in str(erro))
    check("retoma: os originais intactos depois da falha", fotografar(root) == antes)

    # Retoma: não recopia nada, escreve só o ACTIVE em falta.
    meta_bytes = (v1 / model_registry.METADATA_FILE).read_bytes()
    pkl_bytes = {n: (v1 / n).read_bytes() for n in model_registry.ARTIFACT_FILES}
    pkl_mtimes = {n: (v1 / n).stat().st_mtime for n in model_registry.ARTIFACT_FILES}

    retomado = model_registry.adopt(root)
    check("retoma: devolve version 'v1'", retomado["version"] == "v1")
    check("retoma: devolve active_written True", retomado["active_written"] is True)
    check("retoma: devolve resumed True", retomado["resumed"] is True)
    check("retoma: o ACTIVE contém exactamente b'v1\\n'",
          (root / model_registry.ACTIVE_FILE).read_bytes() == b"v1\n")
    check("retoma: o metadata.json da v1 não foi reescrito",
          (v1 / model_registry.METADATA_FILE).read_bytes() == meta_bytes)
    check("retoma: os .pkl da v1 não foram recopiados",
          all((v1 / n).read_bytes() == pkl_bytes[n] for n in model_registry.ARTIFACT_FILES)
          and all((v1 / n).stat().st_mtime == pkl_mtimes[n] for n in model_registry.ARTIFACT_FILES))
    fonte = model_registry.resolve_active_artifacts(root)
    check("retoma: resolve_active_artifacts -> v1 verificada",
          fonte.version == "v1" and fonte.verified is True)
    report = model_registry.build_models_report(root)
    check("retoma: report active 'v1' e active_error None",
          report["active"] == "v1" and report["active_error"] is None)
    check("retoma: a v1 listada está íntegra",
          versoes_por_id(report)["v1"]["status"] == "ok")
    check("retoma: nenhuma entrada legacy", entradas_legacy(report) == [])
    check("retoma: os originais continuam intactos", fotografar(root) == antes)
    check("retoma: não sobrou nenhum temporário",
          restos(root, "v1.tmp-") == [] and restos(root, "ACTIVE.tmp-") == [])
    exc_terceiro = espera_erro(model_registry.adopt, root)
    check("retoma: um terceiro adopt -> already_adopted",
          exc_terceiro is not None and exc_terceiro.code == "already_adopted")


def test_adopt_retomas_recusadas(tmp: Path) -> None:
    secao("T-01-24 — a retoma recusa uma v1 que não é a adoção do legado, sem escrever nada")

    # (i) v1 criada pelo adopt, ACTIVE apagado à mão e um byte trocado no .pkl.
    adulterada = make_legacy(tmp / "reg03-retoma-adulterada")
    antes_adulterada = fotografar(adulterada)
    model_registry.adopt(adulterada)
    (adulterada / model_registry.ACTIVE_FILE).unlink()
    flip_byte(adulterada / "v1" / MODEL_FILE)
    exc = espera_erro(model_registry.adopt, adulterada)
    check("retoma (i): v1 adulterada -> already_adopted",
          exc is not None and exc.code == "already_adopted")
    check("retoma (i): o ACTIVE continua a não existir",
          not (adulterada / model_registry.ACTIVE_FILE).exists())
    check("retoma (i): os originais intactos", fotografar(adulterada) == antes_adulterada)

    # (ii) v1 alheia (bytes diferentes dos .pkl legados) e sem ACTIVE.
    alheia = make_legacy(tmp / "reg03-retoma-alheia")
    antes_alheia = fotografar(alheia)
    make_version(alheia, "v1", model_bytes=b"outro-modelo", scaler_bytes=b"outro-scaler")
    exc = espera_erro(model_registry.adopt, alheia)
    check("retoma (ii): v1 que não corresponde ao legado -> already_adopted",
          exc is not None and exc.code == "already_adopted")
    check("retoma (ii): o ACTIVE continua a não existir",
          not (alheia / model_registry.ACTIVE_FILE).exists())
    check("retoma (ii): os originais intactos", fotografar(alheia) == antes_alheia)

    # (iii) metadata.json inválido e sem ACTIVE.
    invalida = make_legacy(tmp / "reg03-retoma-invalida")
    antes_invalida = fotografar(invalida)
    make_version(invalida, "v1")
    (invalida / "v1" / model_registry.METADATA_FILE).write_text("{nao-json", encoding="utf-8")
    exc = espera_erro(model_registry.adopt, invalida)
    check("retoma (iii): metadata.json inválido -> already_adopted",
          exc is not None and exc.code == "already_adopted")
    check("retoma (iii): o ACTIVE continua a não existir",
          not (invalida / model_registry.ACTIVE_FILE).exists())
    check("retoma (iii): os originais intactos", fotografar(invalida) == antes_invalida)

    # (iv) versão de treino feita à mão (origin != "adopted") e sem ACTIVE.
    treinada = make_legacy(tmp / "reg03-retoma-trained")
    antes_treinada = fotografar(treinada)
    make_version(treinada, "v1", origin="trained", adopted=False)
    exc = espera_erro(model_registry.adopt, treinada)
    check("retoma (iv): origin 'trained' -> already_adopted",
          exc is not None and exc.code == "already_adopted")
    check("retoma (iv): o ACTIVE continua a não existir",
          not (treinada / model_registry.ACTIVE_FILE).exists())
    check("retoma (iv): os originais intactos", fotografar(treinada) == antes_treinada)


def run() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        raiz = Path(tmp)
        test_reg01(raiz)
        test_reg02(raiz)
        test_sec01(raiz)
        test_sec02_ids(raiz)
        test_sec02_active(raiz)
        test_sec02_junction(raiz)
        test_root_e_inexistente(raiz)
        test_adopt_copia_o_legado(raiz)
        test_adopt_d01(raiz)
        test_adopt_pre_condicoes(raiz)
        test_adopt_falha_a_criar_a_v1(raiz)
        test_adopt_falha_so_no_active_e_retoma(raiz)
        test_adopt_retomas_recusadas(raiz)

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")


if __name__ == "__main__":
    run()
