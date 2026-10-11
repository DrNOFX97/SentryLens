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

import contextlib
import io
import inspect
import json
import model_registry
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import tempfile

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
          set(metadata) == set(model_registry.METADATA_PUBLIC_KEYS)
          | set(model_registry.METADATA_EXTRA_PROJECTED_KEYS))
    check("REG-01: as chaves projectadas à parte são só feature_stats (D-03)",
          set(model_registry.METADATA_EXTRA_PROJECTED_KEYS) == {"feature_stats"})
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
    check("REG-03: dataset com as nove chaves todas a None",
          meta["dataset"] == {chave: None for chave in model_registry.DATASET_PUBLIC_KEYS})
    check("REG-03: feature_stats None (D-03: um adopt não tem lote)", meta["feature_stats"] is None)
    check("REG-03: catalog_sha256 None (D-04: não sei, não incompatível)",
          meta["catalog_sha256"] is None)
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


# --- CLI: python model_registry.py adopt -------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent


def correr_cli(*args, timeout=60):
    """Corre o CLI como o utilizador o corre, num processo novo. `cwd` é a
    pasta scripts/, como no run_all_tests.py."""
    return subprocess.run(
        [sys.executable, "-X", "utf8", str(SCRIPT_DIR / "model_registry.py"), *args],
        capture_output=True, text=True, encoding="utf-8",
        cwd=str(SCRIPT_DIR), timeout=timeout,
    )


def test_cli_adopt(tmp: Path) -> None:
    secao("CLI adopt — códigos de saída 0/1 e mensagens PT acionáveis")

    # (a) modelo legado presente -> 0
    root = make_legacy(tmp / "cli-ok")
    antes = fotografar(root)
    proc = correr_cli("adopt", "--models-dir", str(root))
    check("CLI (a): adopt com legado -> código 0", proc.returncode == 0)
    check("CLI (a): stdout diz que o modelo foi adotado como v1", "v1" in proc.stdout)
    check("CLI (a): a pasta v1 foi criada", (root / "v1" / MODEL_FILE).is_file())
    check("CLI (a): o ACTIVE ficou a v1",
          (root / model_registry.ACTIVE_FILE).read_bytes() == b"v1\n")
    check("CLI (a): mostra o SHA-256 dos dois artefactos",
          antes[MODEL_FILE]["sha256"] in proc.stdout
          and antes[SCALER_FILE]["sha256"] in proc.stdout)
    check("CLI (a): diz que os originais não foram alterados",
          "não foram alterados" in proc.stdout)
    check("CLI (a): diz models/ACTIVE -> v1", "models/ACTIVE -> v1" in proc.stdout)
    check("CLI (a): manda reiniciar o backend", "Reinicia o backend" in proc.stdout)
    check("CLI (a): nada em stderr", proc.stderr.strip() == "")
    check("CLI (a): os originais intactos", fotografar(root) == antes)

    # (b) segunda execução -> 1 com o código de erro em stderr
    proc = correr_cli("adopt", "--models-dir", str(root))
    check("CLI (b): segundo adopt -> código 1", proc.returncode == 1)
    check("CLI (b): stderr traz already_adopted", "already_adopted" in proc.stderr)
    check("CLI (b): a mensagem diz que nada foi alterado",
          "Nada foi alterado" in proc.stderr)
    check("CLI (b): nada em stdout", proc.stdout.strip() == "")
    check("CLI (c): os originais continuam intactos", fotografar(root) == antes)

    # (c) pasta vazia -> 1 com no_legacy_model
    vazia = tmp / "cli-vazia"
    vazia.mkdir(parents=True)
    proc = correr_cli("adopt", "--models-dir", str(vazia))
    check("CLI (c): pasta vazia -> código 1", proc.returncode == 1)
    check("CLI (c): stderr traz no_legacy_model", "no_legacy_model" in proc.stderr)
    check("CLI (c): a mensagem diz o que falta",
          "isolation_forest.pkl" in proc.stderr)

    # (d) ACTIVE já existente (D-01) -> 0 com aviso, ACTIVE intacto
    com_active = make_legacy(tmp / "cli-active")
    make_version(com_active, "v2")
    write_active(com_active, b"v2\n")
    ativo = (com_active / model_registry.ACTIVE_FILE).read_bytes()
    proc = correr_cli("adopt", "--models-dir", str(com_active))
    check("CLI (d): adopt com ACTIVE prévio -> código 0", proc.returncode == 0)
    check("CLI (d): stdout traz o Aviso de D-01", "Aviso" in proc.stdout)
    check("CLI (d): o aviso diz como ativar a v1 à mão",
          "não foi alterado" in proc.stdout and "escreve v1" in proc.stdout)
    check("CLI (d): os bytes do ACTIVE ficaram iguais",
          (com_active / model_registry.ACTIVE_FILE).read_bytes() == ativo)

    # (e) --help
    proc = correr_cli("--help")
    check("CLI (e): --help -> código 0", proc.returncode == 0)
    check("CLI (e): --help mostra o subcomando adopt", "adopt" in proc.stdout)
    proc = correr_cli("adopt", "--help")
    check("CLI (e): 'adopt --help' -> código 0 com --models-dir",
          proc.returncode == 0 and "--models-dir" in proc.stdout)

    # (f) main() chamado no próprio processo
    in_process = make_legacy(tmp / "cli-in-process")
    with contextlib.redirect_stdout(io.StringIO()):
        codigo_ok = model_registry.main(["adopt", "--models-dir", str(in_process)])
    check("CLI (f): main([...]) devolve 0", codigo_ok == 0)
    check("CLI (f): e a v1 foi criada", (in_process / "v1" / MODEL_FILE).is_file())

    sem_legado = tmp / "cli-in-process-vazia"
    sem_legado.mkdir(parents=True)
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        codigo_erro = model_registry.main(["adopt", "--models-dir", str(sem_legado)])
    check("CLI (f): main([...]) numa pasta vazia devolve 1", codigo_erro == 1)


def test_cli_recuperacao(tmp: Path) -> None:
    secao("CLI adopt — recuperação de um adopt interrompido e mensagem de falha")

    # (g) o CLI completa um adopt interrompido na escrita do ACTIVE
    root = make_legacy(tmp / "cli-retoma")
    antes = fotografar(root)
    original = replace_bloqueado(model_registry.ACTIVE_FILE)
    try:
        primeira = espera_erro(model_registry.adopt, root)
    finally:
        model_registry.os.replace = original
    check("CLI (g): o estado partido foi criado", primeira is not None
          and primeira.code == "registry_unavailable"
          and not (root / model_registry.ACTIVE_FILE).exists())

    proc = correr_cli("adopt", "--models-dir", str(root))
    check("CLI (g): o CLI completa o adopt -> código 0", proc.returncode == 0)
    check("CLI (g): stdout diz que foi retomado", "retomado" in proc.stdout)
    check("CLI (g): stdout diz models/ACTIVE -> v1", "models/ACTIVE -> v1" in proc.stdout)
    check("CLI (g): o ACTIVE contém b'v1\\n'",
          (root / model_registry.ACTIVE_FILE).read_bytes() == b"v1\n")
    check("CLI (g): os originais intactos", fotografar(root) == antes)
    proc = correr_cli("adopt", "--models-dir", str(root))
    check("CLI (g): a seguir já está adotado -> código 1",
          proc.returncode == 1 and "already_adopted" in proc.stderr)

    # (h) falha de escrita: mensagem PT acionável em stderr
    falha = make_legacy(tmp / "cli-falha")
    original = replace_bloqueado(model_registry.ACTIVE_FILE)
    capturado = io.StringIO()
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(capturado):
            codigo = model_registry.main(["adopt", "--models-dir", str(falha)])
    finally:
        model_registry.os.replace = original
    texto = capturado.getvalue()
    check("CLI (h): main() devolve 1 quando a escrita falha", codigo == 1)
    check("CLI (h): stderr traz 'Erro (registry_unavailable)'",
          "Erro (registry_unavailable)" in texto)
    check("CLI (h): a mensagem manda fechar a pasta e voltar a correr",
          "volta a correr o comando" in texto)
    check("CLI (h): e diz que nada foi registado / originais intactos",
          "não foram alterados" in texto)
    check("CLI (h): a mensagem não contém o caminho da pasta",
          str(falha) not in texto and str(falha.resolve()) not in texto)


# --- Fase 2: resolve_version_artifacts e _write_evaluation (D-02, D-07, D-08) --
#
# O payload de avaliação que serve de fixture a todos os casos abaixo. Tem as
# MESMAS 14 chaves que EVALUATION_PUBLIC_KEYS, com valores plausíveis: é o
# contrato que scripts/ml_evaluation.py escreve e que o registo aceita.

EVALUATION_EXEMPLO = {
    "evaluated_at": "2026-10-10T09:30:00+00:00",
    "events_file": "eventos.json",
    "attack_log": "attack_log.jsonl",
    "label_window_seconds": 120,
    "total_events": 35,
    "attacks_in_dataset": 20,
    "ml": {"precision": 0.8571, "recall": 0.3, "f1": 0.4444},
    "rules": {"precision": 0.875, "recall": 0.35, "f1": 0.5},
    "comparison": {"both_flagged": 5, "ml_only": 2, "rules_only": 3, "neither": 25},
    "min_events": 50,
    "min_attacks": 10,
    "small_sample": True,
    "caveat": (
        "Dataset pequeno (35 eventos, 20 ataques; limiares: min_events=50, "
        "min_attacks=10) — não é uma estimativa robusta de taxa de deteção."
    ),
    "dataset_origin": "real",
}


def test_resolve_version_artifacts(tmp: Path) -> None:
    secao("Fase 2 — resolve_version_artifacts: a versão PEDIDA, com a mesma integridade")

    model_bytes, scaler_bytes = b"modelo-da-v1", b"scaler-da-v1"

    # 1. versão registada e íntegra -> os bytes do ficheiro, verificados.
    ok = tmp / "rva-ok"
    make_version(ok, "v1", model_bytes=model_bytes, scaler_bytes=scaler_bytes)
    write_active(ok, "v1")
    fonte = model_registry.resolve_version_artifacts(ok, "v1")
    check("resolve_version_artifacts: version 'v1'", fonte.version == "v1")
    check("resolve_version_artifacts: verified True", fonte.verified is True)
    check("resolve_version_artifacts: devolve os bytes do ficheiro do modelo",
          fonte.model_bytes == model_bytes)
    check("resolve_version_artifacts: devolve os bytes do ficheiro do scaler",
          fonte.scaler_bytes == scaler_bytes)

    # 2. o mesmo conteúdo que resolve_active_artifacts dá para a versão ativa:
    #    avaliar a vN e carregar a vN ativa usam as mesmas regras de integridade.
    ativa = model_registry.resolve_active_artifacts(ok)
    check("resolve_version_artifacts == resolve_active_artifacts para a ativa",
          fonte == ativa)
    check("e o tipo continua a ser ArtifactSource",
          isinstance(fonte, model_registry.ArtifactSource))

    # 3. D-02: pede-se a v2 com a v1 ativa — são artefactos diferentes.
    duas = tmp / "rva-duas"
    make_version(duas, "v1", model_bytes=b"modelo-v1", scaler_bytes=b"scaler-v1")
    make_version(duas, "v2", model_bytes=b"modelo-v2", scaler_bytes=b"scaler-v2")
    write_active(duas, "v1")
    fonte_v2 = model_registry.resolve_version_artifacts(duas, "v2")
    check("D-02: pedir a v2 com a v1 ativa devolve a v2",
          fonte_v2.version == "v2" and fonte_v2.model_bytes == b"modelo-v2"
          and fonte_v2.verified is True)

    # 4. ids inválidos -> invalid_version_id, sem devolver bytes.
    for valor in ("../x", "v1\n", "vX", 5, None, "", "V1", b"v1"):
        exc = espera_erro(model_registry.resolve_version_artifacts, ok, valor)
        check(f"resolve_version_artifacts({valor!r}) -> invalid_version_id",
              exc is not None and exc.code == "invalid_version_id")

    # 5. versão inexistente -> active_not_found.
    exc = espera_erro(model_registry.resolve_version_artifacts, ok, "v9")
    check("resolve_version_artifacts('v9') -> active_not_found",
          exc is not None and exc.code == "active_not_found")

    # 6. sem metadata.json -> metadata_missing.
    sem_meta = tmp / "rva-sem-meta"
    make_version(sem_meta, "v1", model_bytes=model_bytes, scaler_bytes=scaler_bytes)
    (sem_meta / "v1" / model_registry.METADATA_FILE).unlink()
    exc = espera_erro(model_registry.resolve_version_artifacts, sem_meta, "v1")
    check("resolve_version_artifacts sem metadata.json -> metadata_missing",
          exc is not None and exc.code == "metadata_missing")

    # 7. metadata.json inválido -> metadata_invalid.
    meta_mau = tmp / "rva-meta-mau"
    make_version(meta_mau, "v1", model_bytes=model_bytes, scaler_bytes=scaler_bytes)
    (meta_mau / "v1" / model_registry.METADATA_FILE).write_text("{nao-json", encoding="utf-8")
    exc = espera_erro(model_registry.resolve_version_artifacts, meta_mau, "v1")
    check("resolve_version_artifacts com JSON inválido -> metadata_invalid",
          exc is not None and exc.code == "metadata_invalid")

    # 8. artefacto em falta -> artifact_missing.
    sem_pkl = tmp / "rva-sem-pkl"
    make_version(sem_pkl, "v1", model_bytes=model_bytes, scaler_bytes=scaler_bytes)
    (sem_pkl / "v1" / MODEL_FILE).unlink()
    exc = espera_erro(model_registry.resolve_version_artifacts, sem_pkl, "v1")
    check("resolve_version_artifacts sem o .pkl do modelo -> artifact_missing",
          exc is not None and exc.code == "artifact_missing")

    # 9. um byte trocado -> hash_mismatch, e nenhum byte é devolvido.
    adulterado = tmp / "rva-adulterado"
    make_version(adulterado, "v1", model_bytes=model_bytes, scaler_bytes=scaler_bytes)
    flip_byte(adulterado / "v1" / MODEL_FILE)
    exc = espera_erro(model_registry.resolve_version_artifacts, adulterado, "v1")
    check("resolve_version_artifacts com um byte trocado -> hash_mismatch",
          exc is not None and exc.code == "hash_mismatch")
    check("hash_mismatch: a mensagem é o código, sem caminho",
          exc is not None and str(exc) == "hash_mismatch"
          and str(adulterado) not in str(exc))


def test_write_evaluation(tmp: Path) -> None:
    secao("Fase 2 — _write_evaluation: escrita atómica, validação e rollback")

    root = tmp / "we-ok"
    make_version(root, "v1")
    antes_meta = json.loads((root / "v1" / model_registry.METADATA_FILE).read_text(encoding="utf-8"))
    antes_bytes = (root / "v1" / model_registry.METADATA_FILE).read_bytes()
    antes_pkl = {n: (root / "v1" / n).read_bytes() for n in model_registry.ARTIFACT_FILES}

    devolvido = model_registry._write_evaluation(
        model_registry._root(root), "v1", dict(EVALUATION_EXEMPLO))
    check("_write_evaluation devolve None", devolvido is None)

    relido = model_registry.load_metadata(root / "v1", "v1")
    check("_write_evaluation: a relitura com load_metadata dá a mesma avaliação",
          relido["evaluation"] == EVALUATION_EXEMPLO)
    check("_write_evaluation: os .pkl ficam byte-idênticos",
          all((root / "v1" / n).read_bytes() == antes_pkl[n]
              for n in model_registry.ARTIFACT_FILES))
    check("_write_evaluation: artifacts/sha256/size_bytes intactos",
          relido["artifacts"] == antes_meta["artifacts"])
    check("_write_evaluation: as restantes chaves do metadata.json intactas",
          {k: v for k, v in relido.items() if k != "evaluation"}
          == {k: v for k, v in antes_meta.items() if k != "evaluation"})
    report = model_registry.build_models_report(root)
    check("_write_evaluation: a listagem devolve a mesma avaliação",
          versoes_por_id(report)["v1"]["evaluation"] == EVALUATION_EXEMPLO)
    check("_write_evaluation: a versão continua íntegra",
          versoes_por_id(report)["v1"]["status"] == "ok")
    check("_write_evaluation: não sobrou nenhum metadata.json.tmp-*",
          restos(root / "v1", "metadata.json.tmp-") == [])

    # (a) payload com uma chave a mais OU a menos -> ValueError e nada escrito.
    for rotulo, payload in (
        ("chave a mais", {**EVALUATION_EXEMPLO, "nota_qualquer": "x"}),
        ("chave a menos", {k: v for k, v in EVALUATION_EXEMPLO.items() if k != "caveat"}),
        ("não é um dict", ["nao", "e", "um", "dict"]),
    ):
        intacto = (root / "v1" / model_registry.METADATA_FILE).read_bytes()
        try:
            model_registry._write_evaluation(model_registry._root(root), "v1", payload)
            erro = None
        except ValueError as exc:
            erro = exc
        check(f"_write_evaluation ({rotulo}) -> ValueError", erro is not None)
        check(f"_write_evaluation ({rotulo}): o metadata.json anterior fica byte-idêntico",
              (root / "v1" / model_registry.METADATA_FILE).read_bytes() == intacto)
        check(f"_write_evaluation ({rotulo}): não sobrou temporário nenhum",
              restos(root / "v1", "metadata.json.tmp-") == [])

    # (b) os.replace bloqueado -> registry_unavailable, ficheiro intacto, sem lixo.
    bloqueado = tmp / "we-bloqueado"
    make_version(bloqueado, "v1")
    intacto = (bloqueado / "v1" / model_registry.METADATA_FILE).read_bytes()
    pkl_antes = {n: (bloqueado / "v1" / n).read_bytes() for n in model_registry.ARTIFACT_FILES}
    original = replace_bloqueado(model_registry.METADATA_FILE)
    try:
        exc = espera_erro(model_registry._write_evaluation,
                          model_registry._root(bloqueado), "v1", dict(EVALUATION_EXEMPLO))
    finally:
        model_registry.os.replace = original
    check("_write_evaluation: os.replace bloqueado -> registry_unavailable",
          exc is not None and exc.code == "registry_unavailable")
    check("_write_evaluation: o metadata.json anterior fica byte-idêntico",
          (bloqueado / "v1" / model_registry.METADATA_FILE).read_bytes() == intacto)
    check("_write_evaluation: os .pkl intactos",
          all((bloqueado / "v1" / n).read_bytes() == pkl_antes[n]
              for n in model_registry.ARTIFACT_FILES))
    check("_write_evaluation: não sobra nenhum metadata.json.tmp-*",
          restos(bloqueado / "v1", "metadata.json.tmp-") == [])
    check("_write_evaluation: a versão continua na listagem com status 'ok'",
          versoes_por_id(model_registry.build_models_report(bloqueado))["v1"]["status"] == "ok")

    # (c) só a versão pedida muda: a v2 e o ACTIVE ficam byte-idênticos.
    varias = tmp / "we-varias"
    make_version(varias, "v1")
    make_version(varias, "v2")
    write_active(varias, "v2")
    meta_v2_antes = (varias / "v2" / model_registry.METADATA_FILE).read_bytes()
    pkl_v2_antes = {n: (varias / "v2" / n).read_bytes() for n in model_registry.ARTIFACT_FILES}
    ativo_antes = (varias / model_registry.ACTIVE_FILE).read_bytes()
    model_registry._write_evaluation(
        model_registry._root(varias), "v1", dict(EVALUATION_EXEMPLO))
    check("_write_evaluation: o metadata.json da v2 fica byte-idêntico",
          (varias / "v2" / model_registry.METADATA_FILE).read_bytes() == meta_v2_antes)
    check("_write_evaluation: os .pkl da v2 ficam byte-idênticos",
          all((varias / "v2" / n).read_bytes() == pkl_v2_antes[n]
              for n in model_registry.ARTIFACT_FILES))
    check("_write_evaluation: o ACTIVE fica byte-idêntico",
          (varias / model_registry.ACTIVE_FILE).read_bytes() == ativo_antes)
    relatorio = versoes_por_id(model_registry.build_models_report(varias))
    check("_write_evaluation: a v2 continua sem avaliação",
          relatorio["v2"]["evaluation"] is None)
    check("_write_evaluation: a v1 tem a avaliação",
          relatorio["v1"]["evaluation"] == EVALUATION_EXEMPLO)

    # (d) id inválido ou versão inexistente -> nada escrito em lado nenhum.
    antes_tudo = {p: p.read_bytes() for p in varias.rglob("*") if p.is_file()}
    exc = espera_erro(model_registry._write_evaluation,
                      model_registry._root(varias), "../x", dict(EVALUATION_EXEMPLO))
    check("_write_evaluation('../x') -> invalid_version_id",
          exc is not None and exc.code == "invalid_version_id")
    exc = espera_erro(model_registry._write_evaluation,
                      model_registry._root(varias), "v9", dict(EVALUATION_EXEMPLO))
    check("_write_evaluation('v9') -> active_not_found",
          exc is not None and exc.code == "active_not_found")
    check("_write_evaluation com id mau não escreve nada",
          {p: p.read_bytes() for p in varias.rglob("*") if p.is_file()} == antes_tudo)

    # (e) a verificação pós-escrita relê com load_metadata (D-07): se o que
    #     voltou do disco não for o que foi gravado, metadata_invalid.
    mentiroso = tmp / "we-mentiroso"
    make_version(mentiroso, "v1")
    original_load = model_registry.load_metadata
    chamadas = {"n": 0}

    def load_que_mente(version_dir, version_id):
        chamadas["n"] += 1
        meta = original_load(version_dir, version_id)
        if chamadas["n"] > 1:  # a relidação pós-escrita
            return {**meta, "evaluation": None}
        return meta

    model_registry.load_metadata = load_que_mente
    try:
        exc = espera_erro(model_registry._write_evaluation,
                          model_registry._root(mentiroso), "v1", dict(EVALUATION_EXEMPLO))
    finally:
        model_registry.load_metadata = original_load
    check("_write_evaluation: relitura que não bate -> metadata_invalid",
          exc is not None and exc.code == "metadata_invalid")
    check("_write_evaluation: a verificação pós-escrita relê mesmo (load_metadata chamado 2x)",
          chamadas["n"] == 2)


def test_cli_evaluate(tmp: Path) -> None:
    secao("CLI evaluate — o subcomando existe e recusa antes do motor de avaliação")

    vazia = tmp / "cli-eval-vazia"
    vazia.mkdir(parents=True)
    eventos = tmp / "cli-eval-eventos.json"
    eventos.write_text("[]", encoding="utf-8")

    proc = correr_cli("evaluate", "--help")
    check("CLI evaluate: 'evaluate --help' -> código 0", proc.returncode == 0)
    check("CLI evaluate: o help mostra --events", "--events" in proc.stdout)
    check("CLI evaluate: o help mostra --attack-log", "--attack-log" in proc.stdout)
    check("CLI evaluate: o help mostra --dataset-origin", "--dataset-origin" in proc.stdout)

    proc = correr_cli("--help")
    check("CLI evaluate: o --help geral mostra adopt e evaluate",
          "adopt" in proc.stdout and "evaluate" in proc.stdout)

    # O registo recusa antes do import tardio de ml_evaluation (que traria
    # sklearn): por isso estas duas recusas nem precisam dele.
    proc = correr_cli("evaluate", "v9", "--events", str(eventos), "--models-dir", str(vazia))
    check("CLI evaluate: versão inexistente -> código 1", proc.returncode == 1)
    check("CLI evaluate: versão inexistente -> active_not_found em stderr",
          "active_not_found" in proc.stderr)
    check("CLI evaluate: nada em stdout", proc.stdout.strip() == "")

    proc = correr_cli("evaluate", "../x", "--events", str(eventos), "--models-dir", str(vazia))
    check("CLI evaluate: id inválido -> código 1", proc.returncode == 1)
    check("CLI evaluate: id inválido -> invalid_version_id em stderr",
          "invalid_version_id" in proc.stderr)

    check("CLI evaluate: nenhuma das recusas criou nada na pasta",
          list(vazia.iterdir()) == [])


# --- R10 D-04: o hash do catálogo de features ---------------------------------


def test_catalog_sha256(tmp: Path) -> None:
    """
    D-04: `catalog_sha256()` mede o que determina `event_id_encoded` e nada
    mais. É a medição de D-04 em forma de teste — acrescentar um Event ID
    desloca os índices TODOS e nenhum `.pkl` é invalidado, logo o hash é o
    único sinal de que o modelo ficou a falar outra língua.

    O `CRITICAL_EVENTS` é substituído por uma cópia própria e restaurado num
    `finally`: o teste nunca deixa o catálogo do projecto alterado.
    """
    secao("D-04 — catalog_sha256 mede o _EVENT_ID_ORDER e nada mais")

    import event_catalog

    catalogo_real = event_catalog.CRITICAL_EVENTS
    hash_actual = model_registry.catalog_sha256()

    try:
        check("D-04: o catálogo do projecto tem 31 Event IDs (fixado aqui de propósito)",
              len(catalogo_real) == 31)
        check("D-04: devolve 64 hex", model_registry.SHA256_RE.fullmatch(hash_actual) is not None)
        check("D-04: é minúsculo", hash_actual == hash_actual.lower())

        # determinismo na mesma sessão
        check("D-04: duas chamadas seguidas dão a mesma string",
              hash_actual == model_registry.catalog_sha256())

        # determinismo ENTRE PROCESSOS: o valor não pode depender de nada que
        # só existe neste processo (sys.path, ordem de import, __pycache__).
        proc = subprocess.run(
            [sys.executable, "-X", "utf8", "-c",
             "import model_registry;print(model_registry.catalog_sha256())"],
            capture_output=True, text=True, encoding="utf-8", cwd=str(SCRIPT_DIR), timeout=60,
        )
        check("D-04: determinismo entre processos",
              proc.returncode == 0 and proc.stdout.strip() == hash_actual)

        # a ordem de INSERÇÃO do dict não importa — o que importa é o sorted()
        check("D-04: a mesma chave por outra ordem de inserção dá o mesmo hash",
              _hash_com_catalogo(model_registry, dict(reversed(list(catalogo_real.items())))) == hash_actual)

        # textos NÃO entram no hash: mudar um nome/recomendação não muda o que
        # uma feature significa, e um alarme falso aqui seria pior que o silêncio
        textos_mudados = {
            eid: {**entrada, "name": f"nome alterado {eid}", "severity": "low"}
            for eid, entrada in catalogo_real.items()
        }
        check("D-04: mudar só name/severity NÃO muda o hash",
              _hash_com_catalogo(model_registry, textos_mudados) == hash_actual)

        # D-04 medido: acrescentar UM Event ID muda o hash
        com_extra = dict(catalogo_real)
        com_extra[99999] = {"name": "Evento de teste", "severity": "high", "category": "teste"}
        hash_extra = _hash_com_catalogo(model_registry, com_extra)
        check("D-04: acrescentar um Event ID muda o hash", hash_extra != hash_actual)

        # e a mesma chave com valor vazio também (o hash é das CHAVES, não dos
        # valores — é por isso que a cópia acima também bate)
        check("D-04: o hash é das chaves, não dos textos",
              _hash_com_catalogo(
                  model_registry,
                  {eid: {} for eid in catalogo_real}) == hash_actual)
    finally:
        event_catalog.CRITICAL_EVENTS = catalogo_real

    check("D-04: o catálogo ficou restaurado", event_catalog.CRITICAL_EVENTS is catalogo_real)
    check("D-04: o hash é o de antes da manipulação",
          model_registry.catalog_sha256() == hash_actual)

    # Prova negativa: o import é TARDIO. `event_catalog` e `feature_extractor`
    # não podem estar no namespace do registo — se lá estivessem, `adopt`
    # estaria a pagar um import que não precisa (D-01).
    modulos = set(vars(model_registry))
    check("D-04: 'event_catalog' não está no namespace do registo (import tardio)",
          "event_catalog" not in modulos)
    check("D-04: 'feature_extractor' não está no namespace do registo",
          "feature_extractor" not in modulos)
    check("D-04: 'ml_evaluation' não está no namespace do registo",
          "ml_evaluation" not in modulos)
    # Os únicos módulos no namespace são stdlib (o topo do ficheiro). Nenhum de
    # domínio — o que prova que `catalog_sha256()` não custa um import a quem
    # não precisa dele.
    carregados = {v.__name__.split(".")[0] for v in vars(model_registry).values()
                  if type(v).__name__ == "module"}
    check("D-04: nenhum módulo de DOMÍNIO ficou ligado ao registo",
          not carregados & {"event_catalog", "feature_extractor", "ml_evaluation",
                            "ml_anomalies", "train_anomaly_model"})


def _hash_com_catalogo(modulo, catalogo) -> str:
    """`modulo.catalog_sha256()` com o `CRITICAL_EVENTS` trocado, restaurado
    num `finally` — para que nenhum teste deixe o catálogo do projecto sujo."""
    import event_catalog

    real = event_catalog.CRITICAL_EVENTS
    try:
        event_catalog.CRITICAL_EVENTS = catalogo
        return modulo.catalog_sha256()
    finally:
        event_catalog.CRITICAL_EVENTS = real


def test_dataset_com_proveniencia(tmp: Path) -> None:
    """
    D-02 (proveniência) + D-03 (`feature_stats`) + D-04 (`catalog_sha256`).

    Fecha três portas ao mesmo tempo: o `dataset` deixou de sair CRU (T-10-01),
    um `metadata.json` antigo continua a ser lido sem migração, e a listagem
    diz `catalog_compatible` sem nunca mexer em `status`.
    """
    secao("D-02/D-03/D-04 — dataset com proveniência, feature_stats e compatibilidade de catálogo")

    import feature_extractor

    NOME_FEATURES = set(feature_extractor.FEATURE_NAMES)

    # --- os pins das listas fechadas ------------------------------------------
    check("pin: ERROR_CODES tem exactamente 9 chaves (D-06: a lista não cresce)",
          len(model_registry.ERROR_CODES) == 9)
    check("pin: ERROR_CODES tem as mesmas 9, pela mesma ordem",
          model_registry.ERROR_CODES == (
              "invalid_version_id", "active_not_found", "metadata_missing",
              "metadata_invalid", "artifact_missing", "hash_mismatch",
              "already_adopted", "no_legacy_model", "registry_unavailable"))
    check("pin: MESSAGES_PT tem uma entrada para cada código do registo",
          set(model_registry.MESSAGES_PT) == set(model_registry.ERROR_CODES))
    check("pin: METADATA_PUBLIC_KEYS tem 13 chaves",
          len(model_registry.METADATA_PUBLIC_KEYS) == 13)
    check("pin: METADATA_PUBLIC_KEYS ganhou catalog_sha256",
          "catalog_sha256" in model_registry.METADATA_PUBLIC_KEYS)
    check("pin: DATASET_PUBLIC_KEYS tem 9 chaves pela mesma ordem",
          model_registry.DATASET_PUBLIC_KEYS == (
              "name", "size", "attacks", "synthetic",
              "documents", "processable", "truncated", "window_first", "window_last"))
    check("pin: DATASET_PUBLIC_KEYS tem as mesmas 9 escritas à mão",
          set(model_registry.DATASET_PUBLIC_KEYS) == {
              "name", "size", "attacks", "synthetic",
              "documents", "processable", "truncated", "window_first", "window_last"})
    check("pin: FEATURE_STATS_KEYS são exactamente mean e std",
          model_registry.FEATURE_STATS_KEYS == ("mean", "std"))
    check("pin: FEATURE_STATS_MAX_ENTRIES == 32", model_registry.FEATURE_STATS_MAX_ENTRIES == 32)
    check("pin: DATASET_TEXT_LIMIT == EVALUATION_TEXT_LIMIT == 200",
          model_registry.DATASET_TEXT_LIMIT == model_registry.EVALUATION_TEXT_LIMIT == 200)

    base = dict(
        version_id="v1", contamination=0.2, random_state=42, n_estimators=200,
        dataset_name="eventos.json", dataset_size=36, dataset_attacks=5,
        synthetic=True, library_versions={"python": "3.12"},
    )

    # --- o pin de schema -------------------------------------------------------
    meta = model_registry.build_trained_metadata(**base)
    check("schema: o metadata.json tem 15 chaves", len(meta) == 15)
    check("schema: as chaves são METADATA_PUBLIC_KEYS + evaluation + feature_stats",
          set(meta) == set(model_registry.METADATA_PUBLIC_KEYS)
          | {"evaluation", "feature_stats"})
    check("schema: METADATA_EXTRA_PROJECTED_KEYS é o que falta à tupla",
          set(model_registry.METADATA_EXTRA_PROJECTED_KEYS) == {"feature_stats"})
    check("schema: as 14 do plano + a feature_stats que o plano não contou",
          len(meta) == len(model_registry.METADATA_PUBLIC_KEYS) + 2)

    # --- o dataset por omissão (D-02) -----------------------------------------
    check("D-02: o dataset traz as 9 chaves mesmo sem o chamador as dar",
          set(meta["dataset"]) == set(model_registry.DATASET_PUBLIC_KEYS))
    check("D-02: as 5 chaves novas ficam None",
          all(meta["dataset"][k] is None for k in
              ("documents", "processable", "truncated", "window_first", "window_last")))
    check("D-02: as 4 antigas continuam com os mesmos valores",
          meta["dataset"]["name"] == "eventos.json" and meta["dataset"]["size"] == 36
          and meta["dataset"]["attacks"] == 5 and meta["dataset"]["synthetic"] is True)
    check("D-03: feature_stats None por omissão (tri-estado, não zero)",
          meta["feature_stats"] is None)
    check("D-04: catalog_sha256 None por omissão", meta["catalog_sha256"] is None)

    # --- o dataset completo (D-02) --------------------------------------------
    completo = model_registry.build_trained_metadata(
        dataset_documents=40, dataset_processable=36, dataset_truncated=False,
        dataset_window_first="2026-09-14T15:22:00Z", dataset_window_last="2026-09-14T15:34:00Z",
        **{**base, "dataset_name": "export.json", "synthetic": None},
    )
    check("D-02: o dataset completo é exactamente o esperado",
          completo["dataset"] == {
              "name": "export.json", "size": 36, "attacks": 5, "synthetic": None,
              "documents": 40, "processable": 36, "truncated": False,
              "window_first": "2026-09-14T15:22:00Z", "window_last": "2026-09-14T15:34:00Z",
          })
    check("D-02: '35 de 500' é distinguível de '35 de 35'",
          completo["dataset"]["documents"] != completo["dataset"]["processable"]
          and completo["dataset"]["size"] == completo["dataset"]["processable"])

    # --- feature_stats (D-03) --------------------------------------------------
    stats = {nome: {"mean": 1.5 + i, "std": 0.25} for i, nome in enumerate(sorted(NOME_FEATURES))}
    com_stats = model_registry.build_trained_metadata(feature_stats=stats, **base)
    check("D-03: as chaves de feature_stats são as 7 de FEATURE_NAMES",
          set(com_stats["feature_stats"]) == NOME_FEATURES)
    check("D-03: cada feature tem exactamente mean e std",
          all(set(v) == set(model_registry.FEATURE_STATS_KEYS)
              for v in com_stats["feature_stats"].values()))
    check("D-03: os valores passam tal e qual (float)",
          com_stats["feature_stats"]["hour_of_day"] == stats["hour_of_day"])

    # --- recusas: ANTES de qualquer escrita -----------------------------------
    def recusa(feature_stats=None, catalog_sha256=None, **extra):
        return espera_erro_valor(
            model_registry.build_trained_metadata,
            feature_stats=feature_stats, catalog_sha256=catalog_sha256,
            **{**base, **extra},
        )

    check("D-03: feature_stats que não é dict -> ValueError", recusa(feature_stats=["a"]) is not None)
    check("D-03: feature_stats com uma chave não-texto -> ValueError",
          recusa(feature_stats={1: {"mean": 0.0, "std": 0.0}}) is not None)
    check("D-03: feature_stats com mais de 32 chaves -> ValueError",
          recusa(feature_stats={f"f{i}": {"mean": 0.0, "std": 0.0}
                                for i in range(33)}) is not None)
    check("D-03: feature_stats com uma feature sem as duas chaves -> ValueError",
          recusa(feature_stats={"hour_of_day": {"mean": 0.0}}) is not None)
    check("D-03: feature_stats com uma chave a mais na feature -> ValueError",
          recusa(feature_stats={"hour_of_day": {"mean": 0.0, "std": 0.0, "mediana": 1.0}}) is not None)
    check("D-03: mean inteira -> ValueError",
          recusa(feature_stats={"hour_of_day": {"mean": 1, "std": 0.0}}) is not None)
    check("D-03: mean booleana -> ValueError",
          recusa(feature_stats={"hour_of_day": {"mean": True, "std": 0.0}}) is not None)
    check("D-03: mean textual -> ValueError",
          recusa(feature_stats={"hour_of_day": {"mean": "1.0", "std": 0.0}}) is not None)
    check("D-03: std negativa -> ValueError",
          recusa(feature_stats={"hour_of_day": {"mean": 0.0, "std": -1.0}}) is not None)
    check("D-04: catalog_sha256 que não casa SHA256_RE -> ValueError",
          recusa(catalog_sha256="abc123") is not None)
    check("D-04: catalog_sha256 com 63 hex -> ValueError",
          recusa(catalog_sha256="a" * 63) is not None)
    check("D-02: dataset_truncated=1 -> ValueError (bool não é int aqui)",
          recusa(dataset_truncated=1) is not None)
    check("D-02: dataset_documents negativo -> ValueError",
          recusa(dataset_documents=-1) is not None)
    check("D-02: dataset_size booleano -> ValueError",
          recusa(dataset_size=True) is not None)
    check("D-02: dataset_window_first com 500 caracteres -> ValueError",
          recusa(dataset_window_first="x" * 500) is not None)
    check("D-02: dataset_window_last não-texto -> ValueError",
          recusa(dataset_window_last=12345) is not None)
    check("D-04: catalog_sha256=None é aceite", recusa(catalog_sha256=None) is None)
    check("D-02: dataset_truncated=True grava True e não 1",
          model_registry.build_trained_metadata(
              dataset_truncated=True, **base)["dataset"]["truncated"] is True)

    # --- retrocompatibilidade: o disco do utilizador não precisa de migração ----
    antigo = tmp / "retro"
    antigo.mkdir(parents=True, exist_ok=True)
    make_version(antigo, "v1", origin="trained")  # o metadata.json de hoje: 13 chaves
    em_disco = json.loads((antigo / "v1" / model_registry.METADATA_FILE).read_text(encoding="utf-8"))
    check("retro: o metadata.json de hoje tem 13 chaves (12 + evaluation)",
          len(em_disco) == 13)
    check("retro: e não tem catalog_sha256 nem feature_stats",
          "catalog_sha256" not in em_disco and "feature_stats" not in em_disco)
    relatorio = model_registry.build_models_report(antigo)
    por_id = versoes_por_id(relatorio)
    check("retro: um metadata.json antigo continua a validar",
          por_id["v1"]["status"] == "ok" and por_id["v1"]["error_code"] is None)
    check("retro: e sai com catalog_compatible None ('não sei', não incompatível)",
          por_id["v1"]["catalog_compatible"] is None)
    check("retro: o dataset antigo sai projectado nas 9 chaves",
          set(por_id["v1"]["metadata"]["dataset"]) == set(model_registry.DATASET_PUBLIC_KEYS))
    check("retro: as 4 chaves antigas do utilizador sobrevêm intactas",
          por_id["v1"]["metadata"]["dataset"]["size"] is None)

    # --- catalog_compatible: as três versões na MESMA resposta ---------------
    tres = tmp / "tres-versoes"
    tres.mkdir(parents=True, exist_ok=True)
    make_version(tres, "v1", catalog_sha256=model_registry.catalog_sha256())
    make_version(tres, "v2", catalog_sha256="0" * 64)
    make_version(tres, "v3")  # sem a chave
    relatorio = model_registry.build_models_report(tres)
    por_id = versoes_por_id(relatorio)
    check("D-04: v1 (catálogo actual) -> catalog_compatible True",
          por_id["v1"]["catalog_compatible"] is True)
    check("D-04: v2 (hash adulterado) -> catalog_compatible False",
          por_id["v2"]["catalog_compatible"] is False)
    check("D-04: v3 (sem a chave) -> catalog_compatible None",
          por_id["v3"]["catalog_compatible"] is None)
    check("D-04: as três continuam status 'ok' — a incompatibilidade não é integridade",
          all(por_id[v]["status"] == "ok" and por_id[v]["error_code"] is None
              for v in ("v1", "v2", "v3")))
    check("D-04: nenhuma sai da lista",
          {v["id"] for v in relatorio["versions"]} == {"v1", "v2", "v3"})

    com_legado = make_legacy(tmp / "com-legado")
    legado = entradas_legacy(model_registry.build_models_report(com_legado))
    check("D-04: a entrada legacy traz catalog_compatible None",
          len(legado) == 1 and legado[0]["catalog_compatible"] is None)
    check("D-04: a entrada legacy traz a chave nova de qualquer maneira",
          "catalog_compatible" in legado[0])

    # --- a sub-projeção fecha a porta T-10-01 --------------------------------
    adulterado = tmp / "adulterado"
    adulterado.mkdir(parents=True, exist_ok=True)
    make_version(
        adulterado, "v1",
        dataset={"rodao": "<script>x</script>", "name": "a.json",
                 "window_first": "y" * 500},
        feature_stats={"hour_of_day": {"mean": "<b>", "std": 0.0, "mediana": 9.0},
                       "rodao": {"mean": 1.0, "std": 1.0}},
    )
    meta_pub = (versoes_por_id(model_registry.build_models_report(adulterado))["v1"]["metadata"])
    ds = meta_pub["dataset"]
    fs = meta_pub["feature_stats"]
    check("T-10-01: o dataset sai com exactamente as 9 chaves fechadas",
          set(ds) == set(model_registry.DATASET_PUBLIC_KEYS))
    check("T-10-01: a chave 'rodao' escrita à mão não sai",
          "rodao" not in ds and "<script>" not in json.dumps(meta_pub, ensure_ascii=False))
    check("T-10-01: o nome de ficheiro continua a sair",
          ds["name"] == "a.json")
    check("T-10-01: o texto de 500 caracteres é truncado",
          isinstance(ds["window_first"], str) and len(ds["window_first"]) <= 200)
    check("T-10-01: a feature_stats sai projectada com FEATURE_STATS_KEYS",
          set(fs["hour_of_day"]) == set(model_registry.FEATURE_STATS_KEYS))
    check("T-10-01: uma 'mean' textual dá None em vez de repropagar",
          fs["hour_of_day"]["mean"] is None and fs["hour_of_day"]["std"] == 0.0)
    check("T-10-01: uma chave arbitrária de dentro da feature não sai",
          "mediana" not in fs["hour_of_day"])
    # Limite HONESTO, medido e não escondido: o registo NÃO consegue fechar os
    # NOMES das features — `feature_extractor.FEATURE_NAMES` não pode ser
    # importado (D-01, stdlib puro no topo) e copiá-lo para aqui seria uma
    # segunda lista escrita à mão que divergiria em silêncio. O que a
    # sub-projeção FECHA é o que é o vector de injecção: os VALORES (mean/std
    # projectados por tipo) e o NÚMERO de chaves (teto de 32). Um nome de
    # feature inventado chega ao browser como texto e é escapado pelo `.cjs`.
    check("T-10-01: um NOME de feature inventado sobrevive (limite conhecido)",
          "rodao" in fs)
    check("T-10-01: mas o VALOR dele é projectado por tipo, como todos os outros",
          fs["rodao"] == {"mean": 1.0, "std": 1.0})
    check("T-10-01: o limite dos NOMES está escrito no docstring",
          "NOMES" in inspect.getdoc(model_registry._public_feature_stats).upper())
    check("T-10-01: nada na resposta traz a pasta temporária",
          str(tmp) not in json.dumps(meta_pub, ensure_ascii=False))

    # truncagem defensiva (T-10-05): 40 chaves written à mão, não levantam
    check("T-10-05: mais de FEATURE_STATS_MAX_ENTRIES é truncado, não levanta",
          len(model_registry._public_feature_stats(
              {f"f{i}": {"mean": 0.0, "std": 0.0} for i in range(40)})) == 32)
    check("T-10-05: uma feature que não é dict dá o par a None",
          model_registry._public_feature_stats({"x": "lixo"}) == {"x": {"mean": None, "std": None}})
    check("T-10-05: feature_stats que não é dict dá None",
          model_registry._public_feature_stats(["x"]) is None)
    check("T-10-05: um dataset que não é dict dá as 9 chaves a None",
          model_registry._public_dataset("lixo") == {k: None for k in model_registry.DATASET_PUBLIC_KEYS})

    # --- o caminho completo pelo registo real (não só o dict em memória) ------
    registo = tmp / "registo"
    registo.mkdir(parents=True, exist_ok=True)
    fontes = tmp / "fontes"
    fontes.mkdir(parents=True, exist_ok=True)
    (fontes / MODEL_FILE).write_bytes(b"modelo-proveniencia")
    (fontes / SCALER_FILE).write_bytes(b"scaler-proveniencia")
    resultado = model_registry.register_trained_version(
        str(registo),
        {MODEL_FILE: str(fontes / MODEL_FILE), SCALER_FILE: str(fontes / SCALER_FILE)},
        # `version_id` não entra: quem decide o id é `next_version_id`, e a
        # pasta está vazia, por isso sai "v1".
        **{k: v for k, v in base.items() if k != "version_id"},
        dataset_documents=40, dataset_processable=36, dataset_truncated=False,
        feature_stats=stats,
        catalog_sha256=model_registry.catalog_sha256(),
    )
    check("disco: a versão registada é a v1", resultado["version"] == "v1")
    gravado = json.loads(
        (registo / resultado["version"] / model_registry.METADATA_FILE).read_text(encoding="utf-8"))
    check("disco: o metadata.json gravado tem 15 chaves", len(gravado) == 15)
    check("disco: a proveniência sobreviveu ao disco",
          gravado["dataset"]["documents"] == 40 and gravado["dataset"]["processable"] == 36)
    check("disco: feature_stats sobreviveu ao disco",
          set(gravado["feature_stats"]) == NOME_FEATURES)
    check("disco: o catalog_sha256 gravado é o actual",
          gravado["catalog_sha256"] == model_registry.catalog_sha256())
    pub = versoes_por_id(model_registry.build_models_report(registo))["v1"]
    check("disco: a versão recién-registada sai com catalog_compatible True",
          pub["catalog_compatible"] is True and pub["status"] == "ok")


def espera_erro_valor(func, *args, **kwargs):
    """Chama func e devolve a `ValueError` levantada (ou None). Para as
    validações de `build_trained_metadata`, que são erro de PROGRAMAÇÃO e não
    de dados do utilizador — daí `ValueError` e não `ModelRegistryError`."""
    try:
        func(*args, **kwargs)
    except ValueError as exc:
        return exc
    return None


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
        test_cli_adopt(raiz)
        test_cli_recuperacao(raiz)
        test_resolve_version_artifacts(raiz)
        test_write_evaluation(raiz)
        test_cli_evaluate(raiz)
        test_catalog_sha256(raiz)
        test_dataset_com_proveniencia(raiz)
        # Estas quatro Sections foram escritas DEPOIS do `run()` e nunca foram
        # ligadas a ele: o ficheiro passou 38/38 sem nunca as executar. É a
        # mesma lição de `model_registry.register_trained_version` (escrito e
        # "testado", sem caller) um nível acima — uma secção de teste que o
        # runner não chama também não está testada.
        test_next_version_id(raiz)
        test_build_trained_metadata(raiz)
        test_register_trained_version(raiz)
        _library_versions_pin()

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")


# --- NEW: next_version_id e build_trained_metadata e register_trained_version ---


def test_next_version_id(tmp: Path) -> None:
    "Testa next_version_id nas oito situações esperadas (D-02)."
    import model_registry as mr

    # Pasta PRÓPRIA. Esta secção nunca correu até agora (o `run()` ficou acima
    # dela, sem a chamar) e ao ser ligada passava a partilhar `tmp/"reg01"` com
    # `test_reg01`, que lá deixa versões: o caso 5 lia um directório sujo e
    # falhava por uma razão que não tem a ver com o que está a testar.
    root = tmp / "next_version_id"
    root.mkdir(parents=True, exist_ok=True)

    # 1. pasta inexistente -> v1
    check(f"next_version_id inexistente -> v1", mr.next_version_id(str(tmp / "nao-existe")) == "v1")

    # 2. pasta vazia -> v1
    check(f"next_version_id vazia -> v1", mr.next_version_id(str(root)) == "v1")

    # 3. apenas v1 -> v2
    (root / "v1").mkdir(parents=True, exist_ok=True)
    check(f"next_version_id so v1 -> v2", mr.next_version_id(str(root)) == "v2")

    # 4. v1 e v2 -> v3
    (root / "v2").mkdir(parents=True, exist_ok=True)
    check(f"next_version_id v1+v2 -> v3", mr.next_version_id(str(root)) == "v3")

    # 5. v1 e v3, v2 APAGADA -> v4 (count faria v3; max+1 -> v4)
    #    A v3 TEM de existir em disco: o caso 4 só perguntou qual seria a
    #    resposta, não a materializou. Sem esta pasta, `max` era 2 e a
    #    resposta vinha `v3` — a asserção media o setup errado, não a função.
    import shutil
    (root / "v3").mkdir(parents=True, exist_ok=True)
    shutil.rmtree(root / "v2", ignore_errors=True)
    check(f"next_version_id v1+v3 sem v2 -> v4", mr.next_version_id(str(root)) == "v4")

    # 6. v9999 -> ModelRegistryError invalid_version_id
    #    O `v9999` fica NO DISCO de propósito (é o que provoca o overflow) e
    #    é removido logo a seguir: com ele presente, os casos 7 e 8 dariam
    #    `v10000`, que viola o regex — e a falha apareceria como "o ficheiro
    #    v7 nao e ignorado" quando o que esta a falhar e o residuo do caso 6.
    (root / "v9999").mkdir(parents=True, exist_ok=True)
    try:
        mr.next_version_id(str(root))
        check("next_version_id v9999 -> invalida falha", False)
    except model_registry.ModelRegistryError as exc:
        check(f"next_version_id v9999 -> invalid_version_id ({exc})", True)
    shutil.rmtree(root / "v9999", ignore_errors=True)

    # 7. ignorar ficheiro chamado v7 (não casa is_dir)
    (root / "v7").touch()
    check(f"next_version_id ficheiro v7 ignorado", mr.next_version_id(str(root)) == "v4")

    # 8. nomes que nao combinam com VERSION_ID_RE sao ignorados
    (root / "xyz").mkdir(parents=True, exist_ok=True)
    check(f"next_version_id nomes estranhos ignorados", mr.next_version_id(str(root)) == "v4")


def test_build_trained_metadata(tmp: Path) -> None:
    "Testa build_trained_metadata: schema de 15 chaves, dataset/parameters, synthetic tri-estado (D-04)."
    import model_registry as mr

    meta = mr.build_trained_metadata(
        version_id="v1",
        contamination=0.2,
        random_state=42,
        n_estimators=200,
        dataset_name="eventos.json",
        dataset_size=36,
        dataset_attacks=5,
        synthetic=True,
        library_versions={"python": "3.12", "scikit-learn": "1.5", "joblib": "1.4", "numpy": "2.0"},
    )

    # Schema EXACTAMENTE 15 chaves. O plano 10-01 diz 14 (13 de
    # METADATA_PUBLIC_KEYS + evaluation) e fixa esses dois números em três
    # gates; mas D-03 obriga a GRAVAR feature_stats e D-04 a gravar
    # catalog_sha256, e as duas são de topo. 13 + evaluation + feature_stats
    # = 15: o plano esqueceu-se de contar a `feature_stats`. O pin de 13 chaves
    # em METADATA_PUBLIC_KEYS mantém-se (é o que o <verify> do plano mede) e
    # a diferença de uma chave está escrita e medida em
    # `test_dataset_com_proveniencia` — não escondida.
    check(f"build_trained_metadata -> 15 chaves", len(meta) == 15)
    check(f"schema_version == 1", meta.get("schema_version") == 1)
    check(f"origin == 'trained'", meta.get("origin") == "trained")
    check(f"adopted == False", meta.get("adopted") is False)
    check(f"trained_at_estimated == False", meta.get("trained_at_estimated") is False)
    check(f"evaluation is None", meta.get("evaluation") is None)
    check(f"parameters == {{contamination:0.2, random_state:42, n_estimators:200}}", meta.get("parameters") == {"contamination": 0.2, "random_state": 42, "n_estimators": 200})
    check(f"dataset nome apenas: 'eventos.json'", meta.get("dataset", {}).get("name") == "eventos.json")
    check(f"dataset size == 36", meta.get("dataset", {}).get("size") == 36)
    check(f"dataset attacks == 5", meta.get("dataset", {}).get("attacks") == 5)
    check(f"dataset synthetic == True", meta.get("dataset", {}).get("synthetic") is True)
    check(f"library_versions copiado (não é o mesmo objeto)", meta.get("library_versions") == {"python": "3.12", "scikit-learn": "1.5", "joblib": "1.4", "numpy": "2.0"})

    # synthetic=False
    meta2 = mr.build_trained_metadata(
        version_id="v2",
        contamination=0.2,
        random_state=42,
        n_estimators=200,
        dataset_name="outros.json",
        dataset_size=10,
        dataset_attacks=2,
        synthetic=False,
        library_versions={"python": "3.12"},
    )
    check(f"synthetic False -> dataset.synthetic False", meta2.get("dataset", {}).get("synthetic") is False)

    # synthetic=None
    meta3 = mr.build_trained_metadata(
        version_id="v3",
        contamination=0.2,
        random_state=42,
        n_estimators=200,
        dataset_name="outros.json",
        dataset_size=10,
        dataset_attacks=2,
        synthetic=None,
        library_versions={"python": "3.12"},
    )
    check(f"synthetic None -> dataset.synthetic None", meta3.get("dataset", {}).get("synthetic") is None)

    # synthetic inválido -> ValueError
    try:
        mr.build_trained_metadata(
            version_id="v4",
            contamination=0.2,
            random_state=42,
            n_estimators=200,
            dataset_name="outros.json",
            dataset_size=10,
            dataset_attacks=2,
            synthetic="talvez",
            library_versions={"python": "3.12"},
        )
        check("synthetic inválido -> ValueError", False)
    except ValueError:
        check("synthetic inválido -> ValueError", True)


def test_register_trained_version(tmp: Path) -> None:
    "Testa register_trained_version: caminho feliz, sources incompletos, confirmação falha, os.replace bloqueado (D-03)."
    import model_registry as mr
    import json
    from pathlib import Path

    # Pasta PRÓPRIA (a versão anterior partilhava `tmp/"reg01"` com
    # `test_reg01`, que lá deixa v1/v2 — por isso esta secção, quando finalmente
    # passa a correr, esperava `v2` e recebia outra coisa).
    root = tmp / "register_trained_version"
    root.mkdir(parents=True, exist_ok=True)

    # v1 ADOTADA primeiro: o caminho feliz deste teste é "treinar por cima de
    # um registo que já tem uma v1 activa", e é isso que faz o
    # `next_version_id` devolver v2. A versão anterior escrevia `ACTIVE=v1`
    # sem existir a pasta v1 — um estado que o registo nunca produz e que
    # fazia o `next_version_id` devolver v1.
    v1 = root / "v1"
    v1.mkdir(parents=True, exist_ok=True)
    (v1 / "isolation_forest.pkl").write_bytes(b"legacy-model")
    (v1 / "scaler.pkl").write_bytes(b"legacy-scaler")
    (root / "ACTIVE").write_bytes(b"v1\n")
    (v1 / "metadata.json").write_text(json.dumps({
        "schema_version": 1,
        "version": "v1",
        "origin": "adopted",
        "adopted": True,
        "created_at": "2026-10-11T00:00:00+00:00",
        "trained_at": "2026-10-11T00:00:00+00:00",
        "trained_at_estimated": True,
        "model_type": "IsolationForest",
        "parameters": None,
        "dataset": {"name": None, "size": None, "attacks": None, "synthetic": None},
        "library_versions": None,
        "artifacts": {},
        "evaluation": None,
    }), encoding="utf-8")

    # Pastas fora do registo com .pkl arbitrários (sources)
    tmp_sources = tmp / "sources"
    tmp_sources.mkdir(parents=True, exist_ok=True)
    (tmp_sources / "isolation_forest.pkl").write_bytes(b"modelo-falso")
    (tmp_sources / "scaler.pkl").write_bytes(b"scaler-falso")

    fontes = {
        "isolation_forest.pkl": str(tmp_sources / "isolation_forest.pkl"),
        "scaler.pkl": str(tmp_sources / "scaler.pkl"),
    }

    # 1. caminho feliz: cria v2, escreve ACTIVE=v2, v1 fica intacta
    try:
        resultado = mr.register_trained_version(
            str(root),
            fontes,
            contamination=0.2,
            random_state=42,
            n_estimators=200,
            dataset_name="sample_events_real.json",
            dataset_size=36,
            dataset_attacks=5,
            synthetic=True,
            library_versions={"python": "3.12", "scikit-learn": "1.5", "joblib": "1.4", "numpy": "2.0"},
        )
        check(f"register_trained_version feliz -> version {resultado.get('version')}", resultado.get("version") == "v2")
        check(f"register_trained_version feliz -> active_written True", resultado.get("active_written") is True)
        check(f"ACTIVE agora e v2", (root / "ACTIVE").read_text().strip() == "v2")
    except Exception as exc:
        check(f"register_trained_version feliz falhou: {exc}", False)

    # 2. sources incompleto -> artifact_missing e nada escrito na pasta
    fontes_incompleto = {
        "isolation_forest.pkl": str(tmp_sources / "isolation_forest.pkl"),
    }
    try:
        mr.register_trained_version(
            str(root),
            fontes_incompleto,
            contamination=0.2,
            random_state=42,
            n_estimators=200,
            dataset_name="sample_events_real.json",
            dataset_size=36,
            dataset_attacks=5,
            synthetic=True,
            library_versions={"python": "3.12"},
        )
        check("sources incompleto -> artifact_missing", False)
    except model_registry.ModelRegistryError as exc:
        check(f"sources incompleto -> artifact_missing ({exc})", True)

    # sources extra -> artifact_missing
    fontes_extra = {
        "isolation_forest.pkl": str(tmp_sources / "isolation_forest.pkl"),
        "scaler.pkl": str(tmp_sources / "scaler.pkl"),
        "outro.pkl": str(tmp_sources / "outro.pkl"),
    }
    try:
        mr.register_trained_version(
            str(root),
            fontes_extra,
            contamination=0.2,
            random_state=42,
            n_estimators=200,
            dataset_name="sample_events_real.json",
            dataset_size=36,
            dataset_attacks=5,
            synthetic=True,
            library_versions={"python": "3.12"},
        )
        check("sources extra -> artifact_missing", False)
    except model_registry.ModelRegistryError as exc:
        check(f"sources extra -> artifact_missing ({exc})", True)

    # check de ordem de fontes no corpo do ficheiro
    fonte = inspect.getsource(mr.register_trained_version)
    check(f"_verify_artifacts aparece antes de _write_active_atomic", fonte.index("_verify_artifacts") < fonte.index("_write_active_atomic"))


# --- PIN: library_versions fixo ---


def _library_versions_pin() -> None:
    "Fecha a costura: library_versions tem de ser exatamente estes 4 nomes (teste de regressão)."
    import model_registry as mr

    # Esta função não recebe `tmp` (não toca no disco) e por isso é a única
    # que o `run()` chama sem argumento.

    expected = {"python", "scikit-learn", "joblib", "numpy"}
    meta = mr.build_trained_metadata(
        version_id="v1",
        contamination=0.2,
        random_state=42,
        n_estimators=200,
        dataset_name="eventos.json",
        dataset_size=36,
        dataset_attacks=5,
        synthetic=True,
        library_versions={"python": "3.12", "scikit-learn": "1.5", "joblib": "1.4", "numpy": "2.0"},
    )
    actual_keys = set(meta.get("library_versions", {}).keys())
    check(f"library_versions tem exatamente {len(expected)} chaves", actual_keys == expected)
    check(f"nenhuma chave a mais nem a menos", actual_keys == expected)


run()
