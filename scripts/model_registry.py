"""
Registo de versões de modelo ML em disco (marco R9) — fonte única de
verdade sobre "que versões existem, qual está ativa e os artefactos batem
com o que o metadata.json diz".

Módulo de domínio puro, no mesmo padrão de lifecycle.py / attack_registry.py:
só stdlib, sem HTTP, sem FastAPI e sem joblib. Nunca desserializa pickle —
ler os metadados e verificar um SHA-256 não é carregar o modelo, e carregar o
modelo é o único ponto com `joblib.load` do projeto (ml_anomalies.load_model,
que pede aqui os bytes já verificados).

Layout em disco (ver SKELETON.md):

    scripts/models/ACTIVE                    uma linha UTF-8, p.ex. "v1"
    scripts/models/vN/isolation_forest.pkl
    scripts/models/vN/scaler.pkl
    scripts/models/vN/metadata.json          schema 1
    scripts/models/{isolation_forest,scaler}.pkl   o "legado", sem metadados

Tudo o que vem do disco é dado não confiável (pode ter sido editado à mão
ou estar corrompido), por isso:

    - os ids de versão são validados com `VERSION_ID_RE.fullmatch` **e** com
      uma confirmação de que o caminho resolvido é filho direto de `models/`
      (a segunda camada cobre junctions/symlinks que apontem para fora);
    - os nomes dos artefactos são a constante ARTIFACT_FILES, nunca são
      lidos do metadata.json — nenhum caminho é construído a partir de
      dados do ficheiro;
    - `ACTIVE` é lido em binário com um teto de MAX_ACTIVE_BYTES e
      decodificado em utf-8-sig (um `echo v1 > ACTIVE` no PowerShell 5.1
      grava UTF-16, que tem de falhar em vez de ser adivinhado);
    - `metadata.json` tem um teto de MAX_METADATA_BYTES;
    - os bytes de um `.pkl` são lidos UMA vez e o SHA-256 é calculado sobre
      esses mesmos bytes, que são os que `joblib.load` vai receber — não há
      janela entre "verificar" e "usar" (SEC-01, ameaças T-01-07/T-01-08);
    - qualquer problema é devolvido com um código da lista fechada
      ERROR_CODES — nunca um caminho nem texto de exceção, porque é o código
      que vai para o HTTP (API-02).

Limite honesto desta verificação (D-04): o SHA-256 deteta corrupção, troca
acidental e ficheiros alheios sem metadados, mas NÃO autentica quem escreveu
— quem tem escrita em `models/` reescreve também o `metadata.json`. HMAC ou
assinatura ficam fora do âmbito do R9; ver README/ROADMAP_STATUS.

O módulo tem também o CLI (`python model_registry.py adopt`), que é o ÚNICO
ponto do projeto que escreve no registo: escrever por HTTP mudaria o modelo
em uso sem ninguém o pedir. O CLI traduz cada código de ERROR_CODES numa
mensagem PT acionável e devolve 0 ou 1; o texto vive aqui e nunca no HTTP
(API-02).
"""

import argparse
import hashlib
import hmac
import json
import os
import re
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple

# --- Contrato em disco -------------------------------------------------------

DEFAULT_MODELS_DIR = Path(__file__).resolve().parent / "models"
ARTIFACT_FILES = ("isolation_forest.pkl", "scaler.pkl")
ACTIVE_FILE = "ACTIVE"
METADATA_FILE = "metadata.json"

# Tetos de tamanho: um ACTIVE são 3 bytes ("v1\n"); 64 dá folga sem permitir
# um ficheiro gigante, e 64 KB para o metadata.json dá para metadados
# completos sem permitir um payload disfarçado de JSON.
MAX_ACTIVE_BYTES = 64
MAX_METADATA_BYTES = 65536

SCHEMA_VERSION = 1
LEGACY_LABEL = "legado, sem metadados"

# Ordem importa: ARTIFACT_FILES[0] é o modelo e [1] o scaler, e é essa ordem
# que vai para ArtifactSource.model_bytes / .scaler_bytes.
MODEL_FILE, SCALER_FILE = ARTIFACT_FILES

# Mensagem do FileNotFoundError do carregamento, sem nenhum caminho dentro
# (API-02: o `detail` da resposta HTTP levava `str(e)`, que antes incluía a
# pasta de modelos). A mensagem PT vive aqui e no browser (MLM_ERROR_TEXT);
# a razão fica no log.
NO_MODEL_MESSAGE = (
    "Modelo de ML não encontrado nem ativo. Corre 'python train_anomaly_model.py' "
    "para o gerar, ou 'python model_registry.py adopt' se já existir um modelo legado."
)

# `fullmatch` e nunca `match` com `$`: o `$` casa antes de um "\n" final, ou
# seja "v1\n" passaria a validação (RESEARCH, Pitfall 1).
VERSION_ID_RE = re.compile(r"v[0-9]{1,4}")
SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")

# Lista fechada de códigos (D-06). Não se acrescenta nenhum nesta fase: o
# frontend e as Fases 2/3 traduzem estes por nome.
ERROR_CODES = (
    "invalid_version_id",
    "active_not_found",
    "metadata_missing",
    "metadata_invalid",
    "artifact_missing",
    "hash_mismatch",
    "already_adopted",
    "no_legacy_model",
    "registry_unavailable",
)

# Projeção do metadata.json que a API expõe. `evaluation` NÃO entra aqui: é
# uma chave do nível da versão, não dos metadados (e só a Fase 2 a preenche).
METADATA_PUBLIC_KEYS = (
    "schema_version",
    "version",
    "origin",
    "adopted",
    "created_at",
    "trained_at",
    "trained_at_estimated",
    "model_type",
    "parameters",
    "dataset",
    "library_versions",
    "artifacts",
)


class ModelRegistryError(Exception):
    """
    Erro do registo com um código estável. `str(exc)` é exatamente o código,
    nunca um caminho nem a mensagem original — é esse código que vai no
    `detail` da resposta HTTP e no mapeamento para PT do browser.
    """

    def __init__(self, code):
        if code not in ERROR_CODES:
            raise ValueError(f"código de erro fora de ERROR_CODES: {code!r}")
        self.code = code
        super().__init__(code)


# --- Leitura do registo ------------------------------------------------------


def _root(models_dir) -> Path:
    """
    Pasta de modelos já resolvida. `None` ou string vazia resolvem para a pasta
    por omissão, NUNCA para o cwd: a linha `ML_MODEL_DIR=` vazia do
    .env.example faz `main.ML_MODEL_DIR` valer "".
    """
    if models_dir is None or (isinstance(models_dir, str) and not models_dir.strip()):
        models_dir = DEFAULT_MODELS_DIR
    return Path(models_dir).resolve()


def validate_version_id(value) -> str:
    """
    Um id de versão só pode ser `v` seguido de 1 a 4 dígitos ASCII. Qualquer
    outra coisa — "../x", "v1\n", "V1", "v12345", "", um não-str — é
    `invalid_version_id` (SEC-02).
    """
    if not isinstance(value, str) or VERSION_ID_RE.fullmatch(value) is None:
        raise ModelRegistryError("invalid_version_id")
    return value


def resolve_version_dir(root: Path, version_id: str) -> Path:
    """
    Pasta de uma versão, resolvida e garantida dentro de `models/`. Duas
    camadas: a regex (primária) e `candidate.parent == root` depois de
    `resolve()` (cobre uma junction/symlink `vN` que aponte para fora).
    `root` chega já resolvido por `_root`.
    """
    vid = validate_version_id(version_id)
    candidate = (root / vid).resolve()
    if candidate.parent != root:
        raise ModelRegistryError("invalid_version_id")
    if not candidate.is_dir():
        raise ModelRegistryError("active_not_found")
    return candidate


def read_active(root: Path) -> str | None:
    """
    Conteúdo de `models/ACTIVE` já validado, ou None se o ficheiro não
    existir. Ler mais do que MAX_ACTIVE_BYTES ou não conseguir descodificar
    UTF-8 é `invalid_version_id` (fail-closed: nunca adivinhamos um id).
    """
    try:
        with open(root / ACTIVE_FILE, "rb") as fh:
            raw = fh.read(MAX_ACTIVE_BYTES + 1)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ModelRegistryError("registry_unavailable") from exc

    if len(raw) > MAX_ACTIVE_BYTES:
        raise ModelRegistryError("invalid_version_id")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ModelRegistryError("invalid_version_id") from exc
    return validate_version_id(text.strip())


def _active_state(root: Path) -> tuple[str | None, str | None]:
    """
    Função única que decide o que está ativo: `(active, active_error)`.

    - `ACTIVE` existe e é válido -> (vN, None).
    - `ACTIVE` existe mas é inválido ou aponta para uma pasta que não existe
      -> (None, <código>); quem carrega o modelo recusa com esse código em vez
      de cair para o legado (fail-closed — mesmo com .pkl soltos presentes).
    - `ACTIVE` não existe, os dois `.pkl` soltos existem e `models/v1` não
      existe -> ("legacy", None): o modelo atual continua a carregar (REG-02),
      sem verificação de hash, até ser adotado.
    - caso contrário -> (None, None).
    """
    if not (root / ACTIVE_FILE).exists():
        if not (root / "v1").exists() and detect_legacy(root) is not None:
            return ("legacy", None)
        return (None, None)
    try:
        version_id = read_active(root)
        resolve_version_dir(root, version_id)
    except ModelRegistryError as exc:
        return (None, exc.code)
    return (version_id, None)


def load_metadata(version_dir: Path, version_id: str) -> dict:
    """
    Lê e valida `metadata.json` de uma versão. Devolve o dict tal como está
    no disco; quem chama decide o que é público.

    Inválido = `metadata_invalid`; ausente = `metadata_missing`; erro de I/O
    = `registry_unavailable`. Chaves a mais dentro de `artifacts` são
    ignoradas — em particular nunca são usadas como nome de ficheiro.
    """
    path = version_dir / METADATA_FILE
    try:
        if not path.is_file():
            raise ModelRegistryError("metadata_missing")
        if path.stat().st_size > MAX_METADATA_BYTES:
            raise ModelRegistryError("metadata_invalid")
        raw = path.read_bytes()
    except ModelRegistryError:
        raise
    except OSError as exc:
        raise ModelRegistryError("registry_unavailable") from exc

    try:
        meta = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ModelRegistryError("metadata_invalid") from exc

    if not isinstance(meta, dict):
        raise ModelRegistryError("metadata_invalid")

    schema_version = meta.get("schema_version")
    if isinstance(schema_version, bool) or not isinstance(schema_version, int) or schema_version != SCHEMA_VERSION:
        raise ModelRegistryError("metadata_invalid")

    if meta.get("version") != version_id:
        raise ModelRegistryError("metadata_invalid")

    artifacts = meta.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ModelRegistryError("metadata_invalid")
    for name in ARTIFACT_FILES:
        entry = artifacts.get(name)
        if not isinstance(entry, dict):
            raise ModelRegistryError("metadata_invalid")
        digest = entry.get("sha256")
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            raise ModelRegistryError("metadata_invalid")
        size = entry.get("size_bytes")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ModelRegistryError("metadata_invalid")

    evaluation = meta.get("evaluation")
    if evaluation is not None and not isinstance(evaluation, dict):
        raise ModelRegistryError("metadata_invalid")

    return meta


def _public_metadata(meta: dict) -> dict:
    """Projeção das chaves públicas do metadata.json (chave em falta = None)."""
    public = {key: meta.get(key) for key in METADATA_PUBLIC_KEYS}
    artifacts = meta.get("artifacts")
    if not isinstance(artifacts, dict):
        artifacts = {}
    public["artifacts"] = {
        name: {
            "sha256": str((artifacts.get(name) or {}).get("sha256") or "").lower(),
            "size_bytes": (artifacts.get(name) or {}).get("size_bytes"),
        }
        for name in ARTIFACT_FILES
    }
    return public


# --- Integridade (SEC-01) -----------------------------------------------------


def sha256_file(path) -> str:
    """
    SHA-256 de um ficheiro, em streaming (blocos de 1 MiB — os `.pkl` do
    projeto têm ~0,5 MB, mas a listagem não deve carregar o ficheiro inteiro
    só para o summarizar). Ficheiro em falta = `artifact_missing`; outra
    falha de I/O = `registry_unavailable`.
    """
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
    except FileNotFoundError as exc:
        raise ModelRegistryError("artifact_missing") from exc
    except OSError as exc:
        raise ModelRegistryError("registry_unavailable") from exc
    return digest.hexdigest()


def _verify_artifacts(version_dir: Path, meta: dict) -> str:
    """
    Confere o SHA-256 dos dois artefactos de uma versão contra o que o
    metadata.json diz. Devolve "ok" | "artifact_missing" | "hash_mismatch" |
    "registry_unavailable" — nunca levanta, para que uma versão corrotta
    apareça marcada na lista sem derrubar as restantes.

    `hmac.compare_digest` em vez de `==` por convenção (o hash não é segredo,
    não é defesa contra timing; a stdlib não tem uma comparação de strings
    constante exposta). A comparação é feita em minúsculas para aceitar um
    metadata.json escrito com o hash em maiúsculas.
    """
    artifacts = meta.get("artifacts")
    if not isinstance(artifacts, dict):
        return "metadata_invalid"
    for name in ARTIFACT_FILES:
        esperado = str((artifacts.get(name) or {}).get("sha256") or "")
        try:
            real = sha256_file(version_dir / name)
        except ModelRegistryError as exc:
            return exc.code
        if not hmac.compare_digest(real, esperado.lower()):
            return "hash_mismatch"
    return "ok"


def read_verified_bytes(version_dir: Path, filename: str, expected_sha256: str) -> bytes:
    """
    Os bytes de um artefacto, **verificados**: o ficheiro é lido UMA vez, o
    SHA-256 é calculado sobre esses mesmos bytes e devolve-se exatamente
    esses bytes. Quem chama faz `joblib.load(io.BytesIO(data))` sobre eles —
    nunca reabre o ficheiro, logo não há janela TOCTOU entre verificar e
    carregar (T-01-08).

    `filename` tem de ser uma constante de ARTIFACT_FILES: nenhum caminho é
    construído a partir de texto que venha de fora (uma camada de defence
    contra traversal, para o caso de alguém chamar isto com um nome lido do
    metadata.json). Erro de programação, não de dados — daí `metadata_invalid`
    em vez de um código novo (D-06 fecha a lista).
    """
    if filename not in ARTIFACT_FILES:
        raise ModelRegistryError("metadata_invalid")
    try:
        data = (version_dir / filename).read_bytes()
    except (FileNotFoundError, IsADirectoryError) as exc:
        raise ModelRegistryError("artifact_missing") from exc
    except OSError as exc:
        raise ModelRegistryError("registry_unavailable") from exc
    real = hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(real, str(expected_sha256).lower()):
        raise ModelRegistryError("hash_mismatch")
    return data


def detect_legacy(root: Path) -> dict | None:
    """
    Os dois `.pkl` soltos em `models/` — o "legado" sem metadados — ou None
    se algum deles não existir. Só `stat()`: nunca abre nem desserializa os
    ficheiros (REG-02 obriga a que este seja o mesmo ficheiro local que já
    era carregado antes, agora exposto na lista como "legado, sem
    metadados"). Um `.pkl` isolado (só um dos dois) não é legado.
    """
    ficheiros: dict[str, dict] = {}
    for name in ARTIFACT_FILES:
        path = root / name
        try:
            st = path.stat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ModelRegistryError("registry_unavailable") from exc
        if not path.is_file():
            return None
        ficheiros[name] = {
            "size_bytes": st.st_size,
            "modified_at": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
        }
    return ficheiros


class ArtifactSource(NamedTuple):
    """
    Os bytes com que o modelo vai ser carregado, já decididos pelo registo.

    `version` é "vN" ou "legacy". `verified` é True só quando os bytes foram
    conferidos contra o SHA-256 do metadata.json; no legado é False — REG-02
    obriga a que o modelo atual continue a carregar até ser adotado, e o risco
    aceite está documentado em README e no modelo de ameaças (T-01-10).
    """

    version: str
    verified: bool
    model_bytes: bytes
    scaler_bytes: bytes


def resolve_active_artifacts(models_dir) -> ArtifactSource:
    """
    Os bytes a carregar do que está ativo, com a verificação de integridade
    já feita. É a fronteira de segurança do SEC-01: devolve os dois
    artefactos **juntos** ou não devolve nada — quem chama nunca recebe um par
    em que um foi verificado e o outro não.

    - versão ativa vN -> resolve_version_dir + load_metadata +
      read_verified_bytes para os DOIS artefactos antes de devolver;
    - legado ativo -> os dois `.pkl` soltos, sem verificação (REG-02);
    - `ACTIVE` inválido -> ModelRegistryError com esse código, sem cair para
      o legado (fail-closed);
    - nada ativo (pasta vazia ou inexistente) -> FileNotFoundError com
      NO_MODEL_MESSAGE, que não contém nenhum caminho.
    """
    root = _root(models_dir)
    active, active_error = _active_state(root)
    if active_error:
        raise ModelRegistryError(active_error)

    if active == "legacy":
        brutos: dict[str, bytes] = {}
        for name in ARTIFACT_FILES:
            try:
                brutos[name] = (root / name).read_bytes()
            except (FileNotFoundError, IsADirectoryError) as exc:
                raise ModelRegistryError("artifact_missing") from exc
            except OSError as exc:
                raise ModelRegistryError("registry_unavailable") from exc
        return ArtifactSource(
            version="legacy",
            verified=False,
            model_bytes=brutos[MODEL_FILE],
            scaler_bytes=brutos[SCALER_FILE],
        )

    if active:
        version_dir = resolve_version_dir(root, active)
        meta = load_metadata(version_dir, active)
        artifacts = meta["artifacts"]
        # Os dois lidos e verificados ANTES de devolver qualquer coisa.
        model_bytes = read_verified_bytes(version_dir, MODEL_FILE, artifacts[MODEL_FILE]["sha256"])
        scaler_bytes = read_verified_bytes(version_dir, SCALER_FILE, artifacts[SCALER_FILE]["sha256"])
        return ArtifactSource(
            version=active,
            verified=True,
            model_bytes=model_bytes,
            scaler_bytes=scaler_bytes,
        )

    raise FileNotFoundError(NO_MODEL_MESSAGE)


def build_models_report(models_dir, loaded=None) -> dict:
    """
    Relatório do registo para `GET /api/ml/models` (contrato em SKELETON.md).

    `loaded` é a versão que o processo tem de facto em memória (D-02): depois
    de um adopt o processo continua a servir o modelo antigo, e o dashboard
    não pode afirmar que a ativa é a usada nas deteções.

    Uma pasta inexistente ou um `models/` vazio dão 200 com a lista vazia. Uma
    versão com problema aparece na lista com `status`/`error_code` e nunca
    derruba as restantes — só uma falha a ler a pasta inteira é
    `registry_unavailable`, que a rota mapeia para 503.
    """
    root = _root(models_dir)
    if not root.is_dir():
        return {"active": None, "active_error": None, "loaded": loaded, "total": 0, "versions": []}

    active, active_error = _active_state(root)

    try:
        names = [entry.name for entry in root.iterdir()]
    except OSError as exc:
        raise ModelRegistryError("registry_unavailable") from exc

    # Só pastas cujo nome casa o regex: "v1.tmp-123" (a pasta temporária de um
    # adopt/treino em curso) e ficheiros soltos ficam de fora.
    version_ids = [n for n in names if VERSION_ID_RE.fullmatch(n) and (root / n).is_dir()]

    versions: list[dict] = []
    for version_id in sorted(version_ids, key=lambda v: int(v[1:]), reverse=True):
        try:
            version_dir = resolve_version_dir(root, version_id)
            meta = load_metadata(version_dir, version_id)
            # A verificação de integridade só roda com metadata válido: em
            # `artifact_missing`/`hash_mismatch` os metadados continuam
            # visíveis, para o analista ver que esperava que hash (SKELETON).
            status = _verify_artifacts(version_dir, meta)
            error_code = None if status == "ok" else status
            metadata = _public_metadata(meta)
            evaluation = meta.get("evaluation")
        except ModelRegistryError as exc:
            status = error_code = exc.code
            metadata = evaluation = None

        versions.append({
            "id": version_id,
            "kind": "versioned",
            "label": version_id,
            "active": version_id == active,
            "status": status,
            "error_code": error_code,
            "metadata": metadata,
            "evaluation": evaluation,
        })

    # Entrada do legado (D-03): só enquanto os dois .pkl soltos existirem,
    # `models/v1` não existir e nada válido estar ativo. Nunca substitui uma
    # versão — os originais ficam em disco intactos.
    if not (root / "v1").exists() and active in (None, "legacy"):
        legacy_files = detect_legacy(root)
        if legacy_files is not None:
            versions.append({
                "id": None,
                "kind": "legacy",
                "label": LEGACY_LABEL,
                "active": active == "legacy",
                "status": "no_metadata",
                "error_code": None,
                "metadata": None,
                "evaluation": None,
                "files": legacy_files,
            })

    return {
        "active": active,
        "active_error": active_error,
        "loaded": loaded,
        "total": len(versions),
        "versions": versions,
    }


# --- Escrita no registo (só por CLI, nunca por HTTP) --------------------------
#
# A escrita segue sempre a mesma forma: tudo o que fica visível na listagem é
# escrito primeiro numa pasta/ficheiro temporário e só depois movido para o
# nome final com `os.replace`, que no Windows é atómico dentro do mesmo
# volume. Assim nunca existe uma `v1` a meio (T-01-18) nem um `ACTIVE`
# truncado (T-01-19), e um bloqueio do OneDrive/antivírus/Explorador
# (PermissionError) deixa o registo como estava (T-01-22).


def _materialize_version(root: Path, version_id: str, sources: dict, meta: dict) -> dict:
    """
    Cria `models/<version_id>/` a partir de `sources` (mapeamento nome ->
    caminho), preenchendo `meta["artifacts"]` com o SHA-256 e o tamanho de
    cada cópia. Devolve o mesmo `meta`, já com os artefactos.

    A pasta temporária chama-se `<version_id>.tmp-<aleatorio>`: um nome que
    NÃO casa `VERSION_ID_RE`, logo uma versão a meio é invisível para
    `build_models_report` mesmo que o processo seja interrompido entre a
    cópia e o `os.replace`. O `finally` apaga a temporária em qualquer
   outcome — o disco nunca fica com sobras `v1.tmp-*`.

    Os originais são só lidos: `shutil.copy2` copia e preserva o mtime (a data
    de treino estimada sai daqui), e o SHA-256 é conferido entre a cópia e o
    original antes de a versão se tornar visível (T-01-20). Qualquer
    `OSError` — do `copy2`, da escrita ou do `replace` — é
    `registry_unavailable`; um hash que não bate é `hash_mismatch`.

    Helper privado, mas reutilizável pela Fase 3 (treino a criar vN).
    """
    vid = validate_version_id(version_id)
    target = root / vid
    tmp = None
    try:
        tmp = Path(tempfile.mkdtemp(prefix=f"{vid}.tmp-", dir=root))
        artifacts = meta.setdefault("artifacts", {})
        for nome in ARTIFACT_FILES:
            origem = Path(sources[nome])
            destino = tmp / nome
            shutil.copy2(origem, destino)
            digest_copia = sha256_file(destino)
            digest_original = sha256_file(origem)
            if not hmac.compare_digest(digest_copia, digest_original):
                raise ModelRegistryError("hash_mismatch")
            artifacts[nome] = {"sha256": digest_copia, "size_bytes": destino.stat().st_size}
        (tmp / METADATA_FILE).write_text(
            json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        os.replace(tmp, target)
        tmp = None
    except ModelRegistryError:
        raise
    except OSError as exc:
        raise ModelRegistryError("registry_unavailable") from exc
    finally:
        if tmp is not None and tmp.exists():
            shutil.rmtree(tmp, ignore_errors=True)
    return meta


def _write_active_atomic(root: Path, version_id: str) -> None:
    """
    Escreve `models/ACTIVE` com uma linha UTF-8 (o `newline` final é o que o
    `echo` do POSIX produz; `read_active` faz `strip()`, portanto também
    aceitaria a ausência dele). Por ficheiro temporário + `os.replace`: um
    `ACTIVE` nunca fica truncado, e um bloqueio a meio deixa o ficheiro
    anterior intacto em vez de o substituir por lixo (T-01-19).

    Não decide se deve ou não escrever — quem decide é o chamador (D-01:
    `adopt` só escreve quando não existe nenhum).
    """
    vid = validate_version_id(version_id)
    tmp_name = None
    try:
        descritor, tmp_name = tempfile.mkstemp(prefix=f"{ACTIVE_FILE}.tmp-", dir=root)
        with os.fdopen(descritor, "wb") as fh:
            fh.write((vid + "\n").encode("utf-8"))
        os.replace(tmp_name, root / ACTIVE_FILE)
        tmp_name = None
    except OSError as exc:
        raise ModelRegistryError("registry_unavailable") from exc
    finally:
        if tmp_name is not None:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass


def _resume_adoption(root: Path) -> dict:
    """
    Recupera um `adopt` interrompido entre o `os.replace` da `v1` e a escrita
    do `ACTIVE` (T-01-23): verifica a `v1` existente e escreve só o `ACTIVE`
    em falta, sem recopiar nada.

    Recusa — sempre `already_adopted` e sem escrever uma linha sequer:

    - o `ACTIVE` existe (adopt completo, ou D-01 com outro `ACTIVE`);
    - a `v1` não resolve para dentro de `models/` (junction/symlink para fora,
      via `resolve_version_dir`);
    - o `metadata.json` está em falta ou é inválido;
    - `origin` não é `"adopted"` ou `adopted` não é `True`;
    - o SHA-256 dos `.pkl` da `v1` não bate com o próprio `metadata.json`
      (`_verify_artifacts` != "ok");
    - o SHA-256 do `metadata.json` não é igual ao dos `.pkl` legados.

    A última condição é a que impede ativar uma v1 alheia com metadados
    coerentes (T-01-24): o que se ativa tem de ser, byte a byte, o modelo que
    se ia adotar. Falhar aqui é sempre preferível a ficar a servir o modelo
    errado em silêncio; a falha a escrever o `ACTIVE` volta a ser
    `registry_unavailable` e o utilizador repete o comando.
    """
    active_path = root / ACTIVE_FILE
    if active_path.exists() or active_path.is_symlink():
        raise ModelRegistryError("already_adopted")

    try:
        v1_dir = resolve_version_dir(root, "v1")
        meta = load_metadata(v1_dir, "v1")
        if meta.get("origin") != "adopted" or meta.get("adopted") is not True:
            raise ModelRegistryError("already_adopted")
        if _verify_artifacts(v1_dir, meta) != "ok":
            raise ModelRegistryError("already_adopted")
        artifacts = meta["artifacts"]
        for nome in ARTIFACT_FILES:
            hash_legado = sha256_file(root / nome)
            if not hmac.compare_digest(str(artifacts[nome]["sha256"]).lower(), hash_legado):
                raise ModelRegistryError("already_adopted")
    except Exception as exc:  # noqa: BLE001 — fail-closed: nunca ativar por dúvida
        # `invalid_version_id`, `metadata_missing`, `metadata_invalid`,
        # `hash_mismatch`, `artifact_missing`, `registry_unavailable` — e
        # qualquer outra coisa inesperada — valem o mesmo: `already_adopted`,
        # nada escrito. O código original fica na `__cause__` para o log.
        raise ModelRegistryError("already_adopted") from exc

    _write_active_atomic(root, "v1")
    return {"version": "v1", "metadata": meta, "active_written": True, "resumed": True}


def adopt(models_dir) -> dict:
    """
    Adota o modelo legado (`models/isolation_forest.pkl` + `scaler.pkl`) como
    a versão `v1` do registo (REG-03).

    Copia, nunca move: os `.pkl` soltos são o ficheiro local que já era
    carregado (REG-02) e continuam em `models/` intactos, com o mesmo SHA-256,
    tamanho e mtime — nenhum caminho desta função os abre para escrita, os
    move ou os apaga (T-01-17).

    A ordem das escritas é fixa e é o que torna o comando recuperável:

        1. `models/v1` por pasta temporária + `os.replace` (atómico);
        2. confirmação final com `load_metadata` + `_verify_artifacts`;
        3. `models/ACTIVE`, **só se ainda não existir** (D-01).

    Se o passo 3 falhar, a `v1` fica criada e sem `ACTIVE` — a deteção dá 503
    e o utilizador repete o comando, que entra em `_resume_adoption` e escreve
    só o `ACTIVE` em falta. A ordem inversa (ACTIVE primeiro) foi descartada
    porque a reversão também pode falhar pelo mesmo bloqueio e deixaria o
    `ACTIVE` a apontar para uma `v1` inexistente.

    Devolve `{"version", "metadata", "active_written", "resumed"}`. Códigos:
    `no_legacy_model` (não há os dois `.pkl` soltos), `already_adopted`
    (adopt completo, ou uma `v1` que não é a adoção do legado),
    `hash_mismatch` (a cópia não bate com o original) e `registry_unavailable`
    (bloqueio de I/O — nada fica a meio).
    """
    root = _root(models_dir)
    if not root.is_dir() or detect_legacy(root) is None:
        raise ModelRegistryError("no_legacy_model")

    v1_path = root / "v1"
    if v1_path.exists() or v1_path.is_symlink():
        # Nunca `already_adopted` direto: um adopt interrompido na escrita do
        # ACTIVE tem de se recuperar voltando a correr o comando (T-01-23).
        return _resume_adoption(root)

    try:
        mtime = (root / MODEL_FILE).stat().st_mtime
    except OSError as exc:
        raise ModelRegistryError("registry_unavailable") from exc

    meta = {
        "schema_version": SCHEMA_VERSION,
        "version": "v1",
        "origin": "adopted",
        "adopted": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
        # Data de treino ESTIMADA pela data do ficheiro: o modelo foi
        # treinado fora do registo e ninguém sabe quando (o adopt não
        # desserializa o pickle para o descobrir — SEC-01).
        "trained_at": datetime.fromtimestamp(mtime, timezone.utc).isoformat(),
        "trained_at_estimated": True,
        "model_type": "IsolationForest",
        "parameters": None,
        "dataset": {"name": None, "size": None, "attacks": None, "synthetic": None},
        "library_versions": None,
        "artifacts": {},
        "evaluation": None,
    }
    sources = {nome: root / nome for nome in ARTIFACT_FILES}
    _materialize_version(root, "v1", sources, meta)

    # Confirmação final com o que ficou em disco (e não com o dict em memória):
    # se algo tiver mudado entre a cópia e agora, melhor falhar aqui do que
    # deixar um ACTIVE a apontar para uma versão que não verifica.
    v1_dir = root / "v1"
    try:
        confirmado = load_metadata(v1_dir, "v1")
        status = _verify_artifacts(v1_dir, confirmado)
    except ModelRegistryError:
        raise
    except OSError as exc:
        raise ModelRegistryError("registry_unavailable") from exc
    if status != "ok":
        raise ModelRegistryError(status)

    active_path = root / ACTIVE_FILE
    if active_path.exists() or active_path.is_symlink():
        # D-01: um ACTIVE existente foi escrito pelo utilizador ou aponta para
        # outra versão; reescrevê-lo mudaria em silêncio o modelo usado nas
        # deteções. Deixa-se como está e o CLI diz como ativar a v1 à mão.
        active_written = False
    else:
        _write_active_atomic(root, "v1")
        active_written = True

    return {
        "version": "v1",
        "metadata": meta,
        "active_written": active_written,
        "resumed": False,
    }


# --- CLI (único ponto do projeto que escreve no registo) ---------------------
#
# Um subcomando por operação, porque cada um é destrutivo o suficiente para
# pedir confirmação pelo nome: `adopt` (Fase 1) e, na Fase 2, `evaluate`.
# `--models-dir` por omissão segue `ML_MODEL_DIR` — a mesma pasta que o
# backend usa — e nunca o cwd.

MESSAGES_PT = {
    "invalid_version_id": (
        "Identificador de versão inválido: tem de ser 'v' seguido de 1 a 4 dígitos "
        "(ex.: 'v1'). O models/ACTIVE tem de ter esse nome numa linha, em UTF-8."
    ),
    "active_not_found": (
        "O models/ACTIVE aponta para uma versão que não existe em models/. Cria a "
        "pasta da versão ou apaga/corrige o models/ACTIVE."
    ),
    "metadata_missing": (
        "A versão não tem metadata.json. Volta a adotar o modelo para a escrever."
    ),
    "metadata_invalid": (
        "O metadata.json da versão é inválido (JSON, schema_version ou hashes). Volta "
        "a registar a versão para o reescrever."
    ),
    "artifact_missing": (
        "Falta um dos artefactos .pkl da versão. Repõe o ficheiro em falta a partir "
        "da cópia de segurança."
    ),
    "hash_mismatch": "A cópia não bate com o original (SHA-256); nada foi registado. Repete o comando.",
    "already_adopted": (
        "O modelo legado já foi adotado: models/v1 já existe e o models/ACTIVE também "
        "(ou a v1 existente não corresponde ao modelo legado). Nada foi alterado."
    ),
    "no_legacy_model": (
        "Não há modelo legado para adotar: faltam isolation_forest.pkl e/ou scaler.pkl "
        "em models/."
    ),
    "registry_unavailable": (
        "Não foi possível escrever em models/ — fecha o que tiver a pasta aberta "
        "(Explorador, OneDrive, antivírus) e volta a correr o comando; se a v1 já "
        "tiver ficado criada, o adopt só completa o models/ACTIVE. Os ficheiros "
        "originais não foram alterados."
    ),
}


def _cmd_adopt(args) -> int:
    """`python model_registry.py adopt` — REG-03. Devolve 0 ou 1."""
    modelos = args.models_dir or os.environ.get("ML_MODEL_DIR") or DEFAULT_MODELS_DIR
    try:
        resultado = adopt(modelos)
    except ModelRegistryError as exc:
        print(f"Erro ({exc.code}): {MESSAGES_PT[exc.code]}", file=sys.stderr)
        return 1

    artefatos = (resultado["metadata"].get("artifacts") or {})
    if resultado["resumed"]:
        print("Adopt retomado: a v1 de um adopt interrompido foi verificada "
              "(SHA-256 igual ao do modelo legado); nada foi copiado.")
    else:
        print("Modelo legado adotado como v1 por cópia — os originais em models/ "
              "não foram alterados.")
    for nome in ARTIFACT_FILES:
        entrada = artefatos.get(nome) or {}
        print(f"  {nome}  sha256={entrada.get('sha256')}  {entrada.get('size_bytes')} bytes")
    if resultado["active_written"]:
        print("models/ACTIVE -> v1")
    else:
        print("Aviso: models/ACTIVE já existia e não foi alterado; para ativar a v1 "
              "escreve v1 nesse ficheiro (UTF-8).")
    # A cache do modelo é por processo (D-02): sem isto, o backend continua a
    # servir o modelo antigo e o dashboard diz "ativa: v1" a mentir.
    print("Reinicia o backend (scripts/start-backend.ps1) para carregar a v1.")
    return 0


def main(argv=None) -> int:
    """Ponto de entrada do CLI. 0 = feito, 1 = recusado com um código estável."""
    # Windows manda stdout/stderr para o codepage da consola, o que corrompe
    # os acentos quando a saída é redirecionada (ver main.py).
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8")
            except (AttributeError, ValueError, OSError):
                pass

    parser = argparse.ArgumentParser(
        prog="model_registry.py",
        description=(
            "Registo de versões de modelo ML do SentryLens. Escrita só por linha de "
            "comando: o backend nunca escreve no registo."
        ),
    )
    subcomandos = parser.add_subparsers(dest="command", required=True)

    p_adopt = subcomandos.add_parser(
        "adopt",
        help="Adota os .pkl soltos de models/ como a versão v1 (copia, nunca move)",
    )
    p_adopt.add_argument(
        "--models-dir",
        default=None,
        help="Pasta do registo (por omissão: $ML_MODEL_DIR ou scripts/models)",
    )
    p_adopt.set_defaults(func=_cmd_adopt)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
