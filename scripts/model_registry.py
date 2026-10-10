"""
Registo de versões de modelo ML em disco (marco R9) — fonte única de
verdade sobre "que versões existem, qual está ativa e o que há em cada pasta".

Módulo de domínio puro, no mesmo padrão de lifecycle.py / attack_registry.py:
só stdlib, sem HTTP, sem FastAPI e sem joblib. Nunca desserializa pickle —
ler os metadados não é carregar o modelo, e carregar o modelo é o único ponto
com `joblib.load` do projeto (ml_anomalies.load_model, Fase 2).

Layout em disco (ver SKELETON.md):

    scripts/models/ACTIVE                    uma linha UTF-8, p.ex. "v1"
    scripts/models/vN/isolation_forest.pkl
    scripts/models/vN/scaler.pkl
    scripts/models/vN/metadata.json          schema 1

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
    - qualquer problema é devolvido com um código da lista fechada
      ERROR_CODES — nunca um caminho nem texto de exceção, porque é o código
      que vai para o HTTP (API-02).
"""

import json
import re
from pathlib import Path

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
      de cair para o legado.
    - `ACTIVE` não existe -> (None, None). O ramo do legado (`.pkl` soltos) é
      acrescentado aqui na Fase 2, para o carregamento usar a mesma decisão.
    """
    if not (root / ACTIVE_FILE).exists():
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
    # adopt/treino em curso) e ficheiros soltos ficam de fora. A entrada do
    # legado é acrescentada na Fase 2.
    version_ids = [n for n in names if VERSION_ID_RE.fullmatch(n) and (root / n).is_dir()]

    versions: list[dict] = []
    for version_id in sorted(version_ids, key=lambda v: int(v[1:]), reverse=True):
        try:
            version_dir = resolve_version_dir(root, version_id)
            meta = load_metadata(version_dir, version_id)
            status, error_code = "ok", None
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

    return {
        "active": active,
        "active_error": active_error,
        "loaded": loaded,
        "total": len(versions),
        "versions": versions,
    }