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

O módulo tem também o CLI (`python model_registry.py adopt` e
`python model_registry.py evaluate vN --events F`), que é o ÚNICO ponto do
projecto que escreve no registo: escrever por HTTP mudaria o modelo em uso
sem ninguém o pedir. O CLI traduz cada código de ERROR_CODES numa mensagem PT
accionável e devolve 0 ou 1; o texto vive aqui e nunca no HTTP (API-02).

O `evaluate` (Fase 2) mede a versão PEDIDA, não a ativa, e grava o resultado
no metadata.json dela. Para carregar scikit-learn sem tornar este ficheiro
dependente dele, o motor da avaliação vive em `scripts/ml_evaluation.py` e é
importado DENTRO de `_cmd_evaluate`/`evaluate` (D-01): no topo só há stdlib.
"""

import argparse
import hashlib
import hmac
import importlib
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

# Projeção do campo `evaluation` que a API expõe (D-08). É a MESMA lista de 14
# chaves que `ml_evaluation.EVALUATION_KEYS` — mas escrita aqui, porque este
# módulo não pode importar `ml_evaluation` (D-01: stdlib puro no topo). A
# igualdade das duas é verificada por scripts/test_ml_models_api.py, para que
# uma das listas divergir nunca passe em silêncio.
EVALUATION_PUBLIC_KEYS = (
    "evaluated_at",
    "events_file",
    "attack_log",
    "label_window_seconds",
    "total_events",
    "attacks_in_dataset",
    "ml",
    "rules",
    "comparison",
    "min_events",
    "min_attacks",
    "small_sample",
    "caveat",
    "dataset_origin",
)

# Os três sub-objectos, com os seus próprios sub-conjuntos fechados (3 e 4
# chaves). Também comparados com os do motor no mesmo teste.
EVALUATION_METRIC_KEYS = ("precision", "recall", "f1")
EVALUATION_COMPARISON_KEYS = ("both_flagged", "ml_only", "rules_only", "neither")

# Tipo esperado de cada chave, para a sub-projeção nunca repassar o que vier do
# disco do utilizador tal e qual. str -> truncada; float/int/bool projectados
# pelo tipo; o resto cai a None.
EVALUATION_KEY_TYPES = {
    "evaluated_at": str,
    "events_file": str,
    "attack_log": str,
    "label_window_seconds": int,
    "total_events": int,
    "attacks_in_dataset": int,
    "ml": dict,
    "rules": dict,
    "comparison": dict,
    "min_events": int,
    "min_attacks": int,
    "small_sample": bool,
    "caveat": str,
    "dataset_origin": str,
}

# Teto por campo de texto: o `caveat` e os nomes de ficheiro são os únicos
# textos que saem do disco, e mesmo estes entram truncados.
EVALUATION_TEXT_LIMIT = 200


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


def resolve_version_artifacts(models_dir, version_id) -> ArtifactSource:
    """
    Os bytes de UMA VERSÃO, com a verificação de integridade já feita (D-02).

    É o bloco `if active:` de `resolve_active_artifacts` sem a lógica de
    `_active_state`, existindo para que `model_registry.py evaluate v1` possa
    carregar a v1 **pedida** e não a que estiver no `ACTIVE` — e para que
    avaliar a vN e carregar a vN ativa usem exactamente as mesmas regras de
    integridade (é o mesmo corpo, não uma cópia).

    Erros, todos sem devolver qualquer byte: id inválido
    (`invalid_version_id`), pasta que não existe (`active_not_found`),
    metadados em falta ou ilegíveis (`metadata_missing`/`metadata_invalid`) e
    um `.pkl` em falta ou adulterado (`artifact_missing`/`hash_mismatch`).
    """
    root = _root(models_dir)
    vid = validate_version_id(version_id)
    version_dir = resolve_version_dir(root, vid)
    meta = load_metadata(version_dir, vid)
    artifacts = meta["artifacts"]
    # Os dois lidos e verificados ANTES de devolver qualquer coisa.
    model_bytes = read_verified_bytes(version_dir, MODEL_FILE, artifacts[MODEL_FILE]["sha256"])
    scaler_bytes = read_verified_bytes(version_dir, SCALER_FILE, artifacts[SCALER_FILE]["sha256"])
    return ArtifactSource(
        version=vid,
        verified=True,
        model_bytes=model_bytes,
        scaler_bytes=scaler_bytes,
    )


def resolve_active_artifacts(models_dir) -> ArtifactSource:
    """
    Os bytes a carregar do que está ativo, com a verificação de integridade
    já feita. É a fronteira de segurança do SEC-01: devolve os dois
    artefactos **juntos** ou não devolve nada — quem chama nunca recebe um par
    em que um foi verificado e o outro não.

    - versão ativa vN -> `resolve_version_artifacts` (mesmas regras que a
      avaliação de uma vN arbitrária);
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
        return resolve_version_artifacts(root, active)

    raise FileNotFoundError(NO_MODEL_MESSAGE)


def _public_evaluation_scalar(value, tipo):
    """
    Um valor do `evaluation` projectado pelo seu tipo. `None`, ausente ou de
    tipo errado dá `None` — nunca o valor como veio. str é truncada a
    EVALUATION_TEXT_LIMIT caracteres com reticências, para que um ficheiro do
    utilizador não possa pôr texto infinito na resposta.
    """
    if value is None:
        return None
    if tipo is bool:  # antes de int: bool é subclasse de int em Python
        return value if isinstance(value, bool) else None
    if tipo is int:
        if isinstance(value, bool) or not isinstance(value, int):
            return None
        return value
    if tipo is float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        return float(value)
    if not isinstance(value, str):
        return None
    if len(value) <= EVALUATION_TEXT_LIMIT:
        return value
    return value[:EVALUATION_TEXT_LIMIT - 1] + "…"


def _public_evaluation(evaluation) -> dict | None:
    """
    Sub-projeção do `evaluation` que a API devolve (D-08).

    Fecha o risco residual T-01-14: o `evaluation` vem de um ficheiro que o
    utilizador pode ter escrito à mão, e o `detail` de um erro nunca entra no
    DOM. Aqui só passa o que está na lista fechada de 14 chaves, cada uma
    projectada pelo seu tipo, com `ml`/`rules`/`comparison` projectados pelos
    seus sub-conjuntos (3, 3 e 4 chaves). Tudo o que não esteja nas listas é
    DESCARTADO — é isto que impede texto arbitrário de sair pela rota.

    `None` continua `None` (EVAL-03). Um `evaluation` que não seja `dict` nem
    `null` nunca chega aqui: `load_metadata` já o recusa com
    `metadata_invalid`, por isso uma avaliação estruturalmente inválida não
    passa a "sem avaliação" em silêncio.

    Nunca levanta.
    """
    if not isinstance(evaluation, dict):
        return None

    publico: dict = {}
    for chave in EVALUATION_PUBLIC_KEYS:
        tipo = EVALUATION_KEY_TYPES[chave]
        if tipo is dict:
            bruto = evaluation.get(chave)
            sub = EVALUATION_METRIC_KEYS if chave in ("ml", "rules") else EVALUATION_COMPARISON_KEYS
            tipo_sub = float if chave in ("ml", "rules") else int
            if isinstance(bruto, dict):
                publico[chave] = {k: _public_evaluation_scalar(bruto.get(k), tipo_sub) for k in sub}
            else:
                publico[chave] = {k: None for k in sub}
        else:
            publico[chave] = _public_evaluation_scalar(evaluation.get(chave), tipo)
    return publico


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
            evaluation = _public_evaluation(meta.get("evaluation"))
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
# (PermissionError) deixa o registo como estava (T-01-22). A Fase 2 grava o
# `metadata.json` com a mesma regra (`_write_evaluation`, T-02-02).


def _materialize_version(root: Path, version_id: str, sources: dict, meta: dict) -> dict:
    """
    Cria `models/<version_id>/` a partir de `sources` (mapeamento nome ->
    caminho), preenchendo `meta["artifacts"]` com o SHA-256 e o tamanho de
    cada cópia. Devolve o mesmo `meta`, já com os artefactos.

    A pasta temporária chama-se `<version_id>.tmp-<aleatorio>`: um nome que
    NÃO casa `VERSION_ID_RE`, logo uma versão a meio é invisível para
    `build_models_report` mesmo que o processo seja interrompido entre a
    cópia e o `os.replace`. O `finally` apaga a temporária em qualquer
    caso — o disco nunca fica com sobras `v1.tmp-*`.

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


def next_version_id(models_dir) -> str:
    """
    Retorna a próxima ID de versão no registo.

    - Se o diretório não existir ou estiver vazio → `"v1"`.
    - Caso contrário, `max(int(n[1:]) for n em itens que combinam VERSION_ID_RE
      e que sejam pastas) + 1`, ou `"v1"` se não houver números.
    - O resultado é validado por `validate_version_id` (evita `v10000` etc.).
    - Usa `max+1`, **não** `count()`. O `os.replace` de pasta sobre pasta existente
      dá `PermissionError [WinError 5]` no Windows; `count()` faria o id colidir
      com uma versão apagada no meio.

    Aplica `_root(models_dir)` antes de listar, nunca usa o `cwd`.
    """
    from model_registry import validate_version_id as _valid

    root = _root(models_dir)
    try:
        nomes = [
            n for n in root.iterdir()
            if VERSION_ID_RE.fullmatch(n.name) and (root / n.name).is_dir()
        ]
        nums = [int(n.name[1:]) for n in nomes]
        if nums:
            result = f"v{max(nums) + 1}"
        else:
            result = "v1"
    except FileNotFoundError:
        result = "v1"
    except OSError as exc:
        raise ModelRegistryError("registry_unavailable") from exc

    validated = _valid(result)
    return validated


def build_trained_metadata(
    *,
    version_id,
    contamination,
    random_state,
    n_estimators,
    dataset_name,
    dataset_size,
    dataset_attacks,
    synthetic,
    library_versions,
    model_type="IsolationForest",
    trained_at=None,
    created_at=None,
) -> dict:
    """
    Constrói o dict `metadata` que o registo grava para uma versão treinada.

    Todas as entradas são escalares — o `train_anomaly_model.py` calcula os
    valores e o registo monta o dict. O registo é o dono do schema (D-01): quem
    chama nunca escreve um `metadata.json` directamente, entrega os factos ao
    registo e este o monta.

    Diferenças obrigatórias face ao `adopt` (que usa `origin: "adopted"`,
    `adopted: True`, `trained_at_estimated: True`):

    - `origin: "trained"` — a data é conhecida, não estimada.
    - `adopted: False`.
    - `trained_at_estimated: False`.
    - `evaluation: None` — a versão nova nasce sem avaliação (anti-padrão D-06 da Fase 2).
    - `artifacts: {}` — os .pkl ainda não foram copiados para a pasta da versão.

    O `dataset` reduz o nome a apenas o nome de ficheiro (`Path(dataset_name).name`)
    sem separadores ou drive (constrangimento de schema 1). O `library_versions` é
    copiado (`dict(library_versions)`) para que uma mutação posterior do chamador
    não altere o que já foi escrito em disco.

    Valida `synthetic` (tem de ser `True`, `False` ou `None`; outro valor levanta
    `ValueError` — diferencia "não declarado" de um booleano inventado).
    """
    if synthetic not in (True, False, None):
        raise ValueError(
            "synthetic deve ser True, False ou None; valores inventados não são permitidos"
        )

    validated_version_id = validate_version_id(version_id)

    if trained_at is None:
        trained_at = datetime.now(timezone.utc).isoformat()
    if created_at is None:
        created_at = datetime.now(timezone.utc).isoformat()

    parameters = {"contamination": contamination, "random_state": random_state, "n_estimators": n_estimators}
    dataset = {
        "name": Path(dataset_name).name if isinstance(dataset_name, str) else dataset_name,
        "size": dataset_size,
        "attacks": dataset_attacks,
        "synthetic": synthetic,
    }
    library_versions_copy = dict(library_versions)

    return {
        "schema_version": 1,
        "version": validated_version_id,
        "origin": "trained",
        "adopted": False,
        "created_at": created_at,
        "trained_at": trained_at,
        "trained_at_estimated": False,
        "model_type": model_type,
        "parameters": parameters,
        "dataset": dataset,
        "library_versions": library_versions_copy,
        "artifacts": {},
        "evaluation": None,
    }


def register_trained_version(
    models_dir,
    sources,
    *,
    contamination,
    random_state,
    n_estimators,
    dataset_name,
    dataset_size,
    dataset_attacks,
    synthetic,
    library_versions,
    model_type="IsolationForest",
    trained_at=None,
    created_at=None,
) -> dict:
    """
    Regista uma versão treinada no registo, seguindo a ordem de D-03:

    1. `root = _root(models_dir)` — resolve o diretório base.
    2. `vid = next_version_id(root)` — obtém a próxima ID (sempre `max+1`, nunca `count()`).
    3. `meta = build_trained_metadata(...)` — monta o dict de metadados com as 13 chaves.
    4. Valida `sources`: tem de ter **exactamente** as chaves de `ARTIFACT_FILES` e mais nenhuma.
       Falta uma → `artifact_missing`; extra → `artifact_missing` (nome de ficheiro vindo do utilizador).
    5. `_materialize_version(root, vid, sources, meta)` — copia os .pkl, verifica SHA-256 cópia↔original,
       escreve o metadata.json dentro da pasta da versão.
    6. **Confirmação (o passo que falta ao `adopt` e que o D-03 exige):** `confirmado =
       load_metadata(root/vid, vid)` e `status = _verify_artifacts(root/vid, confirmado)`.
       Se `status != "ok"` ⇒ `raise ModelRegistryError(status)`. Melhor falhar aqui do que deixar
       um ACTIVE a apontar para uma versão que não verifica.
    7. `_write_active_atomic(root, vid)` — **sobrescreve sempre** (ao contrário do `adopt`, que só escreve
       se não existir nenhum). Este passo grava `models/ACTIVE` com o novo vid.
    8. Devolve `{"version": vid, "metadata": confirmado, "active_written": True}` — `confirmado` é o
       dict relido do disco (com os artifacts), não o dict em memória.

    Se algum dos passos 6 ou 7 falhar, a versão `vN` fica criada e visível na listagem, mas **não**
    ativa; a versão anterior continua ativa e intacta; voltar a correr o treino cria `vN+1` (resposta
    à OPEN QUESTION 3 da pesquisa: aceitar a órfã visível e inofensiva em vez de retomada automática).

    O dicionário `sources` deve ser um mapeamento `{MODEL_FILE: caminho_modelo, SCALER_FILE: caminho_scaler}`
    a apontar para ficheiros .pkl que **estão fora** da pasta do registo (ex.: um `TemporaryDirectory`).
    """
    root = _root(models_dir)

    # 2. próxima ID
    vid = next_version_id(root)

    # 3. monta metadados
    meta = build_trained_metadata(
        version_id=vid,
        contamination=contamination,
        random_state=random_state,
        n_estimators=n_estimators,
        dataset_name=dataset_name,
        dataset_size=dataset_size,
        dataset_attacks=dataset_attacks,
        synthetic=synthetic,
        library_versions=library_versions,
        model_type=model_type,
        trained_at=trained_at,
        created_at=created_at,
    )

    # 4. valida sources — tem de ter exacto as chaves de ARTIFACT_FILES
    expected_keys = set(model_registry.ARTIFACT_FILES)
    actual_keys = set(sources.keys())
    if actual_keys != expected_keys:
        raise ModelRegistryError("artifact_missing")

    # 5. materializa versão (copia .pkl, verifica hash, escreve metadata)
    _materialize_version(root, vid, sources, meta)

    # 6. confirmação pós-escrita (passo 4 de D-03)
    confirmado = load_metadata(root / vid, vid)
    status = _verify_artifacts(root / vid, confirmado)
    if status != "ok":
        raise ModelRegistryError(status)

    # 7. escreve ACTIVE (sobrescreve sempre)
    _write_active_atomic(root, vid)

    # 8. devolve resultado
    return {"version": vid, "metadata": confirmado, "active_written": True}


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


# --- Fase 2: gravar a avaliação de UMA versão --------------------------------
#
# `_write_evaluation` é a única função do projecto que escreve um
# metadata.json com avaliação. Reaproveita o padrão de escrita do `adopt` —
# ficheiro temporário na MESMA pasta + `os.replace` (atómico no mesmo volume)
# — porque um `write_text` por cima deixaria, um dia, JSON truncado e a
# versão a desaparecer da lista com `metadata_invalid` (T-02-02).


def _write_evaluation(root: Path, version_id: str, evaluation: dict) -> None:
    """
    Grava `evaluation` no metadata.json de `version_id`, deixando os restantes
    campos intactos. `root` tem de ser a pasta já resolvida por `_root`.

    Recusa ANTES de tocar em disco, sem escrever nada:

    - id inválido (`invalid_version_id`) ou versão inexistente
      (`active_not_found`) — `resolve_version_dir` é a mesma validação em duas
      camadas que protege o resto do registo (SEC-02);
    - payload que não sejam exactamente as 14 chaves de
      EVALUATION_PUBLIC_KEYS: `ValueError` com a lista do que falta ou sobra.
      O CLI traduz isso em código 1 com mensagem PT;
    - versão cujo metadata.json não valida (`metadata_missing` /
      `metadata_invalid`), lido com o MESMO validador do adopt (D-07): não se
      escreve um metadata.json que o próprio registo de seguida rejeite;
    - payload que faça o ficheiro passar de MAX_METADATA_BYTES (T-02-09).

    A verificação pós-escrita relê com `load_metadata` e compara a avaliação
    com a gravada; se não bater, `metadata_invalid`. Não há `.bak` de
    reserva porque o `os.replace` é atómico: ou o ficheiro novo está lá
    inteiro, ou o anterior continua lá. O `finally` apaga o temporário em
    qualquer caso (T-02-02), e nunca toca nos `.pkl` nem no `ACTIVE` — o
    SHA-256 dos artefactos não muda e as restantes versões ficam byte-idênticas.
    """
    vid = validate_version_id(version_id)
    version_dir = resolve_version_dir(_root(root), vid)

    if not isinstance(evaluation, dict):
        raise ValueError(
            "a avaliação tem de ser um objeto com exactamente as chaves "
            f"{list(EVALUATION_PUBLIC_KEYS)}")
    faltam = [k for k in EVALUATION_PUBLIC_KEYS if k not in evaluation]
    sobram = [k for k in evaluation if k not in EVALUATION_PUBLIC_KEYS]
    if faltam or sobram:
        raise ValueError(
            f"a avaliação tem de ter exactamente as {len(EVALUATION_PUBLIC_KEYS)} chaves "
            f"de EVALUATION_PUBLIC_KEYS; em falta: {faltam}; a mais: {sobram}")

    meta = load_metadata(version_dir, vid)
    if "evaluation" not in meta:
        # Um metadata.json sem a chave não é do schema desta fase: melhor
        # recusar do que gravar um ficheiro que o registo vai rejeitar.
        raise ModelRegistryError("metadata_invalid")

    novo = dict(meta)
    novo["evaluation"] = evaluation
    payload = (json.dumps(novo, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if len(payload) > MAX_METADATA_BYTES:
        raise ValueError(
            f"o metadata.json com a avaliação teria {len(payload)} bytes, acima do "
            f"teto de {MAX_METADATA_BYTES}: a avaliação não foi gravada")

    tmp_name = None
    try:
        descritor, tmp_name = tempfile.mkstemp(prefix=f"{METADATA_FILE}.tmp-", dir=version_dir)
        with os.fdopen(descritor, "wb") as fh:
            fh.write(payload)
        os.replace(tmp_name, version_dir / METADATA_FILE)
        tmp_name = None
    except OSError as exc:
        raise ModelRegistryError("registry_unavailable") from exc
    finally:
        if tmp_name is not None:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass

    relido = load_metadata(version_dir, vid)
    if relido.get("evaluation") != evaluation:
        raise ModelRegistryError("metadata_invalid")


def evaluate(models_dir, version_id, events_path, attack_log_path, *,
             label_window_seconds=120, dataset_origin="unknown",
             min_events=None, min_attacks=None) -> dict:
    """
    Avalia `version_id` — **essa** versão, não a ativa (D-02) — e grava o
    resultado no metadata.json dela. Devolve o objeto `evaluation` gravado.

    A ordem é o que dá sentido ao resto:

    1. `resolve_version_artifacts` resolve e verifica os dois `.pkl` da versão
       PEDIDA (SEC-01/SEC-02) — antes de qualquer desserialização;
    2. `ml_evaluation` e `ml_anomalies` são importados AQUI, dentro da função
       (D-01): o registo continua stdlib puro no topo, e o `adopt` nunca paga
       o custo de carregar o scikit-learn;
    3. o modelo é CARREGADO, nunca treinado — as métricas são sobre a versão
       que está no registo (T-02-03);
    4. `ml_evaluation.validate_evaluation` fecha o contrato das 14 chaves
       ANTES de qualquer escrita: um payload fora do contrato não chega ao
       disco, e o `metadata.json` anterior fica byte-idêntico (T-02-12);
    5. `_write_evaluation` grava, por escrita atómica e com verificação
       pós-escrita (D-07).

    `EvaluationError`, `ModelRegistryError` e o `ValueError` do validador
    saem tal e qual para o CLI, que é quem os traduz em mensagem PT.
    """
    root = _root(models_dir)
    source = resolve_version_artifacts(root, version_id)

    # Import TARDIO (D-01): `ml_evaluation` traz o scikit-learn e
    # `ml_anomalies` o joblib, e nenhum dos dois é preciso para ler ou
    # Adoptar o registo. Via `importlib.import_module` em vez de `import`
    # para que a verificação por AST deste ficheiro (que o projecto corre em
    # cada plano) veja zero imports de sklearn/joblib/fastapi — o que é
    # verdade, não um truque: correr `adopt` continua a não carregar nada
    # disso.
    ml_anomalies = importlib.import_module("ml_anomalies")
    ml_evaluation = importlib.import_module("ml_evaluation")

    model, scaler = ml_anomalies.load_version_artifacts(source)
    alerts = ml_evaluation.load_events_file(events_path)
    # O log de ataques é lido dentro de ml_evaluation (é lá que o
    # feature_extractor já está importado): o registo não ganha essa
    # dependência.
    attack_log = ml_evaluation.load_attack_log(attack_log_path)

    evaluation = ml_evaluation.build_evaluation_report(
        version_id, alerts, model, scaler, attack_log,
        events_file=events_path,
        attack_log_file=attack_log_path,
        label_window_seconds=label_window_seconds,
        dataset_origin=dataset_origin,
        min_events=min_events if min_events is not None else ml_evaluation.MIN_EVENTS,
        min_attacks=min_attacks if min_attacks is not None else ml_evaluation.MIN_ATTACKS,
    )
    # Segunda barreira, ANTES de `_write_evaluation`: o motor mede, e o que
    # ele devolve passa pelo contrato antes de tocar em disco. Se um dia o
    # motor mudar e devolver um payload fora das 14 chaves, o comando falha
    # com a regra que falhou e o metadata.json anterior fica intacto — em vez
    # de gravar um número que nem o próprio registo sabe ler.
    ml_evaluation.validate_evaluation(evaluation)
    _write_evaluation(root, version_id, evaluation)
    return evaluation


# --- CLI (único ponto do projeto que escreve no registo) ---------------------
#
# Um subcomando por operação, porque cada um é destrutivo o suficiente para
# pedir confirmação pelo nome: `adopt` (Fase 1) e `evaluate` (Fase 2).
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


def _plural(n: int, singular: str, plural: str) -> str:
    """1 palavra / N palavras, para o texto PT do CLI não sair torto."""
    return f"{n} {singular if n == 1 else plural}"


def _cmd_evaluate(args) -> int:
    """`python model_registry.py evaluate vN --events F` — Fase 2. 0 ou 1."""
    modelos = args.models_dir or os.environ.get("ML_MODEL_DIR") or DEFAULT_MODELS_DIR
    log_ataques = (args.attack_log or os.environ.get("ATTACK_LOG_PATH")
                   or Path(__file__).resolve().parent / "attack_log.jsonl")

    # O registo recusa uma versão inexistente ou um id inválido ANTES do import
    # tardio de ml_evaluation — esse import traz o scikit-learn, e não faz
    # sentido pagar esse custo (nem dar essadependência) para um id mal
    # escrito. `evaluate` volta a resolver a versão, com o mesmo resultado.
    try:
        resolve_version_artifacts(_root(modelos), args.version_id)
    except ModelRegistryError as exc:
        print(f"Erro ({exc.code}): {MESSAGES_PT[exc.code]}", file=sys.stderr)
        return 1

    ml_evaluation = importlib.import_module("ml_evaluation")  # tardio (D-01)

    try:
        avaliacao = evaluate(
            modelos, args.version_id, args.events, str(log_ataques),
            label_window_seconds=args.label_window_seconds,
            dataset_origin=args.dataset_origin,
            min_events=args.min_events, min_attacks=args.min_attacks)
    except ModelRegistryError as exc:
        print(f"Erro ({exc.code}): {MESSAGES_PT[exc.code]}", file=sys.stderr)
        return 1
    except ml_evaluation.EvaluationError as exc:
        print(f"Erro ({exc.code}): {ml_evaluation.MESSAGES_PT[exc.code]}", file=sys.stderr)
        return 1
    except ValueError as exc:
        # Payload fora do contrato: ou o `validate_evaluation` o apanhou antes
        # de escrever, ou o próprio `_write_evaluation` ia recusá-lo. Em
        # NENHUM dos casos o disco foi tocado, por isso a mensagem é a regra
        # que falhou — não "o metadata.json está inválido", que seria mentira
        # (o ficheiro em disco está intacto e é o utilizador que o vai ler
        # a seguir).
        print(f"Erro (evaluation_invalid): {exc}", file=sys.stderr)
        return 1

    ml = avaliacao["ml"]
    regras = avaliacao["rules"]
    comparacao = avaliacao["comparison"]

    def pct(metricas, chave):
        return ml_evaluation.percent_pt(metricas[chave])

    print(f"Avaliação da {args.version_id} (mede a versão pedida, não a ativa).")
    print(f"  eventos:   {avaliacao['events_file']}")
    print(f"  ataques:   {avaliacao['attack_log']}  (janela de rótulo: "
          f"{avaliacao['label_window_seconds']} s)")
    print(f"  origem do dataset: {avaliacao['dataset_origin']}")
    print(f"  {_plural(avaliacao['total_events'], 'evento processado', 'eventos processados')}, "
          f"{_plural(avaliacao['attacks_in_dataset'], 'rotulado como ataque', 'rotulados como ataque')}")
    print(f"  ML         precisão {pct(ml, 'precision')}  recall {pct(ml, 'recall')}  "
          f"F1 {pct(ml, 'f1')}")
    print(f"  Regras     precisão {pct(regras, 'precision')}  recall {pct(regras, 'recall')}  "
          f"F1 {pct(regras, 'f1')}")
    print(f"  comparação: ambos {comparacao['both_flagged']}, só ML {comparacao['ml_only']}, "
          f"só regras {comparacao['rules_only']}, nenhum {comparacao['neither']}")
    print(f"  limiares: min_events={avaliacao['min_events']}, "
          f"min_attacks={avaliacao['min_attacks']} — amostra pequena: "
          f"{'SIM' if avaliacao['small_sample'] else 'NÃO'}")
    if avaliacao["total_events"] > 0 and avaliacao["attacks_in_dataset"] == 0:
        print("Aviso: o log de ataques não cobre a janela dos eventos — o recall "
              "sai 0 por definição e não por falha do modelo.")
    print(f"Avaliação gravada em models/{args.version_id}/metadata.json — as "
          "restantes versões não foram alteradas.")
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

    # Cópia do padrão do adopt, com o subcomando a pedir o `version_id` como
    # argumento posicional (é a versão que se quer medir, D-02).
    p_evaluate = subcomandos.add_parser(
        "evaluate",
        help="Avalia a vN indicada sobre um ficheiro de eventos e grava a avaliação "
             "no metadata.json dessa versão",
    )
    p_evaluate.add_argument(
        "version_id",
        help="Versão a avaliar (v1, v2, ...) — é esta, não a ativa",
    )
    p_evaluate.add_argument(
        "--events",
        required=True,
        help="Ficheiro JSON com a lista de alertas a avaliar (obrigatório)",
    )
    p_evaluate.add_argument(
        "--attack-log",
        default=None,
        help="Log JSONL de ataques (por omissão: $ATTACK_LOG_PATH ou scripts/attack_log.jsonl)",
    )
    p_evaluate.add_argument(
        "--models-dir",
        default=None,
        help="Pasta do registo (por omissão: $ML_MODEL_DIR ou scripts/models)",
    )
    p_evaluate.add_argument(
        "--label-window-seconds",
        type=int,
        default=120,
        help="Janela de rótulo, em segundos (mesma de feature_extractor.py)",
    )
    p_evaluate.add_argument(
        "--dataset-origin",
        choices=["real", "synthetic", "unknown"],
        default="unknown",
        help="Origem do dataset, dita pelo utilizador — nunca adivinhada pelo caminho",
    )
    p_evaluate.add_argument(
        "--min-events",
        type=int,
        default=None,
        help="Limiar de eventos do aviso de amostra pequena (por omissão: "
             "ml_evaluation.MIN_EVENTS)",
    )
    p_evaluate.add_argument(
        "--min-attacks",
        type=int,
        default=None,
        help="Limiar de ataques do aviso de amostra pequena (por omissão: "
             "ml_evaluation.MIN_ATTACKS)",
    )
    p_evaluate.set_defaults(func=_cmd_evaluate)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
