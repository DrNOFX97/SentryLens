"""
Motor de treino do SentryLens: treina um IsolationForest a partir de um
export do Indexer, regista-o no registo de versões com a proveniência do
lote, activa-o e recarrega a cache do modelo.

Existe porque `main.py` dizia (até 2026-10-11) que treinar, adoptar e activar
são operações de CLI e nunca por HTTP. A decisão D-01 inverteu isso, com
quatro protecções obrigatórias; este módulo é a primeira delas e a mais
importante:

  **Nenhum caminho pode vir do pedido.** `train_next_version` não tem
  `sources`, não tem `dataset_path`, não tem `url`: o `dataset` escolhe
  DENTRO de um conjunto fechado no servidor (`ML_EXPORT_DIR` /
  `REQUESTED_EXPORT`, resolvidos aqui), o registo vem sempre de
  `ML_MODEL_DIR`/`DEFAULT_MODELS_DIR` e os dois `.pkl` nascem num
  `tempfile.TemporaryDirectory` do sistema, apagado no `finally`.

  Isto não é prudência estilística. `register_trained_version` aceita `sources`
  de qualquer caminho do host (`model_registry.py`) e o `evaluate` desserializa
  esses ficheiros com `joblib.load` — que é `pickle.load`. Aceitar `.pkl`
  escolhidos pelo corpo do pedido é execução de código remota com a API key.
  Por isso `sources` é montado AQUI, a partir de `ARTIFACT_FILES`, e não é
  parâmetro de lado nenhum.

Três limites honestos, para que ninguém leia isto como mais do que é:

  1. Quem tem a API key passa a ter escrita em `models/` — o que torna o
     SHA-256 dos `.pkl` um detector de corrupção, não uma defesa. E é o que D-08
     obriga a REESCREVER em `docs/SECURITY.md`, não a anotar.
  2. O `model_registry` continua a ser o dono do schema do `metadata.json`.
     Este módulo entrega factos escalares; quem monta o dict é o registo.
  3. `feature_stats` descreve o LOTE, não o modelo (D-03). Ver a função.

Registo stdlib puro no topo, por contrato (gate por AST): `joblib`, `sklearn`,
`fastapi`, `model_registry`, `ml_anomalies`, `train_anomaly_model` e
`feature_extractor` entram todos por `importlib.import_module` dentro das
funções, no mesmo caminho que o `evaluate` do registo usa. Assim importar este
módulo num contexto sem scikit-learn não rebenta — e o teste da prova negativa
(`prova_negativa_de_imports`) mede exactamente isso.
"""

import importlib
import json
import os
import re
import statistics
import tempfile
from pathlib import Path

# Prefixo do temporário de joblib.dump. Distinto do `sentrylens-train-` do CLI
# (model_registry._cmd_train) para que a contagem de sobras de um não pode ser
# confundida com a do outro: um teste que apanhasse o lixo do CLI a chamaria
# de bug deste módulo.
TEMP_PREFIX = "sentrylens-treino-"

# Nomes que o `export_raw_events.unique_output_path` produz:
# `YYYY-MM-DD_HH-MM.json`, com sufixo `_2`, `_3`, ... em colisão
# (export_raw_events.py:208-212). Qualquer outro nome na pasta não é um export
# — é ignorado, em vez de ser treinado por acidente.
#
# Os dois grupos existem para uma coisa: o primeiro decide se o nome É de um
# export, o segundo ordena. `unique_output_path` gera `HH-MM` e o sufixo é um
# contador decimal, pelo que a ordenação tem de ser por (carimbo, sufixo
# inteiro) — ver `resolve_export_path`.
EXPORT_NAME_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}_\d{2}-\d{2})(?:_(\d+))?\.json$")

# Teto de leitura do dataset. O MESMO teto de `ml_evaluation.MAX_EVENTS_BYTES`
# (8 MB): um ficheiro maior é quase sempre o ficheiro errado (T-02-09).
MAX_EVENTS_BYTES = 8 * 1024 * 1024

# Teto de documentos de um export — o mesmo de `export_raw_events.MAX_DOCUMENTS`
# e o mesmo que `/api/ml-anomalies` pede ao Indexer. É o que torna
# `dataset.truncated` verificável: um ficheiro com 1000 documentos pode ter
# sido cortado, um com 999 não.
MAX_DOCUMENTS = 1000

# Pasta por omissão dos exports. `DEFAULT_MODELS_DIR` NÃO é redefinido aqui: o
# registo é o dono desse valor e este módulo vai buscá-lo por import tardio,
# para que haja uma única fonte (o mesmo cuidado de `library_versions_pt`).
DEFAULT_EXPORT_DIR = Path(__file__).resolve().parent / "snapshots"

# Comprimento máximo aceite num `@timestamp` para entrar na janela do dataset.
# O registo recusa um texto acima de DATASET_TEXT_LIMIT (200) com ValueError, e
# um ValueError a meio de um treino é pior do que uma janela desconhecida: um
# `@timestamp` de 4 KB é um campo do atacante, não uma data.
MAX_TIMESTAMP_LEN = 64

# Lista NOVA e separada: `model_registry.ERROR_CODES` (D-06) não ganha chaves,
# e nenhum destes quatro entra na API de listagem de versões. Mesmo padrão de
# `ml_evaluation.EVALUATION_ERROR_CODES`.
TRAINING_ERROR_CODES = (
    "dataset_not_found",
    "dataset_unusable",
    "training_in_progress",
    "training_failed",
)

# As duas escolhas de dataset que o servidor faz em nome do cliente. O pedido
# HTTP escolhe uma destas — um `Literal` de um catálogo fechado — e nunca um
# caminho (D-01.4).
DATASET_CHOICES = ("latest_export", "sample_fixture")


class TrainingError(Exception):
    """
    Erro do motor de treino com um código estável, pela mesma convenção do
    `ModelRegistryError` e do `EvaluationError`: `str(exc)` é exactamente o
    código, nunca uma mensagem nem um caminho. É uma lista NOVA e separada —
    `ERROR_CODES` do registo (D-06) não ganha chaves.
    """

    def __init__(self, code):
        if code not in TRAINING_ERROR_CODES:
            raise ValueError(f"código de erro fora de TRAINING_ERROR_CODES: {code!r}")
        self.code = code
        super().__init__(code)


# --- O dataset: de onde vem, e nunca de fora ------------------------------------


def read_events_file(path) -> list[dict]:
    """
    Lê o ficheiro de eventos e devolve a lista TAL E QUAL — o documento bruto
    chega intacto ao `extract_features`, que é o único que sabe o que é um
    alerta válido. Não normaliza, não preenche, não descarta.

    Recusa, sem treinar e sem escrever nada: ficheiro inexistente ou ilegível,
    JSON inválido, um JSON que não seja lista, uma lista com um elemento que
    não seja `dict`, e ficheiro acima de MAX_EVENTS_BYTES. Todas com
    `dataset_unusable` — são o mesmo sintoma do ponto de vista de quem pede o
    treino ("isto não é um dataset utilizável") e um código a menos para a
    fronteira HTTP traduzir.
    """
    alvo = Path(path)
    try:
        if alvo.stat().st_size > MAX_EVENTS_BYTES:
            raise TrainingError("dataset_unusable")
        with open(alvo, encoding="utf-8") as handle:
            documentos = json.load(handle)
    except TrainingError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TrainingError("dataset_unusable") from exc

    if not isinstance(documentos, list):
        raise TrainingError("dataset_unusable")
    for doc in documentos:
        if not isinstance(doc, dict):
            raise TrainingError("dataset_unusable")
    return documentos


def resolve_export_path(dataset: str = "latest_export") -> Path:
    """
    O ficheiro de eventos do treino. É o ÚNICO lugar do projecto onde se decide
    de onde vem o dataset — e por isso que nenhum caminho precisa de vir do
    pedido (D-01.1).

    Ordem:

    - `sample_fixture` -> `train_anomaly_model.DEFAULT_EVENTS_PATH`, e acabou.
      O `ML_EXPORT_DIR` é ignorado por INTEIRO: o fixture é um conjunto
      versionado no repositório, e um export real a meio não pode mudar o que
      "treinar com o fixture" significa.
    - `REQUESTED_EXPORT` do ambiente, se existir e for um ficheiro;
    - senão, o export mais recente em `ML_EXPORT_DIR` (ou `DEFAULT_EXPORT_DIR`);
    - senão `dataset_not_found`, sem escrever nada.

    "Mais recente" é o ÚLTIMO em ordenação por `(carimbo, sufixo)`, e o
    carimbo é cronológico porque `unique_output_path` gera `YYYY-MM-DD_HH-MM`
    com dois dígitos — nesse formato, ordenar o texto é ordenar o relógio.

    O sufixo é ordena como **inteiro**, não como texto. O plano 10-02 mandava
    "ordena lexicograficamente", e isso é verdade para `_2`/`_3` ( porque `.`
    (0x2E) ordena antes de `_` (0x5F), logo `09-00.json` < `09-00_2.json`) mas
    é FALSO a partir do décimo export no mesmo minuto: em texto,
    `09-00_10.json` < `09-00_2.json`, e o "mais recente" saía errado em
    silêncio — treinar o modelo sobre o export errado. Medido em
    `test_ml_training.py` secção 2, checks (d) e (e).

    Um valor desconhecido é `dataset_not_found` (fail-closed): é melhor um
    dataset inexistente do que um dataset que ninguém pediu.
    """
    if dataset not in DATASET_CHOICES:
        raise TrainingError("dataset_not_found")

    if dataset == "sample_fixture":
        return Path(importlib.import_module("train_anomaly_model").DEFAULT_EVENTS_PATH)

    pedido = os.environ.get("REQUESTED_EXPORT")
    if pedido:
        caminho = Path(pedido)
        if caminho.is_file():
            return caminho

    pasta = Path(os.environ.get("ML_EXPORT_DIR") or DEFAULT_EXPORT_DIR)
    encontrados = []
    try:
        for candidato in pasta.iterdir():
            if not candidato.is_file():
                continue
            casa = EXPORT_NAME_RE.match(candidato.name)
            if casa is None:
                continue
            encontrados.append(((casa.group(1), int(casa.group(2) or 1)), candidato))
    except OSError as exc:
        raise TrainingError("dataset_not_found") from exc
    if not encontrados:
        raise TrainingError("dataset_not_found")
    return max(encontrados, key=lambda par: par[0])[1]


def resolve_attack_log_path(dataset: str = "latest_export") -> Path:
    """
    O log JSONL de ataques, pela mesma resolução de
    `ml_evaluation.events_path_por_omissao`: `ATTACK_LOG_PATH` do ambiente ou
    `scripts/attack_log.jsonl`. `sample_fixture` devolve o fixture versionado.

    Não levanta `dataset_not_found` se o ficheiro não existir: é o log de
    ataques do utilizador, que pode legitimamente não existir num treino de
    demonstração — `feature_extractor.load_attack_log` devolve lista vazia e
    o lote sai com `attacks: 0`, que é a verdade.
    """
    if dataset == "sample_fixture":
        return Path(importlib.import_module("train_anomaly_model").DEFAULT_ATTACK_LOG_PATH)
    return Path(os.environ.get("ATTACK_LOG_PATH")
                or (Path(__file__).resolve().parent / "attack_log.jsonl"))


# --- Os factos do lote (D-02/D-03) ---------------------------------------------


def _janela(documentos) -> tuple[str | None, str | None]:
    """
    O `@timestamp` mais antigo e mais recente do ficheiro, como texto.

    Ordena lexicograficamente, que para ISO-8601 UTC com sufixo `Z` é o mesmo
    que ordenar por data — o mesmo pressuposto de
    `export_raw_events.describe_events`. Um carimbo que não seja texto, ou que
    passe MAX_TIMESTAMP_LEN, é ignorado em vez de entrar: `window_first` é um
    facto, não um eco do que o Indexer mandou.
    """
    carimbos = sorted(
        selo for selo in
        (doc.get("@timestamp") for doc in documentos if isinstance(doc, dict))
        if isinstance(selo, str) and selo.strip() and len(selo) <= MAX_TIMESTAMP_LEN
    )
    if not carimbos:
        return None, None
    return carimbos[0], carimbos[-1]


def dataset_facts(documentos, rows) -> dict:
    """
    Os factos de D-02, e só factos — quem os mete no `metadata.json` é o
    registo, que continua a ser o dono do schema (D-01.1).

        documents      quantos documentos o ficheiro tinha;
        processable    quantos deles o `extract_features` transformou em
                       linhas (timestamp + Event ID válidos);
        size           o MESMO `processable` — as duas chaves coexistem
                       porque `size` é o que o frontend já lia, e mudá-lo
                       seria partir o `mlmDatasetHtml` sem ganho;
        attacks        quantas linhas ficaram rotuladas como ataque, pelo log
                       declarado e nunca inferido;
        truncated      `documents >= MAX_DOCUMENTS`: o exportador nunca
                       escreveu mais do que o teto, logo um ficheiro no teto
                       PODE estar cortado e um abaixo do teto não está. É o
                       que distingue "35 eventos de 500" de "35 de 35";
        window_first /
        window_last    a janela realmente coberta, ou None se o ficheiro não
                       tiver um único `@timestamp` utilizável.

    `attack_log` não entra aqui (o plano 10-02 passava-o): o rótulo
    `is_attack` já está em cada linha depois de `label_with_attack_log`, e
    contar o log outra vez seria um segundo sítio onde o número do ataque é
    decidido — que é exactamente o tipo de divergência silenciosa que D-04 veio
    eliminar no catálogo.
    """
    janela_inicio, janela_fim = _janela(documentos)
    processable = len(rows)
    return {
        "documents": len(documentos),
        "processable": processable,
        "size": processable,
        "attacks": sum(1 for row in rows if row.get("is_attack")),
        "truncated": len(documentos) >= MAX_DOCUMENTS,
        "window_first": janela_inicio,
        "window_last": janela_fim,
    }


def feature_stats(vectors) -> dict:
    """
    Média e desvio **populacional** (`statistics.pstdev`) de cada uma das 7
    features, NO LOTE DE TREINO (D-03), com `round(x, 6)`.

    As chaves são exactamente as de `feature_extractor.FEATURE_NAMES`, nessa
    ordem — o registo não pode importar o extractor para as conferir, e a
    igualdade é presa por um teste.

    O skew NÃO foi corrigido, de propósito: `is_new_source_ip` e
    `failed_attempts_last_hour` acumulam DENTRO do lote
    (`feature_extractor.py:124-131`), pelo que o mesmo evento muda de feature
    em ~9,6% dos casos conforme o lote que o acompanha, e ~8,7% dos eventos
    mudam de veredicto só por isso. Mexer no `feature_extractor` parte o
    contrato partilhado com a inferência e invalida todos os `.pkl` em disco.
    Em vez de corrigir, este módulo **declara**: estes números descrevem o
    lote, não o comportamento do modelo, e a aba Evaluation tem de dizer isso.

    Um lote vazio devolve as 7 features a média 0 e desvio 0. Isso NÃO é um
    evento com média zero: é "não havia linhas", e o `metadata.json` diz
    `documents: 0` ao lado. Um `None` aqui seria lido como "não medido", que
    é mentira — foi medido, sobre nada.
    """
    nomes = importlib.import_module("feature_extractor").FEATURE_NAMES
    if not vectors:
        return {nome: {"mean": 0.0, "std": 0.0} for nome in nomes}

    resumo = {}
    for indice, nome in enumerate(nomes):
        coluna = [float(linha[indice]) for linha in vectors]
        resumo[nome] = {
            "mean": round(statistics.fmean(coluna), 6),
            "std": round(statistics.pstdev(coluna), 6),
        }
    return resumo


# --- O único joblib.dump do projecto ---------------------------------------------


def dump_artifacts(model, scaler, out_dir) -> dict[str, str]:
    """
    Grava os dois `.pkl` em `out_dir` e devolve o mapeamento
    `{ARTIFACT_FILES[0]: caminho, ARTIFACT_FILES[1]: caminho}` para o
    `register_trained_version`.

    É o ÚNICO `joblib.dump` do projecto (contagem por AST: exactamente 1, neste
    ficheiro) e vive aqui, e não em `train_anomaly_model`, por uma razão
    concreta: é este módulo que sabe que o destino tem de estar FORA do registo
    e tem de ser um temporário. `train_anomaly_model.save_model` sobrevive e
    delega aqui; o `_cmd_train` do registo também.

    Os nomes são os de `model_registry.ARTIFACT_FILES` — a lista fechada — e não
    duas strings escritas à mão: um `.pkl` novo no registo aparece aqui sem que
    ninguém se lembre de o escrever (o mesmo motivo de `catalog_sha256` medir
    `_EVENT_ID_ORDER` em vez de uma cópia). Se a lista deixar de bater, é
    `training_failed` — fail-closed, nunca um `KeyError` a meio de um dump.
    """
    registo = importlib.import_module("model_registry")
    if set(registo.ARTIFACT_FILES) != {registo.MODEL_FILE, registo.SCALER_FILE}:
        raise TrainingError("training_failed")

    joblib = importlib.import_module("joblib")
    objetos = {registo.MODEL_FILE: model, registo.SCALER_FILE: scaler}
    destino = Path(out_dir)
    destino.mkdir(parents=True, exist_ok=True)

    sources = {}
    for nome in registo.ARTIFACT_FILES:
        alvo = destino / nome
        joblib.dump(objetos[nome], alvo)
        sources[nome] = str(alvo)
    return sources


# --- O treino --------------------------------------------------------------------


def build_training_rows(documentos, attack_log_path) -> tuple[list[dict], list[list[float]]]:
    """
    Transforma documentos já lidos em linhas rotuladas e em vectores.

    `(rows, vectors)`, com `vectors` na ordem de `FEATURE_NAMES` — a única
    ordem que o modelo e o scaler podem ver.

    É a MESMA função para o CLI (`model_registry._cmd_train`) e para a API
    (`train_next_version`), e é pública por isso: dois sítios onde "um documento
    vira uma linha treinável" pudessem divergir é o tipo de coisa que faz o
    treino e a inferência deixarem de falar a mesma língua — o que
    `feature_extractor` partilhado existe para evitar.

    `train_anomaly_model.load_dataset` faz a mesma composição a partir de um
    CAMINHO; aqui os documentos já foram lidos e validados por
    `read_events_file`, e reler 8 MB para os deitar fora seria o caminho lento
    e sem a barreira do teto de tamanho.
    """
    feature_extractor = importlib.import_module("feature_extractor")
    rotulo = feature_extractor.label_with_attack_log(
        feature_extractor.extract_features(documentos),
        feature_extractor.load_attack_log(str(attack_log_path)),
    )
    return rotulo, feature_extractor.vectorize(rotulo)


def train_next_version(
    models_dir=None,
    events_path=None,
    attack_log_path=None,
    *,
    contamination=0.2,
    random_state=42,
    n_estimators=200,
    dataset_origin="unknown",
) -> dict:
    """
    Treina, regista, activa e recarrega a cache. Devolve o estado final.

    **A ASSINATURA É A PROVA DE D-01.** Repare no que NÃO está aqui: `sources`,
    `pkl`, `dataset_path`, `url`, um `models_dir` vindo do pedido. Os `.pkl` que
    o registo vai verificar e copiar nascem num `TemporaryDirectory` deste
    processo e os nomes vêm de `ARTIFACT_FILES`. Isto não é prudência
    estilística: `register_trained_version` aceita `sources` de qualquer
    caminho do host e o `evaluate` desserializa-os com `joblib.load`, que é
    `pickle.load` — aceitar `.pkl` escolhidos pelo corpo do pedido é execução
    de código com a API key (T-10-09).

    `events_path`/`attack_log_path` existem, mas são **opcionais e resolvidos
    pelo servidor**: `main.py` (plano 10-03) é que os resolve com
    `resolve_export_path(dataset)` a partir de um `Literal`, e passa. Se
    chegarem `None`, esta função resolve sozinha — o que torna impossível um
    pedido chegar aqui com um caminho, porque o caminho já teria de ter sido
    decidido antes de chamar.

    `models_dir=None` resolve por `ML_MODEL_DIR` e depois
    `model_registry.DEFAULT_MODELS_DIR`, **nunca** pelo cwd.

    Ordem dentro do motor — e a ordem É o contrato:

        treinar -> register_trained_version (escreve ACTIVE)
                -> reset_cache -> load_model

    Se o `load_model` viesse antes do registo, ou o `reset_cache` depois do
    `load_model`, o backend anunciaria `active: vN` a servir `v(N-1)`. O
    `ACTIVE` aponta para o que foi mesmo carregado, ou o processo volta a ficar
    com a cache vazia — nunca a meio.

    Levanta `TrainingError` (código estável, sem caminho em `str(exc)`) e
    `ModelRegistryError` do registo. Não apanha `KeyboardInterrupt`: propaga,
    e o `with` limpa o temporário na mesma.
    """
    registo = importlib.import_module("model_registry")
    ml_evaluation = importlib.import_module("ml_evaluation")
    if dataset_origin not in ml_evaluation.DATASET_ORIGINS:
        raise ValueError(f"dataset_origin fora de DATASET_ORIGINS: {dataset_origin!r}")

    # Fora do lock, de propósito: ler um ficheiro é rápido e não é o recurso a
    # proteger. O que se protege é `models/`, e é por isso que o 409 é sobre o
    # treino e não sobre a leitura.
    eventos = Path(events_path) if events_path else resolve_export_path("latest_export")
    log_ataques = (Path(attack_log_path) if attack_log_path
                   else resolve_attack_log_path("latest_export"))
    documentos = read_events_file(eventos)

    root = registo._root(models_dir or os.environ.get("ML_MODEL_DIR"))
    # O registo pode não existir ainda (primeiro treino numa máquina nova).
    # `register_trained_version` faz `os.replace` de pasta e recusa se o
    # destino não existir, portanto quem cria é aqui: a falha vem ANTES de
    # gastar segundos de CPU, e é `registry_unavailable` — nada mais.
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise registo.ModelRegistryError("registry_unavailable") from exc

    rows, vectors = build_training_rows(documentos, log_ataques)
    if not vectors:
        raise TrainingError("dataset_unusable")

    model, scaler = importlib.import_module("train_anomaly_model").train_model(
        vectors,
        contamination=contamination,
        random_state=random_state,
        n_estimators=n_estimators,
    )

    factos = dataset_facts(documentos, rows)
    with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as temporario:
        sources = dump_artifacts(model, scaler, temporario)
        registado = registo.register_trained_version(
            root,
            sources,
            contamination=contamination,
            random_state=random_state,
            n_estimators=n_estimators,
            dataset_name=Path(eventos).name,
            dataset_size=factos["size"],
            dataset_attacks=factos["attacks"],
            # Tri-estado, nunca booleano: `dataset.synthetic` distingue
            # "sintético" de "real" de "não declarado". Com `== "synthetic"`
            # o default `unknown` cairia em `False`, e um treino sobre o
            # fixture sintético ficaria atestado como dados reais (T-10-16).
            synthetic={"synthetic": True, "real": False}.get(dataset_origin),
            library_versions=registo.library_versions_pt(),
            dataset_documents=factos["documents"],
            dataset_processable=factos["processable"],
            dataset_truncated=factos["truncated"],
            dataset_window_first=factos["window_first"],
            dataset_window_last=factos["window_last"],
            feature_stats=feature_stats(vectors),
            catalog_sha256=registo.catalog_sha256(),
        )

    ml_anomalies = importlib.import_module("ml_anomalies")
    # `reset_cache` ANTES de `load_model`, e os dois depois do registo: é esta
    # ordem que impede o backend de anunciar `active: vN` a servir `v(N-1)`.
    ml_anomalies.reset_cache()
    ml_anomalies.load_model(str(root))

    meta = registado["metadata"]
    return {
        "version": registado["version"],
        "active": registo.read_active(root),
        "loaded": ml_anomalies.loaded_version(),
        "dataset": meta["dataset"],
        "parameters": meta["parameters"],
        # A versão NASCE sem avaliação (EVAL-03): um treino não publica
        # métricas sobre o próprio conjunto de treino como se fossem uma
        # avaliação. Quem avalia é o `model_registry evaluate vN`.
        "evaluation": None,
        "catalog_sha256": meta["catalog_sha256"],
    }