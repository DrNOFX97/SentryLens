"""
Suite do motor de treino (`scripts/ml_training.py`), plano 10-02 do R10.

Standalone, sem pytest, com a convenção do resto do projecto: `check()` imprime
`[OK   ]`/`[FALHOU]` e `sys.exit(1)` se houver uma única falha.

NADA AQUI TOCA `scripts/models/`. Todos os cenários de treino, de registo e de
activação correm em `tempfile.TemporaryDirectory()`; os únicos ficheiros reais
que este teste lê são os fixtures versionados (`sample_events_real.json`,
`sample_attack_log.jsonl`) e o catálogo de features. O guard explícito de que o
disco do utilizador fica intacto é o de `test_export_raw_events.py`, que entra
na suite como gate.

A ordem das secções é CONTRATO, não conveniência:

  1. `prova_negativa_de_imports` tem de ser a PRIMEIRA, porque prova que
     `ml_training` é stdlib puro no topo. Se outra secção a corresse primeiro e
     tivesse importado scikit-learn, `sys.modules` viria sujo e a prova não
     provaria nada.
  2. As secções que treinam a sério vêm antes das que remexem na cache de
     `ml_anomalies`, para que uma cache suja não possa fazer a secção seguinte
     passar.

Cada `def secao_*` é chamada pelo `run()` através de `SECOES`. Uma secção que
ninguém chama não está testada: a lista `SECOES` é a que conta.
"""

import ast
import contextlib
import glob
import importlib
import inspect
import json
import os
import re
import statistics
import sys
import tempfile
import threading
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import ml_training  # noqa: E402 — o ponto é poder importá-lo já, sem scikit-learn
import model_registry  # noqa: E402
from feature_extractor import (  # noqa: E402
    FEATURE_NAMES,
    extract_features,
    label_with_attack_log,
    load_attack_log,
    vectorize,
)

FIXTURE_EVENTOS = SCRIPT_DIR / "sample_events_real.json"
FIXTURE_LOG = SCRIPT_DIR / "sample_attack_log.jsonl"

# "C:" no início de um valor seria um caminho de drive a vazar (o mesmo
# DRIVE_RE de test_ml_models_api.py:48). Aqui a lista é maior: o R10 diz que
# NENHUM caminho sai do motor, nem com separadores.
DRIVE_RE = re.compile(r"^[A-Za-z]:")

# Nomes que NUNCA podem aparecer na assinatura de `train_next_version` (D-01.1).
NOMES_PROIBIDOS = {
    "sources", "artifacts", "pkl", "model_path", "scaler_path", "dataset_path",
    "upload", "url", "output", "output_dir", "target", "registry", "pasta",
}

# O que a assinatura tem de ser, exactamente e por ordem. Fixar a assinatura
# inteira — e não só os nomes proibidos — é o que impede alguém de acrescentar
# um `path` "inofensivo" amanhã sem que o gate diga nada.
ASSINATURA_ESPERADA = (
    "models_dir", "events_path", "attack_log_path",
    "contamination", "random_state", "n_estimators", "dataset_origin",
)

TOPO_ESPERADO = {"contextlib", "importlib", "json", "os", "pathlib", "re",
                 "statistics", "tempfile", "threading"}

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def secao(titulo: str) -> None:
    print(f"\n--- {titulo} ---")


# --- Utilitários ----------------------------------------------------------------


def modulos_de(modulo) -> set[str]:
    """Nomes de tudo o que o ficheiro carrega (provas negativas)."""
    return set(getattr(modulo, "__dict__", {})) | {
        valor.__name__ for valor in vars(modulo).values()
        if type(valor).__name__ == "module" and hasattr(valor, "__name__")
    }


def codigo_de(fn) -> str | None:
    """O código de um `TrainingError`, ou uma marca se não foi um `TrainingError`."""
    try:
        fn()
    except ml_training.TrainingError as exc:
        return exc.code
    except Exception as exc:  # noqa: BLE001
        return f"nao-training-error:{type(exc).__name__}"
    return None


def codigo_do_registro(fn) -> str | None:
    try:
        fn()
    except model_registry.ModelRegistryError as exc:
        return exc.code
    except Exception as exc:  # noqa: BLE001
        return f"nao-registry-error:{type(exc).__name__}"
    return None


@contextlib.contextmanager
def substituido(alvo, **atributos):
    """Substitui atributos de um módulo e RESTAURA tudo no `finally`.

    `ml_anomalies._model`/`_scaler`/`_loaded_from` são globais de módulo e
    `train_anomaly_model.train_model` é o ponto de treino do projecto: uma fuga
    aqui contamina a suite inteira em vez de um teste.
    """
    originais = {nome: getattr(alvo, nome) for nome in atributos}
    try:
        for nome, valor in atributos.items():
            setattr(alvo, nome, valor)
        yield
    finally:
        for nome, valor in originais.items():
            setattr(alvo, nome, valor)


@contextlib.contextmanager
def ambiente(**variaveis):
    """`os.environ` temporário, restaurado no `finally` — incluindo o que não
    estava lá antes (uma chave ausente tem de voltar a estar ausente)."""
    anteriores = {nome: os.environ.get(nome) for nome in variaveis}
    try:
        for nome, valor in variaveis.items():
            if valor is None:
                os.environ.pop(nome, None)
            else:
                os.environ[nome] = valor
        yield
    finally:
        for nome, valor in anteriores.items():
            if valor is None:
                os.environ.pop(nome, None)
            else:
                os.environ[nome] = valor


@contextlib.contextmanager
def ml_anomalies_intacto():
    """Guarda e restaura as três funções de `ml_anomalies` que o motor chama, e
    deixa a cache vazia à saída."""
    modulo = importlib.import_module("ml_anomalies")
    originais = {nome: getattr(modulo, nome)
                 for nome in ("load_model", "reset_cache", "loaded_version")}
    try:
        yield modulo
    finally:
        for nome, valor in originais.items():
            setattr(modulo, nome, valor)
        modulo.reset_cache()


class Gate:
    """Um `threading.Event` com verbos em português, para que os testes se leiam
    como português em vez de repetir o par `set()`/`clear()`."""

    def __init__(self) -> None:
        self.evento = threading.Event()

    def entrar(self) -> None:
        self.evento.set()

    def esperar(self, timeout: float = 60) -> bool:
        return self.evento.wait(timeout)


def correr_com_collected(fn) -> list:
    """Corre `fn` numa thread e devolve as excepções que ela levantou.

    `daemon=True` e um `join(timeout)` limitado: uma thread que fique pendurada
    é devolvida como `TimeoutError` e transformada num `[FALHOU]` pelo `check` de
    quem chama. Um teste de concorrência que fica pendurado é PIOR do que um
    teste que não existe — passava a custar o timeout de 300 s do
    `run_all_tests.py` a todos os outros ficheiros.
    """
    capturadas: list = []

    def embrulhado():
        try:
            fn()
        except BaseException as exc:  # noqa: BLE001 — quero o objecto
            capturadas.append(exc)

    thread = threading.Thread(target=embrulhado, daemon=True)
    thread.start()
    thread.join(60)
    if thread.is_alive():
        capturadas.append(TimeoutError("thread pendurada"))
    return capturadas


def listagem(pasta) -> list[str]:
    return sorted(p.name for p in Path(pasta).iterdir())


def sobras_temporarias() -> list[str]:
    return sorted(glob.glob(str(Path(tempfile.gettempdir())
                              / f"{ml_training.TEMP_PREFIX}*")))


def documentos_do_fixture() -> list[dict]:
    return json.loads(FIXTURE_EVENTOS.read_text(encoding="utf-8"))


def documentos_falsos(quantos: int, timestamp="2026-10-01T08:00:00Z") -> list[dict]:
    """Documentos com a forma mínima que o `extract_features` aceita."""
    return [{"@timestamp": timestamp, "data": {"win": {"system": {"eventID": "4625"}}}}
            for _ in range(quantos)]


def escrever_eventos(destino: Path, documentos: list) -> Path:
    destino.parent.mkdir(parents=True, exist_ok=True)
    destino.write_text(json.dumps(documentos, ensure_ascii=False), encoding="utf-8")
    return destino


def linhas_independentes(documentos: list[dict], log: Path) -> list[dict]:
    """O que o teste espera, calculado SEM `ml_training`: o `feature_extractor`
    aplicado à mão ao ficheiro. É a única forma de o `dataset_facts` não se
    validar a si próprio."""
    return label_with_attack_log(extract_features(documentos),
                                 load_attack_log(str(log)))


def caminhos_em(valor) -> list[str]:
    """Todos os valores de texto que parecem um caminho, num objecto qualquer."""
    achados: list[str] = []
    if isinstance(valor, dict):
        for item in valor.values():
            achados.extend(caminhos_em(item))
    elif isinstance(valor, (list, tuple)):
        for item in valor:
            achados.extend(caminhos_em(item))
    elif isinstance(valor, str):
        if DRIVE_RE.match(valor) or "\\" in valor or "/" in valor:
            achados.append(valor)
    return achados


class ContadorJoblib:
    """Embraça `joblib.load` para contar chamadas (copiado de
    `test_ml_models_api.ContadorJoblib`). A propriedade que se prova é negativa:
    com um `.pkl` adulterado o contador tem de ficar a 0 — nada não verificado
    chega ao desserializador (SEC-01)."""

    def __init__(self, joblib_real) -> None:
        self._real = joblib_real
        self.chamadas = 0

    def load(self, *args, **kwargs):
        self.chamadas += 1
        return self._real.load(*args, **kwargs)

    def __getattr__(self, nome):
        return getattr(self._real, nome)


# --- 1. Prova negativa de imports ------------------------------------------------


def prova_negativa_de_imports() -> None:
    secao("1. ml_training e stdlib puro no topo (gate por AST + prova negativa)")

    arvore = ast.parse((SCRIPT_DIR / "ml_training.py").read_text(encoding="utf-8"))
    topo = {alias.name.split(".")[0] for node in ast.walk(arvore)
            if isinstance(node, ast.Import) for alias in node.names}
    topo |= {(node.module or "").split(".")[0] for node in ast.walk(arvore)
             if isinstance(node, ast.ImportFrom)}
    check(f"(a) o topo é exactamente {sorted(TOPO_ESPERADO)}", topo == TOPO_ESPERADO)
    check("(b) nenhum dos proibidos (joblib/sklearn/fastapi/ml_anomalies/"
          "train_anomaly_model/model_registry/feature_extractor) no topo",
          not (topo & {"joblib", "sklearn", "fastapi", "ml_anomalies",
                       "train_anomaly_model", "model_registry", "feature_extractor"}))

    carregados = modulos_de(ml_training)
    check("(c) train_model não está no namespace de ml_training",
          "train_model" not in carregados)
    for nome in ("sklearn", "joblib", "fastapi", "ml_anomalies",
                 "train_anomaly_model", "model_registry", "feature_extractor"):
        check(f"(d) ml_training não carregou {nome}", nome not in carregados)

    # A prova mais forte: nada de scikit-learn no INTERPRETE. Este ficheiro
    # importa ml_training, model_registry e feature_extractor no topo — se
    # alguém acrescentar `import joblib` a ml_training, isto falha mesmo que o
    # check (d) passasse por o módulo estar já carregado por outra via.
    check("(e) scikit-learn ainda não foi importado por ninguém",
          "sklearn" not in sys.modules)
    check("(f) joblib também não", "joblib" not in sys.modules)

    check("(g) TRAINING_ERROR_CODES tem as 4 chaves pela ordem do plano",
          ml_training.TRAINING_ERROR_CODES == (
              "dataset_not_found", "dataset_unusable",
              "training_in_progress", "training_failed"))
    check("(h) ERROR_CODES do registo continua com 9 chaves (D-06)",
          len(model_registry.ERROR_CODES) == 9)
    check("(i) e nenhum dos 4 códigos de treino entrou em ERROR_CODES",
          not (set(ml_training.TRAINING_ERROR_CODES) & set(model_registry.ERROR_CODES)))


# --- 2. resolve_export_path ------------------------------------------------------


def secao_resolve_export_path() -> None:
    secao("2. resolve_export_path: o unico sitio que decide de onde vem o dataset")

    with tempfile.TemporaryDirectory() as tmp:
        raiz = Path(tmp)

        with ambiente(ML_EXPORT_DIR=str(raiz / "nao-existe"), REQUESTED_EXPORT=None):
            codigo = codigo_de(lambda: ml_training.resolve_export_path("latest_export"))
        check("(a) pasta inexistente -> dataset_not_found", codigo == "dataset_not_found")

        vazia = raiz / "vazia"
        vazia.mkdir()
        with ambiente(ML_EXPORT_DIR=str(vazia), REQUESTED_EXPORT=None):
            codigo = codigo_de(lambda: ml_training.resolve_export_path("latest_export"))
        check("(b) pasta vazia -> dataset_not_found", codigo == "dataset_not_found")

        (vazia / "qualquer.json").write_text("[]", encoding="utf-8")
        (vazia / "real_events_2026-10-01.json").write_text("[]", encoding="utf-8")
        with ambiente(ML_EXPORT_DIR=str(vazia), REQUESTED_EXPORT=None):
            codigo = codigo_de(lambda: ml_training.resolve_export_path("latest_export"))
        check("(c) ficheiros fora do padrão são ignorados -> dataset_not_found",
              codigo == "dataset_not_found")

        pasta = raiz / "exports"
        pasta.mkdir()
        for nome in ("2026-10-11_09-00.json", "2026-10-11_09-00_2.json",
                     "2026-10-11_09-00_10.json", "2026-10-10_23-59.json"):
            (pasta / nome).write_text("[]", encoding="utf-8")
        with ambiente(ML_EXPORT_DIR=str(pasta), REQUESTED_EXPORT=None):
            escolhido = ml_training.resolve_export_path("latest_export")
        check("(d) o sufixo ordena como o relógio: o export _10 (décimo do "
              "minuto) ganha a _2, e hoje ganha a ontem",
              escolhido.name == "2026-10-11_09-00_10.json")
        check("(d) e em texto puro seria o contrário — daí o sufixo ser "
              "inteiro", sorted(p.name for p in pasta.iterdir())[-1]
              == "2026-10-11_09-00_2.json")

        (pasta / "2026-10-12_00-00.json").mkdir()
        with ambiente(ML_EXPORT_DIR=str(pasta), REQUESTED_EXPORT=None):
            escolhido = ml_training.resolve_export_path("latest_export")
        check("(e) um directório com nome de export é ignorado",
              escolhido.name == "2026-10-11_09-00_10.json")

        pedido = escrever_eventos(raiz / "pedido.json", documentos_falsos(2))
        with ambiente(ML_EXPORT_DIR=str(pasta), REQUESTED_EXPORT=str(pedido)):
            escolhido = ml_training.resolve_export_path("latest_export")
        check("(f) REQUESTED_EXPORT ganha ao ML_EXPORT_DIR", escolhido == pedido)

        with ambiente(ML_EXPORT_DIR=str(pasta), REQUESTED_EXPORT=str(raiz / "fantasma.json")):
            escolhido = ml_training.resolve_export_path("latest_export")
        check("(g) REQUESTED_EXPORT inexistente cai na pasta", escolhido.parent == pasta)

        with ambiente(ML_EXPORT_DIR=str(pasta), REQUESTED_EXPORT=str(pedido)):
            escolhido = ml_training.resolve_export_path("sample_fixture")
        check("(h) sample_fixture devolve o fixture versionado e ignora um "
              "export real à espera",
              escolhido == FIXTURE_EVENTOS and escolhido != pedido)

        with ambiente(ML_EXPORT_DIR=str(pasta), REQUESTED_EXPORT=None):
            codigo1 = codigo_de(lambda: ml_training.resolve_export_path("/etc/passwd"))
            codigo2 = codigo_de(lambda: ml_training.resolve_export_path("../../../etc"))
        check("(i) um caminho como valor de dataset -> dataset_not_found "
              "(fail-closed)", codigo1 == "dataset_not_found"
              and codigo2 == "dataset_not_found")

        with ambiente(ATTACK_LOG_PATH=None):
            check("(j) o log por omissão é scripts/attack_log.jsonl",
                  ml_training.resolve_attack_log_path() == SCRIPT_DIR / "attack_log.jsonl")
        with ambiente(ATTACK_LOG_PATH=str(raiz / "log.jsonl")):
            check("(j) ATTACK_LOG_PATH do ambiente ganha",
                  ml_training.resolve_attack_log_path() == raiz / "log.jsonl")
        check("(j) sample_fixture devolve o log versionado",
              ml_training.resolve_attack_log_path("sample_fixture") == FIXTURE_LOG)


# --- 3. read_events_file ---------------------------------------------------------


def secao_leitura_do_dataset() -> None:
    secao("3. read_events_file: forma e tamanho, antes de qualquer treino")

    with tempfile.TemporaryDirectory() as tmp:
        raiz = Path(tmp)
        bons = escrever_eventos(raiz / "bons.json", documentos_falsos(3))
        check("(a) um ficheiro válido volta TAL E QUAL (nada é normalizado)",
              ml_training.read_events_file(bons) == documentos_falsos(3))

        casos = {
            "inexistente.json": None,
            "invalido.json": "{isto não é json",
            "nao_lista.json": '{"um": "objeto"}',
            "lista_de_strings.json": '["a", "b"]',
            "misturado.json": '[{"a": 1}, 7]',
        }
        for nome, conteudo in casos.items():
            if conteudo is not None:
                (raiz / nome).write_text(conteudo, encoding="utf-8")
            codigo = codigo_de(lambda n=nome: ml_training.read_events_file(raiz / n))
            check(f"(b) {nome} -> dataset_unusable", codigo == "dataset_unusable")

        grande = raiz / "grande.json"
        # A barreira do tamanho é a PRIMEIRA instrução de `read_events_file`,
        # antes do `json.load` — por isso um ficheiro que nem sequer é JSON
        # válido serve para a provar, e é o que a prova.
        with open(grande, "w", encoding="utf-8") as handle:
            handle.write("[" + "0" * (ml_training.MAX_EVENTS_BYTES + 16) + "]")
        check("(c) o ficheiro de teste passa mesmo do teto de 8 MB",
              grande.stat().st_size > ml_training.MAX_EVENTS_BYTES)
        check("(d) acima do teto -> dataset_unusable, e o JSON nem foi lido",
              codigo_de(lambda: ml_training.read_events_file(grande)) == "dataset_unusable")


# --- 4. dataset_facts (D-02) -----------------------------------------------------


def secao_factos_do_dataset() -> None:
    secao("4. dataset_facts: factos calculados, comparados com o cálculo do teste")

    documentos = documentos_do_fixture()
    linhas = linhas_independentes(documentos, FIXTURE_LOG)
    factos = ml_training.dataset_facts(documentos, linhas)

    check("(a) as chaves são exactamente as 7 do contrato",
          set(factos) == {"documents", "processable", "size", "attacks",
                           "truncated", "window_first", "window_last"})
    check(f"(b) documents == len(fixture) = {len(documentos)}",
          factos["documents"] == len(documentos))
    check(f"(c) processable == len(extract_features) = {len(linhas)}",
          factos["processable"] == len(linhas))
    check("(d) size == processable (o frontend já lia `size`)",
          factos["size"] == factos["processable"])
    ataques = sum(1 for linha in linhas if linha.get("is_attack"))
    check(f"(e) attacks == soma de is_attack = {ataques}",
          factos["attacks"] == ataques)
    carimbos = sorted(d["@timestamp"] for d in documentos)
    check(f"(f) window_first/last são os do ficheiro ({carimbos[0]} .. {carimbos[-1]})",
          factos["window_first"] == carimbos[0] and factos["window_last"] == carimbos[-1])
    check("(g) truncated False com 36 documentos de 1000",
          factos["truncated"] is False)

    truncado = ml_training.dataset_facts(documentos_falsos(ml_training.MAX_DOCUMENTS), linhas)
    check(f"(h) {ml_training.MAX_DOCUMENTS} documentos -> truncated True",
          truncado["truncated"] is True)
    check("(i) o limite é >= e não >: um ficheiro no teto PODE estar cortado",
          ml_training.dataset_facts(documentos_falsos(999), linhas)["truncated"] is False)
    check("(j) 2 documentos dos quais 1 processável: processable 1",
          ml_training.dataset_facts(
              [{"@timestamp": "2026-10-01T08:00:00Z",
                "data": {"win": {"system": {"eventID": "4625"}}}},
               {"sem": "timestamp"}], linhas[:1])["processable"] == 1)

    sem_carimbo = ml_training.dataset_facts([{"data": {}}], [])
    check("(k) sem um único @timestamp utilizável -> janela None, não 'desconhecido'",
          sem_carimbo["window_first"] is None and sem_carimbo["window_last"] is None)
    check("(l) um @timestamp de 5 KB não entra na janela",
          ml_training.dataset_facts([{"@timestamp": "x" * 5000}], [])["window_first"] is None)


# --- 5. feature_stats (D-03) -----------------------------------------------------


def secao_estatisticas_do_lote() -> None:
    secao("5. feature_stats: media e desvio populacional NO LOTE (D-03)")

    documentos = documentos_do_fixture()
    vectors = vectorize(linhas_independentes(documentos, FIXTURE_LOG))
    resumo = ml_training.feature_stats(vectors)

    check(f"(a) as chaves são exactamente as {len(FEATURE_NAMES)} de FEATURE_NAMES, "
          "por ordem", list(resumo) == list(FEATURE_NAMES))

    certo = True
    for indice, nome in enumerate(FEATURE_NAMES):
        coluna = [float(v[indice]) for v in vectors]
        esperado = {"mean": round(statistics.fmean(coluna), 6),
                    "std": round(statistics.pstdev(coluna), 6)}
        if resumo[nome] != esperado:
            certo = False
            print(f"       {nome}: {resumo[nome]} != {esperado}")
    check("(b) media e pstdev recalculadas à mão batem em todas as features", certo)
    check("(c) nenhum std negativo", all(v["std"] >= 0 for v in resumo.values()))
    check("(d) floats a sério — o registo recusa int e bool aqui",
          all(type(x) is float for v in resumo.values() for x in v.values()))

    check("(e) o mesmo lote por ordem diferente dá o mesmo mean/std",
          ml_training.feature_stats(list(reversed(vectors))) == resumo)

    vazio = ml_training.feature_stats([])
    check("(f) lote vazio -> as mesmas 7 chaves a 0.0, não None",
          list(vazio) == list(FEATURE_NAMES)
          and all(v == {"mean": 0.0, "std": 0.0} for v in vazio.values()))

    uma = ml_training.feature_stats([[1.0] * len(FEATURE_NAMES)])
    check("(g) uma única linha -> std 0.0 (o desvio de um valor, não um None)",
          all(v == {"mean": 1.0, "std": 0.0} for v in uma.values()))


# --- 6. O treino a sério ---------------------------------------------------------


def secao_treino_a_serio() -> None:
    secao("6. treino a serio: registo com proveniencia e sem nenhum caminho")

    documentos = documentos_do_fixture()
    linhas = linhas_independentes(documentos, FIXTURE_LOG)
    vectors = vectorize(linhas)
    ataques = sum(1 for linha in linhas if linha.get("is_attack"))
    antes = sobras_temporarias()

    with tempfile.TemporaryDirectory() as tmp, ml_anomalies_intacto():
        registo = Path(tmp) / "models"
        resultado = ml_training.train_next_version(
            registo, events_path=FIXTURE_EVENTOS, attack_log_path=FIXTURE_LOG,
            dataset_origin="synthetic")

        check("(a) devolve v1 activa e carregada",
              resultado["version"] == "v1" and resultado["active"] == "v1"
              and resultado["loaded"] == "v1")
        check("(b) o registo tem exactamente ACTIVE + v1", listagem(registo) == ["ACTIVE", "v1"])
        check("(c) o ACTIVE é 'v1\\n'", (registo / "ACTIVE").read_bytes() == b"v1\n")
        relatorio = model_registry.build_models_report(registo)
        check("(d) a v1 lista como status ok e catalog_compatible True",
              relatorio["versions"][0]["status"] == "ok"
              and relatorio["versions"][0]["catalog_compatible"] is True)

        meta = json.loads((registo / "v1" / "metadata.json").read_text(encoding="utf-8"))
        check(f"(e) parameters == defaults reais: {meta['parameters']}",
              meta["parameters"] == {"contamination": 0.2, "random_state": 42,
                                     "n_estimators": 200})
        check("(f) evaluation nasce None (EVAL-03: um treino não avalia-se a si)",
              meta["evaluation"] is None and resultado["evaluation"] is None)

        joblib = importlib.import_module("joblib")
        modelo = joblib.load(registo / "v1" / model_registry.MODEL_FILE)
        check("(g) T-10-08: o .pkl diz o MESMO que o metadata.json "
              f"(n_estimators={modelo.n_estimators}, random_state={modelo.random_state}, "
              f"contamination={modelo.contamination})",
              modelo.n_estimators == meta["parameters"]["n_estimators"]
              and modelo.random_state == meta["parameters"]["random_state"]
              and modelo.contamination == meta["parameters"]["contamination"])
        check("(h) e o scaler também veio do registo",
              joblib.load(registo / "v1" / model_registry.SCALER_FILE) is not None)

        dataset = meta["dataset"]
        check(f"(i) D-02: documents={dataset['documents']} processable={dataset['processable']} "
              f"attacks={dataset['attacks']} truncated={dataset['truncated']}",
              dataset["documents"] == len(documentos)
              and dataset["processable"] == len(vectors)
              and dataset["size"] == len(vectors)
              and dataset["attacks"] == ataques
              and dataset["truncated"] is False)
        check("(j) a janela é a do ficheiro, calculada pelo teste",
              dataset["window_first"] == carimbos_ordenados()[0]
              and dataset["window_last"] == carimbos_ordenados()[-1])
        check("(k) synthetic True (tri-estado, não booleano por omissão)",
              dataset["synthetic"] is True)
        check("(l) o nome é só o nome de ficheiro, sem separadores nem drive",
              dataset["name"] == "sample_events_real.json")
        check("(m) D-04: catalog_sha256 gravado == o que o registo devolve agora",
              meta["catalog_sha256"] == model_registry.catalog_sha256()
              and resultado["catalog_sha256"] == model_registry.catalog_sha256())
        check("(n) D-03: feature_stats gravado com as 7 features do lote",
              list(meta["feature_stats"]) == list(FEATURE_NAMES)
              and meta["feature_stats"] == ml_training.feature_stats(vectors))
        check(f"(o) D-01.1: nenhum caminho na resposta ({caminhos_em(resultado)})",
              caminhos_em(resultado) == [])
        check("(p) nem no metadata.json em disco", caminhos_em(meta) == [])
        check("(q) o temporário foi limpo", sobras_temporarias() == antes)
        check("(r) nenhum v1.tmp-* nem ACTIVE.tmp-* no registo",
              [n for n in listagem(registo) if ".tmp-" in n] == [])
        check("(s) os .pkl ficaram dentro de v1, não soltos no registo",
              [n for n in listagem(registo) if n.endswith(".pkl")] == [])

        # n_estimators chega ao MODELO, não só ao metadado (D-05).
        registo7 = Path(tmp) / "models7"
        resultado7 = ml_training.train_next_version(
            registo7, events_path=FIXTURE_EVENTOS, attack_log_path=FIXTURE_LOG,
            n_estimators=7, random_state=1234, contamination=0.1,
            dataset_origin="real")
        meta7 = json.loads((registo7 / "v1" / "metadata.json").read_text(encoding="utf-8"))
        modelo7 = joblib.load(registo7 / "v1" / model_registry.MODEL_FILE)
        check("(t) n_estimators=7 produz mesmo um modelo de 7 árvores",
              modelo7.n_estimators == 7 and len(modelo7.estimators_) == 7)
        check("(u) e os parameters gravados são esses mesmos",
              meta7["parameters"] == {"contamination": 0.1, "random_state": 1234,
                                      "n_estimators": 7})
        check("(v) dataset_origin=real dá synthetic False (tri-estado)",
              meta7["dataset"]["synthetic"] is False)
        check("(w) a resposta repete o que foi gravado",
              resultado7["dataset"] == meta7["dataset"]
              and resultado7["parameters"] == meta7["parameters"])

        export = escrever_eventos(Path(tmp) / "snapshots" / "2026-10-11_10-00.json",
                                  documentos_falsos(ml_training.MAX_DOCUMENTS))
        registo3 = Path(tmp) / "models3"
        resultado3 = ml_training.train_next_version(
            registo3, events_path=export, attack_log_path=FIXTURE_LOG,
            dataset_origin="real")
        meta3 = json.loads((registo3 / "v1" / "metadata.json").read_text(encoding="utf-8"))
        check("(x) 1000 documentos ficam registados como truncados=True — é isto "
              "que distingue '1000 de 1000' de '35 de 35'",
              meta3["dataset"]["documents"] == ml_training.MAX_DOCUMENTS
              and meta3["dataset"]["truncated"] is True
              and resultado3["dataset"]["truncated"] is True)

        check("(y) nada sobrou do temporário ao fim de três treinos",
              sobras_temporarias() == antes)


def carimbos_ordenados() -> list[str]:
    return sorted(d["@timestamp"] for d in documentos_do_fixture())


def secao_models_dir_sem_cwd() -> None:
    secao("7. models_dir: ML_MODEL_DIR / DEFAULT_MODELS_DIR, nunca o cwd")

    with tempfile.TemporaryDirectory() as tmp:
        raiz = Path(tmp)
        registo = raiz / "registo"
        falso = raiz / "cwd" / "models"
        (falso / "v9").mkdir(parents=True)
        cwd_original = os.getcwd()
        try:
            os.chdir(raiz / "cwd")
            with ambiente(ML_MODEL_DIR=str(registo)):
                resultado = ml_training.train_next_version(
                    events_path=FIXTURE_EVENTOS, attack_log_path=FIXTURE_LOG,
                    n_estimators=5, dataset_origin="synthetic")
        finally:
            os.chdir(cwd_original)

        check("(a) a versão nova foi para ML_MODEL_DIR",
              resultado["version"] == "v1" and listagem(registo) == ["ACTIVE", "v1"])
        check("(b) o models/ do cwd ficou só com a v9 que lá estava",
              listagem(falso) == ["v9"])
        check("(c) e não nasceu uma v10 ao lado dela", "v10" not in listagem(falso))


# --- 8. O pin de assinatura (D-01.1) --------------------------------------------


def secao_pin_de_assinatura() -> None:
    secao("8. D-01.1: a assinatura NAO aceita nenhum caminho do cliente")

    parametros = tuple(inspect.signature(ml_training.train_next_version).parameters)
    check(f"(a) a assinatura é exactamente {ASSINATURA_ESPERADA}",
          parametros == ASSINATURA_ESPERADA)
    check(f"(b) nenhum nome proibido ({sorted(set(parametros) & NOMES_PROIBIDOS)})",
          not (set(parametros) & NOMES_PROIBIDOS))
    check("(c) nenhum nome de parâmetro fala de artefactos",
          not any(parte in nome for nome in parametros
                  for parte in ("pkl", "sourc", "artifact")))

    assinatura = inspect.signature(ml_training.train_next_version).parameters
    posicionais = [n for n, p in assinatura.items()
                   if p.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD]
    so_keywords = [n for n, p in assinatura.items()
                   if p.kind is inspect.Parameter.KEYWORD_ONLY]
    check("(d) os três primeiros são posicionais e o resto keyword-only",
          posicionais == ["models_dir", "events_path", "attack_log_path"]
          and so_keywords == ["contamination", "random_state", "n_estimators",
                              "dataset_origin"])

    # A prova dinâmica: um caminho no pedido é um TypeError, não um caminho
    # aceito em silêncio. Estes são exactamente os ataques que D-01 fecha.
    ataques = {
        "sources": {"isolation_forest.pkl": "/tmp/x.pkl", "scaler.pkl": "/tmp/y.pkl"},
        "pkl": "/tmp/x.pkl",
        "dataset_path": "/tmp/eventos.json",
        "url": "http://exemplo/x.json",
        "output_dir": "/tmp/saida",
    }
    for nome, valor in ataques.items():
        try:
            ml_training.train_next_version(**{nome: valor})
            recusado, tipo = False, "nenhum"
        except TypeError:
            recusado, tipo = True, "TypeError"
        except BaseException as exc:  # noqa: BLE001
            recusado, tipo = False, type(exc).__name__
        check(f"(e) train_next_version({nome}=...) -> TypeError (veio {tipo})", recusado)

    try:
        ml_training.train_next_version("registo", "eventos.json", "log.jsonl", 0.2)
        recusado = False
    except TypeError:
        recusado = True
    check("(f) contamination por posição não é aceite (é keyword-only)", recusado)

    train_anomaly_model = importlib.import_module("train_anomaly_model")
    with tempfile.TemporaryDirectory() as tmp:
        modelo, scaler = train_anomaly_model.train_model(
            [[0.0] * len(FEATURE_NAMES), [1.0] * len(FEATURE_NAMES)], n_estimators=5)
        sources = ml_training.dump_artifacts(modelo, scaler, tmp)
        check("(g) dump_artifacts devolve exactamente as duas chaves de ARTIFACT_FILES",
              set(sources) == set(model_registry.ARTIFACT_FILES) and len(sources) == 2)
        check("(h) e os ficheiros existem com os nomes do registo",
              all(Path(c).name == nome and Path(c).is_file()
                  for nome, c in sources.items()))

    vectors = [[0.0] * len(FEATURE_NAMES), [1.0] * len(FEATURE_NAMES)]
    try:
        train_anomaly_model.train_model(vectors, 0.2, 42)
        retro = True
    except TypeError:
        retro = False
    check("(i) train_model(vectors, contamination, random_state) por posição "
          "ainda funciona — a assinatura nova não partiu os seis chamadores",
          retro)
    check("(j) e o default de n_estimators é a constante de módulo",
          inspect.signature(train_anomaly_model.train_model)
          .parameters["n_estimators"].default == train_anomaly_model.N_ESTIMATORS)


# --- 9. Os TrainingError ---------------------------------------------------------


def secao_erros_do_treino() -> None:
    secao("9. os TrainingError, cada um com o seu sintoma")

    try:
        ml_training.TrainingError("codigo-que-nao-existe")
        fora = False
    except ValueError:
        fora = True
    check("(a) um código fora da lista é ValueError, não TrainingError", fora)

    with tempfile.TemporaryDirectory() as tmp:
        raiz = Path(tmp)

        registo = raiz / "r0"
        with ambiente(ML_EXPORT_DIR=str(raiz / "sem-exports"), REQUESTED_EXPORT=None):
            codigo = codigo_de(
                lambda: ml_training.train_next_version(registo, attack_log_path=FIXTURE_LOG))
        check("(b) sem export -> dataset_not_found", codigo == "dataset_not_found")
        check("(c) e nada foi escrito no registo",
              not registo.exists() or listagem(registo) == [])

        mau = escrever_eventos(raiz / "mau.json", ["não sou um dicionário"])
        codigo = codigo_de(lambda: ml_training.train_next_version(
            raiz / "r1", events_path=mau, attack_log_path=FIXTURE_LOG))
        check("(d) ficheiro inválido -> dataset_unusable", codigo == "dataset_unusable")

        vazio = escrever_eventos(raiz / "vazio.json", [{"sem": "nada útil"}])
        codigo = codigo_de(lambda: ml_training.train_next_version(
            raiz / "r2", events_path=vazio, attack_log_path=FIXTURE_LOG))
        check("(e) documentos válidos mas ZERO linhas treináveis -> dataset_unusable",
              codigo == "dataset_unusable")

        meio = escrever_eventos(raiz / "meio.json", [
            {"@timestamp": "2026-10-01T08:00:00Z",
             "data": {"win": {"system": {"eventID": "4625"}}}},
            {"sem": "timestamp"},
        ])
        try:
            resultado = ml_training.train_next_version(
                raiz / "r3", events_path=meio, attack_log_path=FIXTURE_LOG,
                n_estimators=5, dataset_origin="real")
            ok = resultado["dataset"]["processable"] == 1
        except BaseException as exc:  # noqa: BLE001
            ok = False
            print(f"       levantou {type(exc).__name__}: {exc}")
        check("(f) 2 documentos dos quais 1 processável é um dataset utilizável", ok)

        try:
            ml_training.train_next_version(
                raiz / "r4", events_path=FIXTURE_EVENTOS, attack_log_path=FIXTURE_LOG,
                dataset_origin="inventado")
            mau2 = False
        except ValueError:
            mau2 = True
        except BaseException as exc:  # noqa: BLE001
            mau2 = False
            print(f"       dataset_origin mau levantou {type(exc).__name__}")
        check("(g) dataset_origin fora de DATASET_ORIGINS -> ValueError (T-10-16: "
              "o 'não declarado' não se decide sozinho)", mau2)

        registo_ficheiro = raiz / "sou-um-ficheiro"
        registo_ficheiro.write_text("isto é um ficheiro, não uma pasta", encoding="utf-8")
        codigo = codigo_do_registro(lambda: ml_training.train_next_version(
            registo_ficheiro, events_path=FIXTURE_EVENTOS, attack_log_path=FIXTURE_LOG,
            n_estimators=5, dataset_origin="synthetic"))
        check("(h) models/ a ser um ficheiro -> registry_unavailable ANTES de treinar",
              codigo == "registry_unavailable")


# --- 10. Single-flight (D-01.2) --------------------------------------------------


def secao_single_flight() -> None:
    secao("10. single-flight: um treino de cada vez, e o perdedor não escreve nada")

    check("(a) TRAIN_LOCK é um threading.Lock",
          isinstance(ml_training.TRAIN_LOCK, type(threading.Lock())))
    check("(b) busy() é um bool e começa a False",
          ml_training.busy() is False and isinstance(ml_training.busy(), bool))

    train_anomaly_model = importlib.import_module("train_anomaly_model")
    # O `train_model` VERDADEIRO, guardado ANTES da substituição. Chamar
    # `train_anomaly_model.train_model` de dentro do substituto seria recursão
    # infinita — e foi exactamente o que aconteceu na primeira versão deste
    # ficheiro.
    train_model_real = train_anomaly_model.train_model

    with tempfile.TemporaryDirectory() as tmp, ml_anomalies_intacto():
        registo = Path(tmp) / "models"
        chegou = Gate()
        liberta = Gate()
        erro_a: list = []
        erro_b: list = []
        resultado_a: list = []

        def train_model_bloqueado(vectors, contamination=0.2, random_state=42, *, n_estimators=200):
            """O `train_model` verdadeiro, preso a meio no `Event`.

            Chamar `train_anomaly_model.train_model` de dentro do substituto
            seria recursão infinita — foi o que aconteceu na primeira versão
            deste ficheiro, e o sintoma (RecursionError na thread A) é o que
            denuncia um substituto mal escrito."""
            chegou.entrar()
            if not liberta.esperar(45):
                raise TimeoutError("o gate de A nunca foi libertado")
            return train_model_real(vectors, contamination=contamination,
                                    random_state=random_state, n_estimators=n_estimators)

        def thread_a():
            try:
                resultado_a.append(ml_training.train_next_version(
                    registo, events_path=FIXTURE_EVENTOS, attack_log_path=FIXTURE_LOG,
                    n_estimators=5, dataset_origin="synthetic"))
            except BaseException as exc:  # noqa: BLE001 — medido no check (j)
                erro_a.append(exc)

        def thread_b():
            try:
                ml_training.train_next_version(
                    registo, events_path=FIXTURE_EVENTOS, attack_log_path=FIXTURE_LOG,
                    n_estimators=5, dataset_origin="synthetic")
            except BaseException as exc:  # noqa: BLE001
                erro_b.append(exc)

        with substituido(train_anomaly_model, train_model=train_model_bloqueado):
            # A entra primeiro e fica presa dentro do `_slot()`.
            ta = threading.Thread(target=thread_a, daemon=True)
            ta.start()
            chegou.esperar(30)
            check("(c) A chegou ao ponto de treino e está a segurar o slot",
                  chegou.esperar(0) and ml_training.busy() is True)

            tb = threading.Thread(target=thread_b, daemon=True)
            tb.start()
            tb.join(30)
            check("(d) B não ficou pendurada — um teste de concorrência "
                  "pendurado custa o timeout de 300 s a toda a suite",
                  not tb.is_alive())
            check(f"(e) B recebeu EXACTAMENTE um training_in_progress (recebeu "
                  f"{[getattr(e, 'code', e) for e in erro_b]})",
                  len(erro_b) == 1 and str(erro_b[0]) == "training_in_progress")
            check("(f) e foi um TrainingError a sério — é o que a rota traduz "
                  "em 409",
                  all(isinstance(e, ml_training.TrainingError) for e in erro_b))
            check(f"(g) e nada foi escrito em models/ por B: {listagem(registo)}",
                  listagem(registo) == [])
            check("(h) e o ACTIVE ainda não existe", not (registo / "ACTIVE").exists())

            liberta.entrar()
            ta.join(45)
            check("(i) A também não ficou pendurada", not ta.is_alive())

        check("(j) A não levantou nada", erro_a == [])
        check("(k) busy() voltou a False depois do treino", ml_training.busy() is False)
        check("(l) A acabou com a v1 e o registo tem ACTIVE + v1",
              bool(resultado_a) and resultado_a[0]["version"] == "v1"
              and listagem(registo) == ["ACTIVE", "v1"])

    # Se a _claim não existisse, o passo (e) acima falhava — mas um teste que
    # passa sem a protecção não prova nada, por isso este segundo cenário:
    # com o motor livre, um segundo treino SEGUINTE tem de correr normal. É o
    # que apanha um `_BUSY` que ficou a True para sempre.
    with tempfile.TemporaryDirectory() as tmp, ml_anomalies_intacto():
        registo = Path(tmp) / "models"
        resultados: list = []

        def primeiro():
            resultados.append(ml_training.train_next_version(
                registo, events_path=FIXTURE_EVENTOS, attack_log_path=FIXTURE_LOG,
                n_estimators=5, dataset_origin="synthetic"))

        penduradas = correr_com_collected(primeiro)
        check("(m) o cenário de recuperação não teve excepções",
              penduradas == [] and bool(resultados))
        check("(n) e o registo ficou com a v1 activa",
              bool(resultados) and resultados[0]["active"] == "v1"
              and listagem(registo) == ["ACTIVE", "v1"])

        # E um segundo treino a seguir ao primeiro: o lock é LIBERTADO, não
        # só exigido uma vez. Um `_BUSY` que fique a True para sempre apanha
        # aqui, e não num pedido de produção.
        segredos = correr_com_collected(primeiro)
        check("(o) dois treinos em sequência: v1 e depois v2",
              segredos == [] and len(resultados) == 2
              and resultados[1]["version"] == "v2"
              and listagem(registo) == ["ACTIVE", "v1", "v2"])


# --- 11. A ordem register -> reset_cache -> load_model ----------------------------


def secao_ordem_da_cache() -> None:
    secao("11. a ordem register -> reset_cache -> load_model, por instrumentacao")

    with tempfile.TemporaryDirectory() as tmp, ml_anomalies_intacto() as ml_anomalies:
        registo = Path(tmp) / "models"
        chamadas: list[str] = []
        activo_durante_o_load: list = []
        # Os verdadeiros, antes de substituir — chamar `ml_anomalies.reset_cache`
        # de dentro do substituto seria recursão infinita.
        reset_real = ml_anomalies.reset_cache
        load_real = ml_anomalies.load_model

        def reset_instrumentado():
            chamadas.append("reset_cache")
            return reset_real()

        def load_instrumentado(model_dir=None):
            chamadas.append("load_model")
            # Fotografia do disco de dentro do load: se o ACTIVE ainda não
            # apontasse para a vN, o backend anunciaria `active: vN` a servir
            # outra coisa. Prova a ordem sem ler código-fonte.
            try:
                activo_durante_o_load.append(
                    (Path(model_dir) / "ACTIVE").read_text(encoding="utf-8").strip())
            except OSError:
                activo_durante_o_load.append(None)
            return load_real(model_dir)

        with substituido(ml_anomalies, reset_cache=reset_instrumentado,
                         load_model=load_instrumentado):
            resultado = ml_training.train_next_version(
                registo, events_path=FIXTURE_EVENTOS, attack_log_path=FIXTURE_LOG,
                n_estimators=5, dataset_origin="synthetic")

        check(f"(a) a sequência instrumentada é {chamadas}",
              chamadas == ["reset_cache", "load_model"])
        check(f"(b) e o ACTIVE já era vN quando o load aconteceu "
              f"({activo_durante_o_load})", activo_durante_o_load == ["v1"])
        check("(c) loaded == active == v1: o backend não anuncia o que não serve",
              resultado["loaded"] == "v1" == resultado["active"])

        registo2 = Path(tmp) / "models2"
        with substituido(ml_anomalies, load_model=_levanta_hash_mismatch):
            codigo = codigo_do_registro(lambda: ml_training.train_next_version(
                registo2, events_path=FIXTURE_EVENTOS, attack_log_path=FIXTURE_LOG,
                n_estimators=5, dataset_origin="synthetic"))
        check("(d) um load_model que falha propaga o erro do registo",
              codigo == "hash_mismatch")
        check("(e) e a cache fica VAZIA — nunca um `loaded` a mentir",
              ml_anomalies.loaded_version() is None)
        check("(f) sem litter de temporário no registo",
              [n for n in listagem(registo2) if ".tmp-" in n] == [])
        check("(g) e a versão registada continua listável — o registo é o dono "
              "do schema e não se desfaz por o carregamento ter falhado",
              [v["id"] for v in model_registry.build_models_report(registo2)["versions"]]
              == ["v1"])


def _levanta_hash_mismatch(model_dir=None):
    raise model_registry.ModelRegistryError("hash_mismatch")


# --- 12. activate_version --------------------------------------------------------


def secao_activate_version() -> None:
    secao("12. activate_version: o ACTIVE só muda depois de os .pkl fazerem sentido")

    joblib = importlib.import_module("joblib")

    with tempfile.TemporaryDirectory() as tmp, ml_anomalies_intacto() as ml_anomalies:
        registo = Path(tmp) / "models"
        for _ in range(2):
            ml_training.train_next_version(
                registo, events_path=FIXTURE_EVENTOS, attack_log_path=FIXTURE_LOG,
                n_estimators=5, dataset_origin="synthetic")
        check("(a) duas versões, com a v2 activa",
              listagem(registo) == ["ACTIVE", "v1", "v2"])

        anterior = ml_training.activate_version(registo, "v1")
        check("(b) activar a v1 devolve version/previous/loaded",
              anterior["version"] == "v1" and anterior["previous"] == "v2"
              and anterior["loaded"] == "v1")
        check("(c) o ACTIVE mudou e a cache seguiu, sem reiniciar o backend",
              (registo / "ACTIVE").read_text(encoding="utf-8").strip() == "v1"
              and ml_anomalies.loaded_version() == "v1")

        activos_antes = (registo / "ACTIVE").read_bytes()
        for mau in ("../x", "v1\n", "V1", "", "v12345", None, 7):
            codigo = codigo_do_registro(
                lambda m=mau: ml_training.activate_version(registo, m))
            check(f"(d) activate_version({mau!r}) -> invalid_version_id",
                  codigo == "invalid_version_id")
        check("(e) e nenhum deles tocou no ACTIVE",
              (registo / "ACTIVE").read_bytes() == activos_antes)

        codigo = codigo_do_registro(lambda: ml_training.activate_version(registo, "v9"))
        check("(f) v9 inexistente -> active_not_found", codigo == "active_not_found")

        ml_training.activate_version(registo, "v2")
        v1 = registo / "v1" / model_registry.MODEL_FILE
        v1.write_bytes(v1.read_bytes() + b"\x00")
        contador = ContadorJoblib(joblib)
        with substituido(ml_anomalies, joblib=contador):
            codigo = codigo_do_registro(lambda: ml_training.activate_version(registo, "v1"))
        check("(g) .pkl adulterado -> hash_mismatch", codigo == "hash_mismatch")
        check("(h) e ZERO chamadas a joblib.load: nada não verificado é "
              "desserializado", contador.chamadas == 0)
        check("(i) o ACTIVE continua na v2 e a cache não mudou",
              (registo / "ACTIVE").read_text(encoding="utf-8").strip() == "v2"
              and ml_anomalies.loaded_version() == "v2")

        antes_active = (registo / "ACTIVE").read_bytes()
        # A v2 e não a v1: a v1 ficou com o `.pkl` adulterado em (g), e a
        # verificação de integridade vem ANTES do compare-and-set — activar a
        # v1 aqui daria `hash_mismatch` e nunca chegaria ao CAS.
        with substituido(model_registry, _write_active_atomic=lambda *a, **k: False):
            codigo = codigo_de(lambda: ml_training.activate_version(registo, "v2"))
        check("(j) compare-and-set perdido -> training_failed", codigo == "training_failed")
        check("(j) e o ACTIVE ficou byte a byte igual",
              (registo / "ACTIVE").read_bytes() == antes_active)

        # Activate também toma o lock: treinar e activar nunca ao mesmo tempo.
        registo4 = Path(tmp) / "models4"
        ml_training.train_next_version(
            registo4, events_path=FIXTURE_EVENTOS, attack_log_path=FIXTURE_LOG,
            n_estimators=5, dataset_origin="synthetic")
        segurou = Gate()
        liberta4 = Gate()

        def write_bloqueado(*_a, **_k):
            segurou.entrar()
            liberta4.esperar(45)
            return True

        erro_t: list = []
        with substituido(model_registry, _write_active_atomic=write_bloqueado):
            ta = threading.Thread(
                target=lambda: erro_t.extend(correr_com_collected(
                    lambda: ml_training.activate_version(registo4, "v1"))),
                daemon=True)
            ta.start()
            segurou.esperar(30)
            codigo = codigo_de(lambda: ml_training.train_next_version(
                Path(tmp) / "models5", events_path=FIXTURE_EVENTOS,
                attack_log_path=FIXTURE_LOG, n_estimators=5, dataset_origin="synthetic"))
            liberta4.entrar()
            ta.join(45)
        check("(k) enquanto uma activação está no ar, um treino leva "
              f"training_in_progress (code={codigo})",
              codigo == "training_in_progress" and not ta.is_alive())


# --- 13. A limpeza do temporário -------------------------------------------------


def secao_limpeza_do_temporario() -> None:
    secao("13. o temporario do joblib.dump e apagado em TODOS os caminhos")

    antes = sobras_temporarias()
    cenarios = (
        ("sucesso", None),
        ("ModelRegistryError", _levanta_registro),
        ("ValueError do registo", _levanta_value_error),
        ("KeyboardInterrupt", _levanta_keyboard_interrupt),
    )

    with tempfile.TemporaryDirectory() as tmp, ml_anomalies_intacto():
        for nome, levantador in cenarios:
            registo = Path(tmp) / nome.replace(" ", "_")

            def chamar():
                return ml_training.train_next_version(
                    registo, events_path=FIXTURE_EVENTOS, attack_log_path=FIXTURE_LOG,
                    n_estimators=5, dataset_origin="synthetic")

            if levantador is None:
                chamar()
                esperado = "sem erro"
            else:
                with substituido(model_registry, register_trained_version=levantador):
                    try:
                        chamar()
                        esperado = "sem erro"
                    except BaseException as exc:  # noqa: BLE001
                        esperado = type(exc).__name__
            check(f"(a) {nome}: o caminho foi {esperado} e o %TEMP% ficou limpo",
                  sobras_temporarias() == antes)
            check(f"(b) {nome}: o registo ficou sem lixo .tmp-*",
                  (not registo.exists())
                  or [n for n in listagem(registo) if ".tmp-" in n] == [])

        codigo = codigo_de(lambda: ml_training.train_next_version(
            Path(tmp) / "unusable",
            events_path=escrever_eventos(Path(tmp) / "nada.json", [{"sem": "nada"}]),
            attack_log_path=FIXTURE_LOG))
        check("(c) dataset_unusable: nada fica em %TEMP% e o erro é o certo",
              sobras_temporarias() == antes and codigo == "dataset_unusable")

    check(f"(e) a contagem final de sobras é a inicial ({len(antes)})",
          sobras_temporarias() == antes)


def _levanta_registro(*_args, **_kwargs):
    raise model_registry.ModelRegistryError("registry_unavailable")


def _levanta_value_error(*_args, **_kwargs):
    raise ValueError("catalog_sha256 tem de ser um SHA-256 de 64 hex")


def _levanta_keyboard_interrupt(*_args, **_kwargs):
    raise KeyboardInterrupt()


# --- 14. O disco do utilizador ---------------------------------------------------


def secao_disco_do_utilizador() -> None:
    secao("14. scripts/models/ nunca foi tocado por este ficheiro")

    modelos = SCRIPT_DIR / "models"
    check("(a) scripts/models/ tem exactamente os dois .pkl legados",
          listagem(modelos) == ["isolation_forest.pkl", "scaler.pkl"])
    check("(b) nenhuma pasta de versão (nenhum registo foi criado aqui)",
          not [n for n in listagem(modelos) if n.startswith("v")])
    check("(c) nem ACTIVE", not (modelos / "ACTIVE").exists())
    check("(d) nem temporários", not [n for n in listagem(modelos) if ".tmp-" in n])


# --- O runner --------------------------------------------------------------------


SECOES = (
    prova_negativa_de_imports,        # tem de ser a primeira (prova negativa)
    secao_resolve_export_path,
    secao_leitura_do_dataset,
    secao_factos_do_dataset,
    secao_estatisticas_do_lote,
    secao_treino_a_serio,
    secao_models_dir_sem_cwd,
    secao_pin_de_assinatura,
    secao_erros_do_treino,
    secao_single_flight,
    secao_ordem_da_cache,
    secao_activate_version,
    secao_limpeza_do_temporario,
    secao_disco_do_utilizador,
)


def run() -> None:
    # A variável chama-se `passo` e não `secao_` de propósito: um gate por AST
    # que procure `secao_*(...)` encontraria esta chamada e contaria a secção
    # de loop como se fosse uma secção de teste.
    for passo in SECOES:
        passo()
    print(f"\n{'FALHOU' if failures else 'OK'} — {len(failures)} check(s) falhados")
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    try:
        run()
    except SystemExit:
        raise
    except BaseException:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        raise SystemExit(1)