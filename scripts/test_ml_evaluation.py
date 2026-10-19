"""
Suite própria do motor de avaliação (scripts/ml_evaluation.py, marco R9
Fase 2) — o ficheiro de teste que este módulo merecia e que o 02-01 não
trouxe.

Porque é que este ficheiro existe e não pode ser o `test_model_registry.py`:
aquele corre o registo sem carregar scikit-learn nem joblib (é a propriedade
que garante D-01, o registo continuar stdlib puro), e um motor que mede com
`sklearn.metrics` precisa de um ficheiro que os importe. Este é esse ficheiro:
domínio puro, sem HTTP, sem CLI, sem disco.

O que fecha:

    D-04  os números são os MESMOS de `train_anomaly_model.evaluate` — a
          comparação é dita-a-dita dos três dicts (ml/rules/comparison), e
          não "quase iguais": é o que torna a comparação com o
          `ml_training_report.json` uma subtração e não um decipher;
    D-05  o aviso de amostra pequena tem DOIS limiares (50 eventos OU 10
          ataques), testados um a um, e não reusa o `soc_metrics`;
    D-03  a guarda `labels_misaligned` dispara se as decisões deixarem de
          ser paralelas aos rótulos, e nada é gravado;
    D-06  a origem do dataset é declarada, nunca adivinhada pelo caminho;
    EVAL-01  `validate_evaluation` fecha o contrato das 14 chaves antes de
          o motor escrever seja o que for.

NÃO precisa do laboratório Wazuh: não há rede, nem HTTP, nem modelos em
`scripts/models/`. O modelo das fixtures é treinado EM MEMÓRIA pelo próprio
teste (200 árvores, cacheado por módulo) e nunca é dumpedado para
`scripts/models/` — os dois `.pkl` do utilizador não são tocados.

Os números-base (36 eventos / 5 ataques, ML 0,4286/0,6/0,5, regras
0,625/1,0/0,7692, comparação 3/4/5/24) são os de `docs/ML.md` e estão
reproduzidos a partir dos ÚNICOS fixtures versionados do repositório
(`sample_events_real.json` + `sample_attack_log.jsonl`, D-06): o dataset real
de `ml_training_report.json` nunca esteve no git.

Correr (a partir de scripts/):
    python test_ml_evaluation.py
"""

import ast
import json
import math
import sys
import tempfile
from pathlib import Path

import ml_anomalies
import ml_evaluation
import feature_extractor
import train_anomaly_model

try:  # o console do Windows pode não ser UTF-8 (ver CLAUDE.md, reconfigure)
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

SCRIPT_DIR = Path(__file__).resolve().parent
EVENTOS_PATH = SCRIPT_DIR / "sample_events_real.json"
LOG_PATH = SCRIPT_DIR / "sample_attack_log.jsonl"

failures: list[str] = []
_cache: dict = {}


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def secao(titulo: str) -> None:
    print(f"\n--- {titulo} ---")


# --- Fixtures ------------------------------------------------------------------
#
# Tudo resolvido a partir do próprio ficheiro, nunca do cwd (Pitfall 5), e
# tudo em memória: nenhum comando escreve no repositório.


def alertas_sinteticos() -> list[dict]:
    if "alertas" not in _cache:
        _cache["alertas"] = json.loads(EVENTOS_PATH.read_text(encoding="utf-8"))
    return _cache["alertas"]


def log_sintetico() -> list[dict]:
    if "log" not in _cache:
        _cache["log"] = feature_extractor.load_attack_log(str(LOG_PATH))
    return _cache["log"]


def linhas_rotuladas() -> list[dict]:
    """As linhas que `train_anomaly_model.load_dataset` produz — as mesmas
    que o `evaluate` histórico mediu, para a comparação ser dita-a-dita."""
    if "linhas" not in _cache:
        _cache["linhas"] = train_anomaly_model.load_dataset(EVENTOS_PATH, LOG_PATH)
    return _cache["linhas"]


def modelo_sintetico() -> tuple:
    """(model, scaler) treinados com os parâmetros por omissão do
    `train_model` do repo (contamination=0.2, random_state=42) — os mesmos
    com que o `ml_training_report.json` foi feito. Treinar 200 árvores em
    cada secção seria lento, por isso é cacheado por módulo."""
    if "modelo" not in _cache:
        linhas = linhas_rotuladas()
        _cache["modelo"] = train_anomaly_model.train_model(
            feature_extractor.vectorize(linhas), contamination=0.2, random_state=42)
    return _cache["modelo"]


def avaliar(*, dataset_origin="synthetic", alerts=None, attack_log=None,
            events_file=EVENTOS_PATH, attack_log_file=LOG_PATH,
            evaluated_at="2026-10-10T00:00:00+00:00", **kwargs) -> dict:
    """`build_evaluation_report` com as fixtures por omissão."""
    model, scaler = modelo_sintetico()
    return ml_evaluation.build_evaluation_report(
        "v1",
        alertas_sinteticos() if alerts is None else alerts,
        model, scaler,
        log_sintetico() if attack_log is None else attack_log,
        events_file=events_file, attack_log_file=attack_log_file,
        dataset_origin=dataset_origin, evaluated_at=evaluated_at, **kwargs)


def alerta(event_id: int, ts: str, user: str = "jsilva", ip: str = "192.168.1.10") -> dict:
    return {
        "@timestamp": ts,
        "agent": {"name": "WIN-PC01", "ip": "192.168.1.5"},
        "rule": {"id": "1", "description": "x", "level": 5},
        "data": {"win": {"system": {"eventID": str(event_id)},
                         "eventdata": {"targetUserName": user, "ipAddress": ip}}},
        "full_log": "x",
    }


# --- 1. Números-base -----------------------------------------------------------


def test_numeros_base() -> None:
    """Os números do motor sobre o fixture versionado são os de docs/ML.md."""
    secao("números-base — o motor reproduz a tabela de docs/ML.md")
    payload = avaliar()

    check("números-base: total_events 36", payload["total_events"] == 36)
    check("números-base: attacks_in_dataset 5", payload["attacks_in_dataset"] == 5)
    check("números-base: ML precisão 0.4286", payload["ml"]["precision"] == 0.4286)
    check("números-base: ML recall 0.6", payload["ml"]["recall"] == 0.6)
    check("números-base: ML F1 0.5", payload["ml"]["f1"] == 0.5)
    check("números-base: regras precisão 0.625", payload["rules"]["precision"] == 0.625)
    check("números-base: regras recall 1.0", payload["rules"]["recall"] == 1.0)
    check("números-base: regras F1 0.7692", payload["rules"]["f1"] == 0.7692)
    check("números-base: comparação 3/4/5/24",
          payload["comparison"] == {"both_flagged": 3, "ml_only": 4,
                                    "rules_only": 5, "neither": 24})
    check("números-base: as quatro contagens somam total_events",
          sum(payload["comparison"].values()) == payload["total_events"])
    check("números-base: small_sample verdadeiro (36<50 e 5<10)",
          payload["small_sample"] is True)
    check("números-base: os limiares gravados são os nomeados do motor",
          payload["min_events"] == ml_evaluation.MIN_EVENTS
          and payload["min_attacks"] == ml_evaluation.MIN_ATTACKS)
    check("números-base: o payload tem exactamente as 14 chaves do contrato",
          tuple(payload) == tuple(ml_evaluation.EVALUATION_KEYS)
          and len(payload) == 14)
    check("números-base: dataset_origin gravado como declarado",
          payload["dataset_origin"] == "synthetic")


# --- 2. Comparabilidade com o histórico (D-04) ---------------------------------


def test_comparavel_com_historico() -> None:
    """
    D-04: o mesmo dataset, modelo e scaler dão ml/rules/comparison
    IDÊNTICOS aos de `train_anomaly_model.evaluate` — dita-a-dita, não
    "com tolerância". É a prova mecânica de que o número novo se subtrai do
    número de `ml_training_report.json`.
    """
    secao("comparabilidade com o histórico (D-04)")
    model, scaler = modelo_sintetico()
    payload = avaliar()
    historico = train_anomaly_model.evaluate(linhas_rotuladas(), model, scaler)

    check("comparabilidade: ml é idêntico ao do evaluate() do treino",
          payload["ml"] == historico["ml"])
    check("comparabilidade: rules é idêntico ao do evaluate() do treino",
          payload["rules"] == historico["rules"])
    check("comparabilidade: comparison é idêntico ao do evaluate() do treino",
          payload["comparison"] == historico["comparison"])
    check("comparabilidade: total_events e attacks_in_dataset também",
          payload["total_events"] == historico["total_events"]
          and payload["attacks_in_dataset"] == historico["attacks_in_dataset"])
    check("comparabilidade: o caveat NÃO é reusado (é dinâmico em cada avaliação, D-04)",
          payload["caveat"] != historico["caveat"])
    check("comparabilidade: 'regra' é severity=='high' (D-04, feature_extractor.py:141)",
          all(row["rule_flagged"] == (row["severity"] == "high")
              for row in linhas_rotuladas()))


# --- 3. Limiares em dois eixos (D-05) ------------------------------------------


def test_limiar_dois_eixos() -> None:
    """
    D-05: o aviso está presente quando eventos < 50 OU ataques < 10. Um só
    limiar deixaria passar 40 eventos com 3 ataques.
    """
    secao("limiares de amostra pequena em dois eixos (D-05)")
    flags = ml_evaluation.small_sample_flags

    check("limiares: MIN_EVENTS == 50 e MIN_ATTACKS == 10 (nomeados, não mágicos)",
          ml_evaluation.MIN_EVENTS == 50 and ml_evaluation.MIN_ATTACKS == 10)
    check("limiares: 35 eventos / 20 ataques -> verdadeiro (abaixo de ambos)",
          flags(35, 20) is True)
    check("limiares: 60 eventos / 12 ataques -> falso (acima de ambos)",
          flags(60, 12) is False)
    check("limiares: 49 eventos / 12 ataques -> verdadeiro (eixo dos eventos)",
          flags(49, 12) is True)
    check("limiares: 60 eventos / 9 ataques -> verdadeiro (eixo dos ataques, "
          "apesar dos 60 eventos)", flags(60, 9) is True)
    check("limiares: 50 eventos / 10 ataques -> falso (nos limiares exactos)",
          flags(50, 10) is False)
    check("limiares: min_events/min_attacks explícitos mudam o resultado",
          flags(35, 20, min_events=50, min_attacks=10) is True
          and flags(35, 20, min_events=30, min_attacks=10) is False)
    payload = avaliar()
    check("limiares: small_sample no payload bate com small_sample_flags",
          payload["small_sample"] == flags(payload["total_events"],
                                            payload["attacks_in_dataset"],
                                            min_events=payload["min_events"],
                                            min_attacks=payload["min_attacks"]))
    check("limiares: os limiares por omissão do payload são 50 e 10",
          payload["min_events"] == 50 and payload["min_attacks"] == 10)

    fonte = Path(ml_evaluation.__file__).read_text(encoding="utf-8")
    arvore = ast.parse(fonte)
    importados = ({alias.name.split(".")[0]
                   for no in ast.walk(arvore) if isinstance(no, ast.Import)
                   for alias in no.names}
                  | {(no.module or "").split(".")[0]
                     for no in ast.walk(arvore) if isinstance(no, ast.ImportFrom)})
    atributos = {no.attr for no in ast.walk(arvore) if isinstance(no, ast.Attribute)}
    check("limiares: soc_metrics.DEFAULT_MIN_SAMPLE não é usado (domínio diferente, Pitfall 4)",
          "soc_metrics" not in importados and "DEFAULT_MIN_SAMPLE" not in atributos)


# --- 4. Log de ataques desencontrado (Pitfall 10) -------------------------------


def test_log_desencontrado() -> None:
    """Um log que não cobre a janela dá recall 0 POR DEFINIÇÃO: o caveat tem
    de dizer isso, para o número não ser lido como falha do modelo."""
    secao("log de ataques desencontrado (Pitfall 10)")
    alertas = ([alerta(4624, f"2026-09-01T09:0{i}:00Z", user="mcosta") for i in range(4)]
               + [alerta(4625, f"2026-09-02T03:0{i}:00Z", user="convidado",
                         ip="203.0.113.50") for i in range(6)])
    payload = avaliar(alerts=alertas, attack_log=[])

    check("log desencontrado: 10 eventos processados", payload["total_events"] == 10)
    check("log desencontrado: 0 ataques rotulados", payload["attacks_in_dataset"] == 0)
    check("log desencontrado: small_sample verdadeiro (0 < min_attacks)",
          payload["small_sample"] is True)
    check("log desencontrado: o caveat começa pelo aviso de cobertura",
          payload["caveat"].startswith(
              "Aviso: o log de ataques não cobre a janela dos eventos"))
    check("log desencontrado: recall do ML é 0 por definição",
          payload["ml"]["recall"] == 0.0)
    check("log desencontrado: as contagens da comparação ainda fecham",
          sum(payload["comparison"].values()) == payload["total_events"])


# --- 5. Guarda de alinhamento rótulo ↔ decisão (D-03) ---------------------------


def test_guarda_de_alinhamento() -> None:
    """
    D-03: rótulo e decisão são emparelhados por índice posicional. Se um dia
    `build_ml_anomalies_report` deixar de devolver uma decisão por evento, o
    motor tem de recusar em vez de medir o alinhamento errado (T-02-14).
    """
    secao("guarda de alinhamento rótulo/decisão (D-03)")
    original = ml_anomalies.build_ml_anomalies_report

    def truncado(alerts, model, scaler):
        relatorio = original(alerts, model, scaler)
        relatorio = dict(relatorio)
        relatorio["results"] = list(relatorio.get("results") or [])[:-3]
        return relatorio

    ml_anomalies.build_ml_anomalies_report = truncado
    try:
        try:
            avaliar()
            exc = None
        except ml_evaluation.EvaluationError as raised:
            exc = raised
    finally:
        ml_anomalies.build_ml_anomalies_report = original

    check("alinhamento: EvaluationError com code 'labels_misaligned'",
          exc is not None and exc.code == "labels_misaligned")
    check("alinhamento: str(exc) é exactamente o código, nunca texto ou caminho",
          str(exc) == "labels_misaligned")
    check("alinhamento: 'labels_misaligned' está em EVALUATION_ERROR_CODES",
          "labels_misaligned" in ml_evaluation.EVALUATION_ERROR_CODES)
    check("alinhamento: com o caminho normal volta a medir",
          avaliar()["total_events"] == 36)


# --- 6. Extremos do PRF ---------------------------------------------------------


def test_prf_extremos() -> None:
    """`zero_division=0`: nunca uma excepção, nunca NaN — e arredondado a 4."""
    secao("PRF nos extremos (zero_division=0, round(4))")
    zero = ml_evaluation._prf([False, False, False], [False, False, False])
    um = ml_evaluation._prf([True, True, True], [True, True, True])

    check("PRF: sem verdadeiros e sem flags -> 0.0 nas três",
          zero == {"precision": 0.0, "recall": 0.0, "f1": 0.0})
    check("PRF: tudo verdadeiro e tudo sinalizado -> 1.0 nas três",
          um == {"precision": 1.0, "recall": 1.0, "f1": 1.0})
    check("PRF: sem flags mas com verdadeiros -> 0.0, não excepção",
          ml_evaluation._prf([True, True], [False, False])
          == {"precision": 0.0, "recall": 0.0, "f1": 0.0})
    check("PRF: sem verdadeiros mas com flags -> 0.0 (precisão indefinida = 0)",
          ml_evaluation._prf([False, False], [True, True])
          == {"precision": 0.0, "recall": 0.0, "f1": 0.0})

    todos = [ml_evaluation._prf([True, False, True, False], flags)
             for flags in ([True, True, False, False], [False, True, True, False],
                           [False, False, True, True], [True, False, False, True])]
    valores = [valor for bloco in todos for valor in bloco.values()]
    check("PRF: nenhum valor é NaN nem infinito",
          all(math.isfinite(v) for v in valores))
    check("PRF: nenhum valor passa das 4 casas decimais",
          all(v == round(v, 4) and len(f"{v:.10f}".rstrip("0").split(".")[1]) <= 4
              for v in valores))
    check("PRF: 1 verdadeiro em 2, sinalizado -> precisão 0.5 e F1 0.6667",
          ml_evaluation._prf([True, False], [True, True])
          == {"precision": 0.5, "recall": 1.0, "f1": 0.6667})


# --- 7. Pureza e determinismo ---------------------------------------------------


def test_puridade() -> None:
    """
    `build_evaluation_report` é puro: mesmas entradas + mesmo `evaluated_at` =
    mesmo payload, e nada de entrada é modificado. É o que permite comparar
    duas avaliações sem que a segunda meça outra coisa.
    """
    secao("pureza e determinismo do motor")
    alertas = alertas_sinteticos()
    antes_alertas = json.dumps(alertas, ensure_ascii=False, sort_keys=True)
    linhas = linhas_rotuladas()
    antes_linhas = json.dumps(linhas, ensure_ascii=False, sort_keys=True)

    primeiro = avaliar()
    segundo = avaliar()

    check("pureza: duas chamadas com o mesmo evaluated_at dão o mesmo payload",
          primeiro == segundo)
    check("pureza: a lista de alertas não foi modificada",
          json.dumps(alertas, ensure_ascii=False, sort_keys=True) == antes_alertas)
    check("pureza: as linhas de features não foram modificadas",
          json.dumps(linhas, ensure_ascii=False, sort_keys=True) == antes_linhas)
    check("pureza: o payload é JSON-serializável tal e qual (vai para o disco)",
          json.loads(json.dumps(primeiro, ensure_ascii=False)) == primeiro)
    check("pureza: sem evaluated_at, o motor põe a hora actual em ISO-8601 com fuso",
          ml_evaluation.build_evaluation_report(
              "v1", alertas, *modelo_sintetico(), log_sintetico(),
              events_file=EVENTOS_PATH, attack_log_file=LOG_PATH,
              dataset_origin="real")["evaluated_at"].endswith("+00:00"))


# --- 8. Leitura do ficheiro de eventos (T-02-09) --------------------------------


def test_leitura_eventos() -> None:
    """`--events` é entrada não confiável: recusa por tamanho, JSON e forma."""
    secao("leitura do ficheiro de eventos (T-02-09)")
    with tempfile.TemporaryDirectory() as tmp:
        pasta = Path(tmp)

        def escrever(nome, conteudo):
            caminho = pasta / nome
            caminho.write_text(conteudo, encoding="utf-8")
            return caminho

        def erro(caminho):
            try:
                ml_evaluation.load_events_file(caminho)
                return None
            except ml_evaluation.EvaluationError as raised:
                return raised.code

        check("leitura: ficheiro inexistente -> events_unreadable",
              erro(pasta / "nao-existe.json") == "events_unreadable")
        check("leitura: JSON inválido -> events_unreadable",
              erro(escrever("ma.json", "{isto não é json")) == "events_unreadable")
        check("leitura: um dict em vez de uma lista -> events_unreadable",
              erro(escrever("dict.json", '{"a": 1}')) == "events_unreadable")
        check("leitura: uma lista de strings -> events_unreadable",
              erro(escrever("strings.json", '["a", "b"]')) == "events_unreadable")
        check("leitura: lista vazia -> events_empty",
              erro(escrever("vazio.json", "[]")) == "events_empty")
        check("leitura: JSON válido é devolvido tal e qual",
              ml_evaluation.load_events_file(escrever("ok.json", '[{"a": 1}]'))
              == [{"a": 1}])

        grande = pasta / "grande.json"
        with open(grande, "wb") as handle:
            handle.truncate(ml_evaluation.MAX_EVENTS_BYTES + 1)
        check("leitura: acima de MAX_EVENTS_BYTES -> events_too_large",
              erro(grande) == "events_too_large")
        check("leitura: MAX_EVENTS_BYTES é um nomeado, não um número mágico no meio",
              isinstance(ml_evaluation.MAX_EVENTS_BYTES, int)
              and ml_evaluation.MAX_EVENTS_BYTES > 0)
        check("leitura: summarize_events dá total e processáveis",
              ml_evaluation.summarize_events(alertas_sinteticos())
              == {"total": 36, "processable": 36})


# --- 9. Origem declarada, nunca adivinhada (D-06) -------------------------------


def test_origem_declarada() -> None:
    """
    D-06: o mesmo ficheiro com três origens declaradas dá três avisos
    diferentes — e nenhum deles diz o caminho, só o nome. O que o painel
    mostra tem de ser o número E a origem; um sintético apresentado como real
    é o "valor inventado" que o PROJECT.md proíbe.
    """
    secao("origem do dataset declarada, nunca adivinhada (D-06)")
    real = avaliar(dataset_origin="real")
    sintetico = avaliar(dataset_origin="synthetic")
    desconhecida = avaliar(dataset_origin="unknown")

    check("origem: os três avisos são diferentes entre si",
          len({real["caveat"], sintetico["caveat"], desconhecida["caveat"]}) == 3)
    check("origem: 'synthetic' diz que os dados são sintéticos",
          "SINTÉTICOS" in sintetico["caveat"])
    check("origem: 'synthetic' diz que não foram validados contra o laboratório",
          "não validados contra o laboratório" in sintetico["caveat"])
    check("origem: 'real' diz que são dados reais do laboratório",
          "reais exportados do laboratório" in real["caveat"])
    check("origem: 'unknown' diz que a origem NÃO foi declarada",
          "NÃO declarada" in desconhecida["caveat"]
          and "procedência é desconhecida" in desconhecida["caveat"])
    check("origem: os números não mudam com a origem declarada (é um atributo "
          "do dataset, não da medição)",
          (real["ml"], real["rules"], real["comparison"])
          == (sintetico["ml"], sintetico["rules"], sintetico["comparison"])
          == (desconhecida["ml"], desconhecida["rules"], desconhecida["comparison"]))
    check("origem: o mesmo ficheiro com origens diferentes dá origens diferentes "
          "gravadas", (real["dataset_origin"], sintetico["dataset_origin"],
                       desconhecida["dataset_origin"]) == ("real", "synthetic", "unknown"))
    check("origem: nenhum dos três avisos traz o caminho do ficheiro",
          not any(("/" in c or "\\" in c) for c in
                  (real["caveat"], sintetico["caveat"], desconhecida["caveat"])))
    check("origem: 'unknown' nunca é adivinhado a partir do caminho — o mesmo "
          "ficheiro versionado com 'real' mantém 'real'",
          avaliar(dataset_origin="real", events_file=EVENTOS_PATH)["dataset_origin"]
          == "real")
    check("origem: os três avisos cabem no teto que a API devolve inteiro",
          all(len(c) <= ml_evaluation.CAVEAT_TEXT_LIMIT
              for c in (real["caveat"], sintetico["caveat"], desconhecida["caveat"])))
    check("origem: os avisos do fixture de 36 eventos / 5 ataques têm amostra pequena",
          real["small_sample"] and sintetico["small_sample"]
          and desconhecida["small_sample"])
    check("origem: DATASET_ORIGINS são os três e mais nenhum",
          tuple(ml_evaluation.DATASET_ORIGINS) == ("real", "synthetic", "unknown"))
    try:
        avaliar(dataset_origin="inventado")
        exc = None
    except ValueError as raised:
        exc = raised
    check("origem: uma origem fora de DATASET_ORIGINS é recusada", exc is not None)


# --- 10. Contrato do payload (EVAL-01) ------------------------------------------


def test_validacao_payload() -> None:
    """
    `validate_evaluation` é a barreira antes do disco: aceita o payload do
    motor e recusa cada incoerência que faria um número falso passar por
    número (T-02-12/T-02-16).
    """
    secao("validação do payload (EVAL-01)")
    base = avaliar()
    ml_evaluation.validate_evaluation(base)

    def com(mutacao):
        payload = json.loads(json.dumps(base))
        mutacao(payload)
        return payload

    def recusa(mutacao):
        try:
            ml_evaluation.validate_evaluation(com(mutacao))
            return False
        except ValueError:
            return True

    def falta_uma(payload):
        del payload["caveat"]

    def sobra_uma(payload):
        payload["nota_extra"] = "x"

    def soma_errada(payload):
        payload["comparison"]["neither"] = 99

    def metrica_fora(payload):
        payload["ml"]["precision"] = 1.7

    def small_sample_incoerente(payload):
        payload["total_events"] = 500
        payload["attacks_in_dataset"] = 50
        payload["comparison"] = {"both_flagged": 250, "ml_only": 125,
                                 "rules_only": 125, "neither": 0}

    def origem_inventada(payload):
        payload["dataset_origin"] = "inventado"

    def ataques_acima_dos_eventos(payload):
        payload["attacks_in_dataset"] = payload["total_events"] + 1

    def texto_vazio(payload):
        payload["events_file"] = "   "

    def texto_gigante(payload):
        payload["caveat"] = "X" * (ml_evaluation.CAVEAT_TEXT_LIMIT + 1)

    def metrica_com_bool(payload):
        payload["rules"]["recall"] = True

    def inteiro_com_bool(payload):
        payload["total_events"] = True

    def limiar_zero(payload):
        payload["min_attacks"] = 0

    check("validação: aceita o payload devolvido por build_evaluation_report", True)
    check("validação: falta uma das 14 chaves -> ValueError", recusa(falta_uma))
    check("validação: uma chave a mais -> ValueError", recusa(sobra_uma))
    check("validação: comparison a somar 99 em vez de total_events -> ValueError",
          recusa(soma_errada))
    check("validação: ml.precision a 1.7 -> ValueError", recusa(metrica_fora))
    check("validação: small_sample incoerente com min_events/min_attacks -> ValueError",
          recusa(small_sample_incoerente))
    check("validação: dataset_origin 'inventado' -> ValueError", recusa(origem_inventada))
    check("validação: ataques acima dos eventos -> ValueError", recusa(ataques_acima_dos_eventos))
    check("validação: um texto só com espaços -> ValueError", recusa(texto_vazio))
    check("validação: um texto acima do teto -> ValueError", recusa(texto_gigante))
    check("validação: uma métrica booleana -> ValueError", recusa(metrica_com_bool))
    check("validação: total_events booleano -> ValueError", recusa(inteiro_com_bool))
    check("validação: um limiar a zero -> ValueError", recusa(limiar_zero))

    try:
        ml_evaluation.validate_evaluation("não sou um objeto")
        exc = None
    except ValueError as raised:
        exc = raised
    check("validação: uma string no lugar do objeto -> ValueError", exc is not None)

    # O `small_sample` coerente com a mutação acima é o outro lado da moeda:
    # a mesma mutação com o booleano certo passa, o que prova que a regra
    # testa a COERÊNCIA e não o valor em si.
    coerente = com(small_sample_incoerente)
    coerente["small_sample"] = False
    try:
        ml_evaluation.validate_evaluation(coerente)
        passou = True
    except ValueError:
        passou = False
    check("validação: o mesmo payload com small_sample coerente passa", passou)

    fonte = Path(ml_evaluation.__file__).read_text(encoding="utf-8")
    check("validação: validate_evaluation está definido uma vez só",
          fonte.count("def validate_evaluation") == 1)


SECOES = (
    test_numeros_base,
    test_comparavel_com_historico,
    test_limiar_dois_eixos,
    test_log_desencontrado,
    test_guarda_de_alinhamento,
    test_prf_extremos,
    test_puridade,
    test_leitura_eventos,
    test_origem_declarada,
    test_validacao_payload,
)


def run() -> None:
    for teste in SECOES:
        teste()

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")


if __name__ == "__main__":
    run()
