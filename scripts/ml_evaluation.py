"""
Motor de avaliação de uma versão de modelo ML (marco R9, Fase 2) — o módulo
onde vivem as MÉTRICAS, para que `model_registry.py` continue stdlib puro.

Porquê um módulo à parte (D-01): `model_registry.py` é o registo em disco e
não pode ganhar scikit-learn nem joblib no topo — os testes que o correm não
têm o sklearn carregado, e o `adopt` não precisa dele. O CLI importa este
módulo **dentro** de `_cmd_evaluate`, e só depois de o registo já ter recusado
uma versão inexistente ou um id inválido. A dependência vai num sentido só:
é este módulo que sabe de sklearn, não o registo.

O que mede (D-03): ML contra regras, sobre UM conjunto de eventos, com o
ground truth tirado do log de ataques.

    rótulo     feature_extractor.label_with_attack_log(...)   (o mecanismo
               puro que já produziu o ml_training_report.json)
    decisão    ml_anomalies.build_ml_anomalies_report(...)    (o ÚNICO caminho
               de código que chega ao model.predict — o mesmo que o dashboard
               usa, nunca uma segunda chamada)
    "regra"    classify_alert(event_id)["severity"] == "high" (D-04, o limiar
               literal de feature_extractor.py:141)

Rótulo e decisão são emparelhados por **índice posicional**, e a função
recusa-se a devolver alguma coisa se os dois conjuntos não tiverem o mesmo
tamanho: dois tamanhos diferentes é o modo silencioso de um número falso.

Limites honestos deste módulo:

    - `joblib.load` NÃO é chamado aqui. Os bytes já verificados do registo são
      desserializados por `ml_anomalies.load_version_artifacts`, que continua a
      ser o único ponto de desserialização do projecto (Pitfall 7);
    - `train_model` nunca é chamado: o `evaluate` mede a versão registada, não
      treina uma nova;
    - o `dataset_origin` é o que o utilizador passou em `--dataset-origin`.
      Nunca é adivinhado pelo caminho do ficheiro — a heurística
      `Path(events_path) == DEFAULT_EVENTS_PATH` de train_anomaly_model.py:72
      mente assim que o ficheiro real tiver outro nome (Pitfall 5);
    - os números só valem para o dataset e para a janela de rótulo usados, e o
      `caveat` diz sempre isso, com os limiares nomeados.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from sklearn.metrics import f1_score, precision_score, recall_score

import feature_extractor
import ml_anomalies

# --- Contrato do objeto `evaluation` ------------------------------------------
#
# 14 chaves fechadas, por esta ordem. `model_registry.EVALUATION_PUBLIC_KEYS`
# é a MESMA lista — o registo é que não pode importar este módulo (D-01), por
# isso a igualdade das duas é verificada por scripts/test_ml_models_api.py.

EVALUATION_KEYS = (
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

METRIC_KEYS = ("precision", "recall", "f1")
COMPARISON_KEYS = ("both_flagged", "ml_only", "rules_only", "neither")

DATASET_ORIGINS = ("real", "synthetic", "unknown")

# O texto de honestidade por origem (D-06). São três frases DISTINTAS de
# propósito: o painel tem de conseguir dizer "isto é sintético" e "isto não
# foi validado contra o laboratório" sem interpretar o texto — a origem
# também está no campo `dataset_origin`, mas o campo pode ser ignorado por
# quem lê só o aviso. 'unknown' não é um terceiro valor cómodo: é o número
# real calculado sobre um ficheiro cuja procedência ninguém declarou, que é
# o estado em que o `evaluate` fica por omissão.
ORIGEM_PT = {
    "real": "Origem declarada: dados reais exportados do laboratório Wazuh",
    "synthetic": "Origem declarada: dados SINTÉTICOS, não validados contra o laboratório",
    "unknown": "Origem NÃO declarada: o número é real mas a procedência é desconhecida",
}

# --- Limiares nomeados (D-05) --------------------------------------------------
#
# Dois eixos, nunca um só: a métrica degrada por amostra pequena E por
# cobertura de ataques (um dataset de 40 eventos com 3 ataques passaria num
# limiar único). `soc_metrics.DEFAULT_MIN_SAMPLE` (5) é de outro domínio — é um
# limiar de incidentes de SOC, não de um dataset de ML (Pitfall 4).
#
# São o sítio único onde a Fase 3 e a documentação mudam os limiares: nenhum
# número mágico aparece dentro das funções.

MIN_EVENTS = 50
MIN_ATTACKS = 10

# Janela de rótulo: um evento é ataque se cair em [t, t + janela] para alguma
# entrada do log. É o mesmo valor que feature_extractor usa por omissão.
DEFAULT_LABEL_WINDOW_SECONDS = 120

# Teto de leitura do ficheiro de eventos. Um dataset maior é quase sempre o
# utilizador a apontar para o ficheiro errado (T-02-09).
MAX_EVENTS_BYTES = 8 * 1024 * 1024

# Teto do texto do `caveat`. É o MESMO teto que a sub-projeção da API aplica
# (`model_registry.EVALUATION_TEXT_LIMIT`): um aviso que a API tivesse de
# cortar a meio perdia a própria ressalva que existe para ser lida — por
# isso o motor escreve um aviso que caiba inteiro e `validate_evaluation`
# recusa o que não caiba.
CAVEAT_TEXT_LIMIT = 200

EVALUATION_ERROR_CODES = (
    "events_unreadable",
    "events_empty",
    "events_too_large",
    "attack_log_mismatch",
    "labels_misaligned",
)

MESSAGES_PT = {
    "events_unreadable": (
        "Não foi possível ler o ficheiro de eventos: tem de ser um JSON com uma "
        "lista de alertas do Wazuh (o exportador do 02-03 escreve um ficheiro "
        "desse formato). Nada foi gravado."
    ),
    "events_empty": (
        "O ficheiro de eventos está vazio: não há nada para avaliar. Exporta "
        "primeiro os alertas do laboratório com o exportador e volta a correr o "
        "comando. Nada foi gravado."
    ),
    "events_too_large": (
        f"O ficheiro de eventos tem mais de {MAX_EVENTS_BYTES // (1024 * 1024)} MB — "
        "isto é quase sempre o ficheiro errado. Passa o export dos alertas do "
        "laboratório, não a base de dados inteira. Nada foi gravado."
    ),
    "attack_log_mismatch": (
        "O log de ataques não é uma lista JSONL de entradas com timestamp. "
        "Confirma o ficheiro passou em --attack-log. Nada foi gravado."
    ),
    "labels_misaligned": (
        "O número de linhas rotuladas não bate com o número de decisões do "
        "modelo — as duas listas têm de ser paralelas, e não são. Isto é um "
        "erro interno do pipeline, não um resultado: nada foi gravado em vez de "
        "se publicar um número falso."
    ),
}


class EvaluationError(Exception):
    """
    Erro do motor de avaliação com um código estável, pela mesma convenção do
    `ModelRegistryError`: `str(exc)` é exactamente o código, nunca uma
    mensagem ou um caminho. É uma lista NOVA e separada — `ERROR_CODES` do
    registo (D-06) não ganha chaves.
    """

    def __init__(self, code):
        if code not in EVALUATION_ERROR_CODES:
            raise ValueError(f"código de erro fora de EVALUATION_ERROR_CODES: {code!r}")
        self.code = code
        super().__init__(code)


# --- Leitura das entradas -------------------------------------------------------


def load_events_file(path) -> list[dict]:
    """
    Lê o ficheiro de eventos do `--events` e devolve a lista de alertas já
    extraída, no formato do Wazuh Indexer.

    Recusa, sem escrever nada: ficheiro ilegível ou JSON que não seja uma
    lista de dicts (`events_unreadable`), acima de MAX_EVENTS_BYTES
    (`events_too_large`) e lista vazia (`events_empty`).
    """
    caminho = Path(path)
    try:
        if caminho.stat().st_size > MAX_EVENTS_BYTES:
            raise EvaluationError("events_too_large")
        with open(caminho, encoding="utf-8") as handle:
            dados = json.load(handle)
    except EvaluationError:
        raise
    except OSError as exc:
        raise EvaluationError("events_unreadable") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvaluationError("events_unreadable") from exc

    if not isinstance(dados, list) or not all(isinstance(alerta, dict) for alerta in dados):
        raise EvaluationError("events_unreadable")
    if not dados:
        raise EvaluationError("events_empty")
    return dados


def load_attack_log(path) -> list[dict]:
    """
    O log de ataques do `--attack-log`, lido pelo mecanismo puro que já
    existe (`feature_extractor.load_attack_log`: ficheiro ausente ou linha
    malformada dá lista vazia em vez de crashar). Um ficheiro que exista mas
    não seja uma lista de entradas é `attack_log_mismatch` — um log ilegível
    daria 0 ataques rotulados e um relatório que parece uma falha do modelo.
    """
    entradas = feature_extractor.load_attack_log(str(path))
    if not isinstance(entradas, list) or not all(isinstance(e, dict) for e in entradas):
        raise EvaluationError("attack_log_mismatch")
    return entradas


def summarize_events(alerts) -> dict:
    """
    Quantos alertas há no ficheiro e quantos são processáveis (timestamp e
    Event ID válidos) — é o que o CLI imprime e o que o exportador do 02-03
    vai reutilizar para dizer, com honestidade, "500 documentos, 35
    processáveis", em vez de prometer 500.
    """
    return {"total": len(alerts), "processable": len(feature_extractor.extract_features(alerts))}


# --- Métricas -------------------------------------------------------------------


def _prf(truth: list[bool], flags: list[bool]) -> dict:
    """
    Precisão/recall/F1 com `zero_division=0` e `round(4)` — literalmente o
    mesmo cálculo de train_anomaly_model.evaluate, para que os números novos
    sejam comparáveis com o ml_training_report.json (D-04). Sem lista, o
    sklearn devolve 0,0 nas três: é o mesmo "não há amostra" que o resto do
    código trata como 0 e nunca como NaN.
    """
    return {
        "precision": round(precision_score(truth, flags, zero_division=0), 4),
        "recall": round(recall_score(truth, flags, zero_division=0), 4),
        "f1": round(f1_score(truth, flags, zero_division=0), 4),
    }


def small_sample_flags(total_events, attacks_in_dataset, *,
                       min_events=MIN_EVENTS, min_attacks=MIN_ATTACKS) -> bool:
    """
    True se o dataset for pequeno em QUALQUER dos dois eixos: menos de
    `min_events` eventos OU menos de `min_attacks` ataques (D-05). 35 eventos
    com 3 ataques dá True mesmo com o eixo dos eventos satisfeito.
    """
    return total_events < min_events or attacks_in_dataset < min_attacks


def _caveat(total_events, attacks_in_dataset, small_sample, dataset_origin, *,
            events_file, min_events, min_attacks, label_window_seconds) -> str:
    """
    O texto de aviso, sempre presente, montado por ORIGEM DECLARADA (D-06) e
    não pelo caminho do ficheiro: a heurística
    `Path(events) == DEFAULT_EVENTS_PATH` de train_anomaly_model.py:72 mente
    assim que o ficheiro real tiver outro nome.

    Ordem das partes (a primeira que jeito é a que manda):

        1. cobertura — `total_events > 0 e attacks_in_dataset == 0`: o log de
           ataques não cobre a janela dos eventos, o recall sai 0 POR
           DEFINIÇÃO e não por falha do modelo (Pitfall 10). Quando isto
           dispara, a parte da amostra pequena é omitida: 0 ataques é
           pequeno por definição e repetir o mesmo facto só gastava orçamento
           do aviso;
        2. origem — 'real' / 'synthetic' / 'unknown' em três textos
           distintos, com o NOME do ficheiro e nunca o caminho (T-02-15);
        3. amostra — pequena (nos dois eixos, com os limiares NOMINADOS) ou
           suficiente, com a janela de rótulo a que os números estão presos.

    O resultado é cortado a CAVEAT_TEXT_LIMIT para que caiba inteiro no
    `metadata.json` E no que a API devolve sem truncar.
    """
    partes: list[str] = []
    sem_cobertura = total_events > 0 and attacks_in_dataset == 0
    if sem_cobertura:
        partes.append(
            "Aviso: o log de ataques não cobre a janela dos eventos; recall 0 "
            "por definição, não por falha do modelo."
        )
    partes.append(f"{ORIGEM_PT[dataset_origin]} ({Path(events_file).name}).")
    if not sem_cobertura:
        if small_sample:
            partes.append(
                f"Amostra pequena: {total_events} eventos, {attacks_in_dataset} "
                f"ataques (min_events={min_events}, min_attacks={min_attacks})."
            )
        else:
            partes.append(
                f"Amostra suficiente: {total_events} eventos, "
                f"{attacks_in_dataset} ataques (min_events={min_events}, "
                f"min_attacks={min_attacks}), janela de rótulo de "
                f"{label_window_seconds}s."
            )
    texto = " ".join(partes)
    if len(texto) > CAVEAT_TEXT_LIMIT:
        texto = texto[:CAVEAT_TEXT_LIMIT - 1].rstrip() + "…"
    return texto


def build_evaluation_report(version_id, alerts, model, scaler, attack_log, *,
                            events_file, attack_log_file,
                            label_window_seconds=DEFAULT_LABEL_WINDOW_SECONDS,
                            dataset_origin="unknown",
                            min_events=MIN_EVENTS, min_attacks=MIN_ATTACKS,
                            evaluated_at=None) -> dict:
    """
    O coração: mede `model` contra as regras sobre `alerts`, com o ground truth
    de `attack_log`, e devolve o objeto `evaluation` — EXACTAMENTE as 14
    chaves de EVALUATION_KEYS, nada mais.

    `version_id` entra só na mensagem de erro de desalinhamento: o payload é
    gravado por VERSÃO, não precisa de se auto-identificar.

    Nada aqui escreve em disco — quem grava é
    `model_registry._write_evaluation`, por escrita atómica (Pattern 3). Um
    `EvaluationError` aqui significa que NÃO foi gravado nada.
    """
    if dataset_origin not in DATASET_ORIGINS:
        raise ValueError(f"dataset_origin fora de DATASET_ORIGINS: {dataset_origin!r}")
    if not isinstance(attack_log, list):
        raise EvaluationError("attack_log_mismatch")

    rows = feature_extractor.label_with_attack_log(
        feature_extractor.extract_features(alerts), attack_log,
        window_seconds=label_window_seconds)
    report = ml_anomalies.build_ml_anomalies_report(alerts, model, scaler)

    # D-03: rótulo e decisão são paralelos por construção (as duas listas vêm
    # de extract_features(alerts) com a mesma função pura), mas isso é uma
    # propriedade, não um contrato: se alguém mudar build_ml_anomalies_report
    # a meio, o zip passa a medir a coisa errada sem dar erro nenhum. É aqui
    # que a recusa acontece (T-02-10).
    resultados = report.get("results") or []
    if len(rows) != len(resultados):
        raise EvaluationError("labels_misaligned")

    truth = [bool(linha["is_attack"]) for linha in rows]
    ml_flags = [bool(linha["ml_is_anomaly"]) for linha in resultados]
    rule_flags = [bool(linha["rule_flagged"]) for linha in resultados]

    comparison = {
        "both_flagged": sum(1 for m, r in zip(ml_flags, rule_flags) if m and r),
        "ml_only": sum(1 for m, r in zip(ml_flags, rule_flags) if m and not r),
        "rules_only": sum(1 for m, r in zip(ml_flags, rule_flags) if r and not m),
        "neither": sum(1 for m, r in zip(ml_flags, rule_flags) if not m and not r),
    }

    total_events = len(rows)
    attacks_in_dataset = sum(1 for t in truth if t)
    small_sample = small_sample_flags(total_events, attacks_in_dataset,
                                      min_events=min_events, min_attacks=min_attacks)

    return {
        "evaluated_at": evaluated_at or datetime.now(timezone.utc).isoformat(),
        # Só o NOME do ficheiro, nunca o caminho (Pitfall 5/API-02): o que
        # vai para o disco do utilizador e para a API não pode conter a
        # árvore de pastas da máquina dele.
        "events_file": Path(events_file).name,
        "attack_log": Path(attack_log_file).name,
        "label_window_seconds": int(label_window_seconds),
        "total_events": total_events,
        "attacks_in_dataset": attacks_in_dataset,
        "ml": _prf(truth, ml_flags),
        "rules": _prf(truth, rule_flags),
        "comparison": comparison,
        "min_events": int(min_events),
        "min_attacks": int(min_attacks),
        "small_sample": bool(small_sample),
        "caveat": _caveat(total_events, attacks_in_dataset, small_sample,
                          dataset_origin, events_file=events_file,
                          min_events=min_events, min_attacks=min_attacks,
                          label_window_seconds=label_window_seconds),
        "dataset_origin": dataset_origin,
    }


def validate_evaluation(payload) -> None:
    """
    A SEGUNDA barreira antes de gravar: `build_evaluation_report` já produz
    o contrato, e isto confirma que o que vai chegar ao `metadata.json` é
    mesmo esse contrato e não um objeto qualquer com números plausíveis
    (T-02-12). Devolve `None` ou levanta `ValueError` — a excepção é a
    resposta, nunca um `False`, para que o CLI não tenha nada de opcional
    para se esquecer de verificar.

    O que é recusado, e porquê:

        - as 14 chaves exactas: falta uma ou sobra uma e o registo, ou a
          sub-projeção da API, ficariam com um campo a menos ou a mais;
        - `total_events` inteiro >= 0 e `attacks_in_dataset` entre 0 e
          `total_events`: mais ataques rotulados do que eventos é um log de
          ataques que não é deste ficheiro;
        - `comparison` com as quatro contagens que SOMAM `total_events` —
          é a soma que fecha a reconciliação ML↔regras;
        - `ml`/`rules` com as três métricas em [0,1]: uma precisão de 1,7 é
          o número de outro motor (ou de uma divisão por zero que ninguém
          apanhou), e nunca uma percentagem;
        - `small_sample` igual ao que `small_sample_flags` diz com os
          limiares gravados: o aviso é um facto derivado, não um campo livre
          que o painel acredite;
        - `dataset_origin` em DATASET_ORIGINS (D-06);
        - os quatro textos não vazios e com tamanho <= CAVEAT_TEXT_LIMIT,
          para que a API não tenha de cortar o aviso a meio.

    `bool` nunca passa como `int`: em Python `isinstance(True, int)` é
    True, e `small_sample: True` num campo inteiro passaria o teste errado.
    Da mesma forma, uma métrica `numpy.float64` (o que o sklearn devolve)
    passa — `np.float64` é subclasse de `float`.
    """
    if not isinstance(payload, dict):
        raise ValueError(f"a avaliação tem de ser um objeto, não {type(payload).__name__}")

    faltam = [k for k in EVALUATION_KEYS if k not in payload]
    sobram = [k for k in payload if k not in EVALUATION_KEYS]
    if faltam or sobram:
        raise ValueError(
            f"a avaliação tem de ter exactamente as {len(EVALUATION_KEYS)} chaves de "
            f"EVALUATION_KEYS; em falta: {faltam}; a mais: {sobram}")

    for chave in ("evaluated_at", "events_file", "attack_log", "caveat"):
        texto = payload[chave]
        if not isinstance(texto, str) or not texto.strip():
            raise ValueError(f"'{chave}' tem de ser um texto não vazio")
        if len(texto) > CAVEAT_TEXT_LIMIT:
            raise ValueError(
                f"'{chave}' tem {len(texto)} caracteres, acima do teto de "
                f"{CAVEAT_TEXT_LIMIT} (o que a API devolveria cortado)")

    def inteiro(chave, minimo):
        valor = payload[chave]
        if isinstance(valor, bool) or not isinstance(valor, int):
            raise ValueError(f"'{chave}' tem de ser um inteiro, não {valor!r}")
        if valor < minimo:
            raise ValueError(f"'{chave}' tem de ser >= {minimo}, não {valor!r}")
        return valor

    inteiro("label_window_seconds", 1)
    min_events = inteiro("min_events", 1)
    min_attacks = inteiro("min_attacks", 1)
    total_events = inteiro("total_events", 0)
    attacks_in_dataset = inteiro("attacks_in_dataset", 0)
    if attacks_in_dataset > total_events:
        raise ValueError(
            f"'attacks_in_dataset' ({attacks_in_dataset}) não pode ser maior que "
            f"'total_events' ({total_events}): o log de ataques não é deste ficheiro")

    for chave in ("ml", "rules"):
        metricas = payload[chave]
        if not isinstance(metricas, dict):
            raise ValueError(f"'{chave}' tem de ser um objeto com {list(METRIC_KEYS)}")
        if set(metricas) != set(METRIC_KEYS):
            raise ValueError(
                f"'{chave}' tem de ter exactamente as chaves {list(METRIC_KEYS)}; "
                f"recebido: {sorted(metricas)}")
        for metrica, valor in metricas.items():
            if isinstance(valor, bool) or not isinstance(valor, float):
                raise ValueError(
                    f"'{chave}.{metrica}' tem de ser um número, não {valor!r}")
            if not 0.0 <= valor <= 1.0:
                raise ValueError(
                    f"'{chave}.{metrica}' tem de estar entre 0.0 e 1.0, não {valor!r}")

    comparacao = payload["comparison"]
    if not isinstance(comparacao, dict):
        raise ValueError(f"'comparison' tem de ser um objeto com {list(COMPARISON_KEYS)}")
    if set(comparacao) != set(COMPARISON_KEYS):
        raise ValueError(
            f"'comparison' tem de ter exactamente as chaves {list(COMPARISON_KEYS)}; "
            f"recebido: {sorted(comparacao)}")
    for nome, valor in comparacao.items():
        if isinstance(valor, bool) or not isinstance(valor, int) or valor < 0:
            raise ValueError(
                f"'comparison.{nome}' tem de ser um inteiro >= 0, não {valor!r}")
    soma = sum(comparacao.values())
    if soma != total_events:
        raise ValueError(
            f"as quatro contagens de 'comparison' somam {soma} e 'total_events' é "
            f"{total_events}: ou sobra um evento sem classificação, ou falta")

    if not isinstance(payload["small_sample"], bool):
        raise ValueError(f"'small_sample' tem de ser um booleano, não {payload['small_sample']!r}")
    esperado = small_sample_flags(total_events, attacks_in_dataset,
                                  min_events=min_events, min_attacks=min_attacks)
    if payload["small_sample"] != esperado:
        raise ValueError(
            f"'small_sample' é {payload['small_sample']} mas com min_events={min_events} "
            f"e min_attacks={min_attacks} e {total_events}/{attacks_in_dataset} o valor "
            f"é {esperado}")

    if payload["dataset_origin"] not in DATASET_ORIGINS:
        raise ValueError(
            f"'dataset_origin' tem de ser um de {list(DATASET_ORIGINS)} (D-06: a "
            f"origem do dataset declara-se, não se adivinha), não "
            f"{payload['dataset_origin']!r}")


def percent_pt(valor, casas=1) -> str:
    """
    Um número 0..1 em percentagem pt-PT ("98,7 %"). É a MESMA formatização que
    o frontend usa, para que o stdout do CLI e a tabela da aba Evaluation
    mostrem o mesmo número para a mesma métrica (é o que o fecho do tracer
    verifica).
    """
    try:
        numero = float(valor)
    except (TypeError, ValueError):
        return "—"
    return f"{numero * 100:.{casas}f}".replace(".", ",") + " %"


def events_path_por_omissao() -> Path:
    """O `attack_log.jsonl` que o CLI usa quando não se passa --attack-log."""
    return Path(os.getenv("ATTACK_LOG_PATH")
                or (Path(__file__).resolve().parent / "attack_log.jsonl"))