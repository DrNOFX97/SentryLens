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


def _caveat(total_events, attacks_in_dataset, small_sample, *,
            min_events, min_attacks, label_window_seconds) -> str:
    """
    O texto de aviso, sempre presente, com os limiares NOMINADOS e as três
    coisas por esta ordem (Pitfall 10):

        1. log de ataques que não cobre a janela dos eventos — o caso em que
           o recall sai 0,0 por definição e não por falha do modelo;
        2. dataset pequeno, nos dois eixos;
        3. ou, sem amostra pequena, que os números valem só para este dataset.
    """
    partes: list[str] = []
    if total_events > 0 and attacks_in_dataset == 0:
        partes.append(
            "Aviso: o log de ataques não cobre a janela dos eventos — nenhum evento "
            "foi rotulado como ataque, por isso o recall é 0 por definição e não por "
            "falha do modelo."
        )
    if small_sample:
        partes.append(
            f"Dataset pequeno ({total_events} eventos, {attacks_in_dataset} ataques; "
            f"limiares: min_events={min_events}, min_attacks={min_attacks}) — não é uma "
            "estimativa robusta de taxa de deteção."
        )
    else:
        partes.append(
            f"Os números valem só para este dataset ({total_events} eventos, "
            f"{attacks_in_dataset} ataques; limiares: min_events={min_events}, "
            f"min_attacks={min_attacks}) e para a janela de rótulo de "
            f"{label_window_seconds}s."
        )
    return " ".join(partes)


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
                          min_events=min_events, min_attacks=min_attacks,
                          label_window_seconds=label_window_seconds),
        "dataset_origin": dataset_origin,
    }


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