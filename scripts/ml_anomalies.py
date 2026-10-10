"""
Painel de deteção de anomalias por Machine Learning (Isolation Forest),
correndo em PARALELO com a classificação por regras do event_catalog.py
— nunca a substitui. Módulo puro (como lifecycle.py/rbac.py/
admin_activity.py): recebe alertas já obtidos do Wazuh, e o modelo/scaler
já carregados, e devolve um relatório pronto para o endpoint servir.

O modelo é treinado por train_anomaly_model.py sobre
feature_extractor.py — o MESMO módulo de extração de features usado
aqui, para que treino e inferência nunca divirjam.
"""

import io
import os

import joblib

import model_registry
from feature_extractor import extract_features, vectorize

DEFAULT_MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")

_model = None
_scaler = None
# De onde veio o modelo que está em memória: "vN", "legacy" ou None. É o
# `loaded` do relatório de GET /api/ml/models (D-02) — a cache é por
# processo, por isso depois de um adopt o processo continua a servir o
# modelo antigo até reiniciar e o dashboard tem de o dizer.
_loaded_from = None


def load_model(model_dir: str | None = None):
    """Carrega (e mantém em cache no processo) o modelo + scaler da versão
    ativa do registo, em model_registry.

    Na cache miss, `model_registry.resolve_active_artifacts()` devolve os
    bytes JÁ VERIFICADOS dos dois .pkl (SHA-256 conferido contra o
    metadata.json) e aqui são desserializados com
    `joblib.load(io.BytesIO(...))` — os mesmos bytes que foram verificados,
    nunca um segundo open do ficheiro (SEC-01, T-01-08).

    Lança FileNotFoundError com uma mensagem acionável e SEM caminhos
    quando não há nada ativo (quem chama decide o estado HTTP, 503), e
    ModelRegistryError(code) quando o registo recusa a versão ativa (hash
    adulterado, ACTIVE inválido, metadados corrompidos).

    Nota de segurança: `joblib.load` desserializa pickle, o que executa
    código arbitrário — daí nada não verificado chegar lá. Os limites
    honestos desta verificação: o SHA-256 deteta corrupção, troca acidental
    e ficheiros alheios sem metadados, mas NÃO autentica (quem escreve em
    models/ reescreve também o metadata.json — dívida registada, D-04); e o
    modelo legado, sem metadados, carrega sem verificação até ser adotado
    com `python model_registry.py adopt` (REG-02, risco aceite T-01-10).
    """
    global _model, _scaler, _loaded_from
    if _model is not None and _scaler is not None:
        return _model, _scaler

    source = model_registry.resolve_active_artifacts(model_dir or DEFAULT_MODEL_DIR)
    # Só depois de os DOIS artefactos virem verificados do registo é que se
    # desserializa; se um `joblib.load` explodir, a cache fica vazia e o
    # próximo pedido volta a tentar em vez de servir metade do modelo.
    model = joblib.load(io.BytesIO(source.model_bytes))
    scaler = joblib.load(io.BytesIO(source.scaler_bytes))
    _model = model
    _scaler = scaler
    _loaded_from = source.version
    return _model, _scaler


def reset_cache() -> None:
    """Esvazia a cache do processo. Usado nos testes e depois de um adopt
    (a cache é por processo: sem isto, o backend continua a servir o modelo
    antigo depois de adotar a v1)."""
    global _model, _scaler, _loaded_from
    _model = None
    _scaler = None
    _loaded_from = None


def loaded_version() -> str | None:
    """A versão que este processo tem de facto em memória: "vN", "legacy"
    ou None. É o `loaded` que GET /api/ml/models expõe (D-02)."""
    return _loaded_from


def load_version_artifacts(source) -> tuple:
    """Desserializa os artefactos de uma versão ARBITRÁRIA (D-02) a partir de
    um `ArtifactSource` do registo — os bytes JÁ VERIFICADOS contra o
    SHA-256 do metadata.json, lidos uma só vez (SEC-01, T-01-08).

    É o mesmo caminho de `load_model` (`joblib.load(io.BytesIO(...))`), pelo
    que este módulo continua a ser o ÚNICO ponto de desserialização do projecto
    (Pitfall 7): o motor de avaliação nunca chama o joblib por si.

    Diferença deliberada em relação a `load_model`: NÃO escreve em
    `_model`/`_scaler`/`_loaded_from`. Avaliar a vN não muda o modelo que o
    processo está a usar nas deteções — o `loaded` do dashboard continua a
    dizer a verdade (D-02), e a cache continua a ser só do `load_model`.

    `source` None é TypeError: é um erro de programação, não de dados.
    """
    if source is None:
        raise TypeError("load_version_artifacts precisa de um ArtifactSource do registo")
    artefatos = [joblib.load(io.BytesIO(dados))
                 for dados in (source.model_bytes, source.scaler_bytes)]
    model, scaler = artefatos
    return model, scaler


def build_ml_anomalies_report(alerts: list[dict], model, scaler) -> dict:
    """Função pura: aplica o modelo já carregado aos alertas e devolve o
    relatório lado a lado com a classificação por regras (rule_flagged,
    já calculado em feature_extractor.extract_features)."""
    features = extract_features(alerts)
    if not features:
        return {
            "total": 0, "ml_anomalies_count": 0, "rule_flagged_count": 0,
            "agree_count": 0, "diverge_count": 0, "results": [],
        }

    vectors = vectorize(features)
    scaled = scaler.transform(vectors)
    # decision_function: quanto MAIOR (mais positivo), mais "normal" o
    # IsolationForest considera o ponto; valores negativos indicam
    # anomalia. ml_is_anomaly (abaixo) já traduz isto para um booleano —
    # ml_score fica exposto em bruto só para quem quiser o grau, não só
    # o veredicto.
    scores = model.decision_function(scaled)
    predictions = model.predict(scaled)

    results = []
    agree = 0
    for row, score, pred in zip(features, scores, predictions):
        ml_is_anomaly = bool(pred == -1)
        rule_flagged = bool(row["rule_flagged"])
        agreement = "agree" if ml_is_anomaly == rule_flagged else "diverge"
        agree += agreement == "agree"
        results.append({
            "timestamp": row["timestamp"],
            "agent_name": row["agent_name"],
            "agent_ip": row["agent_ip"],
            "target_user": row["target_user"],
            "windows_event_id": row["windows_event_id"],
            "severity": row["severity"],
            "rule_flagged": rule_flagged,
            "ml_score": round(float(score), 4),
            "ml_is_anomaly": ml_is_anomaly,
            "agreement": agreement,
        })

    ml_count = sum(r["ml_is_anomaly"] for r in results)
    rule_count = sum(r["rule_flagged"] for r in results)
    return {
        "total": len(results),
        "ml_anomalies_count": ml_count,
        "rule_flagged_count": rule_count,
        "agree_count": agree,
        "diverge_count": len(results) - agree,
        "results": results,
    }
