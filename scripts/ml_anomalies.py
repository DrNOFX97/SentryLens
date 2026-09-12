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

import os

import joblib

from feature_extractor import extract_features, vectorize

DEFAULT_MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")

_model = None
_scaler = None


def load_model(model_dir: str | None = None):
    """Carrega (e mantém em cache no processo) o modelo + scaler
    treinados. Lança FileNotFoundError com uma mensagem acionável se
    train_anomaly_model.py ainda não correu — quem chama decide o
    código de estado HTTP.

    Nota de segurança: joblib.load desserializa pickle, o que permite
    execução arbitrária de código sobre ficheiros não confiáveis. Aqui é
    seguro porque os .pkl só podem vir de train_anomaly_model.py a
    correr localmente (nunca são recebidos de upload, rede ou de fora
    deste repositório) — ver ML_MODEL_DIR em main.py, que aponta sempre
    para uma pasta local gerida por nós.
    """
    global _model, _scaler
    if _model is not None and _scaler is not None:
        return _model, _scaler

    model_dir = model_dir or DEFAULT_MODEL_DIR
    model_path = os.path.join(model_dir, "isolation_forest.pkl")
    scaler_path = os.path.join(model_dir, "scaler.pkl")
    if not os.path.exists(model_path) or not os.path.exists(scaler_path):
        raise FileNotFoundError(
            f"Modelo de ML não encontrado em '{model_dir}'. Corre "
            "'python train_anomaly_model.py' primeiro para o gerar."
        )

    _model = joblib.load(model_path)
    _scaler = joblib.load(scaler_path)
    return _model, _scaler


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
