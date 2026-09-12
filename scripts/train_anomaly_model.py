"""
Treina o modelo de deteção de anomalias (Isolation Forest) sobre o
dataset de features partilhado com o endpoint /api/ml-anomalies via
feature_extractor.py, e compara o resultado com a classificação por
regras já existente em event_catalog.py (não modificado por este
script).

*** IMPORTANTE: este treino usa dados sintéticos (sample_events_real.json
+ sample_attack_log.jsonl, ver scripts/_generate_sample_ml_data.py),
porque o laboratório Wazuh ainda não tem dados reais suficientes. As
métricas abaixo validam que o PIPELINE está correto, não que o modelo
tenha uma boa taxa de deteção em produção — ver README.md. ***

Uso:
    python train_anomaly_model.py
    python train_anomaly_model.py --events sample_events_real.json --attack-log sample_attack_log.jsonl
"""

import argparse
import json
from pathlib import Path

import joblib
from sklearn.ensemble import IsolationForest
from sklearn.metrics import f1_score, precision_score, recall_score
from sklearn.preprocessing import StandardScaler

from feature_extractor import extract_features, label_with_attack_log, load_attack_log, vectorize

DEFAULT_EVENTS_PATH = Path(__file__).parent / "sample_events_real.json"
DEFAULT_ATTACK_LOG_PATH = Path(__file__).parent / "sample_attack_log.jsonl"
DEFAULT_MODEL_DIR = Path(__file__).parent / "models"
DEFAULT_REPORT_PATH = Path(__file__).parent / "ml_training_report.json"


def load_dataset(events_path: Path, attack_log_path: Path) -> list[dict]:
    with open(events_path, encoding="utf-8") as handle:
        alerts = json.load(handle)
    attack_log = load_attack_log(str(attack_log_path))
    return label_with_attack_log(extract_features(alerts), attack_log)


def train_model(vectors: list[list[float]], contamination: float = 0.2, random_state: int = 42):
    scaler = StandardScaler()
    scaled = scaler.fit_transform(vectors)
    model = IsolationForest(contamination=contamination, random_state=random_state, n_estimators=200)
    model.fit(scaled)
    return model, scaler


def evaluate(feature_rows: list[dict], model, scaler) -> dict:
    vectors = vectorize(feature_rows)
    scaled = scaler.transform(vectors)
    predictions = model.predict(scaled)  # -1 = anómalo, 1 = normal

    ml_flags = [pred == -1 for pred in predictions]
    rule_flags = [row["rule_flagged"] for row in feature_rows]
    truth = [bool(row.get("is_attack")) for row in feature_rows]

    def prf(flags: list[bool]) -> dict:
        return {
            "precision": round(precision_score(truth, flags, zero_division=0), 4),
            "recall": round(recall_score(truth, flags, zero_division=0), 4),
            "f1": round(f1_score(truth, flags, zero_division=0), 4),
        }

    both = sum(1 for m, r in zip(ml_flags, rule_flags) if m and r)
    ml_only = sum(1 for m, r in zip(ml_flags, rule_flags) if m and not r)
    rule_only = sum(1 for m, r in zip(ml_flags, rule_flags) if r and not m)
    neither = sum(1 for m, r in zip(ml_flags, rule_flags) if not m and not r)

    return {
        "total_events": len(feature_rows),
        "attacks_in_dataset": sum(truth),
        "ml": prf(ml_flags),
        "rules": prf(rule_flags),
        "comparison": {"both_flagged": both, "ml_only": ml_only, "rules_only": rule_only, "neither": neither},
        "caveat": "Métricas calculadas sobre dados sintéticos (sample_events_real.json), "
                  "não validadas contra o laboratório Wazuh real.",
    }


def save_model(model, scaler, model_dir: Path = DEFAULT_MODEL_DIR) -> None:
    model_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_dir / "isolation_forest.pkl")
    joblib.dump(scaler, model_dir / "scaler.pkl")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--events", default=str(DEFAULT_EVENTS_PATH))
    parser.add_argument("--attack-log", default=str(DEFAULT_ATTACK_LOG_PATH))
    parser.add_argument("--model-dir", default=str(DEFAULT_MODEL_DIR))
    parser.add_argument("--report", default=str(DEFAULT_REPORT_PATH))
    parser.add_argument("--contamination", type=float, default=0.2)
    args = parser.parse_args()

    feature_rows = load_dataset(Path(args.events), Path(args.attack_log))
    vectors = vectorize(feature_rows)

    model, scaler = train_model(vectors, contamination=args.contamination)
    save_model(model, scaler, Path(args.model_dir))

    report = evaluate(feature_rows, model, scaler)
    with open(args.report, "w", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2)

    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"\nModelo guardado em: {args.model_dir}")
    print(f"Relatório guardado em: {args.report}")


if __name__ == "__main__":
    main()
