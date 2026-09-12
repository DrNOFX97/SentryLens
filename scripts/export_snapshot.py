"""
Exporta um snapshot do estado atual do backend SentryLens: /api/alerts,
/api/stats e o log de ataques da VM Kali (attack_scenarios.py), para um
ficheiro único em scripts/snapshots/AAAA-MM-DD_HH-MM.json.

Nunca sobrescreve um snapshot anterior: se já existir um ficheiro para o
mesmo minuto, acrescenta um sufixo numérico (_2, _3, ...).

Uso:
    python export_snapshot.py                       # usa http://localhost:8001
    python export_snapshot.py --api-base http://localhost:8001 --hours 24
"""

import argparse
import json
from datetime import datetime
from pathlib import Path

import httpx

DEFAULT_ATTACK_LOG_PATH = Path(__file__).parent / "attack_log.jsonl"
DEFAULT_OUTPUT_DIR = Path(__file__).parent / "snapshots"


def fetch_json(url: str, params: dict | None = None, timeout: float = 15.0) -> dict:
    response = httpx.get(url, params=params, timeout=timeout)
    response.raise_for_status()
    return response.json()


def load_attack_log(log_path: Path = DEFAULT_ATTACK_LOG_PATH) -> list[dict]:
    if not log_path.exists():
        return []
    entries = []
    with open(log_path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def build_snapshot(alerts_data: dict, stats_data: dict, attack_log: list[dict], now: datetime | None = None) -> dict:
    """Função pura: junta as três fontes já obtidas num único dict de snapshot."""
    return {
        "exported_at": (now or datetime.now()).isoformat(),
        "alerts": alerts_data,
        "stats": stats_data,
        "attack_log": attack_log,
    }


def unique_snapshot_path(output_dir: Path, now: datetime | None = None) -> Path:
    """Nome baseado no minuto atual; nunca reutiliza/sobrescreve um ficheiro existente."""
    now = now or datetime.now()
    base_name = now.strftime("%Y-%m-%d_%H-%M")
    candidate = output_dir / f"{base_name}.json"
    suffix = 2
    while candidate.exists():
        candidate = output_dir / f"{base_name}_{suffix}.json"
        suffix += 1
    return candidate


def save_snapshot(snapshot: dict, output_dir: Path = DEFAULT_OUTPUT_DIR, now: datetime | None = None) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = unique_snapshot_path(output_dir, now)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(snapshot, handle, ensure_ascii=False, indent=2)
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--api-base", default="http://localhost:8001")
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--attack-log", default=str(DEFAULT_ATTACK_LOG_PATH))
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    args = parser.parse_args()

    alerts_data = fetch_json(f"{args.api_base}/api/alerts", params={"hours": args.hours})
    stats_data = fetch_json(f"{args.api_base}/api/stats", params={"hours": args.hours})
    attack_log = load_attack_log(Path(args.attack_log))

    snapshot = build_snapshot(alerts_data, stats_data, attack_log)
    path = save_snapshot(snapshot, Path(args.output_dir))
    print(f"Snapshot escrito em: {path}")


if __name__ == "__main__":
    main()
