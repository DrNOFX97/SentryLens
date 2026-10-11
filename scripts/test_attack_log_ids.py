"""
Testes da atribuição de id pelo escritor do attack log (attack_scenarios.py) e
do caminho completo escritor -> disco -> leitor -> registo -> motor de vaccines
(VAC-03). Sem Wazuh, sem app, sem lançar ferramentas (shutil.which e
subprocess.run mockados), só IPs de documentação (192.0.2.x) e só logs em
pastas temporárias: o scripts/attack_log.jsonl real nunca é escrito.

Correr (a partir de scripts/):
    python test_attack_log_ids.py
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import attack_registry
import attack_scenarios as atk
import vaccine_engine
from attack_scenarios import SCENARIOS
from feature_extractor import load_attack_log

failures: list[str] = []
TMP_DIRS: list[Path] = []
REAL_LOG_SHA: dict = {}

SEED_LINES = [
    '{"scenario": "smb_enum", "target": "192.0.2.20", "timestamp": "2026-10-06T10:23:21Z", "status": "launched", "technique": "T1135", "tool": "netexec"}',
    '{"id": 3, "scenario": "smb_enum", "target": "192.0.2.20", "timestamp": "2026-10-06T10:23:50Z", "status": "launched", "technique": "T1087", "tool": "netexec"}',
    '{"id": 9, "scenario": "brute_force_rdp", "target": "192.0.2.20", "timestamp": "2026-10-06T10:24:08Z", "status": "launched", "technique": "T1110", "tool": "hydra"}',
    '{"id": true, "scenario": "smb_enum", "target": "192.0.2.20", "timestamp": "2026-10-06T10:24:20Z", "status": "launched"}',
    '{"id": "11", "scenario": "smb_enum", "target": "192.0.2.20", "timestamp": "2026-10-06T10:24:30Z", "status": "launched"}',
    "{nao json",
]


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def new_dir() -> Path:
    path = Path(tempfile.mkdtemp())
    TMP_DIRS.append(path)
    return path


def write_seed(path: Path) -> None:
    path.write_bytes(("\n".join(SEED_LINES) + "\n").encode("utf-8"))


def write_lines(path: Path, lines: list[str]) -> None:
    path.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))


def make_args(target="192.0.2.20", user=None, password=None) -> SimpleNamespace:
    return SimpleNamespace(target=target, user=user, password=password, wordlist=None, timeout=5)


@contextmanager
def isolated():
    """Sem allowlist real no ambiente nem no disco; ferramentas e subprocess mockados."""
    saved = os.environ.pop("ATTACK_TARGETS_PATH", None)
    try:
        with mock.patch.object(atk, "DEFAULT_TARGETS_PATH", new_dir() / "ausente.json"):
            yield
    finally:
        if saved is not None:
            os.environ["ATTACK_TARGETS_PATH"] = saved


def ok_process():
    return subprocess.CompletedProcess([], 0, "", "")


def real_log_sha() -> str | None:
    path = Path(atk.DEFAULT_LOG_PATH)
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def invariant(label: str, out: dict) -> None:
    considered, skipped = out["considered"], out["skipped"]
    check(label, considered["partial"] + considered["not_detected"] == out["total"] + sum(skipped.values()))


def run_tracer() -> None:
    REAL_LOG_SHA["start"] = real_log_sha()
    tmp = new_dir()
    log = tmp / "attack_log.jsonl"
    write_seed(log)
    check("seed: próximo id é 10 (max dos válidos 3 e 9, nunca contagem+1)", atk.next_attack_id(log) == 10)

    with isolated(), mock.patch("shutil.which", return_value="/usr/bin/x"), \
            mock.patch("subprocess.run", return_value=ok_process()) as sp:
        entry = atk.run_scenario(SCENARIOS["smb_enum"], make_args(), log)
        check("run_scenario lança smb_enum (launched)", entry["status"] == "launched")
        check("a entrada devolvida tem id 10", entry.get("id") == 10)
        check("subprocess.run chamado uma vez", sp.call_count == 1)

    on_disk = json.loads(log.read_text(encoding="utf-8").splitlines()[-1])
    check("a última linha lida do disco tem id 10 (gravado, não só devolvido)", on_disk.get("id") == 10)

    entries = load_attack_log(str(log))
    reg = attack_registry.build_attack_registry(entries, SCENARIOS, [])
    attack = next((a for a in reg["attacks"] if a["id"] == 10), None)
    check("o registo tem o ataque 10", attack is not None)
    attack = attack or {"actual": {}, "expected": {}}
    check("ataque 10: not_detected", attack["actual"].get("verdict") == "not_detected")
    check("ataque 10: esperado vem do cenário (scenario_default)", attack["expected"].get("source") == "scenario_default")
    check("ataque 10: sem duplicate_id", attack.get("duplicate_id") is False)

    out = vaccine_engine.build_vaccine_candidates(reg)
    check("vaccines geradas para os ataques [10, 9, 3]", [v["origin"]["attack_id"] for v in out["vaccines"]] == [10, 9, 3])
    vac = next((v for v in out["vaccines"] if v["origin"]["attack_id"] == 10), None)
    check("a vaccine do ataque 10 existe", vac is not None)
    vac = vac or {"id": None, "missing_sensors": None, "origin": {}}
    check("vaccine do ataque 10: id determinístico vac-940811b93421", vac["id"] == "vac-940811b93421")
    check("vaccine do ataque 10: missing_sensors [rule, ml]", vac["missing_sensors"] == ["rule", "ml"])
    check("vaccine do ataque 10: origin.scenario smb_enum", vac["origin"].get("scenario") == "smb_enum")
    check("vaccine do ataque 10: validate_vaccine == []", vaccine_engine.validate_vaccine(vac) == [])
    check("três entradas sem id válido contam em skipped.no_attack_id", out["skipped"]["no_attack_id"] == 3)
    check("considered.not_detected == 6", out["considered"]["not_detected"] == 6)
    check("total == 3", out["total"] == 3)
    invariant("invariante: partial + not_detected == total + soma de skipped", out)
    dumped = json.dumps(out)
    check("o alvo da entrada nova não entra na vaccine", "192.0.2.20" not in dumped)
    check("a ferramenta da entrada nova não entra na vaccine", "netexec" not in dumped)


if __name__ == "__main__":
    run_tracer()
    for tmp_dir in TMP_DIRS:
        shutil.rmtree(tmp_dir, ignore_errors=True)
    if failures:
        print(f"\n{len(failures)} verificação(ões) falharam")
        sys.exit(1)
    print("\nTodas as verificações passaram")
