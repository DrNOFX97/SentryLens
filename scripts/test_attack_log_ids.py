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


def launch(log: Path, name: str = "smb_enum", args=None, which="/usr/bin/x", run_effect=None):
    """run_scenario com ferramentas mockadas; devolve (entrada, mock do subprocess.run)."""
    with isolated(), mock.patch("shutil.which", return_value=which), \
            mock.patch("subprocess.run", return_value=ok_process(), side_effect=run_effect) as sp:
        entry = atk.run_scenario(SCENARIOS[name], args or make_args(), log)
    return entry, sp


def raises_unavailable(fn) -> str | None:
    try:
        fn()
    except atk.AttackIdUnavailable as exc:
        return str(exc)
    return None


def run_ids() -> None:
    tmp = new_dir()

    # --- log novo: seis caminhos de escrita seguidos, ids únicos e crescentes ---
    log = tmp / "novo.jsonl"
    check("log inexistente: next_attack_id == 1", atk.next_attack_id(log) == 1)
    launch(log)
    launch(log, run_effect=subprocess.TimeoutExpired(cmd="x", timeout=5))
    launch(log, which=None)
    launch(log, run_effect=OSError("falhou"))
    launch(log, "lateral_movement_schtasks")
    launch(log, args=make_args(target="192.168.1.10"))
    rows = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    check("seis caminhos seguidos: ids [1, 2, 3, 4, 5, 6]", [r.get("id") for r in rows] == [1, 2, 3, 4, 5, 6])
    check("os seis caminhos cobrem launched, timeout, failed x2 e skipped x2",
          [r["status"] for r in rows] == ["launched", "launched", "failed", "failed", "skipped", "skipped"]
          and rows[1]["details"].get("timed_out") is True
          and rows[4]["details"].get("reason", "").startswith("argumentos")
          and rows[5]["details"].get("reason") == "target_not_allowed")
    check("cada id gravado é aceite por attack_registry.normalize_attack_id",
          all(attack_registry.normalize_attack_id(r.get("id")) == r["id"] for r in rows))

    # --- max+1, nunca contagem+1 ---
    gaps = tmp / "falhas.jsonl"
    write_lines(gaps, [SEED_LINES[1], SEED_LINES[2]])
    check("log só com ids 3 e 9: próximo é 10 (contagem+1 daria 3)", atk.next_attack_id(gaps) == 10)
    dup = tmp / "repetidos.jsonl"
    write_lines(dup, ['{"id": 8, "scenario": "smb_enum", "status": "launched"}'] * 2)
    check("log com o id 8 repetido: próximo é 9", atk.next_attack_id(dup) == 9)
    failed_only = tmp / "falhado.jsonl"
    write_lines(failed_only, ['{"id": 4, "scenario": "smb_enum", "status": "failed"}'])
    check("qualquer status conta para o máximo (failed com id 4 -> 5)", atk.next_attack_id(failed_only) == 5)

    # --- linhas hostis ---
    hostile = tmp / "hostil.jsonl"
    write_lines(hostile, ["{nao json", "[1]", "", '{"id": true}', '{"id": "11"}', '{"id": 2.0}',
                          '{"id": 0}', '{"id": -1}', '{"id": 1000000000000}'])
    try:
        got = atk.next_attack_id(hostile)
        check("log hostil: sem exceção e próximo é 1", got == 1)
    except Exception as exc:  # noqa: BLE001 - o teste é exatamente "nunca levanta"
        check(f"log hostil: sem exceção ({type(exc).__name__})", False)

    # --- paridade com o leitor real ---
    seed_path = tmp / "paridade_seed.jsonl"
    write_seed(seed_path)
    for label, path in (("seed", seed_path), ("hostil", hostile)):
        seen = [attack_registry.normalize_attack_id(e.get("id")) for e in load_attack_log(str(path)) if isinstance(e, dict)]
        expected = max([i for i in seen if i is not None] or [0]) + 1
        check(f"paridade com load_attack_log + normalize_attack_id ({label})", atk.next_attack_id(path) == expected)

    # --- paridade com o registo ---
    battery = [True, False, 0, -1, 1, 13, 999_999_999, 10**9, 2.0, "2", None, [1]]
    check("valid_attack_id == normalize_attack_id em 12 valores",
          all(atk.valid_attack_id(v) == attack_registry.normalize_attack_id(v) for v in battery))
    check("MAX_ATTACK_ID == 999_999_999 e casa o padrão da rota ^[0-9]{1,9}$",
          atk.MAX_ATTACK_ID == 999_999_999 and re.fullmatch(r"^[0-9]{1,9}$", str(atk.MAX_ATTACK_ID)) is not None)

    # --- format_log_entry ---
    base = ("smb_enum", "192.0.2.20", "netexec", "launched")
    check("format_log_entry(attack_id=7) grava id 7", atk.format_log_entry(*base, attack_id=7)["id"] == 7)
    bad = []
    for value in (True, 0, "5", 10**9, 2.0):
        try:
            atk.format_log_entry(*base, attack_id=value)
            bad.append(value)
        except ValueError:
            pass
    check("attack_id inválido (True, 0, '5', 10**9, 2.0) levanta ValueError", not bad)
    check("sem attack_id não há chave id", "id" not in atk.format_log_entry(*base))

    # --- sem backfill ---
    nb = tmp / "sem_backfill.jsonl"
    write_seed(nb)
    before = nb.read_bytes()
    e1, _ = launch(nb)
    e2, _ = launch(nb)
    after = nb.read_bytes()
    check("sem backfill: o conteúdo antigo é prefixo exato do novo", after.startswith(before) and len(after) > len(before))
    first = json.loads(after.decode("utf-8").splitlines()[0])
    check("sem backfill: a linha 1 continua sem id", "id" not in first)
    check("sem backfill: os dois novos ids são 10 e 11", (e1["id"], e2["id"]) == (10, 11))

    # --- partial pelo escritor real ---
    pl = tmp / "partial.jsonl"
    write_seed(pl)
    entry, _ = launch(pl)
    stamp = (datetime.fromisoformat(entry["timestamp"]) + timedelta(seconds=5)).isoformat()
    ml_results = [{"timestamp": stamp, "agent_ip": "192.0.2.20", "windows_event_id": 5140,
                   "rule_flagged": True, "ml_is_anomaly": False}]
    reg = attack_registry.build_attack_registry(load_attack_log(str(pl)), SCENARIOS, ml_results)
    attack = next((a for a in reg["attacks"] if a["id"] == 10), {"actual": {}})
    check("partial: ataque 10 partial com achieved [rule]",
          attack["actual"].get("verdict") == "partial" and attack["actual"].get("achieved") == ["rule"])
    out = vaccine_engine.build_vaccine_candidates(reg)
    vac = next((v for v in out["vaccines"] if v["origin"]["attack_id"] == 10), None)
    check("partial: existe vaccine do ataque 10", vac is not None)
    vac = vac or {"id": None, "missing_sensors": None, "proposals": [], "origin": {"evidence": {}}}
    check("partial: id vac-d4586b217de9", vac["id"] == "vac-d4586b217de9")
    check("partial: missing_sensors [ml] e uma proposta ml",
          vac["missing_sensors"] == ["ml"] and [p["sensor"] for p in vac["proposals"]] == ["ml"])
    check("partial: evidência matched_event_ids [5140]", vac["origin"]["evidence"].get("matched_event_ids") == [5140])
    check("partial: validate_vaccine == []", vaccine_engine.validate_vaccine(vac) == [])
    invariant("partial: invariante do motor", out)

    # --- esgotamento (fail-closed) ---
    ex = tmp / "esgotado.jsonl"
    write_lines(ex, ['{"id": 999999999, "scenario": "smb_enum", "status": "launched"}'])
    check("esgotado: next_attack_id levanta AttackIdUnavailable", raises_unavailable(lambda: atk.next_attack_id(ex)) is not None)
    text_before = ex.read_bytes()
    with isolated(), mock.patch("shutil.which", return_value="/usr/bin/x"), \
            mock.patch("subprocess.run", return_value=ok_process()) as sp:
        msg = raises_unavailable(lambda: atk.run_scenario(SCENARIOS["smb_enum"], make_args(), ex))
        check("esgotado: run_scenario levanta AttackIdUnavailable", msg is not None)
        check("esgotado: subprocess.run não foi chamado", sp.call_count == 0)
        msg_out = raises_unavailable(lambda: atk.run_scenario(SCENARIOS["smb_enum"], make_args(target="192.168.1.10"), ex))
        check("esgotado: também antes da allowlist (alvo recusado não é escrito)", msg_out is not None)
    check("esgotado: o log fica igual", ex.read_bytes() == text_before)

    # --- ilegível ---
    folder = tmp / "pasta_log"
    folder.mkdir()
    msg = raises_unavailable(lambda: atk.next_attack_id(folder))
    check("log que é uma pasta: AttackIdUnavailable", msg is not None)
    check("a mensagem não traz o caminho completo", msg is not None and str(tmp) not in msg and "atribuir id" in msg)
    badbytes = tmp / "bytes.jsonl"
    badbytes.write_bytes(b"\xff\xfe\n" + b'{"id": 2}\n')
    check("bytes que não são UTF-8: AttackIdUnavailable", raises_unavailable(lambda: atk.next_attack_id(badbytes)) is not None)

    # --- CLI (subprocess verdadeiro: fora de qualquer mock) ---
    empty = new_dir()
    env = {k: v for k, v in os.environ.items() if k != "ATTACK_TARGETS_PATH"}
    kw = dict(capture_output=True, text=True, env=env, encoding="utf-8", errors="replace")
    script = str(Path(__file__).parent / "attack_scenarios.py")
    r = subprocess.run([sys.executable, script, "--log-path", str(empty), "--target", "192.0.2.20",
                        "--scenario", "smb_enum"], **kw)
    check("CLI: log ilegível sai com código 2", r.returncode == 2)
    check("CLI: mensagem 'atribuir id' no stderr", "atribuir id" in r.stderr)
    check("CLI: nada foi escrito na pasta", list(empty.iterdir()) == [])
    r = subprocess.run([sys.executable, script, "--self-check"], **kw)
    check("CLI: --self-check passa e confirma que grava id", r.returncode == 0 and "grava id" in r.stdout)

    # --- guarda do log real ---
    check("o attack_log.jsonl real não foi escrito (sha256 igual)", real_log_sha() == REAL_LOG_SHA.get("start"))


if __name__ == "__main__":
    run_tracer()
    run_ids()
    for tmp_dir in TMP_DIRS:
        shutil.rmtree(tmp_dir, ignore_errors=True)
    if failures:
        print(f"\n{len(failures)} verificação(ões) falharam")
        sys.exit(1)
    print("\nTodas as verificações passaram")
