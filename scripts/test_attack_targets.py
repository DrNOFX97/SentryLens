"""
Testes da allowlist de alvos de attack_scenarios.py (R5). Sem lançar ataques,
sem rede, só IPs de documentação (192.0.2.x / 203.0.113.x / 198.51.100.x).

Correr (a partir de scripts/):
    python test_attack_targets.py
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import attack_scenarios as atk

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def refused(target, allowlist=None) -> str | None:
    try:
        atk.check_target_allowed(target, allowlist)
    except atk.TargetNotAllowed as exc:
        return str(exc)
    return None


def write(tmp: Path, name: str, content) -> Path:
    path = tmp / name
    path.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
    return path


def run() -> None:
    os.environ.pop("ATTACK_TARGETS_PATH", None)
    tmp = Path(tempfile.mkdtemp())

    with mock.patch.object(atk, "DEFAULT_TARGETS_PATH", tmp / "ausente.json"):
        default = atk.load_target_allowlist()
        check("sem ficheiro: allowlist built-in", default["source"] == "builtin")
        for ok in ("127.0.0.1", "::1", "192.0.2.20", "198.51.100.4", "203.0.113.200", "2001:db8::5"):
            check(f"default aceita {ok}", refused(ok, default) is None)
        for bad in ("192.168.1.10", "10.0.0.5", "8.8.8.8", "alvo-lab.example", "", "  ", "192.0.2.20/24",
                    "192.0.2.20; rm -rf /"):
            check(f"default recusa {bad!r}", refused(bad, default) is not None)
        msg = refused("192.168.1.10", default) or ""
        check("mensagem de recusa e clara (menciona ATTACK_TARGETS_PATH e --allow-any-target)",
              "ATTACK_TARGETS_PATH" in msg and "--allow-any-target" in msg)

        cfg = write(tmp, "t.json", {"allowed_networks": ["198.18.0.0/24"], "allowed_hosts": ["Lab-Host.example"]})
        al = atk.load_target_allowlist(cfg)
        check("ficheiro: rede configurada aceite", refused("198.18.0.7", al) is None)
        check("ficheiro: hostname configurado aceite (case-insensitive)", refused("lab-host.example", al) is None)
        check("ficheiro: built-ins mantêm-se", refused("192.0.2.9", al) is None)
        check("ficheiro: IP fora continua recusado", refused("198.19.0.7", al) is not None)
        check("ficheiro: hostname fora recusado", refused("outro.example", al) is not None)

        with mock.patch.dict(os.environ, {"ATTACK_TARGETS_PATH": str(cfg)}):
            check("ATTACK_TARGETS_PATH é lida", refused("198.18.0.7", atk.load_target_allowlist()) is None)

        ex = atk.load_target_allowlist(Path(__file__).parent / "attack_targets.example.json")
        check("attack_targets.example.json carrega (rede de documentação + host de exemplo)",
              refused("203.0.113.9", ex) is None and "alvo-lab.example" in ex["hosts"])

        for label, content in [
            ("JSON corrompido", "{nao json"),
            ("não é objeto", "[1]"),
            ("allowed_networks não é lista", {"allowed_networks": "192.0.2.0/24"}),
            ("rede inválida", {"allowed_networks": ["não-é-ip"]}),
            ("rede demasiado larga (0.0.0.0/0)", {"allowed_networks": ["0.0.0.0/0"]}),
            ("rede demasiado larga (10.0.0.0/8)", {"allowed_networks": ["10.0.0.0/8"]}),
            ("hostname inválido", {"allowed_hosts": ["a b;c"]}),
        ]:
            try:
                atk.load_target_allowlist(write(tmp, "bad.json", content))
                check(f"allowlist inválida rejeitada: {label}", False)
            except atk.TargetNotAllowed:
                check(f"allowlist inválida rejeitada: {label}", True)
        try:
            atk.load_target_allowlist(tmp / "nao-existe.json")
            check("ficheiro configurado inexistente -> erro (não ignora)", False)
        except atk.TargetNotAllowed as exc:
            check("ficheiro configurado inexistente -> erro (não ignora)", True)
            check("erro não expõe o caminho completo", str(tmp) not in str(exc))

        log = tmp / "log.jsonl"
        args = SimpleNamespace(target="192.168.1.10", user=None, password=None, wordlist=None, timeout=5)
        scenario = atk.SCENARIOS["smb_enum"]
        with mock.patch("shutil.which", return_value="/usr/bin/x"), mock.patch("subprocess.run") as sp:
            entry = atk.run_scenario(scenario, args, log)
            check("run_scenario recusa alvo fora da allowlist: status skipped", entry["status"] == "skipped")
            check("run_scenario recusado: reason target_not_allowed", entry["details"].get("reason") == "target_not_allowed")
            check("run_scenario recusado: subprocess NÃO foi chamado", sp.call_count == 0)
            check("run_scenario recusado: entrada gravada no log",
                  log.exists() and "target_not_allowed" in log.read_text(encoding="utf-8"))

            sp.return_value = subprocess.CompletedProcess([], 0, "", "")
            args_ok = SimpleNamespace(target="192.0.2.20", user=None, password=None, wordlist=None, timeout=5)
            entry_ok = atk.run_scenario(scenario, args_ok, log)
            check("compat.: alvo de documentação continua a lançar (sem flags novas)", entry_ok["status"] == "launched")

            args_flag = SimpleNamespace(target="192.168.1.10", user=None, password=None, wordlist=None, timeout=5,
                                        allow_any_target=True)
            entry_flag = atk.run_scenario(scenario, args_flag, log)
            check("--allow-any-target é o override explícito", entry_flag["status"] == "launched")

    cli = [sys.executable, str(Path(__file__).parent / "attack_scenarios.py"), "--log-path", str(tmp / "cli.jsonl")]
    env = {k: v for k, v in os.environ.items() if k != "ATTACK_TARGETS_PATH"}
    kw = dict(capture_output=True, text=True, env=env, encoding="utf-8", errors="replace")
    r = subprocess.run(cli + ["--target", "192.168.1.10", "--scenario", "smb_enum"], **kw)
    check("CLI: alvo não permitido sai com código 2 e mensagem", r.returncode == 2 and "recusado" in r.stderr)
    check("CLI: nada gravado no log quando recusado", not (tmp / "cli.jsonl").exists())
    r = subprocess.run(cli + ["--list"], **kw)
    check("CLI: --list continua a funcionar sem --target", r.returncode == 0)
    r = subprocess.run(cli + ["--self-check"], **kw)
    check("CLI: --self-check continua a passar", r.returncode == 0)


run()
if failures:
    print(f"\n{len(failures)} verificação(ões) falharam")
    sys.exit(1)
print("\nTodos os testes passaram")
