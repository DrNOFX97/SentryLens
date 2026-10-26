"""
Teste do modo -ConfigureDefenderOnly de install-wazuh-agent.ps1: acrescenta ao
ossec.conf a recolha do canal do Defender, sem instalar nada. Corre o script
real (PowerShell) contra ficheiros ossec.conf de fixture numa pasta temporária;
nunca toca no ossec.conf do agente verdadeiro. Sem `powershell` no PATH falha
de propósito (mesmo critério dos testes que precisam de `node`).
Ver docs/superpowers/specs/2026-10-26-defender-events-design.md.

Correr (a partir de scripts/):
    python test_install_agent_defender.py
"""

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "install-wazuh-agent.ps1"
CANAL = "Microsoft-Windows-Windows Defender/Operational"
IDS = (1116, 1117, 1118, 1119, 5001, 5007, 5008)

SECURITY = """  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
  </localfile>
"""
UM_BLOCO = f"<ossec_config>\n{SECURITY}</ossec_config>\n"
DOIS_BLOCOS = (f"<ossec_config>\n{SECURITY}</ossec_config>\n\n"
               "<ossec_config>\n  <wodle name=\"x\"/>\n</ossec_config>\n")

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def correr(conf: Path) -> subprocess.CompletedProcess:
    powershell = shutil.which("powershell")
    if powershell is None:
        print("[FALHOU] powershell não está no PATH")
        sys.exit(1)
    return subprocess.run(
        [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(SCRIPT),
         "-ConfigureDefenderOnly", "-ConfPath", str(conf), "-NoRestart"],
        capture_output=True, text=True, timeout=60,
    )


def entradas(texto: str) -> int:
    return texto.count(f"<location>{CANAL}</location>")


def dentro_de_um_bloco(texto: str) -> bool:
    """A entrada do Defender está entre um <ossec_config> e o seu fecho."""
    for bloco in re.findall(r"<ossec_config>.*?</ossec_config>", texto, flags=re.S):
        if f"<location>{CANAL}</location>" in bloco:
            return True
    return False


def run_um_bloco(tmp: Path) -> None:
    conf = tmp / "um.conf"
    conf.write_text(UM_BLOCO, encoding="utf-8")
    r = correr(conf)
    texto = conf.read_text(encoding="utf-8")
    check("um bloco: exit code 0", r.returncode == 0)
    check("um bloco: exatamente 1 entrada do Defender", entradas(texto) == 1)
    resto = texto.split(CANAL, 1)[1] if CANAL in texto else ""
    check("um bloco: log_format eventchannel", "<log_format>eventchannel</log_format>" in resto[:200])
    query = re.search(r"<query>(.*?)</query>", resto, flags=re.S)
    check("um bloco: a query tem os 7 IDs",
          query is not None and all(f"EventID={i}" in query.group(1) for i in IDS))
    check("um bloco: entrada dentro de um <ossec_config>", dentro_de_um_bloco(texto))
    check("um bloco: o resto do ficheiro está intacto", SECURITY in texto)
    check("um bloco: sem BOM acrescentado", not conf.read_bytes().startswith(b"\xef\xbb\xbf"))

    primeira = conf.read_bytes()
    check("cópia de segurança com o conteúdo original",
          (tmp / "um.conf.bak-sentrylens").read_text(encoding="utf-8") == UM_BLOCO)
    r2 = correr(conf)
    check("2ª execução: exit code 0", r2.returncode == 0)
    check("2ª execução: continua 1 entrada e o ficheiro não muda", entradas(conf.read_text(encoding="utf-8")) == 1 and conf.read_bytes() == primeira)
    check("2ª execução: a cópia de segurança não é sobrescrita",
          (tmp / "um.conf.bak-sentrylens").read_text(encoding="utf-8") == UM_BLOCO)


def run_dois_blocos(tmp: Path) -> None:
    conf = tmp / "dois.conf"
    conf.write_text(DOIS_BLOCOS, encoding="utf-8")
    r = correr(conf)
    texto = conf.read_text(encoding="utf-8")
    check("dois blocos: exit code 0", r.returncode == 0)
    check("dois blocos: exatamente 1 entrada do Defender", entradas(texto) == 1)
    check("dois blocos: entrada dentro de um <ossec_config>", dentro_de_um_bloco(texto))
    check("dois blocos: continuam 2 fechos </ossec_config>", texto.count("</ossec_config>") == 2)


def run_ficheiro_inexistente(tmp: Path) -> None:
    falta = tmp / "nao-existe.conf"
    r = correr(falta)
    check("ficheiro inexistente: exit code != 0", r.returncode != 0)
    check("ficheiro inexistente: a mensagem diz o caminho", str(falta) in (r.stdout + r.stderr))


def run_bom() -> None:
    check("o .ps1 continua com BOM UTF-8", SCRIPT.read_bytes().startswith(b"\xef\xbb\xbf"))


with tempfile.TemporaryDirectory() as d:
    tmp = Path(d)
    run_um_bloco(tmp)
    run_dois_blocos(tmp)
    run_ficheiro_inexistente(tmp)
run_bom()

if failures:
    print(f"\n[FALHOU] {len(failures)} caso(s) falharam")
    sys.exit(1)
print("\n[OK] Todos os testes passaram")
