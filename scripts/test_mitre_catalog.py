"""
Testes da tabela técnica -> tática MITRE (R16, Phase 18): módulo puro
mitre_catalog.py (carregamento, validação fail-fast, cache, tactics_for,
parent_of) e a chamada a nível de módulo em main.py.

Sem laboratório Wazuh. Sem pytest: imprime [OK   ]/[FALHOU] por caso.

Correr (a partir de scripts/):
    python test_mitre_catalog.py
"""

import ast
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("SENTRYLENS_API_KEY", "test-key-mitre-catalog")

import yaml

import attack_scenarios
import main
import mitre_catalog as mc

main.app.router.on_startup.clear()

# D-10: técnicas vistas em rule.mitre nos snapshots do lab. Escritas aqui de
# propósito: scripts/snapshots/ está no .gitignore e o teste não o lê.
D10_OBSERVED = ("T1078", "T1021", "T1550.002", "T1078.002", "T1484", "T1531")
# D-01: técnicas do catálogo de Event IDs (independente do estado de event_catalog.py).
D01_CATALOG = ("T1110", "T1053.005", "T1136.001", "T1098", "T1562.002", "T1531")
# D-05: conteúdo da tabela fixado por literal (ATT&CK Enterprise v18.1).
EXPECTED_TABLE = {
    "T1021": ["Lateral Movement"],
    "T1053": ["Execution", "Persistence", "Privilege Escalation"],
    "T1053.005": ["Execution", "Persistence", "Privilege Escalation"],
    "T1078": ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"],
    "T1078.002": ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"],
    "T1098": ["Persistence", "Privilege Escalation"],
    "T1110": ["Credential Access"],
    "T1110.003": ["Credential Access"],
    "T1135": ["Discovery"],
    "T1136": ["Persistence"],
    "T1136.001": ["Persistence"],
    "T1484": ["Privilege Escalation", "Defense Evasion"],
    "T1531": ["Impact"],
    "T1550": ["Defense Evasion", "Lateral Movement"],
    "T1550.002": ["Defense Evasion", "Lateral Movement"],
    "T1562": ["Defense Evasion"],
    "T1562.002": ["Defense Evasion"],
}

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def run_tracer() -> None:
    """Fatia fina de ponta a ponta: tabela real -> cache criada no arranque
    do main -> tactics_for/parent_of."""
    # Antes de qualquer reset_cache: prova que o main.py a carregou no arranque.
    check("arranque: a cache vem da tabela por omissão", mc._cache_path == mc.DEFAULT_PATH)
    check("arranque: a cache tem 17 técnicas", mc._cache is not None and len(mc._cache) == 17)

    check("tactics_for('T1110') == ['Credential Access']", mc.tactics_for("T1110") == ["Credential Access"])
    check("sub-técnica sem linha própria herda do pai (T1110.001)",
          mc.tactics_for("T1110.001") == ["Credential Access"])
    check("T1078 tem as 4 táticas",
          mc.tactics_for("T1078") == ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"])
    check("técnica sem entrada nem pai (T1059) -> []", mc.tactics_for("T1059") == [])

    check("parent_of('T1053.005') == 'T1053'", mc.parent_of("T1053.005") == "T1053")
    check("parent_of('T1053') == 'T1053'", mc.parent_of("T1053") == "T1053")
    check("parent_of('lixo') is None", mc.parent_of("lixo") is None)
    check("parent_of(None) is None", mc.parent_of(None) is None)

    first = mc.tactics_for("T1110")
    first.append("Impact")
    check("tactics_for devolve sempre uma lista nova", mc.tactics_for("T1110") == ["Credential Access"])


def write_yaml(tmp_dir: Path, data, name: str = "mitre.yaml") -> Path:
    path = tmp_dir / name
    path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return path


def entry(**overrides) -> dict:
    base = {"id": "T1110", "name": "Brute Force", "tactics": ["Credential Access"]}
    base.update(overrides)
    return base


def has_problem(problems: list[str], *words: str) -> bool:
    return any(all(w in p for w in words) for p in problems)


def load_problems(path: Path, **kwargs) -> list[str] | None:
    """Problemas do ValueError, ou None se carregou sem erro."""
    try:
        mc.load_mitre_techniques(path, use_cache=False, **kwargs)
    except ValueError as exc:
        return exc.args[0]
    return None


def run_validation() -> None:
    mc.reset_cache()
    v = mc.validate_technique_entry

    check("entrada válida: sem problemas", v(1, entry()) == [])
    check("entrada que não é dict: 1 problema", len(v(1, "T1110")) == 1)
    no_name = entry()
    del no_name["name"]
    check("sem name: problema com 'name' e 'falta'", has_problem(v(1, no_name), "name", "falta"))
    typo = {"id": "T1110", "name": "Brute Force", "tactic": ["Credential Access"]}
    typo_problems = v(1, typo)
    check("'tactic' em vez de 'tactics': 'desconhecido' e 'tactics'",
          has_problem(typo_problems, "desconhecido") and has_problem(typo_problems, "tactics"))

    for bad_id in ("T110", "t1110", "T1110.01", "T1110\n", "T1110.0001", 1110):
        check(f"id inválido {bad_id!r} é rejeitado", has_problem(v(1, entry(id=bad_id)), "id"))
    for bad_name in ("", 5, "x" * 129):
        check(f"name inválido {str(bad_name)[:8]!r} é rejeitado", has_problem(v(1, entry(name=bad_name)), "name"))
    check("name com 128 caracteres é aceite", v(1, entry(name="x" * 128)) == [])
    for bad_tactics in ([], "Credential Access", ["Lateral Movment"], ["Credential Access", "Credential Access"]):
        check(f"tactics inválido {bad_tactics!r} é rejeitado", has_problem(v(1, entry(tactics=bad_tactics)), "tactics"))
    check("as 14 táticas Enterprise", len(mc.ENTERPRISE_TACTICS) == 14)

    tmp = Path(tempfile.mkdtemp())

    dup = write_yaml(tmp, [entry(), entry(name="Outro")], "dup.yaml")
    problems = load_problems(dup)
    check("id duplicado: ValueError com 'duplicado' e o id",
          problems is not None and has_problem(problems, "duplicado", "T1110"))

    check("topo dict: ValueError", load_problems(write_yaml(tmp, {"T1110": entry()}, "dict.yaml")) is not None)
    check("topo lista vazia: ValueError", load_problems(write_yaml(tmp, [], "empty_list.yaml")) is not None)
    none_path = tmp / "none.yaml"
    none_path.write_text("", encoding="utf-8")
    check("ficheiro vazio: ValueError", load_problems(none_path) is not None)
    bad_yaml = tmp / "bad.yaml"
    bad_yaml.write_text("- id: [T1110\n  name: x", encoding="utf-8")
    check("YAML malformado: ValueError", load_problems(bad_yaml) is not None)
    check("ficheiro em falta: ValueError", load_problems(tmp / "nao_existe.yaml") is not None)

    two_bad = write_yaml(tmp, [entry(id="lixo"), entry(id="T1111", tactics=["Nope"])], "two_bad.yaml")
    problems = load_problems(two_bad)
    check("duas entradas inválidas: acumula pelo menos 2 frases", problems is not None and len(problems) >= 2)

    # Cobertura (D-11): técnicas de SCENARIOS e CRITICAL_EVENTS têm de ter táticas.
    only_t1110 = write_yaml(tmp, [entry()], "only_t1110.yaml")
    problems = load_problems(
        only_t1110, scenarios={"x": SimpleNamespace(mitre_technique="T1046", mitre_tactic="Discovery")}, catalog={}
    )
    check("cenário com técnica fora da tabela: cita 'T1046' e 'x'",
          problems is not None and has_problem(problems, "T1046", "x"))
    problems = load_problems(
        only_t1110,
        scenarios={"y": SimpleNamespace(mitre_technique="T1110.003", mitre_tactic="Credential Access")},
        catalog={},
    )
    check("cenário com sub-técnica herda do pai: carrega", problems is None)
    problems = load_problems(only_t1110, scenarios={}, catalog={4625: {"technique_id": "T9999"}})
    check("catálogo com técnica fora da tabela: cita '4625' e 'T9999'",
          problems is not None and has_problem(problems, "4625", "T9999"))
    problems = load_problems(only_t1110, scenarios={}, catalog={4625: {"technique_id": "T111O"}})
    check("catálogo com técnica em formato inválido: ValueError de formato",
          problems is not None and has_problem(problems, "4625", "formato"))
    problems = load_problems(only_t1110, scenarios={}, catalog={4625: {"name": "x"}, 4624: "texto"})
    check("catálogo sem technique_id: carrega", problems is None)

    mc.reset_cache()
    mc.load_mitre_techniques(only_t1110, scenarios={}, catalog={})
    check("com dados injetados a cache fica vazia", mc._cache is None)

    # Caminho
    check("_resolve_path relativo resolve-se contra a pasta do módulo",
          mc._resolve_path("mitre_techniques.yaml") == Path(mc.__file__).parent / "mitre_techniques.yaml")
    previous = os.environ.get(mc.PATH_ENV_VAR)
    os.environ[mc.PATH_ENV_VAR] = str(only_t1110)
    try:
        check("_resolve_path(None) usa MITRE_TECHNIQUES_PATH", mc._resolve_path(None) == only_t1110)
    finally:
        if previous is None:
            os.environ.pop(mc.PATH_ENV_VAR, None)
        else:
            os.environ[mc.PATH_ENV_VAR] = previous
    mc.reset_cache()

    # Arranque do backend: tabela inválida impede `import main`; válida deixa.
    here = Path(__file__).resolve().parent
    invalid = write_yaml(tmp, [entry(tactics=["Lateral Movment"])], "invalid_boot.yaml")
    valid_copy = tmp / "valid_boot.yaml"
    valid_copy.write_text(mc.DEFAULT_PATH.read_text(encoding="utf-8"), encoding="utf-8")

    def boot(table_path: Path) -> subprocess.CompletedProcess:
        env = dict(os.environ, SENTRYLENS_API_KEY="test-key-mitre-boot",
                   MITRE_TECHNIQUES_PATH=str(table_path), PYTHONIOENCODING="utf-8")
        return subprocess.run([sys.executable, "-X", "utf8", "-c", "import main"], cwd=here, env=env,
                              capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)

    bad = boot(invalid)
    check("import main com tabela inválida: código != 0", bad.returncode != 0)
    check("import main com tabela inválida: ValueError e a tática no stderr",
          "ValueError" in bad.stderr and "Lateral Movment" in bad.stderr)
    good = boot(valid_copy)
    check("import main com cópia válida da tabela: código 0", good.returncode == 0)


def scenario_tactic_problems(scenarios, table) -> list[str]:
    """D-07: cenários cuja mitre_tactic não é uma das táticas que a tabela
    lista para a sua técnica (ou para o pai)."""
    problems = []
    for name, scenario in scenarios.items():
        allowed = mc.tactics_for(scenario.mitre_technique, table)
        if scenario.mitre_tactic not in allowed:
            problems.append(f"{name}: '{scenario.mitre_tactic}' não está em {allowed} para {scenario.mitre_technique}")
    return problems


def run_completeness_and_coherence() -> None:
    table = mc.load_mitre_techniques(use_cache=False)

    for technique in D10_OBSERVED:
        check(f"D-10: {technique} tem entrada própria", technique in table)
    for technique in D01_CATALOG:
        check(f"D-01: {technique} tem entrada própria", technique in table)

    actual = {tid: list(e["tactics"]) for tid, e in table.items()}
    check("D-05: a tabela real é igual às 17 linhas literais", actual == EXPECTED_TABLE)

    for tid, e in table.items():
        if "." not in tid:
            continue
        parent = mc.parent_of(tid)
        check(f"{tid}: o pai {parent} tem entrada própria", parent in table)
        check(f"{tid}: táticas contidas nas do pai",
              parent in table and set(e["tactics"]) <= set(table[parent]["tactics"]))

    all_tactics = {t for e in table.values() for t in e["tactics"]}
    check("todas as táticas da tabela estão em ENTERPRISE_TACTICS", all_tactics <= set(mc.ENTERPRISE_TACTICS))
    check("'Defense Evasion' está em ENTERPRISE_TACTICS (vocabulário v18.1)", "Defense Evasion" in mc.ENTERPRISE_TACTICS)

    # D-07: coerência cenário -> tabela
    check("D-07: os cenários reais declaram táticas que a tabela lista",
          scenario_tactic_problems(attack_scenarios.SCENARIOS, table) == [])
    fake = {"fake": SimpleNamespace(mitre_technique="T1053", mitre_tactic="Lateral Movement")}
    check("D-07: tática errada para T1053 é detetada", len(scenario_tactic_problems(fake, table)) == 1)
    fake = {"fake": SimpleNamespace(mitre_technique="T1110.003", mitre_tactic="Credential Access")}
    check("D-07: tática pelo pai (T1110.003) é aceite", scenario_tactic_problems(fake, table) == [])

    # D-08: o módulo só abre a tabela, em leitura.
    tree = ast.parse(Path(mc.__file__).read_text(encoding="utf-8"))
    opens = [n for n in ast.walk(tree)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "open"]
    check("D-08: mitre_catalog.py tem exatamente 1 chamada a open()", len(opens) == 1)

    def is_write_mode(call: ast.Call) -> bool:
        modes = [a for a in call.args[1:2]] + [k.value for k in call.keywords if k.arg == "mode"]
        return any(isinstance(m, ast.Constant) and isinstance(m.value, str) and set(m.value) & set("wax+")
                   for m in modes)

    check("D-08: nenhum open() em modo de escrita", not any(is_write_mode(c) for c in opens))


def run() -> None:
    run_tracer()
    run_validation()
    run_completeness_and_coherence()


run()

if failures:
    print(f"\n{len(failures)} verificação(ões) falharam")
    sys.exit(1)
print("\nTodos os testes passaram")
