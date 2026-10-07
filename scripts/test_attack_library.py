"""
Testes da Attack Library (R5): módulo puro attack_library.py (validação,
merge com SCENARIOS, cache) e as rotas GET /api/attack-library[/{id}].

Sem laboratório Wazuh. Só IPs de documentação (192.0.2.x / 203.0.113.x) —
na prática este módulo nem lida com IPs, mas segue a convenção do projeto.

Correr (a partir de scripts/):
    python test_attack_library.py
"""

import json
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("SENTRYLENS_API_KEY", "test-key-attack-library")

import yaml
from fastapi.testclient import TestClient

import attack_library as al
import main
from attack_scenarios import SCENARIOS

main.app.router.on_startup.clear()
client = TestClient(main.app)
HEADERS = {"X-API-Key": os.environ["SENTRYLENS_API_KEY"]}

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


VALID_ENTRY = {
    "name": "Cenário de teste",
    "description": "Descrição de teste.",
    "risk": "medium",
    "prerequisites": "Nenhum.",
    "expected_sensors": ["rule", "ml"],
    "cleanup_steps": ["Passo de limpeza."],
    "replayable": True,
    "replayable_reason": "Motivo.",
    "duration_estimate": "seconds",
}

FAKE_SCENARIOS = {
    "brute_force_rdp": SimpleNamespace(mitre_tactic="Credential Access", mitre_technique="T1110", tool="hydra", event_ids=[4625]),
}


def write_yaml(tmp_dir: Path, data: dict, name: str = "lib.yaml") -> Path:
    path = tmp_dir / name
    path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return path


def test_validate_entry() -> None:
    problems = al.validate_entry("brute_force_rdp", dict(VALID_ENTRY), FAKE_SCENARIOS)
    check("entrada válida: sem problemas", problems == [])

    entry = dict(VALID_ENTRY)
    del entry["risk"]
    check("campo obrigatório em falta ('risk') é identificado",
          any("risk" in p and "falta" in p for p in al.validate_entry("brute_force_rdp", entry, FAKE_SCENARIOS)))

    entry = dict(VALID_ENTRY, risk="critical")
    check("risk fora da taxonomia é rejeitado",
          any("risk" in p for p in al.validate_entry("brute_force_rdp", entry, FAKE_SCENARIOS)))

    entry = dict(VALID_ENTRY, duration_estimate="hours")
    check("duration_estimate fora da taxonomia é rejeitado",
          any("duration_estimate" in p for p in al.validate_entry("brute_force_rdp", entry, FAKE_SCENARIOS)))

    entry = dict(VALID_ENTRY, expected_sensors=["rule", "quantum"])
    check("expected_sensors com valor fora da allowlist é rejeitado",
          any("expected_sensors" in p for p in al.validate_entry("brute_force_rdp", entry, FAKE_SCENARIOS)))

    bad_scenarios = {"brute_force_rdp": SimpleNamespace(mitre_tactic="x", mitre_technique="BAD", tool="x", event_ids=[])}
    check("técnica MITRE fora do formato Txxxx(.xxx) é rejeitada (herdada de SCENARIOS)",
          any("mitre_technique" in p for p in al.validate_entry("brute_force_rdp", VALID_ENTRY, bad_scenarios)))

    check("entrada sem par em SCENARIOS é erro",
          any("sem par" in p for p in al.validate_entry("cenario_inexistente", VALID_ENTRY, FAKE_SCENARIOS)))

    # Incoerências risco/replayable/cleanup (ruling do utilizador)
    entry = dict(VALID_ENTRY, risk="low", replayable=False)
    check("risk=low com replayable=false é incoerência rejeitada",
          any("incoerente" in p for p in al.validate_entry("brute_force_rdp", entry, FAKE_SCENARIOS)))

    entry = dict(VALID_ENTRY, risk="low", cleanup_steps=[])
    check("risk=low com cleanup_steps vazio é incoerência rejeitada",
          any("incoerente" in p for p in al.validate_entry("brute_force_rdp", entry, FAKE_SCENARIOS)))

    entry = dict(VALID_ENTRY, risk="high", replayable=False)
    check("risk=high com replayable=false é coerente (sem problemas)",
          al.validate_entry("brute_force_rdp", entry, FAKE_SCENARIOS) == [])


def test_load_attack_library_real_file() -> None:
    al.reset_cache()
    lib = al.load_attack_library(use_cache=False)
    check("YAML real: carrega sem erros", isinstance(lib, dict))
    check("YAML real: uma entrada por cenário de SCENARIOS", set(lib) == set(SCENARIOS))
    for name, entry in lib.items():
        for field in ("id", "name", "description", "mitre_technique", "tool", "risk", "prerequisites",
                      "expected_sensors", "cleanup_steps", "replayable", "replayable_reason", "duration_estimate"):
            check(f"YAML real: '{name}' tem campo '{field}'", field in entry)
        check(f"YAML real: '{name}'.id == scenario_name", entry["id"] == name)
        check(f"YAML real: '{name}'.mitre_technique vem de SCENARIOS", entry["mitre_technique"] == SCENARIOS[name].mitre_technique)
    check("YAML real: nenhum campo expõe argv/comando executável",
          all("build_command" not in entry and "command" not in entry and "argv" not in entry for entry in lib.values()))
    al.reset_cache()


def test_load_attack_library_invalid() -> None:
    tmp = Path(tempfile.mkdtemp())

    # Campo obrigatório em falta
    data = {name: dict(VALID_ENTRY) for name in SCENARIOS}
    del data["smb_enum"]["risk"]
    path = write_yaml(tmp, data)
    try:
        al.load_attack_library(path, use_cache=False)
        check("campo em falta: ValueError levantado", False)
    except ValueError as exc:
        problems = exc.args[0]
        check("campo em falta: ValueError levantado e identifica o campo",
              any("smb_enum" in p and "risk" in p for p in problems))

    # Técnica MITRE inválida herdada de SCENARIOS: simula substituindo o YAML
    # por uma entrada cujo scenario_name não existe em SCENARIOS (mesmo efeito
    # de teste: o validador tem de reportar e não travar a leitura do YAML).
    data = {name: dict(VALID_ENTRY) for name in SCENARIOS}
    data["scenario_fantasma"] = dict(VALID_ENTRY)
    path = write_yaml(tmp, data)
    try:
        al.load_attack_library(path, use_cache=False)
        check("entrada extra sem par em SCENARIOS: ValueError levantado", False)
    except ValueError as exc:
        check("entrada extra sem par em SCENARIOS: identificada na mensagem",
              any("scenario_fantasma" in p for p in exc.args[0]))

    # risk inválido
    data = {name: dict(VALID_ENTRY) for name in SCENARIOS}
    data["smb_enum"]["risk"] = "catastrophic"
    path = write_yaml(tmp, data)
    try:
        al.load_attack_library(path, use_cache=False)
        check("risk inválido: ValueError levantado", False)
    except ValueError as exc:
        check("risk inválido: identificado na mensagem", any("risk" in p for p in exc.args[0]))

    # incoerência risk/replayable
    data = {name: dict(VALID_ENTRY) for name in SCENARIOS}
    data["smb_enum"]["risk"] = "low"
    data["smb_enum"]["replayable"] = False
    path = write_yaml(tmp, data)
    try:
        al.load_attack_library(path, use_cache=False)
        check("incoerência risk=low/replayable=false: ValueError levantado", False)
    except ValueError as exc:
        check("incoerência risk=low/replayable=false: identificada", any("incoerente" in p for p in exc.args[0]))

    # YAML corrompido
    bad_path = tmp / "corrupt.yaml"
    bad_path.write_text("isto: nao: fecha: [", encoding="utf-8")
    try:
        al.load_attack_library(bad_path, use_cache=False)
        check("YAML corrompido: ValueError levantado", False)
    except ValueError:
        check("YAML corrompido: ValueError levantado", True)

    # Ficheiro ausente
    try:
        al.load_attack_library(tmp / "nao-existe.yaml", use_cache=False)
        check("ficheiro ausente: ValueError levantado", False)
    except ValueError:
        check("ficheiro ausente: ValueError levantado", True)

    # Topo não é mapa
    not_map = tmp / "list.yaml"
    not_map.write_text("- 1\n- 2\n", encoding="utf-8")
    try:
        al.load_attack_library(not_map, use_cache=False)
        check("topo não é mapa: ValueError levantado", False)
    except ValueError:
        check("topo não é mapa: ValueError levantado", True)


def test_get_expected_sensors_integration() -> None:
    al.reset_cache()
    sensors = al.get_expected_sensors("brute_force_rdp")
    check("get_expected_sensors: devolve a lista da biblioteca", set(sensors) <= set(al.EXPECTED_SOURCES) and sensors)
    check("get_expected_sensors: cenário sem entrada devolve lista vazia", al.get_expected_sensors("nao_existe") == [])


def test_routes() -> None:
    r = client.get("/api/attack-library")
    check("GET /api/attack-library sem API key -> 401", r.status_code == 401)

    r = client.get("/api/attack-library", headers=HEADERS)
    check("GET /api/attack-library com API key -> 200", r.status_code == 200)
    body = r.json()
    check("GET /api/attack-library: total == len(SCENARIOS)", body["total"] == len(SCENARIOS))
    check("GET /api/attack-library: entries com o mesmo tamanho", len(body["entries"]) == len(SCENARIOS))
    check("GET /api/attack-library: nenhuma entrada expõe comando executável",
          all("command" not in e and "build_command" not in e and "argv" not in e for e in body["entries"]))

    one_id = body["entries"][0]["id"]
    r = client.get(f"/api/attack-library/{one_id}", headers=HEADERS)
    check("GET /api/attack-library/{id} válido -> 200", r.status_code == 200)
    check("GET /api/attack-library/{id} válido: id coincide", r.json()["id"] == one_id)

    r = client.get("/api/attack-library/nao_existe_de_certeza", headers=HEADERS)
    check("GET /api/attack-library/{id} inexistente -> 404", r.status_code == 404)
    check("GET /api/attack-library/{id} inexistente: código estável 'entry_not_found'",
          r.json().get("detail", {}).get("code") == "entry_not_found" if isinstance(r.json().get("detail"), dict)
          else "entry_not_found" in json.dumps(r.json()))

    # "../etc/passwd" é deliberadamente omitido daqui: o cliente HTTP normaliza
    # o path antes do pedido (RFC 3986), por isso nunca chega ao nosso regex —
    # cai noutra rota inexistente e dá 404 por si só, sem risco de traversal.
    for bad_id in ("Maiusculas", "com espaco", "a" * 65, "com;ponto-e-virgula"):
        r = client.get(f"/api/attack-library/{bad_id}", headers=HEADERS)
        check(f"GET /api/attack-library/{{id}} malformado ({bad_id!r}) -> 422", r.status_code == 422)

    r = client.get("/api/attack-library/nao_existe_de_certeza")
    check("GET /api/attack-library/{id} sem API key -> 401", r.status_code == 401)


def run() -> None:
    test_validate_entry()
    test_load_attack_library_real_file()
    test_load_attack_library_invalid()

    import contextlib
    import io
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        tmp = Path(tempfile.mkdtemp())
        data = {name: dict(VALID_ENTRY) for name in SCENARIOS if name != "smb_enum"}
        path = write_yaml(tmp, data)
        lib = al.load_attack_library(path, use_cache=False)
    captured_err = buf.getvalue()
    check("cenário sem entrada na biblioteca: não trava o arranque", set(lib) == set(SCENARIOS) - {"smb_enum"})
    check("cenário sem entrada: aviso não-bloqueante impresso", "smb_enum" in captured_err and "AVISO" in captured_err)

    al.reset_cache()
    test_get_expected_sensors_integration()
    al.reset_cache()
    test_routes()
    al.reset_cache()


run()
if failures:
    print(f"\n{len(failures)} verificação(ões) falharam")
    sys.exit(1)
print("\nTodos os testes passaram")
