"""
Contrato estático da aba Vaccines (R11/R12) sobre os ficheiros SERVIDOS
pelo serve_frontend.py, ligado às chaves reais das rotas de vaccines. Sem
browser e sem Wazuh: lê o texto de vaccines.js e do index.html tal como o
servidor estático os entrega e compara cada campo que vaccines.js (e os
helpers slVac* do ui_helpers.js) lê de um objeto da API com as chaves da
resposta REAL da rota (TestClient sobre um store temporário semeado pelo
motor de vaccines). Apanha, por exemplo, `created` em vez de `created_at`
sem precisar de um browser.

O único JavaScript executado é o ui_helpers.js, em node:vm (sem DOM): serve
para provar que o corpo que slVacDecisionBody constrói é aceite pela rota
real de decisão e que slVacAnalystOptions lê campos reais. Sem node no PATH
estes checks falham de propósito.

Segue o estilo de test_serve_frontend.py: standalone, check()/[OK]/[FALHOU],
sys.exit(1) em caso de falha.

Correr (a partir de scripts/):
    python test_vaccines_frontend.py
"""

import http.client
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import typing
from http.server import HTTPServer
from pathlib import Path

os.environ.setdefault("SENTRYLENS_API_KEY", "test-key-vaccines-frontend")

from fastapi.testclient import TestClient

import main
import serve_frontend
import vaccine_engine
import vaccine_ingest
from incident_store import IncidentStore
from vaccine_store import VaccineStore

main.app.router.on_startup.clear()
client = TestClient(main.app)
HEADERS = {"X-API-Key": os.environ["SENTRYLENS_API_KEY"]}

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def get(port: int, path: str, headers: dict | None = None) -> tuple[int, dict, str]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    # putheader manual para controlar Host (http.client põe o seu por omissão).
    conn.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
    sent = dict(headers or {})
    sent.setdefault("Host", f"127.0.0.1:{port}")
    for name, value in sent.items():
        conn.putheader(name, value)
    conn.endheaders()
    resp = conn.getresponse()
    body = resp.read().decode("utf-8", errors="replace")
    result = (resp.status, {k.lower(): v for k, v in resp.getheaders()}, body)
    conn.close()
    return result


# --- helpers ---------------------------------------------------------------

SERVED_PATHS = ("/index.html", "/vaccines.js", "/app.js", "/style.css", "/ui_helpers.js", "/api.js")


def served() -> dict[str, tuple[int, dict, str]]:
    """Sobe o servidor estático real numa porta efémera e devolve, por caminho,
    (estado, cabeçalhos, texto) dos ficheiros que a aba usa."""
    server = HTTPServer(("127.0.0.1", 0), serve_frontend.FrontendHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        return {path: get(port, path) for path in SERVED_PATHS}
    finally:
        server.shutdown()
        server.server_close()


def function_body(js: str, name: str) -> str:
    """Texto de `function <name>(` até à primeira linha que é só `}` (as
    funções de topo fecham na coluna 0). Vazio se a função não existir."""
    start = js.find(f"function {name}(")
    if start == -1:
        return ""
    end = re.search(r"^\}\s*$", js[start:], re.M)
    return js[start:start + end.end()] if end else js[start:]


_NODE_SCRIPT = r"""
const fs = require("node:fs");
const vm = require("node:vm");
const ctx = vm.createContext({});
vm.runInContext(fs.readFileSync(process.argv[1], "utf8"), ctx, { filename: process.argv[1] });
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => { input += chunk; });
process.stdin.on("end", () => {
  const out = JSON.parse(input).map(([name, args]) => JSON.stringify(ctx[name](...args)));
  process.stdout.write("[" + out.join(",") + "]");
});
"""


def node_ui_helpers(calls):
    """Corre funções do ui_helpers.js REAL em node:vm (sem DOM) e devolve os
    resultados, um por chamada `[nome_da_função, [args...]]`. Devolve None sem
    node no PATH ou se o node falhar (quem chama decide se isso é uma falha)."""
    node = shutil.which("node")
    if node is None:
        return None
    helpers = str(serve_frontend.PROJECT_ROOT / "ui_helpers.js")
    proc = subprocess.run([node, "-e", _NODE_SCRIPT, helpers], input=json.dumps(calls), capture_output=True,
                          text=True, encoding="utf-8", timeout=60)
    if proc.returncode != 0:
        print(proc.stderr)
        return None
    return json.loads(proc.stdout)


API_VARS = ("envelope", "vaccine", "origin", "evidence", "proposal", "rule",
            "catalogEvent", "generator", "counts", "decision", "analyst")
_ACCESS_RE = re.compile(r"\b(" + "|".join(API_VARS) + r")\s*\??\.\s*([A-Za-z_$][\w$]*)")


def data_accesses(js: str) -> set[tuple[str, str]]:
    """Pares (variável, propriedade) lidos de objetos vindos da API."""
    return set(_ACCESS_RE.findall(js))


def sl_vac_bodies(ui_js: str) -> str:
    """Corpos concatenados das funções slVac* do ui_helpers.js (os helpers puros
    da aba Vaccines): também leem campos de objetos da API."""
    nomes = re.findall(r"^function (slVac\w+)\(", ui_js, re.M)
    return "\n".join(function_body(ui_js, nome) for nome in nomes)


def field_accesses(files: dict) -> set[tuple[str, str]]:
    """Campos lidos de objetos da API por vaccines.js e pelos helpers slVac*."""
    return data_accesses(files["/vaccines.js"][2]) | data_accesses(sl_vac_bodies(files["/ui_helpers.js"][2]))


def make_attack(attack_id, verdict, expected, achieved, scenario="smb_enum", event_ids=(5140, 5145),
                duplicate_id=False, expected_source="scenario_default", correlation_reason=None,
                technique="T1135", incidents=()) -> dict:
    """Dict com a mesma forma de um ataque de build_attack_registry."""
    return {
        "id": attack_id,
        "duplicate_id": duplicate_id,
        "timestamp": "2026-10-12T09:00:00+00:00",
        "scenario": scenario,
        "mitre_tactic": "Discovery",
        "mitre_technique": technique,
        "expected": {"detection": list(expected), "source": expected_source, "event_ids": list(event_ids)},
        "actual": {"verdict": verdict, "correlation_reason": correlation_reason, "achieved": list(achieved)},
        "evidence": {"matched_event_ids": [], "matched_alert_count": 0, "network_detection_types": [],
                     "incident_count": 0},
        "incidents": [{"id": i} for i in incidents],
    }


def engine_vaccine(attack: dict) -> dict:
    return vaccine_engine.build_vaccine_candidates({"attacks": [attack]})["vaccines"][0]


def all_keys(value, found: set | None = None) -> set:
    """Todas as chaves de dicts encontradas recursivamente."""
    found = set() if found is None else found
    if isinstance(value, dict):
        for key, item in value.items():
            found.add(key)
            all_keys(item, found)
    elif isinstance(value, list):
        for item in value:
            all_keys(item, found)
    return found


ID_A, ID_B, ID_C = "vac-ed793c0b3437", "vac-5fe3861aa2a3", "vac-bd617cce8054"


def real_api_keys(extra_paths=()) -> tuple[set, dict]:
    """Semeia um store temporário com vaccines do motor (a A é substituída pela
    B) e chama as duas rotas reais. Devolve (todas as chaves das respostas,
    as respostas por nome). Os caminhos extra são pedidos com o mesmo
    TestClient sobre o mesmo store e devolvidos em respostas["extra"], por
    caminho, como (estado HTTP, corpo JSON); não entram nas chaves."""
    v_a = engine_vaccine(make_attack(2, "partial", ["rule", "ml"], ["rule"]))
    v_b = engine_vaccine(make_attack(2, "not_detected", ["rule", "ml"], []))
    v_c = engine_vaccine(make_attack(3, "partial", ["rule", "ml"], ["rule"], scenario="lateral_movement_schtasks",
                                     event_ids=(4672, 4698), technique="T1053",
                                     incidents=("INC-20261012-1",)))
    iso1, iso2 = "2026-10-12T09:05:00+00:00", "2026-10-12T09:10:00+00:00"
    original_store, original_state = main.vaccine_store, main.vaccine_loop_state
    original_incidents = main.incident_store
    tmp = tempfile.TemporaryDirectory()
    try:
        store = VaccineStore(os.path.join(tmp.name, "v.sqlite3"))
        store.upsert_batch([v_a], iso1)
        store.upsert_batch([v_b, v_c], iso2)
        state = vaccine_ingest.VaccineLoopState()
        state.record(iso2, "ok", counts={k: 1 for k in vaccine_ingest.COUNT_KEYS}, alerts_truncated=False)
        main.vaccine_store, main.vaccine_loop_state = store, state
        lista = client.get("/api/vaccines?include_superseded=true", headers=HEADERS)
        detalhe = client.get(f"/api/vaccines/{ID_B}", headers=HEADERS)
        state.record(iso2, "error", "indexer_unavailable")
        com_erro = client.get("/api/vaccines", headers=HEADERS)
        respostas = {"lista": lista.json(), "detalhe": detalhe.json(), "com_erro": com_erro.json()}
        chaves = all_keys(list(respostas.values()))
        # Decisões: os corpos vêm do ui_helpers.js REAL (slVacDecisionBody, em node) e são enviados tal
        # como estão. Sem node não há POST e respostas["decisao"] fica None.
        respostas["decisao"] = respostas["decisao_rejeitar"] = None
        main.incident_store = IncidentStore(os.path.join(tmp.name, "i.sqlite3"))
        main.incident_store.create_analyst("analyst-eddie", "Eddie", 1, None, iso1)
        main.incident_store.create_analyst("analyst-jeremy", "Jeremy", 2, None, iso1)
        main.incident_store.create_analyst("analyst-mike", "Mike", 1, None, iso1)
        main.incident_store.deactivate_analyst("analyst-mike")
        analistas = client.get("/api/soc/analysts?active_only=true", headers=HEADERS)
        respostas["analistas"] = (analistas.status_code, analistas.json())
        chaves |= all_keys(analistas.json())
        corpos = node_ui_helpers([["slVacDecisionBody", ["analyst-eddie", "approved", ""]],
                                  ["slVacDecisionBody", ["analyst-jeremy", "rejected", "  Regra ruidosa  "]]])
        respostas["corpos"] = [c["body"] for c in corpos] if corpos else None
        if corpos:
            for nome, vaccine_id, resultado in (("decisao", ID_C, corpos[0]), ("decisao_rejeitar", ID_B, corpos[1])):
                resposta = client.post(f"/api/vaccines/{vaccine_id}/decision", headers=HEADERS, json=resultado["body"])
                respostas[nome] = (resposta.status_code, resposta.json())
                chaves |= all_keys(resposta.json()) | all_keys(resultado["body"])
        # Segunda aprovação da mesma vaccine (409) e a lista depois das decisões.
        respostas["decisao_409"] = respostas["lista_decidida"] = None
        if corpos:
            segunda = client.post(f"/api/vaccines/{ID_C}/decision", headers=HEADERS, json=corpos[0]["body"])
            respostas["decisao_409"] = (segunda.status_code, segunda.json())
            decidida = client.get("/api/vaccines?include_superseded=true", headers=HEADERS)
            respostas["lista_decidida"] = decidida.json()
            chaves |= all_keys(segunda.json()) | all_keys(decidida.json())
        # Recusas reais da rota de decisão, por nome: (estado HTTP, corpo JSON). Estados do store neste ponto:
        # C aprovada, B rejeitada, A substituída (ainda proposta). Os pedidos recusados não gravam nada.
        respostas["erros_decisao"] = None
        if corpos:
            aprovar = {"decision": "approved", "analyst_id": "analyst-eddie"}
            rota = "/api/vaccines/{}/decision"
            pedidos = {
                "already_decided": (ID_C, aprovar),
                "vaccine_superseded": (ID_A, aprovar),
                "reason_required": (ID_C, {"decision": "rejected", "analyst_id": "analyst-eddie"}),
                "analyst_not_found": (ID_C, {**aprovar, "analyst_id": "analyst-ninguem"}),
                "analyst_inactive": (ID_C, {**aprovar, "analyst_id": "analyst-mike"}),
                "invalid_body": (ID_C, {**aprovar, "decided_by_name": "Eddie"}),
                "invalid_author": (ID_C, {**aprovar, "analyst_id": "Eddie O'Neil"}),
                "invalid_decision": (ID_C, {**aprovar, "decision": "maybe"}),
                "invalid_reason": (ID_C, {**aprovar, "reason": "linha um\nlinha dois"}),
                "invalid_vaccine_id": ("vac-xyz", aprovar),
                "entry_not_found": ("vac-000000000000", aprovar),
            }
            erros = {}
            for nome, (vaccine_id, corpo) in pedidos.items():
                resposta = client.post(rota.format(vaccine_id), headers=HEADERS, json=corpo)
                erros[nome] = (resposta.status_code, resposta.json())
            put = client.put(rota.format(ID_C), headers=HEADERS, json=aprovar)
            erros["metodo_put"] = (put.status_code, put.json())
            sem_chave = client.post(rota.format(ID_C), json=aprovar)
            erros["sem_chave"] = (sem_chave.status_code, sem_chave.json())
            respostas["erros_decisao"] = erros
        respostas["extra"] = {}
        for caminho in extra_paths:
            resposta = client.get(caminho, headers=HEADERS)
            respostas["extra"][caminho] = (resposta.status_code, resposta.json())
        return chaves, respostas
    finally:
        main.vaccine_store, main.vaccine_loop_state = original_store, original_state
        main.incident_store = original_incidents
        tmp.cleanup()


# --- varrimentos do ficheiro inteiro ----------------------------------------

_DECL_RE = re.compile(r"^(?:const|let|var|class|function|async function)\s+([A-Za-z_$][\w$]*)", re.M)
# Desde a W7 o HTML desenha-se só com htmlT/htmRender (html.js), que escapa
# toda a interpolação: não há innerHTML nem htmlRaw em vaccines.js, e um
# escapeHtml( dentro de um htmlT escaparia duas vezes.
_INNERHTML_RE = re.compile(r"\.innerHTML\b")
_RAW_RE = re.compile(r"\bhtmlRaw\(|\bescapeHtml\(")
_MESSAGE_RE = re.compile(r"\.message\b")
_MESSAGE_SINKS = ("vacErrorText", "vacRenderError", "vacRenderDetailError", "vacRenderDecisionError",
                  "vacSetAnalystsError", "slVacErrorFollowUp")


def top_level_decls(js: str) -> list[str]:
    """Identificadores declarados na coluna 0 (os globais que o ficheiro cria)."""
    return _DECL_RE.findall(js)


def interpolation_violations(js: str) -> list[str]:
    """Nenhum htmlRaw( (HTML que escapa ao htmlT) nem escapeHtml( (escape à mão,
    que dentro de um htmlT escaparia duas vezes) em vaccines.js."""
    return [m.group(0) for m in _RAW_RE.finditer(js)]


def innerhtml_violations(js: str) -> list[str]:
    """Qualquer uso de .innerHTML (leitura, `=` ou `+=`) é violação: o HTML
    desenha-se com htmRender(el, htmlT`...`) e limpa-se com replaceChildren()."""
    return [m.group(0) for m in _INNERHTML_RE.finditer(js)]


def message_violations(js: str) -> list[str]:
    """Cada `.message` tem de ser o argumento direto de vacErrorText(,
    vacRenderError( ou vacRenderDetailError(. Devolve o contexto das outras."""
    found = []
    for m in _MESSAGE_RE.finditer(js):
        antes = js[:m.start()]
        depois = js[m.end():].lstrip()
        ok = (re.search(r"(?:" + "|".join(_MESSAGE_SINKS) + r")\(\s*[A-Za-z_$][\w$]*$", antes)
              and depois.startswith(")"))
        if not ok:
            found.append(js[max(0, m.start() - 30):m.end() + 10])
    return found


# --- run_tracer ------------------------------------------------------------

def run_tracer() -> None:
    files = served()
    index_html = files["/index.html"][2]
    js = files["/vaccines.js"][2]
    disk_js_path = serve_frontend.PROJECT_ROOT / "vaccines.js"
    disk_js = disk_js_path.read_text(encoding="utf-8") if disk_js_path.exists() else None

    # a) servido
    status, headers, body = files["/vaccines.js"]
    check("/vaccines.js é servido: 200 e application/javascript",
          status == 200 and headers.get("content-type", "").startswith("application/javascript"))
    check("/vaccines.js servido é igual ao ficheiro em disco",
          disk_js is not None and body.replace("\r\n", "\n") == disk_js.replace("\r\n", "\n"))
    check("ALLOWED_FILES mapeia /vaccines.js -> vaccines.js",
          serve_frontend.ALLOWED_FILES.get("/vaccines.js") == "vaccines.js")
    server = HTTPServer(("127.0.0.1", 0), serve_frontend.FrontendHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        check("/scripts/vaccines.sqlite3 continua a dar 404", get(port, "/scripts/vaccines.sqlite3")[0] == 404)
        check("/vaccines.sqlite3 continua a dar 404", get(port, "/vaccines.sqlite3")[0] == 404)
    finally:
        server.shutdown()
        server.server_close()

    # b) sidebar
    linhas = index_html.splitlines()
    candidates = [l for l in linhas if 'data-tab="vaccines"' in l]
    check('exatamente um botão com data-tab="vaccines"', len(candidates) == 1)
    check("o botão Vaccines abre a aba e não é planeado",
          len(candidates) == 1 and "Vaccines" in candidates[0]
          and "is-planned" not in candidates[0] and "nav-badge" not in candidates[0])
    # W5.1: os itens planeados saíram do menu e vivem na página Roadmap.
    roadmap = index_html[index_html.index('id="tab-roadmap"'):]
    for label, planned in (("Validation", "R12"), ("Approved", "R14"), ("Regression", "R14")):
        check(f"{label} listado no Roadmap como planeado ({planned}), fora do menu",
              f"<strong>{label}</strong> <span class=\"roadmap-status\">Planeado ({planned})" in roadmap
              and f'data-label="{label}"' not in index_html)
    check("index.html já não tem nenhum marcador de planeado R11", 'data-planned="R11"' not in index_html)

    # c) markup
    check('id="tab-vaccines" aparece uma vez, numa div tab-content',
          index_html.count('id="tab-vaccines"') == 1
          and re.search(r'<div\s+class="tab-content"\s+id="tab-vaccines"', index_html) is not None)
    for marker in ('id="vaccines-panel"', 'id="vac-notice"', 'id="vac-table"', 'id="vac-body"'):
        check(f"index.html contém {marker}", marker in index_html)
    thead = re.search(r'<table id="vac-table">.*?</thead>', index_html, re.S)
    colunas = re.findall(r"<th>(.*?)</th>", thead.group(0)) if thead else []
    check("o cabeçalho da tabela de vaccines tem as 8 colunas pela ordem de D-04",
          colunas == ["Vaccine", "Ataque", "Cenário", "Técnica", "Veredito", "Sensores em falta", "Estado", "Criada"])
    check('a linha inicial do corpo usa colspan="8"',
          bool(re.search(r'<tbody id="vac-body">\s*<tr><td colspan="8" class="empty-state">A carregar\.\.\.</td></tr>',
                         index_html)))

    # d) scripts
    tag, app_tag = '<script src="vaccines.js"></script>', '<script src="app.js"></script>'
    check("index.html carrega vaccines.js uma vez, depois de app.js",
          index_html.count(tag) == 1 and app_tag in index_html and index_html.index(tag) > index_html.index(app_tag))

    # e) pedidos
    check("vaccines.js não faz fetch( próprio (o transporte é do apiRequest)", js.count("fetch(") == 0)
    corpo_request = function_body(js, "vacRequest")
    check("vacRequest delega em apiRequest (a chave X-API-Key é posta por api.js)",
          "apiRequest(" in corpo_request)
    check('vaccines.js pede "/api/vaccines"', '"/api/vaccines"' in js)
    check("a chave nunca vai na query (sem api_key=)", "api_key=" not in js)
    check('um só "method:" e um só "POST", ambos dentro de vacDecide; sem PUT, PATCH nem DELETE',
          len(re.findall(r"\bmethod\s*:", js)) == 1 and js.count('"POST"') == 1
          and re.search(r'method:\s*"POST"', function_body(js, "vacDecide")) is not None
          and re.search(r"\b(PUT|PATCH|DELETE)\b", js) is None)

    # f) contrato de campos contra a resposta real da rota
    real, respostas = real_api_keys()
    check("as chaves reais incluem created_at, superseded_by, generator e vaccine",
          {"created_at", "superseded_by", "generator", "vaccine"} <= real)
    ids = [v["id"] for v in respostas["lista"]["vaccines"]]
    check("a lista com include_superseded traz as 3 vaccines em ordem attack_id desc, created_at desc",
          ids == [ID_C, ID_B, ID_A])
    v_a = next((v for v in respostas["lista"]["vaccines"] if v["id"] == ID_A), {})
    check("a vaccine A foi substituída pela B", v_a.get("superseded_by") == ID_B)
    proibidas = {"command", "argv", "build_command", "tool", "target", "source", "operator"}
    check("a resposta real não tem nenhuma chave de comando, ferramenta, alvo ou operador",
          not (proibidas & real))
    acessos = field_accesses(files)
    desconhecidos = sorted(a for a in acessos if a[1] not in real and a[1] != "length")
    check("cada campo lido de um objeto da API existe na resposta real", not desconhecidos)
    if desconhecidos:
        print(f"       campos que a API não tem: {desconhecidos}")
    check("nenhum objeto da API é acedido por parênteses retos",
          re.search(r"\b(" + "|".join(API_VARS) + r")\s*\[", js) is None)
    check("nenhum objeto da API é desestruturado",
          re.search(r"\}\s*=\s*(" + "|".join(API_VARS) + r")\b", js) is None)
    esperados = {("envelope", "vaccines"), ("envelope", "reason"), ("vaccine", "id"), ("vaccine", "origin"),
                 ("origin", "attack_id"), ("origin", "scenario"), ("origin", "mitre_technique"),
                 ("vaccine", "verdict"), ("vaccine", "missing_sensors"), ("vaccine", "state"),
                 ("vaccine", "created_at")}
    check("vaccines.js lê os campos que a tabela mostra", esperados <= acessos)
    if not esperados <= acessos:
        print(f"       em falta: {sorted(esperados - acessos)}")


def run_guards() -> None:
    files = served()
    js = files["/vaccines.js"][2]
    app_js = files["/app.js"][2]

    # a) globais: os scripts clássicos partilham um só escopo global
    decls = top_level_decls(js)
    sem_prefixo = [n for n in decls if not n.startswith(("vac", "VAC_"))]
    check("todos os identificadores de topo de vaccines.js têm prefixo vac/VAC_", bool(decls) and not sem_prefixo)
    if sem_prefixo:
        print(f"       nomes sem prefixo: {sem_prefixo}")
    colisoes = {}
    for caminho, nome in sorted(serve_frontend.ALLOWED_FILES.items()):
        if not nome.endswith(".js") or nome == "vaccines.js":
            continue
        outras = set(top_level_decls((serve_frontend.PROJECT_ROOT / nome).read_text(encoding="utf-8")))
        comuns = sorted(set(decls) & outras)
        if comuns:
            colisoes[nome] = comuns
    check("vaccines.js não repete nenhum identificador de topo dos outros .js servidos", not colisoes)
    if colisoes:
        print(f"       colisões: {colisoes}")
    check("vaccines.js não redeclara os globais de app.js",
          not ({"API_BASE", "API_KEY", "escapeHtml", "renderPanelError"} & set(decls)))

    # b) escape: cada varrimento tem de apanhar uma violação sintética conhecida
    check("vaccines.js não usa htmlRaw( nem escapeHtml( (a interpolação do htmlT já escapa)", not interpolation_violations(js))
    check("vaccines.js não usa innerHTML (htmRender / replaceChildren)", not innerhtml_violations(js))
    check("vaccines.js desenha HTML com htmRender e htmlT", "htmRender(" in js and "htmlT`" in js)
    check("vaccines.js não usa insertAdjacentHTML, outerHTML nem document.write",
          not any(x in js for x in ("insertAdjacentHTML", "outerHTML", "document.write")))
    check("o varrimento de escape à mão apanha violações sintéticas",
          len(interpolation_violations("x = htmlT`<td>${escapeHtml(a)}</td>`;")) >= 1
          and len(interpolation_violations("x = htmlRaw(a);")) >= 1
          and not interpolation_violations("x = htmlT`<td>${vacCell(b)}${VAC_X}</td>`;"))
    check("o varrimento de innerHTML apanha atribuição, leitura e += sintéticos",
          len(innerhtml_violations("body.innerHTML = texto;")) >= 1
          and len(innerhtml_violations("x = body.innerHTML;")) >= 1
          and len(innerhtml_violations("body.innerHTML += `<tr></tr>`;")) >= 1
          and not innerhtml_violations("htmRender(body, vacRowsHtml(l)); c.replaceChildren();"))
    check("o varrimento de .message apanha um uso solto sintético",
          len(message_violations("alert(err.message);")) >= 1
          and not message_violations("vacRenderError(err.message);"))

    # c) erros só por código
    objeto = re.search(r"const VAC_ERROR_TEXT = \{(.*?)^\};", js, re.S | re.M)
    chaves = set(re.findall(r"^\s{2}([A-Za-z_]\w*):", objeto.group(1), re.M)) if objeto else set()
    esperadas = {"unauthorized", "network_error", "store_unavailable", "entry_not_found",
                 "http_404", "http_422", "http_502", "http_503"}
    check("VAC_ERROR_TEXT tem as 8 chaves pedidas", esperadas <= chaves)
    check("nenhuma frase de erro diz que não há dados",
          bool(objeto) and "Sem dados" not in objeto.group(1))
    check("o único código aceite do servidor é /^[a-z_]{1,64}$/", "/^[a-z_]{1,64}$/" in js)
    corpo = function_body(js, "vacCodeFromResponse")
    check("vacCodeFromResponse trata o 401 como unauthorized", "401" in corpo and '"unauthorized"' in corpo)
    corpo = function_body(js, "vacErrorText")
    check("vacErrorText usa hasOwnProperty e cai em VAC_GENERIC_ERROR",
          "hasOwnProperty" in corpo and "VAC_GENERIC_ERROR" in corpo)
    check("cada .message é argumento direto de vacErrorText/vacRenderError/vacRenderDetailError",
          not message_violations(js))
    for violacao in message_violations(js):
        print(f"       .message solto: {violacao!r}")

    # d) honestidade: erro nunca é "Sem dados" nem lista vazia
    check('o texto "Sem dados" aparece exatamente uma vez em vaccines.js', js.count("Sem dados") == 1)
    corpo = function_body(js, "vacRenderList")
    check("vacRenderList liga no_data a VAC_NO_DATA_TEXT e o filtro vazio a VAC_FILTER_EMPTY_TEXT",
          '"no_data"' in corpo and "VAC_NO_DATA_TEXT" in corpo and "VAC_FILTER_EMPTY_TEXT" in corpo)
    corpo = function_body(js, "vacRenderError")
    check("vacRenderError não usa 'Sem dados' nem os textos de lista vazia",
          bool(corpo) and not any(x in corpo for x in ("Sem dados", "VAC_NO_DATA_TEXT", "VAC_FILTER_EMPTY_TEXT")))
    check("vacRenderError desenha o banner e a linha vac-error-state",
          "renderPanelError" in corpo and "vac-error-state" in corpo)

    # e) ciclo de vida (D-02)
    check("a aba reage à ativação: MutationObserver, visibilitychange e guarda vacLoading",
          all(x in js for x in ("MutationObserver", '"visibilitychange"', "vacLoading")))
    check("sem polling, sem canal em tempo real e sem guarda de carregar uma só vez",
          not any(x in js for x in ("setInterval", "WebSocket", "vacLoaded")))

    # f) app.js intacto: nenhuma referência à aba nova
    check("app.js não referencia vaccines.js, tab-vaccines nem /api/vaccines",
          not any(x in app_js for x in ("vaccines.js", "tab-vaccines", "/api/vaccines")))


def run_filters() -> None:
    files = served()
    index_html = files["/index.html"][2]
    js = files["/vaccines.js"][2]

    # a) markup: filter-row dentro de #vaccines-panel, antes de #vac-notice
    painel = index_html.find('id="vaccines-panel"')
    aviso = index_html.find('id="vac-notice"')
    fila = index_html.find('class="filter-row"', painel) if painel != -1 else -1
    check("há uma div.filter-row dentro de #vaccines-panel, antes de #vac-notice",
          painel != -1 and aviso != -1 and painel < fila < aviso)
    bloco = index_html[fila:aviso] if fila != -1 and aviso != -1 else ""
    check("a filter-row tem label[for=vac-attack-filter] e input#vac-attack-filter",
          'for="vac-attack-filter"' in bloco and re.search(r'<input[^>]*id="vac-attack-filter"', bloco) is not None)
    check("a filter-row tem label[for=vac-technique-filter] e select#vac-technique-filter",
          'for="vac-technique-filter"' in bloco and re.search(r'<select[^>]*id="vac-technique-filter"', bloco) is not None)
    primeira = re.search(r'<select[^>]*id="vac-technique-filter"[^>]*>\s*<option([^>]*)>(.*?)</option>', bloco, re.S)
    check('a primeira option do select de técnica tem value="" e o texto "Todas"',
          primeira is not None and 'value=""' in primeira.group(1) and primeira.group(2).strip() == "Todas")
    caixa = re.search(r'<input[^>]*id="vac-superseded-filter"[^>]*>', bloco)
    check('#vac-superseded-filter é um checkbox com o label "Incluir substituídas"',
          caixa is not None and 'type="checkbox"' in caixa.group(0) and "Incluir substituídas" in bloco)
    botao = re.search(r'<button[^>]*id="vac-refresh-btn"[^>]*>', bloco)
    check('#vac-refresh-btn é um button type="button"', botao is not None and 'type="button"' in botao.group(0))

    # b) vaccines.js
    check("vaccines.js tem attack_id, technique, include_superseded e URLSearchParams",
          all(x in js for x in ("attack_id", "technique", "include_superseded", "URLSearchParams")))
    check("vaccines.js tem os literais das expressões de attack_id e de técnica",
          r"/^[1-9]\d{0,8}$/" in js and r"/^T\d{4}(\.\d{3})?$/" in js)
    corpo = function_body(js, "vacBuildQuery")
    check("vacBuildQuery usa VAC_ATTACK_ID_RE e VAC_TECHNIQUE_RE",
          "VAC_ATTACK_ID_RE" in corpo and "VAC_TECHNIQUE_RE" in corpo)
    corpo = function_body(js, "vacRefresh")
    check("vacRefresh usa vacBuildQuery pelo menos 2 vezes (a query usada e a comparação no fim)",
          corpo.count("vacBuildQuery") >= 2)
    check('vaccines.js liga "vac-refresh-btn" aos eventos "click" e "change"',
          '"vac-refresh-btn"' in js and '"click"' in js and '"change"' in js)

    # c) rota real
    caminhos = ("/api/vaccines?attack_id=3&technique=T1053", "/api/vaccines?attack_id=2",
                "/api/vaccines?attack_id=2&include_superseded=true", "/api/vaccines?technique=T9999")
    _, respostas = real_api_keys(caminhos)
    extra = respostas["extra"]

    def ids_de(caminho):
        estado, corpo_json = extra[caminho]
        return estado, [v["id"] for v in corpo_json["vaccines"]]

    check("rota real: attack_id=3&technique=T1053 -> 200 e só a vaccine C",
          ids_de(caminhos[0]) == (200, [ID_C]))
    check("rota real: attack_id=2 -> só a vaccine B (a A está substituída)", ids_de(caminhos[1]) == (200, [ID_B]))
    estado, ids = ids_de(caminhos[2])
    check("rota real: attack_id=2&include_superseded=true -> B e A", estado == 200 and sorted(ids) == sorted([ID_B, ID_A]))
    estado, vazio = extra[caminhos[3]]
    check("rota real: technique=T9999 -> 200, vaccines [], reason None, available True (filtro vazio, não no_data)",
          estado == 200 and vazio["vaccines"] == [] and vazio["reason"] is None and vazio["available"] is True)


def run_states() -> None:
    files = served()
    index_html = files["/index.html"][2]
    js = files["/vaccines.js"][2]
    css = files["/style.css"][2]

    # a) linha de estado do gerador no markup, a seguir à filter-row
    gerador = re.search(r'<div\s+id="vac-generator"\s+class="panel-note"\s+role="status"\s*>\s*</div>', index_html)
    fila = index_html.find('class="filter-row"', index_html.find('id="vaccines-panel"'))
    aviso = index_html.find('id="vac-notice"')
    check('index.html tem div#vac-generator.panel-note[role="status"] entre a filter-row e #vac-notice',
          gerador is not None and fila != -1 and fila < gerador.start() < aviso)

    # b) frases e estados do gerador
    objeto = re.search(r"const VAC_ERROR_TEXT = \{(.*?)^\};", js, re.S | re.M)
    chaves = set(re.findall(r"^\s{2}([A-Za-z_]\w*):", objeto.group(1), re.M)) if objeto else set()
    em_falta = [c for c in vaccine_ingest.GENERATOR_ERROR_CODES if c not in chaves]
    check("VAC_ERROR_TEXT tem uma frase para cada código de vaccine_ingest.GENERATOR_ERROR_CODES", not em_falta)
    if em_falta:
        print(f"       códigos sem frase: {em_falta}")
    check('nenhuma frase de VAC_ERROR_TEXT diz "Sem dados"', bool(objeto) and "Sem dados" not in objeto.group(1))
    check("vaccines.js tem cada estado de GENERATOR_STATUSES como literal de string",
          all(f'"{estado}"' in js for estado in vaccine_ingest.GENERATOR_STATUSES))

    # c) campos do gerador lidos, todos dentro das chaves reais
    real, respostas = real_api_keys()
    acessos = field_accesses(files)
    esperados = {("envelope", "generator"), ("generator", "status"), ("generator", "error_code"),
                 ("generator", "last_run_at"), ("generator", "last_success_at"), ("generator", "alerts_truncated"),
                 ("generator", "counts"), ("counts", "pending_settle"), ("vaccine", "superseded_by")}
    check("vaccines.js lê os campos do gerador e superseded_by", esperados <= acessos)
    if not esperados <= acessos:
        print(f"       em falta: {sorted(esperados - acessos)}")
    desconhecidos = sorted(a for a in acessos if a[1] not in real and a[1] != "length")
    check("cada campo lido de um objeto da API existe na resposta real", not desconhecidos)
    if desconhecidos:
        print(f"       campos que a API não tem: {desconhecidos}")
    lidos_do_gerador = {p for v, p in acessos if v == "generator"}
    check("os campos lidos do gerador são chaves de vaccine_ingest.GENERATOR_KEYS",
          lidos_do_gerador <= vaccine_ingest.GENERATOR_KEYS)

    # d) funções do gerador
    check('vacRenderGenerator usa a classe "vac-generator-error"',
          "vac-generator-error" in function_body(js, "vacRenderGenerator"))
    check("vacGeneratorText traduz o código de erro só por vacErrorText",
          "vacErrorText" in function_body(js, "vacGeneratorText"))
    check("vacRefresh passa envelope.generator a vacRenderGenerator",
          "vacRenderGenerator(envelope.generator)" in function_body(js, "vacRefresh"))
    texto = function_body(js, "vacGeneratorText")
    check("a linha do gerador diz 'Última execução' e a frase própria de never_run",
          "Última execução" in texto and "ainda não correu" in texto)
    check("a linha do gerador explica pending_settle e o teto de alertas (alerts_truncated)",
          "pending_settle" in texto and "alerts_truncated" in texto and "1000 alertas" in texto)
    check("vacAgo cobre data inválida, minutos, horas e dias",
          all(x in function_body(js, "vacAgo") for x in ("Date.parse", "menos de 1 min", " min", " h", " dias")))

    # e) rota real: o erro do gerador chega como código estável com frase própria
    gerador_real = respostas["com_erro"]["generator"]
    check("rota real: o gerador com erro tem status error e error_code indexer_unavailable",
          gerador_real["status"] == "error" and gerador_real["error_code"] == "indexer_unavailable")
    check("rota real: o error_code do gerador tem frase em VAC_ERROR_TEXT",
          gerador_real["error_code"] in chaves)
    check("rota real: o gerador ok tem as chaves de GENERATOR_KEYS",
          set(respostas["lista"]["generator"]) == set(vaccine_ingest.GENERATOR_KEYS))

    # f) badges de veredito e substituídas esbatidas
    check("vaccines.js tem 'Substituída por', vac-row-superseded e vac-verdict",
          all(x in js for x in ("Substituída por", "vac-row-superseded", "vac-verdict")))
    linhas = function_body(js, "vacRowsHtml")
    check("vacRowsHtml usa vacVerdictBadge, vacRowClass e vacSupersededNote",
          all(x in linhas for x in ("vacVerdictBadge", "vacRowClass", "vacSupersededNote")))
    check("os rótulos de veredito mantêm Não detetado e Parcial",
          re.search(r'VAC_VERDICT_LABELS = \{[^}]*not_detected: "Não detetado"[^}]*partial: "Parcial"', js) is not None)
    badge = function_body(js, "vacVerdictBadge")
    check("vacVerdictBadge interpola o veredito e o rótulo num htmlT (escapados)",
          "htmlT`" in badge and "${String(verdict)}" in badge and "${String(label)}" in badge)
    check("vacSupersededNote desenha o id substituto por vacCell",
          "vacCell(vaccine.superseded_by)" in function_body(js, "vacSupersededNote"))

    # g) estilos
    for classe in ("vac-verdict", "vac-verdict-not_detected", "vac-verdict-partial", "vac-row-superseded",
                   "vac-superseded-note", "vac-generator-error", "vac-error-state"):
        check(f"style.css servido define .{classe}", re.search(r"\." + re.escape(classe) + r"\s*\{", css) is not None)

    # h) Phase 16: o backend já serve approved/rejected; o rótulo é da Phase 17. Um estado sem
    # rótulo desenha-se como o próprio texto (escapado pelo htmlT), nunca "undefined".
    # O badge de estado (17-03, D-07) substitui o texto simples; o estado sem rótulo continua a
    # desenhar-se como o próprio texto, escapado (ver run_state_ui).
    check("vacRowsHtml desenha o estado por vacStateBadge(vaccine.state) (badge com texto, nunca só cor)",
          "vacStateBadge(vaccine.state)" in linhas)


def run_detail() -> None:
    files = served()
    index_html = files["/index.html"][2]
    js = files["/vaccines.js"][2]
    css = files["/style.css"][2]

    # a) markup: o painel de detalhe fica em #tab-vaccines, depois de #vaccines-panel
    aba = index_html.find('id="tab-vaccines"')
    painel_lista = index_html.find('id="vaccines-panel"')
    abertura = '<section class="panel" id="vaccine-detail-panel" hidden>'
    painel = index_html.find(abertura)
    proxima_aba = index_html.find('<div class="tab-content"', aba + 1)
    check("o painel de detalhe está dentro de #tab-vaccines, depois de #vaccines-panel, com hidden",
          aba != -1 and painel_lista != -1 and aba < painel_lista < painel < proxima_aba
          and index_html.count('id="vaccine-detail-panel"') == 1)
    fim = index_html.find("</section>", painel)
    bloco = index_html[painel:fim] if painel != -1 and fim != -1 else ""
    check('o painel tem #vac-detail-title',
          re.search(r'<h2[^>]*id="vac-detail-title"', bloco) is not None)
    aviso = re.search(r'<p[^>]*id="vac-detail-warning"[^>]*>(.*?)</p>', bloco, re.S)
    check('o aviso #vac-detail-warning tem class="vac-not-applied" e o texto estático diz "não aplicada no Wazuh"',
          aviso is not None and "vac-not-applied" in aviso.group(0)
          and "não aplicada no Wazuh" in aviso.group(1))
    check("vacRenderDetail escreve o aviso por estado (slVacWarningText( com VAC_STATE_LABELS)",
          "slVacWarningText(" in function_body(js, "vacRenderDetail")
          and "VAC_STATE_LABELS" in function_body(js, "vacRenderDetail"))
    check("os h3 do painel são Decisão, Origem, Propostas e Cadeia, por esta ordem",
          re.findall(r"<h3>(.*?)</h3>", bloco) == ["Decisão", "Origem", "Propostas", "Cadeia"])
    check("o painel tem #vac-detail-origin, #vac-detail-proposals e #vac-detail-chain",
          all(f'id="{i}"' in bloco for i in ("vac-detail-origin", "vac-detail-proposals", "vac-detail-chain")))

    # b) vaccines.js: pedido, validação, anti-corrida, listeners
    check("vaccines.js tem o literal da expressão do id de vaccine", r"/^vac-[0-9a-f]{12}$/" in js)
    check('o pedido de detalhe é "/api/vaccines/" + encodeURIComponent(',
          '"/api/vaccines/" + encodeURIComponent(' in js)
    corpo = function_body(js, "vacSelect")
    check("vacSelect valida com VAC_ID_RE e ignora respostas fora de ordem (seq !== vacSelectSeq, 2 vezes)",
          "VAC_ID_RE" in corpo and corpo.count("seq !== vacSelectSeq") >= 2)
    check("vacSelect (leitura) e vacDecide (escrita) são as únicas chamadas a /api/vaccines/ com o id",
          "async function vacSelect(" in js and js.count('"/api/vaccines/"') == 2
          and '"/api/vaccines/"' in function_body(js, "vacSelect")
          and '"/api/vaccines/"' in function_body(js, "vacDecide"))
    check('há listeners "click" e "keydown" em #vac-body, com "Enter" e " "',
          re.search(r'getElementById\("vac-body"\)\.addEventListener\("click"', js) is not None
          and re.search(r'getElementById\("vac-body"\)\.addEventListener\("keydown"', js) is not None
          and '"Enter"' in js and '" "' in js and "preventDefault" in js)

    # c) contrato de campos do detalhe
    acessos = field_accesses(files)
    esperados = {("envelope", "vaccine"), ("origin", "mitre_tactic"), ("origin", "incident_ids"),
                 ("origin", "evidence"), ("evidence", "matched_event_ids"), ("evidence", "matched_alert_count"),
                 ("evidence", "network_detection_types"), ("vaccine", "proposals"), ("vaccine", "expected"),
                 ("vaccine", "achieved"), ("vaccine", "expected_source"), ("proposal", "sensor"),
                 ("proposal", "rule"), ("proposal", "events"), ("proposal", "recommendation"),
                 ("rule", "event_ids"), ("rule", "min_count"), ("rule", "window_seconds"),
                 ("catalogEvent", "event_id"), ("catalogEvent", "name"), ("catalogEvent", "severity")}
    check("vaccines.js lê os campos do detalhe (origem, evidência, propostas, regra, eventos)",
          esperados <= acessos)
    if not esperados <= acessos:
        print(f"       em falta: {sorted(esperados - acessos)}")
    caminhos = (f"/api/vaccines/{ID_A}", f"/api/vaccines/{ID_B}", f"/api/vaccines/{ID_C}",
                "/api/vaccines/vac-000000000000")
    real, respostas = real_api_keys(caminhos)
    desconhecidos = sorted(a for a in acessos if a[1] not in real and a[1] != "length")
    check("cada campo lido de um objeto da API existe na resposta real (incluindo o detalhe)", not desconhecidos)
    if desconhecidos:
        print(f"       campos que a API não tem: {desconhecidos}")
    proibidas = {"command", "argv", "build_command", "tool", "target", "source", "operator"}
    check("as respostas reais do detalhe não têm chave de comando, ferramenta, alvo nem operador",
          not (proibidas & real))

    # d) erros no detalhe
    corpo = function_body(js, "vacRenderDetailError")
    check("vacRenderDetailError mostra o banner do painel de detalhe e nunca 'Sem dados'",
          "renderPanelError" in corpo and "#vaccine-detail-panel" in corpo
          and "Sem dados" not in corpo and "VAC_NO_DATA_TEXT" not in corpo)

    # e) rota real sobre o store semeado
    extra = respostas["extra"]
    estado, a = extra[caminhos[0]]
    check("rota real: a vaccine A (substituída) abre com 200 e superseded_by = B",
          estado == 200 and a["vaccine"]["superseded_by"] == ID_B)
    estado, c = extra[caminhos[2]]
    vc = c.get("vaccine", {})
    propostas = vc.get("proposals", [])
    check("rota real: C tem o incidente INC-20261012-1 e a técnica T1053",
          estado == 200 and vc.get("origin", {}).get("incident_ids") == ["INC-20261012-1"]
          and vc["origin"].get("mitre_technique") == "T1053")
    check("rota real: C tem uma só proposta ml, sem regra, com recomendação em texto",
          len(propostas) == 1 and propostas[0]["sensor"] == "ml" and propostas[0]["rule"] is None
          and isinstance(propostas[0]["recommendation"], str) and propostas[0]["recommendation"] != "")
    estado, b = extra[caminhos[1]]
    regra = b["vaccine"]["proposals"][0] if estado == 200 and b["vaccine"]["proposals"] else {}
    check("rota real: a primeira proposta de B tem a regra [5140, 5145], 1 ocorrência, 300 s",
          regra.get("sensor") == "rule" and regra["rule"]["event_ids"] == [5140, 5145]
          and regra["rule"]["min_count"] == 1 and regra["rule"]["window_seconds"] == 300)
    check("rota real: os eventos da regra têm nome e severidade",
          bool(regra.get("events")) and all(e.get("name") and e.get("severity") for e in regra["events"]))
    estado, nao_existe = extra[caminhos[3]]
    check("rota real: vac-000000000000 -> 404 com entry_not_found",
          estado == 404 and nao_existe == {"detail": "entry_not_found"})
    objeto = re.search(r"const VAC_ERROR_TEXT = \{(.*?)^\};", js, re.S | re.M)
    chaves = set(re.findall(r"^\s{2}([A-Za-z_]\w*):", objeto.group(1), re.M)) if objeto else set()
    check("entry_not_found tem frase em VAC_ERROR_TEXT", "entry_not_found" in chaves)

    # f) estilos novos
    for classe in ("vac-not-applied", "vac-proposal"):
        check(f"style.css servido define .{classe}", re.search(r"\." + re.escape(classe) + r"\s*\{", css) is not None)


def run_chain() -> None:
    files = served()
    js = files["/vaccines.js"][2]

    # a) vacLoadChain: um segundo pedido só de leitura, por ataque
    corpo = function_body(js, "vacLoadChain")
    check("vacLoadChain pede attack_id, include_superseded e limit por vacRequest(",
          all(x in corpo for x in ("include_superseded", "attack_id", "limit", "vacRequest(")))
    check("vacLoadChain ignora respostas fora de ordem (seq !== vacSelectSeq, 2 vezes: resposta e erro)",
          corpo.count("seq !== vacSelectSeq") >= 2)
    check("vacSelect chama vacLoadChain", "vacLoadChain(" in function_body(js, "vacSelect"))
    check("vacReplacedIds lê superseded_by", "superseded_by" in function_body(js, "vacReplacedIds"))

    # b) textos da cadeia; o erro nunca afirma que não substitui nada
    check("vaccines.js tem Substitui, Substituída por, Atual e Cadeia indisponível",
          all(x in js for x in ("Substitui", "Substituída por", "Atual", "Cadeia indisponível")))
    check('"Cadeia indisponível" aparece só dentro de vacLoadChain, junto de vacErrorText(',
          js.count("Cadeia indisponível") == corpo.count("Cadeia indisponível") >= 1 and "vacErrorText(" in corpo)
    check("a frase 'Não substitui nenhuma' fica fora de vacLoadChain (um erro nunca a desenha)",
          "Não substitui nenhuma" in function_body(js, "vacChainHtml") and "Não substitui nenhuma" not in corpo)

    # c) D-07: só texto, sem navegação
    check("vaccines.js não tem links nem navegação (<a, href, activateTab(, location.hash)",
          not any(x in js for x in ("<a", "href", "activateTab(", "location.hash")))
    check("a linha selecionada sobrevive a um Atualizar (vacRowClass lê vacSelectedId)",
          "vacSelectedId" in function_body(js, "vacRowClass"))

    # d) rota real: o "Substitui" é derivável das vaccines do mesmo ataque
    caminhos = ("/api/vaccines?attack_id=2&include_superseded=true", "/api/vaccines?attack_id=3&include_superseded=true")
    _, respostas = real_api_keys(caminhos)
    estado, dois = respostas["extra"][caminhos[0]]
    check("rota real: attack_id=2&include_superseded=true -> B e A",
          estado == 200 and [v["id"] for v in dois["vaccines"]] == [ID_B, ID_A])
    a = next((v for v in dois["vaccines"] if v["id"] == ID_A), {})
    check("rota real: A tem superseded_by = B (o 'Substitui A' de B é derivável)", a.get("superseded_by") == ID_B)
    estado, tres = respostas["extra"][caminhos[1]]
    check("rota real: attack_id=3&include_superseded=true -> só C, sem superseded_by",
          estado == 200 and [v["id"] for v in tres["vaccines"]] == [ID_C]
          and tres["vaccines"][0]["superseded_by"] is None)


def run_decision() -> None:
    """Tracer da decisão: o corpo que o ui_helpers.js real constrói é aceite pela rota real, e o markup e o
    vacDecide do tracer estão ligados."""
    files = served()
    index_html = files["/index.html"][2]
    js = files["/vaccines.js"][2]

    check("node encontrado no PATH (necessário para executar o ui_helpers.js real)", shutil.which("node") is not None)
    _, respostas = real_api_keys()
    aprovar, rejeitar = respostas["decisao"], respostas["decisao_rejeitar"]
    check("o corpo do helper (aprovar, eddie) é aceite pela rota real: 200, approved, autor Eddie, reason None",
          aprovar is not None and aprovar[0] == 200 and aprovar[1]["vaccine"]["state"] == "approved"
          and aprovar[1]["vaccine"]["decision"]["decided_by_name"] == "Eddie"
          and aprovar[1]["vaccine"]["decision"]["reason"] is None)
    check("o corpo do helper (rejeitar, jeremy, motivo aparado) é aceite pela rota real: 200, rejected, autor Jeremy",
          rejeitar is not None and rejeitar[0] == 200 and rejeitar[1]["vaccine"]["state"] == "rejected"
          and rejeitar[1]["vaccine"]["decision"]["decided_by_name"] == "Jeremy"
          and rejeitar[1]["vaccine"]["decision"]["reason"] == "Regra ruidosa")
    check("a resposta da decisão traz o aviso do servidor (notice) e a vaccine",
          aprovar is not None and {"vaccine", "notice"} <= set(aprovar[1])
          and "não aplicada no Wazuh" in aprovar[1]["notice"])

    painel = index_html.find('<section class="panel" id="vaccine-detail-panel" hidden>')
    fim = index_html.find("</section>", painel)
    bloco = index_html[painel:fim] if painel != -1 and fim != -1 else ""
    check("o painel de detalhe tem os botões data-action vac-approve e vac-reject",
          'data-action="vac-approve"' in bloco and 'data-action="vac-reject"' in bloco)
    corpo = function_body(js, "vacDecide")
    check('vacDecide valida e constrói o corpo por slVacDecisionBody(, pede "/decision" e usa method: "POST"',
          "slVacDecisionBody(" in corpo and '"/decision"' in corpo and 'method: "POST"' in corpo)
    envelope_lidos = {p for v, p in data_accesses(js) if v == "envelope"}
    check("vaccines.js lê envelope.vaccine e envelope.notice, ambos nas chaves reais da decisão",
          {"vaccine", "notice"} <= envelope_lidos and {"vaccine", "notice"} <= real_api_keys()[0])


def run_decision_contract() -> None:
    """Contrato do bloco Decisão: markup, listener delegado, analistas reais e campos lidos."""
    files = served()
    index_html = files["/index.html"][2]
    js = files["/vaccines.js"][2]
    ui_js = files["/ui_helpers.js"][2]

    # a) markup do bloco no painel de detalhe
    painel = index_html.find('<section class="panel" id="vaccine-detail-panel" hidden>')
    fim = index_html.find("</section>", painel)
    bloco = index_html[painel:fim] if painel != -1 and fim != -1 else ""
    for marcador in ("vac-detail-decision", "vac-decision-state", "vac-decision-count"):
        check(f'o bloco Decisão tem #{marcador}', f'id="{marcador}"' in bloco)
    check("#vac-decision-form começa escondido (hidden)",
          re.search(r'<div[^>]*id="vac-decision-form"[^>]*\bhidden\b', bloco) is not None)
    check('label[for=vac-decision-analyst] e select cuja primeira option tem value="" e o texto "Escolher…"',
          'for="vac-decision-analyst"' in bloco
          and re.search(r'<select id="vac-decision-analyst">\s*<option value="">Escolher…</option>', bloco) is not None)
    check("label[for=vac-decision-reason] e textarea com maxlength=500",
          'for="vac-decision-reason"' in bloco
          and re.search(r'<textarea[^>]*id="vac-decision-reason"[^>]*maxlength="500"', bloco) is not None)
    check('#vac-decision-status é um parágrafo com role="status", fora do formulário',
          re.search(r'<p id="vac-decision-status" role="status">', bloco) is not None
          and bloco.index('id="vac-decision-status"') > bloco.index('class="vac-decision-final"'))
    for acao, texto in (("vac-approve", "Aprovar"), ("vac-reject", "Rejeitar")):
        check(f"o botão {texto} é type=button, começa disabled e liga-se por data-action={acao}",
              re.search(r'<button type="button"[^>]*data-action="' + acao + r'"[^>]*\bdisabled\b[^>]*>' + texto + "</button>",
                        bloco) is not None)
    aviso = re.search(r'<p class="vac-decision-final">([^<]*)</p>\s*<div class="form-actions[^"]*">\s*<button', bloco)
    check("o aviso fixo, junto aos botões, diz que a decisão é final e que aprovar não aplica nada no Wazuh",
          aviso is not None and "final" in aviso.group(1) and "não aplica nada no Wazuh" in aviso.group(1))
    aba = index_html.find('id="tab-vaccines"')
    proxima = index_html.find('<div class="tab-content"', aba + 1)
    check("nenhum atributo on*= no bloco #tab-vaccines do index.html",
          aba != -1 and re.search(r"\son[a-z]+\s*=", index_html[aba:proxima]) is None)

    # b) vaccines.js: listener delegado, estado dos botões, analistas
    check('vaccines.js liga "vac-approve" e "vac-reject" por closest("[data-action]") num listener de #vac-detail-decision',
          '"vac-approve"' in js and '"vac-reject"' in js and 'closest("[data-action]")' in js
          and re.search(r'getElementById\("vac-detail-decision"\)\.addEventListener\("click"', js) is not None)
    check("vaccines.js não tem atributos on*= nem handlers inline", re.search(r"\bon[a-z]+\s*=\s*[\"']", js) is None)
    corpo = function_body(js, "vacDecide")
    check("vacDecide recusa o segundo clique (vacDeciding) e dessincroniza os botões (vacSyncDecisionControls)",
          "vacDeciding" in corpo and "vacSyncDecisionControls" in corpo)
    corpo = function_body(js, "vacSyncDecisionControls")
    check('vacSyncDecisionControls desativa os botões com vacDeciding ou com o select em ""',
          "disabled" in corpo and "vacDeciding" in corpo and '=== ""' in corpo)
    corpo = function_body(js, "vacLoadAnalysts")
    check("vacLoadAnalysts pede /api/soc/analysts?active_only=true e filtra por slVacAnalystOptions(",
          '"/api/soc/analysts?active_only=true"' in corpo and "slVacAnalystOptions(" in corpo)
    check("vaccines.js não guarda nada no armazenamento do browser", "localStorage" not in js and "sessionStorage" not in js)

    # c) campos lidos pelo JS e pelos helpers slVac*, contra as respostas reais
    check("/ui_helpers.js é servido e define slVacDecisionBody e slVacAnalystOptions",
          files["/ui_helpers.js"][0] == 200 and "function slVacDecisionBody(" in ui_js
          and "function slVacAnalystOptions(" in ui_js)
    real, respostas = real_api_keys()
    acessos = field_accesses(files)
    esperados = {("analyst", "id"), ("analyst", "name"), ("analyst", "active"), ("envelope", "analysts"),
                 ("envelope", "notice")}
    check("o JS lê analyst.id, analyst.name, analyst.active, envelope.analysts e envelope.notice", esperados <= acessos)
    desconhecidos = sorted(a for a in acessos if a[1] not in real and a[1] != "length")
    check("cada campo lido (vaccines.js e slVac*) existe nas respostas reais, incluindo analistas e decisões",
          not desconhecidos)
    if desconhecidos:
        print(f"       campos que a API não tem: {desconhecidos}")

    # d) analistas reais: só os ativos, e o helper devolve Eddie e Jeremy
    estado, analistas = respostas["analistas"]
    check("rota real: GET /api/soc/analysts?active_only=true -> 200 e sem o analista desativado",
          estado == 200 and sorted(a["name"] for a in analistas["analysts"]) == ["Eddie", "Jeremy"])
    opcoes = node_ui_helpers([["slVacAnalystOptions", [analistas]]])
    check("slVacAnalystOptions sobre o corpo real devolve Eddie e Jeremy, com id e nome",
          opcoes is not None and sorted((o["id"], o["name"]) for o in opcoes[0])
          == [("analyst-eddie", "Eddie"), ("analyst-jeremy", "Jeremy")])
    mike = {"analysts": [{"id": "analyst-mike", "name": "Mike", "active": 0}]}
    vazio = node_ui_helpers([["slVacAnalystOptions", [mike]]])
    check("slVacAnalystOptions nunca lista um analista com active 0", vazio is not None and vazio[0] == [])

    # e) decisões reais: segunda aprovação e lista depois das decisões
    segunda = respostas["decisao_409"]
    check("rota real: a segunda aprovação da mesma vaccine dá 409 already_decided",
          segunda is not None and segunda[0] == 409 and segunda[1] == {"detail": "already_decided"})
    lista = respostas["lista_decidida"]
    estados = {v["id"]: v["state"] for v in lista["vaccines"]} if lista else {}
    check("rota real: depois das decisões C está approved, B rejected e A (substituída) continua proposed",
          estados == {ID_C: "approved", ID_B: "rejected", ID_A: "proposed"})


_SLUG_RE = re.compile(r"^[a-z_]{1,64}$")


def client_code(status: int, body) -> str:
    """O código de erro como o cliente o vê: a regra de apiCodeFromResponse (api.js: 401 -> unauthorized,
    422 com lista -> validation_error, 403 sem slug -> forbidden, detail a casar ^[a-z_]{1,64}$ -> detail,
    senão http_<estado>, ou validation_error se for 422) seguida da de vacCodeFromApiError (vaccines.js:
    forbidden e validation_error passam a http_<estado>)."""
    detail = body.get("detail") if isinstance(body, dict) else None
    slug = detail if isinstance(detail, str) and _SLUG_RE.match(detail) else None
    if status == 401:
        code = "unauthorized"
    elif status == 422 and isinstance(detail, list):
        code = "validation_error"
    elif status == 403 and not slug:
        code = "forbidden"
    else:
        code = slug or ("validation_error" if status == 422 else f"http_{status}")
    return transport_code(code)


def transport_code(code: str) -> str:
    """A regra de vacCodeFromApiError: forbidden e validation_error ficam http_<estado> (o estado de
    ambos é fixo: 403 e 422)."""
    return {"forbidden": "http_403", "validation_error": "http_422"}.get(code, code)


def run_decision_errors() -> None:
    """D-11: cada erro que a decisão pode dar (rota, validação local, transporte) tem frase PT-PT em
    VAC_ERROR_TEXT, provada contra as recusas REAIS da rota; o texto do servidor nunca é a frase."""
    import vaccine_decision

    files = served()
    js = files["/vaccines.js"][2]
    api_js = files["/api.js"][2]
    objeto = re.search(r"const VAC_ERROR_TEXT = \{(.*?)^\};", js, re.S | re.M)
    corpo_objeto = objeto.group(1) if objeto else ""
    chaves = set(re.findall(r"^\s{2}([A-Za-z_]\w*):", corpo_objeto, re.M))
    frases = dict(re.findall(r'^\s{2}([A-Za-z_]\w*):\s*"(.*)",\s*$', corpo_objeto, re.M))

    # a) cobertura por conjunto de códigos
    pedidos = (set(vaccine_decision.ERROR_CODES) | set(main.VACCINE_DECISION_ROUTE_CODES)
               | {"analyst_required", "http_403", "http_405", "http_409", "http_500", "http_504"})
    em_falta = sorted(pedidos - chaves)
    check("VAC_ERROR_TEXT tem frase para vaccine_decision.ERROR_CODES, os códigos da rota, analyst_required "
          "e http_403/405/409/500/504", not em_falta)
    if em_falta:
        print(f"       códigos sem frase: {em_falta}")

    # b) transporte: as chaves de API_ERROR_TEXT (depois da regra de vacCodeFromApiError) têm frase
    api_obj = re.search(r"const API_ERROR_TEXT = \{(.*?)^\};", api_js, re.S | re.M)
    api_chaves = set(re.findall(r"^\s{2}([A-Za-z_]\w*):", api_obj.group(1), re.M)) if api_obj else set()
    check("api.js servido tem API_ERROR_TEXT com timeout, invalid_response e network_error",
          {"timeout", "invalid_response", "network_error"} <= api_chaves)
    transporte = {transport_code(c) for c in api_chaves} | {"http_405", "http_409", "http_500"}
    sem_frase = sorted(transporte - chaves)
    check("cada código de transporte do api.js (e http_405/409/500) tem frase em VAC_ERROR_TEXT", not sem_frase)
    if sem_frase:
        print(f"       códigos de transporte sem frase: {sem_frase}")

    # c) conteúdo das frases
    check("nenhuma frase de VAC_ERROR_TEXT contém 'Sem dados', 'undefined' nem 'null'",
          bool(frases) and not any(x in f for f in frases.values() for x in ("Sem dados", "undefined", "null")))
    curtas = sorted(c for c in pedidos | transporte if c in frases and len(frases[c]) < 20)
    check("cada frase dos códigos da decisão e do transporte tem pelo menos 20 caracteres", not curtas)
    for c in ("timeout", "invalid_response"):
        f = frases.get(c, "")
        check(f"{c}: diz que o pedido pode ter chegado ao backend, que a decisão pode ter ficado gravada e que "
              "a vista é atualizada, sem falar do Wazuh Indexer",
              "pode ter chegado" in f and "decisão" in f and "atualiz" in f and "Indexer" not in f)
    check("http_422 serve filtros e decisão (diz que o backend recusou o pedido, sem falar só de filtro)",
          "recusou o pedido" in frases.get("http_422", "") and "filtro" not in frases.get("http_422", "").lower())
    f = frases.get("invalid_author", "")
    check("invalid_author diz que o nome do analista tem caracteres fora do aceite e manda corrigi-lo na Equipa SOC",
          "nome" in f and "caracteres" in f and "Equipa SOC" in f)
    f = frases.get("already_decided", "")
    check("already_decided diz que outra pessoa ou outro separador já decidiu e que a vista é atualizada",
          "outro separador" in f and "atualiz" in f)
    f = frases.get("vaccine_superseded", "")
    check("vaccine_superseded diz que foi substituída e que se decide a atual", "substituída" in f and "atual" in f)
    check("analyst_inactive e analyst_not_found mandam escolher outro analista",
          all("outro analista" in frases.get(c, "") for c in ("analyst_inactive", "analyst_not_found")))
    gen = re.search(r'const VAC_GENERIC_ERROR = "([^"]*)"', js)
    check("VAC_GENERIC_ERROR já não diz 'ao ler' (serve leitura e decisão)",
          gen is not None and "ao ler" not in gen.group(1) and "vaccines" in gen.group(1))
    check("a frase de incidents_unavailable serve o gerador e a decisão (sem 'perder a ligação')",
          "perder a ligação" not in frases.get("incidents_unavailable", "x")
          and "Equipa SOC" in frases.get("incidents_unavailable", ""))

    # d) respostas reais da rota: o código que o cliente extrai tem frase própria
    _, respostas = real_api_keys()
    erros = respostas["erros_decisao"]
    check("recusas reais da rota de decisão obtidas (precisa de node)", erros is not None)
    esperados = {
        "already_decided": (409, "already_decided"), "vaccine_superseded": (409, "vaccine_superseded"),
        "reason_required": (422, "reason_required"), "analyst_not_found": (422, "analyst_not_found"),
        "analyst_inactive": (422, "analyst_inactive"), "invalid_body": (422, "invalid_body"),
        "invalid_author": (422, "invalid_author"), "invalid_decision": (422, "invalid_decision"),
        "invalid_reason": (422, "invalid_reason"), "invalid_vaccine_id": (422, "invalid_vaccine_id"),
        "entry_not_found": (404, "entry_not_found"), "metodo_put": (405, "http_405"),
        "sem_chave": (401, "unauthorized"),
    }
    for nome, (estado_esperado, codigo_esperado) in esperados.items():
        estado, corpo = (erros or {}).get(nome, (None, None))
        codigo = client_code(estado, corpo) if estado is not None else None
        check(f"rota real: {nome} -> {estado_esperado} e o cliente vê '{codigo_esperado}', com frase própria",
              estado == estado_esperado and codigo == codigo_esperado and codigo in frases
              and frases[codigo] != (gen.group(1) if gen else None))
        if estado is not None and (estado, codigo) != (estado_esperado, codigo_esperado):
            print(f"       obtido: {estado} {corpo!r} -> {codigo}")
    put_detail = ((erros or {}).get("metodo_put") or (None, {}))[1]
    check("o PUT na rota dá 405 com um detail que não é slug (o cliente cai em http_405)",
          isinstance(put_detail, dict) and not _SLUG_RE.match(str(put_detail.get("detail"))))

    # e) a própria regra client_code
    check("client_code segue a regra do api.js: 422 com lista, 403 sem slug, slug e http_<estado>",
          client_code(422, {"detail": [{"loc": []}]}) == "http_422"
          and client_code(403, {"detail": "Forbidden"}) == "http_403"
          and client_code(409, {"detail": "already_decided"}) == "already_decided"
          and client_code(500, {"detail": "Internal Server Error"}) == "http_500"
          and client_code(504, None) == "http_504")


def run_decision_view() -> None:
    """D-03, D-06, D-09, D-10, D-01, D-04: o bloco Decisão por modos, provado sobre as vaccines REAIS da rota
    (slVacDecisionView em node:vm) e pelo contrato de texto de vaccines.js."""
    files = served()
    js = files["/vaccines.js"][2]
    ui_js = files["/ui_helpers.js"][2]

    # a) modos sobre respostas reais
    _, respostas = real_api_keys()
    lista = respostas["lista_decidida"]
    por_id = {v["id"]: v for v in lista["vaccines"]} if lista else {}
    analistas = [{"id": "analyst-eddie", "name": "Eddie"}]
    check("há vaccines reais C, B e A depois das decisões", set(por_id) == {ID_C, ID_B, ID_A})
    vistas = node_ui_helpers([["slVacDecisionView", [por_id.get(i), analistas, None]] for i in (ID_C, ID_B, ID_A)])
    vc, vb, va = vistas if vistas else ({}, {}, {})
    check("vaccine C real (aprovada): decided, approved, autor Eddie",
          vc.get("mode") == "decided" and vc.get("state") == "approved" and vc.get("author") == "Eddie"
          and bool(vc.get("decidedAt")))
    check("vaccine B real (rejeitada): decided, rejected, motivo 'Regra ruidosa', autor Jeremy",
          vb.get("mode") == "decided" and vb.get("state") == "rejected" and vb.get("reason") == "Regra ruidosa"
          and vb.get("author") == "Jeremy")
    check("vaccine A real (proposta e substituída por B): superseded com supersededBy B, sem botões",
          va.get("mode") == "superseded" and va.get("supersededBy") == ID_B)
    sem_analistas = node_ui_helpers([["slVacDecisionView", [por_id.get(i), None, "http_500"]] for i in (ID_C, ID_A)])
    check("uma vaccine decidida ou substituída não depende da lista de analistas (mesmo com erro)",
          sem_analistas is not None and [v["mode"] for v in sem_analistas] == ["decided", "superseded"])
    avisos = node_ui_helpers([["slVacWarningText", [por_id.get(i, {}).get("state"), {"proposed": "Proposta",
                              "approved": "Aprovada", "rejected": "Rejeitada"}]] for i in (ID_C, ID_B, ID_A)])
    check("o aviso das vaccines reais: C aprovada, B rejeitada, A proposta, todos com 'não aplicada no Wazuh'",
          avisos == ["Aprovada — aceite pelo analista, não aplicada no Wazuh",
                     "Rejeitada — não aplicada no Wazuh", "Proposta — não aplicada no Wazuh"])

    # b) vacRenderDecision: só decide pelo helper, com um ramo por modo
    corpo = function_body(js, "vacRenderDecision")
    check("vacRenderDecision decide só por slVacDecisionView(vacDetailVaccine, vacAnalysts, vacAnalystsError)",
          "slVacDecisionView(vacDetailVaccine, vacAnalysts, vacAnalystsError)" in corpo)
    modos = ("none", "decided", "unknown_state", "superseded", "analysts_error", "loading", "no_analysts", "controls")
    em_falta = [m for m in modos if f'case "{m}"' not in corpo]
    check("vacRenderDecision tem um case por modo (none, decided, unknown_state, superseded, analysts_error, "
          "loading, no_analysts, controls)", not em_falta)
    check("o modo decided desenha autor, data e motivo por vacCell( e vacDate(, nunca HTML à mão",
          "vacCell(" in corpo and "vacDate(" in corpo and "vacShowDecisionLines(" in corpo and "innerHTML" not in corpo
          and "htmRender(" in function_body(js, "vacShowDecisionLines")
          and "htmlT`" in function_body(js, "vacShowDecisionLines"))
    check("vacRenderDecision mantém vacSyncDecisionControls() e o modo analysts_error usa vacErrorText(",
          "vacSyncDecisionControls()" in corpo and "vacErrorText(" in corpo)
    m = re.search(r'const VAC_NO_ANALYSTS_TEXT = "([^"]*)"', js)
    check("VAC_NO_ANALYSTS_TEXT diz 'Sem analistas ativos' e manda para a aba Equipa SOC",
          m is not None and "Sem analistas ativos" in m.group(1) and "Equipa SOC" in m.group(1))
    check("a frase da vaccine substituída diz 'já não pode ser decidida'", "já não pode ser decidida" in corpo)
    check("VAC_DECISION_LOADING_TEXT existe e o modo loading o usa",
          "const VAC_DECISION_LOADING_TEXT" in js and "VAC_DECISION_LOADING_TEXT" in corpo)
    check("'Sem dados' continua a aparecer uma só vez em vaccines.js (um erro nunca é ausência de dados)",
          js.count("Sem dados") == 1)

    # c) D-01: reposição ao mudar de vaccine; D-04: contador
    corpo = function_body(js, "vacSelect")
    pos = corpo.find("vacResetDecisionForm(")
    check("vacSelect repõe o formulário (vacResetDecisionForm) só quando o id muda, antes de atualizar vacSelectedId",
          pos != -1 and re.search(r"if\s*\(\s*id\s*!==\s*vacSelectedId\s*\)\s*vacResetDecisionForm\(\)", corpo) is not None
          and pos < corpo.find("vacSelectedId = id"))
    corpo = function_body(js, "vacResetDecisionForm")
    check("vacResetDecisionForm limpa o analista, o motivo, o contador (0/500) e a linha de estado",
          all(x in corpo for x in ("vac-decision-analyst", "vac-decision-reason", "vac-decision-count",
                                   'vacSetDecisionStatus("", false)', "slVacReasonCounter(")))
    check("vacSetDecisionStatus escreve #vac-decision-status e tira a classe de erro quando isError é falso",
          "vac-decision-status" in function_body(js, "vacSetDecisionStatus")
          and "classList.toggle" in function_body(js, "vacSetDecisionStatus"))
    check('há um listener "input" em #vac-decision-reason que escreve o contador com slVacReasonCounter(',
          re.search(r'getElementById\("vac-decision-reason"\)\.addEventListener\("input"', js) is not None
          and "slVacReasonCounter(" in js)

    # d) D-10: aviso por estado
    corpo = function_body(js, "vacDecide")
    check("o 200 da decisão atualiza o aviso com a vaccine da resposta (slVacWarningText( em vacDecide)",
          "slVacWarningText(" in corpo and "envelope.vaccine" in corpo)
    corpo = function_body(js, "vacRenderDetailError")
    check("vacRenderDetailError escreve o aviso de estado desconhecido e esconde o formulário (vacRenderDecision)",
          "slVacWarningText(null, VAC_STATE_LABELS)" in corpo and "vacDetailVaccine = null" in corpo
          and "vacRenderDecision()" in corpo)
    check("vaccines.js usa slVacWarningText( pelo menos 3 vezes (detalhe, resposta do POST e detalhe com erro)",
          js.count("slVacWarningText(") >= 3)
    check("ui_helpers.js servido define slVacDecisionView, slVacWarningText e slVacReasonCounter",
          all(f"function {n}(" in ui_js for n in ("slVacDecisionView", "slVacWarningText", "slVacReasonCounter")))


def run_conflict() -> None:
    """D-13, D-14: depois de um 409 (ou de qualquer erro em que o servidor pode ter gravado) o detalhe e a lista
    são refeitos; respostas fora de ordem são descartadas e o refresco nunca se perde. Provado sobre o 409
    REAL da rota e o detalhe real a seguir."""
    files = served()
    js = files["/vaccines.js"][2]
    ui_js = files["/ui_helpers.js"][2]
    eddie = [{"id": "analyst-eddie", "name": "Eddie"}]

    # a) o 409 real e o detalhe real a seguir
    _, respostas = real_api_keys((f"/api/vaccines/{ID_C}", f"/api/vaccines/{ID_A}"))
    segunda = respostas["decisao_409"]
    check("rota real: a segunda aprovação de C dá 409 com detail 'already_decided'",
          segunda is not None and segunda[0] == 409 and segunda[1] == {"detail": "already_decided"})
    codigo = client_code(*segunda) if segunda else None
    check("o cliente vê o código 'already_decided'", codigo == "already_decided")
    seguimento = node_ui_helpers([["slVacErrorFollowUp", [codigo]]])
    check("slVacErrorFollowUp('already_decided') == 'refresh' (node, ui_helpers.js real)",
          seguimento is not None and seguimento[0] == "refresh")
    estado, detalhe = respostas["extra"][f"/api/vaccines/{ID_C}"]
    vista = node_ui_helpers([["slVacDecisionView", [detalhe.get("vaccine"), eddie, None]]])
    check("o detalhe real de C a seguir ao 409 é approved e a vista refeita é decided (sem botões)",
          estado == 200 and detalhe["vaccine"]["state"] == "approved" and vista is not None
          and vista[0]["mode"] == "decided" and vista[0]["author"] == "Eddie")
    estado, antiga = respostas["extra"][f"/api/vaccines/{ID_A}"]
    erros = respostas["erros_decisao"] or {}
    super_resp = erros.get("vaccine_superseded")
    vista_a = node_ui_helpers([["slVacDecisionView", [antiga.get("vaccine"), eddie, None]]])
    check("rota real: decidir a vaccine substituída A dá 409 vaccine_superseded e o detalhe refeito é 'superseded'",
          super_resp is not None and super_resp[0] == 409 and client_code(*super_resp) == "vaccine_superseded"
          and vista_a is not None and vista_a[0]["mode"] == "superseded")

    # b) o seguimento de cada recusa real da rota
    codigos = {nome: client_code(*erros[nome]) for nome in erros}
    resultados = node_ui_helpers([["slVacErrorFollowUp", [c]] for c in codigos.values()]) if codigos else None
    por_nome = dict(zip(codigos, resultados)) if resultados else {}
    esperado = {"already_decided": "refresh", "vaccine_superseded": "refresh", "entry_not_found": "refresh",
                "analyst_not_found": "reload_analysts", "analyst_inactive": "reload_analysts",
                "reason_required": "none", "invalid_body": "none", "invalid_author": "none", "invalid_decision": "none",
                "invalid_reason": "none", "invalid_vaccine_id": "none", "metodo_put": "none", "sem_chave": "none"}
    check("cada recusa real da rota tem o seguimento previsto (refresh, reload_analysts ou none)",
          bool(por_nome) and all(por_nome.get(n) == v for n, v in esperado.items()))
    if por_nome:
        print(f"       seguimentos: {por_nome}")
    locais = node_ui_helpers([["slVacErrorFollowUp", [c]] for c in ("analyst_required", "reason_required", "invalid_reason")])
    check("os erros de validação local nunca mandam refazer nada", locais is not None and set(locais) == {"none"})
    check("slVacErrorFollowUp está definido no ui_helpers.js servido", "function slVacErrorFollowUp(" in ui_js)

    # c) vacRenderDecisionError: frase e seguimento, nunca um novo POST
    corpo = function_body(js, "vacRenderDecisionError")
    check("vacRenderDecisionError mostra vacErrorText( e escolhe o seguimento por slVacErrorFollowUp(",
          "vacErrorText(" in corpo and "slVacErrorFollowUp(" in corpo)
    check("seguimento refresh: vacSelect(vacSelectedId) refaz o detalhe e vacRefresh() a lista",
          "vacSelect(vacSelectedId)" in corpo and "vacRefresh()" in corpo)
    check("seguimento reload_analysts: vacLoadAnalysts()", "vacLoadAnalysts()" in corpo)
    check("vacRenderDecisionError nunca chama vacDecide( (sem novo POST automático)", "vacDecide(" not in corpo)

    # d) D-14: descarte fora de ordem em vacDecide
    corpo = function_body(js, "vacDecide")
    check("vacDecide captura seq antes do POST e compara com vacSelectSeq no sucesso e no erro (2 vezes)",
          "const seq = vacSelectSeq" in corpo and len(re.findall(r"seq (?:!==|===) vacSelectSeq", corpo)) >= 2)
    erro = corpo[corpo.find("catch (err)"):]
    check("no erro, uma resposta de outra vaccine não mostra a frase mas, se o seguimento é refresh, refaz a lista",
          "slVacErrorFollowUp(err.message)" in erro and "vacRefresh()" in erro
          and "vacRenderDecisionError(err.message)" in erro)

    # e) D-14: vacRefresh não perde um pedido por haver outro no ar
    corpo = function_body(js, "vacRefresh")
    check("vacRefresh tem a fila vacRefreshQueued (marcar, ler e limpar) e a declaração de topo",
          js.count("vacRefreshQueued") >= 4 and corpo.count("vacRefreshQueued") >= 3
          and re.search(r"^let vacRefreshQueued = false;", js, re.M) is not None)
    check("vacRefresh marca a fila quando já está a carregar e só então sai",
          re.search(r"if \(vacLoading\) \{\s*vacRefreshQueued = true;\s*return;\s*\}", corpo) is not None)
    check("vacRefresh continua a usar vacBuildQuery (query do pedido e query atual, pelo menos 2 vezes)",
          corpo.count("vacBuildQuery(") >= 2)
    fim = corpo[corpo.find("finally"):]
    check("no finally, vacRefresh limpa a marca e faz no máximo uma volta extra (vacRefresh() uma vez)",
          "vacRefreshQueued = false" in fim and fim.count("vacRefresh()") == 1)
    check("sem canal em tempo real nem temporizadores no seguimento (F16 D-15)",
          not any(x in js for x in ("setInterval", "setTimeout", "WebSocket")))


# --- run_state_ui ----------------------------------------------------------

_BADGE_NODE = r"""
const fs = require("node:fs");
const vm = require("node:vm");
const esc = (v) => String(v).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
const ctx = vm.createContext({
  htmlT: (strings, ...values) => strings.reduce((out, s, i) => out + s + (i < values.length ? esc(values[i]) : ""), ""),
});
vm.runInContext(fs.readFileSync(process.argv[1], "utf8"), ctx);
const calls = JSON.parse(fs.readFileSync(0, "utf8"));
process.stdout.write(JSON.stringify(calls.map((state) => ctx.vacStateBadge(state))));
"""


def node_state_badges(js: str, states):
    """Corre o vacStateBadge REAL de vaccines.js em node:vm (só as declarações de que depende, htmlT
    simulado com escape) e devolve o HTML por estado. None sem node ou se o node falhar."""
    node = shutil.which("node")
    if node is None:
        return None
    labels = re.search(r"^const VAC_STATE_LABELS = .*$", js, re.M)
    if labels is None:
        return None
    partes = [labels.group(0)] + [function_body(js, n) for n in ("vacCell", "vacLabel", "vacStateBadge")]
    if not all(partes):
        return None
    with tempfile.TemporaryDirectory() as tmp:
        origem = Path(tmp) / "badge.js"
        origem.write_text("\n".join(partes), encoding="utf-8")
        proc = subprocess.run([node, "-e", _BADGE_NODE, str(origem)], input=json.dumps(list(states)),
                              capture_output=True, text=True, encoding="utf-8", timeout=60)
    if proc.returncode != 0:
        print(proc.stderr)
        return None
    return json.loads(proc.stdout)


def css_rules(css: str) -> list[tuple[list[str], str]]:
    """(seletores, corpo) de cada bloco `seletores { corpo }` sem chavetas dentro (chega para o que se procura)."""
    sem_comentarios = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    return [([x.strip() for x in m.group(1).split(",")], m.group(2))
            for m in re.finditer(r"([^{}]+)\{([^{}]*)\}", sem_comentarios)]


def hidden_classes(html_block: str) -> set[str]:
    """Classes dos elementos do bloco que têm o atributo hidden."""
    classes: set[str] = set()
    for tag in re.finditer(r"<\w+\b[^>]*\shidden(?=[\s>=/])[^>]*>", html_block):
        found = re.search(r'class="([^"]*)"', tag.group(0))
        if found:
            classes.update(found.group(1).split())
    return classes


def run_state_ui() -> None:
    """17-03 (D-07, D-08, D-10): badge de estado, estilos com tokens, filtro por estado, contadores e textos."""
    files = served()
    index_html = files["/index.html"][2]
    js = files["/vaccines.js"][2]
    css = files["/style.css"][2]

    # a) badge de estado (D-07): texto + classe, nunca só cor
    badge = function_body(js, "vacStateBadge")
    check("vaccines.js define vacStateBadge com htmlT e hasOwnProperty sobre VAC_STATE_LABELS",
          bool(badge) and "htmlT`" in badge and "hasOwnProperty" in badge and "VAC_STATE_LABELS" in badge)
    check("vacRenderDecision mostra o estado por vacStateBadge (decided e proposed)",
          function_body(js, "vacRenderDecision").count("vacStateBadge(") >= 2)
    estados = ["proposed", "approved", "rejected", "xpto", None, "", 7, "<b>x</b>", "constructor"]
    nomes = ["proposed", "approved", "rejected", "xpto", "none", "vazio", "num", "html", "ctor"]
    html_estados = node_state_badges(js, estados)
    check("vacStateBadge corre em node (vaccines.js real)", html_estados is not None)
    if html_estados is not None:
        por_estado = dict(zip(nomes, html_estados))
        check("proposed -> 'vac-state vac-state-proposed' com o texto Proposta",
              "vac-state vac-state-proposed" in por_estado["proposed"] and ">Proposta<" in por_estado["proposed"])
        check("approved -> classe vac-state-approved e texto Aprovada",
              "vac-state vac-state-approved" in por_estado["approved"] and ">Aprovada<" in por_estado["approved"])
        check("rejected -> classe vac-state-rejected e texto Rejeitada",
              "vac-state vac-state-rejected" in por_estado["rejected"] and ">Rejeitada<" in por_estado["rejected"])
        check("estado desconhecido -> classe vac-state-unknown e o próprio texto",
              "vac-state vac-state-unknown" in por_estado["xpto"] and ">xpto<" in por_estado["xpto"])
        check("estado ausente, vazio ou não-string -> travessão, sem badge",
              all(por_estado[k] == "—" for k in ("none", "vazio", "num")))
        check("estado com HTML é escapado e a classe fica unknown (nunca injeta no atributo)",
              "<b>" not in por_estado["html"] and "&lt;b&gt;" in por_estado["html"]
              and "vac-state-unknown" in por_estado["html"])
        check("uma chave herdada ('constructor') não vira modificador: classe unknown",
              "vac-state-unknown" in por_estado["ctor"] and "vac-state-constructor" not in por_estado["ctor"])

    # b) estilos só com tokens (D-07)
    regras = css_rules(css)
    partilhada = next((sels for sels, corpo in regras if ".vac-verdict" in sels and "display: inline-block" in corpo), [])
    check("style.css põe .vac-state na regra partilhada dos badges (a de .vac-verdict)", ".vac-state" in partilhada)
    for classe in ("vac-state-approved", "vac-state-rejected", "vac-decision", "vac-decision-final",
                   "vac-decision-error", "vac-decision-form"):
        corpo = next((c for sels, c in regras if f".{classe}" in sels), None)
        check(f"style.css define .{classe} sem cores literais (só var(--...))",
              corpo is not None and not re.search(r"#[0-9a-fA-F]{3,8}\b|rgba?\(", corpo))
    corpo = next((c for sels, c in regras if ".vac-state" in sels and ".vac-verdict" not in sels), None)
    check("style.css define .vac-state (cor base) com var(--...)",
          corpo is not None and "var(--" in corpo and not re.search(r"#[0-9a-fA-F]{3,8}\b|rgba?\(", corpo))
    check("style.css define o botão desativado da decisão (opacity e cursor not-allowed)",
          any(".vac-decision-actions button:disabled" in sels and "not-allowed" in corpo and "opacity" in corpo
              for sels, corpo in regras))
    painel = index_html[index_html.index('id="tab-vaccines"'):index_html.index('id="tab-attack-registry"')]
    classes = sorted(hidden_classes(painel))
    check("há elementos com classe e hidden na aba Vaccines (o varrimento do [hidden] não é vazio)", len(classes) >= 1)
    for classe in classes:
        com_display = [c for sels, c in regras if f".{classe}" in sels and re.search(r"display\s*:\s*(?!none)", c)]
        if com_display:
            check(f".{classe} tem display em style.css e por isso a regra .{classe}[hidden] {{ display: none }}",
                  any(f".{classe}[hidden]" in sels and re.search(r"display\s*:\s*none", c) for sels, c in regras))
        else:
            check(f".{classe} (hidden) não define display: a regra [hidden] do navegador chega", True)
    check("o varrimento do [hidden] apanha classes sintéticas",
          hidden_classes('<div class="a b" hidden></div><p class="c"></p><div class="d" hidden="">') == {"a", "b", "d"})

    # c) filtro por estado (D-08): igual ao conjunto da API
    ui_js = files["/ui_helpers.js"][2]
    inicio = index_html.find('id="vaccines-panel"')
    fila = index_html.find('class="filter-row"', inicio)
    aviso = index_html.find('id="vac-notice"')
    bloco = index_html[fila:aviso] if fila != -1 and aviso != -1 else ""
    check("a filter-row tem label[for=vac-state-filter] e select#vac-state-filter",
          'for="vac-state-filter"' in bloco and re.search(r'<select[^>]*id="vac-state-filter"', bloco) is not None)
    seletor = re.search(r'<select[^>]*id="vac-state-filter"[^>]*>(.*?)</select>', bloco, re.S)
    opcoes = re.findall(r'<option\s+value="([^"]*)"\s*>(.*?)</option>', seletor.group(1), re.S) if seletor else []
    check("as options do filtro de estado são, por ordem, Todos, Proposta, Aprovada e Rejeitada",
          [(v, t.strip()) for v, t in opcoes]
          == [("", "Todos"), ("proposed", "Proposta"), ("approved", "Aprovada"), ("rejected", "Rejeitada")])
    estados_api = set(typing.get_args(main.VaccineState))
    check("os values não vazios do filtro são exatamente typing.get_args(main.VaccineState)",
          {v for v, _ in opcoes if v} == estados_api and len(estados_api) == 3)
    lista_js = re.search(r"^const VAC_STATES = \[([^\]]*)\];", js, re.M)
    estados_js = set(re.findall(r'"([^"]+)"', lista_js.group(1))) if lista_js else set()
    check("VAC_STATES em vaccines.js é exatamente o conjunto de main.VaccineState", estados_js == estados_api)
    corpo = function_body(js, "vacBuildQuery")
    check('vacBuildQuery só acrescenta state se VAC_STATES.includes(...) (params.set("state")',
          "VAC_STATES.includes(" in corpo and 'params.set("state"' in corpo and "vac-state-filter" in corpo)
    check('"vac-state-filter" está na lista de ids que pedem a lista de novo (evento change)',
          re.search(r'for \(const id of \[[^\]]*"vac-state-filter"[^\]]*\]\) \{\s*document\.getElementById\(id\)'
                    r'\.addEventListener\("change", vacRefresh\)', js) is not None)

    # d) a rota real aceita o que o filtro envia e recusa o resto
    caminhos = ("/api/vaccines?state=approved", "/api/vaccines?state=rejected", "/api/vaccines?state=proposed",
                "/api/vaccines?state=proposed&include_superseded=true", "/api/vaccines?state=xpto")
    _, respostas = real_api_keys(caminhos)
    extra = respostas["extra"]

    def ids_do_estado(caminho):
        codigo, corpo_json = extra[caminho]
        return codigo, [v["id"] for v in corpo_json.get("vaccines", [])]

    check("rota real: ?state=approved -> só a vaccine C", ids_do_estado(caminhos[0]) == (200, [ID_C]))
    check("rota real: ?state=rejected -> só a vaccine B", ids_do_estado(caminhos[1]) == (200, [ID_B]))
    check("rota real: ?state=proposed -> [] (a A está substituída)", ids_do_estado(caminhos[2]) == (200, []))
    check("rota real: ?state=proposed&include_superseded=true -> só a vaccine A",
          ids_do_estado(caminhos[3]) == (200, [ID_A]))
    check("rota real: ?state=xpto -> 422", extra[caminhos[4]][0] == 422)

    # e) contadores (D-08): três cartões kpi dentro do painel, antes da filter-row
    posicao = index_html.find('id="vac-counts"')
    check("#vac-counts é uma .kpi-grid dentro de #vaccines-panel, antes da filter-row",
          re.search(r'<div\s+class="kpi-grid"\s+id="vac-counts"', index_html) is not None
          and inicio != -1 and inicio < posicao < fila)
    zona = index_html[posicao:fila] if posicao != -1 and fila != -1 else ""
    rotulos = {"proposed": "Propostas", "approved": "Aprovadas", "rejected": "Rejeitadas"}
    for estado, rotulo in rotulos.items():
        cartao = re.search(r'<div\s+class="card"\s+id="vac-count-' + estado + r'"\s*>\s*<h3>(.*?)</h3>\s*'
                           r'<div\s+class="value">(.*?)</div>', zona, re.S)
        check(f"#vac-count-{estado} é um cartão com o rótulo {rotulo} e o valor inicial —",
              cartao is not None and cartao.group(1).strip() == rotulo and cartao.group(2).strip() == "—")
    check("os contadores têm a nota de que contam as vaccines atuais, independentemente dos filtros",
          "vaccines atuais" in zona and "independente dos filtros" in zona)
    check("a nota dos contadores é um panel-note e os h3 não levam emojis",
          'class="panel-note"' in zona and re.search(r"[\U0001F300-\U0001FAFF☀-➿]", zona) is None)
    corpo = function_body(js, "vacRenderCounts")
    check("vacRenderCounts usa slVacStateCounts( e kpiRender( e os três ids #vac-count-*",
          "slVacStateCounts(" in corpo and "kpiRender(" in corpo
          and all(f"vac-count-{e}" in corpo or e in corpo for e in rotulos))
    check("os cartões não são clicáveis (sem data-action no markup nem listener nos contadores)",
          "data-action" not in zona and re.search(r'getElementById\("vac-count[^"]*"\)\.addEventListener', js) is None
          and "addEventListener" not in corpo)
    corpo = function_body(js, "vacRefresh")
    check("vacRefresh passa envelope.state_counts a vacRenderCounts (também com reason no_data)",
          "vacRenderCounts(envelope.state_counts)" in corpo)
    erro = corpo[corpo.find("catch (err)"):corpo.find("finally")]
    check("o caminho de erro de vacRefresh desenha os contadores com null (—, nunca 0)",
          "vacRenderCounts(null)" in erro)
    check("kpi.js carrega antes de vaccines.js no index.html",
          index_html.index('<script src="kpi.js"></script>') < index_html.index('<script src="vaccines.js"></script>'))

    # f) os contadores sobre dados reais: slVacStateCounts (node, ui_helpers.js real)
    real_counts = (respostas["lista_decidida"] or {}).get("state_counts")
    resultado = node_ui_helpers([["slVacStateCounts", [real_counts]]])
    check("o state_counts real depois das decisões (C aprovada, B rejeitada, A substituída) é {0, 1, 1}",
          real_counts == {"proposed": 0, "approved": 1, "rejected": 1}
          and resultado is not None and resultado[0] == {"proposed": 0, "approved": 1, "rejected": 1})
    original = main.vaccine_store
    tmp = tempfile.TemporaryDirectory()
    try:
        main.vaccine_store = VaccineStore(os.path.join(tmp.name, "nao_existe.sqlite3"))
        vazio = client.get("/api/vaccines", headers=HEADERS)
    finally:
        main.vaccine_store = original
        tmp.cleanup()
    corpo_vazio = vazio.json() if vazio.status_code == 200 else {}
    resultado = node_ui_helpers([["slVacStateCounts", [corpo_vazio.get("state_counts", "ausente")]]])
    check("store inexistente: 200, reason no_data, state_counts null e os três contadores —(null), nunca 0",
          vazio.status_code == 200 and corpo_vazio.get("reason") == "no_data" and corpo_vazio.get("state_counts") is None
          and resultado is not None and resultado[0] == {"proposed": None, "approved": None, "rejected": None})
    check("slVacStateCounts está definido no ui_helpers.js servido", "function slVacStateCounts(" in ui_js)

    # g) textos fixos (D-10): ninguém diz que é só leitura
    nota = re.search(r'id="vaccines-panel">.*?<p class="panel-note">(.*?)</p>', index_html, re.S)
    texto = " ".join(nota.group(1).split()) if nota else ""
    check("o panel-note do cabeçalho diz que se pode aprovar ou rejeitar e que nada é aplicado no Wazuh",
          "aprovar ou rejeitar" in texto and ("não aplicada no Wazuh" in texto or "nunca é aplicada no Wazuh" in texto
                                              or "nenhuma vaccine é aplicada no Wazuh" in texto))
    check("o panel-note do cabeçalho não diz 'Só leitura' nem 'todas em estado proposta'",
          bool(texto) and "Só leitura" not in texto and "todas em estado proposta" not in texto)
    check("o panel-note diz que a decisão é final e que aprovada é só aceite pelo analista",
          "final" in texto and "aceite pelo analista" in texto)
    check("a aba Vaccines não diz 'Só leitura' em lado nenhum do index.html", "Só leitura" not in painel)
    topo = "\n".join(js.splitlines()[:15])
    check("o comentário de topo de vaccines.js não diz 'Só leitura' e diz que o analista pode aprovar",
          "Só leitura" not in topo and "aprovar" in topo and "Wazuh" in topo)


if __name__ == "__main__":
    run_tracer()
    run_guards()
    run_filters()
    run_states()
    run_detail()
    run_chain()
    run_decision()
    run_decision_contract()
    run_decision_errors()
    run_decision_view()
    run_conflict()
    run_state_ui()
    if failures:
        print(f"\n[FALHOU] {len(failures)} teste(s) falharam:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("\n[OK] Todos os testes passaram")
