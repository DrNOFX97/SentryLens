"""
Contrato estático da aba Vaccines (R11, Phase 14) sobre os ficheiros SERVIDOS
pelo serve_frontend.py, ligado às chaves reais de GET /api/vaccines. Sem
browser, sem node, sem Wazuh: não executa JavaScript, lê o texto de
vaccines.js e do index.html tal como o servidor estático os entrega e
compara cada campo que vaccines.js lê de um objeto da API com as chaves da
resposta REAL da rota (TestClient sobre um store temporário semeado pelo
motor de vaccines). Apanha, por exemplo, `created` em vez de `created_at`
sem precisar de um browser.

Segue o estilo de test_serve_frontend.py: standalone, check()/[OK]/[FALHOU],
sys.exit(1) em caso de falha.

Correr (a partir de scripts/):
    python test_vaccines_frontend.py
"""

import http.client
import os
import re
import sys
import tempfile
import threading
from http.server import HTTPServer
from pathlib import Path

os.environ.setdefault("SENTRYLENS_API_KEY", "test-key-vaccines-frontend")

from fastapi.testclient import TestClient

import main
import serve_frontend
import vaccine_engine
import vaccine_ingest
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

SERVED_PATHS = ("/index.html", "/vaccines.js", "/app.js", "/style.css")


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


API_VARS = ("envelope", "vaccine", "origin", "evidence", "proposal", "rule",
            "catalogEvent", "generator", "counts")
_ACCESS_RE = re.compile(r"\b(" + "|".join(API_VARS) + r")\s*\??\.\s*([A-Za-z_$][\w$]*)")


def data_accesses(js: str) -> set[tuple[str, str]]:
    """Pares (variável, propriedade) lidos de objetos vindos da API."""
    return set(_ACCESS_RE.findall(js))


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
        respostas["extra"] = {}
        for caminho in extra_paths:
            resposta = client.get(caminho, headers=HEADERS)
            respostas["extra"][caminho] = (resposta.status_code, resposta.json())
        return chaves, respostas
    finally:
        main.vaccine_store, main.vaccine_loop_state = original_store, original_state
        tmp.cleanup()


# --- varrimentos do ficheiro inteiro ----------------------------------------

_DECL_RE = re.compile(r"^(?:const|let|var|class|function|async function)\s+([A-Za-z_$][\w$]*)", re.M)
# Um helper vac* só conta como chamada (vacCell(...)): um identificador que
# apenas começa por "vac", como vaccine, é um dado cru da API.
_SAFE_INTERPOLATION_RE = re.compile(r"escapeHtml\(|vac[A-Za-z0-9_$]*\(|VAC_[A-Z_]+\b")
_INNERHTML_RE = re.compile(r"\.innerHTML\s*(\+?=)\s*(\S{0,40})")
_MESSAGE_RE = re.compile(r"\.message\b")
_MESSAGE_SINKS = ("vacErrorText", "vacRenderError", "vacRenderDetailError")


def top_level_decls(js: str) -> list[str]:
    """Identificadores declarados na coluna 0 (os globais que o ficheiro cria)."""
    return _DECL_RE.findall(js)


def interpolation_violations(js: str) -> list[str]:
    """Cada `${` tem de começar por escapeHtml(, por um helper vac* ou por uma
    constante VAC_*. Um identificador que só começa por vac (vaccine) não conta. Devolve o início das que não começam."""
    found = []
    for m in re.finditer(r"\$\{", js):
        resto = js[m.end():].lstrip()
        if not _SAFE_INTERPOLATION_RE.match(resto):
            found.append(resto[:40])
    return found


def innerhtml_violations(js: str) -> list[str]:
    """`.innerHTML =` só com um template (crase), uma chamada vac...( ou "";
    `.innerHTML +=` é sempre violação."""
    found = []
    for m in _INNERHTML_RE.finditer(js):
        operador, valor = m.group(1), m.group(2)
        if operador == "+=" or not (valor.startswith("`") or valor.startswith('""')
                                    or re.match(r"vac[A-Za-z0-9_$]*\(", valor)):
            found.append(m.group(0))
    return found


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
    check("o botão Candidates abre a aba e deixou de ser planeado",
          len(candidates) == 1 and "Candidates" in candidates[0]
          and "is-planned" not in candidates[0] and "nav-badge" not in candidates[0])
    for label, planned in (("Validation", "R12"), ("Approved", "R14"), ("Regression", "R14")):
        linha = [l for l in linhas if f'data-label="{label}"' in l]
        check(f"{label} continua planeado ({planned})",
              len(linha) == 1 and "is-planned" in linha[0] and f'data-planned="{planned}"' in linha[0])
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
    check("vaccines.js tem exatamente um fetch(", js.count("fetch(") == 1)
    corpo_request = function_body(js, "vacRequest")
    check("o fetch está dentro de vacRequest e leva X-API-Key", "fetch(" in corpo_request
          and '"X-API-Key": API_KEY' in corpo_request)
    check('vaccines.js pede "/api/vaccines"', '"/api/vaccines"' in js)
    check("a chave nunca vai na query (sem api_key=)", "api_key=" not in js)
    check("sem opção method nem verbos HTTP de escrita",
          re.search(r"\bmethod\s*:", js) is None and re.search(r"\b(POST|PUT|PATCH|DELETE)\b", js) is None)

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
    acessos = data_accesses(js)
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
    check("cada interpolação ${...} começa por escapeHtml(, vac* ou VAC_*", not interpolation_violations(js))
    check("cada atribuição a innerHTML é um template, um helper vac* ou vazia", not innerhtml_violations(js))
    check("vaccines.js não usa insertAdjacentHTML, outerHTML nem document.write",
          not any(x in js for x in ("insertAdjacentHTML", "outerHTML", "document.write")))
    check("o varrimento de interpolações apanha uma violação sintética",
          len(interpolation_violations("x = `<td>${vaccine.id}</td>`;")) >= 1
          and not interpolation_violations("x = `<td>${escapeHtml(a)}${vacCell(b)}${VAC_X}</td>`;"))
    check("o varrimento de innerHTML apanha uma atribuição de variável sintética",
          len(innerhtml_violations("body.innerHTML = texto;")) >= 1
          and not innerhtml_violations('a.innerHTML = `<b></b>`; b.innerHTML = vacRowsHtml(l); c.innerHTML = "";'))
    check("o varrimento de innerHTML apanha o operador += sintético",
          len(innerhtml_violations("body.innerHTML += `<tr></tr>`;")) >= 1)
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
    acessos = data_accesses(js)
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
    check("vacVerdictBadge escapa o veredito e o rótulo",
          function_body(js, "vacVerdictBadge").count("escapeHtml(") >= 2)
    check("vacSupersededNote desenha o id substituto por vacCell",
          "vacCell(vaccine.superseded_by)" in function_body(js, "vacSupersededNote"))

    # g) estilos
    for classe in ("vac-verdict", "vac-verdict-not_detected", "vac-verdict-partial", "vac-row-superseded",
                   "vac-superseded-note", "vac-generator-error", "vac-error-state"):
        check(f"style.css servido define .{classe}", re.search(r"\." + re.escape(classe) + r"\s*\{", css) is not None)


if __name__ == "__main__":
    run_tracer()
    run_guards()
    run_filters()
    run_states()
    if failures:
        print(f"\n[FALHOU] {len(failures)} teste(s) falharam:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("\n[OK] Todos os testes passaram")
