"""
Suite do exportador de documentos brutos do Wazuh Indexer
(scripts/export_raw_events.py — marco R9, Fase 2, plano 02-03).

O que este ficheiro prova, e porquê:

    D-06   o ficheiro exportado é legível por `feature_extractor.extract_features`
           — a asserção que fecha o gap de `docs/ML.md:71-75`. A prova é uma
           LINHA POR DOCUMENTO devolvida pelo extractor sobre o ficheiro
           ESCRITO, não uma comparação de nomes de campo: um campo com o nome
           certo no sítio errado dava a mesma falsa segurança;
    T-02-17  a palavra-passe nunca sai em stdout nem em stderr;
    T-02-18  a pasta por omissão é `scripts/snapshots/`, que está no
           `.gitignore` — e nenhum teste escreve lá;
    T-02-20  duas exportações nunca partilham ficheiro, e o primeiro fica
           byte-idêntico;
    T-02-21  o pedido ao Indexer é limitado a MAX_DOCUMENTS e o CLI diz que a
           janela pode ter mais alertas do que os exportados;
    T-02-22  o que o Indexer devolve entra no ficheiro intacto (incluindo um
           campo inventado dentro do `_source` e o `_id`).

NÃO precisa do laboratório Wazuh: o único cliente de rede usado é o
`ClienteFalso`; a secção que prova que o caminho real do cliente serve
injeta um `_search` numa instância de `WazuhIndexerClient`, que não abre
socket nenhum. Todo o disco é `tempfile.TemporaryDirectory()` — nada é
escrito em `scripts/` nem em `scripts/models/`, e os dois `.pkl` do utilizador
não são tocados.

Correr (a partir de scripts/):
    python test_export_raw_events.py
"""

import ast
import asyncio
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

import httpx

import export_raw_events
import feature_extractor
import ml_evaluation
from wazuh_client import WazuhIndexerClient

try:  # o console do Windows pode não ser UTF-8 (ver CLAUDE.md, reconfigure)
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
SEGREDOS = ("segredo-de-teste", "segredo-muito-quebrado-1")

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def secao(titulo: str) -> None:
    print(f"\n--- {titulo} ---")


def _plural(n: int, singular: str, plural: str) -> str:
    return f"{n} {singular if n == 1 else plural}"


def recusa(acao) -> bool:
    """True só quando a ação levanta `ValueError` — uma exceção outra
    qualquer é um teste mal escrito, não uma recusa do exportador."""
    try:
        acao()
    except ValueError:
        return True
    except Exception:
        return False
    return False


# --- Documentos de teste --------------------------------------------------------
#
# O formato é o `_source` de um hit do Wazuh Indexer tal como
# `wazuh_client.get_recent_alerts` o devolve: `{**hit["_source"], "_id": ...}`.
# O mesmo formato do `alerta()` de test_ml_models_api.py:143, com
# `@timestamp`, `agent`, `rule` e `data.win.system/eventdata`.

DOCUMENTOS_BASE = 10


def alerta_bruto(indice: int, event_id: int = 4624, user: str = "jsilva",
                 ts: str | None = None) -> dict:
    """Um documento do `_source` + `_id`. Sem `full_log` normalizado, sem
    campos criaados pelo backend — só o que o Indexer devolve."""
    if ts is None:
        ts = f"2026-09-01T09:{indice:02d}:00Z"
    doc = {
        "@timestamp": ts,
        "agent": {"name": "WIN-PC01", "ip": "192.168.1.5", "id": "002"},
        "manager": {"name": "fnuno"},
        "rule": {"id": str(1000 + indice), "description": "Regra do laboratório",
                 "level": 5, "groups": ["windows", "security"]},
        "data": {"win": {"system": {"eventID": str(event_id), "computer": "WIN-PC01"},
                         "eventdata": {"targetUserName": user, "ipAddress": "192.168.1.10"}}},
        "full_log": "Tentativa de autenticação falhada — autenticação rejeitada",
    }
    if indice == 2:
        # Campo inventado do laboratório: prova que NADA é normalizado ou
        # aparado. Se o exportador inventasse um esquema, este campo sumia.
        doc["data"]["win"]["campos_do_lab"] = {
            "nota": "isto não existe no esquema do SentryLens",
            "score": 0.87,
        }
    return doc


def documentos(indice_base: int = 0) -> list[dict]:
    """Dez documentos válidos: quatro logons e seis falhas, todos com
    `@timestamp` e Event ID — é este o ficheiro que tem de dar DEZ linhas do
    `extract_features`."""
    docs = [alerta_bruto(i, 4624, user="mcosta", ts=f"2026-09-01T09:0{i}:00Z")
            for i in range(4)]
    docs += [alerta_bruto(i, 4625, user="convidado", ts=f"2026-09-02T03:0{i}:00Z")
             for i in range(6)]
    for posicao, doc in enumerate(docs):
        doc["_id"] = f"doc-de-teste-{indice_base}-{posicao}"
    return docs


class ClienteFalso:
    """O único cliente que este ficheiro usa contra o Indexer. Guarda os
    argumentos recebidos (para as asserções sobre `size`/`agent_name`) e
    devolve documentos brutos já prontos — nunca abre socket."""

    def __init__(self, docs=None, erro: Exception | None = None):
        self.docs = documentos() if docs is None else docs
        self.erro = erro
        self.chamadas: list[dict] = []

    async def get_recent_alerts(self, hours=24, min_level=0, size=200, agent_name=None):
        self.chamadas.append({"hours": hours, "min_level": min_level,
                              "size": size, "agent_name": agent_name})
        if self.erro is not None:
            raise self.erro
        return self.docs


# --- Corrida do CLI ------------------------------------------------------------

VARS_AMBIENTE_ISOLADAS = ("WAZUH_INDEXER_URL", "WAZUH_INDEXER_USER",
                          "WAZUH_INDEXER_PASSWORD", "WAZUH_VERIFY_SSL")


def correr_cli(argumentos, cliente, env=None) -> tuple[int, str, str]:
    """Chama `export_raw_events.main()` no próprio processo, com o cliente
    trocado, a saída num `StringIO` (que não tem `reconfigure` — é o que
    exercita o guarda) e o ambiente isolado.

    O ambiente é isolado de propósito: `load_dotenv` é trocado por um no-op e as
    quatro variáveis WAZUH_* são removidas durante a chamada, para que o teste
    dê o mesmo resultado com ou sem o `scripts/.env` do utilizador. A chamada a
    `load_dotenv` continua a existir no `main` — ver secção 11.
    """
    argv_original = sys.argv
    build_client_original = export_raw_events.build_client
    load_dotenv_original = export_raw_events.load_dotenv
    ambiente_original = {v: os.environ.pop(v, None) for v in VARS_AMBIENTE_ISOLADAS}

    saida, erro = io.StringIO(), io.StringIO()
    sys.argv = ["export_raw_events.py", *[str(a) for a in argumentos]]
    export_raw_events.build_client = lambda: cliente
    export_raw_events.load_dotenv = lambda *a, **k: False
    try:
        if env:
            os.environ.update(env)
        with contextlib.redirect_stdout(saida), contextlib.redirect_stderr(erro):
            codigo = export_raw_events.main()
    finally:
        sys.argv = argv_original
        export_raw_events.build_client = build_client_original
        export_raw_events.load_dotenv = load_dotenv_original
        for variavel, valor in ambiente_original.items():
            os.environ.pop(variavel, None)
            if valor is not None:
                os.environ[variavel] = valor
    return codigo, saida.getvalue(), erro.getvalue()


def listagem_scripts() -> dict:
    """Nome -> tamanho de tudo o que está em `scripts/` (fora do venv e do
    `__pycache__`, que o próprio import do teste mexe) e dos ficheiros da raiz
    do repositório. É o "teste de lado" que prova que nenhuma escrita do CLI
    sai da pasta pedida."""
    vistos: dict[str, int] = {}
    for raiz, pastas, ficheiros in os.walk(SCRIPT_DIR):
        pastas[:] = [p for p in pastas if p not in {".venv", "__pycache__"}]
        for nome in ficheiros:
            caminho = Path(raiz) / nome
            try:
                vistos[str(caminho)] = caminho.stat().st_size
            except OSError:
                vistos[str(caminho)] = -1
    for entrada in REPO_ROOT.iterdir():
        if entrada.is_file():
            vistos[str(entrada)] = entrada.stat().st_size
    return vistos


# --- Secções -------------------------------------------------------------------


def test_payload() -> None:
    secao("build_events_payload / describe_events — validação sem mexer nos documentos")

    check("(a) lista vazia -> lista vazia", export_raw_events.build_events_payload([]) == [])
    check("(b) um dicionário em vez de lista -> ValueError",
          recusa(lambda: export_raw_events.build_events_payload({"@timestamp": "x"})))
    check("(c) uma lista de strings -> ValueError",
          recusa(lambda: export_raw_events.build_events_payload(["x", "y"])))
    check("(d) uma lista com um dict e uma string -> ValueError",
          recusa(lambda: export_raw_events.build_events_payload([{"a": 1}, "y"])))
    check("(e) None -> ValueError",
          recusa(lambda: export_raw_events.build_events_payload(None)))

    docs = documentos()
    payload = export_raw_events.build_events_payload(docs)
    check("(f) a lista de dicts sai intacta", payload == docs)
    check("(g) e são os MESMOS objectos (nada é copiado nem reescrito)",
          payload[0] is docs[0])
    check("(h) o campo inventado sobrevive ao payload",
          payload[2]["data"]["win"]["campos_do_lab"]["score"] == 0.87)
    check("(i) o _id sobrevive ao payload", payload[0]["_id"].startswith("doc-de-teste"))

    # describe_events: contagens e janela. O `processable` é calculado pelo
    # `summarize_events` do motor — é o mesmo número que o `evaluate` vai usar.
    descricao = export_raw_events.describe_events(payload)
    check("(j) documents = número de documentos",
          descricao["documents"] == DOCUMENTOS_BASE)
    check("(k) processable = número de linhas do feature_extractor",
          descricao["processable"] == DOCUMENTOS_BASE)
    check("(l) primeiro @timestamp em ordem",
          descricao["first_timestamp"] == "2026-09-01T09:00:00Z")
    check("(m) último @timestamp em ordem",
          descricao["last_timestamp"] == "2026-09-02T03:05:00Z")

    sem_ts = [{"_id": "a"}, {"_id": "b"}]
    descricao_vazia = export_raw_events.describe_events(sem_ts)
    check("(n) sem @timestamp nenhum -> 'desconhecido' nos dois",
          descricao_vazia["first_timestamp"] == "desconhecido"
          and descricao_vazia["last_timestamp"] == "desconhecido")
    check("(o) e ainda assim conta os documentos", descricao_vazia["documents"] == 2)
    check("(p) documentos sem @timestamp não são processáveis",
          descricao_vazia["processable"] == 0)

    parcial = [{"@timestamp": "2026-09-01T09:00:00Z"}, {"_id": "sem timestamp"}]
    descricao_parcial = export_raw_events.describe_events(parcial)
    check("(q) com um só @timestamp, o primeiro e o último são esse",
          descricao_parcial["first_timestamp"] == descricao_parcial["last_timestamp"]
          == "2026-09-01T09:00:00Z")


def test_escrita() -> None:
    secao("unique_output_path / write_events_file — nunca sobrescrever, escrita atómica")

    momento = datetime(2026, 10, 10, 9, 5)
    with tempfile.TemporaryDirectory() as tmp:
        pasta = Path(tmp)

        primeiro = export_raw_events.unique_output_path(pasta, now=momento)
        check("(a) sem ficheiro nenhum devolve <data>_<hora>.json",
              primeiro.name == "2026-10-10_09-05.json")
        check("(b) e devolve um caminho que não existe", not primeiro.exists())
        primeiro.touch()

        segundo = export_raw_events.unique_output_path(pasta, now=momento)
        check("(c) já existente -> sufixo _2", segundo.name == "2026-10-10_09-05_2.json")
        check("(d) e devolve um caminho que não existe", not segundo.exists())
        segundo.touch()

        terceiro = export_raw_events.unique_output_path(pasta, now=momento)
        check("(e) já existentes dois -> sufixo _3, e ainda livre",
              terceiro.name == "2026-10-10_09-05_3.json" and not terceiro.exists())

        nome = export_raw_events.unique_output_path(pasta, now=momento, base_name="bruto")
        check("(f) com base_name usa esse nome, e também livre",
              nome.name == "bruto.json" and not nome.exists())

        destino = pasta / "bruto.json"
        docs = documentos()
        escrito = export_raw_events.write_events_file(docs, destino)
        check("(f) write_events_file devolve o caminho", escrito == destino)
        check("(g) e o ficheiro existe", destino.exists())

        bruto = destino.read_bytes()
        check("(h) JSON UTF-8 com ensure_ascii=False (o acento vai em bytes, não em \\u)",
              "autenticação" in bruto.decode("utf-8") and b"\\u00e7" not in bruto)
        check("(i) indent=2 (o payload é pretty-printed)", b"\n  {" in bruto)
        check("(j) termina com newline", bruto.endswith(b"\n"))
        check("(k) o conteúdo é a lista tal e qual", json.loads(bruto.decode("utf-8")) == docs)

        try:
            export_raw_events.write_events_file(docs, destino)
            levantou = False
        except FileExistsError:
            levantou = True
        check("(l) destino existente -> FileExistsError", levantou)
        check("(m) e o ficheiro anterior fica byte-idêntico",
              destino.read_bytes() == bruto)

        antes = sorted(p.name for p in pasta.iterdir())
        export_raw_events.write_events_file([], pasta / "vazio.json")
        check("(n) uma escrita nova não toca nos anteriores",
              all((pasta / anterior).exists() for anterior in antes))
        check("(o) e não deixa ficheiros temporários por limpar",
              [p.name for p in pasta.iterdir() if p.name.endswith(".tmp")] == [])
        check("(p) lista vazia escreve [] e nada mais", (pasta / "vazio.json").read_text(encoding="utf-8") == "[]\n")


def test_cliente_real_sem_rede() -> None:
    secao("fetch_events sobre um WazuhIndexerClient real com o _search trocado")

    capturado: dict = {}

    async def search_falso(index, query):
        capturado["index"] = index
        capturado["query"] = query
        return {"hits": {"hits": [
            {"_source": alerta_bruto(0, 4624), "_id": "abc123"},
            {"_source": alerta_bruto(1, 4625), "_id": "def456"},
        ]}}

    cliente = WazuhIndexerClient("https://exemplo.invalido:9200", "admin", SEGREDOS[0])
    cliente._search = search_falso  # tipo: ignore[method-assign]

    docs = asyncio.run(export_raw_events.fetch_events(cliente, hours=48, size=1000))

    check("(a) devolve dois documentos", len(docs) == 2)
    check("(b) cada um traz o _id do hit", [d["_id"] for d in docs] == ["abc123", "def456"])
    check("(c) o _source chega intacto (campo do laboratório incluído)",
          docs[0]["data"]["win"]["system"]["eventID"] == "4624")
    check("(d) query vai ao índice wazuh-alerts-*", capturado["index"] == "wazuh-alerts-*")
    check("(e) size é o que foi pedido", capturado["query"]["size"] == 1000)
    check("(f) min_level=0 aparece na query (todos os níveis)",
          {"range": {"rule.level": {"gte": 0}}} in capturado["query"]["query"]["bool"]["must"])

    payload = export_raw_events.build_events_payload(docs)
    check("(g) o exportador não transforma o que o cliente devolveu", payload == docs)
    check("(h) e o feature_extractor lê esse payload sem transformação",
          len(feature_extractor.extract_features(payload)) == 2)

    cliente_vazio = ClienteFalso([])
    check("(i) uma janela sem documentos não levanta",
          asyncio.run(export_raw_events.fetch_events(cliente_vazio, hours=1, size=10)) == [])
    check("(j) e o pedido saiu com o size pedido",
          cliente_vazio.chamadas[0]["size"] == 10)

    cliente_agente = ClienteFalso([])
    asyncio.run(export_raw_events.fetch_events(cliente_agente, hours=1, size=10,
                                               agent_name="WIN-PC01"))
    check("(k) --agent vai para o cliente",
          cliente_agente.chamadas[0]["agent_name"] == "WIN-PC01")
    check("(l) e min_level é sempre 0", cliente_agente.chamadas[0]["min_level"] == 0)

    # Nenhum socket aberto, mecanicamente: `_search` é o ÚNICO sítio do
    # `wazuh_client` que constrói um `httpx.AsyncClient`. Se este teste passar
    # com a classe trocada por uma que levanta, ninguém abriu ligação — nem
    # à porta 9200, nem a nenhuma outra (critério "nenhum comando desta fase
    # tentou ligar ao Indexer").
    import wazuh_client

    class ClienteQuebrado:
        def __init__(self, *a, **k):
            raise AssertionError("isto abriu uma ligação de rede")

    http_original = wazuh_client.httpx.AsyncClient
    wazuh_client.httpx.AsyncClient = ClienteQuebrado
    try:
        cliente_sem_rede = WazuhIndexerClient("https://localhost:9200", "admin", SEGREDOS[0])
        cliente_sem_rede._search = search_falso  # tipo: ignore[method-assign]
        documentos_sem_rede = asyncio.run(
            export_raw_events.fetch_events(cliente_sem_rede, hours=1, size=10))
        check("(m) nenhum socket aberto: o httpx.AsyncClient nunca foi construído",
              len(documentos_sem_rede) == 2)
    finally:
        wazuh_client.httpx.AsyncClient = http_original


def test_formato_compativel() -> None:
    secao("D-06: o ficheiro escrito é lido por feature_extractor.extract_features")

    with tempfile.TemporaryDirectory() as tmp:
        destino = Path(tmp) / "raw_events_2026-10-10.json"
        docs = documentos()
        codigo, saida, erro = correr_cli(["--hours", "48", "--output", str(destino)],
                                         ClienteFalso(docs))

        check("(a) sai com 0", codigo == 0)
        check("(b) nada no stderr", erro == "")
        check("(c) o ficheiro foi escrito onde foi pedido", destino.exists())

        exportado = json.loads(destino.read_text(encoding="utf-8"))

        # --- A asserção que fecha o gap de docs/ML.md:71-75 -------------
        linhas = feature_extractor.extract_features(exportado)
        check("(d) extract_features devolve UMA LINHA POR DOCUMENTO",
              len(linhas) == DOCUMENTOS_BASE)
        check("(e) todas com @timestamp válido",
              all(linha["timestamp"] for linha in linhas))
        check("(f) todas com Event ID válido",
              all(isinstance(linha["windows_event_id"], int) and linha["windows_event_id"] > 0
                  for linha in linhas))
        check("(g) e na ordem cronológica",
              [l["timestamp"] for l in linhas] == sorted(l["timestamp"] for l in linhas))

        # --- O caminho que o evaluate percorre, de facto -----------------
        check("(h) ml_evaluation.load_events_file aceita o ficheiro escrito",
              ml_evaluation.load_events_file(destino) == exportado)
        check("(i) e summarize_events dá total == processable",
              ml_evaluation.summarize_events(exportado) ==
              {"total": DOCUMENTOS_BASE, "processable": DOCUMENTOS_BASE})

        # --- Nada é normalizado, nada é inventado -----------------------
        check("(j) os documentos chegam intactos (igualdade dita-a-dita)", exportado == docs)
        check("(k) o campo inventado do laboratório sobrevive",
              exportado[2]["data"]["win"]["campos_do_lab"]["nota"].startswith("isto não existe"))
        check("(l) o _id do Indexer está em cada documento",
              all(d.get("_id", "").startswith("doc-de-teste") for d in exportado))

        # --- Honestidade do CLI ------------------------------------------
        check("(m) diz quantos documentos e quantos processáveis",
              f"{DOCUMENTOS_BASE} documentos" in saida and
              f"{DOCUMENTOS_BASE} processáveis" in saida)
        check("(n) diz a janela coberta",
              "2026-09-01T09:00:00Z" in saida and "2026-09-02T03:05:00Z" in saida)
        check("(o) diz Dataset bruto escrito em: <caminho>",
              f"Dataset bruto escrito em: {destino}" in saida)
        check("(p) dá o comando do evaluate a seguir",
              "model_registry.py evaluate" in saida and "--dataset-origin real" in saida)
        check("(q) avisa que o log de ataques tem de cobrir a janela",
              "cobrir a janela" in saida)
        check("(r) com 10 documentos não fala em truncagem",
              "pode conter mais alertas" not in saida)


def test_nunca_sobrescreve() -> None:
    secao("T-02-20: duas exportações no mesmo minuto dão dois ficheiros")

    with tempfile.TemporaryDirectory() as tmp:
        pasta = Path(tmp)
        destino = pasta / "raw.json"
        argumentos = ["--hours", "24", "--output", str(destino)]

        codigo1, _, _ = correr_cli(argumentos, ClienteFalso(documentos(0)))
        check("(a) primeira exportação sai com 0", codigo1 == 0)
        antes = destino.read_bytes()

        codigo2, saida2, _ = correr_cli(argumentos, ClienteFalso(documentos(1)))
        check("(b) segunda exportação também sai com 0", codigo2 == 0)
        check("(c) o primeiro ficheiro existe e é o pedido",
              destino.exists() and destino.name == "raw.json")
        check("(d) o segundo ficheiro é raw_2.json", (pasta / "raw_2.json").exists())
        check("(e) o primeiro fica BYTE-IDÊNTICO", destino.read_bytes() == antes)
        check("(f) e o CLI diz que não sobrescreve", "nunca se sobrescreve" in saida2)

        codigo3, _, _ = correr_cli(argumentos, ClienteFalso(documentos(2)))
        check("(g) uma terceira dá raw_3.json", (pasta / "raw_3.json").exists())
        check("(h) e o segundo também fica byte-idêntico",
              (pasta / "raw_2.json").exists() and codigo3 == 0)
        check("(i) três ficheiros, nada mais",
              sorted(p.name for p in pasta.iterdir()) ==
              ["raw.json", "raw_2.json", "raw_3.json"])

        codigo4, saida4, erro4 = correr_cli(["--hours", "24", "--output",
                                             str(pasta / "inexistente" / "x.json")],
                                            ClienteFalso(documentos(3)))
        check("(j) cria a pasta de destino se não existir",
              codigo4 == 0 and (pasta / "inexistente" / "x.json").exists() and erro4 == "")


def test_teto_de_documentos() -> None:
    secao("T-02-21: --size é limitado a MAX_DOCUMENTS e a truncagem é dita")

    check("(a) MAX_DOCUMENTS é 1000 (o mesmo teto de /api/ml-anomalies)",
          export_raw_events.MAX_DOCUMENTS == 1000)
    check("(b) DEFAULT_HOURS é 168 (uma semana)", export_raw_events.DEFAULT_HOURS == 168)

    with tempfile.TemporaryDirectory() as tmp:
        destino = Path(tmp) / "grande.json"
        cliente = ClienteFalso(documentos(7))
        codigo, saida, erro = correr_cli(["--size", "5000", "--output", str(destino)],
                                         cliente)

        check("(c) sai com 0", codigo == 0)
        check("(d) o pedido ao Indexer foi limitado a 1000",
              cliente.chamadas[0]["size"] == export_raw_events.MAX_DOCUMENTS)
        check("(e) o stdout diz 'limitado a 1000'", "limitado a 1000" in saida)
        check("(f) o ficheiro escrito tem os 10 documentos",
              len(json.loads(destino.read_text(encoding="utf-8"))) == DOCUMENTOS_BASE)

    with tempfile.TemporaryDirectory() as tmp:
        destino = Path(tmp) / "cheio.json"
        cliente = ClienteFalso([alerta_bruto(i) for i in range(export_raw_events.MAX_DOCUMENTS)])
        for posicao, doc in enumerate(cliente.docs):
            doc["_id"] = f"cheio-{posicao}"
        codigo, saida, _ = correr_cli(["--output", str(destino)], cliente)
        check("(g) uma janela cheia (1000 documentos) também avisa",
              codigo == 0 and "pode conter mais alertas" in saida)

    with tempfile.TemporaryDirectory() as tmp:
        codigo, _, erro = correr_cli(["--size", "0", "--output",
                                      str(Path(tmp) / "nunca.json")], ClienteFalso())
        check("(h) --size 0 é recusado com código 1", codigo == 1 and "Erro" in erro)
        check("(i) e nada é escrito", list(Path(tmp).iterdir()) == [])


def test_indexer_fora_do_ar() -> None:
    secao("T-02-19: Indexer fora do ar -> código 1, mensagem PT, sem ficheiro")

    with tempfile.TemporaryDirectory() as tmp:
        destino = Path(tmp) / "nunca.json"
        erro_rede = httpx.ConnectError("[WinError 10061] Nenhuma ligação pode ser feita")
        codigo, saida, erro = correr_cli(["--output", str(destino)],
                                         ClienteFalso(erro=erro_rede))

        check("(a) sai com 1", codigo == 1)
        check("(b) a mensagem começa por 'Erro'", erro.startswith("Erro"))
        check("(c) nomeia o Indexer e a porta", "9200" in erro)
        check("(d) diz o que verificar (VM/credenciais)",
              "WAZUH_INDEXER_PASSWORD" in erro and ".env" in erro)
        check("(e) NENHUM traceback em stdout ou stderr",
              "Traceback" not in saida and "Traceback" not in erro)
        check("(f) nada foi escrito", list(Path(tmp).iterdir()) == [])
        check("(g) o TIPO da exceção entra (para se saber o que foi) mas o texto "
              "dela não é despejado (pode trazer o URL)",
              erro_rede.__class__.__name__ in erro
              and str(erro_rede) not in erro)

    with tempfile.TemporaryDirectory() as tmp:
        destino = Path(tmp) / "nunca.json"
        codigo, _, erro = correr_cli(["--output", str(destino)],
                                     ClienteFalso(erro=httpx.HTTPStatusError(
                                         "500", request=httpx.Request("POST", "https://localhost:9200"),
                                         response=httpx.Response(500))))
        check("(h) um HTTP 500 também dá código 1 sem traceback",
              codigo == 1 and "Erro" in erro and "Traceback" not in erro)
        check("(i) e sem ficheiro", list(Path(tmp).iterdir()) == [])

    with tempfile.TemporaryDirectory() as tmp:
        destino = Path(tmp) / "nunca.json"
        codigo, _, erro = correr_cli(["--output", str(destino)],
                                     ClienteFalso(docs="isto não é uma lista de documentos"))
        check("(j) payload que não é uma lista de dicts -> código 1",
              codigo == 1 and "Erro" in erro and "Traceback" not in erro)
        check("(k) e sem ficheiro", list(Path(tmp).iterdir()) == [])


def test_janela_vazia() -> None:
    secao("Janela sem documentos: ficheiro escrito, e o evaluate recusa-se a seguir")

    with tempfile.TemporaryDirectory() as tmp:
        destino = Path(tmp) / "vazio.json"
        codigo, saida, erro = correr_cli(["--output", str(destino)], ClienteFalso([]))

        check("(a) sai com 0", codigo == 0 and erro == "")
        check("(b) o ficheiro é uma lista vazia",
              json.loads(destino.read_text(encoding="utf-8")) == [])
        check("(c) o stdout diz '0 documentos'", "0 documentos" in saida)
        check("(d) e diz 0 processáveis", "0 processáveis" in saida)
        check("(e) a janela é 'desconhecido'", "desconhecido" in saida)

        check("(f) extract_features desse ficheiro devolve []",
              feature_extractor.extract_features(json.loads(destino.read_text(encoding="utf-8"))) == [])

        try:
            ml_evaluation.load_events_file(destino)
            codigo_erro = None
        except ml_evaluation.EvaluationError as exc:
            codigo_erro = exc.code
        check("(g) e o evaluate recusa-se a seguir com events_empty",
              codigo_erro == "events_empty")


def test_credenciais() -> None:
    secao("T-02-17: credenciais só do ambiente, e a palavra-passe nunca sai")

    original = {v: os.environ.get(v) for v in VARS_AMBIENTE_ISOLADAS}
    try:
        for variavel in VARS_AMBIENTE_ISOLADAS:
            os.environ.pop(variavel, None)

        try:
            export_raw_events.build_client()
            levantou = None
        except ValueError as exc:
            levantou = str(exc)
        check("(a) sem WAZUH_INDEXER_PASSWORD o build_client recusa",
              levantou is not None)
        check("(b) e a mensagem diz qual é a variável e onde a definir",
              "WAZUH_INDEXER_PASSWORD" in (levantou or "")
              and ".env" in (levantou or ""))

        os.environ["WAZUH_INDEXER_PASSWORD"] = SEGREDOS[0]
        os.environ["WAZUH_INDEXER_USER"] = "admin"
        cliente = export_raw_events.build_client()
        check("(c) com a password definida monta o cliente", cliente.user == "admin")
        check("(d) e o default do Indexer é https://localhost:9200",
              cliente.base_url == "https://localhost:9200")
        check("(e) verify_ssl é False por omissão (o laboratório é autoassinado)",
              cliente.verify_ssl is False)

        os.environ["WAZUH_VERIFY_SSL"] = "true"
        check("(f) WAZUH_VERIFY_SSL=true liga a verificação",
              export_raw_events.build_client().verify_ssl is True)
        os.environ["WAZUH_VERIFY_SSL"] = "false"

        # O teste que importa: com a palavra-passe no ambiente, em NENHUM caso
        # ela aparece na saída — sucesso, payload inválido ou rede em baixo.
        with tempfile.TemporaryDirectory() as tmp:
            ambiente = {"WAZUH_INDEXER_PASSWORD": SEGREDOS[1]}
            casos = [
                (["--output", str(Path(tmp) / "ok.json")], ClienteFalso(), "sucesso"),
                (["--output", str(Path(tmp) / "erro.json")],
                 ClienteFalso(erro=httpx.ConnectError("recusado")), "rede em baixo"),
                (["--output", str(Path(tmp) / "lixo.json")], ClienteFalso("lixo"), "payload inválido"),
                (["--size", "0", "--output", str(Path(tmp) / "zero.json")],
                 ClienteFalso(), "argumento inválido"),
            ]
            for argumentos, cliente_falso, rotulo in casos:
                _, saida, erro = correr_cli(argumentos, cliente_falso, env=ambiente)
                check(f"(g/{rotulo}) a palavra-passe não sai em stdout nem em stderr",
                      SEGREDOS[1] not in saida and SEGREDOS[1] not in erro)

        # E o `build_client` a sério (sem cliente trocado) não imprime nada
        saida_crua, erro_cruo = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(saida_crua), contextlib.redirect_stderr(erro_cruo):
            export_raw_events.build_client()
        check("(h) construir o cliente não escreve nada",
              saida_crua.getvalue() == "" and erro_cruo.getvalue() == "")
    finally:
        for variavel, valor in original.items():
            os.environ.pop(variavel, None)
            if valor is not None:
                os.environ[variavel] = valor


def test_help_e_pureza() -> None:
    secao("--help, imports e a pasta por omissão")

    processo = subprocess.run(
        [sys.executable, "-X", "utf8", str(SCRIPT_DIR / "export_raw_events.py"), "--help"],
        cwd=SCRIPT_DIR, capture_output=True, text=True, encoding="utf-8", timeout=120)
    ajuda = processo.stdout
    check("(a) --help sai com 0", processo.returncode == 0)
    for opcao in ("--hours", "--size", "--agent", "--output"):
        check(f"(b) --help mostra {opcao}", opcao in ajuda)
    for opcao in ("--api-url", "--user", "--password", "--api-key"):
        check(f"(c) --help NÃO mostra {opcao} (as credenciais vêm do ambiente)",
              opcao not in ajuda)
    check("(d) o --help explica de onde vêm as credenciais",
          "WAZUH_INDEXER_PASSWORD" in ajuda)

    codigo = Path(export_raw_events.__file__).read_text(encoding="utf-8")
    arvore = ast.parse(codigo)
    importados = {a.name.split(".")[0]
                  for n in ast.walk(arvore) if isinstance(n, ast.Import)
                  for a in n.names}
    importados |= {(n.module or "").split(".")[0]
                   for n in ast.walk(arvore) if isinstance(n, ast.ImportFrom)}
    check("(e) o exportador NÃO importa main", "main" not in importados)
    check("(f) nem o backend (fastapi) nem o registo de modelos",
          "fastapi" not in importados and "model_registry" not in importados)
    check("(g) chama load_dotenv() (para o .env do utilizador)",
          "load_dotenv()" in codigo)
    for funcao in ("def fetch_events", "def unique_output_path",
                   "def write_events_file", "def describe_events"):
        check(f"(h) {funcao} aparece exactamente uma vez", codigo.count(funcao) == 1)
    check("(i) MAX_DOCUMENTS = 1000 está declarado uma vez",
          codigo.count("MAX_DOCUMENTS = 1000") == 1)
    check("(j) a escrita em disco é por temporário + os.replace (nunca um "
          "export parcial)",
          "os.replace" in codigo and "mkstemp" in codigo)

    # O exemplo de uso é copiável tal e qual: um caminho escrito a partir de
    # scripts/ que repetisse "scripts" escreveria em scripts/scripts/ — e
    # criava a pasta sem dizer nada.
    exemplos = [linha.strip().replace("\\\\", "\\")
                for linha in codigo.splitlines()
                if linha.strip().startswith("python export_raw_events.py")]
    check("(k) o exemplo de uso aponta para dentro de scripts/ (não scripts/scripts/)",
          bool(exemplos) and all("scripts\\scripts" not in linha for linha in exemplos))

    check("(k) a pasta por omissão é scripts/snapshots/",
          export_raw_events.DEFAULT_OUTPUT_DIR == SCRIPT_DIR / "snapshots")
    gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    check("(l) scripts/snapshots/ está no .gitignore (dataset real fora do git)",
          "scripts/snapshots/" in gitignore)
    check("(m) e scripts/models/ também",
          "scripts/models/" in gitignore)


def test_nada_fora_da_pasta() -> None:
    secao("Teste de lado: nenhuma escrita fora da pasta pedida")

    snapshots_antes = sorted(p.name for p in (SCRIPT_DIR / "snapshots").iterdir())
    modelos_antes = sorted(p.name for p in (SCRIPT_DIR / "models").iterdir())
    antes = listagem_scripts()
    with tempfile.TemporaryDirectory() as tmp:
        destino = Path(tmp) / "unico.json"
        codigo, _, _ = correr_cli(["--hours", "24", "--output", str(destino)],
                                  ClienteFalso(documentos()))
        check("(a) a corrida para o código 0", codigo == 0)
        check("(b) e o único ficheiro criado é o pedido",
              [p.name for p in Path(tmp).iterdir()] == ["unico.json"])

    depois = listagem_scripts()
    novos = sorted(set(depois) - set(antes))
    alterados = sorted(f for f in set(depois) & set(antes)
                       if depois[f] != antes[f])
    check("(c) nenhum ficheiro novo em scripts/ nem na raiz do repositório",
          novos == [])
    check("(d) nenhum ficheiro alterado", alterados == [])
    check("(e) scripts/snapshots/ continua igual",
          sorted(p.name for p in (SCRIPT_DIR / "snapshots").iterdir()) == snapshots_antes)
    check("(f) scripts/models/ nunca foi tocado (os dois .pkl do utilizador)",
          sorted(p.name for p in (SCRIPT_DIR / "models").iterdir()) == modelos_antes
          == ["isolation_forest.pkl", "scaler.pkl"])


SECOES = (
    test_payload,
    test_escrita,
    test_cliente_real_sem_rede,
    test_formato_compativel,
    test_nunca_sobrescreve,
    test_teto_de_documentos,
    test_indexer_fora_do_ar,
    test_janela_vazia,
    test_credenciais,
    test_help_e_pureza,
    test_nada_fora_da_pasta,
)


def run() -> None:
    for teste in SECOES:
        teste()

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")


if __name__ == "__main__":
    run()