"""
Exportador dos documentos BRUTOS do Wazuh Indexer para um ficheiro que o
`feature_extractor.py` lê sem qualquer transformação (marco R9, Fase 2).

Porque é que `/api/alerts` não serve: o backend classifica cada alerta com
`event_catalog.classify_alert` ANTES de o servir, e o objeto que sai de lá já
não é o documento do Indexer. `feature_extractor.extract_features` lê
`@timestamp`, `data.win.system.eventID` e `data.win.eventdata.targetUserName`
do `_source` — campos que esse caminho não devolve na forma em que o
extractor os quer. É o gap que `docs/ML.md:71-75` regista desde o primeiro
ciclo real: os 500 documentos brutos de 2026-09-14 saíram do Indexer à mão e
o ficheiro (`real_events_2026-09-14.json`) nunca ficou no git.

Porque é que se fala com o Indexer diretamente: `WazuhIndexerClient.
get_recent_alerts` devolve exactamente `{**hit["_source"], "_id": hit["_id"]}` —
o documento bruto mais o identificador estável do OpenSearch — e é esse o
formato que o `feature_extractor` já consome no treino e na inferência, sem
qualquer camada pelo meio. Não é uma exportação nova: é a mesma consulta que
o backend já faz, com o cliente que o backend já tem.

O que este ficheiro NÃO faz: não rotula (o rótulo vem do `attack_log.jsonl`,
que o `evaluate` recebe à parte), não avalia e não treina. Escreve um ficheiro
e diz com honestidade o que ele contém, que janela cobre e o que pode ter
ficado de fora.

Limites honestos:

    - o pedido ao Indexer é limitado a MAX_DOCUMENTS (1000, o mesmo teto de
      `/api/ml-anomalies`). Uma janela com mais alertas fica TRUNCADA, e o
      CLI diz isso em vez de o esconder — os exportados são os mais recentes;
    - `--dataset-origin` NÃO é adivinhado aqui. Quem decide de onde vêm os
      dados é o `model_registry.py evaluate` (D-06);
    - a palavra-passe vem do ambiente (ou de `scripts/.env`, via
      `load_dotenv()`, como o backend) e nunca sai em stdout nem em stderr;
    - a pasta por omissão é `scripts/snapshots/`, que está no `.gitignore`:
      um dataset real do utilizador não vai para o git por este caminho.

Uso (a partir de scripts/, com o venv activo):
    python export_raw_events.py
    python export_raw_events.py --hours 168 --size 1000
    python export_raw_events.py --output scripts\\snapshots\\raw_events_hoje.json

Depois:
    python model_registry.py adopt        # se ainda não foi adotado
    python model_registry.py evaluate v1 --events <este ficheiro> \
        --attack-log attack_log.jsonl --dataset-origin real
"""

import argparse
import asyncio
import json
import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path

import httpx
from dotenv import load_dotenv

from ml_evaluation import summarize_events
from wazuh_client import WazuhIndexerClient

# Teto de documentos por exportação. É o mesmo teto que `/api/ml-anomalies`
# usa (main.py:774) — mais do que isto e o relatório do dashboard já mentiria
# sobre a cobertura.
MAX_DOCUMENTS = 1000

# Pasta por omissão: `scripts/snapshots/` está no `.gitignore:18`, que é o que
# impede um dataset real do utilizador de acabar no repositório.
DEFAULT_OUTPUT_DIR = Path(__file__).parent / "snapshots"

# Uma semana por omissão. O Indexer só guarda ~90 dias (retenção por omissão)
# e um dia não chega para um dataset com ataques espalhados por vários dias.
DEFAULT_HOURS = 168

# O `attack_log.jsonl` que o `evaluate` vai esperar, pela MESMA resolução de
# omissão do CLI (`$ATTACK_LOG_PATH` ou `scripts/attack_log.jsonl`).
DEFAULT_ATTACK_LOG = Path(__file__).parent / "attack_log.jsonl"

MENSAGEM_SEM_PASSWORD = (
    "WAZUH_INDEXER_PASSWORD não está definida nem no ambiente nem em "
    "scripts/.env. Define-a (ver scripts/.env.example) e volta a correr. "
    "Nada foi escrito."
)


def _plural(n: int, singular: str, plural: str) -> str:
    """1 palavra / N palavras, para o texto PT do CLI não sair torto."""
    return f"{n} {singular if n == 1 else plural}"


def _indexer_url() -> str:
    """Só o endereço, para as mensagens de erro poderem dizer onde se falhou.
    Nunca inclui a palavra-passe: o cliente faz Basic Auth à parte."""
    return os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200").rstrip("/")


def build_client() -> WazuhIndexerClient:
    """
    Monta o cliente do Indexer a partir do ambiente, com os MESMOS nomes de
    variável e os mesmos defaults do backend (`main.py:100-102` e `:221-222`),
    para que um `.env` que serve para o backend sirva também para aqui.

    Recusa, com uma mensagem accionável, quando não há palavra-passe: sem ela
    a falha seria um 401 do Indexer que não diz nada de útil. A palavra-passe
    em si nunca sai daqui.
    """
    password = os.getenv("WAZUH_INDEXER_PASSWORD", "")
    if not password:
        raise ValueError(MENSAGEM_SEM_PASSWORD)
    return WazuhIndexerClient(
        _indexer_url(),
        os.getenv("WAZUH_INDEXER_USER", "admin"),
        password,
        verify_ssl=os.getenv("WAZUH_VERIFY_SSL", "false").strip().lower() in ("1", "true", "yes"),
    )


async def fetch_events(client, hours: int = DEFAULT_HOURS, size: int = MAX_DOCUMENTS,
                       agent_name: str | None = None) -> list[dict]:
    """
    Uma única chamada a `WazuhIndexerClient.get_recent_alerts` — a MESMA
    consulta que o backend faz, com `min_level=0` (todos os níveis: um dataset
    de ML que só exportasse níveis altos não teria o que medir).

    Devolve a lista TAL COMO VEIO do cliente: `{**hit["_source"], "_id": ...}`.
    Nada é normalizado, renomeado ou aparado aqui — é essa a garantia que
    fecha o gap de `docs/ML.md:71-75`. Uma janela sem alertas dá `[]` e não
    levanta.
    """
    return await client.get_recent_alerts(
        hours=hours, min_level=0, size=size, agent_name=agent_name)


def build_events_payload(docs) -> list[dict]:
    """
    Valida a forma do que o Indexer devolveu e devolve a lista SEM TOCAR nos
    documentos — os mesmos objetos, os mesmos campos, mais nada (T-02-22).

    Recusa com `ValueError` o que não seja uma lista de dicionários: o
    `_search` do cliente já faz `{**hit["_source"], "_id": hit["_id"]}`, que
    levanta se um hit não tiver `_source`, mas um Indexer com um documento de
    formato inesperado tem de ser recusado com uma mensagem nossa e não com um
    `TypeError` a meio do `json.dump`.
    """
    if not isinstance(docs, list):
        raise ValueError(
            f"o Indexer devolveu {type(docs).__name__} e não uma lista de documentos "
            "(lista vazia, ou lista de objetos com @timestamp e data.win.system.eventID)"
        )
    for posicao, doc in enumerate(docs):
        if not isinstance(doc, dict):
            raise ValueError(
                f"o documento na posição {posicao} é {type(doc).__name__} e não um "
                "objeto JSON; a exportação foi abortada e nada foi escrito"
            )
    return docs


def describe_events(docs) -> dict:
    """
    O que o CLI diz sobre o que acabou de escrever, sem prometer mais do que
    entregou:

        documents        quantos documentos foram exportados;
        processable      quantos deles o `feature_extractor` consegue
                         transformar em linhas (timestamp + Event ID válidos).
                         É o mesmo número que o `evaluate` vai usar — dito por
                         `ml_evaluation.summarize_events`, o motor e não uma
                         contagem feita aqui à parte;
        first/last_timestamp  a janela realmente coberta. O Indexer devolve os
                         documentos do mais recente para o mais antigo e todos
                         em ISO-8601 com sufixo `Z`, que ordena
                         lexicograficamente; `None` (sem `@timestamp` em lado
                         nenhum) vira a string "desconhecido".
    """
    resumo = summarize_events(docs)
    carimbos = sorted(selo for selo in
                      (doc.get("@timestamp") for doc in docs
                       if isinstance(doc, dict))
                      if isinstance(selo, str) and selo.strip())
    if carimbos:
        primeiro, ultimo = carimbos[0], carimbos[-1]
    else:
        primeiro = ultimo = "desconhecido"
    return {
        "documents": resumo["total"],
        "processable": resumo["processable"],
        "first_timestamp": primeiro,
        "last_timestamp": ultimo,
    }


def unique_output_path(output_dir, now: datetime | None = None,
                       base_name: str | None = None) -> Path:
    """
    Nome livre na pasta pedida: `base_name` (quando o utilizador diz onde
    quer) ou o minuto actual, com sufixo numérico `_2`, `_3`, ... até não
    haver colisão. Nunca devolve um caminho que já exista (T-02-20) — o mesmo
    laço de `export_snapshot.py:55`.
    """
    pasta = Path(output_dir)
    nome = base_name or (now or datetime.now()).strftime("%Y-%m-%d_%H-%M")
    candidato = pasta / f"{nome}.json"
    sufixo = 2
    while candidato.exists():
        candidato = pasta / f"{nome}_{sufixo}.json"
        sufixo += 1
    return candidato


def write_events_file(docs, output_path) -> Path:
    """
    Grava a lista em JSON UTF-8 (`ensure_ascii=False`, `indent=2`, newline no
    fim) e devolve o caminho.

    Duas garantias:

        - NUNCA sobrescreve: um destino que já existe levanta
          `FileExistsError`. O `unique_output_path` já escolheu um nome livre;
          isto é a segunda barreira, para o caso de alguém chamar esta função
          directamente;
        - NUNCA deixa um export pela metade: escreve primeiro num ficheiro
          temporário NA MESMA pasta (mesmo volume, logo `os.replace` é
          atómico) e só depois o promote. Um ficheiro truncado por um Ctrl-C
          seria lido a seguir pelo `evaluate` como se fosse um dataset
          completo — a mesma razão do `metadata.json` do adopt (D-07).

    Entre a verificação de existência e o `os.replace` há uma janela de
      corrida de milissegundos que só um segundo processo simultâneo no mesmo
      caminho aproveita; para um CLI de exportação isso é aceitável e está
      escrito aqui para não ser uma surpresa.
    """
    caminho = Path(output_path)
    if caminho.exists():
        raise FileExistsError(f"{caminho} já existe — este exportador nunca sobrescreve")

    caminho.parent.mkdir(parents=True, exist_ok=True)
    descritor, temporario = tempfile.mkstemp(
        dir=str(caminho.parent), prefix=".export_raw_events-", suffix=".tmp")
    try:
        with os.fdopen(descritor, "w", encoding="utf-8") as handle:
            json.dump(docs, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        os.replace(temporario, caminho)
    except BaseException:
        Path(temporario).unlink(missing_ok=True)
        raise
    return caminho


def _destino(argumentado: str | None) -> Path:
    """
    O caminho a escrever: o que o `--output` diz (com sufixo numérico se já
    existir) ou um nome novo na pasta por omissão. O que o utilizador pede é
    respeitado; o que ele pede já ocupado nunca é destruído.
    """
    if not argumentado:
        return unique_output_path(DEFAULT_OUTPUT_DIR)
    pedido = Path(argumentado)
    return unique_output_path(pedido.parent, base_name=pedido.stem or "raw_events")


def _log_de_ataques() -> Path:
    """O mesmo `attack_log.jsonl` que o `evaluate` vai esperar por omissão."""
    return Path(os.getenv("ATTACK_LOG_PATH") or DEFAULT_ATTACK_LOG)


def _next_step(caminho: Path, log_ataques: Path, documentos: int) -> None:
    """
    O comando a seguir, copiável, e a ressalva que o torna honesto: o log de
    ataques tem de COBRIR a janela exportada, senão saem 0 ataques rotulados
    e o recall sai 0 por definição — não por falha do modelo (Pitfall 10).
    """
    if documentos == 0:
        print("\nAtenção: a janela não devolveu nenhum documento — este ficheiro "
              "vai ser recusado pelo evaluate (events_empty). Alarga --hours, ou "
              "tira --agent se estiveste a filtrar por um agente sem alertas.")
    print("\nPróximo passo — avaliar um modelo sobre este dataset real (D-06):")
    print("  1) se ainda não adotaste o modelo legado:  python model_registry.py adopt")
    print("  2) avaliar a versão, com a origem DECLARADA por ti (nunca adivinhada):")
    print(f'     python model_registry.py evaluate v1 --events "{caminho}" '
          f'--attack-log "{log_ataques}" --dataset-origin real')
    if not log_ataques.exists():
        print(f"\nAtenção: não encontrei {log_ataques.name}. Sem esse log o passo 2 "
              "sai com 0 ataques rotulados e o recall 0 por definição.")
    print("\nO log de ataques tem de cobrir a janela exportada; se não cobrir, o "
          "evaluate avisa e o recall sai 0 por definição, não por falha do modelo.")


def main() -> int:
    """
    CLI do exportador. `0` = ficheiro escrito; `1` = recusado com uma mensagem
    em português e SEM ficheiro escrito.

    As credenciais vêm do ambiente (ou de `scripts/.env`, que é o que
    `load_dotenv` lê) e não de opções: `--password` na linha de comando
    ficaria no histórico do shell. Não há `--api-url` nem `--user` por
    respeitar o mesmo caminho de sempre.
    """
    # Windows manda stdout/stderr para o codepage da consola, o que corrompe os
    # acentos quando a saída é redirecionada (ver main.py:31-32). O `hasattr`
    # é o que permite a isto ser testado com um `io.StringIO`, que não tem
    # `reconfigure`.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8")
            except (AttributeError, ValueError, OSError):
                pass

    load_dotenv()

    parser = argparse.ArgumentParser(
        prog="export_raw_events.py",
        description=(
            "Exporta os documentos BRUTOS do Wazuh Indexer para um JSON que o "
            "feature_extractor.py lê sem transformação, para alimentar o "
            "model_registry.py evaluate. Fala com o Indexer directamente — não "
            "com o backend e não com /api/alerts, cujo formato já classificado "
            "não serve."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Credenciais: só do ambiente (WAZUH_INDEXER_URL / WAZUH_INDEXER_USER / "
            "WAZUH_INDEXER_PASSWORD / WAZUH_VERIFY_SSL), ou de scripts/.env.\n"
            "Pasta por omissão: scripts/snapshots/, que está no .gitignore."
        ),
    )
    parser.add_argument("--hours", type=int, default=DEFAULT_HOURS,
                        help=f"Janela em horas (por omissão: {DEFAULT_HOURS}, uma semana)")
    parser.add_argument("--size", type=int, default=MAX_DOCUMENTS,
                        help=f"Nº máximo de documentos (limitado a {MAX_DOCUMENTS})")
    parser.add_argument("--agent", default=None,
                        help="Agente específico (por omissão: todos)")
    parser.add_argument("--output", default=None,
                        help="Ficheiro a escrever (nunca é sobrescrito; sem esta "
                             f"opção vai para scripts/snapshots/)")
    args = parser.parse_args()

    for opcao, valor in (("--hours", args.hours), ("--size", args.size)):
        if valor < 1:
            print(f"Erro: {opcao} tem de ser >= 1, não {valor}. Nada foi escrito.",
                  file=sys.stderr)
            return 1

    tamanho = min(args.size, MAX_DOCUMENTS)

    try:
        cliente = build_client()
        documentos = asyncio.run(fetch_events(
            cliente, hours=args.hours, size=tamanho, agent_name=args.agent))
        payload = build_events_payload(documentos)
    except httpx.HTTPError as exc:
        # O Indexer está em baixo, a porta está fechada ou as credenciais
        # bateram mal. O tipo de exceção entra; a exceção em si não — é a
        # exceção que pode trazer o URL e nunca deve trazer a palavra-passe.
        print(f"Erro ({exc.__class__.__name__}): não consegui falar com o Wazuh "
              f"Indexer em {_indexer_url()}. Verifica que a VM do Wazuh está "
              "ligada e que WAZUH_INDEXER_URL / WAZUH_INDEXER_USER / "
              "WAZUH_INDEXER_PASSWORD estão certas (scripts/.env, ver "
              "scripts/.env.example). Nada foi escrito.", file=sys.stderr)
        return 1
    except (ValueError, OSError) as exc:
        # `ValueError`: credenciais em falta ou payload inesperado.
        # `OSError`: algum problema de filesystem a ler o `.env`/a rede.
        print(f"Erro: {exc}", file=sys.stderr)
        return 1

    descricao = describe_events(payload)
    pedido = _destino(args.output)
    try:
        escrito = write_events_file(payload, pedido)
    except OSError as exc:  # FileExistsError é um OSError: nunca se sobrescreve
        print(f"Erro: não consegui escrever {pedido} — {exc}", file=sys.stderr)
        return 1

    if args.size > MAX_DOCUMENTS:
        print(f"Aviso: --size {args.size} limitado a {MAX_DOCUMENTS} (o mesmo teto "
              "de /api/ml-anomalies).")
    if args.output and escrito != Path(args.output).with_suffix(".json"):
        print(f"Nota: {Path(args.output).name} já existia — escrito em {escrito.name}; "
              "neste exportador nunca se sobrescreve.")

    print(f"Dataset bruto escrito em: {escrito}")
    print(f"  {_plural(descricao['documents'], 'documento', 'documentos')}, "
          f"{_plural(descricao['processable'], 'processável', 'processáveis')}")
    print(f"  janela coberta: {descricao['first_timestamp']} … "
          f"{descricao['last_timestamp']}")
    if descricao["documents"] >= MAX_DOCUMENTS:
        print(f"Atenção: a janela pode conter mais alertas do que os "
              f"{MAX_DOCUMENTS} exportados — os exportados são os mais recentes.")
    if descricao["processable"] < descricao["documents"]:
        print(f"Nota: {descricao['documents'] - descricao['processable']} "
              "documento(s) sem @timestamp ou sem Event ID não são processáveis; "
              "o evaluate usa só os processáveis.")

    _next_step(escrito, _log_de_ataques(), descricao["documents"])
    return 0


if __name__ == "__main__":
    sys.exit(main())