---
phase: 02-avaliacao-ligada-a-versao
plan: 03
subsystem: ml-registry
tags: [python, httpx, wazuh-indexer, opensearch, json, cli, standalone-tests, dataset-origin, ml, feature-extractor]

# Dependency graph
requires:
  - phase: fase-6-ml-anomaly-detection
    provides: "wazuh_client.WazuhIndexerClient.get_recent_alerts (devolve {**hit['_source'], '_id': hit['_id']}) e feature_extractor.extract_features (o que conta como documento processável)"
  - phase: 02-avaliacao-ligada-a-versao (02-01)
    provides: "ml_evaluation.summarize_events(docs) -> {total, processable} e ml_evaluation.load_events_file(path), o validador do contrato de 14 chaves"
  - phase: 02-avaliacao-ligada-a-versao (02-02)
    provides: "load_events_file com MAX_EVENTS_BYTES e errors_empty/events_unreadable, e o CLI `model_registry.py evaluate vN --events F --dataset-origin real`"
  - phase: export-snapshot
    provides: "export_snapshot.py — o padrão de nunca sobrescrever (unique_snapshot_path) e de mensagens PT que este exportador copia"
provides:
  - "scripts/export_raw_events.py — exportador dos documentos BRUTOS do Wazuh Indexer para um JSON que o feature_extractor lê: fetch_events, build_events_payload, describe_events, unique_output_path, write_events_file, build_client, main"
  - "scripts/test_export_raw_events.py — 11 secções, 142 checks, cliente do Indexer sempre falso, sem rede e sem o laboratório ligado"
  - "O caminho de execução real contra o Indexer, escrito como passo do utilizador com o comando exacto e o que verificar"
affects: [02-avaliacao-ligada-a-versao, r9, model-registry, ml-registry, docs/ML.md, fase-3, fase-r10]

actuals:
  tokens: 19800   # chars/4 sobre o diff real (2 ficheiros novos, +790 linhas); o estimate de 45000 era generoso
  tasks: 2
  commits: 2

# Tech tracking
tech-stack:
  added: []   # nada novo instalado — httpx 0.27.2 e python-dotenv 1.0.1 já estavam no scripts/requirements.txt
  patterns:
    - "Escrita por tempfile.mkstemp na MESMA pasta + os.replace: um Ctrl-C a meio não deixa um export pela metade, que o evaluate leria a seguir como dataset completo (o mesmo raciocínio do metadata.json do adopt, D-07)"
    - "Nome livre em duas camadas: unique_output_path escolhe o nome que não existe (sufixo _2/_3) e write_events_file recusa com FileExistsError um destino ocupado — o que o chamador escolheu nunca é destruído"
    - "O cliente real provado com `_search` trocado por um stub em memória: a forma que o Indexer devolve é a mesma do backend, sem abrir socket"

key-files:
  created:
    - scripts/export_raw_events.py
    - scripts/test_export_raw_events.py
  modified: []

key-decisions:
  - "O `--output` do utilizador é um NOME, não um destino intocável: se já existir, o exportador acrescenta o sufixo numérico e DIZ isso, em vez de recusar. O `FileExistsError` fica como segunda barreira para quem chama `write_events_file` directamente"
  - "A função que diz quanto é processável é `ml_evaluation.summarize_events`, a mesma que o evaluate vai usar: o CLI não promete um número que o motor não vá contar"
  - "Credenciais só do ambiente (nem `--api-url`, nem `--user`, nem `--password`): um `--password` na linha de comando ficaria no histórico do shell"
  - "Na falha de rede entra o TIPO da exceção (ConnectError, HTTPStatusError) e não o texto dela: a mensagem pode trazer o URL, e o URL nunca é a palavra-passe"
  - "A suíte isola o ambiente de cada corrida do CLI (as quatro variáveis WAZUH_* removidas + load_dotenv trocado por no-op), para o mesmo teste dar o mesmo resultado com ou sem o scripts/.env do utilizador; a chamada a load_dotenv() continua no main, presa por uma verificação de código-fonte"
  - "Prova mecânica de que nada toca a porta 9200: `_search` é o único sítio do wazuh_client que constrói um httpx.AsyncClient, e a suíte corre o fetch com essa classe trocada por uma que levanta"

patterns-established:
  - "A compatibilidade de formato entre o que se exporta e o que o feature_extractor lê prova-se CHAMANDO O EXTRATOR sobre o ficheiro escrito (uma linha por documento), nunca comparando nomes de campo — foi o que faltou em docs/ML.md:71-75"
  - "As funções puras do exportador (`build_events_payload`, `describe_events`, `unique_output_path`, `write_events_file`) são testadas sem o CLI, e o CLI é testado com `contextlib.redirect_stdout` num `io.StringIO` — que não tem `reconfigure`, e portanto exercita o guarda do Windows"

requirements-completed: [EVAL-02]

coverage:
  - id: D1
    description: "python export_raw_events.py escreve a lista JSON dos documentos BRUTOS do Indexer (o _source de cada hit mais o _id) e não toca em nenhum campo — um campo inventado dentro do _source chega intacto ao ficheiro"
    requirement: EVAL-02
    verification:
      - kind: unit
        ref: "scripts/test_export_raw_events.py#test_formato_compativel (j)/(k)/(l) e test_payload (h)/(i)"
        status: pass
    human_judgment: false
  - id: D2
    description: "O ficheiro exportado é legível pelo feature_extractor: extract_features(json.load(ficheiro)) devolve uma linha por documento com @timestamp e Event ID válidos — é esta asserção que fecha o gap de docs/ML.md:71-75"
    requirement: EVAL-02
    verification:
      - kind: unit
        ref: "scripts/test_export_raw_events.py#test_formato_compativel (d)-(i), sobre o ficheiro ESCRITO pelo main()"
        status: pass
    human_judgment: false
  - id: D3
    description: "O exportador não passa pelo backend: fala com o WazuhIndexerClient, não importa main, não pede API key e não usa o formato já classificado de /api/alerts"
    requirement: EVAL-02
    verification:
      - kind: unit
        ref: "scripts/test_export_raw_events.py#test_help_e_pureza (e)/(f) + gate AST do plano (exit 0) e test_cliente_real_sem_rede (d)/(m)"
        status: pass
    human_judgment: false
  - id: D4
    description: "Nunca sobrescreve: duas exportações no mesmo minuto dão <nome>.json e <nome>_2.json, e o primeiro ficheiro fica byte-idêntico"
    requirement: EVAL-02
    verification:
      - kind: unit
        ref: "scripts/test_export_raw_events.py#test_nunca_sobrescreve (a)-(i) e test_escrita (l)/(m)"
        status: pass
    human_judgment: false
  - id: D5
    description: "O pedido ao Indexer é limitado a 1000 documentos (o teto de /api/ml-anomalies) e a truncagem é dita ao utilizador em vez de escondida"
    requirement: EVAL-02
    verification:
      - kind: unit
        ref: "scripts/test_export_raw_events.py#test_teto_de_documentos (c)-(g)"
        status: pass
    human_judgment: false
  - id: D6
    description: "Indexer fora do ar ou payload inesperado: código 1, mensagem PT accionável, sem ficheiro escrito, sem traceback e sem a palavra-passe em stdout/stderr"
    requirement: EVAL-02
    verification:
      - kind: unit
        ref: "scripts/test_export_raw_events.py#test_indexer_fora_do_ar (a)-(k) e test_credenciais (g)"
        status: pass
    human_judgment: false
  - id: D7
    description: "Janela vazia: ficheiro escrito com [], o CLI diz 0 documentos, extract_features devolve [] e o evaluate recusa-se a seguir com events_empty"
    requirement: EVAL-02
    verification:
      - kind: unit
        ref: "scripts/test_export_raw_events.py#test_janela_vazia (a)-(g)"
        status: pass
    human_judgment: false
  - id: D8
    description: "O exportador termina a dizer qual é o attack_log que o evaluate vai esperar e avisa que o log tem de cobrir a janela"
    requirement: EVAL-02
    verification:
      - kind: unit
        ref: "scripts/test_export_raw_events.py#test_formato_compativel (p)/(q)"
        status: pass
    human_judgment: false
  - id: D9
    description: "A execução real contra o Indexer, com a VM ligada (export → verificar o feature_extractor → adopt → evaluate → aba Evaluation)"
    verification: []
    human_judgment: true
    rationale: "O laboratório Wazuh está desligado (portas 9200 e 55000 fechadas) e não é para ser ligado pelo executor. O que se pode provar sem o serviço está provado: o exportador roda inteiro com o cliente mockado, e o teste de compatibilidade chama mesmo o extract_features sobre o ficheiro escrito. O resto é execução do utilizador"

# Metrics
duration: ~55 min
completed: 2026-10-10
status: complete
---

# Phase 02 Plan 03: Exportador do dataset real (D-06)

**O exportador que faltava desde September: documentos brutos do Wazuh Indexer para um JSON que o `feature_extractor` lê sem transformação, com o formato provado a chamar o extractor sobre o ficheiro escrito — e nenhum caminho que dependa do laboratório estar ligado.**

## Performance

- **Duration:** ~55 min
- **Started:** 2026-10-10T21:20:00+01:00
- **Completed:** 2026-10-10T22:15:00+01:00
- **Tasks:** 2
- **Files modified:** 2 (ambos criados)

## Accomplishments

- `scripts/export_raw_events.py` (novo, 404 linhas): fala com o `WazuhIndexerClient` directamente — a mesma consulta que o backend já faz, com `min_level=0` — e escreve `{**_source, _id}` tal e qual. Não importa `main`, não usa API key e não pede palavra-passe na linha de comando (vem do ambiente ou de `scripts/.env`, como o backend). Termina a dizer o comando `evaluate` a correr, com o `--dataset-origin real` ditado pelo utilizador.
- **A compatibilidade de formato está provada, não afirmada:** o teste chama `feature_extractor.extract_features` sobre o ficheiro **escrito pelo `main()`** e exige uma linha por documento com `@timestamp` e Event ID válidos; e `ml_evaluation.load_events_file` em cima do mesmo ficheiro, que é a porta de entrada real do `evaluate`. Um campo inventado (`data.win.campos_do_lab`) sobrevive intacto — o que prova que nada é normalizado, e não apenas que os camposbons batem certo.
- **O caminho do cliente real também está provado, sem socket:** a suíte corre `fetch_events` sobre uma instância verdadeira de `WazuhIndexerClient` com o `_search` trocado por um stub em memória, e confirma que o que sai é mesmo `{**_source, _id}`. Numa segunda passagem, o `httpx.AsyncClient` do `wazuh_client` é trocado por uma classe que levanta — se alguém abrir uma ligação, o teste fica vermelho.
- **Nada é escrito onde não foi pedido:** escrita por `mkstemp` na mesma pasta + `os.replace` (nunca um export pela metade), `unique_output_path` com sufixo `_2`/`_3` e `FileExistsError` como segunda barreira, e um teste de lado que compara a listagem de `scripts/` e da raiz antes e depois de correr o CLI.
- **O teto de 1000 documentos é dito, não escondido:** `--size 5000` dá um pedido de 1000, imprime "limitado a 1000", e uma janela cheia imprime que a janela pode ter mais alertas do que os exportados (os exportados são os mais recentes).
- **O ficheiro de ataque que faz o rótulo não é exportado por aqui** (é fora de âmbito): o CLI diz qual é o `attack_log.jsonl` que o `evaluate` vai esperar e avisa que esse log tem de cobrir a janela — senão saem 0 ataques rotulados e o recall 0 por definição (Pitfall 10).

## Task Commits

Cada task foi commitada atomicamente:

1. **Task 1 — export_raw_events.py + test_export_raw_events.py**: `0ccdeaf` (feat)
2. **Task 2 — Fecho do exportador (caminho do exemplo de uso + prova de que ninguém abre socket)**: `b647697` (docs+test)

## Files Created/Modified

- `scripts/export_raw_events.py` - **novo**: `build_client` (credenciais do ambiente, com mensagem accionável se faltarem), `fetch_events` (uma chamada a `get_recent_alerts`), `build_events_payload` (valida lista de dicts, não toca nos documentos), `describe_events` (documents/processable/primeiro/último `@timestamp`), `unique_output_path` (nunca devolve um caminho existente), `write_events_file` (nunca sobrescreve, escrita atómica), `main()` com argparse `--hours/--size/--agent/--output` e código 0/1 sem traceback
- `scripts/test_export_raw_events.py` - **novo**: 11 secções, 142 checks, `ClienteFalso` como único cliente, `correr_cli` com `redirect_stdout`/`redirect_stderr` e ambiente isolado, disco sempre em `TemporaryDirectory`

## Decisions Made

- **`--output` é um nome, não um destino sacred** (ver Desvio 1): se já existir, acrescenta-se o sufixo e diz-se isso. Recusar seria mais simples, mas o plano exige duas exportações no mesmo minuto aresultarem em dois ficheiros.
- **`unique_output_path` ganhou um `base_name` opcional** em vez de haver uma segunda função: o plano exige `def unique_output_path` exactamente uma vez, e era isso que o `--output` do utilizador precisava.
- **`processable` vem do motor** (`ml_evaluation.summarize_events`), não de uma contagem feita no exportador: se um dia o motor mudar o que é processável, o número que o CLI imprime muda com ele.
- **Na falha de rede entra o tipo da exceção, não o texto**: `httpx` pode pôr o URL na mensagem, e o URL nunca é a palavra-passe. O teste confirma que o texto cru da exceção não sai e que o tipo sai.
- **`_log_de_ataques()` sem opção nova**: pela mesma resolução de omissão do `evaluate` (`$ATTACK_LOG_PATH` ou `scripts/attack_log.jsonl`), para o exportador e o evaluate apontarem sempre ao mesmo ficheiro.

## Deviations from Plan

### Auto-fixed Issues

**1. [Regra: behaviour do plano vs. `--output` explícito] `unique_output_path` com `base_name`**
- **Found during:** Task 1 (casos "duas execuções no mesmo minuto, mesmo --output")
- **Issue:** o plano pede `unique_output_path(output_dir, now)` com o nome tirado do minuto, e ao mesmo tempo duas execuções com o **mesmo** `--output` a darem `<nome>.json` e `<nome>_2.json`. Com a assinatura escrita no plano, um `--output` explícito seria um `FileExistsError` na segunda execução.
- **Fix:** `base_name=None` como terceiro argumento. Sem `--output` o nome continua a vir do minuto; com `--output` vem do nome pedido. Continua a ser `def unique_output_path` uma vez só, como o critério exige.
- **Files modified:** `scripts/export_raw_events.py`
- **Verification:** `test_nunca_sobrescreve` (a)-(i) — três execuções dão `raw.json`, `raw_2.json`, `raw_3.json` e os anteriores ficam byte-idênticos.
- **Committed in:** `0ccdeaf`

**2. [Regra: texto de PT que mente] "2)evaluate" e o bloco de próximo passo numa janela vazia**
- **Found during:** Task 2 (revisão do texto das mensagens contra `export_snapshot.py` e `_cmd_adopt`)
- **Issue:** o bloco de próximo passo era impresso mesmo com 0 documentos — sugeria um comando que o `evaluate` vai recusar com `events_empty`.
- **Fix:** "2)evaluate" passou a "2) avaliar", e uma janela vazia passa a dizer, antes do bloco, que o ficheiro vai ser recusado e o que fazer (alargar `--hours`, tirar `--agent`).
- **Files modified:** `scripts/export_raw_events.py`
- **Verification:** saída do CLI inspecionada nos dois casos; `test_janela_vazia` (a)-(g) continua verde.
- **Committed in:** `b647697`

**3. [Regra: exemplo copiável que cria a pasta errada] O caminho do exemplo de uso**
- **Found during:** Task 2 (revisão do docstring contra a Task 2 do plano)
- **Issue:** o docstring dizia "a partir de scripts/" e logo a seguir `--output scripts\\snapshots\\raw_events_hoje.json` — que resolve para `scripts/scripts/snapshots/`, criando uma pasta nova no sítio errado sem dizer nada.
- **Fix:** a forma que funciona a partir de `scripts/` ficou primeiro, com a forma da raiz do repositório logo a seguir. Um teste prende o exemplo com uma verificação de caminho.
- **Files modified:** `scripts/export_raw_events.py`, `scripts/test_export_raw_events.py`
- **Verification:** `test_help_e_pureza (k)`.
- **Committed in:** `b647697`

**4. [Regra: critério de aceitação sem prova mecânica] "Nenhum comando tentou ligar à porta 9200"**
- **Found during:** Task 2
- **Issue:** o critério é verificável por inspecção, não por teste. Um cliente real com `_search` trocado prova que o formato é o certo; não prova que nada abre socket.
- **Fix:** nova verificação `(m)` — o `httpx.AsyncClient` do `wazuh_client` (o único sítio que abre socket) é trocado por uma classe que levanta `AssertionError`, e o `fetch_events` corre na mesma. Passar é a prova.
- **Files modified:** `scripts/test_export_raw_events.py`
- **Verification:** `[OK] (m) nenhum socket aberto: o httpx.AsyncClient nunca foi construído`.
- **Committed in:** `b647697`

---

**Total deviations:** 4 auto-fixed (1 reconciliação interna do plano, 1 mensagem de CLI enganadora, 1 exemplo de uso com o caminho errado, 1 critério de aceitação sem prova)
**Impact on plan:** Nenhuma alteração de âmbito. `files_modified` foi exactamente o que o plano diz: `scripts/export_raw_events.py` e `scripts/test_export_raw_events.py`. Nenhum outro ficheiro do repositório foi tocado.

## Issues Encountered

- **`os.fdopen` + `except BaseException`**: o `os.replace` só entra depois de o temporário estar fechado e completo. A limpeza do temporário em `except BaseException` (com `raise`) apanha também o `KeyboardInterrupt` — um `except Exception` deixaria um `.export_raw_events-*.tmp` órfão em `snapshots/` num Ctrl-C.
- **Janela de corrida conhecida entre a verificação de existência e o `os.replace`**: dois processos a exportar para o mesmo caminho no mesmo milissegundo. Está escrito no docstring em vez de escondido; um exportador de CLI não precisa de `O_EXCL` sobre o destino final, porque o ficheiro temporário já é criado com `mkstemp` (que é exclusivo) e só a promoção é o instante aberto.
- **`load_dotenv` é trocado nos testes**: se o `scripts/.env` do utilizador tivesse `WAZUH_INDEXER_PASSWORD`, a seção de credenciais seria não-determinística. O ambiente é isolado por chamada, e a presença da chamada no `main` é presa por uma verificação de código-fonte (`(g)`).

## Achado que o plano não previa (para decisão do utilizador)

`scripts/snapshots/real_events_2026-09-14.json` **existe nesta máquina** — 1,7 MB, sem versionar (`scripts/snapshots/` está no `.gitignore:18`), datado de 2026-09-14 16:38. Verificado a leitura, sem escrever nada:

| medição | valor | contra |
|---|---|---|
| documentos | 500 | "500 alertas reais", `docs/ML.md:70` |
| processáveis (`extract_features`) | **35** | "35 eventos eram processáveis", `docs/ML.md:77` |
| janela dos 35 | 2026-09-14T15:22:39Z … 15:34:27Z | — |
| `ml_evaluation.load_events_file` | aceita (500) | o `evaluate` lê este ficheiro tal e qual |
| tem `_id` | não (exportado à mão, antes de o cliente o acrescentar) | irrelevante para o `feature_extractor` |

Ou seja: **o dataset de D-06 não se perdeu** — falta é o caminho reproduzível, que é o que este plano criou. E o ficheiro tem o formato bruto que o `feature_extractor` lê (35 processáveis bate certo com o número do `ml_training_report.json` e de `docs/ML.md`).

O problema ao lado: o `scripts/attack_log.jsonl` actual só tem **12 entradas, todas de 2026-10-06**, e a janela dos 35 eventos é de 2026-09-14 — **0 sobreposições, 0 ataques rotulados**. Um `evaluate` corrido hoje sobre este ficheiro daria recall 0 por definição (Pitfall 10), que é exactamente o modo silencioso de um número falso. O CLI do `evaluate` avisa nesse caso (`model_registry.py:1226`).

Nada disto foi corrigido aqui: o ficheiro de ataque é fora de âmbito deste plano, e `--dataset-origin` é do utilizador.

## User Setup Required

None — nada a instalar nem a configurar (`httpx` e `python-dotenv` já estavam em `scripts/requirements.txt`).

Bloqueio conhecido, igual ao do 02-01: **a execução real contra o Indexer é passo do utilizador**, com a VM ligada.

## Verification Run

Todos os comandos de `<verify><automated>` das duas tasks, com `scripts\.venv\Scripts\python.exe` (CPython 3.12.14), **laboratório Wazuh desligado** (9200 e 55000 fechadas) e **sem nenhum comando a abrir socket** (prova: `test_export_raw_events.py#test_cliente_real_sem_rede (m)`):

| # | Comando | Resultado |
|---|---|---|
| 1 | `test_export_raw_events.py` | exit 0, **142 `[OK]`**, 0 linhas `[FALHOU]` |
| 2 | `export_raw_events.py --help` | exit 0; mostra `--hours`, `--size`, `--agent`, `--output`; **não** mostra `--api-url`, `--user`, `--password`, `--api-key` |
| 3 | Gate AST: `export_raw_events.py` não importa `main` | exit 0; imports = argparse, asyncio, datetime, dotenv, httpx, json, ml_evaluation, os, pathlib, sys, tempfile, wazuh_client |
| 4 | `def fetch_events` / `def unique_output_path` / `def write_events_file` / `def describe_events` | 1 ocorrência cada |
| 5 | `MAX_DOCUMENTS = 1000` | 1 ocorrência |
| 6 | `run_all_tests.py` | exit 0, **38/38** (baseline 37/37; +1 ficheiro, runner **sem edição**) |
| 7 | `scripts/snapshots/` e `scripts/models/` | intactos (mesmos nomes, tamanhos e mtimes; os dois `.pkl` com 539673 e 767 bytes) |

Ciclo TDD respeitado: o `test_export_raw_events.py` foi escrito primeiro e correu a vermelho com `ModuleNotFoundError: No module named 'export_raw_events'` antes de o exportador existir.

## Next Phase Readiness

- **Pronto para 02-04** (concordância ao vivo, D-10): sem trabalho do meu lado. O que este plano dá ao 02-04 é o ficheiro real para o `<human-check>` da aba Evaluation.
- **A tensão D-06 mudou de forma:** deixou de ser "não há dataset" e passou a "o dataset existe mas não é reproduzível, e o `attack_log` actual não cobre a janela de nenhum dos dois". O 02-04 continua a não poder publicar número nenhum sem ataques que rotulem a janela — ver abaixo.
- **`docs/ML.md:71-75` está agora desatualizado** por este plano: o texto diz que os documentos brutos "foram obtidos diretamente do Indexer para este treino — gap registado para uma sessão futura". A sessão futura foi esta. **Não toquei em `docs/ML.md`** (está fora do `files_modified` do plano) — é decisão editorial do utilizador, e a tabela de 2026-09-14 continua a ser a do dataset real.
- **Risco residual a sinalizar:** `ml_evaluation.summarize_events` é agora chamada por um CLI. Se mudar o que o motor considera processável, o número que o exportador imprime muda com ele — o que é o comportamento pretendido, mas vale a pena saber que os dois dependem um do outro.
- **Pendente de humano:** nada foi corrido contra o Indexer real, e o `attack_log.jsonl` actual (2026-10-06) não rotula nada da janela de 2026-09-14.

---
*Phase: 02-avaliacao-ligada-a-versao*
*Completed: 2026-10-10*