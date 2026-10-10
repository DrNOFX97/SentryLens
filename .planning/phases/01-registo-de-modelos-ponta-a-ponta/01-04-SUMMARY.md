---
phase: 01-registo-de-modelos-ponta-a-ponta
plan: 04
subsystem: cli
tags: [python-stdlib, argparse, shutil-copy2, os-replace, tempfile, sha256, fail-closed, testing]

# Dependency graph
requires:
  - phase: (nenhuma — continua a primeira fatia do R9)
    provides: "model_registry.py com _root, ARTIFACT_FILES, detect_legacy, sha256_file, load_metadata, _verify_artifacts, resolve_version_dir, _active_state, build_models_report e a lista fechada de 9 códigos de erro (D-06)"
    plan: "01-02 (a1e4001, 2605b32, d5ba48a)"
  - phase: (nenhuma)
    provides: "os cinco avisos de mlmModelsNoticeText, incluindo o aviso de 'adopt interrompido' para active: null com versões em lista"
    plan: "01-03 (efd8a9b, 1f584c5)"
provides:
  - "model_registry.py: _materialize_version, _write_active_atomic, _resume_adoption e adopt(models_dir) — REG-03"
  - "REG-03: adopt copia (nunca move) os dois .pkl soltos para models/v1/ com metadata.json (origin adopted, adopted true, trained_at = mtime do modelo, trained_at_estimated true) e SHA-256 dos artefactos; os originais ficam intactos"
  - "D-01: o models/ACTIVE só é escrito se ainda não existir; com um ACTIVE prévio a v1 é criada e o ACTIVE fica exatamente como estava"
  - "T-01-23: adopt interrompido (v1 criada, falha só na escrita do ACTIVE) recupera-se voltando a correr o comando — verifica a v1 existente e escreve só o ACTIVE em falta, sem recopiar nada"
  - "T-01-24: a retoma recusa (already_adopted, sem escrever nada) uma v1 alheia, adulterada, com metadados inválidos ou que seja junction/symlink para fora de models/"
  - "model_registry.py: MESSAGES_PT (9 mensagens PT accionáveis, só do CLI) e main(argv) com argparse e o subcomando adopt [--models-dir DIR]"
  - "scripts/test_model_registry.py: 267 checks (era 128) — adopt de domínio, falha e retoma, e CLI por subprocess"
  - "scripts/test_ml_models_api.py: 142 checks (era 110) — adopção ponta a ponta com pickles reais e o fluxo interrompido/retomado contra as rotas"
affects: [fase-2-avalicao, fase-3-treino, doc-01, r10-ativar-versoes]

# Actuals — pares com o `estimate` do plano para calibrar estimativas futuras.
actuals:
  tokens: 13014
  tasks: 2
  commits: 4

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Temporário + os.replace para tudo o que fica visível: pasta v1.tmp-* (nome que não casa VERSION_ID_RE, logo invisível à listagem) e ficheiro ACTIVE.tmp-*, com limpeza no finally — nenhum comando de escrita deixa lixo nem versão a meio"
    - "adopt é idempotente por verificação, não por flag: `models/v1` existente nunca devolve already_adopted diretamente, entra em _resume_adoption, que só escreve quando o ACTIVE falta e a v1 bate com os .pkl legados byte a byte"
    - "Falha convertida no limite do comando: a retoma transforma QUALQUER erro (metadata_invalid, hash_mismatch, junction para fora, erro inesperado) em already_adopted, porque o único resultado aceitável de dúvida é não escrever o ACTIVE"

key-files:
  created: []
  modified:
    - scripts/model_registry.py
    - scripts/test_model_registry.py
    - scripts/test_ml_models_api.py

key-decisions:
  - "A ordem das escritas é fixa: v1 por os.replace, confirmação final com load_metadata + _verify_artifacts, e só então o ACTIVE. É o que torna o adopt interrompido recuperável sem desfazer nada — a alternativa (ACTIVE primeiro, com reversão) foi descartada pelo plano porque a própria reversão pode falhar pelo mesmo bloqueio"
  - "_resume_adoption compara o SHA-256 do metadata.json com o dos .pkl legados, e não só com o dos ficheiros da v1: sem esta comparação, uma v1 alheia com metadados coerentes seria activada em silêncio"
  - "except Exception a converter tudo em already_adopted dentro da retoma (fail-closed), em vez de propagar o código original: o código entra na __cause__ para o log, o utilizador vê só 'já adoptado'"
  - "O CLI imprime os SHA-256 das cópias e diz explicitamente que os originais não foram alterados: é a única garantia possível para quem está a mexer nos ficheiros de dados do utilizador"

patterns-established:
  - "Pattern: helper de teste `replace_bloqueado(*nomes)` que troca `model_registry.os.replace` por uma função que levanta PermissionError só nos destinos nomeados e delega nos restantes — simula o bloqueio do OneDrive/antivírus (Pitfall 5) sem depender do Windows real, e restaura no finally"
  - "Pattern: fotografia dos originais (sha256 + size + mtime) tirada ANTES e comparada depois, inclusive nos caminhos de falha e de retoma — é o que prova 'copia, nunca move' (T-01-17)"
  - "Pattern: os testes de CLI correm por subprocess com `python -X utf8 <script> adopt --models-dir <tmp>`, e o `main()` chamado no próprio processo com redirect_stdout/redirect_stderr para io.StringIO (que não tem reconfigure, logo exercita o guarda)"

requirements-completed: [REG-03]

coverage:
  - id: D1
    description: "adopt regista o modelo legado como v1: copia os dois .pkl para models/v1/ com metadata.json (origin adopted, adopted true, trained_at = mtime de isolation_forest.pkl, trained_at_estimated true) e SHA-256 + tamanho de cada artefacto"
    requirement: REG-03
    verification:
      - kind: unit
        ref: "scripts/test_model_registry.py#REG-03: origin/adopted/trained_at/trained_at_estimated/parameters/dataset/library_versions/evaluation + artifacts com sha256 e size_bytes dos originais"
        status: pass
    human_judgment: false
  - id: D2
    description: "Os .pkl originais ficam com o mesmo SHA-256, tamanho e mtime antes e depois do adopt, nunca são abertos para escrita, e nenhum caminho do código os move ou apaga"
    requirement: REG-03
    verification:
      - kind: unit
        ref: "scripts/test_model_registry.py#fotografar(root) == antes — no adopt normal, no adopt com ACTIVE prévio, na falha do os.replace, na falha só do ACTIVE e na retoma"
        status: pass
      - kind: unit
        ref: "scripts/test_model_registry.py#REG-03: os originais continuam em models/ / cópias com os mesmos bytes e o mesmo mtime (copy2)"
        status: pass
    human_judgment: false
  - id: D3
    description: "Depois do adopt sem ACTIVE prévio, models/ACTIVE passa a conter v1, GET /api/ml/models mostra a v1 activa e a entrada 'legado, sem metadados' desaparece (D-03), e o carregamento passa a ser verificado por SHA-256"
    requirement: REG-03
    verification:
      - kind: unit
        ref: "scripts/test_model_registry.py#REG-03: ACTIVE contém exactamente b'v1\\n' / report active 'v1', total 1, status 'ok' / nenhuma entrada legacy / resolve_active_artifacts -> v1 verificada"
        status: pass
      - kind: integration
        ref: "scripts/test_ml_models_api.py#(q) /api/ml/models -> active 'v1', adopted true, trained_at_estimated true, evaluation None, nenhuma entrada kind 'legacy'; /api/ml-anomalies -> 200; loaded == 'v1'"
        status: pass
    human_judgment: false
  - id: D4
    description: "Com um models/ACTIVE já existente, o adopt cria a v1, devolve active_written False, não altera um byte do ACTIVE e avisa no CLI como activar a v1 à mão (D-01); um adopt seguinte recusa com already_adopted"
    requirement: REG-03
    verification:
      - kind: unit
        ref: "scripts/test_model_registry.py#D-01: os bytes do ACTIVE ficaram exactamente iguais / o ACTIVE continua a apontar para v2 / adopt seguinte -> already_adopted"
        status: pass
      - kind: integration
        ref: "scripts/test_model_registry.py#CLI (d): adopt com ACTIVE prévio -> código 0 com 'Aviso' e 'escreve v1', ACTIVE intacto"
        status: pass
    human_judgment: false
  - id: D5
    description: "Adopt interrompido na escrita do ACTIVE: o comando recusa com registry_unavailable sem deixar ACTIVE nem temporários; voltar a correr o mesmo comando escreve só o ACTIVE em falta, sem recopiar nada, e a detecção volta a 200 com a v1 verificada"
    requirement: REG-03
    verification:
      - kind: unit
        ref: "scripts/test_model_registry.py#retoma: falha só no ACTIVE -> registry_unavailable; ACTIVE não existe; nenhum ACTIVE.tmp-*/v1.tmp-* sobrou; metadata.json e .pkl da v1 inalterados; ACTIVE == b'v1\\n'; resolve_active_artifacts -> v1 verificada; 3.º adopt -> already_adopted"
        status: pass
      - kind: integration
        ref: "scripts/test_ml_models_api.py#(r) /api/ml-anomalies -> 503 sem caminho na resposta -> adopt retomado (resumed True) -> /api/ml-anomalies -> 200 com active 'v1' e loaded 'v1'"
        status: pass
    human_judgment: false
  - id: D6
    description: "Um adopt sobre um registo já adoptado, sem modelo legado ou com uma v1 que não corresponde ao legado recusa com already_adopted / no_legacy_model sem escrever nada; um os.replace bloqueado ao criar a v1 recusa com registry_unavailable sem deixar v1 nem pastas temporárias"
    requirement: REG-03
    verification:
      - kind: unit
        ref: "scripts/test_model_registry.py#segundo adopt -> already_adopted / pasta vazia, inexistente e com só um .pkl -> no_legacy_model / os.replace bloqueado -> registry_unavailable sem v1 e sem v1.tmp-*"
        status: pass
      - kind: unit
        ref: "scripts/test_model_registry.py#retoma (i)-(iv): v1 adulterada, v1 alheia, metadata.json inválido e origin 'trained' -> already_adopted e o ACTIVE continua a não existir"
        status: pass
    human_judgment: false
  - id: D7
    description: "python model_registry.py adopt funciona como CLI: --help mostra o subcomando, o caminho feliz devolve 0 com os SHA-256 e 'models/ACTIVE -> v1', cada recusa devolve 1 com 'Erro (<código>): <mensagem PT accionável>' em stderr, e a falha de escrita diz o que fazer"
    requirement: REG-03
    verification:
      - kind: integration
        ref: "scripts/test_model_registry.py#CLI (a)-(f) por subprocess: 0/1, --help, D-01, e main() no próprio processo"
        status: pass
      - kind: integration
        ref: "scripts/test_model_registry.py#CLI (g)/(h): recuperação pelo CLI ('retomado' + 'models/ACTIVE -> v1') e 'Erro (registry_unavailable)' + 'volta a correr o comando', sem o caminho da pasta"
        status: pass
    human_judgment: false
  - id: D8
    description: "model_registry.py continua stdlib pura (sem joblib, ml_anomalies nem fastapi, verificado por AST), nunca desserializa pickle, e scripts/models/ real não é tocado em nenhum momento"
    requirement: REG-03
    verification:
      - kind: other
        ref: "AST sobre model_registry.py: imports = ['argparse', 'datetime', 'hashlib', 'hmac', 'json', 'os', 'pathlib', 're', 'shutil', 'sys', 'tempfile', 'typing'] (exit 0); todo o disco dos testes em tempfile.TemporaryDirectory(); ls scripts/models antes e depois mostra só os dois .pkl originais"
        status: pass
    human_judgment: false
  - id: D9
    description: "A aba Models no browser depois de adoptar o modelo real do utilizador: badges 'ativa' e 'adoptado', 'Treinado em 14/09/2026 (estimada)', 'Íntegra (SHA-256 verificado)', 'Sem avaliação', entrada legado desaparecida e aviso de reinício do backend a aparecer e a desaparecer"
    requirement: REG-03
    verification: []
    human_judgment: true
    rationale: "node:vm não tem DOM e nenhum teste deste plano arranca serviços: provar os badges, o painel de detalhe e o ciclo do aviso de reinício exige o backend e o frontend a correr e o adopt sobre scripts/models real — que mexe nos dados do utilizador e é decisão dele (ver <human-check> da Task 2 do plano). Acumula com o coverage.D10 de 01-01, 01-02 e 01-03."

# Metrics
duration: ~12min
completed: 2026-10-10
status: complete
---

# Phase 1 Plan 04: Adoção do modelo legado — Summary

**`python model_registry.py adopt` regista o modelo actual como `v1` por cópia — originais intactos, `ACTIVE` só quando não existe, e um adopt interrompido na escrita do `ACTIVE` recupera-se voltando a correr o mesmo comando.**

## Performance

- **Duration:** ~12 min
- **Started:** 2026-10-10T13:58:00+01:00 (estimado: pouco depois do commit de summary do 01-03, às 13:56:42)
- **Completed:** 2026-10-10T14:09:00+01:00
- **Tasks:** 2 (Task 1 domínio `adopt` + testes; Task 2 CLI + ponta a ponta)
- **Files modified:** 3 (nenhum criado) — 1006 linhas, +1005/−1
- **Estimate do plano:** 60 000 tokens / 2 tasks — o real foi ~13 000 (chars/4 sobre o diff).

## Accomplishments

- **`adopt` copia e nunca move, e isso é provado por uma fotografia, não por um argumento.** O teste tira SHA-256, tamanho e mtime dos dois `.pkl` soltos antes do `adopt` e compara depois — no caminho feliz, no caminho com um `ACTIVE` prévio, no caminho de falha do `os.replace`, na falha só do `ACTIVE` e na retoma. Nenhuma função do módulo abre os originais para escrita, os move ou os apaga.
- **Um `adopt` interrompido nunca deixa o laboratório sem recuperação.** O `ACTIVE` é escrito *depois* do `os.replace` da `v1`, por isso uma falha ali deixa a v1 criada e nada activo (a detecção dá 503, a listagem mostra a v1 íntegra com `active: null` e `active_error: null`, que é exactamente o estado que o aviso (c) do 01-03 já sabia descrever). Voltar a correr o comando verifica a v1 — metadados válidos, `origin: "adopted"`, SHA-256 do metadata contra o dos `.pkl` **e** contra o dos `.pkl` legados — e escreve só o `ACTIVE` em falta. O teste guarda os bytes e os mtimes da v1 antes da retoma e confirma que não foi recopiado nada.
- **A retoma é fail-closed em todas as entradas.** Quatro v1 diferentes — adulterada, alheia com metadados coerentes, `metadata.json` inválido e `origin: "trained"` — dão `already_adopted` sem escrever uma linha. A comparação com os `.pkl` legados é o que impede activar em silêncio um modelo que não é o que se ia adoptar; sem ela, uma v1 alheia com hashes correctos passaria.
- **D-01 respeitado ao byte.** Com um `ACTIVE` prévio, a v1 é criada, `active_written` é `False` e o ficheiro fica exactamente igual — o teste compara os bytes. O CLI transforma isso num aviso que diz como activar a v1 à mão, em vez de uma linha de erro.
- **O CLI diz o que fez e o que não fez.** Códigos de saída 0/1, `Erro (<código>): <mensagem PT>` em stderr, e as nove mensagens são accionáveis — a de `registry_unavailable` manda fechar o Explorador/OneDrive/antivírus e repetir o comando. No sucesso mostra os dois SHA-256, `models/ACTIVE -> v1` e que é preciso reiniciar o backend (a cache do modelo é por processo, D-02).

## Task Commits

Cada task foi commitada atomicamente:

1. **Task 1: `adopt()` copia o legado para v1 de forma atómica, escreve ACTIVE só se não existir e retoma um adopt interrompido** — `5a861e8` (feat)
2. **Task 2: CLI `python model_registry.py adopt` e verificação ponta a ponta depois de adoptar** — `f6ea5c7` (feat)
3. *(não é uma task)* **Summary do plano** — `38472e2` (docs)
4. *(não é uma task)* **Correcção de um docstring** — `eec7471` (fix): "em qualquer outcome" → "em qualquer caso", em `_materialize_version`. Só texto; nenhum teste foi tocado.

_Note: as duas tasks têm `tdd="true"`. Os casos de comportamento foram acrescentados primeiro a `scripts/test_model_registry.py` e corridos a falhar — `AttributeError: module 'model_registry' has no attribute 'adopt'` — e só depois o `model_registry.py` foi implementado. Na Task 1 a implementação também divergiu do plano uma vez durante o ciclo TDD: a primeira versão da retoma propagava o erro original (ver Deviation 1)._

**Commits sem `Co-Authored-By` e sem "Generated with ..."** (D-08): confirmado com `git log --format=%B 8e27f21..HEAD` filtrado por `co-authored-by|generated with` → **vazio**. (O `grep` binário não existe nesta máquina Windows; foi o equivalente em PowerShell, `Select-String`.)

## Files Created/Modified

- `scripts/model_registry.py` — **alterado.** +360 linhas. Imports a juntar: `argparse`, `os`, `shutil`, `sys`, `tempfile` (continua sem `joblib`/`ml_anomalies`/`fastapi`, verificado por AST). Secção "Escrita no registo": `_materialize_version` (pasta `v1.tmp-*` + `shutil.copy2` + SHA-256 da cópia contra o do original + `metadata.json` + `os.replace`, com limpeza no `finally`), `_write_active_atomic` (ficheiro temporário + `os.replace`), `_resume_adoption` e `adopt`. Secção "CLI": `MESSAGES_PT` (9 mensagens), `_cmd_adopt` e `main(argv=None)` com `add_subparsers` e o subcomando `adopt [--models-dir DIR]`, mais `if __name__ == "__main__": sys.exit(main())`. O docstring do módulo ganhou um parágrafo a dizer que o CLI é o único ponto do projecto que escreve no registo.
- `scripts/test_model_registry.py` — **alterado.** +510/−1, 128 → **267** checks. Novos helpers `MTIME_FIXO`/`fixar_mtime`, `fotografar`, `restos` e `replace_bloqueado`; seis testes de domínio do adopt (cópia e metadados, D-01, pré-condições, falha a criar a v1, falha só no ACTIVE + retoma, e as quatro retomas recusadas) e dois de CLI (`correr_cli` por subprocess com `python -X utf8` e `cwd=scripts/`). `run()` chama os oito.
- `scripts/test_ml_models_api.py` — **alterado.** +136 linhas. `replace_bloqueado` e `adocao_ponta_a_ponta(client)` com os casos (q) — adopt, `/api/ml/models` com a v1 activa/adoptada/sem entrada legacy, `/api/ml-anomalies` 200 e `loaded: "v1"` — e (r) — adopt interrompido, 503 sem caminho na resposta, adopt retomado e 200. Pickles reais (`real_model_bytes`), como em `carregamento_verificado`.

## Decisions Made

- **`_materialize_version` confere o SHA-256 da cópia contra o do original** antes do `os.replace`. O plano pedia-o (T-01-20) e vale a pena o custo: uma cópia a meio que chegasse visível à listagem apareceria como `hash_mismatch`, não como uma v1 íntegra.
- **`_resume_adoption` converte qualquer falha em `already_adopted`** em vez de propagar o código original (`metadata_invalid`, `hash_mismatch`, ...). O utilizador que volta a correr o adopt não pode ficar a tentar "consertar" um registo que não tem nada de errado a não ser a situação dele — e o código original fica na `__cause__`, disponível para o log. Fail-closed, como manda T-01-24.
- **`already_adopted` nunca sai directamente de `adopt` quando `models/v1` existe** — sai sempre por `_resume_adoption`. É o que permite que um adopt interrompido se recupere e o que faz com que um adopt completo continue a recusar sem escrever nada.
- **`_write_active_atomic` não decide se escreve**; quem decide é o `adopt`, com a regra do D-01. A função fica responsável só pelo "nunca truncado", e a Fase 3 pode reutilizá-la tal e qual para activar uma versão treinada.
- **`--models-dir` resolve para `args.models_dir or os.environ.get("ML_MODEL_DIR") or DEFAULT_MODELS_DIR`** — a mesma pasta que o backend usa, nunca o cwd.
- **O CLI mostra os SHA-256 das cópias em vez de os esconder.** É a confirmação de que o que ficou registado é o que foi copiado, e é a garantia que dá sossego a quem tem o modelo em produção.
- **Nada foi escrito no `SKELETON.md`.** O contrato JSON não mudou (a entrada legacy e o esquema do `metadata.json` já estavam lá); o plano lista o SKELETON como contrato a consumir.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 5 — Correcção] A retoma propagava o erro original em vez de `already_adopted`**
- **Found during:** Task 1, depois de implementar, com o `behavior` do plano já escrito
- **Issue:** a primeira versão de `_resume_adoption` fazia `except ModelRegistryError: raise` para o erro que ela própria lançava e só convertia o resto. O resultado é que uma v1 com `metadata.json` inválido (caso (iii) do behavior) devolvia `metadata_invalid` em vez de `already_adopted` — um código que, pelo nome, levaria o utilizador a tentar corrigir um `metadata.json` que não tem nada de errado. O plano é explícito: "qualquer falha ... levanta already_adopted sem escrever nada".
- **Fix:** um único `except Exception` a converter tudo em `already_adopted`, com o código original na `__cause__` (fica no log, não na mensagem). Fail-closed e coerente com T-01-24.
- **Files modified:** `scripts/model_registry.py`
- **Verification:** `test_model_registry.py` exit 0 (o caso `retoma (iii): metadata.json inválido -> already_adopted` falhava antes da correcção e passa depois); `run_all_tests.py` 36/36
- **Committed in:** `5a861e8`

**2. [Rule 3 — Bloqueio] `$ML_MODEL_DIR` na mensagem de commit foi interpolado pelo PowerShell**
- **Found during:** Task 2, ao rever `git log` depois do commit
- **Issue:** a mensagem foi passada com `-m` numa string do PowerShell, onde `$ML_MODEL_DIR` expandiu para vazio e deixou um `\` isolado no texto ("a resolver para \ ou scripts/models").
- **Fix:** `git commit --amend -F <ficheiro>` com a mensagem escrita num ficheiro, que o shell não toca. O commit da Task 1 foi revisto e está limpo.
- **Files modified:** nenhum (só a mensagem de commit)
- **Verification:** `git log -1 --format=%B` mostra a frase correcta
- **Committed in:** `f6ea5c7` (era `3f8017a`)

---

**Total deviations:** 2 auto-fixed (1 correcção, 1 bloqueio)
**Impact on plan:** a primeira foi necessária para que a retoma obedecesse ao behavior especificado; a segunda só afectou a mensagem de commit. Zero scope creep — nada foi criado fora do `files_modified`, nenhuma capacidade foi acrescentada, nenhum ficheiro novo apareceu.

## Issues Encountered

- **A referência de `node:vm` e o caso `symlink`/`junction` da Task anterior limitaram o que este plano podia exercitar.** Nada a resolver, mas é o que justifica o `human_judgment: true` do D9: este plano só pode provar o CLI e as rotas, não o browser.
- **O bloqueio de `os.replace` nos testes é global ao processo**, porque `model_registry.os` é o próprio módulo `os`. É inofensivo aqui (é restaurado num `finally` e nada no caminho exercitado usa `os.replace`), mas é a razão de o helper se instalar e restaurar sempre em bloco, e não só à volta da chamada que se quer fazer falhar.

## Commands Run (resultados reais)

| Comando | Resultado |
|---|---|
| `cd scripts && .venv/Scripts/python test_model_registry.py` | **exit 0** — **267** checks `[OK]`, zero `[FALHOU]` (128 antes do plano) |
| `cd scripts && .venv/Scripts/python test_ml_models_api.py` | **exit 0** — **142** checks `[OK]`, zero `[FALHOU]` (110 antes do plano) |
| `cd scripts && .venv/Scripts/python model_registry.py --help` | **exit 0** — mostra o subcomando `adopt` |
| `cd scripts && .venv/Scripts/python run_all_tests.py` | **exit 0** — `36/36 ficheiros passaram` |
| AST: `model_registry.py` não importa `joblib`/`ml_anomalies`/`fastapi` | **exit 0**; imports reais = `['argparse', 'datetime', 'hashlib', 'hmac', 'json', 'os', 'pathlib', 're', 'shutil', 'sys', 'tempfile', 'typing']` |
| `def adopt` / `def _resume_adoption` / `def _materialize_version` / `def _write_active_atomic` em `model_registry.py` | `1` / `1` / `1` / `1` |
| `shutil.copy2` em `model_registry.py` | `2` (≥ 1 exigido) |
| `add_subparsers` / `MESSAGES_PT` em `model_registry.py` | `1` / `2` (≥ 2 exigido) |
| `node --check ml_models.js` | **exit 0** (Node v24.14.1; o ficheiro não foi tocado neste plano) |
| `ls scripts/models/` antes e depois da execução | `isolation_forest.pkl` (539 673 B) e `scaler.pkl` (767 B), mtime 14/09/2026 16:40:15 — **sem `v1/`, sem `ACTIVE`, sem temporários** |
| `git log --format=%B 8e27f21..HEAD \| Select-String "co-authored-by\|generated with"` | **vazio** |

Baseline antes de qualquer alteração: `run_all_tests.py` **36/36** (o mesmo depois).

## User Setup Required

None — no external service configuration required. Nenhum serviço novo, nenhuma variável de ambiente nova, nenhum pacote instalado.

Uma nota **operacional** para quem for adoptar o modelo real: depois do `adopt` é preciso **reiniciar o backend** (ou chamar `ml_anomalies.reset_cache()`), porque a cache do modelo é por processo — é o que o campo `loaded` torna visível no dashboard e o que a última linha do CLI lembra. E o `models/ACTIVE` escreve-se em UTF-8: um `echo v1 > models\ACTIVE` no PowerShell 5.1 grava UTF-16 e o registo recusa-o (`invalid_version_id`) de propósito — para activar à mão, use o `adopt` ou um editor que grave UTF-8.

## Next Phase Readiness

- **Fase 2 (`evaluate vN --events <ficheiro>`)** acopla-se ao parser que já existe: `subcomandos.add_parser("evaluate", ...)` e `set_defaults(func=...)`, sem tocar no `adopt`. `MESSAGES_PT` já tem mensagem para os nove códigos, incluindo `metadata_missing`/`metadata_invalid`, que são os que uma avaliação sobre uma versão mal registada vai encontrar.
- **Fase 3 (treino a criar vN)** pode chamar `_materialize_version(root, "vN", sources, meta)` com os `parameters`, `dataset` e `library_versions` preenchidos e o `origin: "trained"`, e `_write_active_atomic(root, "vN")` para activar. Os dois helpers já estão escritos para esse uso e nenhum deles toca nos `.pkl` de origem.
- **`adopt` convive com uma v2 treinada:** se a Fase 3 criar a `v2` e o `ACTIVE` apontar para ela, um `adopt` posterior cria a `v1` e avisa (D-01) — comportamento testado.
- **Dívida de segurança mantida e honesta** (D-04, T-01-21): o SHA-256 que o `adopt` grava detecta corrupção e troca acidental, **não autentica** — quem escreve em `models/` reescreve também o `metadata.json`. O `_resume_adoption` fecha a janela mais óbvia (uma v1 alheia com metadados coerentes), mas não muda o limite. Nenhum texto deste plano — código, mensagem ou teste — afirma o contrário.
- **Um ponto em que o `SKELETON.md` continua atrás da implementação** (já registado pelo 01-02 e pelo 01-03, e aqui confirmado): a lista de `status` de uma entrada **versionada** (linha 85) não inclui `no_metadata`, que é o `status` da entrada **legacy** (linha 86). Não foi corrigido porque o `SKELETON.md` é contrato e não está no `files_modified` deste plano — fica para DOC-01 (Fase 3), juntamente com `README.md`, `CLAUDE.md` e `docs/ROADMAP_STATUS.md`, que têm de descrever o comando `adopt` e a dívida do SHA-256.
- **Sem dívida técnica deixada por este plano.**

---
*Phase: 01-registo-de-modelos-ponta-a-ponta*
*Completed: 2026-10-10*