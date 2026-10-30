---
phase: 16-api-de-decisao
plan: 03
subsystem: testing
tags: [ast, security, cors, vaccines, no-apply, read-only-guarantee]

requires:
  - phase: 16-api-de-decisao
    provides: POST /api/vaccines/{id}/decision (16-01), state e state_counts em GET /api/vaccines (16-02)
provides:
  - "run_no_apply(): varrimento AST de scripts/vaccine_*.py e das funções de vaccines de main.py (com fecho de funções locais), provado contra violações plantadas"
  - "Prova automática de que o handler de decisão só usa vaccine_store.decide_vaccine, vaccine_store.get_vaccine e incident_store.get_analyst, por esta ordem, sem WebSocket nem histórico JSONL"
  - "Pin das três rotas de vaccines (sem apply/deploy/activate/execute/enable, só a de decisão aceita POST, API key em cada uma) e do texto aprovada != aplicada"
  - "test_cors.py: preflight POST da rota de decisão, PUT/DELETE recusados, origens externas sem ACAO e allow_methods fixado em ['GET', 'POST', 'PATCH']"
affects: [17-frontend-de-decisao]

plan_head_before: b33a73f16570a1b93f70e11de46d955f7dc7f95a
plan_head_after: 6561b323d9275a5a32dc7ff45ed60ac1feacf0b7
commits: 2
status: complete

actuals:
  tokens: 3500
  tasks: 2
  commits: 2

tech-stack:
  added: []
  patterns:
    - "Garantia de segurança como teste de AST sobre o código real, ela própria testada com fontes sintéticas plantadas (um varrimento que nunca falhou não prova nada)"
    - "Varrimento por função em main.py (não do ficheiro): regras completas nas funções de vaccines, regras de fecho (sem manager_client/vm_ssh_client/subprocess) nas funções locais que elas alcançam por referência a um nome"

key-files:
  created: []
  modified:
    - scripts/test_vaccine_decision_api.py
    - scripts/test_cors.py

key-decisions:
  - "O fecho de funções locais segue referências a nomes (chamadas e funções passadas como argumento, ex. run_in_threadpool(helper)), não só ast.Call, e proíbe qualquer acesso por atributo a manager_client/vm_ssh_client/VMSSHClient/subprocess; uma comparação `vm_ssh_client is not None` continua a passar"
  - "Nenhum código de produção mudou: o allow_methods já tinha POST (D-16), o critério 4 cumpre-se fixando-o por teste"

patterns-established:
  - "Rotas protegidas contra regressão por pin de caminhos e métodos sobre main.app.routes"

requirements-completed: [VLB-04, VLB-01]

coverage:
  - id: D1
    description: "Nenhum módulo vaccine_*.py nem função de vaccines de main.py (nem as funções locais que alcançam) importa, referencia ou chama subprocess, SSH, wazuh_client, manager_client, rede ou os.system/os.popen/os.spawn*/os.exec*"
    requirement: "VLB-04"
    verification:
      - kind: unit
        ref: "scripts/test_vaccine_decision_api.py#run_no_apply"
        status: pass
    human_judgment: false
  - id: D2
    description: "O varrimento é provado contra violações plantadas (subprocess, manager_client, os.system em auxiliar, import subprocess) e deixa passar código limpo"
    requirement: "VLB-04"
    verification:
      - kind: unit
        ref: "scripts/test_vaccine_decision_api.py#run_no_apply"
        status: pass
    human_judgment: false
  - id: D3
    description: "Handler de decisão só usa decide_vaccine, get_vaccine e get_analyst, decide antes de reler, sem WebSocket nem append_*; só as três rotas permitidas existem; aviso e docstring dizem que aprovada não é aplicada"
    requirement: "VLB-04"
    verification:
      - kind: unit
        ref: "scripts/test_vaccine_decision_api.py#run_no_apply"
        status: pass
    human_judgment: false
  - id: D4
    description: "CORS cobre o POST da rota de decisão a partir do dashboard local sem abrir PUT/DELETE, e allow_methods está fixado"
    requirement: "VLB-01"
    verification:
      - kind: unit
        ref: "scripts/test_cors.py"
        status: pass
    human_judgment: false
---

# Phase 16 Plan 03: Garantias "nada aplica nem executa" e CORS Summary

**Varrimento AST de `vaccine_*.py` e das funções de vaccines de `main.py` (com fecho de funções locais), provado contra violações plantadas, mais o CORS do POST de decisão fixado por teste; a suite chega a 84/84 sem mudar código de produção.**

## Performance

- **Duration:** ~8 min
- **Tasks:** 2 (1 tracer, 1 auto)
- **Files modified:** 2 (ambos de teste)

## Accomplishments

- `run_no_apply()` em `scripts/test_vaccine_decision_api.py` (27 checks `varrimento:`):
  - **Regras:** `FORBIDDEN_IMPORT_ROOTS` (subprocess, ssh_client, paramiko, asyncssh, wazuh_client, httpx, requests, socket, urllib, http, pty, shlex, multiprocessing, ctypes) e `FORBIDDEN_NAMES` (subprocess, ssh_client, VMSSHClient, vm_ssh_client, manager_client, WazuhManagerClient, paramiko), mais chamadas `os.system/popen/spawn*/exec*`, `asyncio.create_subprocess_*` e `__import__/eval/exec/import_module`.
  - **Módulos varridos:** `vaccine_decision`, `vaccine_engine`, `vaccine_ingest`, `vaccine_store` (glob `vaccine_*.py`, apanha módulos futuros), todos sem violações.
  - **Funções de `main.py`:** as onze esperadas (`_run_vaccine_cycle`, `_vaccine_cycle_body`, `_vaccine_loop`, `_start_vaccine_loop`, `list_vaccines`, `get_vaccine`, `decide_vaccine_route`, `_parse_vaccine_decision_body`, `_read_vaccine_decision_body`, `_vaccine_decision_refusal`, `_vaccine_decision_validation_error`) encontradas por nome ou por decorador `/api/vaccines*`, sem violações; o fecho local (ex. `_build_attack_registry`) também limpo.
  - **Autoteste:** 12 checks com fontes sintéticas (subprocess numa `_vaccine_*`, `manager_client` numa rota com nome neutro, `os.system` num auxiliar, `vm_ssh_client.run` passado como argumento, `import subprocess`/`from socket`, `os.execv`, handler com get antes de decide, store a mais, `ws_manager`, `append_*`), mais fonte limpa.
  - **Handler:** `vaccine_store` só `decide_vaccine` e `get_vaccine` (uma vez cada, decide primeiro), `incident_store` só `get_analyst`, sem `indexer_client`/`manager_client`/`vm_ssh_client`/`ws_manager`/`network_ws_manager`/`append_*` (D-08, D-14, D-15).
  - **Rotas:** exatamente `/api/vaccines`, `/api/vaccines/{vaccine_id}`, `/api/vaccines/{vaccine_id}/decision`; sem apply/deploy/activate/execute/enable; só a de decisão com POST; `require_api_key` em cada uma.
  - **Texto:** `VACCINE_DECISION_NOTICE` e docstring de `decide_vaccine_route` dizem "aceite pelo analista", "não aplicada/aplica nada no Wazuh" e "autodeclarada".
- `scripts/test_cors.py`: `preflight(..., url=URL)`, `VAC_URL`, preflight POST de `127.0.0.1:5500`, `localhost:5500` e `127.0.0.1:8080` (200, POST permitido, origem devolvida), PUT e DELETE a 400, três origens externas sem `Access-Control-Allow-Origin`, e `allow_methods` do único `CORSMiddleware` fixado em `['GET', 'POST', 'PATCH']`.
- Suite completa: `84/84 ficheiros passaram` na primeira execução (sem flake); `test_attack_log_ids.py` e `test_attack_targets.py` também passam isolados.

## Task Commits

1. **Task 1 (tracer): varrimento AST** - `20ab912` (test)
2. **Task 2: CORS da rota de decisão** - `6561b32` (test)

Base do plano: `refs/gsd/16-03-base` = `b33a73f16570a1b93f70e11de46d955f7dc7f95a`. `git diff --quiet refs/gsd/16-03-base -- scripts/main.py scripts/vaccine_*.py` sai 0.

## Files Created/Modified

- `scripts/test_vaccine_decision_api.py` - `run_no_apply`, `scan_module`, `scan_main`, `handler_problems`, `FORBIDDEN_IMPORT_ROOTS`, `FORBIDDEN_NAMES`
- `scripts/test_cors.py` - `VAC_URL`, `url` no `preflight`, checks da rota de decisão e de `allow_methods`

## Decisions Made

- O fecho de funções locais segue referências a nomes (não só chamadas) e proíbe qualquer acesso por atributo às raízes de Wazuh/SSH/subprocess: uma função passada como argumento a `run_in_threadpool` não escapa. Comparações como `vm_ssh_client is not None` (em `_build_attack_registry`) não contam.
- Nenhum código de produção mudou; o varrimento passou ao primeiro dia sobre o código real, por isso não houve violação a reportar.

## Deviations from Plan

None - plan executed exactly as written. Detalhe de implementação: a docstring do handler quebra linhas a meio de frases ("não aplica\n    nada no Wazuh"), por isso o check normaliza o espaço em branco antes de procurar as frases (erro do próprio teste, não de produção).

## Issues Encountered

None.

## Known Stubs

None.

## Threat Flags

None - só ficheiros de teste.

## User Setup Required

None.

## Next Phase Readiness

Phase 16 fica com os quatro critérios do ROADMAP provados na suite (`84/84`). A Phase 17 (frontend de decisão e documentação VLB-07: `DATA_MODEL.md`, `API.md`, `ROADMAP_STATUS.md`, `README.md`, `CLAUDE.md`, contagem 83 -> 84 ficheiros) pode arrancar; o risco T-16-13 (render de motivo e nome do analista) é dela, com `htmlT`/`escapeHtml`.

## Self-Check: PASSED

- `scripts/test_vaccine_decision_api.py` e `scripts/test_cors.py` existem; commits `20ab912` e `6561b32` são ancestrais de HEAD.
- `run_all_tests.py`: 84/84; ficheiros de flake conhecido passam isolados.
- Nenhum trailer de coautor nos commits da fase.
