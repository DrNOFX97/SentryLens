---
phase: 14-aba-vaccines-testes-e-documenta-o
plan: 04
subsystem: docs
tags: [vaccines, documentation, data-model, roadmap-status, readme, claude-md, test-suite]

requires:
  - phase: 14-aba-vaccines-testes-e-documenta-o
    provides: "14-01 a 14-03: aba Vaccines (vaccines.js) e test_vaccines_frontend.py"
  - phase: 13-store-e-api-de-leitura
    provides: "GET /api/vaccines[/{id}], vaccine_store.py, vaccine_ingest.py e o bloco generator"
provides:
  - "docs/DATA_MODEL.md: secção Vaccine (R11) verificada por script contra os conjuntos de chaves do código (53 chaves)"
  - "docs/API.md: secção Vaccines (R11) e duas linhas na Tabela de endpoints"
  - "docs/ROADMAP_STATUS.md: R11 com estado concluído, dívida do R11, flake da suite como dívida aberta, secção R11 verificado por máquina / por verificar em humano"
  - "README.md e CLAUDE.md a descrever motor, store, loop, rotas e aba, com as contagens reais (45 testes, 26 abas)"
affects: [R12 Vaccine Lab, fecho da fase 14]

status: complete
plan_head_before: c103638141791d7b8917d5214c9df03337241c34
plan_head_after: 6f2671eee883590c36a2a5a617c4a2c8277a6ed6

actuals:
  tokens: 5500
  tasks: 2
  commits: 2

tech-stack:
  added: []
  patterns:
    - "Documentação de entidade verificada por script: o verify importa os módulos e falha com a lista das chaves que não aparecem entre crases"
    - "Edições pontuais por script Python em ficheiros CRLF, com uma asserção de ocorrência única por substituição"

key-files:
  created: []
  modified:
    - docs/DATA_MODEL.md
    - docs/API.md
    - docs/ROADMAP_STATUS.md
    - README.md
    - CLAUDE.md

key-decisions:
  - "Contagens medidas no momento: N = 45 (git ls-files 'scripts/test_*.py'), T = 26 (data-tab= no index.html commitado); nada copiado do plano"
  - "A linha R10 do ROADMAP_STATUS fica por tocar (follow-up); as referências históricas '38' na linha R9 e na secção R9 também (são o estado do R9 na altura)"
  - "A evidência N/N da suite foi obtida num venv novo fora do repositório (ver desvio 1), porque o scripts/.venv estava corrompido"

requirements-completed: [VAC-08]

coverage:
  - id: D1
    description: "DATA_MODEL.md define a entidade Vaccine com todas as chaves dos conjuntos fechados do motor, do store e do gerador"
    requirement: VAC-08
    verification:
      - kind: command
        ref: "verify automatizado da Task 1 (importa vaccine_engine/vaccine_ingest/vaccine_store): OK 53 chaves documentadas"
        status: pass
    human_judgment: false
  - id: D2
    description: "API.md documenta as duas rotas e a Tabela de endpoints inclui-as"
    requirement: VAC-08
    verification:
      - kind: command
        ref: "verify automatizado da Task 1: OK API.md"
        status: pass
    human_judgment: false
  - id: D3
    description: "Suite completa run_all_tests.py verde sem o Wazuh (45/45, uma única execução completa com código 0), com as garantias negativas presentes"
    requirement: VAC-08
    verification:
      - kind: command
        ref: "cd scripts && python run_all_tests.py -> 45/45 ficheiros passaram, exit 0 (venv novo, ver desvio 1)"
        status: pass
    human_judgment: false
  - id: D4
    description: "ROADMAP_STATUS, README e CLAUDE.md refletem o R11 com contagens reais, sem prometer mais do que o código garante"
    requirement: VAC-08
    verification:
      - kind: command
        ref: "verify automatizado da Task 2: OK docs N=45 e OK divida e evidencia N=45"
        status: pass
      - kind: manual
        ref: "verificação humana da aba (14-02 e 14-03) listada em ROADMAP_STATUS 'R11 — por verificar em humano'"
        status: pending
    human_judgment: true
---

# Phase 14 Plan 04: Documentação do R11 e fecho da suite Summary

**A entidade Vaccine e as duas rotas ficam documentadas contra o código (53 chaves verificadas por script), o R11 passa a concluído no Roadmap v2 com a dívida e o flake da suite registados, README e CLAUDE.md descrevem motor, store, loop, rotas e aba com as contagens reais, e `run_all_tests.py` termina 45/45 com código 0 numa única execução completa.**

## Performance

- **Duration:** ~25 min (inclui a reconstrução do ambiente de testes, desvio 1)
- **Tasks:** 2 (1 tracer + 1 auto)
- **Files modified:** 5 (nenhum criado; nenhum código alterado)
- **Commits:** 2 de tarefa (medidos pelo ledger) + este SUMMARY

## Accomplishments

- **Task 1 (tracer, `047086d`):** `docs/DATA_MODEL.md` ganhou a secção `## Vaccine (R11)` (exemplo de `GET /api/vaccines/{id}` gerado pelo próprio motor e validado por `validate_vaccine`, campos por grupo, regras do id/`superseded_by`/store, `ON CONFLICT(id) DO NOTHING` e o porquê, gerador com as 4 variáveis de ambiente, contagens, estados e tabela dos 8 códigos de erro, envelope, limites A7/A8/A3/A5 e o id que não autentica). `docs/API.md` ganhou a secção `## 💉 Vaccines (R11)` e as duas linhas da tabela. Os dois verifies passam: `OK 53 chaves documentadas` e `OK API.md`.
- **Task 2 (`6f2671e`):** `ROADMAP_STATUS.md` com R11 concluído e notas, R24 com 45, bullets "Vaccine Engine (R11)" e "Flake de `run_all_tests.py`" em "Dívida conhecida", e a secção `R11 — verificado por máquina / por verificar em humano`. `README.md` com 26 abas, linha Vaccines, bullet em "Também inclui", secção `## Vaccines`, 45 testes, exemplo `test_vaccines_api.py`, duas rotas na tabela da API e a linha dos módulos. `CLAUDE.md` com 45 ficheiros, três bullets (`vaccine_engine.py`, `vaccine_store.py`, `vaccine_ingest.py` com rotas e `vaccines.js`), um bullet nas coisas não óbvias e o primeiro bullet da secção GSD atualizado (editado, nunca regenerado: +7 −2 linhas).

## Evidência da suite (VAC-08, critério 3 do ROADMAP)

- Uma única execução completa de `run_all_tests.py` (a partir de `scripts/`): **45/45 ficheiros passaram, código de saída 0**. Precisou de **1** execução completa; nenhum ficheiro falhou, incluindo `test_attack_log_ids.py`, `test_attack_targets.py` e `test_ml_training.py` (os flakes conhecidos não reproduziram nesta corrida). N = `git ls-files 'scripts/test_*.py'` = 45.
- Corrida com um venv novo criado fora do repositório a partir de `scripts/requirements.txt` (mesmas versões que o `.venv` tinha), ver desvio 1.
- Garantias negativas presentes na suite (greps do critério de aceitação): `com chave -> 405` (1), `DENY_RE` (9), `sem texto de exceção` (2), `2.º ciclo` (2), `reinício` (2).
- `git diff --quiet 878d8e5 HEAD -- app.js` sai 0 (app.js por editar em toda a fase).

## Task Commits

1. **Task 1: Entidade Vaccine e rotas (DATA_MODEL, API)** — `047086d` (docs(14-04))
2. **Task 2: R11 no Roadmap v2, README e CLAUDE.md** — `6f2671e` (docs(14-04))

## Deviations from Plan

**1. [Rule 3 - Blocking] `scripts/.venv` corrompido: suite corrida num venv novo fora do repositório**
- **Found during:** precondition da Task 1 (`test_vaccines_frontend.py` saiu 1 com `ModuleNotFoundError: No module named 'anyio._lazyimport'`).
- **Issue:** o `scripts/.venv` ficou com instalações parciais e misturadas: 46 dist-info com ficheiros em falta (por exemplo `anyio/_core/*`, `fastapi/cli.py`, `sklearn/utils/tests/*`), dist-info de versões antigas sem `RECORD` (fastapi 0.109.2, starlette 0.36.3, uvicorn 0.27.1, scikit-learn 1.3.2), um `.whl` de 0 bytes dentro de `site-packages` e o próprio `pip` sem `__main__.py`. Os ficheiros foram alterados entre as 10:10 e as 11:03 de 2026-10-12, por outra atividade (não por este plano). Causa provável (não confirmada): `uv pip install` com hardlinks do cache do `uv`; ao criar um venv novo com o modo por omissão o `uv` falhou com o erro do Windows `os error 396` ("não é possível executar a operação na cloud num ficheiro com ligações fixas incompatíveis"), e com `--link-mode=copy` instalou sem problemas.
- **Fix:** não toquei no `scripts/.venv` nem no `scripts/.venv2`. Criei um venv novo em `%TEMP%` (scratchpad da sessão) com `uv venv` (CPython 3.12.14) e `uv pip install --link-mode=copy -r scripts/requirements.txt` (32 pacotes, todos os pinados do `requirements.txt` do projeto; sem nomes novos). Todos os testes e verifies Python deste plano correram com esse interpretador.
- **Files modified:** nenhum no repositório.
- **Verification:** `run_all_tests.py` 45/45, código 0 (acima). A primeira execução da suite falhou antes do venv novo só por o ambiente estar partido, e não conta como falha de teste nem como execução completa.
- **Para o utilizador:** `scripts/.venv` precisa de ser recriado (por exemplo `uv venv --clear` + `uv pip install --link-mode=copy -r requirements.txt`, ou `python -m venv`); sem isto `.\scripts\start-backend.ps1` e os testes com o `.venv` não arrancam. Usar `--link-mode=copy` no `uv pip install` evita o erro de hardlinks.

**2. [Critério desatualizado] "Opção A: Usar VMs Pré-configuradas" já está no HEAD**
- **Found during:** Task 2 (Procedimento C).
- **Issue:** o plano previa trabalho alheio por commitar no `README.md` e um critério `grep -c "Opção A: Usar VMs Pré-configuradas"` = 0 no HEAD. `git diff --quiet -- README.md` já saía 0 antes de qualquer edição e o HEAD anterior ao plano já tinha essa secção (contagem 1 em `c103638`). O critério daria 1 por trabalho de outra frente, não por este plano.
- **Fix:** o Procedimento C (patch seletivo) não foi necessário; o `README.md` foi editado diretamente e adicionado normalmente. O diff do commit só tem as 22 linhas novas e as 3 contagens trocadas. Mesma situação do `index.html` no 14-01.

**3. [Prefixo dos commits] `docs(14-04)` em vez de `docs(vaccines)`**
- Por instrução do orquestrador (`type(14-04): ...`); o plano sugeria `docs(vaccines): ...`.

**Total deviations:** 3 (1 bloqueio de ambiente contornado sem tocar no repositório, 1 critério desatualizado, 1 instrução de prefixo). **Impact:** nenhum no conteúdo entregue.

## Procedimento C aplicado ao README

Não foi necessário (ver desvio 2). Nada de `git stash`, `checkout --`, `add -A` nem `commit -a`. O `README.md` tem fins de linha mistos (CRLF e LF); as edições foram substituições exatas por script com fim de linha CRLF nas linhas vizinhas, e `git diff --stat` mostra 25 linhas (+22 −3). `.planning/config.json`, `.github/`, `packer/`, `scripts/.venv2/`, `.planning/state.json`, `.planning/milestone.lock` e `scripts/setup-boot-lab-entry.ps1` ficaram intocados.

## Contagens medidas

- **N = 45** ficheiros de teste (`git ls-files 'scripts/test_*.py'`); o plano e o CLAUDE.md diziam 38.
- **T = 26** abas (`grep -c 'data-tab="'` no `index.html` commitado); o README dizia 24. Nota: a tabela de Funcionalidades agrupa abas na mesma linha (por exemplo Attack Registry / Attack Timeline), por isso o número de linhas da tabela não é T.

## Known Follow-ups (fora do âmbito)

- A linha R10 de `docs/ROADMAP_STATUS.md` continua ⬜ apesar de o v1.0 ter entregue o R10.
- `scripts/.env.example` não lista as variáveis `SENTRYLENS_VACCINE*` (ficam no README e no DATA_MODEL).
- Verificação humana da aba (14-02/14-03) por fazer; está em `ROADMAP_STATUS.md`, secção "R11 — por verificar em humano".
- O flake de `test_attack_log_ids.py`/`test_attack_targets.py`/`test_ml_training.py` em execução paralela continua por investigar (dívida aberta em `ROADMAP_STATUS.md`); não reproduziu nesta fase na corrida citada.
- Recriar `scripts/.venv` (desvio 1).

## Known Stubs

Nenhum (só documentação).

## Threat Flags

Nenhum: sem superfície nova. T-14-14 (sem IPs, chaves nem alvos nos exemplos; o exemplo vem do motor e só tem referências), T-14-15 (CLAUDE.md editado pontualmente: +7 −2 linhas, secções-chave e aviso `generate-claude-md` presentes) e T-14-16 (documentação diz que é só proposta, que o id não autentica e lista A3/A5/A7/A8; o flake fica como dívida aberta) mitigados e verificados.

## Self-Check: PASSED

- `docs/DATA_MODEL.md`, `docs/API.md`, `docs/ROADMAP_STATUS.md`, `README.md`, `CLAUDE.md` existem e têm o conteúdo esperado; commits `047086d` e `6f2671e` existem; `git log` sem `Co-Authored-By` nos dois.
- Todos os critérios de aceitação das Tasks 1 e 2 correram e passam, exceto o do desvio 2 (desatualizado, ver acima).
