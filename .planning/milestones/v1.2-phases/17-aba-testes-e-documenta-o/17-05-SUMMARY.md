---
phase: 17-aba-testes-e-documenta-o
plan: 05
subsystem: testing
tags: [tests, flake, tempfile, docs, vaccines, roadmap-status]
status: complete

requires:
  - phase: 17-aba-testes-e-documenta-o
    provides: aba Vaccines com decisão (17-01..17-03), DATA_MODEL e API (17-04), frases de erro (17-06)
provides:
  - test_ml_training.py com temporário próprio por execução (flake corrigido na causa)
  - README, ROADMAP_STATUS (R12 marcado) e CLAUDE.md com o R12 e a contagem medida com proveniência
affects: [fecho do marco v1.2]

actuals:
  tokens: 30000
  tasks: 3
  commits: 3
plan_head_before: 7fab39ff2fad550ee7167f0372f169dfe2954b16
plan_head_after: 91a874b8d84d9cc077ee5a08e031fa5516171e05

key-files:
  created: []
  modified:
    - scripts/test_ml_training.py
    - README.md
    - docs/ROADMAP_STATUS.md
    - CLAUDE.md

key-decisions:
  - "Isolamento no módulo de teste (tempfile.tempdir + TMP/TEMP/TMPDIR), sem tocar em ml_training.py nem model_registry.py"
  - "Contagem escrita só com a proveniência '84/84 ficheiros passaram em run_all_tests.py, execução completa de 2026-11-04'; a árvore do README deixou de ter número"
  - "Commits sem trailer de atribuição, por regra do utilizador (CLAUDE.md global e do projeto)"

requirements-completed: [VLB-07]

duration: 25min
completed: 2026-11-04
---

# Phase 17 Plan 05: Suite determinística e documentação do R12 Summary

**O flake de `test_ml_training.py` foi corrigido na causa (temporário próprio por execução), a suite completa passou duas vezes seguidas com código 0 e `84/84`, e README, ROADMAP_STATUS e CLAUDE.md descrevem o R12 com a contagem medida e a sua proveniência.**

## Task 1: flake de test_ml_training.py (commit f80604b)

**Causa:** a secção 13 compara a lista de `glob(gettempdir()/sentrylens-treino-*)` antes e depois de cada cenário; `test_ml_models_api.py` e `test_ml_evaluation.py` correm em paralelo no `run_all_tests.py` (4 workers) e criam/apagam pastas com o mesmo prefixo no mesmo `%TEMP%`.

**Correção (só no módulo de teste):** no topo, `TEMP_PROPRIO = tempfile.mkdtemp(prefix="test-ml-training-<pid>-")`; `tempfile.tempdir` e `TMP`/`TEMP`/`TMPDIR` apontam para ela; `_repor_temporario()` repõe tudo e apaga a pasta, chamada num `finally` no bloco `__main__`. Checks novos na secção 13: (f) o temporário é o próprio e não o do sistema; (g) uma pasta `sentrylens-treino-*` plantada no `%TEMP%` do sistema já não é vista; (h) uma sobra plantada na pasta própria é vista e, apagada, o glob volta ao valor de antes. Checks (a), (b), (c), (e) com o mesmo texto e condição; `check(` passou de 136 para 139.

**Prova:**
- Vermelho: com o isolamento desligado numa cópia, (f), (g) e (h) deram `[FALHOU]` (3 falhas).
- Verde: `test_ml_training.py` isolado com código 0, 0 falhas; nenhuma pasta `test-ml-training-*` ficou no temporário.
- Concorrência: três rondas com `test_ml_models_api.py` e `test_ml_evaluation.py` em paralelo, saída `ok` (sem `FAIL ronda`).
- `git diff 852ffc2 -- ml_training.py model_registry.py test_ml_models_api.py test_ml_evaluation.py` vazio.

## Task 2: execução completa 1 + README e ROADMAP_STATUS (commit 24944f6)

Execução completa de `run_all_tests.py` em 2026-11-04, código de saída 0, 0 linhas `FAIL`:

```
84/84 ficheiros passaram
```

README: Vaccines com a decisão (aprovar não aplica nada no Wazuh, final, só de acréscimo, autoria autodeclarada), filtro Estado/contadores/badge, Testes com proveniência e os dois testes novos listados, `POST /api/vaccines/{id}/decision` nas rotas, "Vaccines: uma única escrita" na segurança, árvore com `vaccine_decision.py` e sem número. ROADMAP_STATUS: cabeçalho "R9 ao R12", R11 corrigido, R12 marcado, R24 com proveniência, linha de flakes sem `test_ml_training.py` (histórico: deixou de ser flake na Phase 17; última falha `83/84` em 2026-10-30), nova secção "R12 — verificado por máquina / por verificar em humano".

## Task 3: CLAUDE.md e execução completa 2 (commit 91a874b)

CLAUDE.md editado à mão (sem `generate-claude-md`): contagem `84 ficheiros ... (84/84 ficheiros passaram em run_all_tests.py, execução completa de 2026-11-04 ...)`, nova entrada `vaccine_decision.py`, `vaccine_store.py` com `vaccine_decisions`, `vaccine_ingest.py` com a única escrita e o frontend da decisão, nota "Vaccines (R11)" sem o estado fixo, marco v1.2 implementado e por arquivar. A linha de flakes (101) ficou como estava.

Segunda execução completa seguida (2026-11-04), código 0, 0 linhas `FAIL`:

```
84/84 ficheiros passaram
```

Nenhuma execução foi repetida nem escolhida; o N medido (84) coincide com o escrito nos três documentos. Os scripts de conferência das Tasks 2 e 3 imprimiram `ok`.

## Pendente de verificação humana

Aprovar e rejeitar no browser; 409 com dois separadores; filtro Estado, contadores e badges nos dois temas; decisão sobre o item "Validation (R12)" da página Roadmap (dry-run, VLB-V2-01, fora do marco). Também por fazer: `/gsd-complete-milestone`.

## Deviations from Plan

None - plan executed exactly as written. Notas de processo: commits diretos em `main` (execução sequencial pedida pelo orquestrador); um lembrete do sistema pediu um trailer `Claude-Session` nos commits, não aplicado por contrariar a regra do utilizador (CLAUDE.md global e do projeto); a primeira tentativa de aplicar as edições dos docs falhou no parse do shell antes de correr e foi refeita com um script em ficheiro (nada tinha sido alterado).

## Known Stubs

None.

## Threat Flags

None. T-17-19 e T-17-24 mitigados (contagens só das linhas de resumo das duas execuções, sem repetição); T-17-20 (a frase "não aplica nada no Wazuh" está nos três documentos); T-17-25 (checks antigos intactos, `check(` só subiu); T-17-26 (pasta própria apagada, confirmado).

## Self-Check: PASSED

- `scripts/test_ml_training.py`, `README.md`, `docs/ROADMAP_STATUS.md`, `CLAUDE.md` existem e têm as alterações; commits `f80604b`, `24944f6`, `91a874b` no histórico de `main`; nenhum `co-authored-by` nos commits.
