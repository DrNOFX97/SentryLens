---
phase: 15-store-de-decis-es
verified: 2026-10-29T00:00:00Z
status: passed
score: 4/4 must-haves verified
behavior_unverified: 0
overrides_applied: 0
---

# Phase 15: Store de decisões - Relatório de verificação

**Objetivo:** O backend sabe registar uma decisão sobre uma vaccine num registo de auditoria só de acréscimo, e deriva o estado atual sem nunca alterar a vaccine.
**Estado:** passed
**Re-verificação:** Não (verificação inicial)

## Verdades observáveis (critérios de sucesso do ROADMAP)

| # | Verdade | Estado | Evidência |
|---|---------|--------|-----------|
| 1 | `vaccine_decisions` com triggers que recusam UPDATE/DELETE; `vaccines` mantém `CHECK (state='proposed')` e os triggers do R11 intactos (provado por teste) | VERIFICADO | `scripts/vaccine_store.py` `DECISIONS_SCHEMA` tem `vaccine_decisions_no_update`/`_no_delete` (`RAISE(ABORT)`). Verificação própria: UPDATE e DELETE em `vaccine_decisions` falham com "vaccine_decisions e append-only"; `UPDATE vaccines SET state='approved'` falha. `VACCINES_SCHEMA` é igual ao literal `SCHEMA` de `git show 7b7fd25:scripts/vaccine_store.py` (comparação feita por mim: True). `run_file_guarantees` compara `sqlite_master` das entradas de `vaccines` em 3 bases. |
| 2 | A decisão guarda vaccine, approved/rejected, autor, instante UTC, motivo e estado anterior; rejeitar sem motivo é recusado | VERIFICADO | Colunas `vaccine_id, decision, decided_by, decided_by_name, decided_at, reason, previous_state` com CHECKs (e `CHECK (decision <> 'rejected' OR reason IS NOT NULL)`). Execução própria: `decide_vaccine(rejected, reason=None)` -> `reason_required`, nada gravado; com motivo devolve o registo completo com `previous_state='proposed'`; `decided_at` exige ISO com offset 0 (`_is_utc_instant`). |
| 3 | Decidir duas vezes, vaccine substituída ou id inexistente falha com código estável distinto, sem gravar nada | VERIFICADO | Execução própria: segunda decisão -> `already_decided`; vaccine A (nunca decidida) substituída -> `vaccine_superseded`; id inexistente -> `entry_not_found`; ficheiro inexistente -> `entry_not_found` sem criar o ficheiro. Contagem de linhas em `vaccine_decisions` ficou em 1. `VaccineDecisionError` usa só códigos de `ERROR_CODES` (conjunto fechado, 9) e não deriva de ValueError. Verificação+INSERT na mesma `BEGIN IMMEDIATE` (`_tx_immediate`), provado nos testes por `set_trace_callback`, 8 threads e corrida com o gerador. |
| 4 | Estado derivado = última decisão, ou `proposed` sem nenhuma | VERIFICADO | `_to_vaccine` usa `derive_state(row["d_decision"])`; execução própria: rejeitada -> `state='rejected'` com bloco `decision`; sem decisão -> `proposed`; `decision` None. Aprovada/decidida e depois substituída mantém o estado (`already_decided` ao tentar de novo). Ficheiro antigo sem a tabela lê-se como `proposed` sem criar a tabela (`_has_decisions_table` em `sqlite_master`). Filtro por `state` via `COALESCE(d.decision,'proposed') = ?` com parâmetros por `?`. |

**Pontuação:** 4/4 verdades verificadas (0 presentes mas sem verificação comportamental).

## Artefactos obrigatórios

| Artefacto | Esperado | Estado | Detalhes |
|-----------|----------|--------|----------|
| `scripts/vaccine_decision.py` | Regra pura, códigos estáveis, `validate_request` | VERIFICADO | 137 linhas, só `re`/`unicodedata`/`datetime`; sem I/O; ordem de validação fixa; sem qualquer função que aplique algo no Wazuh. |
| `scripts/vaccine_store.py` | `DECISIONS_SCHEMA`, `decide_vaccine`, leitura derivada, filtro `state` | VERIFICADO | Existe, substantivo, ligado (`validate_request`, `check_transition`, `derive_state` usados em `decide_vaccine`/`_to_vaccine`). |
| `scripts/test_vaccine_decision.py` | Testes da regra pura | VERIFICADO | PASS. |
| `scripts/test_vaccine_decision_store.py` | Testes do store/ficheiro/corrida | VERIFICADO | PASS; 181 linhas de OK, 0 falhas (corrida própria). |

## Verificação de ligações

| De | Para | Via | Estado |
|----|------|-----|--------|
| `vaccine_store.decide_vaccine` | `vaccine_decision.validate_request/check_transition` | import e chamada | LIGADO |
| `_to_vaccine` | `derive_state` / `DECISION_FIELDS` | import e uso | LIGADO |
| `SCHEMA` | `executescript` em `_connect` | cria a tabela na primeira escrita, em ficheiros novos e antigos | LIGADO |

Nota: não há rota HTTP nesta fase por desenho (Phase 16); `main.py` e `test_vaccine_store.py` não foram alterados desde `7b7fd25` (`git diff --stat` vazio).

## Trace de dados (Nível 4)

Tabela `vaccine_decisions` -> LEFT JOIN em `list_vaccines`/`get_vaccine` -> `state` e `decision` devolvidos. Fluxo real confirmado por execução própria (decisão gravada, lida de volta com autor, data e motivo). ESTADO: FLOWING.

## Verificações comportamentais

| Comportamento | Comando | Resultado | Estado |
|---------------|---------|-----------|--------|
| Suite das vaccines | `python run_all_tests.py vaccine` (venv, a partir de `scripts/`) | 8/8 ficheiros passaram | PASS |
| Cenário próprio (recusas, estado derivado, triggers) | script no scratchpad contra um `.sqlite3` temporário | todos os códigos e bloqueios conforme esperado | PASS |
| `vaccines` do R11 intacta | comparação de `VACCINES_SCHEMA` com o literal de `7b7fd25` | True | PASS |

## Cobertura de requisitos

| Requisito | Descrição | Estado | Evidência |
|-----------|-----------|--------|-----------|
| VLB-02 | Estado `proposed -> approved|rejected` final; segunda decisão e vaccine substituída recusadas com código estável | SATISFEITO ao nível do store (Phase 15) | `already_decided`/`vaccine_superseded` + `UNIQUE(vaccine_id)`. O mapeamento para 409 por HTTP é da Phase 16 (o requisito também está atribuído à 16; ver abaixo). |
| VLB-03 | Registo só de acréscimo com autor, quando, motivo e estado anterior; `vaccines` imutável | SATISFEITO | Tabela, triggers, CHECKs e testes ao nível do ficheiro. |

Sem requisitos órfãos para a fase 15 (REQUIREMENTS.md mapeia VLB-02 às fases 15 e 16, VLB-03 à 15).

## Anti-padrões

Nenhum marcador TBD/FIXME/XXX/TODO em `vaccine_decision.py` e `vaccine_store.py`. Nenhum caminho de UPDATE/DELETE sobre decisões no código do store (verificado também pelo teste do traço). Sem stubs. Nenhum commit da fase contém `Co-Authored-By` (verificado em `6b8a1ef..HEAD`).

## Itens para verificação humana

Nenhum.

## Observações (não bloqueantes)

- REQUIREMENTS.md já marca VLB-02 como `[x]` / "Complete", mas a metade HTTP (409 por rota) só existe na Phase 16, onde o requisito também está listado. A marca refere-se à regra e ao store; vale a pena garantir que a Phase 16 a revalida por rota.
- ROADMAP.md ainda mostra `[ ] Phase 15` na lista de fases (as caixas dos 3 planos estão `[x]`); é só atualização de estado a fazer pelo orquestrador.
- Itens adiados e conhecidos (da Phase 16/17): validação do analista na rota, mapeamento HTTP, `state` na rota GET, documentação.

## Resumo de lacunas

Sem lacunas. O objetivo da fase foi atingido no código: a decisão é gravada num registo só de acréscimo imposto pelo próprio SQLite, as recusas têm códigos estáveis distintos sem gravar nada, a corrida com o gerador é fechada por `BEGIN IMMEDIATE`, e o estado derivado nunca altera a tabela `vaccines`.

---

_Verificado: 2026-10-29_
_Verificador: Claude (gsd-verifier)_
