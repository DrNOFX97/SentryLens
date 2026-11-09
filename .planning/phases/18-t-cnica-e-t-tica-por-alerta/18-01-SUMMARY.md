---
phase: 18-t-cnica-e-t-tica-por-alerta
plan: 01
subsystem: backend-mitre
tags: [mitre, attack, yaml, fail-fast, tactics]
status: complete

requires:
  - phase: 17
    provides: attack_library.py (padrão de carregador YAML fail-fast) e attack_scenarios.SCENARIOS
provides:
  - scripts/mitre_techniques.yaml (17 técnicas, ATT&CK Enterprise v18.1)
  - mitre_catalog.load_mitre_techniques / tactics_for / parent_of
  - validação fail-fast da tabela no arranque do backend
affects: [18-02, 18-03, 19-cobertura-mitre]

plan_head_before: 07289b2f0ae77e4eaadb1d3bae355524bebd6223
plan_head_after: 500c1a1897512d91548c1567d1020dc9ec55f457
actuals:
  tokens: 6500
  tasks: 3
  commits: 4

tech-stack:
  added: []
  patterns: ["tabela de dados versionada + carregador puro com cache e fail-fast em main.py (como attack_library)"]

key-files:
  created:
    - scripts/mitre_techniques.yaml
    - scripts/mitre_catalog.py
    - scripts/test_mitre_catalog.py
  modified:
    - scripts/main.py
    - scripts/attack_scenarios.py

key-decisions:
  - "ATT&CK fixado na v18.1 (14 táticas Enterprise com Defense Evasion); v19+ troca-a por Stealth/Defense Impairment, decisão futura"
  - "Tabela como lista de {id, name, tactics} para o duplicado ser detetável; contrato fechado (campo desconhecido é erro)"
  - "Coerência cenário->tática é teste (D-07), cobertura de técnicas é regra do carregador (D-11)"
  - "lateral_movement_schtasks passa a mitre_tactic Execution (T1053, /sc once)"

requirements-completed: [MITRE-02]
---

# Phase 18 Plan 01: Tabela técnica->tática MITRE Summary

Tabela técnica->tática versionada (17 entradas ATT&CK Enterprise v18.1) com carregador `yaml.safe_load`, validação fail-fast que o `main.py` executa no arranque, `tactics_for`/`parent_of` para o resolvedor e a cobertura, e a tática de T1053 corrigida para `Execution`.

## Escolhas do planner (a registar)

- **Módulo:** `scripts/mitre_catalog.py`, variável de ambiente `MITRE_TECHNIQUES_PATH`.
- **Versão ATT&CK v18.1**, porque é a última com as 14 táticas Enterprise incluindo Defense Evasion (D-05 e D-11 e o vocabulário que o Wazuh do lab envia em `rule.mitre.tactic`). Constante `ATTACK_VERSION = "v18.1"` e cabeçalho do YAML.
- **As 17 entradas:** T1021, T1053, T1053.005, T1078, T1078.002, T1098, T1110, T1110.003, T1135, T1136, T1136.001, T1484, T1531, T1550, T1550.002, T1562, T1562.002 (T1136, T1550, T1562 entram como pais de sub-técnicas).
- **Tática de `lateral_movement_schtasks`: `Execution`** (tarefa `/sc once` corre um binário uma vez).

## Tarefas e commits

| Tarefa | Commit | Conteúdo |
|--------|--------|----------|
| 1 (tracer) | 111ec47 | YAML, `mitre_catalog.py`, chamada em `main.py`, `run_tracer` |
| 2 | 5f5fac0 | validação completa (campo desconhecido, name, tática repetida, duplicado), cobertura D-11, `run_validation` com subprocesso |
| 3 | 6bbb5d2, 500c1a1 | `fix(attack-scenarios)` T1053 -> Execution; `run_completeness_and_coherence` |

Tracer feedback gate: o `<verify>` automatizado foi re-executado e passou antes de expandir.

## Verificação

- `test_mitre_catalog.py`: todos os testes passam.
- Arranque inválido (subprocesso, `MITRE_TECHNIQUES_PATH` com tática `Lateral Movment`): código 1, stderr
  `ValueError: ["entrada #1 (T1110): tactics com tática fora das 14 Enterprise: 'Lateral Movment'"]`; com cópia válida da tabela: código 0.
- `attack_scenarios.py --self-check` sai com 0; `git diff --stat` de `attack_scenarios.py`: 1 inserção, 1 remoção.
- Suites `attack` 5/5, `redblue` 4/4, `vaccine` 9/9.
- `python run_all_tests.py` completo: **85/85** ficheiros passaram (84 + o novo; 18-02 acrescentará mais um).
- AST: a única chamada ao PyYAML é `safe_load`; `mitre_catalog.py` tem uma só chamada a `open`, em leitura.

## Deviations from Plan

None - plan executed exactly as written.

(Detalhe de execução: o `fix` de T1053 e o teste de coerência ficaram em dois commits em vez de um, ordem fix -> test para cada commit ficar verde.)

## Known Stubs

None.

## Threat Flags

None - sem rotas, ficheiros de frontend nem superfície nova; a tabela é lida só em leitura e só com `safe_load`.

## Known follow-ups (fora do âmbito)

- Phase 19: a tática de um ataque recalcula-se com `tactics_for(técnica)` (D-08); vaccines já gravadas guardam `origin.mitre_tactic` "Lateral Movement" para ataques antigos de `lateral_movement_schtasks` (linhas imutáveis) e não são fonte de tática.
- Phase 19: o `attack_log.jsonl` local tem técnicas fora da tabela (T1087, T1046, T1557.001, T1003, T1566, T1040, T1558); pela regra D-09 ficam sem tática; decidir se a tabela cresce.
- Atualização para ATT&CK v19+ é uma decisão nova.
- `kali-share/attack_scenarios.py` (cópia gitignored para a VM Kali) mantém a tática antiga até ser recopiada.
- Phase 20 (DOC-01): `docs/DATA_MODEL.md` (~linha 226) ainda mostra "Lateral Movement" para T1053; contagem de testes em `CLAUDE.md`/`README.md`.

## Self-Check: PASSED

Ficheiros criados existem (`mitre_techniques.yaml`, `mitre_catalog.py`, `test_mitre_catalog.py`); commits 111ec47, 5f5fac0, 6bbb5d2 e 500c1a1 são antecessores de HEAD.
