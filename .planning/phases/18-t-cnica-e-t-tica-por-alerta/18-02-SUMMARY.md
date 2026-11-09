---
phase: 18-t-cnica-e-t-tica-por-alerta
plan: 02
subsystem: backend-mitre
tags: [mitre, event-catalog, technique-id, non-regression]
status: complete

requires:
  - phase: 18-01
    provides: tabela técnica->tática (o carregador lê technique_id com .get e valida a cobertura destes 8 mapeamentos)
provides:
  - technique_id em 8 entradas de CRITICAL_EVENTS (comentário `# MITRE:` acima de cada uma)
  - event_catalog.wazuh_win_fields(raw) — extração única de Event ID/canal/eventdata
  - event_catalog.catalog_technique_id(win_event_id, channel=None) — fallback do resolvedor MITRE
affects: [18-03]

plan_head_before: 4c58348486f87a51460e25f788ff7dfc47f89607
plan_head_after: 4dd9444077c31ffe9dd877aed8c55867611f750a
actuals:
  tokens: 3500
  tasks: 2
  commits: 2

tech-stack:
  added: []
  patterns: ["dado aditivo no catálogo partilhado, provado por digests medidos antes da mudança"]

key-files:
  created:
    - scripts/test_event_catalog_mitre.py
  modified:
    - scripts/event_catalog.py

key-decisions:
  - "Vazio = chave ausente (não None nem string vazia): classify_alert e feature_extractor nunca a veem"
  - "Os restantes 23 Event IDs ficam sem technique_id (na dúvida fica vazio)"
  - "catalog_technique_id usa a mesma comparação casefold de classify_alert para o canal do Defender"

requirements-completed: [MITRE-01]
---

# Phase 18 Plan 02: technique_id no catálogo de Event IDs Summary

`CRITICAL_EVENTS` ganha `technique_id` em 8 Event IDs inequívocos (cada um justificado por um comentário `# MITRE:`), com `wazuh_win_fields` + `catalog_technique_id` como caminho de leitura do resolvedor do plano 18-03, e prova por digests medidos antes da mudança de que `classify_alert`, `classify_wazuh_alert`, o `log_analyzer.py` e o `catalog_sha256` do ML não mudaram.

## Os 8 mapeamentos (D-01, D-03)

| Event ID | technique_id | Justificação |
|----------|--------------|--------------|
| 4625 | T1110 | Brute Force: cada logon falhado é uma tentativa de adivinhar credenciais |
| 4698 | T1053.005 | Scheduled Task: o evento é a própria criação da tarefa agendada |
| 4720 | T1136.001 | Local Account: o evento é a própria criação da conta |
| 4726 | T1531 | Account Access Removal: apagar a conta remove o acesso de quem a usava |
| 4728 | T1098 | Account Manipulation: entrar num grupo global muda os privilégios |
| 4732 | T1098 | Account Manipulation: entrar num grupo local muda os privilégios |
| 4756 | T1098 | Account Manipulation: entrar num grupo universal muda os privilégios |
| 4719 | T1562.002 | Disable Windows Event Logging: o evento é a alteração da política de auditoria |

## Revisão dos restantes 23 Event IDs (escolha do planner, D-01)

Nenhum ganha `technique_id`. 4624/4672/4688/5140/5145 são atividade normal; 4699-4703 (apagar/desativar/alterar tarefas), 4704, 4713, 4722-4725, 4729/4733/4757, 4738, 4740, 4767 e 4797 podem ser ataque ou administração legítima, ou são consequência de um ataque e não a técnica em si (ex.: 4740, bloqueio). `DEFENDER_EVENTS` fica sem técnica (D-02).

## Digests: antes e depois

| Valor | Antes da mudança | Depois (8 mapeamentos aplicados) |
|-------|-----------------------------------------------|------------------------------------------|
| `classify_alert` (31 IDs + None + 9999 + 7 Defender) | f56e004b...fd5a (reconfirmado por mim antes de editar) | igual |
| `model_registry.catalog_sha256()` | 5e98dbc2...b5ca (reconfirmado por mim antes de editar) | igual |
| análise de `sample_events.json` pelo `log_analyzer` | 1f2c7843...2051 (valor do planner em ac80dec; corrida do teste após a tarefa 1 e antes dos 7 mapeamentos restantes já igual) | igual |

AST de `classify_alert`, `_defender_5007_is_tampering`, `RECOMMENDATIONS` e dos três `DEFENDER_*` igual a ac80dec (6 nós, saída 0). `git diff --quiet ac80dec` sobre `log_analyzer.py`, `feature_extractor.py`, `model_registry.py` e `detection_event.py` sai com 0. `log_analyzer.py` não importa `event_catalog`, `mitre_catalog` nem `detection_event` (AST).

## Tarefas e commits

| Tarefa | Commit | Conteúdo |
|--------|--------|----------|
| 1 (tracer) | 88ce187 | 4625->T1110, `wazuh_win_fields`, `catalog_technique_id`, `classify_wazuh_alert` sobre `wazuh_win_fields`, `run_tracer` |
| 2 (tdd) | 4dd9444 | os 7 mapeamentos restantes, `EXPECTED_TECHNIQUE_IDS`, `log_analyzer_digest`, `run_mapping` |

RED da tarefa 2 observado: falhou só `exatamente os 8 mapeamentos de D-01` (os digests e restantes casos já passavam). Tracer feedback gate: o `<verify>` automatizado foi re-executado e passou antes de expandir (modo interativo, `end-of-phase`).

## Verificação

- `test_event_catalog_mitre.py`: todos os testes passam (tracer + mapeamento, incluindo `catalog_technique_id` para `(4625, DEFENDER_CHANNEL)` e a variante em maiúsculas -> `None`, `("4625")`, `(True)` e `([4625])` -> `None` sem levantar, e `wazuh_win_fields` em 9 alertas, malformados incluídos).
- Suites `defender` 3/3, `feature` 1/1, `detection` 3/3, `incident` 8/8, `model_registry` 1/1.
- `python run_all_tests.py` completo: **86/86** ficheiros passaram (85 + o novo).
- `grep -c "# MITRE:"` em `event_catalog.py` = 8; `grep -c "classify_alert(\*wazuh_win_fields(raw))"` = 1.

## Deviations from Plan

None - plan executed exactly as written.

(Detalhe: um script auxiliar chamado `ast.py` na pasta de rascunho sombreou o módulo `ast` da stdlib; renomeado, sem efeito no repositório.)

## Known Stubs

None.

## Threat Flags

None - sem rotas, ficheiros de frontend nem superfície nova; só dados aditivos e duas funções puras que nunca levantam.

## Known follow-ups (fora do âmbito)

- `technique_id` para `DEFENDER_EVENTS` (ex.: 5001/5007 de adulteração -> T1562.001) é ideia diferida no CONTEXT, não desta fase.
- Mostrar a técnica no relatório do `log_analyzer.py` não é requisito e fica de fora.
- Phase 20 (DOC-01): documentar `technique_id` na secção do catálogo do `README.md`; contagem de testes (agora 86) em `CLAUDE.md`/`README.md`.
- Aviso do git `LF will be replaced by CRLF` nos dois ficheiros (autocrlf do Windows), sem efeito no conteúdo.

## Self-Check: PASSED

`scripts/test_event_catalog_mitre.py` e `scripts/event_catalog.py` existem; commits 88ce187 e 4dd9444 são antecessores de HEAD.
