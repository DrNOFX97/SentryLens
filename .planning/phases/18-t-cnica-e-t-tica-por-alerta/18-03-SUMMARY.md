---
phase: 18-t-cnica-e-t-tica-por-alerta
plan: 03
subsystem: backend-mitre
tags: [mitre, detections, resolver, additive-contract, untrusted-input]
status: complete

requires:
  - phase: 18-01
    provides: tabela técnica->tática, tactics_for, parent_of, TECHNIQUE_RE
  - phase: 18-02
    provides: wazuh_win_fields, catalog_technique_id (fallback do catálogo)
provides:
  - mitre_catalog.resolve_alert_techniques(raw, table=None) -> [{id, source, tactics}]
  - DetectionEvent.techniques e DetectionEvent.technique_source (aditivos); technique = 1.ª técnica ou None
  - GET /api/detections com os campos novos, sem tocar em main.py
affects: [19, 20]

plan_head_before: 436abfe7d3c288ff0f2d0d8eb4e272bd5d26c3cc
plan_head_after: f96b13fb8a9c59725cf2354b09e3284b252ad6de
actuals:
  tokens: 6200
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns: ["resolvedor puro com precedência que substitui e não une", "entrada não confiável filtrada por tipo, tamanho e fullmatch antes de entrar no vocabulário"]

key-files:
  created: []
  modified:
    - scripts/mitre_catalog.py
    - scripts/detection_event.py
    - scripts/test_mitre_catalog.py
    - scripts/test_detection_event.py
    - scripts/test_detections_api.py

key-decisions:
  - "Assinatura resolve_alert_techniques(raw, table=None) -> list[dict], itens {id, source, tactics}; table=None usa a cache de load_mitre_techniques()"
  - "technique_source sem técnica é None; como a precedência substitui, todos os itens de uma lista têm a mesma origem"
  - "rule.mitre.id só com lixo conta como sem rule.mitre e cai no catálogo"
  - "Limites: MAX_ALERT_TECHNIQUES = 32 elementos inspecionados, MAX_TECHNIQUE_ID_LENGTH = 9 verificado antes da regex"
  - "ML e rede ganham techniques [] e technique_source None pelo default de _make"
  - "detection_event.py continua puro; a única leitura de ficheiro é a tabela MITRE em cache desde o arranque (documentado na docstring)"

requirements-completed: [MITRE-03, MITRE-04]
---

# Phase 18 Plan 03: Resolvedor de técnicas e campos aditivos no DetectionEvent Summary

`resolve_alert_techniques` dá, para qualquer alerta cru, as técnicas MITRE com origem e táticas (`rule.mitre.id` válido primeiro, técnica do catálogo de Event IDs como fallback, `[]` caso contrário; as táticas vêm sempre da tabela), `from_rule_alert` preenche `technique`/`techniques`/`technique_source` e `GET /api/detections` passa a devolvê-los sem uma linha de `main.py` e sem mudar nenhum campo antigo.

## Forma final de `resolve_alert_techniques`

```python
def resolve_alert_techniques(raw, table: dict | None = None) -> list[dict]:
    # table None -> load_mitre_techniques() (cache do arranque)
    wazuh_ids = _wazuh_technique_ids(raw)          # rule.mitre.id, só válidos, sem duplicados, ordem do Wazuh
    if wazuh_ids:                                   # D-00a: substitui, não une
        return [{"id": t, "source": "wazuh", "tactics": tactics_for(t, table)} for t in wazuh_ids]
    event_id, channel, _ = wazuh_win_fields(raw)
    tid = catalog_technique_id(event_id, channel)   # None para o canal do Defender
    if tid:
        return [{"id": tid, "source": "catalog", "tactics": tactics_for(tid, table)}]
    return []
```

`_wazuh_technique_ids`: só lê `raw["rule"]["mitre"]["id"]` se `raw`, `rule` e `mitre` forem dicts; `id` str vale como lista de um; só os primeiros 32 elementos são inspecionados; só passa str com `len <= 9` e `TECHNIQUE_RE.fullmatch`. Nunca lê a chave `tactic` (D-09; confirmado por AST: nenhuma constante `"tactic"` em `mitre_catalog.py`). Cada item e cada lista de táticas são objetos novos.

## Casos que já passavam antes do GREEN da Task 2

Com o resolvedor da Task 1 (sem limites), todos os casos de `run_resolver` passavam exceto o único que depende do limite: com 100 ids válidos, `len(resultado) == MAX_ALERT_TECHNIQUES == 32` (o teste rebentava logo com `AttributeError` por a constante não existir, e sem ela o resolvedor devolvia 100 itens). Os outros casos de tamanho já passavam por outras razões: `["T1078"] * 100000 + ["T1021"]` dá só `T1078` por deduplicação e a string de 1 milhão de caracteres falha o `fullmatch` em tempo curto. O que a Task 2 acrescentou de facto foi o teto de elementos (T-18-12: antes o custo era linear no tamanho da lista) e o `len <= 9` antes da regex.

## Chaves de `/api/detections`, antes e depois

| | Chaves por evento |
|--|--|
| Antes (R7, ac80dec) | `source, severity, asset, ts, technique, confidence, label, description` (`ref` é retirado pela rota) |
| Depois | as 8 acima + `techniques, technique_source` (igualdade exata, `OLD_EVENT_KEYS | NEW_EVENT_KEYS` em `test_detections_api.py`) |

Envelope inalterado: `{window_hours, sources, total, truncated, events}` (igualdade exata no teste). Significado dos campos antigos provado para um 4625: `severity "high"`, `label "Failed Logon"`, `confidence None`, `description == RECOMMENDATIONS[4625]`. `technique` deixou de ser sempre `None` na regra (agora a 1.ª técnica ou `None`): é o único campo antigo cujo valor muda, e é o objetivo do MITRE-04 (mesmo nome, mesmo tipo `str | None`). `DetectionEvent.__annotations__` = as 9 antigas + 2 novas.

## Prova de não regressão

- `git diff --quiet 436abfe -- scripts/incident_engine.py scripts/jev_client.py scripts/redblue_correlator.py scripts/incident_ingest.py` sai com 0; `main.py` não foi tocado neste plano (o diff contra ac80dec tem só as 6 linhas do 18-01, 0 removidas).
- Suites dos consumidores: detection 3/3, incident 8/8, redblue 4/4, jev 1/1, defender 3/3, mitre 2/2, event_catalog 1/1.
- Suite completa: `86/86 ficheiros passaram` (checkout principal, sem flakes desta vez).

## Task Commits

1. Task 1 (tracer): `96a1134` feat(detections): técnica MITRE por alerta em `from_rule_alert`
2. Task 2: `614e69f` feat(mitre): resolvedor endurecido contra `rule.mitre` não confiável
3. Task 3: `f96b13f` test(detections): prova do contrato anterior de `/api/detections`

## Deviations from Plan

None - plan executed exactly as written. Os critérios de aceitação (saídas dos `python -c`, `grep -c`, `git diff`) deram os valores esperados. A Task 2 foi um único commit (teste + código) para não deixar um commit vermelho no histórico.

Nota de processo: ao escrever o teste `"T1078\n"` por script, o `\n` virou quebra de linha real e partiu a sintaxe; corrigido com `Edit` antes de qualquer commit.

## Known Stubs

None.

## Threat Flags

None. Nenhuma superfície nova: sem rota, sem I/O novo; o `jev_client.py` não mudou e continua a usar só `label`.

## Known follow-ups

- Phase 19: usar `resolve_alert_techniques` para contar alertas por técnica e por origem, `parent_of` para casar ataque e alerta pelo pai (D-04) e pôr as técnicas com `tactics == []` na secção "sem tática" (D-09).
- Phase 20: `detections.js` pode mostrar `technique`/`technique_source` (hoje ignora-os); documentar os campos novos em `docs/DATA_MODEL.md` e `docs/API.md`; atualizar a contagem de testes (84 -> 86) em `CLAUDE.md`/`README.md` (DOC-01).
- Aviso em runtime para técnicas fora da tabela continua diferido.
- `.planning/state.json` ficou modificado pela ferramenta GSD e não foi incluído nos commits de tarefa.

## Self-Check: PASSED

- `scripts/mitre_catalog.py`, `scripts/detection_event.py`, `scripts/test_mitre_catalog.py`, `scripts/test_detection_event.py`, `scripts/test_detections_api.py`: existem e contêm os símbolos do plano.
- Commits `96a1134`, `614e69f`, `f96b13f`: ancestrais de HEAD.
