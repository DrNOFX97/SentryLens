# Deferred items - Phase 12

## Descobertos durante 12-03 (fora do âmbito, não corrigidos)

- `scripts/test_attack_registry.py` falha 2 checks ("lista: ataque 1 com incidente ligado", "detalhe: 200 com esperado vs real e incidentes") na árvore de trabalho atual. Causa: diff não commitado de `scripts/incident_store.py` (novo parâmetro posicional `assigned_to` em `IncidentStore.list_incidents`, antes de `limit`) que desalinha a chamada posicional `list_incidents(None, None, None, 100000, 0)` de `main.py` em `_build_attack_registry`. Confirmado: com `main.py`/`incident_store.py` de HEAD o teste passa, tanto com o `attack_scenarios.py` antigo como com o novo. Trabalho alheio à Phase 12 (triagem JEV / atribuição de analista); resolver quando esse trabalho for commitado (por exemplo passar `limit=`/`offset=` por palavra-chave em `main.py`).
