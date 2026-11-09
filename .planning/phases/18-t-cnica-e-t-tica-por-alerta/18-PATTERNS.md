# Fase 18: Técnica e tática por alerta - Mapa de padrões

**Mapeado:** 2026-11-09
**Ficheiros analisados:** 9 (4 novos, 4 modificados, 1 só verificação)
**Análogos encontrados:** 9 / 9 (todos git-tracked: attack_library.py/.yaml, test_*.py, event_catalog.py, detection_event.py confirmados com `git ls-files`)

## Classificação de ficheiros

| Ficheiro | Papel | Fluxo | Análogo mais próximo | Qualidade |
|---|---|---|---|---|
| `scripts/event_catalog.py` (MOD: `technique_id` + comentários em `CRITICAL_EVENTS`) | config/catálogo | transform | ele próprio (entradas existentes) | exato |
| `scripts/mitre_techniques.yaml` (NOVO) | config (dados versionados) | file-I/O | `scripts/attack_library.yaml` | exato |
| `scripts/mitre_catalog.py` (NOVO, nome à escolha do planner: loader/validador/resolvedor/`parent_of`) | utilitário puro | transform + file-I/O (YAML em cache) | `scripts/attack_library.py` | exato |
| `scripts/main.py` (MOD: chamada fail-fast a nível de módulo) | config/arranque | — | linhas 142-146 (`load_attack_library()`) | exato |
| `scripts/detection_event.py` (MOD: `from_rule_alert` + TypedDict + `_make`) | modelo/construtor puro | transform | ele próprio | exato |
| `scripts/attack_scenarios.py` (MOD: T1053 `mitre_tactic`) | config | — | linhas 214-222 | exato |
| `scripts/test_mitre_catalog.py` (NOVO: tabela, resolvedor, completude D-10, coerência cenários, mapeamento exato do catálogo D-03) | teste | request-response/unit | `scripts/test_attack_library.py` | exato |
| `scripts/test_detection_event.py` (MOD) | teste | unit | ele próprio | exato |
| `scripts/test_detections_api.py` (MOD, opcional: campos aditivos) | teste | request-response | ele próprio (linha 95) | exato |
| `scripts/incident_engine.py:206` (só verificar) | engine puro | — | — | n/a |
| `scripts/run_all_tests.py` (só verificar) | runner | — | — | n/a |

## Atribuições de padrão

### `scripts/mitre_catalog.py` (NOVO)

**Análogo:** `scripts/attack_library.py`

**Cabeçalho/imports/constantes** (linhas 19-43). Copiar estrutura, trocar nomes:
```python
from __future__ import annotations
import os, re, sys
from pathlib import Path
import yaml

DEFAULT_PATH = Path(__file__).parent / "attack_library.yaml"   # -> mitre_techniques.yaml
MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")   # já existe; reutilizar/importar de attack_library.MITRE_RE (D-11 usa a mesma regex)
_cache: dict[str, dict] | None = None
_cache_path: Path | None = None
```
Acrescentar a constante com as 14 táticas Enterprise (Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact).

**Resolução de caminho** (linhas 46-53): copiar `_resolve_path` com variável de ambiente própria (ex. `MITRE_TECHNIQUES_PATH`); relativo é sempre relativo ao ficheiro, nunca ao cwd.

**Validação** (linhas 56-113): `validate_entry(...) -> list[str]` nunca levanta; devolve problemas em português com prefixo `f"{name}: ..."`. Aplicar a: id fora de `MITRE_RE`, tática fora das 14, tática lista vazia/não lista, campo em falta (`name`, `tactics`), id duplicado (YAML `safe_load` colapsa chaves duplicadas em silêncio num mapa, por isso a tabela deve ser **lista** de `{id, name, tactics}` e o loader deteta duplicados explicitamente), técnica de `SCENARIOS` ou de `CRITICAL_EVENTS` em falta na tabela (ou no pai).

**Loader com cache fail-fast** (linhas 116-178): estrutura exata a copiar:
```python
try:
    with open(resolved, encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
except FileNotFoundError as exc:
    raise ValueError([f"... não encontrado em '{resolved}'"]) from exc
except yaml.YAMLError as exc:
    raise ValueError([f"... inválido (YAML malformado): {exc}"]) from exc
...
if problems:
    raise ValueError(problems)
if use_cache:
    _cache = merged; _cache_path = resolved
return merged
```
`reset_cache()` (181-185) para testes. Atenção: attack_library importa `attack_scenarios`; o novo módulo pode importar `attack_scenarios.SCENARIOS` e `event_catalog.CRITICAL_EVENTS` para a verificação de completude sem ciclos (nenhum importa o novo módulo).

**Resolvedor e `parent_of`** (sem análogo direto, puro): `parent_of("T1053.005") -> "T1053"`; `tactics_for(tid)` = entrada própria, senão a do pai, senão `[]` (D-04, D-09); `resolve_alert_techniques(raw) -> list[{"id","source","tactics"}]`: `rule.mitre.id` (lista ou string, ignorar não-str e fora de `MITRE_RE`, manter ordem e deduplicar) -> origem `wazuh`; senão `technique_id` do catálogo via Event ID (reaproveitar a extração de `event_catalog.classify_wazuh_alert`/`data.win.system.eventID`, não duplicar) -> origem `catalog`; senão `[]`. Nunca ler `rule.mitre.tactic` (D-09). Tolerar alerta malformado sem levantar (padrão `except (AttributeError, ValueError, TypeError)` de `event_catalog.classify_wazuh_alert`, linhas 179-190).

---

### `scripts/mitre_techniques.yaml` (NOVO)

**Análogo:** `scripts/attack_library.yaml` (cabeçalho de comentários a documentar campos e coerência; sem acentos nos comentários, ASCII; strings entre aspas).

Conteúdo mínimo (D-10/D-11): T1078, T1021, T1550.002, T1078.002, T1484, T1531 (observadas), mais as do catálogo (T1110, T1053.005 ou pai T1053, T1136.001, T1098, T1562.002) e dos cenários (T1110, T1110.003, T1135, T1053). Cada técnica com a lista completa de táticas (D-05), ex. T1078 -> Defense Evasion, Persistence, Privilege Escalation, Initial Access.

---

### `scripts/main.py` (MOD)

**Análogo:** linhas 142-146
```python
# Attack Library (R5): ... Validação fail-fast e síncrona no arranque ...
load_attack_library()
```
Linha 62 mostra o import: `from attack_library import ID_RE as ..., load_attack_library`. Adicionar `from mitre_catalog import load_mitre_techniques` e uma chamada `load_mitre_techniques()` logo a seguir, com comentário no mesmo estilo. Sem rota nova nesta fase (Fase 19). Nenhum ficheiro novo no frontend, logo `serve_frontend.ALLOWED_FILES` não muda.

---

### `scripts/event_catalog.py` (MOD)

**Análogo:** `CRITICAL_EVENTS` (linhas 13-45), entradas `dict[str, str]`. Padrão atual:
```python
4625: {"name": "Failed Logon", "severity": "high", "category": "autenticacao"},
```
Acrescentar a chave `"technique_id"` só às entradas D-01 (4625 T1110; 4698 T1053.005; 4720 T1136.001; 4728/4732/4756 T1098; 4719 T1562.002; 4726 T1531), cada uma com comentário curto de justificação (D-03). Vigiar:
- `classify_alert()` (linhas 139-176) devolve um dict novo com 4 chaves; **não** o alterar (restrição do marco). `info.get("category", "geral")` é o padrão de leitura opcional; ler a técnica com `CRITICAL_EVENTS.get(eid, {}).get("technique_id")`.
- `feature_extractor._EVENT_ID_ORDER = sorted(CRITICAL_EVENTS.keys())` (feature_extractor.py:50) só usa chaves; não acrescentar nem remover Event IDs (a ordem do ML ia mudar, ver comentário linha ~80 de event_catalog.py).
- `log_analyzer.py` (Fase 1) tem o seu próprio `CRITICAL_EVENTS` (linha 41); não é tocado.
- `DEFENDER_EVENTS` não ganha `technique_id` (D-02).

---

### `scripts/detection_event.py` (MOD)

**Análogo:** próprio ficheiro. Pontos exatos:
- `DetectionEvent` TypedDict (linhas 32-41): acrescentar `techniques: list[dict]` e `technique_source: str | None`; manter `technique: str | None` e atualizar o comentário da linha 37 (já não é "sempre None" para a regra).
- `_make()` (44-53): acrescentar kwargs `techniques: list | None = None`, `technique_source: str | None = None` com default que produz `[]`/`None`, para `from_ml_anomaly` e `from_network_detection` ficarem inalterados (apenas ganham as chaves aditivas vazias).
- `from_rule_alert()` (56-73): depois de `classification = classify_wazuh_alert(raw)`, chamar o resolvedor; `technique` = id da primeira (D-06), `technique_source` = origem da primeira ou `None` sem técnica. `ref=raw` mantém-se (apontador, nunca cópia).
- Importa já `from event_catalog import classify_wazuh_alert`; novo import `from mitre_catalog import ...` (módulo puro, sem ciclo).
- Cuidado: `incident_engine.py` e `redblue_correlator.py` constroem sobre `from_rule_alert` (docstring, linhas 11-14); confirmar que `test_incident_engine.py` e `test_redblue_*` continuam a passar (as chaves aditivas não devem vazar para as suas formas próprias).

---

### `scripts/attack_scenarios.py` (MOD)

**Análogo:** linhas 214-222, cenário `lateral_movement_schtasks`:
```python
mitre_tactic="Lateral Movement",   # errado para T1053
mitre_technique="T1053",
```
Trocar por uma tática que a tabela liste para T1053 (Execution, Persistence ou Privilege Escalation; o planner decide, tem de coincidir com a tabela). O teste da linha ~450 (`assert scenario.mitre_tactic`) continua válido. Verificar que `attack_library.yaml`/testes não fixam "Lateral Movement" (grep em `scripts/test_*.py`, `redblue.js`, `attack_*.js`).

---

### `scripts/test_mitre_catalog.py` (NOVO)

**Análogo:** `scripts/test_attack_library.py`

**Cabeçalho** (linhas 1-39): docstring em pt, "Correr (a partir de scripts/)", `os.environ.setdefault("SENTRYLENS_API_KEY", "test-key-...")` **antes** de `import main`, `main.app.router.on_startup.clear()`, `check()`:
```python
failures: list[str] = []
def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)
```
Rodapé (linhas finais): `run()`; `if failures: print(f"\n{len(failures)} verificação(ões) falharam"); sys.exit(1)`; `print("\nTodos os testes passaram")`. Chamar `reset_cache()` entre cenários.

Casos a cobrir: tabela válida carrega; cada tipo de erro de validação (id mau, tática fora das 14, duplicado, campo em falta) via YAML temporário em `tempfile` (padrão já usado em test_attack_library, importa `tempfile`/`yaml`); herança pai->sub-técnica; `parent_of`; precedência wazuh>catalog>vazio e substituição (não união); `tactic[]` do Wazuh ignorado; técnica desconhecida -> `tactics: []`; lista literal D-10 escrita no teste (nunca ler `scripts/snapshots/`); mapeamento exato de `CRITICAL_EVENTS` com `technique_id` (D-03); coerência `SCENARIOS` tática vs tabela (técnica ou pai); `main` arranca (import já valida). Sem mocks de Wazuh necessários (módulo puro); se testar rota `/api/detections`, usar `AsyncMock` de `WazuhIndexerClient` como em `test_detections_api.py`.

---

### `scripts/test_detection_event.py` (MOD)

**Análogo:** próprio. Linha ~49 `check("technique fica None (ruling 2, R7)", e["technique"] is None)` **falha** depois da fase: o fixture usa Event ID 4625 -> `technique == "T1110"`, `technique_source == "catalog"`. Atualizar e acrescentar casos: alerta com `rule.mitre.id` (origem `wazuh`, precedência sobre o catálogo), alerta sem técnica (`technique None`, `technique_source None`, `techniques == []`). O helper `raw_alert(...)` (linhas 33-41) devolve `rule` sem `mitre`; estender com parâmetro `mitre=None`. As asserções de `from_ml_anomaly`/`from_network_detection` não devem mudar.

### `scripts/test_detections_api.py` (MOD, opcional)
Linha 95 verifica `<= e.keys()` (subconjunto), logo as chaves aditivas não a quebram; acrescentar `techniques`/`technique_source` ao conjunto.

## Padrões partilhados

### Módulo puro, erros como listas de frases
Fonte: `attack_library.validate_entry`/`load_attack_library`. Aplicar a `mitre_catalog.py`: nunca levantar em dados de alerta; `ValueError(list[str])` só no carregamento da tabela.

### Fail-fast no arranque
Fonte: `main.py:142-146`. Chamada síncrona a nível de módulo, sem try/except.

### Aditivo e sem valores inventados
`None`/`[]` quando não há técnica (nunca `0` nem strings inventadas); nenhum campo existente de `/api/detections` muda (D-00b).

### Testes standalone
Sem pytest; `[OK   ]`/`[FALHOU]`; `sys.exit(1)`; `SENTRYLENS_API_KEY` antes de `import main`; `run_all_tests.py:29` descobre `test_*.py` por glob, por isso o novo teste entra sozinho (nada a registar). Não depender de `scripts/snapshots/` nem `scripts/models/` (gitignored). Fonte do README: acrescentar o novo teste à lista de testes (a contagem 84 em CLAUDE.md/README sobe para 85).

## Verificações sem alteração

- `scripts/incident_engine.py:206`: `"technique": entry.get("technique") or (scenario.mitre_technique if scenario else None)` lê o `attack_log` (entrada de ataque), não o DetectionEvent; permanece coerente. D-08: o `attack_log.jsonl` não se reescreve; a tática é recalculada da tabela a jusante (Fase 19).
- `docs/DATA_MODEL.md`: atualização do `DetectionEvent` fica para a Fase 20 (DOC-01), não nesta.

## Sem análogo

| Ficheiro/Função | Motivo |
|---|---|
| `parent_of()` e `resolve_alert_techniques()` | Lógica nova; seguir só o estilo (puro, tolerante) de `event_catalog.classify_wazuh_alert` |

## Metadados

**Âmbito da pesquisa:** `scripts/` (attack_library*, event_catalog, detection_event, attack_scenarios, main, incident_engine, test_*), `log_analyzer.py`
**Ignorado:** cópias em `.claude/worktrees/` e `.worktrees/` (não são fonte rastreada relevante)
**Data:** 2026-11-09
