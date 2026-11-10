---
phase: 19-api-de-cobertura-mitre
plan: 02
subsystem: api
tags: [mitre, att&ck, coverage, fastapi, source-isolation, fail-closed]

requires:
  - phase: 19-api-de-cobertura-mitre
    provides: "GET /api/mitre/coverage e mitre_coverage.build_mitre_coverage_report (plano 19-01)"
provides:
  - "get_mitre_coverage com try/except isolado por fonte (D-07): Indexer em baixo ou log/registry em baixo nunca dão 500"
  - "Prova pela rota de: truncagem no teto de 8000, janela hours, contrato de métodos, só leitura"
affects: [20-matriz-mitre-frontend]

actuals:
  tokens: 11000
  tasks: 2
  commits: 2

plan_head_before: f5bb8076d1798c268102bde63bd6fa0906241b8b
plan_head_after: 5f5303c
commits: 2

tech-stack:
  added: []
  patterns:
    - "uma fonte em baixo chega à função pura como None; o corpo leva só source_unavailable e o detalhe da exceção vai para logger.warning(exc_info=True)"
    - "except Exception (não BaseException): CancelledError continua a cancelar o pedido"

key-files:
  created: []
  modified:
    - scripts/main.py
    - scripts/test_mitre_coverage_api.py

key-decisions:
  - "Fronteira de cada fonte: alertas = só o get_recent_alerts + cálculo de alerts_truncated; ataques = _read_attack_log + _build_attack_registry + filtro de janela num único try"
  - "O HTTPException(500) de _read_attack_log é apanhado como qualquer Exception e vira fonte indisponível, nunca 500"
  - "A tabela MITRE fica fora dos try (validada no arranque)"

requirements-completed: [API-01, API-02]

coverage:
  - id: D1
    description: "Indexer em baixo: 200, sources.alerts source_unavailable, alerts/totals.alerts/alerts_truncated null, ataques com vereditos unknown (correlation.reason indexer_unavailable), sem texto de exceção no corpo"
    requirement: "API-02"
    verification:
      - kind: integration
        ref: "scripts/test_mitre_coverage_api.py#run_indexer_down"
        status: pass
    human_judgment: false
  - id: D2
    description: "Log ilegível (bytes inválidos e diretório), registry a levantar, as duas fontes em baixo, modelo ML em falta e base de incidentes em baixo: sempre 200, cada fonte diz o seu estado, nada interno no corpo"
    requirement: "API-02"
    verification:
      - kind: integration
        ref: "scripts/test_mitre_coverage_api.py#run_attacks_down"
        status: pass
    human_judgment: false
  - id: D3
    description: "Teto de 8000 alertas: alerts_truncated true com 8000 e false com 7999"
    requirement: "API-02"
    verification:
      - kind: integration
        ref: "scripts/test_mitre_coverage_api.py#run_truncation"
        status: pass
    human_judgment: false
  - id: D4
    description: "Janela (168 por omissão, 720 aceite, 0/721/abc dão 422, Indexer chamado com hours/size/exclude_infra_noise), única rota sob /api/mitre só GET/HEAD com API key, POST/PUT/PATCH/DELETE dão 405"
    requirement: "API-01"
    verification:
      - kind: integration
        ref: "scripts/test_mitre_coverage_api.py#run_window_and_methods"
        status: pass
    human_judgment: false
  - id: D5
    description: "Só leitura: log de ataques byte a byte igual, nenhum método de escrita do IncidentStore chamado, a única leitura é list_incidents"
    requirement: "API-01"
    verification:
      - kind: integration
        ref: "scripts/test_mitre_coverage_api.py#run_read_only"
        status: pass
    human_judgment: false

duration: 10min
completed: 2026-11-10
status: complete
---

# Phase 19 Plan 02: Fontes isoladas e prova de só leitura Summary

**`GET /api/mitre/coverage` isola as duas fontes: o Indexer em baixo tira só os alertas, o log de ataques ilegível ou o registry a falhar tira só os ataques, e nenhum caso dá 500 nem deixa texto de exceção ou caminho no corpo.**

## Performance

- **Duration:** ~10 min
- **Completed:** 2026-11-10
- **Tasks:** 2 (Task 1 tracer, Task 2 TDD)
- **Files modified:** 2 (`scripts/main.py` com 41 linhas acrescentadas e 0 removidas face a b0bec80; `scripts/test_mitre_coverage_api.py`)

## Task Commits

1. **Task 1: Tracer, fonte de alertas isolada (Indexer em baixo)** - `4aca552` (feat)
2. **Task 2: fonte de ataques isolada, truncagem, janela, métodos, só leitura** - `5f5303c` (feat; RED e GREEN no mesmo commit, ver "TDD")

**Plan metadata:** commit `docs(19-02)` a seguir a este ficheiro.

## Corpo de `get_mitre_coverage` depois do GREEN

```python
table = load_mitre_techniques()
# Cada fonte isolada (D-07): ...
raw_alerts = None
alerts_truncated = False
try:
    raw_alerts = await indexer_client.get_recent_alerts(
        hours=hours, size=ATTACK_ALERTS_SIZE, exclude_infra_noise=True)
    alerts_truncated = len(raw_alerts) >= ATTACK_ALERTS_SIZE
except Exception:
    logger.warning("GET /api/mitre/coverage: Wazuh Indexer indisponível — fonte de alertas source_unavailable", exc_info=True)
    raw_alerts = None
attacks = None
correlation = None
try:
    attack_log = await _read_attack_log()
    registry, correlation, _ = await _build_attack_registry(attack_log, hours)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    attacks = [a for a in registry["attacks"] if (ts := incident_engine_parse(a["timestamp"])) is not None and ts >= cutoff]
except Exception:  # inclui o HTTPException(500) de _read_attack_log
    logger.warning("GET /api/mitre/coverage: registo de ataques indisponível — fonte de ataques source_unavailable", exc_info=True)
    attacks = None
    correlation = None
return mitre_coverage.build_mitre_coverage_report(
    raw_alerts, attacks, table, hours, alerts_truncated=alerts_truncated, correlation=correlation)
```

## TDD: o que falhava antes do GREEN da Task 2

Corrida RED (testes novos sobre a rota só com a fonte de alertas isolada): `run_attacks_down` rebentava logo no primeiro caso, o log com bytes `\xff\xfe\xfa`, que propagava a falha (`UnicodeDecodeError`/500 via `HTTPException` de `_read_attack_log`) em vez de devolver 200; o mesmo valia para o log que é um diretório e para o registry a levantar (a corrida abortou no primeiro, por isso os restantes não chegaram a correr). Os casos de modelo ML em falta e de base de incidentes em baixo já passavam por o `_build_attack_registry` os tratar, tal como `run_truncation`, `run_window_and_methods` e `run_read_only` (provas de comportamento já existente). Nota de processo: RED e GREEN da Task 2 foram um só commit (`5f5303c`), não dois; o RED foi confirmado por corrida antes de editar `main.py`.

## Verificação

- `test_mitre_coverage_api.py`: 100 verificações `[OK   ]`, nenhuma `[FALHOU]`, código de saída 0. Os tracebacks que aparecem no stderr são os `logger.warning(..., exc_info=True)` esperados, só em log.
- `run_all_tests.py` completo: **88/88 ficheiros passaram** (sem flakes desta vez).
- `git diff --numstat b0bec80 -- scripts/main.py`: `41 0` (só linhas acrescentadas); `allow_methods=["GET", "POST", "PATCH"]` inalterado; `mitre_catalog.py`, `attack_registry.py`, `feature_extractor.py` e `test_cors.py` sem diff.
- Verificação humana (`curl` com o backend e a VM Wazuh a correr; depois com a VM desligada): **por fazer** (laboratório não ligado nesta execução).

## Decisions Made

- Fronteira de cada fonte e `except Exception` como no plano; mensagens de log em pt-PT com prefixo `GET /api/mitre/coverage:`.
- A-06 aceite: o Indexer pode cair entre os dois pedidos; cada fonte reporta o seu estado.
- Um timeout do Indexer (exceção do httpx) é tratado como "em baixo" pelo mesmo `except`; sem teste de tempo real.

## Deviations from Plan

None - plan executed exactly as written (a única nota é o RED/GREEN num commit só, acima).

## Known Stubs

None.

## Threat Flags

None. T-19-05 (texto de exceção no corpo), T-19-06 (500 por dependência em baixo) e T-19-07 (escrita/efeitos secundários) mitigados e provados por teste; sem superfície nova.

## Known follow-ups (fora do âmbito)

- Phase 20: mostrar `—`/`Sem dados` quando `sources.*.available` é falso e o aviso de truncagem quando `alerts_truncated` é `true`; `alerts_truncated` pode ser `null`.
- Phase 20 (DOC-01): documentar a rota em `docs/API.md`, o contrato em `docs/DATA_MODEL.md` e a contagem de testes 86 -> 88 em `README.md`/`CLAUDE.md`.
- Cache da resposta só se a rota se revelar lenta (dois pedidos de até 8000 alertas por chamada).
- Truncagem por ataque (em vez de por lote) continua por decidir (carry-over do R11).

## Self-Check: PASSED

- `scripts/main.py` e `scripts/test_mitre_coverage_api.py` existem e estão modificados.
- Commits `4aca552` e `5f5303c` são ancestrais de HEAD; `git rev-list --count f5bb807..HEAD` = 2.
- Critérios de aceitação das duas tarefas e a suite completa (88/88) verificados.
