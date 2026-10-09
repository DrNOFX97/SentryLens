# R8 — MTTD / MTTR / métricas (design)

Data: 2026-10-09 · Estado: spec para revisão · Fase anterior: R7 (Detection Engine)

## Objetivo

Dar ao laboratório números formais e reproduzíveis de quão bem deteta e
responde, calculados **só a partir de dados reais** já recolhidos pelo
SentryLens. Três painéis só de leitura (MTTD / MTTR, Detection Coverage,
Detection Rate) sobre uma rota nova `GET /api/metrics`. Sem dados, os painéis
mostram "Sem dados" — nunca um valor inventado.

Não muda nenhum contrato existente (`/api/redblue/metrics`, `/api/incidents`,
`/api/detections`).

## Estado atual (de onde parte)

- MTTD já existe em `redblue_correlator.py` (`mttd_seconds` por ataque,
  `avg_mttd_seconds` por cenário e global): primeiro alerta correspondente
  menos o instante do ataque, dentro da janela do ataque.
- `incident_engine.py` já calcula `time_to_first_response_seconds`
  (1.ª transição para `INVESTIGATING` menos `first_evidence_at`).
- Estados do incidente: `NEW → INVESTIGATING → CONTAINED → RESOLVED → CLOSED`;
  `NEW → CLOSED` exige nota (é assim que se regista um falso positivo).
- Em falta: MTTR, FP/FN e definições formais (`docs/ROADMAP_STATUS.md`, R8).

## Decisões tomadas

1. **MTTR = `first_evidence_at` → entrada em `RESOLVED`**, só sobre incidentes
   que chegaram a `RESOLVED`. Os ainda abertos não entram na média; aparecem
   como contagem separada, para não enviesar o número.
2. **FN** = ataque lançado (`attack_log`) com veredito `not_detected`.
3. **FP** = só incidentes fechados como falso positivo (`NEW → CLOSED` com a
   nota obrigatória). Taxa de FP = incidentes FP / incidentes fechados. Alertas
   ou incidentes sem ataque correlacionado **não** contam como FP (o laboratório
   tem tráfego legítimo de fundo; contá-lo inflacionaria o número).
4. **Mediana e p90** além da média em MTTD/MTTR: com amostras pequenas a média
   engana.
5. Abordagem: módulo puro novo, sem alterar `redblue_correlator.py` nem
   `incident_engine.py`. Snapshots periódicos para tendência ficam de fora.

## Arquitetura

- `scripts/soc_metrics.py` (novo, **puro**, sem I/O):
  `build_metrics_report(redblue_report, incidents, window_hours)`.
  Recebe os dados já obtidos; devolve o relatório. Segue o padrão
  `build_*_report` dos outros painéis (testável com mocks, sem o Wazuh).
- `scripts/main.py`: rota `GET /api/metrics?hours=` com
  `dependencies=_REQUIRE_API_KEY` **na própria rota** (nunca a nível de app).
  `hours`: `Query(168, ge=1, le=168)` (mesmo teto dos outros endpoints
  temporais). A rota obtém o relatório Red vs Blue e os incidentes (store
  SQLite) e chama `build_metrics_report`.
- `metrics.js` (novo, raiz): serve os 3 itens da sidebar que hoje são
  `data-planned="R8"` (passam a `data-tab`). Um só pedido por ativação da aba.
  Não edita `app.js`; reutiliza os seus globais, como `redblue.js`.
- `scripts/serve_frontend.py`: acrescentar `metrics.js` à whitelist fixa.

### Fontes de dados (sem recolha nova)

| Fonte | Dá |
|---|---|
| `build_redblue_report` | tentativas de ataque, veredito, MTTD, fonte da deteção (regra/ML/rede), técnica MITRE e cenário |
| `incident_store` (SQLite) | incidentes, transições de estado com timestamps, notas de fecho |

## Forma do relatório (`GET /api/metrics`)

```
{
  "window_hours": 168,
  "generated_at": "...",
  "min_sample": 5,
  "mttd":     {"available", "n", "median_s", "p90_s", "avg_s", "by_scenario": {...}},
  "mttr":     {"available", "n", "median_s", "p90_s", "avg_s", "open_count",
               "first_response": {"n", "median_s", "p90_s", "avg_s"}},
  "coverage": {"available", "scenarios": {"covered", "total", "pct"},
               "techniques": {"covered", "total", "pct"},
               "gaps": {"scenarios": [...], "techniques": [...]}},
  "rate":     {"available", "launched", "detected", "partial", "not_detected",
               "unknown", "detection_pct", "by_source": {"rule","ml","network","multiple"},
               "false_negatives": N,
               "false_positives": {"n", "closed_total", "pct"}},
  "definitions": {"mttd": "...", "mttr": "...", "fp": "...", "fn": "..."}
}
```

Cada bloco traz `available` e `n`. Um valor sem amostra é `null`, nunca `0`.

## Regras de honestidade dos dados

- Sem amostra → `null` + "Sem dados" no painel.
- `n < METRICS_MIN_SAMPLE` (env, default 5) → valor mostrado com aviso
  "amostra pequena"; a taxa de FP **não** é calculada abaixo do mínimo.
- Ataques com veredito `unknown` ficam fora do denominador da taxa de deteção e
  são contados à parte.
- Cada métrica expõe a sua definição em texto curto (`definitions`).
- Uma fonte que falhe (Indexer, store) isola-se: o bloco afetado fica
  `available: false`; os outros continuam a responder (como `/api/detections`).
- Erros expostos como códigos estáveis, nunca texto de exceção (padrão do
  `siem_health.py`).

## Testes

`scripts/test_soc_metrics.py` standalone (sem pytest; `[OK]`/`[FALHOU]`,
`sys.exit(1)` em falha; `SENTRYLENS_API_KEY` antes de `import main`;
`main.app.router.on_startup.clear()`):

- entradas vazias → tudo `null`/`available: false`;
- amostra abaixo do mínimo → aviso e sem taxa de FP;
- MTTR só com `RESOLVED`; abertos contados à parte;
- mediana/p90 corretos (casos pares/ímpares, n=1);
- FP só via `NEW → CLOSED` com nota; FN só `not_detected`; `unknown` excluído;
- lacunas de cobertura por cenário e por técnica MITRE;
- rota: 401 sem API key, 200 com mocks, isolamento quando uma fonte falha,
  `hours` fora de 1–168 → 422.

`run_all_tests.py` passa a apanhar o ficheiro novo (padrão `test_*.py`).

## Fora de âmbito

- Tendências no tempo / snapshots periódicos; alertas por limiar.
- Exportação para o relatório HTML (R19).
- Alterar o cálculo de MTTD existente ou `incident_engine.py`.
- Tornar `confidence`/`technique` do R7 não-`None`.

## Documentação a atualizar no fecho

`docs/ROADMAP_STATUS.md` (R8 → ✅; **corrigir R7 → ✅**, o painel Detections foi
entregue no commit `f168fab`), `docs/DATA_MODEL.md` (definições de MTTR/FP/FN —
hoje diz "MTTR ainda não existe"), `README.md` (endpoint, aba, testes) e
`CLAUDE.md` (módulo `soc_metrics.py`, contagem de testes).

## Ajustes ao ler o código (plano de 2026-10-09)

1. **MTTD usa a deteção mais cedo de qualquer fonte** (`min(mttd_seconds, mttd_network_seconds)`), só para ataques realmente sinalizados — coerente com a taxa, que conta a rede.
2. **"Detetado" = alguém sinalizou** (`detected_by != "none"` ou `detected_by_network`): o `detected` do correlator é verdadeiro para qualquer alerta correspondente, mesmo não sinalizado.
3. **Não existe `partial`**: o correlator não tem esse veredito. O bloco `rate` tem `detected`/`not_detected`.
4. **`unknown` passou a `excluded`**: contagem de `not_executed`, `unknown_scenario` e `invalid_entries`, fora do denominador.
5. **Universo da cobertura** = cenários e técnicas lançados na janela (não o catálogo inteiro).
6. **A rota filtra o log de ataques pela janela**: sem isso, um ataque anterior à janela apareceria como falso negativo.
7. **`alerts_truncated`** (descoberto ao testar com dados reais): quando o Indexer devolve o teto de 1000 alertas, ataques antigos ficam sem os seus alertas e aparecem como não detetados (o `/api/redblue/metrics` tem o mesmo limite). O relatório sinaliza-o e os painéis avisam que os valores são limites inferiores.
