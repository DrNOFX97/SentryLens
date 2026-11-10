# Phase 19: API de cobertura MITRE - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-11-10
**Phase:** 19-api-de-cobertura-mitre
**Areas discussed:** Que técnicas aparecem, Definição de "detetado", Fontes/janela/truncagem, Tática multi-valor e envelope

---

## Que técnicas aparecem

| Option | Description | Selected |
|--------|-------------|----------|
| Tabela + observadas | Todas as 17 da tabela com zeros reais mais técnicas vistas fora da tabela | ✓ |
| Só as observadas | Só técnicas com ≥1 alerta ou ataque | |

**User's choice:** Tabela + observadas

### Granularidade (sub-técnica vs pai)

| Option | Description | Selected |
|--------|-------------|----------|
| Linha própria + pai agregado | Cada id exato com linha; pai só decide "detetado" | ✓ |
| Só ao nível do pai | Tudo somado no pai, sub-técnicas em `variants` | |
| You decide | Deixar ao planner | |

**User's choice:** Linha própria + pai agregado

---

## Definição de "detetado"

| Option | Description | Selected |
|--------|-------------|----------|
| Só detected | `partial` conta como não detetado, mas contado à parte | ✓ |
| detected + partial | Basta uma fonte ter visto | |

**User's choice:** Só detected

### Ataques `unknown`

| Option | Description | Selected |
|--------|-------------|----------|
| Fora do denominador | Contados à parte; taxa `null` se denominador 0 | ✓ |
| Dentro, como não detetados | Falha do Indexer faria a cobertura cair a 0% | |

**User's choice:** Fora do denominador

---

## Fontes, janela e truncagem

| Option | Description | Selected |
|--------|-------------|----------|
| Duas fontes isoladas | Alertas via Indexer direto, ataques via registry, cada uma com `source_unavailable` | ✓ |
| Só via registry | Alertas vistos saem dos que o registry busca | |

**User's choice:** Duas fontes isoladas

### Janela e teto

| Option | Description | Selected |
|--------|-------------|----------|
| hours 24, máx 720, teto 8000 | | |
| hours 168, máx 720, teto 8000 | Ataques do lab são esporádicos | ✓ |
| Teto 1000 (como /api/metrics) | | |

**User's choice:** hours 168 por omissão, máx 720, teto 8000

---

## Tática multi-valor e envelope

| Option | Description | Selected |
|--------|-------------|----------|
| Em todas as táticas | Soma pode exceder o total; total único à parte | ✓ |
| Só na primeira tática | Viola D-05 da Fase 18 | |

**User's choice:** Em todas as táticas

### Envelope

| Option | Description | Selected |
|--------|-------------|----------|
| tactics[] + techniques[] + unmapped[] + sources | Sem-tática fora de `techniques[]` | ✓ |
| Sem tática em bloco próprio mas também em `techniques[]` | | |

**User's choice:** tactics[] + techniques[] + unmapped[] + sources

---

## Claude's Discretion

- Nomes exatos dos campos, módulo puro de cálculo, ordenação, totais, validação de `hours`.

## Deferred Ideas

- Cache da resposta; Caldera (SIM-01).
