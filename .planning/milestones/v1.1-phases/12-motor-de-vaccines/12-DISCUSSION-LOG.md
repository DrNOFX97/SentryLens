# Phase 12: Motor de vaccines - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-10-11
**Phase:** 12-Motor de vaccines
**Areas discussed:** Regra para partial, Identidade e id, Janela e condição, Sensor ml/network

---

## Regra para partial
Options: só sensor em falta ✓ / regra completa / tu decides.

## Id determinístico
Options: hash attack_id + sensor em falta ✓ / só attack_id / cenário + sensor.

## Sem attack_id / duplicate_id
Options: saltar e contar ✓ / gerar com timestamp+cenário.

## Janela
Options: DEFAULT_WINDOW_SECONDS do correlator ✓ / por cenário na library.

## Condição
Options: estruturada event_ids+min_count+janela ✓ / frase descritiva.

## Sensor ml/network
Options: propor com rule null + recommendation ✓ / só rule / tudo como event_ids.

## Claude's Discretion
Hash, nomes de campos, forma do "Sem dados", texto das recommendations.

## Deferred Ideas
Janela por cenário; escrita no store (Phase 13).
