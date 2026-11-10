---
status: testing
phase: 19-api-de-cobertura-mitre
source: [19-VERIFICATION.md]
started: 2026-11-10T10:15:59Z
updated: 2026-11-10T10:15:59Z
---

## Current Test

number: 1
name: GET /api/mitre/coverage com a VM Wazuh ligada
expected: |
  200 com header X-API-Key; 17 tecnicas em techniques[] e 14 taticas.
awaiting: user response

## Tests

### 1. GET /api/mitre/coverage com a VM Wazuh ligada
expected: 200, 17 tecnicas, 14 taticas, fontes disponiveis.
result: [pending]

### 2. Mesmo pedido com a VM Wazuh desligada
expected: continua 200; sources.alerts = {available:false, reason:"source_unavailable"}; alerts_truncated, totals.alerts e alerts a null; ataques unknown com correlation.reason indexer_unavailable; corpo sem texto de excecao nem caminhos.
result: [pending]

## Summary

total: 2
passed: 0
issues: 0
pending: 2
skipped: 0
blocked: 0

## Gaps
