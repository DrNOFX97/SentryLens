---
status: complete
phase: 17-aba-testes-e-documenta-o
source: [17-01-SUMMARY.md, 17-02-SUMMARY.md, 17-03-SUMMARY.md, 17-04-SUMMARY.md, 17-05-SUMMARY.md, 17-06-SUMMARY.md]
started: 2026-11-04T13:54:36Z
updated: 2026-11-04T14:03:06Z
---

## Current Test

[testing complete]

## Tests

### 1. Aprovar e rejeitar no detalhe da vaccine
expected: Botões desativados até escolher analista; rejeitar sem motivo é recusado localmente; após decidir, bloco só de leitura (badge, autor, data, motivo, "não aplicada no Wazuh") e tabela/contadores atualizados.
result: pass

### 2. Conflito 409 com dois separadores
expected: Decide a mesma vaccine no separador 1 e depois no separador 2. O separador 2 mostra a frase de "já decidida" e refaz detalhe e lista sozinho, sem novo POST automático.
result: pass

### 3. Temas claro e escuro
expected: Badges de estado, bloco Decisão, filtro Estado e cartões dos contadores legíveis nos dois temas; a cor não é a única pista; o formulário mostra-se e esconde-se corretamente. Os contadores não mudam ao filtrar e mostram "—" com o store vazio.
result: pass

### 4. Vaccine substituída e lista de analistas vazia ou indisponível
expected: Com "Incluir substituídas", uma vaccine substituída mostra uma frase no lugar dos botões. Com a lista de analistas vazia ou indisponível, aparece uma frase em vez dos botões, nunca um bloco escondido.
result: pass

## Summary

total: 4
passed: 4
issues: 0
pending: 0
skipped: 0
blocked: 0

## Gaps

[none yet]
