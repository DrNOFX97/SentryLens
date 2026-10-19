---
status: testing
phase: 14-aba-vaccines-testes-e-documenta-o
source: [14-VERIFICATION.md]
started: 2026-10-19T16:52:00Z
updated: 2026-10-19T16:52:00Z
---

## Current Test

number: 1
name: Abrir a aba Vaccines no dashboard e usar os filtros
expected: |
  A tabela mostra o subconjunto certo; linha do gerador legível ("Última execução há X min" ou a frase do código);
  badges de veredito (Não detetado/Parcial) distinguíveis; vaccines substituídas esbatidas com "Substituída por <id>".
awaiting: user response

## Tests

### 1. Abrir a aba Vaccines no dashboard e usar os filtros
expected: Abrir a aba Vaccines no dashboard (backend + frontend a correr) e usar os filtros (ataque, técnica MITRE, Incluir substituídas) e o botão Atualizar. A tabela mostra o subconjunto certo; linha do gerador legível ("Última execução há X min" ou a frase do código); badges de veredito (Não detetado/Parcial) distinguíveis; vaccines substituídas esbatidas com "Substituída por <id>".
result: [pending]

### 2. Backend parado + Atualizar
expected: Parar o backend e carregar em Atualizar. Banner de erro e linha "Sem ligação ao backend (localhost:8001)...", nunca "Sem dados" nem lista vazia.
result: [pending]

### 3. Navegação por teclado e detalhe/cadeia
expected: Clicar (e Tab + Enter/Espaço) numa linha; abrir uma vaccine substituída com "Incluir substituídas"; carregar em Atualizar com uma linha aberta. Detalhe com aviso "Proposta — não aplicada no Wazuh", Origem (ataque, cenário, MITRE, incidentes), Propostas e Cadeia, sem links; foco visível; a linha selecionada mantém o destaque depois de Atualizar.
result: [pending]

### 4. Ataque não detetado, ponta a ponta
expected: Lançar um ataque que escape à deteção e esperar 10 a 15 min. A vaccine aparece na aba depois da estabilização (600s) mais o intervalo do loop (300s).
result: [pending]
blocked_by: physical-device
reason: "Depende do laboratório Wazuh ligado e de um ataque de teste real; pausado por pedido do utilizador nesta sessão."

## Summary

total: 4
passed: 0
issues: 0
pending: 3
skipped: 0
blocked: 1

## Gaps
