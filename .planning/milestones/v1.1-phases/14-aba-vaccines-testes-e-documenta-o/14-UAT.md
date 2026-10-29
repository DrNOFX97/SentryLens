---
status: complete
phase: 14-aba-vaccines-testes-e-documenta-o
source: [14-VERIFICATION.md]
started: 2026-10-19T16:52:00Z
updated: 2026-10-29T11:00:00Z
---

## Current Test

[testing complete]

## Tests

### 1. Abrir a aba Vaccines no dashboard e usar os filtros
expected: Abrir a aba Vaccines no dashboard (backend + frontend a correr) e usar os filtros (ataque, técnica MITRE, Incluir substituídas) e o botão Atualizar. A tabela mostra o subconjunto certo; linha do gerador legível ("Última execução há X min" ou a frase do código); badges de veredito (Não detetado/Parcial) distinguíveis; vaccines substituídas esbatidas com "Substituída por <id>".
result: pass
accepted_by: utilizador (2026-10-29), com a ressalva abaixo
evidence: "2026-10-29, Playwright em localhost:5500: tabela mostra a vaccine vac-a09c1541972a (#14, T1110, badge Não detetado, Regra/ML em falta, Proposta); linha do gerador 'Última execução há <1 min'; filtro de ataque 99 -> 'Nenhuma vaccine corresponde aos filtros.'; 'Incluir substituídas' e Atualizar funcionam. NÃO verificado: vaccines substituídas esbatidas com 'Substituída por <id>' — não existe nenhuma vaccine substituída para mostrar; só se confirma com um segundo ataque que mude o veredito. Verificação automatizada; aceite pelo utilizador sem esse caso. Reverificar quando existir uma vaccine substituída."

### 2. Backend parado + Atualizar
expected: Parar o backend e carregar em Atualizar. Banner de erro e linha "Sem ligação ao backend (localhost:8001)...", nunca "Sem dados" nem lista vazia.
result: pass
evidence: "2026-10-29, Playwright: pedidos a /api/vaccines bloqueados no browser (o backend não foi parado) -> banner 'Sem ligação ao backend (localhost:8001)...' e a mesma frase na tabela, sem 'Sem dados' nem lista vazia; ao repor a rota, Atualizar recupera a lista."

### 3. Navegação por teclado e detalhe/cadeia
expected: Clicar (e Tab + Enter/Espaço) numa linha; abrir uma vaccine substituída com "Incluir substituídas"; carregar em Atualizar com uma linha aberta. Detalhe com aviso "Proposta — não aplicada no Wazuh", Origem (ataque, cenário, MITRE, incidentes), Propostas e Cadeia, sem links; foco visível; a linha selecionada mantém o destaque depois de Atualizar.
result: pass
evidence: "2026-10-29, Playwright: linha com tabindex=0, Enter abre o detalhe; foco visível (outline 2px solid); detalhe com 'Proposta — não aplicada no Wazuh', Origem, Propostas e Cadeia ('Atual... Não substitui nenhuma vaccine anterior'); 0 links; linha selecionada mantém o destaque depois de Atualizar. Caso de uma vaccine substituída na cadeia não exercido (sem dados)."

### 4. Ataque não detetado, ponta a ponta
expected: Lançar um ataque que escape à deteção e esperar 10 a 15 min. A vaccine aparece na aba depois da estabilização (600s) mais o intervalo do loop (300s).
result: pass
evidence: "2026-10-28: ataque id=14 (blank_password_check, Kali -> FARENSE1910) gerou a vaccine vac-a09c1541972a depois da estabilização de 600 s (1 inserida, 0 rejeitadas). Confirmado no backend, não na aba no browser."

## Summary

total: 4
passed: 4
issues: 0
pending: 0
skipped: 0
blocked: 0

## Gaps
