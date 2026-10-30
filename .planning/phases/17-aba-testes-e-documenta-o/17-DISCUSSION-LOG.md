# Phase 17: Aba, testes e documentação - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-10-30
**Phase:** 17-Aba, testes e documentação
**Areas discussed:** Escolha do analista, Fluxo Aprovar/Rejeitar, Estado na tabela e KPIs, Erros/409/refresco

---

## Escolha do analista

| Option | Description | Selected |
|--------|-------------|----------|
| Dropdown, sem pré-seleção | Começa em "Escolher…"; botões desativados até haver escolha | ✓ |
| Dropdown, lembra a última escolha na sessão | Só em memória JS | |
| Dropdown pré-selecionado no 1.º analista | Menos cliques, risco de decidir como outra pessoa | |

**User's choice:** Dropdown sem pré-seleção.

| Option | Description | Selected |
|--------|-------------|----------|
| Secção "Decisão" no detalhe | Analista + motivo + botões num bloco | ✓ |
| Global no topo da aba | Um seletor único para a sessão | |

**User's choice:** Secção Decisão no detalhe.

| Option | Description | Selected |
|--------|-------------|----------|
| Bloco Decisão desativado com frase | Mostra o motivo no lugar dos botões | ✓ |
| Esconde o bloco Decisão | Mais limpo, opaco | |

**User's choice:** Bloco desativado com frase.

---

## Fluxo Aprovar/Rejeitar

| Option | Description | Selected |
|--------|-------------|----------|
| Textarea sempre visível, obrigatório só ao rejeitar | Espelha o backend | ✓ |
| Textarea só ao clicar Rejeitar | Mais limpo, mais estado | |

**User's choice:** Textarea sempre visível.

| Option | Description | Selected |
|--------|-------------|----------|
| Sem diálogo, aviso fixo "decisão final" | Botões desativam durante o pedido | ✓ |
| Confirmação em dois passos | Mais estado | |
| Modal de confirmação | Mais pesado | |

**User's choice:** Sem diálogo, aviso fixo.

| Option | Description | Selected |
|--------|-------------|----------|
| Só leitura: autor, data, motivo; sem botões | Substituída → frase | ✓ |
| Botões visíveis mas desativados | Mais ruído | |

**User's choice:** Só leitura, sem botões.

---

## Estado na tabela e KPIs

| Option | Description | Selected |
|--------|-------------|----------|
| Badge por estado | Classe `vac-state-*`, tokens, nunca só cor | ✓ |
| Só texto | Rótulos alargados | |

**User's choice:** Badge por estado.

| Option | Description | Selected |
|--------|-------------|----------|
| Select de estado + 3 contadores | `state_counts`, None → "—" | ✓ |
| Só o select | state_counts por usar | |
| Contadores clicáveis | Novo padrão de interação | |

**User's choice:** Select + 3 contadores.

| Option | Description | Selected |
|--------|-------------|----------|
| Reescrever textos fixos | "aprovada = aceite pelo analista, não aplicada" | ✓ |
| Manter só o aviso do detalhe | Aviso fica errado em aprovadas | |

**User's choice:** Reescrever.

---

## Erros, 409 e refresco

| Option | Description | Selected |
|--------|-------------|----------|
| Frase + recarrega detalhe e lista | Cumpre critério 2 | ✓ |
| Só recarrega o detalhe | Lista desatualizada | |

**User's choice:** Frase + recarrega detalhe e lista.

| Option | Description | Selected |
|--------|-------------|----------|
| Usa a vaccine da resposta + recarrega a lista | Sem GET extra | ✓ |
| GET ao detalhe a seguir | Redundante | |

**User's choice:** Vaccine da resposta + recarrega a lista.

| Option | Description | Selected |
|--------|-------------|----------|
| Valida antes de enviar + frase para cada código | Texto do servidor nunca no DOM | ✓ |
| Só deixa o servidor validar | Menos código | |

**User's choice:** Validação local + frase por código.

---

## Claude's Discretion

- Nomes de ids/classes, estrutura do bloco Decisão, divisão pure/DOM, textos exatos PT-PT, divisão em planos, docs e `ALLOWED_FILES`.

## Deferred Ideas

- Contadores clicáveis; lembrar analista; confirmação em dois passos/modal; evento WebSocket; reverter, papéis por tier, dry-run, aplicar no Wazuh.
