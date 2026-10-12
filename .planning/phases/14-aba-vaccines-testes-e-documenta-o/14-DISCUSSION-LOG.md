# Phase 14: Aba Vaccines, testes e documentação - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-10-12
**Phase:** 14-aba-vaccines-testes-e-documenta-o
**Areas discussed:** Entrada na sidebar, Refresh e estado do gerador, Lista e filtros, Detalhe da vaccine, Testes/docs

---

## Entrada na sidebar

| Option | Description | Selected |
|--------|-------------|----------|
| Candidates → aba real | `data-tab="vaccines"` no item Candidates; resto planeado | ✓ |
| Renomear para 'Vaccines' | Substitui Candidates, remove Approved | |
| Candidates + Approved na mesma aba | Sugere estado inexistente | |

**User's choice:** Candidates → aba real

---

## Refresh e estado do gerador

| Option | Description | Selected |
|--------|-------------|----------|
| A cada ativação + botão Atualizar | Sem polling | ✓ |
| Uma vez só | Como Attack Library | |
| Polling ~60 s | Com aba visível | |

**User's choice:** A cada ativação + botão Atualizar

| Option | Description | Selected |
|--------|-------------|----------|
| Linha de estado no topo | Última execução / erro destacado | ✓ |
| Só quando há erro | | |
| Não mostrar | | |

**User's choice:** Linha de estado no topo

---

## Lista e filtros

| Option | Description | Selected |
|--------|-------------|----------|
| Filtros no servidor + toggle | attack_id, técnica, incluir substituídas | ✓ |
| Filtros no cliente | Carrega 500 e filtra | |
| Só attack_id e substituídas | | |

**User's choice:** Filtros no servidor + toggle

| Option | Description | Selected |
|--------|-------------|----------|
| Badges + linha esbatida | | ✓ |
| Só texto | | |

**User's choice:** Badges + linha esbatida

---

## Detalhe da vaccine

| Option | Description | Selected |
|--------|-------------|----------|
| Painel com 3 blocos | Origem · Propostas · Cadeia + aviso fixo | ✓ |
| Painel simples | | |

**User's choice:** Painel com 3 blocos

| Option | Description | Selected |
|--------|-------------|----------|
| Só texto | Sem acoplar a outras abas | ✓ |
| Links para as abas | | |

**User's choice:** Só texto

---

## Testes/docs

| Option | Description | Selected |
|--------|-------------|----------|
| Testes só do contrato estático | | ✓ |
| Acrescentar verificação no browser | | |
| Decide o planner | | |

**User's choice:** Testes só do contrato estático

## Claude's Discretion

HTML/ids/classes `vac-*`, frases dos códigos de erro, formatação de datas, reconstrução do select de técnica.

## Deferred Ideas

Links para outras abas; polling; verificação no browser; Validation/Regression/estados novos.
