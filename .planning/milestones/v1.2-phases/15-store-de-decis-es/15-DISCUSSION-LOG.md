# Phase 15: Store de decisões - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-10-29
**Phase:** 15-store-de-decis-es
**Areas discussed:** Identidade do autor, Corrida com o gerador (estado de uma vaccine substituída), Ficheiros antigos sem a tabela, Regras do motivo e da decisão final

Nota de processo: as quatro questões foram feitas numa só ronda (uma por área), em vez de quatro turnos por área, para não interromper o utilizador.

---

## Identidade do autor

| Option | Description | Selected |
|--------|-------------|----------|
| Id + nome no momento | Guarda `decided_by` e `decided_by_name`; a auditoria continua legível se o analista for renomeado ou desativado; a rota valida existência e atividade | ✓ |
| Só o id | Mais simples; depois de renomear/desativar mostra só um id seco | |
| Texto livre | Sem validação contra a Equipa SOC; enfraquece a auditoria | |

**User's choice:** Id + nome no momento (recomendada)
**Notes:** Os analistas vivem em `incidents.sqlite3` e as vaccines em `vaccines.sqlite3`, por isso o store só valida o formato e a rota da Phase 16 valida a existência.

---

## Estado de uma vaccine aprovada e depois substituída

| Option | Description | Selected |
|--------|-------------|----------|
| approved + superseded_by | Estado derivado continua o que o analista decidiu; a substituição aparece à parte em `superseded_by`; a decisão nunca se reescreve | ✓ |
| Estado 'superseded' prevalece | A leitura troca `approved` por `superseded`; esconde a decisão e mistura dois conceitos num campo | |

**User's choice:** approved + superseded_by (recomendada)
**Notes:** A corrida com o gerador resolve-se com verificação e escrita na mesma transação (`BEGIN IMMEDIATE`); decidida pelo Claude como consequência técnica, sem pergunta separada.

---

## Ficheiro antigo sem a tabela

| Option | Description | Selected |
|--------|-------------|----------|
| Sem tabela = sem decisões | Leitura só-leitura trata a tabela em falta como "sem decisões"; a tabela nasce na primeira escrita; sem migração | ✓ |
| Migrar no arranque | O backend cria a tabela ao arrancar; passa a haver escrita no arranque, contra a regra "o GET nunca escreve" | |

**User's choice:** Sem tabela = sem decisões (recomendada)
**Notes:** —

---

## Regras do motivo e da decisão final

| Option | Description | Selected |
|--------|-------------|----------|
| Rejeitar obriga, aprovar opcional | Rejeitar exige motivo, aprovar aceita vazio; máx. 500 caracteres, texto simples; `UNIQUE(vaccine_id)` e triggers impõem "final" na base de dados | ✓ |
| Obrigatório nas duas | Mais rasto, mas uma justificação por cada aprovação | |
| Sempre opcional | Mínimo de atrito, mas rejeições sem explicação | |

**User's choice:** Rejeitar obriga, aprovar opcional (recomendada)
**Notes:** —

---

## Claude's Discretion

- Nomes exatos dos códigos de erro estáveis e das exceções (conjunto fechado, distinto por causa).
- Se o filtro por estado no SQL entra nesta fase ou na Phase 16.
- Regex exata do id e do nome do autor; índice em `decided_at`.

## Deferred Ideas

- Reverter/reabrir uma decisão (VLB-V2-03).
- Papéis por tier (VLB-V2-02).
- Dry-run da regra proposta (VLB-V2-01 / R13).
- Truncagem de alertas por ataque em vez de por lote (dívida do R11).
