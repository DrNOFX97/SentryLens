# Phase 16: API de decisão - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-10-29
**Phase:** 16-api-de-decisao
**Areas discussed:** Corpo e identidade, Erros 422 estáveis, Leitura e filtro, Garantias e limites

---

## Corpo e identidade

| Option | Description | Selected |
|--------|-------------|----------|
| Vaccine completa + notice | Relê get_vaccine; poupa um GET ao frontend | ✓ |
| Só o registo + notice | Dict de decide_vaccine; a F17 faz GET extra | |
| analyst_id no corpo | Validado com get_analyst; autoria autodeclarada | ✓ |
| Header X-Analyst-Id | Padrão novo, CORS teria de listar o header | |
| Lista GET /api/soc/analysts | Como incidents.js | ✓ |
| localStorage | Estado por viewer, pode ficar obsoleto | |

**User's choice:** Todas as recomendadas.
**Notes:** Autoria documentada como não autenticada (só existe uma API key).

---

## Erros 422 estáveis

| Option | Description | Selected |
|--------|-------------|----------|
| Validação à mão, códigos da F15 | detail sempre string | ✓ |
| Pydantic + handler só desta rota | Idiomático, mas detail em lista por omissão | |
| 422 analyst_not_found / analyst_inactive | Erro no corpo; 404 reservado à vaccine | ✓ |
| 404 / 403 | Mistura com o 404 da vaccine | |
| Aceitar e documentar apóstrofo | Charset da F15 fica fechado | ✓ |
| Relaxar o regex na F15 | Reabre código fechado | |
| 503 incidents_unavailable | Código próprio | ✓ |
| 500 genérico via _incidents_call | Perde o código estável | |

**User's choice:** Todas as recomendadas.
**Notes:** D-F do rascunho estava parcialmente resolvido na F15 (regex Unicode sem apóstrofo).

---

## Leitura e filtro

| Option | Description | Selected |
|--------|-------------|----------|
| Contagens por estado na F16 | None sem amostra, nunca 0 | ✓ |
| A F17 conta no frontend | Limitado à página carregada | |
| ?state= desconhecido = 422 | Como technique | ✓ |
| ?state= desconhecido = lista vazia | Esconde erros | |
| Contagens do universo atual, sem filtros | KPI estável | ✓ |
| Contagens respeitam filtros | KPI muda ao filtrar | |
| Substituídas: regra da F15, sem extra | superseded_by já assinala | ✓ |
| Flag explícita no envelope | Superfície nova | |

**User's choice:** Todas as recomendadas.

---

## Garantias e limites

| Option | Description | Selected |
|--------|-------------|----------|
| 409 already_decided sem exceção | VLB-02 literal | ✓ |
| 200 idempotente se igual | Exceção à regra de decisão final | |
| Só limites de campo + teto de corpo | Sem rate limit | ✓ |
| Sem limite extra | Corpo gigante lido antes de recusar | |
| Sem WebSocket nem JSONL | Uma só fonte de verdade | ✓ |
| Só evento WebSocket | Canal novo | |
| Varrimento AST de main.py + vaccine_*.py | Apanha chamadas escondidas | ✓ |
| Só rotas e texto | Não apanha módulos | |

**User's choice:** Todas as recomendadas.

---

## Claude's Discretion

- Valor do teto do corpo e status ao excedê-lo; nome do campo das contagens e do método de leitura; texto exato do `notice`; divisão em planos/waves.

## Deferred Ideas

- Botões/UI e documentação (Phase 17); reverter decisões, papéis por tier, dry-run (v2); evento WebSocket e cópia no JSONL; aplicar no Wazuh (R21).
