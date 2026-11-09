# Phase 18: Técnica e tática por alerta - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-11-09
**Phase:** 18-técnica-e-tática-por-alerta
**Areas discussed:** Política de mapeamento, Sub-técnicas e multi-tática, Conflito com cenários, Técnicas fora da tabela

---

## Política de mapeamento

| Option | Description | Selected |
|--------|-------------|----------|
| Só inequívocos | 4625, 4698, 4720, 4728/4732/4756, 4719, 4726; ambíguos vazios | ✓ |
| Amplo | Também 4624→T1078, 4672→T1078.002, 4688→T1059… | |
| Mínimo do plano | Só 4625 e 4698 | |

| Option | Description | Selected |
|--------|-------------|----------|
| Não, só CRITICAL_EVENTS | Defender fica sem technique_id | ✓ |
| Só o inequívoco | 5001/5007-tampering→T1562.001 | |

| Option | Description | Selected |
|--------|-------------|----------|
| Comentário com o porquê | Justificação por entrada + teste que fixa a lista | ✓ |
| Tu decides | Claude escolhe; revisão no PR | |

**User's choice:** inequívocos, só CRITICAL_EVENTS, comentário + teste.

---

## Sub-técnicas e multi-tática

| Option | Description | Selected |
|--------|-------------|----------|
| Guardar exata + pai derivado | Sub-técnica tal como veio; tática herdada do pai; ataque↔alerta casam pelo pai | ✓ |
| Cada sub-técnica independente | Entrada e célula próprias | |
| Colapsar para o pai | Perde .005 | |

| Option | Description | Selected |
|--------|-------------|----------|
| Lista completa do MITRE | Todas as táticas Enterprise | ✓ |
| Uma tática principal | Matriz mais limpa, perde ligações | |

| Option | Description | Selected |
|--------|-------------|----------|
| A primeira da ordem do Wazuh | Determinístico | ✓ |
| A mais específica | Precisa de desempate | |

---

## Conflito com cenários

| Option | Description | Selected |
|--------|-------------|----------|
| A tabela manda + teste de coerência | Corrigir o cenário T1053; teste falha em divergências | ✓ |
| A tabela manda, cenário fica | Divergência escondida | |
| O cenário prevalece nos ataques | Duas verdades | |

| Option | Description | Selected |
|--------|-------------|----------|
| Não, nunca reescrever | Tática recalculada pela técnica | ✓ |
| Migrar com backup | Reescrever linhas antigas | |

---

## Técnicas fora da tabela

| Option | Description | Selected |
|--------|-------------|----------|
| Nenhuma → 'sem tática' | rule.mitre.tactic não é fiável por técnica | ✓ |
| Usar rule.mitre.tactic se houver 1 técnica | | |

| Option | Description | Selected |
|--------|-------------|----------|
| Teste sobre o snapshot R9 | Técnicas observadas exigidas na tabela | ✓ |
| Também aviso em runtime | stderr uma vez por técnica | |

| Option | Description | Selected |
|--------|-------------|----------|
| YAML + loader fail-fast | `scripts/mitre_techniques.yaml`, padrão attack_library | ✓ |
| Dict Python no código | Sem validação no arranque | |

**Notes:** Claude ajustou a implementação do teste do snapshot: como `scripts/snapshots/` está no `.gitignore` (falha em worktrees), a lista de técnicas observadas fica escrita no teste, com a origem documentada.

---

## Claude's Discretion

- Nome/local do módulo do resolvedor e assinatura exata.
- `technique_source` quando não há técnica (`None` recomendado).
- Mostrar a técnica no `log_analyzer.py` (só aditivo, não requisito).

## Deferred Ideas

- `technique_id` no `DEFENDER_EVENTS`.
- Aviso em runtime para técnicas fora da tabela.
- Matriz MITRE completa.
