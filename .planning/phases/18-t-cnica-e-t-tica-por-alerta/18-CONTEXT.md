# Phase 18: Técnica e tática por alerta - Context

**Gathered:** 2026-11-09
**Status:** Ready for planning

<domain>
## Phase Boundary

Para qualquer alerta cru do Wazuh, o backend devolve as técnicas MITRE ATT&CK que lhe correspondem, a origem de cada uma (`wazuh` | `catalog`) e as táticas, sem inventar técnicas e sem mudar o comportamento de `classify_alert()` nem do `log_analyzer.py` (Fase 1). Entrega: `technique_id` no `CRITICAL_EVENTS`, tabela técnica→tática versionada com validação fail-fast, resolvedor puro, e campos aditivos no `DetectionEvent` de regra (visíveis em `GET /api/detections`).

Fora desta fase: a rota `GET /api/mitre/coverage` (Fase 19), a matriz no dashboard (Fase 20), Caldera, PostgreSQL, auth, casos.

Requisitos: MITRE-01, MITRE-02, MITRE-03, MITRE-04.

</domain>

<decisions>
## Implementation Decisions

### Já decididos no marco (não reabrir)
- **D-00a:** Precedência: `rule.mitre.id` do alerta primeiro (origem `wazuh`), `technique_id` do catálogo pelo Event ID como fallback (origem `catalog`), lista vazia quando nenhum existe. O catálogo **substitui-se** pelo Wazuh, não se une.
- **D-00b:** `DetectionEvent` ganha campos de forma aditiva (`techniques`, `technique_source`); `technique` continua `str | None`. Nenhum campo existente de `/api/detections` muda.
- **D-00c:** Estado próprio em ficheiros versionados/SQLite; sem PostgreSQL, sem tabela de técnicas em base de dados.

### Política de mapeamento do catálogo
- **D-01:** Só mapeamentos inequívocos (o próprio evento é a técnica) no `CRITICAL_EVENTS`: 4625→T1110, 4698→T1053.005, 4720→T1136.001, 4728/4732/4756→T1098, 4719→T1562.002, 4726→T1531. Eventos de atividade normal ou ambígua (4624, 4672, 4688, 5140, …) ficam **sem** `technique_id`. O planner pode rever os restantes ids do catálogo com o mesmo critério, mas na dúvida fica vazio.
- **D-02:** `DEFENDER_EVENTS` (1116–5008) **não** ganha `technique_id` nesta fase.
- **D-03:** Cada `technique_id` leva um comentário curto com a justificação no próprio `event_catalog.py`, e um teste fixa a lista exata de mapeamentos (adicionar/remover um exige mudar o teste conscientemente).

### Sub-técnicas e multi-tática
- **D-04:** O resolvedor devolve a técnica **exatamente** como veio (ex.: `T1053.005`). A tabela pode ter só o pai (`T1053`): uma sub-técnica sem entrada própria herda as táticas do pai. Para cruzar ataques com alertas, sub-técnica e pai casam pelo pai (ataque `T1110` ↔ alerta `T1110.003`); expor um helper puro para "pai de" para a Fase 19 usar.
- **D-05:** A tabela guarda a **lista completa** de táticas Enterprise de cada técnica (ex.: T1078 → Defense Evasion, Persistence, Privilege Escalation, Initial Access). Nada de "tática principal".
- **D-06:** `DetectionEvent.technique` (singular) = a **primeira** técnica na ordem em que o Wazuh a enviou (ou a do catálogo); a lista completa vai em `techniques`.

### Conflito com os cenários de ataque
- **D-07:** A tática vem **sempre** da tabela. Corrigir o `mitre_tactic` de `attack_scenarios.py` para uma tática Enterprise válida da técnica (T1053 hoje está como "Lateral Movement", que não é tática de T1053). Um teste de coerência falha se algum cenário declarar uma tática que a tabela não lista para a sua técnica (ou para o pai dela). — **Reversibility:** reversible
- **D-08:** O `attack_log.jsonl` histórico **nunca** é reescrito; a tática de um ataque é recalculada a partir da tabela pela técnica.

### Técnicas fora da tabela
- **D-09:** Uma técnica vinda do Wazuh que não está na tabela (nem o pai) mantém-se na lista com `tactics: []`; **não** se usa `rule.mitre.tactic` (as listas `id[]`/`tactic[]` não vêm emparelhadas). A Fase 19 põe estas técnicas na secção "sem tática".
- **D-10:** A completude da tabela é garantida por um teste que exige todas as técnicas já observadas em `rule.mitre` no lab: T1078, T1021, T1550.002, T1078.002, T1484, T1531 (origem: `scripts/snapshots/raw_events_r9_ciclo1.json` e `real_events_2026-09-14.json`). A lista vai **escrita no teste** — `scripts/snapshots/` está no `.gitignore` e o teste tem de passar em worktrees. Sem aviso em runtime.
- **D-11:** Formato: `scripts/mitre_techniques.yaml` (id, nome, táticas) com loader e cache em memória ao estilo de `attack_library.py`, validado de forma síncrona e fail-fast a nível de módulo em `main.py` (id fora de `^T\d{4}(\.\d{3})?$`, tática fora das 14 táticas Enterprise, id duplicado ou campo em falta → o backend não arranca). Também cobre as técnicas dos cenários e do catálogo (o loader/teste falha se alguma faltar). — **Reversibility:** reversible

### Claude's Discretion
- Nome e localização do módulo do resolvedor (ex.: `mitre_catalog.py` puro, ou funções em `event_catalog.py`), assinatura exata e nome do campo de origem por técnica.
- Forma exata de `technique_source` quando não há técnica (`None` recomendado — nunca uma string inventada).
- Se o `log_analyzer.py` passa a mostrar a técnica (só se for aditivo e sem mudar o output existente — não é requisito).

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Âmbito e requisitos
- `.planning/REQUIREMENTS.md` — MITRE-01..04 (e contexto de API-01/02 da Fase 19, que consome o resolvedor)
- `.planning/ROADMAP.md` §Phase 18 — critérios de sucesso
- `.planning/PROJECT.md` — Constraints e Key Decisions (técnica: `rule.mitre` primeiro)
- `docs/plans/2026-11-09-arquitetura-fases-10-19.md` §Fase 10 — plano externo de origem (só a parte MITRE foi importada)

### Código a seguir como padrão
- `scripts/attack_library.py` + `scripts/attack_library.yaml` — padrão de YAML versionado com loader/cache e validação fail-fast chamada a nível de módulo em `main.py`
- `scripts/event_catalog.py` — `CRITICAL_EVENTS`, `classify_alert()`, `DEFENDER_EVENTS` (não tocar no comportamento)
- `scripts/detection_event.py` — `DetectionEvent`, `_make()`, `from_rule_alert()` (linha 56; hoje `technique` sempre `None`)
- `scripts/attack_scenarios.py` linhas ~150-230 — `mitre_tactic`/`mitre_technique` por cenário (T1053 com tática errada)
- `docs/DATA_MODEL.md` — definições do `DetectionEvent` (atualizar na Fase 20, DOC-01)
- `CLAUDE.md` — testes standalone (sem pytest), `SENTRYLENS_API_KEY` antes de `import main`, worktrees sem `scripts/snapshots/`

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `attack_library.load_attack_library()` / `reset_cache()` / `validate_entry()`: modelo direto para `load_mitre_techniques()` com cache e validação.
- `classify_wazuh_alert(raw)` (usado em `from_rule_alert`): já extrai o Event ID do alerta; o resolvedor deve reaproveitar a mesma extração em vez de duplicar.
- `scripts/snapshots/raw_events_r9_ciclo1.json` (664/1000 alertas com `rule.mitre`): útil para verificar manualmente, nunca como dependência de teste.

### Established Patterns
- Módulos de domínio puros (sem I/O) + teste standalone `test_*.py` que imprime `[OK]`/`[FALHOU]` e sai com `sys.exit(1)`.
- Validação fail-fast a nível de módulo em `main.py` (um YAML inválido impede o arranque).
- Contratos de API aditivos; "Sem dados"/`None`, nunca valores inventados.

### Integration Points
- `detection_event.from_rule_alert()` → preencher `technique`/`techniques`/`technique_source`.
- `main.py` → validar `mitre_techniques.yaml` no arranque.
- `incident_engine.py:206` já usa `entry.get("technique") or scenario.mitre_technique` — verificar que continua coerente.
- Fase 19 vai consumir o resolvedor, a tabela e o helper "pai de".

</code_context>

<specifics>
## Specific Ideas

- `rule.mitre` real: `{"id": ["T1078","T1021"], "tactic": ["Defense Evasion","Persistence","Privilege Escalation","Initial Access","Lateral Movement"]}` — listas independentes.
- Exemplos do plano: 4625→T1110 (força bruta), 4698→T1053.005 (tarefa agendada).

</specifics>

<deferred>
## Deferred Ideas

- `technique_id` para `DEFENDER_EVENTS` (ex.: 5001/5007-tampering→T1562.001) — fase futura.
- Aviso em runtime quando o Wazuh envia uma técnica fora da tabela — rejeitado por agora; reconsiderar se a secção "sem tática" ficar grande.
- Matriz MITRE completa (todas as técnicas Enterprise) — fora do âmbito do v1.3.

</deferred>

---

*Phase: 18-tecnica-e-tatica-por-alerta*
*Context gathered: 2026-11-09*
