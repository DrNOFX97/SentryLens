# Phase 12: Motor de vaccines - Context

**Gathered:** 2026-10-11
**Status:** Ready for planning

<domain>
## Phase Boundary

Motor puro (sem I/O, sem HTTP, sem store) que, a partir do relatório do Attack Registry / Red vs Blue, decide que ataques geram uma *vaccine* (regra de deteção proposta), que regra se propõe e de onde vem, com id determinístico. Sem amostra ou fonte indisponível devolve "Sem dados" ou um código estável. Store e API são a Phase 13; aba é a Phase 14.

</domain>

<decisions>
## Implementation Decisions

### Ataque partial
- **D-01:** Um ataque `partial` gera uma vaccine só para o(s) sensor(es) em falta: `missing_sensors = expected − achieved`. A vaccine guarda também `achieved` para contexto. Um `not_detected` tem `missing_sensors` = todos os esperados.

### Identidade e id
- **D-02:** Um candidato por ataque (`not_detected`/`partial`); `detected` e `unknown` (incluindo `unknown` por `alerts_truncated`) nunca geram.
- **D-03:** O id é um hash determinístico de `attack_id` + conjunto ordenado de `missing_sensors`. Reprocessar os mesmos ataques dá os mesmos ids. Se o veredito evoluir (partial → not_detected) o id muda de propósito, porque o conjunto em falta mudou. — **Reversibility:** costly — o id é a chave do store (Phase 13) e da rota `/api/vaccines/{id}`; mudar a fórmula depois exige migração.
- **D-04:** Ataques sem `attack_id` válido ou com `duplicate_id` são saltados (sem origem rastreável, VAC-03) e contados; o motor devolve `skipped` com contadores (ex.: `no_attack_id`, `duplicate_id`) em vez de os esconder.

### Regra proposta
- **D-05:** A janela vem de `redblue_correlator.DEFAULT_WINDOW_SECONDS` (300 s), a mesma usada na correlação que mediu o gap. Sem campo novo no `attack_library.yaml`.
- **D-06:** A condição é estruturada e de chaves fechadas: `{event_ids, min_count, window_seconds}`, com `min_count = 1` por omissão (a evidência só tem `matched_alert_count`, sem base para limiares inventados). `event_ids` vêm de `attack_scenarios.SCENARIOS` (ligados a `event_catalog`). Nenhum campo contém comando executável.
- **D-07:** Cada vaccine tem `sensor` ∈ {rule, ml, network}. Para `ml`/`network` a regra de `event_ids` não se aplica: `rule: null` e uma `recommendation` em texto (português, sem comandos). Nada é inventado nem perdido.

### Claude's Discretion
- Algoritmo do hash (ex.: sha256 truncado) e nomes exatos dos campos fora dos acima.
- Forma exata do "Sem dados" / código estável (seguir o padrão `source_unavailable` de `soc_metrics.py`).
- Texto das `recommendation` para ml/network.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requisitos e roadmap
- `.planning/ROADMAP.md` — Phase 12, critérios de sucesso 1–4
- `.planning/REQUIREMENTS.md` — VAC-01..04 e Out of Scope (sem aplicar no Wazuh, sem comandos)
- `.planning/STATE.md` — blockers resolvidos por este contexto (regra para partial)

### Código a reutilizar
- `scripts/attack_registry.py` — `build_attack_registry`, `verdict`, `expected_detection`, `achieved_sources`, `duplicate_id`; fonte dos vereditos e da origem
- `scripts/redblue_correlator.py` — `DEFAULT_WINDOW_SECONDS`, `build_redblue_report`
- `scripts/attack_library.py` + `scripts/attack_library.yaml` — `get_expected_sensors`, catálogo só de leitura (sem comandos)
- `scripts/attack_scenarios.py` — `SCENARIOS` (event_ids, MITRE)
- `scripts/event_catalog.py` — nomes/severidade dos Event IDs
- `scripts/soc_metrics.py` — padrão de fontes isoladas e `source_unavailable`
- `docs/DATA_MODEL.md` — convenções de entidades (a Vaccine entra na Phase 14)

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `build_attack_registry()`: já entrega por ataque `actual.verdict`, `expected.detection`, `actual.achieved`, `evidence`, `incidents`, `mitre_technique`, `duplicate_id`.
- `attack_registry.summarize()`: contagens por veredito.

### Established Patterns
- Módulos `build_*` puros, testados com mocks; testes standalone sem pytest (`test_vaccine_engine.py`).
- Erros como códigos estáveis, nunca texto de exceção.
- Evidência por referência, nunca cópia de payload.

### Integration Points
- O motor consome a saída de `build_attack_registry`; a Phase 13 decide quem o chama e persiste (fora do `GET`).

</code_context>

<specifics>
## Specific Ideas

No specific requirements — open to standard approaches.

</specifics>

<deferred>
## Deferred Ideas

- Janela por cenário no `attack_library.yaml` — só se a janela única se mostrar insuficiente.
- Quem escreve no store e quando — decisão da Phase 13.

</deferred>

---

*Phase: 12-Motor de vaccines*
*Context gathered: 2026-10-11*

## Decisão posterior (plan-phase, 2026-10-11)

- **D-07 refinado (confirmado pelo utilizador):** a vaccine é uma por ataque (D-02) e traz uma lista `proposals[]`, uma entrada por sensor em falta, cada uma com `sensor`, `rule` e `recommendation`. Não há `sensor` singular no topo da vaccine.
