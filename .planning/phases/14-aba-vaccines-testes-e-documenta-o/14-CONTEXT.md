# Phase 14: Aba Vaccines, testes e documentação - Context

**Gathered:** 2026-10-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Entregar a aba real "Vaccines" no dashboard (`vaccines.js`, sem editar `app.js`, servido por `serve_frontend.py`), que lista as vaccines propostas com filtros e abre um detalhe com a regra proposta e a origem; e fechar o marco R11 com a suite completa verde e a documentação atualizada (`DATA_MODEL.md`, `ROADMAP_STATUS.md`, `README.md`, `CLAUDE.md`). Só leitura: nenhuma ação de escrita, nenhuma regra aplicada no Wazuh (R12+). Requisitos: VAC-07, VAC-08.

</domain>

<decisions>
## Implementation Decisions

### Entrada na sidebar
- **D-01:** O item "Candidates" (R11) do grupo Vaccines passa a `data-tab="vaccines"` (sem `is-planned`/badge R11). "Validation" (R12), "Approved" e "Regression" (R14) ficam como planeados — nada está aprovado, todas as vaccines são `proposed`.

### Refresh e estado do gerador
- **D-02:** A aba carrega a cada ativação (aba visível e separador visível) e tem um botão "Atualizar". Sem polling, sem WebSocket. Pedidos concorrentes são ignorados (guarda `loading`), como nas outras abas.
- **D-03:** Uma linha de estado no topo mostra o `generator` devolvido por `GET /api/vaccines`: "última execução há X min"; se o último ciclo falhou, a frase do código de erro estável, destacada. O texto do erro nunca vem de exceção.

### Lista e filtros
- **D-04:** Filtros enviados à API (servidor): campo `attack_id`, select de técnica MITRE (preenchido a partir das vaccines carregadas) e checkbox "Incluir substituídas" (`include_superseded`). Colunas: id, ataque, cenário, técnica, veredito, sensores em falta, estado, criada.
- **D-05:** Veredito como badge (Não detetado / Parcial), no estilo dos badges de risco da Attack Library. Vaccine substituída aparece esbatida com "Substituída por <id>".

### Detalhe da vaccine
- **D-06:** Painel por baixo da tabela (padrão Attack Library, linha clicável/teclável) com 3 blocos: **Origem** (ataque, cenário, MITRE, incidentes, evidência por referência), **Propostas** por sensor em falta (regra `event_ids`/`min_count`/`window_seconds`, eventos com nome e severidade, recomendação) e **Cadeia** (substituída por / substitui). Aviso fixo "Proposta — não aplicada no Wazuh".
- **D-07:** Incidentes e ataque de origem são só texto (sem links para outras abas), para não acoplar `vaccines.js` a `incidents.js`/`attack_registry.js`.

### Estados e erros (herdados dos critérios de sucesso)
- **D-08:** Sem amostra (`reason: no_data`) mostra "Sem dados". 401/404/502/503 desenham-se como erro com a frase do código — nunca como "Sem dados" nem lista vazia. Filtro sem resultados com store não vazio é uma lista vazia distinta de "Sem dados" (Fase 13, D-09).

### Testes e documentação (VAC-08)
- **D-09:** Teste standalone do contrato estático (HTML/JS servidos, whitelist do `serve_frontend.py`, ids esperados, `app.js` não editado, `escapeHtml` no texto dinâmico) registado em `run_all_tests.py`; sem browser automatizado. Garantias negativas já cobertas nas Fases 12–13 mantêm-se e entram na verificação final; `python run_all_tests.py` verde sem Wazuh.
- **D-10:** Documentação: entidade Vaccine em `docs/DATA_MODEL.md`, R11 ✅ em `docs/ROADMAP_STATUS.md`, e motor/store/rota/aba em `README.md` e `CLAUDE.md` (editar, nunca regenerar o `CLAUDE.md`).

### Claude's Discretion
- Estrutura exata do HTML da aba, nomes de ids/classes CSS (prefixo `vac-`), e o texto das frases dos códigos de erro.
- Formatação de datas/"há X min" e ordem das colunas dentro do que D-04 fixa.
- Se o select de técnica se reconstrói a cada resposta ou só na primeira.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requisitos e fases anteriores
- `.planning/ROADMAP.md` — Phase 14, critérios de sucesso 1–4
- `.planning/REQUIREMENTS.md` — VAC-07, VAC-08 e Out of Scope
- `.planning/phases/13-store-e-api-de-leitura/13-CONTEXT.md` — forma da API (D-08..D-10), `superseded_by`, `reason`, 503/404 estáveis
- `.planning/phases/12-motor-de-vaccines/12-CONTEXT.md` — contrato da vaccine (`proposals[]`, origem, id determinístico)

### Código a reutilizar
- `attack_library.js` — padrão da aba (MutationObserver de ativação, `alibRequest`, `renderPanelError`, painel de detalhe, `escapeHtml`)
- `index.html` — sidebar (grupo Vaccines, ~linha 94), `tab-attack-library` (~linha 1302) como modelo de markup, ordem dos `<script>` (~linha 1665)
- `style.css` — classes `alib-*`/`atk-row` como modelo
- `scripts/serve_frontend.py` — whitelist fixa (acrescentar `/vaccines.js`)
- `scripts/main.py` — `GET /api/vaccines` e `GET /api/vaccines/{id}` (linhas ~1940–1985)
- `scripts/vaccine_engine.py` — `VACCINE_KEYS`, `ORIGIN_KEYS`, `PROPOSAL_KEYS`, `RULE_KEYS`, `EVENT_KEYS`
- `scripts/vaccine_ingest.py` — `snapshot()` do estado do gerador
- `scripts/run_all_tests.py` — registo do teste novo
- `docs/DATA_MODEL.md`, `docs/ROADMAP_STATUS.md`, `README.md`, `CLAUDE.md` — a atualizar

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- Globais de `app.js` (`API_BASE`, `API_KEY`, `escapeHtml`, `renderPanelError`): reutilizar, nunca redeclarar.
- `attack_library.js`: estrutura de pedido com erro como `detail` estável, seleção de linha com `selectSeq` anti-corrida.

### Established Patterns
- Uma aba por ficheiro JS carregado depois de `app.js`, ativada por `MutationObserver` na classe `active` + `visibilitychange`.
- Todo o texto dinâmico via `escapeHtml`; sem dados -> "Sem dados".
- Testes standalone sem pytest; contrato estático verificado sobre os ficheiros servidos.

### Integration Points
- `index.html`: item da sidebar, `<div class="tab-content" id="tab-vaccines">` e `<script src="vaccines.js">`.
- `serve_frontend.py`: nova entrada na whitelist.
- `style.css`: classes `vac-*` (badges de veredito, linha esbatida).

</code_context>

<specifics>
## Specific Ideas

- Aviso fixo no detalhe: "Proposta — não aplicada no Wazuh".
- Badges de veredito no estilo dos badges de risco da Attack Library.

</specifics>

<deferred>
## Deferred Ideas

- Links do detalhe para as abas de incidentes/ataques — decidido só texto; reavaliar mais tarde.
- Polling/refresh automático da aba — não nesta fase.
- Verificação no browser com screenshots — recusada; só contrato estático.
- Validation (R12), estados `resolved`/`stale`, aplicar regras no Wazuh, Regression (R14) — fases futuras.

</deferred>

---

*Phase: 14-Aba Vaccines, testes e documentação*
*Context gathered: 2026-10-12*
