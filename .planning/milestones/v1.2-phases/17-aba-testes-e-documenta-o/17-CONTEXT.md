# Phase 17: Aba, testes e documentação - Context

**Gathered:** 2026-10-30
**Status:** Ready for planning

<domain>
## Phase Boundary

O analista decide no dashboard (aba Vaccines → detalhe) e o marco v1.2 fecha com a suite completa e a documentação. Cobre VLB-06 e VLB-07. **Só frontend e docs**: o backend (store F15, API F16) não muda; o contrato de erros, o corpo do `POST` e o `notice` já estão fixados. Não inclui aplicar nada no Wazuh (R21), reverter decisões (VLB-V2-03), papéis por tier (VLB-V2-02) nem tempo real por WebSocket.

</domain>

<decisions>
## Implementation Decisions

### Escolha do analista

- **D-01:** O analista escolhe-se num `<select>` com os analistas ativos de `GET /api/soc/analysts?active_only=true` (mesmo padrão de `incidents.js`), que **começa em "Escolher…" sem pré-seleção**; enquanto não houver escolha, Aprovar e Rejeitar ficam desativados. A escolha vive só no estado do detalhe (nunca `localStorage`, regra da Fase 16): ao recarregar a página volta a "Escolher…". Razão: evitar decidir "em nome de" outra pessoa por engano, já que a autoria é autodeclarada e não autenticada (F16 D-03).
- **D-02:** O seletor vive **dentro de uma secção "Decisão" no painel de detalhe** (`vaccine-detail-panel`), com analista + motivo + botões, junto ao aviso "não aplicada". A secção só tem controlos quando a vaccine é decidível (ver D-06). Não há seletor global no topo da aba.
- **D-03:** Se a lista de analistas falhar (rede, `incidents_unavailable`) ou não houver nenhum analista ativo, o bloco Decisão mostra **uma frase no lugar dos botões** (`incidents_unavailable` com a sua frase, ou "Sem analistas ativos") e o resto do detalhe funciona. Nunca se esconde o bloco nem se desenha como "sem dados".

### Fluxo Aprovar / Rejeitar

- **D-04:** O motivo é uma `<textarea>` **sempre visível** no bloco Decisão (máx 500 caracteres, contador). Rejeitar exige motivo não vazio depois de `trim` (validado antes de enviar, com frase local); Aprovar aceita vazio. Espelha a regra do backend (F15 D-12), que continua a ser a fonte de verdade.
- **D-05:** **Sem diálogo de confirmação.** Em vez disso há um aviso fixo junto aos botões: a decisão é final e aprovar não aplica nada no Wazuh. Os botões desativam durante o pedido para evitar o clique duplo (que daria 409, F16 D-08). Handlers por `data-action` + listener delegado, nunca inline.
- **D-06:** Vaccine **já decidida** (`approved`/`rejected`): o bloco Decisão fica **só de leitura** — autor (`decided_by_name`), data e motivo — sem botões. Vaccine **substituída e ainda `proposed`**: uma frase "substituída, já não pode ser decidida" sem botões (mesma regra do backend, `vaccine_superseded`). Só uma vaccine atual `proposed` mostra controlos.

### Estado na tabela, filtro e contadores

- **D-07:** A coluna Estado passa a **badge** com texto por estado (Proposta / Aprovada / Rejeitada) e classe `vac-state-*`, com cores só por tokens CSS (sem literais; `test_no_literal_colors`/`test_contrast`) e nunca só cor. `VAC_STATE_LABELS` ganha `approved` e `rejected`; um estado desconhecido aparece como veio (como `vacLabel`).
- **D-08:** Novo `<select>` "Estado" nos filtros (Todos/Proposta/Aprovada/Rejeitada) que envia `?state=` (valor fora do conjunto nunca sai do cliente; o backend dá 422 se sair). Mais uma **linha de 3 contadores** (Propostas/Aprovadas/Rejeitadas) a partir de `state_counts` do envelope (universo das vaccines atuais, não muda ao filtrar a tabela — F16 D-11). `state_counts` `None` → "—", **nunca 0**. Sem contadores clicáveis.
- **D-09:** O detalhe mostra um bloco **"Decisão"** com o estado atual e, se decidida, autor, data e motivo (texto simples, via `vacCell`, nunca HTML).
- **D-10:** **Reescrever os textos fixos** que ficam falsos com botões: o `<p class="panel-note">` do cabeçalho da aba ("Só leitura… todas em estado proposta") e o `#vac-detail-warning` ("Proposta — não aplicada no Wazuh"), que passa a depender do estado (Proposta / Aprovada / Rejeitada — **não aplicada no Wazuh**). A mensagem central é: "aprovada" = aceite pelo analista, nunca aplicada. O comentário de topo de `vaccines.js` ("Só leitura…") também é atualizado. O `index.html` mantém-se sem handlers inline.

### Erros, 409 e refresco

- **D-11:** Cada código da tabela D-05 da Fase 16 ganha **frase PT-PT acionável** em `VAC_ERROR_TEXT` (`analyst_not_found`, `analyst_inactive`, `already_decided`, `vaccine_superseded`, `invalid_body`, `invalid_author`, `reason_required`, `invalid_decision`, `invalid_reason`, `invalid_analyst_id`/códigos de `INVALID_INPUT_CODES`, `incidents_unavailable` já existe, `http_409`, `http_405`). `invalid_author` diz que o nome do analista tem caracteres fora do aceite e que é preciso corrigi-lo (F16 D-07). O texto do servidor **nunca** entra no DOM: `detail` só serve de chave de lookup. Os códigos exatos de `INVALID_INPUT_CODES` lêem-se de `scripts/vaccine_decision.py`.
- **D-12:** Validação **local antes de enviar** (sem analista escolhido, rejeitar sem motivo, motivo > 500): frase local imediata, sem pedido. O servidor continua a validar tudo.
- **D-13:** Em **409** (`already_decided` / `vaccine_superseded`): mostra a frase do código e **refaz GET do detalhe e da lista** (e contadores), para o estado real aparecer e os botões saírem. A vista nunca fica a mentir (critério 2 da fase).
- **D-14:** Em **200**: renderiza o detalhe com a `vaccine` da própria resposta (já traz `state`/`decision`), mostra o `notice` do servidor (texto de `notice` entra via `textContent`/`htmlT`, é string fixa do backend) e refaz a lista/contadores. **Sem WebSocket** e sem GET extra ao detalhe (F16 D-15). Pedidos concorrentes: respeitar o contador `vacSelectSeq` para descartar respostas fora de ordem.

### Testes e documentação (VLB-07)

- **D-15:** Testes sem Wazuh e sem browser: estende-se `test_vaccines_frontend.py` (contratos de texto: `data-action`, sem `on*=`, tokens de cor, `[hidden]`, ícones) e a lógica com decisões (estado derivado do bloco Decisão, validação local, código→frase, contadores) vai para funções puras `sl*` em `ui_helpers.js` testadas por `test_ui_helpers.cjs` em `node:vm`, como a regra do projeto manda. `run_all_tests.py` tem de terminar com código 0.
- **D-16:** Documentação com **contagens medidas**, não estimadas: `DATA_MODEL.md` (entidade decisão + estado derivado), `API.md` (`POST /api/vaccines/{id}/decision`, `?state=`, `state_counts`, códigos), `ROADMAP_STATUS.md` (R12 ✅), `README.md` (testes novos) e `CLAUDE.md` (R12, contagem de testes e nota de que a aprovação não aplica nada). Ordem e granularidade ao critério do planner; a contagem final vem de uma execução real de `run_all_tests.py`.

### Claude's Discretion

- Nomes exatos de ids/classes no HTML novo, estrutura do bloco Decisão e do contador do textarea, desde que respeitem o prefixo `vac`/`sl` e as regras de escopo global.
- Que funções vão para `ui_helpers.js` (puras) e quais ficam em `vaccines.js`.
- Textos exatos das frases PT-PT (desde que acionáveis, sem texto de exceção e sem "sem dados" num erro).
- Divisão em planos/waves e como dividir os documentos pelos planos.
- Se `serve_frontend.py` `ALLOWED_FILES` precisa de alteração (só se surgir ficheiro novo; hoje não é esperado).

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requisitos e roadmap
- `.planning/REQUIREMENTS.md` — VLB-06 e VLB-07 (esta fase); VLB-01..05 já completos
- `.planning/ROADMAP.md` § Phase 17 — critérios de sucesso 1 a 4
- `.planning/PROJECT.md` — Constraints (Segurança, Dados reais, Git sem `Co-Authored-By`)

### Contratos das fases anteriores (o que o frontend consome)
- `.planning/phases/16-api-de-decisao/16-CONTEXT.md` — corpo do POST (D-01), resposta e `notice` (D-02), autoria autodeclarada (D-03), tabela de códigos HTTP (D-05), `invalid_author` (D-07), 409 sem idempotência (D-08), `state`/`state_counts` (D-10..D-12), sem WebSocket (D-15)
- `.planning/phases/15-store-de-decis-es/15-CONTEXT.md` — regras de transição, motivo (D-12), estado derivado (D-09), decisão final
- `scripts/vaccine_decision.py` — `INVALID_INPUT_CODES`/`NOT_FOUND_CODES`/`CONFLICT_CODES` (lista exata dos códigos a que o frontend dá frase)
- `scripts/main.py` — rotas `/api/vaccines[/{id}]`, `POST /api/vaccines/{id}/decision`, `GET /api/soc/analysts`

### Frontend
- `vaccines.js` — aba atual (render da lista/detalhe, `vacRequest`, `VAC_ERROR_TEXT`, `vacSelect`, `vacSelectSeq`)
- `index.html` (secção Vaccines, ~linha 1405) — painéis `vaccines-panel` e `vaccine-detail-panel`; `#vac-detail-warning` e cabeçalho com texto "só leitura"
- `incidents.js` (~linha 251 e ~481) — padrão de seletor de analistas e de `incRequest("PATCH", …)` com estado/erro
- `api.js` (`apiRequest`, `ApiError`) — transporte com `X-API-Key`, corpo JSON e timeout
- `ui_helpers.js` + `scripts/test_ui_helpers.cjs` — funções puras `sl*` testáveis em `node:vm`
- `scripts/test_vaccines_frontend.py`, `scripts/test_frontend_static.py`, `scripts/test_no_raw_innerhtml.py`, `scripts/test_no_literal_colors.py`, `scripts/test_contrast.py`, `scripts/test_icons_a11y.py` — contratos estáticos que têm de continuar verdes
- `style.css` — tokens de cor e `.modal[hidden]`/regras de `hidden`

### Documentação a atualizar
- `docs/DATA_MODEL.md`, `docs/API.md`, `docs/ROADMAP_STATUS.md`, `README.md`, `CLAUDE.md` — descrevem o R12 com contagens medidas (critério 4)

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `vacRequest(path)` → `apiRequest`, com `vacCodeFromApiError` (a mensagem do erro é sempre um código estável). Falta aceitar método/corpo para o `POST` (o `apiRequest` já suporta `method`/`body`).
- `htmlT`/`htmRender` (escape por omissão), `vacCell`, `vacLabel`, `renderPanelError`, `sttShowLoading`/`sttShowError`.
- `VAC_ERROR_TEXT` + `vacErrorText(code)`: lookup fechado por chave; só estender.
- `incidents.js`: padrão de lista de analistas ativos e de ação com estado "A atribuir…/✅".
- `vacSelect`/`vacSelectSeq`/`vacSelectedId`: descarte de respostas fora de ordem, a reutilizar.

### Established Patterns
- Scripts clássicos num só escopo global, prefixo por ficheiro (`vac`, `sl`); `app.js` não se edita.
- Nenhum handler inline: `data-action`/`data-id` + listener delegado.
- Sem dados é `—`/"Sem dados", nunca `0`; erro nunca se desenha como ausência.
- Cores só por tokens CSS; `.modal[hidden]`-style: qualquer elemento novo com `hidden` e `display` próprio precisa da regra `[hidden]`.
- Carrega a cada passagem a ativa, sem polling.

### Integration Points
- `vaccines.js`: `vacRowsHtml` (coluna Estado), `vacRenderList` (contadores), `vacRenderDetail` (bloco Decisão), `vacBuildQuery` (`state`), `VAC_STATE_LABELS`/`VAC_ERROR_TEXT`.
- `index.html`: novo `<select>` Estado, linha de contadores, secção Decisão no detalhe, textos fixos reescritos.
- `style.css`: classes `vac-state-*` e do bloco Decisão, só com tokens.
- `ui_helpers.js` + `test_ui_helpers.cjs`: lógica pura nova.
- `test_vaccines_frontend.py`: contrato estático estendido.

</code_context>

<specifics>
## Specific Ideas

- "Aprovada ≠ aplicada" tem de ler-se sem ambiguidade no cabeçalho da aba, no aviso do detalhe e junto aos botões.
- O autor aparece com o nome humano da Equipa SOC (Eddie, Jeremy, Mike).
- A vista nunca mente: depois de um 409, o estado e os botões refletem o servidor.

</specifics>

<deferred>
## Deferred Ideas

- Contadores clicáveis que filtram a tabela — recusado nesta fase (novo padrão de interação).
- Lembrar o último analista entre sessões / pré-seleção — recusado; autoria autodeclarada pede escolha explícita (identidade por pedido é VLB-V2-02).
- Confirmação em dois passos ou modal antes de decidir — recusado; reabrir só com "reabrir decisão" (VLB-V2-03).
- Evento WebSocket ao decidir — F16 D-15.
- Reverter decisões (VLB-V2-03), papéis por tier (VLB-V2-02), dry-run (VLB-V2-01), aplicar no Wazuh (R21).
- W8.2/W8.4 e verificação humana no browser da aba (vaccine substituída, `.planning` deferred) — a verificação humana desta fase fica ao `/gsd-verify-work`.

</deferred>

---

*Phase: 17-Aba, testes e documentação*
*Context gathered: 2026-10-30*
