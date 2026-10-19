---
phase: 14-aba-vaccines-testes-e-documenta-o
reviewed: 2026-10-19T00:00:00Z
depth: standard
files_reviewed: 11
files_reviewed_list:
  - vaccines.js
  - index.html
  - style.css
  - scripts/serve_frontend.py
  - scripts/test_vaccines_frontend.py
  - scripts/test_serve_frontend.py
  - docs/DATA_MODEL.md
  - docs/API.md
  - docs/ROADMAP_STATUS.md
  - README.md
  - CLAUDE.md
findings:
  critical: 0
  warning: 3
  info: 3
  total: 6
status: issues_found
---

# Phase 14: Code Review Report

**Reviewed:** 2026-10-19
**Depth:** standard
**Files Reviewed:** 11
**Status:** issues_found

## Summary

Revi o código e a documentação da Fase 14 (aba Vaccines) tal como estão em disco **hoje**, depois de uma refatorização posterior e não relacionada (ondas 2-8 de outra auditoria, já integrada) ter trocado o mecanismo de pedidos/HTML de `vaccines.js` de `fetch`/`escapeHtml`/`innerHTML` para os módulos partilhados `api.js` (`apiRequest`/`ApiError`), `html.js` (`htmlT`/`htmRender`) e `state.js` (`sttShowLoading`/`sttShowError`). Corri `test_vaccines_frontend.py` e `test_serve_frontend.py` no `.venv` do projeto: ambos passam de ponta a ponta (109 checks, 0 `[FALHOU]`), e tracei manualmente a contrato real (`vaccine_engine.py`/`vaccine_store.py`/`vaccine_ingest.py`/`main.py`) contra cada campo lido por `vaccines.js`. Não encontrei nenhuma vulnerabilidade XSS, nenhum pedido de escrita, nenhuma fuga de texto de exceção para o DOM, nem nenhuma regressão funcional: a escrita HTML é sempre auto-escapada por `htmlT`, os erros do servidor só servem de chave de `VAC_ERROR_TEXT`, e `vacSelectSeq`/`vacLoading` continuam a impedir que uma resposta tardia sobreponha a seleção/filtro mais recente.

Os problemas que encontrei são de manutenção e de documentação, concentrados na fronteira entre o código escrito na Fase 14 e a refatorização posterior que o reutiliza sem o atualizar por completo: código morto que mascara qual é de facto o caminho de erro em produção, um comentário de cabeçalho desatualizado desde a própria Fase 14, uma inconsistência visual entre o estado de erro e os estados vazio/a carregar da mesma tabela, e três ficheiros de documentação (`README.md`, `CLAUDE.md`, `docs/ROADMAP_STATUS.md`) que ainda descrevem um rótulo de menu ("💉 Candidates") que a refatorização posterior removeu.

## Warnings

### WR-01: Código morto (`vacCodeFromResponse`/`VAC_CODE_RE`) mascara o caminho de erro real, e a guarda do contrato testa o código morto em vez do vivo

**File:** `vaccines.js:33`, `vaccines.js:91-96` (ver também `vaccines.js:111-125`)
**Issue:** `vacRequest` (linhas 111-117) já não usa `fetch`/`vacCodeFromResponse`: delega em `apiRequest` (de `api.js`) e converte o erro com `vacCodeFromApiError` (linhas 121-125). `vacCodeFromResponse` (linhas 91-96) e a constante `VAC_CODE_RE` (linha 33, só usada por essa função) ficaram sem nenhuma chamada — confirmei com grep que `vacCodeFromResponse(` não aparece em mais nenhum sítio do ficheiro. O problema não é só estética: `scripts/test_vaccines_frontend.py` (linhas 376-378) ainda faz
```python
corpo = function_body(js, "vacCodeFromResponse")
check("vacCodeFromResponse trata o 401 como unauthorized", "401" in corpo and '"unauthorized"' in corpo)
```
e a linha 376 (`"o único código aceite do servidor é /^[a-z_]{1,64}$/"`) só passa porque a regex ainda existe como literal dentro da função morta. Ou seja, a guarda que devia provar a propriedade de segurança "o `detail` do servidor só é aceite como código se casar um slug seguro" está hoje a verificar uma função que o `vacRequest` real nunca chama — o caminho vivo (`apiCodeFromResponse` em `api.js` + `vacCodeFromApiError` em `vaccines.js`) não tem nenhuma asserção própria no contrato estático. (Tracei manualmente que `vacCodeFromApiError` continua seguro — qualquer código desconhecido cai em `VAC_GENERIC_ERROR` dentro de `vacErrorText`, nunca mostra texto do servidor — mas isso é verificação minha, não do teste.)
**Fix:** Remover `vacCodeFromResponse` e `VAC_CODE_RE` de `vaccines.js` (ou, se se preferir manter como validação extra do lado do cliente, chamá-la de facto dentro de `vacCodeFromApiError`). Atualizar `test_vaccines_frontend.py` para testar `vacCodeFromApiError`/`apiSafeCode` (de `api.js`) em vez de `vacCodeFromResponse`, por exemplo:
```python
corpo = function_body(js, "vacCodeFromApiError")
check("vacCodeFromApiError devolve err.code (vindo de apiSafeCode em api.js)", "err.code" in corpo)
```

### WR-02: O estado de erro da tabela fica com uma caixa dupla, inconsistente com os estados vazio/a carregar da mesma tabela

**File:** `vaccines.js:192-204` (`vacRenderError`) e `vaccines.js:295-302` (`vacShowLoadingRow`); `style.css:614` (`.empty-state`), `style.css:1046` (`.loading-state`), `style.css:1048` (`.vac-error-state`), `style.css:1247` (`.error-state`)
**Issue:** `vacRenderList` desenha "Sem dados"/lista vazia com `<td class="empty-state">texto</td>` direto (sem elemento aninhado): `.empty-state` dá só `text-align:center` + `padding:30px 10px`, sem borda nem fundo. Mas `vacRenderError` cria `<td class="vac-error-state">` e depois chama `sttShowError(td, text)`, que insere um `<p class="error-state" role="alert">` DENTRO do `td` (via `sttBuild`/`replaceChildren`). `.vac-error-state` (td) já tem `padding:30px 10px`; `.error-state` (p) acrescenta por cima `padding:16px 12px` + `border:1px solid` + `background`. O resultado visual é uma caixa com borda e fundo colorido dentro de uma célula já centrada e almofadada — diferente do tratamento plano de `.empty-state`/`.loading-state` na mesma tabela, para o mesmo tipo de "uma linha, uma mensagem". `vacShowLoadingRow` tem o mesmo padrão de aninhamento (sem `className` no `td`, mas ainda assim um `<p class="loading-state">` dentro de um `<td>` sem classe própria), o que é inconsistente com `vacRenderError` ter as duas (`td.vac-error-state` E `p.error-state`).
**Fix:** Escolher um único padrão para as 3 linhas de estado (vazio/a carregar/erro) na tabela de vaccines: ou todas usam `sttShow*` sem `className` extra no `td` (deixando a caixa de `.error-state`/`.loading-state` ser a única), ou nenhuma usa os helpers de `state.js` e todas ficam com `td.className` + `textContent` direto, como `vacRenderList` já faz para "Sem dados". Por exemplo, para alinhar com o padrão existente de `vacRenderList`:
```js
td.className = "vac-error-state";
td.textContent = text;
```
em vez de `sttShowError(td, text)`.

### WR-03: README.md, CLAUDE.md e docs/ROADMAP_STATUS.md continuam a descrever o rótulo de menu "💉 Candidates", que já não existe no index.html servido

**File:** `README.md:163`, `CLAUDE.md:181`, `docs/ROADMAP_STATUS.md:117`
**Issue:** A refatorização posterior (W5.1, redução do menu) trocou o grupo "Vaccines" (com os subitens Candidates/Validation/Approved/Regression) por um único botão `<button class="nav-item" data-tab="vaccines">...Vaccines</button>` (`index.html:103`) — os antigos subitens planeados passaram para a página Roadmap (`index.html:1799-1801`), e o próprio `scripts/test_vaccines_frontend.py` (linha 255) já verifica `"Vaccines" in candidates[0]`, não "Candidates". As três docs ainda dizem "em 💉 Candidates" (`README.md:163`), "aba Vaccines -> Candidates" (`CLAUDE.md:181`) e "Abrir 💉 Candidates" (`docs/ROADMAP_STATUS.md:117`), instruindo quem lê a procurar um rótulo que já não aparece na interface.
**Fix:** Trocar as três ocorrências para o rótulo atual ("Vaccines", sem "Candidates"), por exemplo em `README.md:163`: `"em 💉 Candidates"` → `"na aba Vaccines"`; em `CLAUDE.md:181`: `"aba Vaccines -> Candidates"` → `"aba Vaccines"`; em `docs/ROADMAP_STATUS.md:117`: `"Abrir 💉 Candidates"` → `"Abrir a aba Vaccines"`.

## Info

### IN-01: Comentário de cabeçalho de vaccines.js desatualizado desde a própria Fase 14

**File:** `vaccines.js:1-15`
**Issue:** O comentário diz "reutiliza os seus globais (API_BASE, API_KEY, htmlT/htmRender de html.js, renderPanelError)" sem mencionar `apiRequest`/`ApiError`/`apiErrorMessage` (api.js) nem `sttShowError`/`sttShowLoading` (state.js), todos usados extensivamente no ficheiro. Diz também "um único pedido GET a /api/vaccines com o cabeçalho X-API-Key" (linha 3) — verdade no 14-01, mas desde o 14-02/14-03 o ficheiro também pede `/api/vaccines/{id}` (`vacSelect`) e um segundo `/api/vaccines?attack_id=...` (`vacLoadChain`); nenhuma destas chamadas escreve, mas o comentário já não descreve a superfície real de pedidos.
**Fix:** Atualizar o comentário de topo para listar os globais realmente usados e a frase sobre o número/forma dos pedidos, por exemplo "um ou mais pedidos GET só de leitura a /api/vaccines e /api/vaccines/{id}".

### IN-02: O regex de attack_id do frontend é mais estrito do que a validação do backend

**File:** `vaccines.js:57` (`VAC_ATTACK_ID_RE = /^[1-9]\d{0,8}$/`) vs. `scripts/main.py:1945` (`attack_id: int | None = Query(None, ge=1, le=999_999_999)`)
**Issue:** O backend aceita `attack_id` com zeros à esquerda na query string (o FastAPI/Pydantic converte `"0123"` para o inteiro `123`, que passa `ge=1, le=999999999`). O frontend rejeita esse mesmo valor antes de o enviar (`VAC_ATTACK_ID_RE` exige que o primeiro caractere seja 1-9), mostrando "ID de ataque inválido" para um id que o backend teria aceitado. Impacto prático baixo (ids de ataque não costumam ter zeros à esquerda), mas é uma inconsistência de validação entre as duas camadas.
**Fix:** Se interessar aceitar zeros à esquerda, trocar para `/^\d{1,9}$/` com um limite adicional de valor (`Number(attackId) <= 999999999`), ou documentar explicitamente que o campo não aceita zeros à esquerda por desenho.

### IN-03: vaccines.js mantém o seu próprio ciclo de vida de aba (MutationObserver) em vez do router.js partilhado

**File:** `vaccines.js:485-494` (`vacOnShow`/`vacObserver`) vs. `router.js` (`rtRegisterTab`/`rtActivate`/`rtDeactivate`, usado por `shell.js:200-210` para `alerts`, `agents`, `system`, `lifecycle`, etc.)
**Issue:** A refatorização posterior introduziu `router.js` como mecanismo único de ciclo de vida de aba (carrega só quando ativa e visível, intervalo de refresh, pára o temporizador ao esconder). `vaccines.js` nunca foi migrado: continua com o seu próprio `MutationObserver` + `visibilitychange` escrito na Fase 14. Não encontrei nenhum efeito incorreto diretamente observável (confirmei que `rtRouter.activate("vaccines")` simplesmente não encontra nenhuma aba registada e não interfere), e o mesmo padrão continua em `attack_library.js` (não tocado por esta fase) — não é uma regressão introduzida por este plano, mas é uma duplicação de lógica que divergiu do padrão hoje usado pela maioria das abas.
**Fix:** Fora do âmbito desta fase; registar como follow-up para uma fase de migração do frontend para `router.js` (a mesma dívida já existe em `attack_library.js`).

---

_Reviewed: 2026-10-19_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
