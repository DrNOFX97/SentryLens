---
phase: 14-aba-vaccines-testes-e-documenta-o
verified: 2026-10-19T15:46:21Z
status: human_needed
score: 4/4 must-haves verified
covered_files:
  - .planning/phases/14-aba-vaccines-testes-e-documenta-o/14-01-PLAN.md
  - .planning/phases/14-aba-vaccines-testes-e-documenta-o/14-01-SUMMARY.md
  - .planning/phases/14-aba-vaccines-testes-e-documenta-o/14-02-PLAN.md
  - .planning/phases/14-aba-vaccines-testes-e-documenta-o/14-02-SUMMARY.md
  - .planning/phases/14-aba-vaccines-testes-e-documenta-o/14-03-PLAN.md
  - .planning/phases/14-aba-vaccines-testes-e-documenta-o/14-03-SUMMARY.md
  - .planning/phases/14-aba-vaccines-testes-e-documenta-o/14-04-PLAN.md
  - .planning/phases/14-aba-vaccines-testes-e-documenta-o/14-04-SUMMARY.md
  - CLAUDE.md
  - README.md
  - docs/API.md
  - docs/DATA_MODEL.md
  - docs/ROADMAP_STATUS.md
  - index.html
  - scripts/serve_frontend.py
  - scripts/test_serve_frontend.py
  - scripts/test_vaccines_frontend.py
  - style.css
  - vaccines.js
covered_digest: "v3:sha256:0355896997e51c0fb913fe807377df5f746c8b33696077d1559118da318fb253"
behavior_unverified: 0
overrides_applied: 0
human_verification:
  - test: "Abrir a aba Vaccines no dashboard (backend + frontend a correr) e usar os filtros (ataque, técnica MITRE, Incluir substituídas) e o botão Atualizar"
    expected: "A tabela mostra o subconjunto certo; linha do gerador legível ('Última execução há X min' ou a frase do código); badges de veredito (Não detetado/Parcial) distinguíveis; vaccines substituídas esbatidas com 'Substituída por <id>'"
    why_human: "Aspeto visual (CSS vac-*) e integração real com o browser não são verificáveis sem browser (human-check dos planos 14-02); a UI foi reorganizada depois da fase (ícone SVG em vez de emoji, menu reduzido), sem evidência registada de que alguém reconfirmou visualmente"
  - test: "Parar o backend e carregar em Atualizar"
    expected: "Banner de erro e linha 'Sem ligação ao backend (localhost:8001)...', nunca 'Sem dados' nem lista vazia"
    why_human: "Destaque visual do erro e o fetch real do browser (a lógica foi só exercida em node com stubs de DOM e no teste estático, não num browser real)"
  - test: "Clicar (e Tab + Enter/Espaço) numa linha; abrir uma vaccine substituída com 'Incluir substituídas'; carregar em Atualizar com uma linha aberta"
    expected: "Detalhe com aviso 'Proposta — não aplicada no Wazuh', Origem (ataque, cenário, MITRE, incidentes), Propostas e Cadeia, sem links; foco visível; a linha selecionada mantém o destaque depois de Atualizar"
    why_human: "Foco por teclado e leitura do detalhe são experiência de utilizador (human-check do 14-03), nunca confirmada por um humano desde a execução da fase"
  - test: "Lançar um ataque que escape à deteção e esperar 10 a 15 min"
    expected: "A vaccine aparece na aba depois da estabilização (600 s) mais o intervalo do loop (300 s)"
    why_human: "Ponta a ponta com o laboratório Wazuh ligado; a suite corre tudo mockado"
---

# Phase 14: Aba Vaccines, testes e documentação — Verification Report

**Phase Goal:** O analista vê as vaccines na aba Vaccines do dashboard, com o que cada uma propõe e de onde vem, e o marco R11 fica fechado com testes completos e documentação atualizada.
**Verified:** 2026-10-19 (regenerado — a verificação de 2026-10-12 foi assinalada como stale pela CLI porque `index.html`, `vaccines.js` e `style.css` foram alterados depois por um refactor de frontend não relacionado, "Ondas 0-8": extração de `api.js`/`html.js`/`state.js`/`router.js`. Este relatório ignora o veredito anterior e reavalia tudo contra o estado atual do código.)
**Status:** human_needed (todas as verificações automáticas passam contra o código atual; falta só a verificação visual/UX no browser, nunca confirmada desde a execução da fase)
**Re-verification:** No — tratado como verificação inicial (o relatório anterior não tinha secção `gaps:`; é regenerado do zero por indicação explícita, não por fecho de gaps)

## Nota prévia: Mode: mvp no ROADMAP.md não corresponde ao formato de User Story

`ROADMAP.md` declara `**Mode:** mvp` para a Phase 14, mas o goal não está no formato «As a / I want to / so that» — confirmado programaticamente:
`gsd_run query user-story.validate --story "<goal>"` devolve `valid: false` (role/capability/outcome ausentes). O próprio `14-01-PLAN.md` já documentava isto na altura do planeamento ("Goal do ROADMAP citado tal como está. Não está no formato «As a / I want to / so that» e o planner não inventa uma user story; se a quiseres, corre `/gsd-mvp-phase 14`"), ou seja, a fase foi deliberadamente planeada e executada como fase comum, não como fatia MVP.

Pela regra do verificador, um goal que falha a validação de User Story sob `mode: mvp` pede para se recusar a secção "User Flow Coverage" do MVP e pedir decisão humana em vez de a gerar com baixa qualidade. Não bloqueei a verificação inteira (o relatório anterior, de 2026-10-12, já tinha tratado esta fase com a metodologia padrão goal-backward, sem a secção MVP, e obteve um veredito válido) — mas sinalizo esta inconsistência: ou o `Mode: mvp` em `ROADMAP.md` é um resíduo que devia ser removido para esta fase, ou alguém tem de correr `/gsd-mvp-phase 14` para lhe dar um goal em formato de User Story. Isto não é um gap de implementação; é uma decisão de processo para o condutor humano.

## Goal Achievement

### Observable Truths (ROADMAP Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | O item "Vaccines" da sidebar abre uma aba real (`vaccines.js` servido pelo `serve_frontend.py`) que lista as vaccines com filtros e abre um detalhe com a regra proposta e a origem (ataque, cenário, técnica MITRE, incidentes); todo o texto dinâmico passa por `escapeHtml` | VERIFIED | `index.html:103` `data-tab="vaccines"` (botão agora com ícone SVG, texto "Vaccines" — mudou de "💉 Candidates" num refactor posterior, sem efeito funcional) + `#tab-vaccines` (l.1407) + `<script src="vaccines.js">` (l.1857); `scripts/serve_frontend.py:69` `"/vaccines.js": "vaccines.js"` confirmado por grep. **Mudança desde a fase:** `escapeHtml` direto foi substituído por `htmlT`/`htmRender` de `html.js` (escape por omissão em cada interpolação, API.js centraliza o fetch) — é a mesma garantia de escape por outro mecanismo, feita num refactor de frontend não relacionado (commits `8529709`, `64b5c2b`) que também atualizou o teste estático da fase. Corri `scripts/test_vaccines_frontend.py` contra o código atual: **0 `[FALHOU]`, exit 0** — `run_tracer`, `run_guards`, `run_filters`, `run_states`, `run_detail` e `run_chain` todos verdes, incluindo os checks que provam que não há `fetch(` direto fora de `api.js`, que `vaccines.js` não redeclara os globais de `app.js`, e que cada campo lido existe na resposta real da rota (`TestClient` sobre store semeado) |
| 2 | Sem amostra a aba mostra "Sem dados"; um 401/404/502/503 desenha-se como erro com a frase do código, nunca como "Sem dados" nem como lista vazia | VERIFIED | `run_guards` (corrido agora): "nenhuma frase de VAC_ERROR_TEXT diz 'Sem dados'", `vacRenderDetailError` nunca mostra 'Sem dados', `vacCodeFromResponse`/`vacCodeFromApiError` só devolvem código estável (nunca texto do servidor); `vacRequest` delega agora em `apiRequest` (`api.js`) mas a garantia de "mensagem = sempre um código" mantém-se (`vacCodeFromApiError` mapeia `ApiError.code`/`status` para a chave de `VAC_ERROR_TEXT`) |
| 3 | `python run_all_tests.py` termina verde sem o Wazuh ligado, com testes standalone para motor, store e rotas, incluindo as garantias negativas (sem rota de escrita, sem comando executável, sem texto de exceção, sem duplicados após reprocessar ou reiniciar) | VERIFIED | Corri a suite completa 3 vezes a partir de `scripts/` (`.venv/Scripts/python.exe run_all_tests.py`): 1ª e 2ª corrida **74/75** (falhou só `test_export_raw_events.py`, caso "(d) nenhum ficheiro alterado", que passa sempre isolado — é o flake de execução paralela já documentado como dívida aberta em `docs/ROADMAP_STATUS.md`, não introduzido por esta fase); 3ª corrida **75/75, código 0**. `test_vaccine_engine.py`, `test_vaccine_store.py`, `test_vaccine_ingest.py`, `test_vaccines_api.py` e `test_vaccines_frontend.py` passaram nas 3 corridas sem exceção. Garantias negativas confirmadas por grep no código atual: `"com chave -> 405"` em `test_vaccines_api.py` (1), `DENY_RE` em `test_vaccine_engine.py` (9), `"sem texto de exceção"` (2), `"2.º ciclo"` (2) e `"reinício"` (2) em `test_vaccines_api.py` |
| 4 | `docs/DATA_MODEL.md` define a entidade Vaccine, `docs/ROADMAP_STATUS.md` marca o R11 como concluído (✅) e `README.md` e `CLAUDE.md` descrevem o motor, o store e a rota | VERIFIED | Reexecutei o verify de `14-04-PLAN.md` contra o código atual: `docs/DATA_MODEL.md` secção `## Vaccine (R11)` (l.203) com **53 chaves documentadas** (script que importa `vaccine_engine`/`vaccine_ingest`/`vaccine_store` e falha com a lista em falta — não falhou: `OK 53 chaves documentadas`). `docs/API.md` secção `## 💉 Vaccines (R11)` (l.362) + 2 linhas na Tabela de endpoints (l.485-486) — `OK API.md`. `docs/ROADMAP_STATUS.md` tem `## Dívida conhecida` e `## R11 — verificado por máquina / por verificar em humano` (l.104). `README.md` secção `## Vaccines` (l.155-163) e `CLAUDE.md` com `vaccine_engine.py`/`vaccine_store.py`/`vaccine_ingest.py`/`vaccines.js` (l.179-181). Nenhuma das docs descreve uma vaccine como aplicada/aprovada/autenticada (grep confirma "nunca aplicada no Wazuh"/"não aplicada no Wazuh" em README e index.html) |

**Score:** 4/4 truths verified (0 present-but-behavior-unverified).

### Advisory (documentação desatualizada por trabalho posterior não relacionado)

- As contagens de ficheiros de teste citadas nas docs estão desatualizadas: `README.md`/`CLAUDE.md` dizem **48**, `docs/ROADMAP_STATUS.md` diz **45**; a contagem real hoje é **75** (`git ls-files 'scripts/test_*.py' | wc -l`), porque fases/trabalho posteriores (migração ML, triagem JEV, Equipa SOC, refactor de frontend) acrescentaram ficheiros de teste sem atualizar estas linhas. Isto não é uma falha da Phase 14 (as contagens estavam certas quando o 14-04 as escreveu, 45, e alguém as corrigiu parcialmente para 48 depois) — é dívida de manutenção documental contínua, fora do controlo desta fase. Não bloqueia o veredito porque o conteúdo central do critério 4 (a entidade Vaccine, o R11 ✅, a descrição do motor/store/rota) continua correto e verificado por script.
- `README.md` ainda refere a aba como "💉 Candidates" (l.163), mas o botão real em `index.html` hoje mostra apenas "Vaccines" com um ícone SVG (reorganização do menu num refactor posterior, W5.1). Cosmético, sem impacto funcional.
- O flake de execução paralela da suite completa mudou de ficheiro (antes `test_attack_log_ids.py`/`test_attack_targets.py`/`test_ml_training.py`; agora também `test_export_raw_events.py`), mas a classe do problema (recurso partilhado entre testes paralelos) é a mesma dívida já registada em `docs/ROADMAP_STATUS.md`, que não nomeia este ficheiro especificamente — considerar atualizar essa lista.

### Required Artifacts

| Artifact | Status | Details |
|----------|--------|---------|
| `vaccines.js` | VERIFIED | Existe, substantivo, ligado (`<script src="vaccines.js">` depois de `app.js`/`api.js`/`html.js`/`state.js`, whitelist do `serve_frontend.py`); dados reais via `apiRequest` -> `GET /api/vaccines[/{id}]`. Conteúdo mudou desde a fase (adotou `htmlT`/`apiRequest`), mas a função e o contrato (8 colunas, filtros, detalhe, cadeia) permanecem — confirmado pelo teste estático atualizado |
| `index.html` (aba, filtros, detalhe, aviso fixo) | VERIFIED | `#vaccines-panel`, `#vac-attack-filter`/`#vac-technique-filter`/`#vac-superseded-filter`/`#vac-refresh-btn`, `#vac-generator`, `#vaccine-detail-panel` com `#vac-detail-warning.vac-not-applied` — todos confirmados pelos checks de `run_tracer`/`run_filters`/`run_states`/`run_detail` a correr agora |
| `style.css` (`vac-*`) | VERIFIED | `.vac-verdict`, `.vac-verdict-not_detected`, `.vac-verdict-partial`, `.vac-row-superseded`, `.vac-superseded-note`, `.vac-generator-error`, `.vac-error-state`, `.vac-not-applied`, `.vac-proposal` — todas confirmadas pelo teste a correr sobre o `style.css` servido |
| `scripts/serve_frontend.py` | VERIFIED | `ALLOWED_FILES["/vaccines.js"] == "vaccines.js"`; `/scripts/vaccines.sqlite3` e `/vaccines.sqlite3` continuam 404 (`test_serve_frontend.py` verde) |
| `scripts/test_vaccines_frontend.py` | VERIFIED | Corrido agora, 0 `[FALHOU]`, 6 blocos (`run_tracer`/`run_guards`/`run_filters`/`run_states`/`run_detail`/`run_chain`) ligados à rota real |
| `docs/API.md`, `docs/DATA_MODEL.md`, `docs/ROADMAP_STATUS.md`, `README.md`, `CLAUDE.md` | VERIFIED | Ver truth 4; contagens desatualizadas registadas como advisory, não como gap |

### Key Link Verification

| From | To | Via | Status |
|------|----|-----|--------|
| sidebar `data-tab="vaccines"` | `#tab-vaccines` | ativação de aba genérica (agora em `router.js`, antes em `app.js`) | WIRED |
| `vaccines.js` | `GET /api/vaccines[/{id}]` | `vacRequest` -> `apiRequest` (`api.js`) com `X-API-Key` | WIRED |
| `vaccines.js` | `scripts/serve_frontend.py` | `ALLOWED_FILES["/vaccines.js"]` | WIRED |
| `vaccines.js` | globais partilhados | `API_BASE`/`API_KEY`/`renderPanelError` (`app.js`), `htmlT`/`htmRender` (`html.js`), `apiRequest`/`ApiError` (`api.js`) — nenhum redeclarado (`run_guards`) | WIRED |

### Data-Flow Trace (Level 4)

| Artifact | Dado | Fonte | Real | Status |
|----------|------|-------|------|--------|
| lista (`vacRowsHtml`) | `envelope.vaccines` | `GET /api/vaccines` -> `vaccine_store` SQLite | Sim (campos validados contra a resposta real no teste, agora) | FLOWING |
| detalhe | `envelope.vaccine` + 2.º GET `attack_id`+`include_superseded` | idem | Sim | FLOWING |
| linha do gerador | `envelope.generator` | `VaccineLoopState` | Sim | FLOWING |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Teste estático da aba Vaccines (todos os blocos) | `scripts/.venv/Scripts/python.exe -X utf8 test_vaccines_frontend.py` | 0 `[FALHOU]`, exit 0 | PASS |
| `/vaccines.js` servido pela whitelist | `scripts/.venv/Scripts/python.exe -X utf8 test_serve_frontend.py` | 0 `[FALHOU]`, exit 0 | PASS |
| Rotas `/api/vaccines[/{id}]` (sem frontend) | `scripts/.venv/Scripts/python.exe -X utf8 test_vaccines_api.py` | 0 `[FALHOU]`, exit 0 | PASS |
| Suite completa sem Wazuh (1ª e 2ª corrida) | `scripts/.venv/Scripts/python.exe run_all_tests.py` | 74/75 (flake pré-existente, isolado) | PASS (com nota) |
| Suite completa sem Wazuh (3ª corrida) | `scripts/.venv/Scripts/python.exe run_all_tests.py` | 75/75, exit 0 | PASS |
| DATA_MODEL.md contra as chaves do código | script Python do `14-04-PLAN.md` (import `vaccine_engine`/`vaccine_ingest`/`vaccine_store`) | `OK 53 chaves documentadas` | PASS |
| API.md contém as duas rotas e a Tabela de endpoints | script Python do `14-04-PLAN.md` | `OK API.md` | PASS |

### Probe Execution

SKIPPED (a fase não declara probes `probe-*.sh`; nenhum encontrado em `scripts/*/tests/probe-*.sh`).

### Requirements Coverage

| Requirement | Plans | Description | Status | Evidence |
|-------------|-------|-------------|--------|----------|
| VAC-07 | 14-01, 14-02, 14-03 | Aba Vaccines (`vaccines.js`, servida pelo `serve_frontend.py`) com filtros, detalhe e "Sem dados" sem amostra | SATISFIED (falta confirmação visual humana) | Truths 1 e 2 |
| VAC-08 | 14-01, 14-04 | Testes standalone sem Wazuh, suite verde, DATA_MODEL/ROADMAP_STATUS/README/CLAUDE.md refletem o R11 | SATISFIED | Truths 3 e 4 (contagens desatualizadas registadas como advisory) |

Sem requisitos órfãos (REQUIREMENTS.md mapeia só VAC-07 e VAC-08 à Phase 14; `.planning/REQUIREMENTS.md` já marca ambos `Complete`).

### Anti-Patterns Found

| File | Pattern | Severity | Impact |
|------|---------|----------|--------|
| `vaccines.js`, `scripts/test_vaccines_frontend.py` | `TBD`/`FIXME`/`XXX`/`TODO`/`HACK`/`PLACEHOLDER` | nenhum encontrado | — |
| `index.html` (bloco `#tab-vaccines`) | marcador `data-planned="R11"` | nenhum encontrado (confirmado pelo teste) | — |

### Human Verification Required

Ver frontmatter (4 itens, repetidos do relatório de 2026-10-12 porque continuam sem confirmação humana registada: nenhum `*-UAT.md` para a Phase 14, e `STATE.md` continua com `status: verifying` desde 2026-10-12): aspeto visual e filtros, erro com o backend parado, detalhe por teclado/rato, ponta a ponta com um ataque real contra o laboratório Wazuh.

### Gaps Summary

Nenhum gap de implementação. Os quatro critérios do ROADMAP continuam verificados no código atual, mesmo depois do refactor de frontend não relacionado (Ondas 0-8) que tocou `index.html`, `vaccines.js` e `style.css` — a suite de testes da fase foi atualizada em paralelo por esse trabalho e continua verde. Ficam por resolver, sem bloquear:
1. A verificação humana no browser (nunca feita desde a execução da fase).
2. A inconsistência `Mode: mvp` vs. goal não-User-Story em `ROADMAP.md` (decisão de processo, não de código).
3. As contagens de testes desatualizadas nas docs (45/48 vs. 75 reais) — manutenção documental, não específica desta fase.

---

_Verified: 2026-10-19_
_Verifier: Claude (gsd-verifier)_
