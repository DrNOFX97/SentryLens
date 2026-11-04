---
phase: 17-aba-testes-e-documenta-o
verified: 2026-11-04T12:00:00Z
status: passed
score: 4/4 must-haves verified
covered_files:
  - ".planning/phases/17-aba-testes-e-documenta-o/17-01-PLAN.md"
  - ".planning/phases/17-aba-testes-e-documenta-o/17-01-SUMMARY.md"
  - ".planning/phases/17-aba-testes-e-documenta-o/17-02-PLAN.md"
  - ".planning/phases/17-aba-testes-e-documenta-o/17-02-SUMMARY.md"
  - ".planning/phases/17-aba-testes-e-documenta-o/17-03-PLAN.md"
  - ".planning/phases/17-aba-testes-e-documenta-o/17-03-SUMMARY.md"
  - ".planning/phases/17-aba-testes-e-documenta-o/17-04-PLAN.md"
  - ".planning/phases/17-aba-testes-e-documenta-o/17-04-SUMMARY.md"
  - ".planning/phases/17-aba-testes-e-documenta-o/17-05-PLAN.md"
  - ".planning/phases/17-aba-testes-e-documenta-o/17-05-SUMMARY.md"
  - ".planning/phases/17-aba-testes-e-documenta-o/17-06-PLAN.md"
  - ".planning/phases/17-aba-testes-e-documenta-o/17-06-SUMMARY.md"
  - "CLAUDE.md"
  - "README.md"
  - "docs/API.md"
  - "docs/DATA_MODEL.md"
  - "docs/ROADMAP_STATUS.md"
  - "index.html"
  - "scripts/test_ml_training.py"
  - "scripts/test_ui_helpers.cjs"
  - "scripts/test_vaccines_frontend.py"
  - "style.css"
  - "ui_helpers.js"
  - "vaccines.js"
covered_digest: "v3:sha256:e15c274ff5cb43f2b822128508fc3e0165c8906fe718ad14107cd19631859c2d"
behavior_unverified: 0
overrides_applied: 0
human_verification:
  - test: "Abrir a aba Vaccines com o backend e o frontend a correr, abrir uma vaccine proposta atual, escolher um analista e Aprovar; repetir noutra com Rejeitar sem motivo e depois com motivo."
    expected: "Aprovar e Rejeitar ficam desativados até haver analista; Rejeitar sem motivo mostra a frase local e não envia pedido; depois de decidir o bloco mostra o badge, autor, data e motivo sem botões, o aviso do detalhe diz 'não aplicada no Wazuh' e a linha da tabela e os contadores mudam."
    why_human: "Interação real no DOM (estados disabled, foco, redesenho) não é exercida pelos testes, que são de texto e de node:vm sobre funções puras."
  - test: "Abrir a mesma vaccine proposta em dois separadores; decidir no primeiro e depois no segundo."
    expected: "O segundo mostra a frase de already_decided e o detalhe e a lista refazem-se sozinhos (botões desaparecem, badge e contadores corretos), sem novo POST automático."
    why_human: "O refresco após 409 (vacRenderDecisionError -> vacSelect + vacRefresh) é prova de texto/código; a sequência assíncrona no browser só se vê a correr."
  - test: "Ver a aba nos dois temas (claro e escuro): badges Proposta/Aprovada/Rejeitada, bloco Decisão, filtro Estado e cartões de contadores."
    expected: "Legíveis, com contraste suficiente, sem cor como única pista, e o bloco do formulário aparece/desaparece corretamente (regra [hidden])."
    why_human: "Aparência visual e contraste percebido; os testes só verificam tokens e regras CSS por texto."
  - test: "Abrir uma vaccine substituída (com 'Incluir substituídas') e uma com a lista de analistas indisponível/vazia."
    expected: "Frase 'Substituída por …' sem botões; frase de erro ou 'Sem analistas ativos' no lugar dos botões, nunca bloco escondido."
    why_human: "Cenários dependem de dados reais do laboratório e do estado da Equipa SOC."
---

# Phase 17: Aba, testes e documentação Verification Report

**Phase Goal:** O analista decide no dashboard e o marco fecha com a suite completa e a documentação.
**Verified:** 2026-11-04
**Status:** human_needed
**Re-verification:** No, verificação inicial

## Goal Achievement

### Observable Truths

| #   | Truth | Status | Evidence |
| --- | ----- | ------ | -------- |
| 1 | O detalhe da vaccine tem Aprovar e Rejeitar (motivo obrigatório ao rejeitar) via `data-action`, sem handlers inline; estado e decisão aparecem na tabela e no detalhe | VERIFIED (código e testes estáticos); interação no browser em Human Verification | `index.html:1476-1477` botões `data-action="vac-approve"`/`"vac-reject"`, `disabled` por omissão; listener delegado `vaccines.js:715-720` (`event.target.closest("[data-action]")`); `grep -E "\bon[a-z]+="` em `index.html` e `vaccines.js` sem resultados. Motivo: `slVacDecisionBody` (`ui_helpers.js:400-411`) devolve `reason_required` se `rejected` e `trim()` vazio; `<textarea id="vac-decision-reason" maxlength="500">` com contador. Select de analistas sem pré-seleção ("Escolher…") e botões bloqueados até haver escolha (`vacSyncDecisionControls`). Tabela: coluna Estado com `vacStateBadge` (`vaccines.js:213`, texto + classe `vac-state-*`); detalhe: `vacRenderDecision` com modos `decided`/`superseded`/`controls`/etc. via `slVacDecisionView` (autor, data, motivo para decididas) e aviso por estado `slVacWarningText`. `.vac-decision-form[hidden]{display:none}` presente (`style.css:1058`). Único POST em `vacDecide` (`vaccines.js:661-662`). |
| 2 | Erros aparecem pela frase do código estável; um 409 (já decidida) atualiza a vista em vez de a deixar a mentir | VERIFIED (código e testes); fluxo real em Human Verification | `VAC_ERROR_TEXT` (`vaccines.js:41-82`) tem frase PT-PT para `analyst_required`, `invalid_decision`, `reason_required`, `invalid_reason`, `invalid_author`, `invalid_vaccine_id`, `invalid_decided_at`, `invalid_body`, `analyst_not_found`, `analyst_inactive`, `already_decided`, `vaccine_superseded`, `http_405`, `http_409`, etc.; `vacRequest` lança só o código (`vacCodeFromApiError`), o texto do servidor nunca entra no DOM. `vacRenderDecisionError` (`vaccines.js:601-610`) usa `slVacErrorFollowUp`: `already_decided`/`vaccine_superseded`/`http_409`/5xx/timeout etc. -> `vacSelect(vacSelectedId)` + `vacRefresh()` (detalhe, lista e contadores); `analyst_not_found`/`analyst_inactive`/`incidents_unavailable` -> recarrega analistas. Só GETs no seguimento, sem novo POST. `test_vaccines_frontend.py` cobre D-11 (frase por código contra respostas reais da rota, linha 976) e D-13 (linha 1158). |
| 3 | `run_all_tests.py` termina com código 0 numa execução completa, sem Wazuh, incluindo os testes novos | VERIFIED | Executado por mim, a partir de `scripts/` com o venv e `PYTHONIOENCODING=utf-8`: `84/84 ficheiros passaram`, `exit=0`, nenhum `FAIL`. `ls scripts/test_*.py` = 84 ficheiros. PASS inclui `test_vaccine_decision.py`, `test_vaccine_decision_api.py`, `test_vaccine_decision_store.py`, `test_vaccines_api.py`, `test_vaccines_frontend.py`, `test_ui_helpers.py`, `test_ml_training.py`. `git status` limpo depois da suite (só 2 PATTERNS.md e `relatorio.html` por rastrear, anteriores). Teste do flake corrigido (`scripts/test_ml_training.py`, temporário próprio). |
| 4 | `DATA_MODEL.md`, `API.md`, `ROADMAP_STATUS.md` (R12 ✅), `README.md` e `CLAUDE.md` descrevem o R12 com contagens medidas | VERIFIED | `docs/DATA_MODEL.md`: secção "Decisão do analista (R12)" (tabela `vaccine_decisions`, triggers, estado derivado, `state_counts`, códigos 404/409/422/503). `docs/API.md`: `POST /api/vaccines/{id}/decision`, `?state=`, `state_counts`, `decision`, tabela de códigos e resposta 200 com `notice`. `docs/ROADMAP_STATUS.md:30`: linha R12 com ✅; secção "R12 — verificado por máquina / por verificar em humano" (linhas 124-139). `README.md:328`, `CLAUDE.md:83`, `ROADMAP_STATUS.md:42,127`: "84/84 ficheiros passaram em run_all_tests.py, execução completa de 2026-11-04", que coincide com a minha execução (84/84) e com a contagem real de ficheiros (84). A antiga "81 ficheiros" já não existe. `CLAUDE.md` descreve `vaccine_decision.py`, a nota de que aprovar não aplica nada (linha 182) e o estado do marco. |

**Score:** 4/4 truths verified (0 present-but-behavior-unverified); a parte de interação no browser fica listada abaixo como verificação humana e não é contada como provada.

### Required Artifacts

| Artifact | Expected | Status | Details |
| -------- | -------- | ------ | ------- |
| `vaccines.js` | Bloco Decisão, `vacDecide`, `VAC_ERROR_TEXT`, badge, contadores, filtro | VERIFIED | 738 linhas, substantivo, ligado (`index.html:1894`, `serve_frontend.py:69`) |
| `ui_helpers.js` | `slVacDecisionBody/AnalystOptions/DecisionView/WarningText/ReasonCounter/ErrorFollowUp/StateCounts` | VERIFIED | `ui_helpers.js:389-502`, puras; 69 referências `slVac` em `test_ui_helpers.cjs` |
| `index.html` | Secção Decisão, filtro Estado, contadores, textos sem "só leitura" | VERIFIED | linhas 1406-1489; nenhum handler inline |
| `style.css` | `vac-state-*`, bloco Decisão, `[hidden]` | VERIFIED | linhas 1052-1061, só tokens (`var(--…)`) |
| `docs/*.md`, `README.md`, `CLAUDE.md` | R12 com contagens | VERIFIED | ver truth 4 |
| `scripts/test_vaccines_frontend.py` | Contrato estático e funcional da decisão | VERIFIED | passa na suite |

### Key Link Verification

| From | To | Via | Status | Details |
| ---- | -- | --- | ------ | ------- |
| `vaccines.js` botões Decisão | `POST /api/vaccines/{id}/decision` | `vacDecide` -> `vacRequest(..., {method:"POST", body})` | WIRED | corpo vindo de `slVacDecisionBody`; teste prova que o corpo é aceite pela rota real |
| `vaccines.js` analistas | `GET /api/soc/analysts?active_only=true` | `vacLoadAnalysts` em `vacOnShow` | WIRED | `slVacAnalystOptions` filtra ativos/ids válidos |
| erro 409 | refresco detalhe+lista | `slVacErrorFollowUp` -> `vacSelect` + `vacRefresh` | WIRED | |
| `state_counts` do envelope | cartões de contadores | `vacRenderCounts` -> `slVacStateCounts` -> `kpiRender` | WIRED | null -> "—" |
| filtro Estado | `?state=` | `vacBuildQuery` com `VAC_STATES.includes` | WIRED | valor fora do conjunto nunca sai |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
| -------- | ------------- | ------ | ------------------ | ------ |
| Badge/tabela | `vaccine.state` | `GET /api/vaccines` (estado derivado do store) | Sim | FLOWING |
| Bloco Decisão | `vaccine.decision` | detalhe `GET` / resposta `200` do POST | Sim | FLOWING |
| Contadores | `envelope.state_counts` | `count_by_state` do store | Sim (null sem amostra) | FLOWING |
| Select analistas | `vacAnalysts` | `/api/soc/analysts` | Sim | FLOWING |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
| -------- | ------- | ------ | ------ |
| Suite completa | `python run_all_tests.py` (venv, UTF-8) em `scripts/` | `84/84 ficheiros passaram`, `exit=0` | PASS |
| Sem handlers inline | `grep -E "\bon[a-z]+="` em `index.html`/`vaccines.js` | sem resultados | PASS |
| Contagem de testes vs docs | `ls scripts/test_*.py \| wc -l` | 84 (docs dizem 84) | PASS |

### Probe Execution

Step 7c: SKIPPED (a fase não declara probes).

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
| ----------- | ----------- | ----------- | ------ | -------- |
| VLB-06 | 17-01, 17-02, 17-03, 17-06 | Botões Aprovar/Rejeitar com motivo, `data-action`, erros por frase do código | SATISFIED (código e testes); interação real a confirmar por humano | truths 1 e 2 |
| VLB-07 | 17-01..17-06 | Testes sem Wazuh e documentação com contagens medidas | SATISFIED | truths 3 e 4 |

Nenhum requisito órfão: REQUIREMENTS.md só mapeia VLB-06 e VLB-07 à Fase 17.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
| ---- | ---- | ------- | -------- | ------ |
| (nenhum) | - | `TBD`/`FIXME`/`XXX`/`TODO`/`HACK` nos ficheiros alterados | - | Os `return null`/`[]` encontrados são estados iniciais sobrescritos por pedidos reais, não stubs |

### Human Verification Required

Estes pontos só se provam num browser real; os testes são de texto e `node:vm`.

### 1. Aprovar e Rejeitar no dashboard

**Test:** Com backend e frontend a correr, abrir uma vaccine proposta atual, escolher analista, Aprovar; noutra, Rejeitar sem motivo e depois com motivo.
**Expected:** Botões desativados até haver analista; Rejeitar sem motivo mostra a frase local sem pedido; após decidir, o bloco passa a só leitura (badge, autor, data, motivo), o aviso diz "não aplicada no Wazuh", tabela e contadores mudam.
**Why human:** Interação e redesenho do DOM não são exercidos pelos testes.

### 2. 409 com dois separadores

**Test:** Abrir a mesma vaccine em dois separadores, decidir no primeiro e no segundo.
**Expected:** O segundo mostra a frase de `already_decided` e o detalhe e a lista refazem-se sozinhos, sem novo POST.
**Why human:** Sequência assíncrona real.

### 3. Temas claro e escuro

**Test:** Ver badges, bloco Decisão, filtro Estado e contadores nos dois temas.
**Expected:** Legível, contraste suficiente, cor nunca única pista, formulário a aparecer/desaparecer corretamente.
**Why human:** Aparência.

### 4. Vaccine substituída e analistas indisponíveis

**Test:** Abrir uma vaccine substituída e simular lista de analistas vazia/indisponível.
**Expected:** Frase sem botões; nunca o bloco escondido.
**Why human:** Depende de dados reais do laboratório.

### Gaps Summary

Sem lacunas automáticas: os quatro critérios do ROADMAP resolvem-se em VERIFIED por código, testes e uma execução completa da suite feita nesta verificação (84/84, código 0). O backend não foi alterado nesta fase (só frontend, testes e docs). O estado é `human_needed` apenas porque o comportamento de browser listado acima não é provável pelos testes automáticos; o `ROADMAP_STATUS.md` já regista os mesmos pontos como "por verificar em humano".

---

_Verified: 2026-11-04T12:00:00Z_
_Verifier: Claude (gsd-verifier)_
