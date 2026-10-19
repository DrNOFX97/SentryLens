---
phase: 14-aba-vaccines-testes-e-documenta-o
verified: 2026-10-12T13:00:00Z
status: human_needed
score: 4/4 must-haves verified
covered_files:
  - CLAUDE.md
  - README.md
  - docs/API.md
  - docs/DATA_MODEL.md
  - docs/ROADMAP_STATUS.md
  - index.html
  - scripts/serve_frontend.py
  - scripts/test_vaccines_frontend.py
  - style.css
  - vaccines.js
covered_digest: "v2:sha256:7d6c373a726cb676d7fc40a39c721cf49e0bc1a13099197ba8b7a38632c2333d"
behavior_unverified: 0
overrides_applied: 0
human_verification:
  - test: "Abrir 💉 Candidates no dashboard (backend + frontend a correr) e usar os filtros (ataque, técnica MITRE, Incluir substituídas) e Atualizar"
    expected: "A tabela mostra o subconjunto certo; linha do gerador legível; badges de veredito (Não detetado/Parcial) distinguíveis; vaccines substituídas esbatidas com 'Substituída por <id>'"
    why_human: "Aspeto visual (CSS vac-*) não é verificável sem browser (14-02 human-check)"
  - test: "Parar o backend e carregar em Atualizar"
    expected: "Banner de erro e linha 'Sem ligação ao backend (localhost:8001)...', nunca 'Sem dados' nem lista vazia"
    why_human: "Destaque visual do erro e integração real com o fetch do browser (a lógica foi provada em node com stubs de DOM, não em browser real)"
  - test: "Clicar (e Tab + Enter/Espaço) numa linha; abrir uma substituída com 'Incluir substituídas'; carregar em Atualizar com uma linha aberta"
    expected: "Detalhe com aviso 'Proposta — não aplicada no Wazuh', Origem (ataque, cenário, MITRE, incidentes), Propostas e Cadeia, sem links; foco visível; linha selecionada mantém destaque depois de Atualizar"
    why_human: "Foco por teclado e leitura do detalhe são experiência de utilizador (14-03 human-check)"
  - test: "Lançar um ataque que escape à deteção e esperar 10 a 15 min"
    expected: "A vaccine aparece na aba depois da estabilização (600 s) mais o intervalo do loop (300 s)"
    why_human: "Ponta a ponta com o laboratório Wazuh ligado; a suite corre tudo mockado"
---

# Phase 14: Aba Vaccines, testes e documentação — Verification Report

**Phase Goal:** O analista vê as vaccines na aba Vaccines do dashboard, com o que cada uma propõe e de onde vem, e o marco R11 fica fechado com testes completos e documentação atualizada.
**Verified:** 2026-10-12
**Status:** human_needed (todas as verificações automáticas passam; falta só a verificação visual/UX no browser, declarada nos planos 14-02 e 14-03)
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (ROADMAP Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | O item "Vaccines" da sidebar abre uma aba real (`vaccines.js` servido pelo `serve_frontend.py`, sem editar `app.js`) que lista as vaccines com filtros e abre um detalhe com regra proposta e origem (ataque, cenário, MITRE, incidentes); todo o texto dinâmico passa por `escapeHtml` | VERIFIED | `index.html:95` `data-tab="vaccines"` + `#tab-vaccines` (l.1355) + `<script src="vaccines.js">` (l.1721); `app.js` genérico `tab-${tabName}` abre-o sem edição; `serve_frontend.py:53` `"/vaccines.js": "vaccines.js"`; `git diff --quiet 878d8e5 HEAD -- app.js` = 0 e `grep vaccin app.js` vazio. `vaccines.js` (474 linhas) lê só chaves reais: filtros no servidor via `vacBuildQuery`, `vacSelect` -> `GET /api/vaccines/{id}`, `vacOriginHtml` (ataque, cenário, MITRE, incidentes, sensores, evidência por referência), `vacProposalsHtml` (regra com event_ids/janela/min_count). Toda a interpolação em `innerHTML` passa por `escapeHtml`/`vacCell`/helpers `vac*`; título e linha do gerador por `textContent`. Guardas em `run_guards` (com prova de não-vacuidade). Sem `TODO/FIXME/TBD` |
| 2 | Sem amostra a aba mostra "Sem dados"; um 401/404/502/503 desenha-se como erro com a frase do código, nunca como "Sem dados" nem lista vazia | VERIFIED | Executado por mim em node (vm com stubs de DOM e fetch simulado) sobre o `vaccines.js` real: `reason:no_data` -> "Sem dados — ainda não há vaccines..."; filtro sem resultados -> frase distinta "Nenhuma vaccine corresponde aos filtros."; 401 -> "API key inválida ou em falta..."; 404 -> "O backend não tem a rota de vaccines..."; 502 -> "O backend devolveu 502..."; 503 -> "O store de vaccines ... não pôde ser lido..."; falha de rede -> "Sem ligação ao backend...". Corpo de erro com `<script>`/"Traceback" nunca chega ao DOM (só serve de chave em `VAC_ERROR_TEXT`). "Sem dados" aparece uma só vez no ficheiro |
| 3 | `python run_all_tests.py` termina verde sem o Wazuh, com testes standalone novos para motor, store e rotas, incluindo as garantias negativas (sem rota de escrita, sem comando executável, sem texto de exceção, sem duplicados após reprocessar ou reiniciar) | VERIFIED | Corri `run_all_tests.py` a partir de `scripts/` num venv novo fora do repo (uv, `--link-mode=copy`, `requirements.txt`): **45/45 ficheiros passaram, exit 0**; inclui `test_vaccine_engine/store/ingest.py`, `test_vaccines_api.py`, `test_vaccines_frontend.py`. Garantias negativas localizadas: 405 em POST/PUT/PATCH/DELETE (`test_vaccines_api.py:353-355`), `DENY_RE` varrendo todas as strings (`test_vaccine_engine.py:355,414`), 503 sem texto de exceção (`test_vaccines_api.py:211-218`), 2.º ciclo sem duplicados e reinício (`test_vaccines_api.py:185-194`, `test_vaccine_store.py:114-118`) |
| 4 | `docs/DATA_MODEL.md` define a entidade Vaccine, `docs/ROADMAP_STATUS.md` marca o R11 como concluído (✅) e `README.md` e `CLAUDE.md` descrevem o motor, o store e a rota | VERIFIED | `DATA_MODEL.md:203` secção "Vaccine (R11)" — reverifiquei por script: as 45 chaves dos conjuntos fechados do motor/gerador aparecem entre crases, exceto as 5 de `RESULT_KEYS` (retorno interno de `build_vaccine_candidates`), cujo equivalente público (`available, reason, total, vaccines`) está documentado no envelope (l.326). `docs/API.md:362` + 2 linhas da tabela (l.485-486). `ROADMAP_STATUS.md:29` R11 ✅ com ressalva "verificado por máquina / por verificar em humano" (l.104). `README.md` secção "## Vaccines" (l.155), rotas, módulos. `CLAUDE.md` l.176-178 (engine, store, ingest, rotas, `vaccines.js`), l.327, l.331; contagem "45 ficheiros" = `git ls-files 'scripts/test_*.py'`. `app.js` e `generate-claude-md` respeitados |

**Score:** 4/4 truths verified (0 present-but-behavior-unverified; a lógica de erro foi exercida em node, não só por presença).

### Required Artifacts

| Artifact | Status | Details |
|----------|--------|---------|
| `vaccines.js` | VERIFIED | Substantivo (474 l.), ligado (script em index.html, whitelist, observer de ativação), dados reais (GET /api/vaccines e /{id}) |
| `index.html` (aba, filtros, detalhe, aviso fixo) | VERIFIED | `#vaccines-panel`, `#vac-*`, `#vaccine-detail-panel` com `vac-not-applied` |
| `style.css` (`vac-*`) | VERIFIED | Regras presentes (9 ocorrências); aspeto visual -> human |
| `scripts/serve_frontend.py` | VERIFIED | Whitelist inclui `/vaccines.js`; `test_serve_frontend.py` verde (sqlite continua 404) |
| `scripts/test_vaccines_frontend.py` | VERIFIED | 716 l., run_tracer/guards/filters/states/detail/chain, ligado à rota real |
| `docs/API.md`, `docs/DATA_MODEL.md`, `docs/ROADMAP_STATUS.md`, `README.md`, `CLAUDE.md` | VERIFIED | Ver truth 4 |

### Key Link Verification

| From | To | Via | Status |
|------|----|-----|--------|
| sidebar `data-tab="vaccines"` | `#tab-vaccines` | `showTab('tab-'+name)` genérico em `app.js` | WIRED |
| `vaccines.js` | `GET /api/vaccines[/{id}]` | `vacRequest` com `X-API-Key` | WIRED |
| `vaccines.js` | `serve_frontend.py` | `ALLOWED_FILES["/vaccines.js"]` | WIRED |
| `vaccines.js` | `app.js` globais | `API_BASE`, `API_KEY`, `escapeHtml`, `renderPanelError` (sem redeclarar; guardado por `run_guards`) | WIRED |

### Data-Flow Trace (Level 4)

| Artifact | Dado | Fonte | Real | Status |
|----------|------|-------|------|--------|
| lista (`vacRowsHtml`) | `envelope.vaccines` | `GET /api/vaccines` -> `vaccine_store` SQLite | Sim (campos validados contra a resposta real da rota no teste) | FLOWING |
| detalhe | `envelope.vaccine` + 2.º GET `attack_id`+`include_superseded` | idem | Sim | FLOWING |
| linha do gerador | `envelope.generator` | `VaccineLoopState` | Sim | FLOWING |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Suite completa sem Wazuh | `cd scripts && python run_all_tests.py` (venv novo) | 45/45, exit 0 | PASS |
| Estados de lista/erro em `vaccines.js` | node + vm com stubs (ad hoc) | 7 cenários conforme esperado (ver truth 2) | PASS |
| `app.js` intacto | `git diff --quiet 878d8e5 HEAD -- app.js` | 0 | PASS |
| Sem coautoria nos commits da fase | `git log 878d8e5..HEAD --format=%B \| grep -ci co-authored-by` | 0 | PASS |

### Probe Execution

SKIPPED (a fase não declara probes `probe-*.sh`).

### Requirements Coverage

| Requirement | Plans | Description | Status | Evidence |
|-------------|-------|-------------|--------|----------|
| VAC-07 | 14-01, 14-02, 14-03 | Aba Vaccines (`vaccines.js`, sem editar `app.js`, servida pelo `serve_frontend.py`) com filtros, detalhe e "Sem dados" sem amostra | SATISFIED (visual por humano) | Truths 1 e 2 |
| VAC-08 | 14-01, 14-04 | Testes standalone sem Wazuh, suite verde, DATA_MODEL/ROADMAP_STATUS/README/CLAUDE.md refletem o R11 | SATISFIED | Truths 3 e 4 |

Sem requisitos órfãos (REQUIREMENTS.md mapeia só VAC-07 e VAC-08 à Phase 14).

### Anti-Patterns Found

| File | Pattern | Severity | Impact |
|------|---------|----------|--------|
| — | `TBD/FIXME/XXX/TODO/HACK/PLACEHOLDER` em `vaccines.js` e `test_vaccines_frontend.py` | nenhum | — |

### Notas (não bloqueiam)

- `scripts/.venv` está corrompido (problema de ambiente, fora da fase); a suite foi corrida num venv novo. Recriar o `.venv` com `--link-mode=copy`.
- Flake conhecido da suite paralela (`test_ml_training.py`, `test_attack_log_ids.py`, `test_attack_targets.py`) está registado como dívida em `ROADMAP_STATUS.md`; não reproduziu na minha corrida.
- `.planning/ROADMAP.md` ainda tem `- [ ] **Phase 14**` (l.49) e a linha de progresso da fase por fechar; é a atualização de estado a cargo do orquestrador depois da verificação humana.
- A linha R10 de `ROADMAP_STATUS.md` continua ⬜ (follow-up já registado pelo executor, fora do âmbito da fase 14).

### Human Verification Required

Ver frontmatter (4 itens): aspeto visual e filtros, erro com backend parado, detalhe por teclado/rato, ponta a ponta com ataque real. Estas são as mesmas verificações listadas em `docs/ROADMAP_STATUS.md` ("R11 — por verificar em humano").

### Gaps Summary

Nenhum gap. Os quatro critérios do ROADMAP estão verificados no código e por execução. Fica só a verificação humana no browser, não automatizável.

---

_Verified: 2026-10-12_
_Verifier: Claude (gsd-verifier)_
