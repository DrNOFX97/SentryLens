---
phase: 14-aba-vaccines-testes-e-documenta-o
verified: 2026-10-29T12:00:00Z
status: passed
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
  - scripts/main.py
  - scripts/serve_frontend.py
  - scripts/test_serve_frontend.py
  - scripts/test_vaccines_frontend.py
  - scripts/vaccine_engine.py
  - scripts/vaccine_ingest.py
  - scripts/vaccine_store.py
  - style.css
  - vaccines.js
covered_digest: "v3:sha256:492ea65260238d0f2e8020c5f075b1b91bba61cb6ad2d1b442e9fb29f6ad033e"
behavior_unverified: 0
overrides_applied: 0
re_verification:
  previous_status: human_needed
  previous_score: 4/4
  gaps_closed: []
  gaps_remaining: []
  regressions: []
human_verification: []
---

# Phase 14: Aba Vaccines, testes e documentação — Verification Report

**Phase Goal:** O analista vê as vaccines na aba Vaccines do dashboard, com o que cada uma propõe e de onde vem, e o marco R11 fica fechado com testes completos e documentação atualizada.
**Verified:** 2026-10-29
**Status:** passed (todas as verificações automáticas passam contra o código atual; os 4 itens humanos do relatório de 2026-10-19 foram executados e aceites no `14-UAT.md`, 4/4 pass)
**Re-verification:** Sim, regenerada porque o relatório de 2026-10-19 ficou `stale` (o digest deixou de bater: `scripts/main.py`, `scripts/serve_frontend.py`, `CLAUDE.md` e outros ficheiros cobertos mudaram depois). O relatório anterior não tinha `gaps:`; reavaliou-se tudo contra o código atual.

## O que mudou desde 2026-10-19 (e porque o digest deixou de bater)

| Commit | Alteração | Efeito na fase |
|--------|-----------|----------------|
| `d661723` | `serve_frontend.py` passa a `ThreadingHTTPServer` | Sem efeito no contrato `ALLOWED_FILES["/vaccines.js"]`; `test_serve_frontend.py` verde |
| `9c5b431` | `CLAUDE.md` com contagem de testes e módulos do frontend | Docs; as descrições de motor/store/rota mantêm-se (l.179-181) |
| `da7e2a7`, `0f62f0c` | `attack_registry` exclui ruído SSH/PAM; `ATTACK_ALERTS_SIZE` sobe de 1000 para 8000 em `main.py` | Desbloqueou a geração real da vaccine `vac-a09c1541972a` (ataque id=14), exercitada no UAT 4. Ver advisory sobre docs que ainda dizem "teto de 1000" |
| `62bc072`, `0a384a6`, `9c08cb6`, `46abb90`, `e649bef` | Triagem de incidentes, CORS/PATCH, catálogo Defender | Fora do âmbito da fase; sem impacto nos ficheiros `vaccine_*` nem em `vaccines.js` |

`index.html`, `vaccines.js`, `style.css`, `docs/API.md`, `docs/DATA_MODEL.md`, `docs/ROADMAP_STATUS.md` e `README.md` não mudaram desde 1946853 (`git diff 1946853 HEAD --stat` só mostra `CLAUDE.md`, `serve_frontend.py`).

## Goal Achievement

### Observable Truths (ROADMAP Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | O item "Vaccines" da sidebar abre uma aba real (`vaccines.js` servido pelo `serve_frontend.py`, sem editar `app.js`) que lista as vaccines com filtros e abre um detalhe com a regra proposta e a origem (ataque, cenário, técnica MITRE, incidentes); todo o texto dinâmico passa por `escapeHtml` | VERIFIED | `index.html:103` `data-tab="vaccines"`, `index.html:1407` `#tab-vaccines`, `index.html:1857` `<script src="vaccines.js">`; `scripts/serve_frontend.py:69` `"/vaccines.js": "vaccines.js"`. Escape por `htmlT` (escape por omissão, `html.js`) e fetch só por `apiRequest` (`api.js`); sem `fetch(` em `vaccines.js` (grep vazio). `test_vaccines_frontend.py` corrido agora: exit 0, 0 `[FALHOU]` (tracer, guards, filtros, estados, detalhe, cadeia, contra a resposta real da rota). UAT 1 e 3 (Playwright, 2026-10-29): tabela com a vaccine real, filtros e Atualizar funcionam, detalhe com "Proposta — não aplicada no Wazuh", Origem, Propostas, Cadeia, 0 links, foco por teclado |
| 2 | Sem amostra a aba mostra "Sem dados"; um 401/404/502/503 desenha-se como erro com a frase do código, nunca como "Sem dados" nem como lista vazia | VERIFIED | `run_guards` (corrido agora): nenhuma frase de `VAC_ERROR_TEXT` diz "Sem dados", o erro só mostra códigos estáveis, nunca texto do servidor. UAT 2 (Playwright, pedidos a `/api/vaccines` bloqueados): banner e tabela com "Sem ligação ao backend (localhost:8001)...", sem "Sem dados" nem lista vazia; Atualizar recupera ao repor a rota |
| 3 | `python run_all_tests.py` termina verde sem o Wazuh ligado, com testes standalone novos para motor, store e rotas, incluindo as garantias negativas | VERIFIED (com ressalva ambiental, ver abaixo) | `test_vaccine_engine.py`, `test_vaccine_store.py`, `test_vaccine_ingest.py`, `test_vaccines_api.py`, `test_vaccines_frontend.py` e `test_serve_frontend.py` corridos isoladamente agora: exit 0, 0 `[FALHOU]` cada. Suite completa: **79/81** (81 ficheiros `test_*.py` em `git ls-files`); as 2 falhas são `test_ml_training.py` e `test_export_raw_events.py` (ver Advisory 1), nenhuma toca em código ou testes de vaccines |
| 4 | `docs/DATA_MODEL.md` define a entidade Vaccine, `docs/ROADMAP_STATUS.md` marca o R11 como concluído (✅) e `README.md` e `CLAUDE.md` descrevem o motor, o store e a rota | VERIFIED | `docs/DATA_MODEL.md:203` `## Vaccine (R11)`; `docs/API.md:362` `## 💉 Vaccines (R11)`; `docs/ROADMAP_STATUS.md:29` linha R11 com ✅ e secção `## R11 — verificado por máquina...` (l.104); `README.md:155-163` secção Vaccines e árvore (l.420); `CLAUDE.md:179-181` `vaccine_engine.py`, `vaccine_store.py`, `vaccine_ingest.py`, `vaccines.js`. Nenhuma doc descreve uma vaccine como aplicada/aprovada |

**Score:** 4/4 truths verified (0 present-but-behavior-unverified).

### Advisory (não bloqueia)

1. **Suite completa 79/81 neste checkout, por estado local do registo de modelos (não por código de vaccines).** `test_ml_training.py` (secção 14: "`scripts/models/` tem exactamente os dois .pkl legados", "nenhuma pasta de versão", "nem ACTIVE") e `test_export_raw_events.py` (f) assumem que `scripts/models/` (gitignored) só tem os dois `.pkl` legados. Desde 2026-10-28 11:38 existem `scripts/models/ACTIVE` (`v1`) e `scripts/models/v1/` (a adoção do modelo pelo utilizador), por isso estes checks falham, também isolados. Os dois testes pertencem às fases do R9/R10, não à Fase 14; num clone limpo a suite não vê esse estado. Recomenda-se, em trabalho futuro, tornar esses dois testes independentes do estado real de `scripts/models/` (por exemplo, com `SENTRYLENS_MODELS_DIR` temporário) ou registar a dívida em `docs/ROADMAP_STATUS.md`.
2. **Docs com valores entretanto desatualizados** (manutenção, não gap da fase): (a) `docs/DATA_MODEL.md` l.296 e l.444 e `docs/ROADMAP_STATUS.md` l.83 dizem "teto de 1000" para os alertas das vaccines, mas o loop usa agora `ATTACK_ALERTS_SIZE = 8000` (`main.py:1725`, commit `0f62f0c`, que o próprio commit descreve como paliativo); (b) contagens de ficheiros de teste: `README.md:424` diz 48, `docs/ROADMAP_STATUS.md:42` diz 45, `CLAUDE.md:83` diz 80, real 81; (c) `docs/ROADMAP_STATUS.md:27` (R9) ainda diz que `scripts/models/` só tem os `.pkl` legados, sem `vN/`/`ACTIVE`, o que deixou de ser verdade a 2026-10-28.
3. **Caso "vaccine substituída" sem prova de browser.** O UAT 1 e 3 aceitaram sem exercitar a linha esbatida "Substituída por <id>" e a cadeia com vaccine substituída por não existir nenhuma no store. Está coberto por texto/lógica em `test_vaccines_frontend.py` (`vac-row-superseded`, "Substituída por", "Substitui", "Cadeia indisponível" presentes e a funcionar sobre o store semeado), mas não por render real. Reverificar quando um segundo ataque mudar o veredito de um existente.
4. **`Mode: mvp` no ROADMAP.md não corresponde ao formato de User Story.** `ROADMAP.md` declara `**Mode:** mvp` para a Phase 14, mas o goal não está no formato "As a / I want to / so that" (`user-story.validate` devolve `valid: false`, igual ao relatório anterior). A fase foi planeada e executada como fase comum (o `14-01-PLAN.md` documenta-o); por isso verificou-se com a metodologia goal-backward padrão, sem a secção "User Flow Coverage". Decisão de processo para o condutor humano (remover o `Mode: mvp` desta fase ou correr `/gsd-mvp-phase 14`), não é um gap de implementação.

### Required Artifacts

| Artifact | Status | Details |
|----------|--------|---------|
| `vaccines.js` | VERIFIED | Existe, substantivo, ligado (`index.html:1857`, whitelist), dados reais via `apiRequest` para `GET /api/vaccines[/{id}]`; sem `fetch(` direto; sem marcadores de dívida |
| `index.html` (aba, filtros, detalhe, aviso fixo) | VERIFIED | Aba, filtros e painel de detalhe presentes; confirmados pelos blocos do teste estático e no UAT |
| `style.css` (`vac-*`) | VERIFIED | Classes `vac-*` verificadas pelo teste sobre o CSS servido |
| `scripts/serve_frontend.py` | VERIFIED | `ALLOWED_FILES["/vaccines.js"]`; `test_serve_frontend.py` verde depois da mudança para `ThreadingHTTPServer` |
| `scripts/test_vaccines_frontend.py` | VERIFIED | Exit 0, 0 `[FALHOU]` |
| `scripts/vaccine_engine.py`, `vaccine_store.py`, `vaccine_ingest.py` | VERIFIED | Respetivos testes verdes (exit 0); loop ligado em `main.py` (vaccine gerada a partir do ataque real id=14, UAT 4) |
| `docs/API.md`, `docs/DATA_MODEL.md`, `docs/ROADMAP_STATUS.md`, `README.md`, `CLAUDE.md` | VERIFIED | Ver truth 4; valores desatualizados registados no Advisory 2 |

### Key Link Verification

| From | To | Via | Status |
|------|----|-----|--------|
| sidebar `data-tab="vaccines"` | `#tab-vaccines` | ativação de aba genérica (`router.js`) | WIRED |
| `vaccines.js` | `GET /api/vaccines[/{id}]` | `apiRequest` (`api.js`) com `X-API-Key` | WIRED |
| `vaccines.js` | `scripts/serve_frontend.py` | `ALLOWED_FILES["/vaccines.js"]` | WIRED |
| `main._vaccine_loop` | `vaccine_store` / `GET /api/vaccines` | `persist_vaccines` -> SQLite -> rota; vaccine real `vac-a09c1541972a` visível na aba (UAT 1) | WIRED |

### Data-Flow Trace (Level 4)

| Artifact | Dado | Fonte | Real | Status |
|----------|------|-------|------|--------|
| lista (`vacRowsHtml`) | `envelope.vaccines` | `GET /api/vaccines` -> `vaccine_store` | Sim (vaccine real #14 / T1110 no UAT) | FLOWING |
| detalhe | `envelope.vaccine` + 2.º GET por `attack_id` | idem | Sim | FLOWING |
| linha do gerador | `envelope.generator` | `VaccineLoopState` | Sim ("Última execução há <1 min" no UAT) | FLOWING |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Aba Vaccines (todos os blocos) | `test_vaccines_frontend.py` | exit 0, 0 `[FALHOU]` | PASS |
| Whitelist serve `/vaccines.js` | `test_serve_frontend.py` | exit 0 | PASS |
| Rotas `/api/vaccines` | `test_vaccines_api.py` | exit 0 | PASS |
| Motor / store / ingest | `test_vaccine_engine.py`, `test_vaccine_store.py`, `test_vaccine_ingest.py` | exit 0 cada | PASS |
| Suite completa sem Wazuh | `python run_all_tests.py` | 79/81; falham `test_ml_training.py` e `test_export_raw_events.py` por `scripts/models/` com `ACTIVE`+`v1` local (Advisory 1) | PASS com ressalva |

### Probe Execution

SKIPPED (a fase não declara probes; nenhum `scripts/*/tests/probe-*.sh`).

### Requirements Coverage

| Requirement | Plans | Description | Status | Evidence |
|-------------|-------|-------------|--------|----------|
| VAC-07 | 14-01, 14-02, 14-03 | Aba Vaccines com filtros, detalhe e "Sem dados" honesto | SATISFIED | Truths 1 e 2; UAT 1-3 pass |
| VAC-08 | 14-01, 14-04 | Testes standalone sem Wazuh e documentação do R11 | SATISFIED | Truths 3 e 4 |

Sem requisitos órfãos.

### Anti-Patterns Found

Nenhum. `grep` por `TBD|FIXME|XXX|TODO|HACK` em `vaccines.js`, `scripts/test_vaccines_frontend.py` e `scripts/vaccine_*.py` devolve vazio (nenhum marcador de dívida).

### Human Verification

Resolvida. Os 4 itens do relatório anterior foram executados e registados em `14-UAT.md` (`status: complete`, 4/4 pass, verificação via Playwright em 2026-10-29 e aceite pelo utilizador):

| # | Item | Resultado | Nota |
|---|------|-----------|------|
| 1 | Filtros, Atualizar, badges, linha do gerador | pass | Ressalva aceite: vaccine substituída esbatida não exercitada (sem dados) |
| 2 | Backend indisponível + Atualizar | pass | Simulado bloqueando os pedidos no browser (o backend não foi parado) |
| 3 | Teclado, detalhe e cadeia | pass | Cadeia com vaccine substituída não exercitada (sem dados) |
| 4 | Ataque não detetado ponta a ponta | pass | Confirmado no backend (vaccine gerada após 600 s), não na aba nesse momento; a aba mostrou a vaccine no UAT 1 |

### Gaps Summary

Nenhum gap. Os quatro critérios do ROADMAP estão verificados contra o código atual e os itens humanos estão fechados. Ficam registados, sem bloquear, os 4 advisories acima.

---

_Verified: 2026-10-29_
_Verifier: Claude (gsd-verifier)_
