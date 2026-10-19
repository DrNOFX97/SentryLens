---
phase: 14-aba-vaccines-testes-e-documenta-o
plan: 03
subsystem: frontend
tags: [vaccines, dashboard, detail-panel, chain, read-only, static-contract, escapeHtml]

requires:
  - phase: 14-aba-vaccines-testes-e-documenta-o
    provides: "14-01/14-02: aba Vaccines (vaccines.js), filtros, gerador, badges, run_tracer/run_guards/run_filters/run_states"
  - phase: 13-store-e-api-de-leitura
    provides: "GET /api/vaccines/{id} e GET /api/vaccines com attack_id e include_superseded"
provides:
  - "Painel #vaccine-detail-panel com aviso fixo 'Proposta — não aplicada no Wazuh' e blocos Origem, Propostas e Cadeia"
  - "vacSelect (clique, Enter, Espaço) com guarda anti-corrida vacSelectSeq e erros por código estável"
  - "Cadeia 'Substituída por' / 'Substitui' calculada por um segundo GET só de leitura, com 'Cadeia indisponível' em falha"
  - "run_detail e run_chain em test_vaccines_frontend.py"
affects: [14-04 documentação e fecho da fase]

status: complete
plan_head_before: 6042ce4acaae270c06ebb0c8a2ef499bcf6b2caa
plan_head_after: 802b8fb862177c1d121ae03e17cfb0b5c90513db

actuals:
  tokens: 4500
  tasks: 2
  commits: 2

tech-stack:
  added: []
  patterns:
    - "Detalhe só texto (D-07): ids de incidente e de ataque via vacCell, sem links nem navegação"
    - "vacSelectSeq verificado depois de cada await (detalhe e cadeia): resposta tardia nunca sobrepõe a seleção mais recente"
    - "O erro da cadeia mostra o que a própria vaccine já diz mais 'Cadeia indisponível: <frase do código>', nunca 'não substitui nenhuma'"
    - "vacLabel com hasOwnProperty para mapas de rótulos indexados por valores do servidor"

key-files:
  created: []
  modified:
    - index.html
    - vaccines.js
    - style.css
    - scripts/test_vaccines_frontend.py

key-decisions:
  - "Cadeia calculada no cliente: 'Substitui' não existe na API (só superseded_by), por isso um GET attack_id + include_superseded=true + limit=500 e vacReplacedIds"
  - "vacChainLead é a única fonte do texto 'Substituída por X.' / 'Atual', usada tanto no HTML da cadeia como no texto de erro"
  - "Commits com o prefixo feat(14-03) por instrução do orquestrador (o plano sugeria feat(vaccines-ui))"

requirements-completed: []

coverage:
  - id: D1
    description: "Clicar/Enter/Espaço numa linha abre o detalhe com Origem, Propostas e o aviso fixo; erros do detalhe como banner com a frase do código"
    requirement: VAC-07
    verification:
      - kind: unit
        ref: "scripts/test_vaccines_frontend.py (run_detail, rota real com TestClient)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Cadeia Substituída por / Substitui por segundo GET de leitura; falha diz 'Cadeia indisponível'; sem links"
    requirement: VAC-07
    verification:
      - kind: unit
        ref: "scripts/test_vaccines_frontend.py (run_chain)"
        status: pass
      - kind: manual
        ref: "Task 2 human-check (leitura do detalhe, foco por teclado, aspeto visual) - pendente, juntado ao UAT no fim da fase"
        status: pending
    human_judgment: true
---

# Phase 14 Plan 03: Detalhe da vaccine e cadeia Summary

**Clicar (ou Enter/Espaço) numa linha da aba Vaccines abre o painel de detalhe com a Origem (ataque, cenário, MITRE, incidentes como texto, sensores, evidência por referência), as Propostas (regra com Event IDs, janela e eventos com nome/severidade, ou a recomendação) e a Cadeia (Substituída por / Substitui), sempre com o aviso fixo "Proposta — não aplicada no Wazuh"; erros aparecem como banner com a frase do código e respostas fora de ordem são ignoradas.**

## Performance

- **Tasks:** 2 (1 tracer + 1 auto/tdd)
- **Files modified:** 4 (nenhum criado)
- **Commits:** 2 (medidos pelo ledger, `plan_head_before` -> `plan_head_after`)

## Accomplishments

- **Task 1 (tracer, `7deedfc`):** `index.html` ganha `#vaccine-detail-panel` (hidden) dentro de `#tab-vaccines`, a seguir a `#vaccines-panel`, com `#vac-detail-title`, `#vac-detail-warning` (classe `vac-not-applied`, texto estático), e os blocos Origem/Propostas/Cadeia. `vaccines.js`: `VAC_ID_RE`, `VAC_EXPECTED_SOURCE_LABELS`, `vacSelectedId`, `vacSelectSeq`, `vacList`, `vacLabel`, `vacAttackLabel`, `vacSourceNote`, `vacOriginHtml`, `vacEventRowsHtml`, `vacRuleHtml`, `vacRecommendationHtml`, `vacProposalsHtml`, `vacChainHtml`, `vacRenderDetail`, `vacRenderDetailError`, `vacSelect`, mais os listeners de clique e teclado em `#vac-body`; `vacRowClass` acrescenta ` selected` para a seleção sobreviver a um Atualizar. `style.css`: `.vac-not-applied` e `.vac-proposal`. `run_detail` (teste primeiro, falhou 14 checks antes da implementação) cobre markup, literais, contrato de campos contra as respostas reais e a rota real (A substituída por B, C com incidente INC-20261012-1 e técnica T1053 e uma só proposta ml, B com regra [5140, 5145] 1 ocorrência 300 s, 404 `entry_not_found`).
- **Task 2 (`802b8fb`):** `vacChainLead` (fonte única do texto da cadeia), `vacChainHtml(vaccine, replacedIds)`, `vacReplacedIds(vaccines, id)` e `vacLoadChain(vaccine, seq)` (segundo GET `attack_id` + `include_superseded=true` + `limit=500`, `seq !== vacSelectSeq` na resposta e no erro; em falha, texto simples "…Cadeia indisponível: <vacErrorText>"). `vacSelect` chama `vacLoadChain` sem bloquear o resto do detalhe. `run_chain` (teste primeiro, 7 checks a falhar) fixa as funções, os textos, a ausência de `<a`/`href`/`activateTab(`/`location.hash` e, na rota real, `attack_id=2&include_superseded=true` -> B, A (A com `superseded_by` B) e `attack_id=3&...` -> só C.
- Verificação adicional fora do teste estático: as funções novas foram corridas em node (vm com stubs de DOM) sobre uma vaccine de exemplo com `<` no cenário e no nome do evento (saem escapados), com a cadeia a dar "Substitui: vac-ed793c0b3437" e, com o segundo pedido a falhar 503, "Cadeia indisponível: O store de vaccines… não pôde ser lido".

## Task Commits

1. **Task 1: Tracer detalhe com Origem e Propostas** — `7deedfc` (feat(14-03))
2. **Task 2: Cadeia substituída por / substitui** — `802b8fb` (feat(14-03))

## Deviations from Plan

**1. [Instrução do orquestrador] Prefixo dos commits** — o plano sugeria `feat(vaccines-ui): ...`; os commits usam `feat(14-03): ...` como exigido. Sem outra consequência.

**2. [Critério de aceitação desatualizado] `data-tab="soc-team"` no index.html commitado** — o critério da Task 1 esperava 0 ocorrências em `git show HEAD:index.html`; dá 1. Esse markup (aba Equipa SOC) já estava em `HEAD~1` desde o commit `a4bbc72` (anterior a esta fase), não vem deste plano. `git diff --quiet -- index.html style.css` saiu 0 antes de qualquer edição, ou seja, não havia trabalho alheio por commitar nesses dois ficheiros. O critério reflete o estado da árvore quando o plano foi escrito.

**3. [Escolha de implementação] `vacChainHtml` sem `<strong>` à volta do id substituto** — a linha "Substituída por X." sai de `vacChainLead` para a mesma frase servir o HTML e o texto de erro. Sem impacto funcional.

Sem desvios de comportamento além destes.

## Procedimento C

Não foi necessário. `git diff --quiet -- index.html style.css` saiu 0 antes de qualquer edição em ambos, por isso foram editados e adicionados normalmente (`git add` explícito dos quatro ficheiros). `.planning/config.json`, `.github/`, `packer/`, `scripts/.venv2/`, `.planning/state.json`, `.planning/milestone.lock` e `scripts/setup-boot-lab-entry.ps1` ficaram intocados.

## Verification

- `test_vaccines_frontend.py` (run_tracer, run_guards, run_filters, run_states, run_detail, run_chain): exit 0, 0 `[FALHOU]`.
- `run_all_tests.py vaccine`: 5/5.
- `run_all_tests.py` (suite completa): **45/45** (`git ls-files 'scripts/test_*.py'` mede 45).
- `git diff --quiet 878d8e5 HEAD -- app.js` -> 0; `git status --porcelain -- vaccines.js scripts/test_vaccines_frontend.py` vazio; nenhum `Co-Authored-By` nos commits do plano (`git log 6042ce4..HEAD`).
- Provas das proibições: VAC-02 no ecrã (chaves reais sem command/argv/build_command/tool/target/source/operator; `vaccines.js` só lê chaves reais), sem links (run_chain), sem "Sem dados" em erro (run_detail, run_chain).

## Known Stubs

Nenhum.

## Known Follow-ups (fora do âmbito)

- O `<human-check>` da Task 2 (ler o detalhe no browser, Tab + Enter, "Incluir substituídas" e abrir uma substituída, linha destacada depois de Atualizar, sem links) fica juntado ao UAT no fim da fase (D-09: sem browser automatizado).
- Links do detalhe para Incidentes/Attack Registry ficam nas Deferred Ideas (D-07).
- VAC-07/VAC-08 continuam por fechar: só o 14-04 fecha a fase.

## Threat Flags

Nenhum: sem superfície nova. Mitigações aplicadas: T-14-08 (todos os valores por `vacCell`/`escapeHtml`, título por `textContent`, cobertos pelos varrimentos de `run_guards`), T-14-09 (`VAC_ID_RE` + `encodeURIComponent`), T-14-10 (`vacSelectSeq` em `vacSelect` e `vacLoadChain`), T-14-11 (aviso fixo no HTML estático), T-14-12 (só frases de `VAC_ERROR_TEXT`), T-14-13 (sem links).

## Self-Check: PASSED

- `index.html`, `vaccines.js`, `style.css`, `scripts/test_vaccines_frontend.py` existem; commits `7deedfc` e `802b8fb` existem.
