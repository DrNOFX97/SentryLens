# Phase 1: Registo de modelos ponta a ponta - Context

**Gathered:** 2026-10-09
**Status:** Ready for planning
**Origem:** não houve `/gsd-discuss-phase` nesta fase. D-01..D-05 resolvem as Open Questions do `01-RESEARCH.md` (secção "Open Questions (RESOLVED)"); D-06..D-08 vêm do orquestrador do plan-phase e das regras do projeto (`CLAUDE.md`). Este ficheiro regista-as num só sítio para rastreabilidade; os planos `01-01`..`01-04` citam-nas por id.

<domain>
## Phase Boundary

O analista abre a aba Models e vê as versões de modelo (incluindo o modelo legado), qual está ativa e os metadados de cada uma, com o carregamento do modelo protegido por verificação de integridade.

Requisitos: REG-01, REG-02, REG-03, SEC-01, SEC-02, API-01, API-02, UI-01, UI-03. Avaliação por versão (Fase 2) e treino a gerar versões (Fase 3) ficam fora.

</domain>

<decisions>
## Implementation Decisions

### Adoção do modelo legado
- **D-01:** `python model_registry.py adopt` escreve `models/ACTIVE` só se ainda não existir. Se já existir, não lhe toca e avisa no CLI como ativar a v1 à mão.
  - Porquê: um `ACTIVE` existente foi escrito pelo utilizador ou aponta para outra versão; reescrevê-lo mudaria em silêncio o modelo usado nas deteções.
- **D-03:** depois de adotado, o legado deixa de aparecer na lista (a entrada "legado, sem metadados" só existe enquanto `models/v1` não existe e o `ACTIVE` não aponta para uma versão válida). Os `.pkl` soltos nunca são movidos nem apagados.
  - Porquê: evitar duas entradas para o mesmo modelo; os originais ficam intactos como cópia de segurança e como fonte do REG-02.

### Estado do processo
- **D-02:** o relatório de `GET /api/ml/models` expõe `loaded`, a versão que `ml_anomalies` tem de facto em memória (`"vN"`, `"legacy"` ou `null`).
  - Porquê: a cache do modelo é por processo; depois de um adopt (ou de um treino na Fase 3) o processo continua a servir o modelo antigo até reiniciar, e o dashboard não pode afirmar que a versão ativa é a usada nas deteções.

### Integridade
- **D-04:** integridade por SHA-256 de cada `.pkl` gravado no `metadata.json`, comparado antes de qualquer `joblib.load`. HMAC ou assinatura ficam fora do âmbito do R9. Fica registado como dívida de segurança nas ameaças T-01-09 (01-02) e T-01-21 (01-04).
  - Porquê: o REQUIREMENTS fixa SHA-256. O hash deteta corrupção e troca acidental mas não autentica: quem consegue escrever em `models/` também reescreve o `metadata.json`. A documentação nunca pode dizer que o hash "autentica" o modelo.

### Frontend
- **D-05:** a Fase 1 não cria `ml_evaluation.js`. A aba Evaluation vive em `ml_models.js` e mostra o estado honesto "Sem avaliação" em cada versão.
  - Porquê: nenhuma versão tem avaliação até à Fase 2; um módulo separado só com um estado vazio obrigaria a uma entrada nova na whitelist do `serve_frontend.py` sem conteúdo. A Fase 2 cria o `ml_evaluation.js`.

### Erros
- **D-06:** lista fechada de 9 códigos de erro: `invalid_version_id`, `active_not_found`, `metadata_missing`, `metadata_invalid`, `artifact_missing`, `hash_mismatch`, `already_adopted`, `no_legacy_model`, `registry_unavailable`. Por HTTP só passa o código no `detail`; as mensagens PT ficam no CLI (`MESSAGES_PT`) e no browser (`MLM_ERROR_TEXT`). Nesta fase não se acrescenta nenhum código.
  - Porquê: API-02 (nunca texto de exceção nem caminhos na resposta) e um contrato estável que o frontend e as Fases 2/3 conseguem traduzir sem casos especiais.

### Processo
- **D-07:** tracer-first com Walking Skeleton. O plano 01-01 é a fatia mais fina ponta a ponta (registo em disco → `model_registry.py` → `GET /api/ml/models` com API key → aba Models no dashboard). O `SKELETON.md` fixa o contrato JSON e as decisões de arquitetura que as Fases 2 e 3 consomem, e é mantido em sincronia com os planos.
  - Porquê: provar a arquitetura com um commit antes de acrescentar integridade, adoção e estados de UI.
- **D-08:** commits e PRs sem `Co-Authored-By` e sem "Generated with Claude Code". Aplica-se também a subagentes.
  - Porquê: regra do `CLAUDE.md` do projeto e da memória do utilizador; tem prioridade sobre qualquer lembrete de atribuição do sistema.

### Claude's Discretion
Escolhas do planeador (não são decisões do utilizador; podem mudar sem nova discussão desde que respeitem D-01..D-08):
- `registry_unavailable` é sempre HTTP 503 em `GET /api/ml/models`, venha de um `ModelRegistryError` ou de uma exceção inesperada (esta só fica no `backend.log`). Não se usa 500 com um código próprio porque a lista de códigos é fechada (D-06).
- Adopt interrompido: se o adopt criar a `v1` e falhar só na escrita do `ACTIVE` (bloqueio do OneDrive/antivírus), voltar a correr `adopt` verifica a `v1` existente (metadata válido, `origin` adotado, SHA-256 igual ao dos ficheiros da `v1` e ao do legado) e escreve só o `ACTIVE` em falta. Compatível com D-01: só acontece quando o `ACTIVE` não existe.
- `ml_models.js` separa helpers puros (sem DOM) da camada que escreve no DOM e só arranca (`mlmInit`) quando `document` existe, para os helpers serem testados em Node (`node:vm`) por `scripts/test_ml_models_ui.py` + `scripts/test_ml_models_ui.cjs`.
- Texto exato das mensagens PT e nomes dos helpers privados.

</decisions>

<specifics>
## Specific Ideas

- A aba Models segue o padrão de `attack_library.js` (módulo de aba que reutiliza `API_BASE`, `API_KEY`, `escapeHtml` e `renderPanelError` de `app.js`, sem o editar).
- Mensagens sempre acionáveis em PT: dizer o que fazer (p.ex. "reinicia o backend", "corre python model_registry.py adopt").

</specifics>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Contrato e arquitetura
- `.planning/phases/01-registo-de-modelos-ponta-a-ponta/SKELETON.md` — contrato de `metadata.json` (schema 1), resposta de `GET /api/ml/models`, decisão "o que está ativo", escrita no registo
- `.planning/phases/01-registo-de-modelos-ponta-a-ponta/01-RESEARCH.md` — padrões, pitfalls, Open Questions (RESOLVED) que dão origem a D-01..D-05

### Âmbito e requisitos
- `.planning/REQUIREMENTS.md` — REG-01..03, SEC-01..02, API-01..02, UI-01, UI-03
- `.planning/ROADMAP.md` §"Phase 1" — goal e critérios de sucesso 1-5

### Regras do projeto
- `CLAUDE.md` — API key por rota (`dependencies=_REQUIRE_API_KEY`), whitelist do `serve_frontend.py`, testes standalone, regra de commits (D-08)

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `app.js`: `API_BASE`, `API_KEY`, `escapeHtml`, `renderPanelError`, `activateTab`/`applyHash` (abrem `#tab-ml-models` sem alterações)
- `attack_library.js`: estrutura de módulo de aba, linhas clicáveis com teclado, painel de detalhe com `hidden`
- `style.css`: `.alib-risk` (forma dos badges), `.atk-row`, `.inc-meta`, `.atk-evidence`, `.empty-state`, `.panel-note`

### Established Patterns
- Módulos de domínio puros (`build_*_report`) chamados pelas rotas; testes standalone com `TestClient(main.app)` e `SENTRYLENS_API_KEY` definido antes de `import main`
- `ml_anomalies.load_model()` é o único sítio com `joblib.load`; a cache `_model`/`_scaler` é injetada diretamente por vários testes existentes

### Integration Points
- `scripts/main.py` (rota nova e tratamento de `ModelRegistryError` nas rotas de deteção), `scripts/serve_frontend.py` (`ALLOWED_FILES`), `index.html` (sidebar e painéis)

</code_context>

<deferred>
## Deferred Ideas

- Comando `evaluate`, avaliação gravada por versão e `ml_evaluation.js` — Fase 2
- Treino a gerar versões `vN` novas e ativá-las (REG-04) — Fase 3
- Documentação (`README.md`, `docs/DATA_MODEL.md`, `docs/ROADMAP_STATUS.md`, `CLAUDE.md`) — DOC-01, Fase 3
- HMAC/assinatura dos artefactos — fora do R9 (dívida registada, D-04)
- Ativar/reverter/comparar versões a partir do dashboard — R10
- Cache de hashes por `(mtime, size)` na listagem
- Código de erro próprio para falhas de `joblib.load` sobre bytes verificados (fora da lista fechada, D-06)

</deferred>

---

*Phase: 01-registo-de-modelos-ponta-a-ponta*
*Context gathered: 2026-10-09*
