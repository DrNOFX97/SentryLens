# Milestones

## v1.1 R11 Vaccine Engine (Shipped: 2026-10-29)

**Phases completed:** 3 phases, 10 plans, 16 tasks

**Key accomplishments:**
- Motor puro `build_vaccine_candidates` que, sobre o registo real de ataques, propõe uma regra de deteção rastreável (proposals[] por sensor em falta, id sha256 determinístico fixado por literais) e conta cada ataque saltado em vez de o omitir.
- `validate_vaccine` com contrato fechado e allowlist por campo (nenhum comando passa, provado por varrimento de todas as strings, 27 negativos e um log hostil pelo registo real) e envelope de três estados que nunca inventa vaccines (`no_data`, `source_unavailable`, ou `reason None`).
- `attack_scenarios.run_scenario` passa a gravar um `id` inteiro (max+1 sobre os ids válidos do próprio log, teto 999_999_999, fail-closed antes de lançar nada) em todas as entradas novas, e um teste prova o caminho escritor real -> disco -> leitor real -> registo -> motor até à vaccine validada (VAC-03).
- Store SQLite de vaccines com estado `proposed` imposto pelo proprio ficheiro, ciclo do backend que grava so vaccines validadas de ataques assentes, e GET /api/vaccines[/{id}] so de leitura com API key.
- O backend gera vaccines sozinho num loop registado no arranque, e GET /api/vaccines expoe no bloco `generator` o estado da ultima execucao com codigos estaveis, para que "Indexer indisponivel" chegue ao analista como codigo e nao como lista vazia.
- GET /api/vaccines filtra por ataque, tecnica MITRE e include_superseded, e as garantias negativas do ROADMAP (sem escrita, API key por rota, estado proposed, 503 sem fuga) ficam presas por teste.
- Aba Vaccines ponta a ponta: 💉 Candidates abre `#tab-vaccines`, `vaccines.js` (servido pela whitelist, carregado depois de `app.js`) lista `GET /api/vaccines` em 8 colunas com `X-API-Key`, com "Sem dados" so para `no_data` e erros com a frase do codigo; blindada por um teste estatico ligado as chaves reais da rota.
- A aba Vaccines passa a filtrar no servidor (ataque, tecnica MITRE, incluir substituidas) com botao Atualizar, mostra o estado do gerador ("Ultima execucao ha X min" ou a frase do codigo estavel de erro), desenha o veredito em badge e esbate as vaccines substituidas com "Substituida por <id>"; tudo preso por run_filters/run_states ligados a rota real.
- Clicar (ou Enter/Espaço) numa linha da aba Vaccines abre o painel de detalhe com a Origem (ataque, cenário, MITRE, incidentes como texto, sensores, evidência por referência), as Propostas (regra com Event IDs, janela e eventos com nome/severidade, ou a recomendação) e a Cadeia (Substituída por / Substitui), sempre com o aviso fixo "Proposta — não aplicada no Wazuh"; erros aparecem como banner com a frase do código e respostas fora de ordem são ignoradas.
- A entidade Vaccine e as duas rotas ficam documentadas contra o código (53 chaves verificadas por script), o R11 passa a concluído no Roadmap v2 com a dívida e o flake da suite registados, README e CLAUDE.md descrevem motor, store, loop, rotas e aba com as contagens reais, e `run_all_tests.py` termina 45/45 com código 0 numa única execução completa.

---

## v1.0 ML Registry & Learning Loop (Shipped: 2026-10-11)

**Phases completed:** 5 phases, 17 plans, 26 tasks

**Key accomplishments:**
- Registo de modelos ML em disco lido por um módulo de domínio stdlib-puro, exposto por `GET /api/ml/models` autenticado por API key, com as abas Models e Evaluation do dashboard a mostrarem as versões e o estado honesto "Sem avaliação".
- SHA-256 conferido sobre os mesmos bytes que chegam ao `joblib.load`, modelo legado reconhecido como "legado, sem metadados" e ativo, e rotas de deteção a devolver 503 com código estável em vez de 500.
- A aba Models passou a distinguir ativa, legado, adotada e versões com problema com mensagens PT acionáveis, e a dizer quando é preciso reiniciar o backend; selecionar uma versão (rato ou Enter/Espaço) abre um painel de detalhe com os SHA-256, os tamanhos e todos os metadados, com "desconhecido" em cada valor em falta.
- `python model_registry.py adopt` regista o modelo actual como `v1` por cópia — originais intactos, `ACTIVE` só quando não existe, e um adopt interrompido na escrita do `ACTIVE` recupera-se voltando a correr o mesmo comando.

- R10: treino e ativação por HTTP (`POST /api/ml/train`, `POST /api/ml/models/{id}/activate`) com as quatro protecções de D-01, `catalog_sha256`/`feature_stats` no `metadata.json`, compare-and-set no `ACTIVE`, e no dashboard o botão Treinar com a UX honesta do `loaded != active` e a comparação vN vs vN-1.

**Closeout:** `override_closeout` — sem VERIFICATION `passed` nas fases 3, 10 e 11 e sem MILESTONE-AUDIT.

### Known Gaps

- REQUIREMENTS.md arquivado com 16 requisitos por marcar `[x]` (REG-01..04, SEC-01/02, EVAL-01..03, API-01/02, UI-01..03, TST-01, DOC-01), embora o código esteja entregue; REG-04, TST-01 e DOC-01 constavam como Pending.
- SUMMARY.md em falta: fase 3 (2/3) e fase 11 (1/3), apesar de STATE.md e commits as darem como concluídas.
- Por verificar em humano: badges/detalhe por teclado, aviso após `adopt`, avaliação rotulada. Nenhuma versão treinada (`vN/`) existe ainda em `scripts/models/`.

---
