# Milestones

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
