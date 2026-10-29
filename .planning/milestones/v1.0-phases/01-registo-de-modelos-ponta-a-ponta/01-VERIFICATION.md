---
phase: 01-registo-de-modelos-ponta-a-ponta
verified: 2026-10-10
status: human_needed
plans: 4/4
audit_acknowledged:
  milestone: v1.1
  at: 2026-10-29
  status: human_needed
---

# Verificação — Fase 1: Registo de modelos ponta a ponta

Verificação feita pelo orquestrador depois da execução dos 4 planos (3 waves), por confronto
directo com os 5 Success Criteria do ROADMAP e com o contrato do `SKELETON.md`.

## Estado dos planos

| Plano | Wave | Commits | Estado |
|-------|------|---------|--------|
| 01-01 | 1 | `36724f6`, `cbbefd6`, `b9155af`, `6703532` | Completo |
| 01-02 | 2 | `a1e4001`, `2605b32`, `d5ba48a` | Completo |
| 01-03 | 2 | `efd8a9b`, `1f584c5`, `8e27f21` | Completo |
| 01-04 | 3 | `5a861e8`, `f6ea5c7`, `38472e2`, `eec7471`, `cfd2bcf` | Completo |

## Success Criteria do ROADMAP

### 1. `GET /api/ml/models` com API key — PASS (verificado contra o registo real)

Verificado directamente (TestClient, `scripts/models/` real do repositório):

- Sem `X-API-Key` → **401**.
- Com key → **200**, `active: "legacy"`, `active_error: null`, `total: 1`, com a entrada
  `{"id": null, "kind": "legacy", "label": "legado, sem metadados", "active": true,
  "status": "no_metadata", "error_code": null, "metadata": null, "evaluation": null,
  "files": {...}}` — `files` com `size_bytes` e `modified_at` dos dois `.pkl` reais.
- Pasta vazia ou inexistente → 200 com `active: null`, `versions: []`, `total: 0`
  (coberto por `test_ml_models_api.py`, casos b/c).
- A chave `evaluation` existe no contrato e vale `null` (D-05: a Fase 2 é que a preenche).

### 2. Só com os `.pkl` soltos — PASS

O modelo real em `scripts/models/` é reconhecido como legado e **continua a carregar**:
depois do pedido, `GET /api/ml/models` devolve `loaded: "legacy"`, o que só acontece
depois de um `joblib.load` bem-sucedido (`ml_anomalies.loaded_version()`).
`/api/ml-anomalies` devolveu 502 com o Wazuh Indexer desligado — comportamento esperado e
alheio ao registo (não há alertas para classificar); a resposta não contém caminho nem
texto de exceção. `run_all_tests.py`: **36/36 verdes**, sem regressão em `test_ml_anomalies`.

### 3. `python model_registry.py adopt` — PASS (automatizado)

`model_registry.py adopt` existe e está exposto no CLI (`--help` mostra o subcomando).
Cópia atómica para `v1/`, originais intactos, `ACTIVE` escrito só se não existir (D-01) e
retomada de um adopt interrompido: `test_model_registry.py` com **267 checks** e
`test_ml_models_api.py` com **142 checks**, ambos verdes. `scripts/models/` real continua
com os dois `.pkl` originais e sem `v1/` nem `ACTIVE` (nenhum teste toca no disco do
utilizador).

### 4. Integridade e códigos estáveis — PASS

- `hash_mismatch` é recusado **antes** de qualquer `joblib.load`: o teste conta as chamadas e
  fixa o valor a 0 com um byte trocado em `isolation_forest.pkl` **ou** em `scaler.pkl`. O
  caminho bom usa pickles reais, para o teste não passar a vácuo.
- O hash é calculado sobre os mesmos bytes que chegam ao `joblib.load`
  (`joblib.load(io.BytesIO(source.model_bytes))` — sem qualquer `joblib.load` com caminho de
  ficheiro no código).
- `ACTIVE` com `../x`, gravado em UTF-16, com mais de 64 bytes ou a apontar para uma pasta
  inexistente → `active: null` + `active_error` de D-06; `resolve_version_dir` recusa
  qualquer `candidate.parent != root`, incluindo symlink/junction para fora de `models/`.
- Respostas de erro: só o código em `detail`, nunca `str(e)` nem caminhos; `registry_unavailable`
  dá 503 tanto a partir de um `ModelRegistryError` como de uma exceção inesperada (causa só no
  log). `/api/ml-anomalies` e `/api/redblue/metrics` dão 503 com código em vez de 500.

### 5. Abas Models e Evaluation reais — PASS (automatizado; falta o browser)

- `index.html` não tem nenhum `data-planned="R9"`; os botões Models e Evaluation são
  `nav-item` com `data-tab`, e o Training (R10) continua planeado.
- `ml_models.js` está na whitelist de `serve_frontend.py` (`/ml_models.js` servido como
  JavaScript, check em `test_serve_frontend.py`).
- A aba Models lista versões, distingue ativa / adotada / legada / erro, avisa quando
  `active_error` ou quando `loaded != active`, e tem painel de detalhe por versão com
  "desconhecido" para valores `null`. A Evaluation mostra "Sem avaliação".
- `test_ml_models_ui.py`: 185 checks Node verdes sobre os helpers puros carregados em
  `node:vm`; `test_serve_frontend.py` protege a whitelist, a sidebar e o prefixo `mlm`.

## Verificações automatizadas (executadas pelo orquestrador)

| Comando | Resultado |
|---------|-----------|
| `scripts\.venv\Scripts\python run_all_tests.py` | **36/36 verdes** |
| `node --check ml_models.js` | exit 0 |
| `model_registry.py --help` | exit 0, mostra `adopt` |
| `git log --format=%B 13c36f5..HEAD \| grep -i "co-authored-by\|generated with"` | vazio |

## Em aberto

**Verificação humana (não executada — nenhum serviço foi arrancado nesta sessão):**

1. Abrir `http://localhost:5500/index.html`, clicar em "📦 Models" e "📐 Evaluation" e
   confirmar que abrem painéis reais (não o painel genérico de secção planeada).
2. Confirmar os badges no browser: "legado, sem metadados" + "ativa", e depois de um `adopt`
   real os badges "ativa" + "adotado" e a entrada do legado desaparecida.
3. Confirmar a seleção por teclado (Enter/Espaço numa linha com foco) e o detalhe com
   "desconhecido" nos campos `null`.
4. Confirmar o aviso de reiniciar o backend depois de um `adopt` (a cache é por processo).

Os testes cobrem a camada pura em `node:vm`; a camada DOM (`mlmRenderDetail`, `mlmSelectEntry`,
`.selected`, `panel.hidden`) nunca correu num browser.

**Dívidas aceite, registadas no STATE.md:**

- **D-04:** o SHA-256 deteta corrupção e troca acidental mas **não autentica** — quem escreve
  em `models/` reescreve o `metadata.json`. O legado carrega sem verificação até ao `adopt`.
  A documentação da Fase 3 tem de manter esta honestidade.
- Risco residual **T-01-14**: campos novos no `metadata.json` nas Fases 2/3 têm de entrar por
  `escapeHtml`/`mlmCell` — nenhum teste os apanha automaticamente.
- DOC-01 (Fase 3) tem de documentar o comando `adopt` em `README.md`, `CLAUDE.md` e
  `docs/ROADMAP_STATUS.md`.
