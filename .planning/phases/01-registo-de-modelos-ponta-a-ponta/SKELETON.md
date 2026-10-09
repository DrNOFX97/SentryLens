# Walking Skeleton — SentryLens (marco R9, registo de modelos)

**Phase:** 1
**Generated:** 2026-10-09

> O SentryLens já existe (backend FastAPI em `scripts/`, frontend estático na raiz). Este esqueleto não cria um projeto novo: é o primeiro *tracer* do marco R9 e fixa as decisões de arquitetura do registo de modelos sobre as quais as Fases 2 e 3 constroem. Trata-o como contrato, não como rascunho.

## Capability Proven End-to-End

O analista abre a aba **📦 Models** do dashboard e vê as versões de modelo lidas de `scripts/models/` (`vN/metadata.json` + `ACTIVE`) através de `GET /api/ml/models` autenticado por API key, com a versão ativa marcada.

## Architectural Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Armazenamento do registo | Sistema de ficheiros: `scripts/models/vN/{isolation_forest.pkl, scaler.pkl, metadata.json}` + ficheiro de texto `scripts/models/ACTIVE` (uma linha UTF-8, p.ex. `v1`). Os `.pkl` soltos em `scripts/models/` são o "legado". Sem SQLite. | Decisão do projeto (PROJECT.md); `scripts/models/` está no `.gitignore`; legível à mão |
| Módulo de domínio | `scripts/model_registry.py`: stdlib pura (`hashlib`, `hmac`, `json`, `pathlib`, `re`, `shutil`, `tempfile`, `os`, `argparse`); **não** importa `joblib`, `ml_anomalies` nem FastAPI; nunca desserializa pickle | Mesmo padrão dos `build_*_report` puros; testável sem Wazuh |
| Único ponto de desserialização | `ml_anomalies.load_model()` — único sítio com `joblib.load`. Na *cache miss* pede a `model_registry.resolve_active_artifacts()` os **bytes já verificados** dos dois `.pkl` e faz `joblib.load(io.BytesIO(bytes))` sobre esses mesmos bytes. A *cache hit* (`_model`/`_scaler` em memória) continua a devolver sem tocar no disco | Sem TOCTOU entre verificar e carregar; os testes existentes injetam `_model`/`_scaler` |
| Integridade | SHA-256 de cada `.pkl` gravado em `metadata.json` (`artifacts.<nome>.sha256`), comparado com `hmac.compare_digest` antes de qualquer `joblib.load`. O legado carrega **sem** verificação até ser adotado (REG-02) | Deteta corrupção/troca acidental. **Não** autentica: quem escreve em `models/` reescreve o `metadata.json` (HMAC fora de âmbito, dívida de segurança registada) |
| Ids de versão | `re.fullmatch(r"v[0-9]{1,4}", id)` + `(root / id).resolve().parent == root.resolve()`; `ACTIVE` lido em binário (≤ 64 bytes), decodificado `utf-8-sig`, `strip()`; falha de decode = `invalid_version_id` | `re.match` com `$` aceita `"v1\n"`; a 2.ª camada cobre junctions/symlinks |
| Nomes dos artefactos | Constante `ARTIFACT_FILES = ("isolation_forest.pkl", "scaler.pkl")`; nunca lidos do `metadata.json` | Nenhum caminho é construído a partir de dados do ficheiro |
| Modelo de erros | `ModelRegistryError(code)` com `.code` estável e `str(exc) == code`. Códigos (fechados): `invalid_version_id`, `active_not_found`, `metadata_missing`, `metadata_invalid`, `artifact_missing`, `hash_mismatch`, `already_adopted`, `no_legacy_model`, `registry_unavailable`. HTTP devolve só o código em `detail`; mensagens PT só no CLI e no browser | API-02: nunca texto de exceção nem caminhos |
| Contrato HTTP | `GET /api/ml/models` (só leitura, `dependencies=_REQUIRE_API_KEY` na própria rota) — ver "Contrato" abaixo | API key por rota, nunca a nível de app (CLAUDE.md) |
| Erros de carregamento nas rotas de deteção | `/api/ml-anomalies` e `/api/redblue/metrics`: `ModelRegistryError` → 503 com `detail=<código>`; `FileNotFoundError` → 503 com mensagem sem caminhos | Hoje só apanham `FileNotFoundError`; um hash adulterado daria 500 |
| CLI | `python model_registry.py <subcomando>` com `argparse` e subcomandos. Fase 1: `adopt [--models-dir DIR]`. A Fase 2 acrescenta `evaluate vN --events <ficheiro>` ao mesmo parser | Um só ponto de entrada para operações de registo |
| Escrita no registo | Só por CLI (nunca por HTTP). Versão nova = pasta temporária `vN.tmp-*` (nome que não casa o regex, logo invisível à listagem) + `shutil.copy2` + `metadata.json` + `os.replace` para `vN`; `ACTIVE` por ficheiro temporário + `os.replace`. Helper privado `_materialize_version()` reutilizável pela Fase 3 (treino) | Atómico; originais só lidos; sem versões a meio |
| Frontend | `ml_models.js` na raiz, servido por `serve_frontend.py` (whitelist). Todos os identificadores de topo com prefixo `mlm`/`MLM_`. Reutiliza `API_BASE`, `API_KEY`, `escapeHtml`, `renderPanelError` de `app.js` (não edita `app.js`). Um só `fetch` a `/api/ml/models` por ativação de aba, partilhado pelas abas Models e Evaluation; recarrega sempre que uma das abas passa de inativa a ativa. Códigos de erro traduzidos por `MLM_ERROR_TEXT`; `detail` nunca é inserido no DOM | Padrão de `attack_library.js`; globais partilhados entre scripts clássicos |
| Abas | `#tab-ml-models` e `#tab-ml-evaluation` (botões da sidebar com `data-tab="ml-models"` / `data-tab="ml-evaluation"`); a navegação de `app.js` (`activateTab`, `applyHash`) já as abre sem alterações | UI-03 |
| Testes | Scripts standalone sem pytest: `scripts/test_model_registry.py` (domínio + CLI) e `scripts/test_ml_models_api.py` (rotas via `TestClient`); `SENTRYLENS_API_KEY` antes de `import main`; `main.app.router.on_startup.clear()`; todo o disco em `tempfile.TemporaryDirectory()`; nunca `scripts/models/` real | Convenção do repo; `run_all_tests.py` descobre-os sozinho |
| Execução local | `.\scripts\start-backend.ps1` (porta 8001) + `.\scripts\start-frontend.ps1` (porta 5500) → `http://localhost:5500/index.html#ml-models`. Depois de `adopt`/treino, **reiniciar o backend** (a cache do modelo é por processo) | Scripts do repo; o campo `loaded` mostra o que o processo tem em memória |

## Contrato

### `scripts/models/vN/metadata.json` (schema 1)

```json
{
  "schema_version": 1,
  "version": "v1",
  "origin": "adopted",
  "adopted": true,
  "created_at": "2026-10-09T21:00:00+00:00",
  "trained_at": "2026-09-14T15:40:00+00:00",
  "trained_at_estimated": true,
  "model_type": "IsolationForest",
  "parameters": null,
  "dataset": {"name": null, "size": null, "attacks": null, "synthetic": null},
  "library_versions": null,
  "artifacts": {
    "isolation_forest.pkl": {"sha256": "<64 hex>", "size_bytes": 539673},
    "scaler.pkl": {"sha256": "<64 hex>", "size_bytes": 767}
  },
  "evaluation": null
}
```

Regras de validade (`load_metadata`): ficheiro ≤ 65 536 bytes; JSON UTF-8 que é um objeto; `schema_version == 1` (int, não bool); `version` igual ao nome da pasta; `artifacts` com uma entrada para cada nome de `ARTIFACT_FILES`, cada uma com `sha256` que casa `[0-9a-fA-F]{64}` (comparado em minúsculas) e `size_bytes` int ≥ 0 (não bool); `evaluation` é `null` ou objeto. Qualquer outra coisa → `metadata_invalid`; sem ficheiro → `metadata_missing`. `origin` é `"adopted"` (Fase 1) ou `"trained"` (Fase 3). Em adotados, `parameters`/`dataset`/`library_versions` ficam `null` (não se desserializa nada no `adopt` e não se inventa o dataset); a Fase 3 preenche-os nas versões treinadas; a Fase 2 substitui `evaluation` por um objeto.

### Resposta de `GET /api/ml/models`

```json
{
  "active": "v1",
  "active_error": null,
  "loaded": "legacy",
  "total": 1,
  "versions": [
    {"id": "v1", "kind": "versioned", "label": "v1", "active": true,
     "status": "ok", "error_code": null,
     "metadata": {"schema_version": 1, "version": "v1", "origin": "adopted", "adopted": true,
                  "created_at": "...", "trained_at": "...", "trained_at_estimated": true,
                  "model_type": "IsolationForest", "parameters": null,
                  "dataset": {"name": null, "size": null, "attacks": null, "synthetic": null},
                  "library_versions": null,
                  "artifacts": {"isolation_forest.pkl": {"sha256": "...", "size_bytes": 539673},
                                "scaler.pkl": {"sha256": "...", "size_bytes": 767}}},
     "evaluation": null}
  ]
}
```

- `active`: `"vN"` | `"legacy"` | `null`. `active_error`: `null` | `"invalid_version_id"` | `"active_not_found"` | `"registry_unavailable"`. `loaded`: o que `ml_anomalies` tem em memória (`"vN"` | `"legacy"` | `null`). Vazio ou pasta inexistente → `{"active": null, "active_error": null, "loaded": null, "total": 0, "versions": []}` com 200.
- Entrada versionada: `status` ∈ `ok`, `metadata_missing`, `metadata_invalid`, `artifact_missing`, `hash_mismatch`, `invalid_version_id`, `registry_unavailable`; `error_code` = `null` se `ok`, senão igual ao `status`. `metadata` = projeção das chaves públicas (`METADATA_PUBLIC_KEYS`) quando o `metadata.json` é válido (também em `artifact_missing`/`hash_mismatch`), senão `null`. `evaluation` = `metadata.json.evaluation` quando válido, senão `null`. Uma versão com problema nunca derruba a lista.
- Entrada legado: `{"id": null, "kind": "legacy", "label": "legado, sem metadados", "active": <bool>, "status": "no_metadata", "error_code": null, "metadata": null, "evaluation": null, "files": {"isolation_forest.pkl": {"size_bytes": N, "modified_at": "<ISO UTC>"}, "scaler.pkl": {...}}}`.
- Ordem: versões por número decrescente, legado no fim. `total == len(versions)`.

### Decisão "o que está ativo" (função única `_active_state`, usada pelo relatório e pelo carregamento)

1. `models/ACTIVE` existe → ler + validar + resolver → `"vN"`. Qualquer falha → `active = null`, `active_error = <código>`; o carregamento recusa com esse código (sem cair para o legado — fail-closed).
2. `ACTIVE` não existe, os dois `.pkl` soltos existem e `models/v1` não existe → `"legacy"` (carrega sem verificação).
3. Caso contrário → `null`; o carregamento levanta `FileNotFoundError` com mensagem sem caminhos (503 como hoje).

A entrada legado aparece só se os dois `.pkl` soltos existem **e** `models/v1` não existe **e** o `ACTIVE` não aponta para uma versão válida (decisão travada 3); `active: true` só quando `active == "legacy"`. Os `.pkl` soltos nunca são movidos nem apagados.

## Stack Touched in Phase 1

- [x] Project scaffold — já existe (FastAPI + estático); a fase acrescenta `scripts/model_registry.py`, `ml_models.js` e dois ficheiros de teste standalone
- [ ] Routing — `GET /api/ml/models` (rota real, API key por rota)
- [ ] "Base de dados" — registo em disco: leitura real (`ACTIVE`, `vN/metadata.json`, SHA-256) e escrita real (`python model_registry.py adopt`)
- [ ] UI — abas Models e Evaluation ligadas à API (botão "Atualizar", seleção de versão com detalhe)
- [ ] Deployment — execução local documentada: `start-backend.ps1` + `start-frontend.ps1` → `http://localhost:5500/index.html#ml-models`

## Out of Scope (Deferred to Later Slices)

- Comando `evaluate`, avaliação gravada por versão e métricas ML contra regras na aba Evaluation (Fase 2; o módulo `ml_evaluation.js` é criado na Fase 2, decisão travada 5)
- Treino a gerar versões `vN` novas e ativá-las (REG-04, Fase 3)
- Documentação (`README.md`, `docs/DATA_MODEL.md`, `docs/ROADMAP_STATUS.md`, `CLAUDE.md`) — DOC-01, Fase 3
- HMAC/assinatura dos artefactos (dívida de segurança registada no modelo de ameaças; decisão travada 4)
- Ativar/reverter versões, treinar ou comparar versões a partir do dashboard (R10)
- Cache de hashes por `(mtime, size)` na listagem
- Código de erro próprio para falhas de `joblib.load` sobre bytes verificados (fora da lista fechada de códigos, decisão travada 6)

## Subsequent Slice Plan

- Phase 2: avaliação ligada à versão — `python model_registry.py evaluate vN --events <ficheiro>` grava `evaluation` no `metadata.json` dessa versão; aba Evaluation mostra ML contra regras por versão e a concordância ao vivo de `/api/ml-anomalies`, sempre com o aviso de amostra pequena.
- Phase 3: cada `train_anomaly_model.py` cria `vN` seguinte via `_materialize_version()` com metadados completos e ativa-a; cobertura de testes TST-01 fechada; documentação DOC-01.
