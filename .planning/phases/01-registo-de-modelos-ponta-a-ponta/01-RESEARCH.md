# Phase 1: Registo de modelos ponta a ponta - Research

**Researched:** 2026-10-09
**Domain:** registo de modelos ML versionado em disco (stdlib), verificação de integridade SHA-256 antes de `joblib.load`, rota FastAPI só-leitura e aba de dashboard em JS vanilla
**Confidence:** HIGH (tudo assenta em código do próprio repo e stdlib; nenhum pacote novo)

> Não existe `01-CONTEXT.md` para esta fase (pasta vazia), por isso não há secção `User Constraints`. As decisões travadas vêm de `REQUIREMENTS.md`, `ROADMAP.md`, `STATE.md` e `CLAUDE.md` (copiadas em "Project Constraints").

## Summary

A fase é pequena do ponto de vista tecnológico: **zero dependências novas** (só `hashlib`, `hmac`, `json`, `pathlib`, `shutil`, `re`, `argparse`, `os` + `joblib` já instalado). O trabalho está em três decisões de desenho: (1) um módulo novo `scripts/model_registry.py`, que não faz HTTP e não faz `joblib.load`, e que é a única fonte de verdade sobre "que versões existem, qual está ativa, os ficheiros batem com o hash?"; (2) `ml_anomalies.load_model()` passa a delegar nesse módulo **só quando a cache de módulo falha**, mantendo o curto-circuito `_model is not None` intacto (os testes `test_ml_anomalies.py`, `test_redblue.py`, `test_detections_api.py` injetam `ml_anomalies._model`/`_scaler` diretamente e dependem disso); (3) um contrato de resposta com códigos de erro estáveis, em que o campo `evaluation` já existe e é `null` até à Fase 2.

Achados não óbvios que o planeador tem de tratar: (a) `re.match(r"^v[0-9]{1,4}$", "v1\n")` **aceita** `"v1\n"` (o `$` casa antes de uma newline final) — usar `re.fullmatch` [VERIFIED: executado no venv, ver Code Examples]; (b) um erro novo de integridade não é `FileNotFoundError`, e `main.py` linhas 762 e 787 só apanham `FileNotFoundError`, por isso um hash adulterado viraria **500** em `/api/ml-anomalies` e `/api/redblue/metrics` se não se tratar; (c) o hash verificado e o `joblib.load` têm de operar sobre **os mesmos bytes** (ler uma vez, hash, `joblib.load(io.BytesIO(data))`) para não deixar janela TOCTOU — confirmado que o `joblib.load` aceita `BytesIO` neste venv; (d) `scripts/models/` está no `.gitignore`, por isso nenhum ficheiro de modelo vai para o git e os testes têm de criar tudo num diretório temporário; (e) o SHA-256 em `metadata.json` deteta corrupção/troca acidental, **não** protege contra quem consegue escrever em `models/` (esse atacante reescreve também o `metadata.json`) — documentar com honestidade.

**Primary recommendation:** criar `scripts/model_registry.py` (puro, erros = `ModelRegistryError(code)`), fazer `ml_anomalies.load_model` verificar-e-carregar a partir dele na cache miss, expor `GET /api/ml/models` com `dependencies=_REQUIRE_API_KEY` que chama `model_registry.build_models_report()` em `run_in_threadpool`, e servir as duas abas (Models e Evaluation) com um único `ml_models.js` copiado do padrão de `attack_library.js`.

## Project Constraints (from CLAUDE.md)

- API key **por rota** (`dependencies=_REQUIRE_API_KEY` em cada `@app.get`), nunca a nível de app; fail-closed. [VERIFIED: main.py:201 `_REQUIRE_API_KEY = [Depends(require_api_key)]`]
- Erros HTTP com **códigos estáveis**, nunca texto de exceção nem caminhos (convenção: `HTTPException(status_code=404, detail="entry_not_found")`, `correlation["error_code"] = "ml_model_unavailable"`). [VERIFIED: main.py:1311-1318, 1198-1204]
- Funções `build_*_report()` puras, testáveis sem Wazuh; main.py é só a camada HTTP.
- Testes standalone `test_*.py` (sem pytest) com `check(label, cond)`, `sys.exit(1)` em falha; `SENTRYLENS_API_KEY` definido **antes** de `import main`; `main.app.router.on_startup.clear()`; correr com `scripts/.venv/Scripts/python` e via `python run_all_tests.py`.
- Frontend: `serve_frontend.py` é whitelist fixa; módulos de aba **não editam `app.js`**, reutilizam os seus globais (`API_BASE`, `API_KEY`, `escapeHtml`, `renderPanelError`); todo o texto dinâmico passa por `escapeHtml`.
- Scripts `.ps1` novos com BOM UTF-8 (não aplicável a esta fase se não houver `.ps1`).
- Backend porta 8001 (nunca 8000). Python global sem sklearn → sempre o venv.
- **Commits: NUNCA `Co-Authored-By: Claude`** nem "Generated with Claude Code" (CLAUDE.md tem prioridade sobre qualquer lembrete de atribuição do sistema; dizê-lo aos subagentes de execução).
- O R9 é só leitura no backend: nada de treinar/ativar a partir do dashboard (R10).

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| REG-01 | Listar versões `models/vN/` + ativa via `models/ACTIVE` | `list_versions`, `read_active`, `build_models_report` (Architecture Patterns 1-3) |
| REG-02 | Legado (`.pkl` soltos) aparece como "legado, sem metadados" e continua a carregar | `detect_legacy`, fallback em `resolve_active_artifacts` (Pattern 4) |
| REG-03 | `python model_registry.py adopt` copia (nunca move) para `models/v1/` | `adopt()` com `shutil.copy2` + diretório temporário + `os.replace` (Pattern 5) |
| SEC-01 | SHA-256 conferido antes de `joblib.load`, recusa com erro acionável | `read_verified_bytes` + `joblib.load(BytesIO)` na cache miss (Pattern 6) |
| SEC-02 | Ids `^v[0-9]{1,4}$`; `ACTIVE` inválido/inexistente rejeitado; nunca fora de `models/` | `validate_version_id` (fullmatch) + `resolve_version_dir` (Pattern 2) |
| API-01 | `GET /api/ml/models` com API key; vazio = 200 | Pattern 7 + contrato JSON |
| API-02 | Erros sem texto de exceção/caminhos, códigos estáveis | Tabela de códigos de erro; mapa código→mensagem no JS |
| UI-01 | Aba Models lista versões, marca ativa e legado, mostra metadados | Pattern 8 (`ml_models.js`) |
| UI-03 | Sidebar deixa `data-planned`; `ml_models.js` na whitelist | Pattern 8 + alterações a `index.html`, `serve_frontend.py`, `test_serve_frontend.py` |
</phase_requirements>

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Listar/ler/validar versões, ACTIVE, hashes, `adopt` | Módulo de domínio (`model_registry.py`, stdlib, sem HTTP) | CLI (`python model_registry.py adopt`) | Mesmo padrão dos `build_*_report` puros: testável sem Wazuh |
| Verificar hash e carregar `.pkl` | `ml_anomalies.load_model()` (único sítio com `joblib.load`) | `model_registry` fornece bytes verificados | Mantém um só ponto de desserialização de pickle |
| Contrato HTTP + auth + mapeamento de erros | API / Backend (`main.py`, rota fina) | — | `main.py` é só a camada HTTP; API key por rota |
| Persistência | Sistema de ficheiros `scripts/models/` (`vN/`, `ACTIVE`) | — | Decisão do projeto; sem SQLite para isto |
| Apresentação, mapa código→texto PT | Browser (`ml_models.js`) | `serve_frontend.py` (whitelist) | Backend nunca envia texto de erro; o browser traduz códigos |

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `hashlib` / `hmac` / `json` / `pathlib` / `shutil` / `re` / `argparse` / `os` | stdlib (Python 3.12.7 no venv) [VERIFIED: `scripts/.venv/Scripts/python --version`] | Todo o registo | Sem dependências novas; já é o estilo do repo |
| `joblib` | 1.4.2 [VERIFIED: venv `joblib.__version__`] | `joblib.load` do `.pkl` | Já usado por `ml_anomalies.py` e `train_anomaly_model.py` |
| `scikit-learn` | 1.5.2 [VERIFIED: venv] | Tipo do modelo (IsolationForest) | Já instalado; só necessário em testes que treinam um modelo minúsculo |
| FastAPI `Depends`, `HTTPException`, `run_in_threadpool` | já em `main.py` | Rota + IO bloqueante fora do event loop | Padrão existente (`main.py:1037`) |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| JSON `metadata.json` | YAML / SQLite | JSON é stdlib, legível, e o requisito fixa o nome `metadata.json` |
| Hash simples SHA-256 | HMAC-SHA256 com chave secreta | HMAC resistiria a um atacante com escrita em `models/`; fora de âmbito (REQUIREMENTS fixa SHA-256) — ver Open Questions |
| `skops` para persistência segura | — | Não tem suporte em `IsolationForest`+`StandardScaler` triviais para o formato atual; mudaria o formato dos `.pkl`; fora de âmbito [ASSUMED] |

**Installation:** nenhuma. **Package Legitimacy Audit:** não aplicável — a fase não instala pacotes externos (só stdlib + `joblib`/`scikit-learn` já presentes em `scripts/requirements.txt`).

## Architecture Patterns

### System Architecture Diagram

```
 CLI: python model_registry.py adopt ──► adopt() ──► copia 2 .pkl ──► models/v1.tmp-<pid>/ ──os.replace──► models/v1/
                                              │                         (+ metadata.json)         └─► models/ACTIVE ("v1")
                                              ▼
              models/  ┌─ isolation_forest.pkl, scaler.pkl   (legado, solto, NUNCA tocado)
                       ├─ ACTIVE                              (texto: "v1")
                       └─ v1/ {isolation_forest.pkl, scaler.pkl, metadata.json}

 Browser (aba Models / Evaluation, ml_models.js) ──GET /api/ml/models (X-API-Key)──► main.py rota fina
        ▲                                                                   │ run_in_threadpool
        │  JSON {active, versions[], total}                                 ▼
        └────────────────────────────────────────  model_registry.build_models_report(ML_MODEL_DIR)
                                                    ├ read_active()  ── validate_version_id ── resolve_version_dir (is-under-root)
                                                    ├ list_versions() ── metadata.json (cap 64 KB) + verify_artifacts (SHA-256 streaming)
                                                    └ detect_legacy() ── ficheiros soltos, size/mtime, SEM unpickle

 Pedido de deteção (/api/ml-anomalies etc.) ──► ml_anomalies.load_model(dir)
        cache hit (_model & _scaler)? ──sim──► devolve (comportamento atual, inalterado)
        │ não
        ▼
   model_registry.resolve_active_artifacts(dir)
        ├ ACTIVE existe ─► resolve vN ─► read bytes 1x ─► SHA-256 == metadata? ──não──► ModelRegistryError("hash_mismatch")  [NÃO carrega]
        │                                                      └─sim─► joblib.load(BytesIO(bytes)) ─► cache
        ├ sem ACTIVE, .pkl soltos ─► legado (sem metadados, sem hash) ─► joblib.load(path) ─► cache
        └ nada ─► FileNotFoundError (503 como hoje)
```

### Recommended Project Structure
```
scripts/
├── model_registry.py        # NOVO: domínio puro + CLI (adopt; Fase 2 acrescenta evaluate)
├── ml_anomalies.py          # load_model delega na cache miss; reset_cache() novo
├── main.py                  # + rota GET /api/ml/models; apanhar ModelRegistryError nas rotas 762/787
├── serve_frontend.py        # + "/ml_models.js": "ml_models.js"
├── test_model_registry.py   # NOVO: domínio + CLI adopt (tmp dir)
├── test_ml_models_api.py    # NOVO: rota (401, 200 vazio, legado, versões, hash adulterado)
└── test_serve_frontend.py   # + check de /ml_models.js
index.html                   # sidebar: 2 botões com data-tab; + 2 <div class="tab-content">; + <script src="ml_models.js">
ml_models.js                 # NOVO (raiz): abas Models e Evaluation (estado "Sem avaliação")
style.css                    # + .mlm-* (badges)
```

### Pattern 1: Códigos de erro estáveis e `ModelRegistryError`
`ModelRegistryError(Exception)` com atributo `.code` (str estável). Mensagem humana só no CLI/logs, nunca em HTTP. Códigos propostos:

| Código | Quando |
|--------|--------|
| `invalid_version_id` | id não casa `v[0-9]{1,4}` (inclui `../x`, `v1\n`, vazio, `ACTIVE` ilegível/UTF-16) |
| `active_not_found` | `ACTIVE` válido mas `models/vN/` não existe (ou não é pasta direta de `models/`) |
| `metadata_missing` / `metadata_invalid` | sem `metadata.json`, JSON inválido, >64 KB, não-objeto, `version` ≠ nome da pasta, hash não-hex64 |
| `artifact_missing` | falta um dos dois `.pkl` na versão |
| `hash_mismatch` | SHA-256 real ≠ `metadata.json` |
| `already_adopted` | `adopt` com `models/v1/` já existente |
| `no_legacy_model` | `adopt` sem os dois `.pkl` soltos |
| `registry_unavailable` | `OSError` ao ler `models/` (HTTP 503) |

### Pattern 2: Validação de id + resolver à prova de path traversal (SEC-02)
Defesa em duas camadas: regex `fullmatch` (primária) e confirmação de que o caminho resolvido é filho **direto** de `models/` (cobre junctions/symlinks `vN` que apontem para fora). [VERIFIED: executado no venv]: `(root/'../x').resolve().is_relative_to(root)` → `False`; `(root/'C:/Windows')` → `False`; `(root/'v1/../../x')` → `False`; `(root/'v1')` → `True`.

```python
VERSION_ID_RE = re.compile(r"v[0-9]{1,4}")          # usar SEMPRE fullmatch (ver pitfall do "\n")

def validate_version_id(value) -> str:
    if not isinstance(value, str) or VERSION_ID_RE.fullmatch(value) is None:
        raise ModelRegistryError("invalid_version_id")
    return value

def resolve_version_dir(models_dir, version_id) -> Path:
    vid = validate_version_id(version_id)
    root = Path(models_dir).resolve()
    candidate = (root / vid).resolve()
    if candidate.parent != root:          # junction/symlink para fora => recusado
        raise ModelRegistryError("invalid_version_id")
    if not candidate.is_dir():
        raise ModelRegistryError("active_not_found")
    return candidate
```
Formato do `ACTIVE`: uma linha UTF-8 (`v1`, newline final opcional). Ler com cap de bytes, decodificar com `utf-8-sig`, `strip()`, depois `validate_version_id`. Qualquer falha de decode (p.ex. UTF-16 do `echo v1 > ACTIVE` no PowerShell 5.1) → `invalid_version_id` (fail-closed).

### Pattern 3: Esquema de `metadata.json` (contrato desta fase + campos já nulos para as Fases 2/3)
```json
{
  "schema_version": 1,
  "version": "v1",
  "origin": "adopted",
  "created_at": "2026-10-09T21:00:00+00:00",
  "trained_at": "2026-09-14T15:40:00+00:00",
  "trained_at_estimated": true,
  "model_type": "IsolationForest",
  "parameters": null,
  "dataset": {"name": null, "size": null, "attacks": null, "synthetic": null},
  "library_versions": null,
  "artifacts": {
    "isolation_forest.pkl": {"sha256": "<64 hex>", "size_bytes": 539673},
    "scaler.pkl":           {"sha256": "<64 hex>", "size_bytes": 767}
  },
  "evaluation": null
}
```
- `origin`: `"adopted"` (Fase 1) | `"trained"` (Fase 3). `trained_at_estimated: true` só em adotados (mtime de `isolation_forest.pkl`; os dois `.pkl` do repo têm mtime de 14 Set 2026 [VERIFIED: ls -la]).
- `parameters`/`dataset`/`library_versions` são `null`/campos `null` em adotados: **não** se faz unpickle no `adopt` para descobrir parâmetros (carregar um pickle antes de haver hash confiável é o que SEC-01 proíbe) e não se inventa o dataset. O modelo atual tem `n_estimators=200`, `contamination=0.2` [VERIFIED: `get_params()` no venv] mas isso não entra em `metadata.json` por `adopt`; a Fase 3 (REG-04) preenche-os nas versões treinadas. A UI mostra "desconhecido" para `null`.
- `evaluation: null` existe sempre no contrato (Fase 2 substitui por objeto). A API devolve `evaluation` por versão copiado de `metadata.json` (ausente → `null`). Nunca preencher com `ml_training_report.json`.
- Os nomes dos ficheiros de artefacto são **constantes** (`ARTIFACT_FILES = ("isolation_forest.pkl", "scaler.pkl")`); nunca ler nomes/caminhos a partir do `metadata.json`.
- Timestamps em ISO-8601 com fuso (`datetime.fromtimestamp(mtime, timezone.utc).isoformat()`), coerente com o resto do repo.

### Pattern 4: Representar o legado
Entrada sintética no relatório, não numa pasta:
```json
{"id": null, "kind": "legacy", "label": "legado, sem metadados", "active": true,
 "status": "no_metadata", "error_code": null, "metadata": null, "evaluation": null,
 "files": {"isolation_forest.pkl": {"size_bytes": 539673, "modified_at": "2026-09-14T..."}, "scaler.pkl": {...}}}
```
Regras: aparece quando os dois `.pkl` soltos existem **e** não há versão adotada; `active: true` se não houver `ACTIVE` (é o que `load_model` carrega); depois de `adopt` deixa de aparecer (a v1 é a ativa; os originais ficam no disco intactos). O legado **não tem hash para verificar** (REG-02 exige que continue a carregar) — risco aceite e documentado; é um dos motivos para recomendar `adopt`.

### Pattern 5: `adopt` (REG-03) — copiar, nunca mover
1. Pré-condições: existem os dois `.pkl` soltos (`no_legacy_model`), `models/v1/` não existe (`already_adopted`).
2. Criar `models/v1.tmp-<pid>/` (nome que **não** casa o regex, logo invisível à listagem), `shutil.copy2(src, dst)` de cada `.pkl` (preserva mtime), calcular SHA-256 **do ficheiro copiado** em streaming, escrever `metadata.json`, `os.replace(tmp, models/v1)` (rename de pasta atómico no mesmo volume; falha com `PermissionError` no Windows se algo tiver a pasta aberta → apanhar `OSError`, limpar tmp, sair com código ≠ 0).
3. Escrever `ACTIVE` por ficheiro temporário + `os.replace` (só se `ACTIVE` não existir; se existir, deixar e avisar — ver Open Questions).
4. Verificação final: hash da cópia == hash do original; os originais não são abertos para escrita em nenhum momento. Teste: mtime+tamanho+SHA-256 dos originais iguais antes/depois.
5. CLI: `python model_registry.py adopt [--models-dir DIR]`, `argparse` com subcomandos (a Fase 2 acrescenta `evaluate`); `--models-dir` default = `ML_MODEL_DIR` do ambiente ou `scripts/models` (caminho relativo ao próprio ficheiro, como `attack_library.DEFAULT_PATH`, nunca ao cwd). Mensagens em PT, acionáveis; exit code 1 em erro.

### Pattern 6: Verificação antes de `joblib.load` e relação com a cache (SEC-01)
`ml_anomalies.load_model` hoje: `if _model is not None and _scaler is not None: return` → depois `os.path.exists` → `joblib.load`. Manter exatamente o curto-circuito (os testes injetam `_model`/`_scaler`) e inserir a verificação **na cache miss, antes de qualquer `joblib.load`**. Ler uma vez, hash dos bytes lidos, carregar desses mesmos bytes — sem janela entre "verificar" e "usar":

```python
# model_registry.py
def read_verified_bytes(version_dir: Path, filename: str, meta: dict) -> bytes:
    expected = meta["artifacts"][filename]["sha256"]       # já validado como hex64
    data = (version_dir / filename).read_bytes()           # .pkl têm ~0.5 MB; ok em memória
    actual = hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(actual, expected.lower()):
        raise ModelRegistryError("hash_mismatch")
    return data

# ml_anomalies.py (esboço)
def load_model(model_dir=None):
    global _model, _scaler
    if _model is not None and _scaler is not None:
        return _model, _scaler
    model_dir = model_dir or DEFAULT_MODEL_DIR
    source = model_registry.resolve_active_artifacts(model_dir)   # levanta FileNotFoundError / ModelRegistryError
    _model  = joblib.load(io.BytesIO(source.model_bytes)) if source.verified else joblib.load(source.model_path)
    ...
```
[VERIFIED: `joblib.load(io.BytesIO(open('models/isolation_forest.pkl','rb').read()))` devolve `IsolationForest` neste venv.]
Notas: `hmac.compare_digest` aqui não é defesa contra timing (o hash não é segredo); usa-se por convenção e é inofensivo. Para listagem (`build_models_report`) usar hash em streaming (`iter(lambda: f.read(1<<20), b"")`) — mesma função base `sha256_file`.
Cache: a cache não sabe de versões; depois de `adopt`/treino o processo em execução continua com o modelo já em memória até reiniciar. Acrescentar `ml_anomalies.reset_cache()` (útil para testes) e documentar "reiniciar o backend após adopt/treino". Opcional: guardar `_loaded_from` ("legacy"/"vN") e expô-lo como `loaded` no relatório para o dashboard não mostrar "ativa: v1" enquanto o processo serve o legado (ver Open Questions).

### Pattern 7: Rota fina `GET /api/ml/models` (API-01/02)
```python
@app.get("/api/ml/models", dependencies=_REQUIRE_API_KEY)
async def get_ml_models():
    try:
        return await run_in_threadpool(model_registry.build_models_report, ML_MODEL_DIR)
    except model_registry.ModelRegistryError as e:     # só registry_unavailable chega aqui
        logger.warning("GET /api/ml/models: %s", e.code)
        raise HTTPException(status_code=503, detail=e.code)
    except Exception:
        logger.exception("GET /api/ml/models")
        raise HTTPException(status_code=500, detail="registry_unavailable")
```
`build_models_report` **não levanta** por problemas de uma versão individual: marca essa versão com `status`/`error_code` e continua (uma pasta com `metadata.json` corrompido não derruba a lista nem a aba). `ACTIVE` inválido → `active: null`, `active_error: "<código>"`. Diretório `models/` inexistente → 200 vazio. Contrato:
```json
{"active": "v1" | "legacy" | null, "active_error": null | "invalid_version_id" | "active_not_found",
 "total": 2,
 "versions": [{"id":"v1","kind":"versioned","active":true,"status":"ok|hash_mismatch|artifact_missing|metadata_invalid|metadata_missing",
               "error_code": null, "metadata": {...}, "evaluation": null}, {"id":null,"kind":"legacy",...}]}
```
Ordem: versões por número decrescente (mais recente primeiro), legado no fim. Registar com `logger`, nunca `str(e)` na resposta. **Colocar a rota no bloco ML** perto de `main.py:754` e usar `Path` do FastAPI só se acrescentar rotas com parâmetro (esta não tem).

### Pattern 8: Frontend `ml_models.js` (UI-01/03)
Copiar a estrutura de `attack_library.js` (globais com prefixo `mlm`, **todos** prefixados porque os scripts clássicos partilham o escopo global e um `const` repetido rebenta o script inteiro):
- `index.html`: trocar os dois botões (linhas ~88 e ~90) para `<button class="nav-item" data-tab="ml-models">📦 Models</button>` e `data-tab="ml-evaluation"` (sem `is-planned`/`data-planned`/`nav-badge`); acrescentar `<div class="tab-content" id="tab-ml-models">` e `id="tab-ml-evaluation"` (cada um com um `<section class="panel" id="ml-models-panel">` com `<h2>` — `renderPanelError` insere o banner depois do `h2`); `<script src="ml_models.js"></script>` depois de `metrics.js`. A navegação já funciona sem editar `app.js`: `activateTab(name)` abre `tab-${name}` e `applyHash` aceita `#ml-models` [VERIFIED: app.js:1258-1330].
- Ciclo de vida: `MutationObserver` no atributo `class` do `#tab-ml-models`/`#tab-ml-evaluation`; **recarregar sempre que a aba passa de inativa a ativa** (ao contrário da Attack Library, que carrega uma vez; aqui `adopt` pode ter corrido entretanto) e botão "Atualizar". Um único `fetch` partilhado pelas duas abas.
- Segurança de apresentação: `escapeHtml` em todo o texto; erros mostrados via mapa `MLM_ERROR_TEXT = {invalid_version_id: "...", hash_mismatch: "...", ...}` (mensagens PT acionáveis, p.ex. "O ficheiro do modelo foi alterado desde que foi registado; não foi carregado. Restaura-o a partir da cópia legada ou volta a adotar/treinar."); códigos desconhecidos → texto genérico. **Nunca** mostrar `response.detail` em bruto.
- Estados: `evaluation === null` → "Sem avaliação" (na aba Evaluation, por versão, mais nota "A avaliação por versão chega na Fase 2"); lista vazia → "Sem dados — ainda não há modelos registados"; legado → badge "legado, sem metadados"; ativa → badge "ativa"; `null` nos metadados → "desconhecido".
- `style.css`: acrescentar `.mlm-badge-active`, `.mlm-badge-legacy`, `.mlm-badge-error` reutilizando a paleta de `.alib-risk-*`.
- `serve_frontend.py`: `ALLOWED_FILES["/ml_models.js"] = "ml_models.js"`. `test_serve_frontend.py`: acrescentar o mesmo `check` que existe para `/metrics.js` (linhas ~127-128).

### Anti-Patterns to Avoid
- `re.match(r"^v[0-9]{1,4}$", ...)` — aceita `"v1\n"`; usar `fullmatch`.
- Hashear o ficheiro e depois `joblib.load(path)` (TOCTOU): usar os mesmos bytes.
- Mover/apagar/reescrever os `.pkl` soltos; chamar `joblib.load` no `adopt`.
- Esquecer `dependencies=_REQUIRE_API_KEY` na rota nova (não herda de app).
- `detail=str(e)` ou mensagens com `model_dir` em respostas HTTP.
- Ler nomes de ficheiros do `metadata.json`.
- IO síncrono pesado dentro de `async def` sem `run_in_threadpool`.
- Fazer o `ml_anomalies.load_model` consultar o disco quando `_model`/`_scaler` já estão em memória (parte os testes existentes).

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Hash de ficheiro | Loop manual de bytes sem padrão | `hashlib.sha256` + `iter(lambda: f.read(1<<20), b"")` | stdlib, streaming correto |
| Comparação de digests | `==` entre strings | `hmac.compare_digest` | convenção segura, custo zero |
| Anti-traversal | Filtros de `".."`/barras por substring | `fullmatch` do regex de id + `Path.resolve()` + `candidate.parent == root` | substring filters falham com junctions, `\` Windows, drive letters |
| Escrita atómica | Escrever diretamente em `models/v1/` / `ACTIVE` | pasta/ficheiro temporário + `os.replace` | evita versões a meio e `ACTIVE` truncado |
| Cópia com metadados | `open().write()` | `shutil.copy2` (preserva mtime; [VERIFIED: mtime preservado] ) | a data de treino estimada usa o mtime |
| Parsing CLI | `sys.argv` à mão | `argparse` com subcomandos | Fase 2 acrescenta `evaluate` |

**Key insight:** a segurança desta fase está em **não deixar o `joblib.load` ver bytes não verificados** e em **nunca construir caminhos a partir de texto não validado**; tudo o resto é bookkeeping de JSON.

## Runtime State Inventory

> Não é fase de rename/refactor. Há, porém, estado em runtime relevante:

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | `scripts/models/isolation_forest.pkl` (539 673 B), `scaler.pkl` (767 B), SHA-256 do modelo `3c2fe308…b106` [VERIFIED: hash calculado], `.gitignore` inclui `scripts/models/` | Nenhuma migração; `adopt` copia. Testes nunca usam esta pasta |
| Live service config | None — nenhum serviço externo guarda o caminho do modelo | None |
| OS-registered state | `start-backend.ps1`/tarefa agendada arrancam o backend; o processo guarda o modelo em cache | Documentar "reiniciar o backend após `adopt`" |
| Secrets/env vars | `ML_MODEL_DIR` (`.env.example:18`, vazio por omissão) | Reutilizar a mesma variável para o diretório do registo; nenhuma nova |
| Build artifacts | None | None |

## Common Pitfalls

### Pitfall 1: `$` aceita newline final
**What goes wrong:** `"v1\n"` passa `^v[0-9]{1,4}$` com `re.match`. **Why:** `$` casa antes de `\n` final. **How to avoid:** `fullmatch` (ou `\Z`). **Warning signs:** teste com `"v1\n"` e `"v1 "` a passar.

### Pitfall 2: Erro novo não apanhado → 500
**What goes wrong:** `/api/ml-anomalies` (main.py:762) e `/api/redblue/metrics` (main.py:787) só apanham `FileNotFoundError`. **How to avoid:** apanhar também `ModelRegistryError` → 503 com `detail=<código>`; as restantes rotas (964, 1074, 1198, `incident_ingest.ml_summary`) já usam `except Exception`, mas `main.py:1198` devolve sempre `ml_model_unavailable` (aceitável). Aproveitar para tirar o caminho da mensagem do `FileNotFoundError` em `load_model` ("Modelo de ML não encontrado em '{model_dir}'" vaza o caminho para `detail=str(e)` hoje) — os testes só verificam o status 503.

### Pitfall 3: Cache de módulo e `ACTIVE` mudado
**What goes wrong:** depois de `adopt`, o processo continua a servir o modelo em cache e a aba pode dizer "ativa v1" sem que isso seja o que está em memória. **How to avoid:** `reset_cache()`, documentar o reinício, e/ou expor `loaded` (ver Open Questions).

### Pitfall 4: Windows — `ACTIVE` em UTF-16 / BOM / CRLF
`echo v1 > models\ACTIVE` no PowerShell 5.1 grava UTF-16 LE com BOM. Ler com `utf-8-sig`, `strip()`, falha de decode → `invalid_version_id`. O CLI `adopt` é a forma suportada de escrever `ACTIVE`; documentar.

### Pitfall 5: Windows — bloqueios e paths
Pasta no OneDrive com espaços: usar sempre `pathlib` (nunca concatenar strings nem `shell=True`); testes usam `tempfile.TemporaryDirectory()` fora do OneDrive. `os.replace` de pasta falha com `PermissionError` se o OneDrive/antivírus/Explorer tiver um ficheiro aberto → apanhar `OSError`, limpar tmp, mensagem acionável ("fecha o que tem models/ aberto e repete"). Num `TemporaryDirectory` os testes devem fechar tudo antes de limpar (Windows não apaga ficheiros abertos). Sincronização do OneDrive pode tocar nos `mtime`; o `copy2` + mtime do original fixa a data estimada no momento do `adopt`.

### Pitfall 6: Segurança de pickle (limite do SEC-01)
`joblib.load` desserializa pickle ⇒ executa código arbitrário. O SHA-256 em `metadata.json` só prova que os bytes são os que foram registados; **quem consegue escrever em `models/` consegue reescrever `metadata.json`**. Portanto SEC-01 protege contra corrupção, troca acidental e cópia de ficheiros alheios sem metadados, não contra um atacante local com escrita. Reduzir a superfície: `models/` não é servido pelo `serve_frontend.py` (whitelist), nenhuma rota aceita upload, e a rota nova é só leitura. Não afirmar na documentação que o hash "autentica" o modelo. Os `.pkl` do legado carregam sem verificação até à adoção (REG-02).

### Pitfall 7: Pickles dependem da versão do scikit-learn
Um `.pkl` treinado com sklearn diferente pode dar `InconsistentVersionWarning` ou falhar. Por isso a Fase 3 deve gravar `library_versions` nas versões treinadas; em adotados é `null` (não inventar a versão de treino). Apanhar exceções de `joblib.load` e devolver `model_load_failed` (código estável) em vez de deixar passar texto.

### Pitfall 8: Colisões de globais JS
Todos os scripts de aba partilham o escopo global; um `const mlmX` repetido ou um nome que já exista em `app.js` (`escapeHtml`, `API_BASE`, `charts`, `navItems`, `tabContents`) lança `SyntaxError`/`TypeError` e a aba fica em branco. Prefixar tudo `mlm`; validar com `node --check ml_models.js` (Node v24.11.1 disponível [VERIFIED: node --version]).

### Pitfall 9: Listagem repete hashes a cada pedido
Hash de N versões por pedido é barato (0,5 MB cada) e a aba só pede ao ficar ativa, mas se o número de versões crescer, considerar cache por `(mtime, size)`. Fora de âmbito agora.

## Code Examples

### Validação do id (verificado no venv)
```python
# Source: executado em scripts/.venv (Python 3.12.7)
# re.match(r"^v[0-9]{1,4}$", "v1\n") -> match   (BUG)
# re.fullmatch(r"v[0-9]{1,4}", "v1\n") -> None  (correto)
# "v12345", "../x", "V1", "", "v1/.." -> None em ambos
```

### Hash em streaming
```python
def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
```

### Esboço de `adopt`
```python
def adopt(models_dir) -> dict:
    root = Path(models_dir).resolve()
    srcs = {n: root / n for n in ARTIFACT_FILES}
    if not all(p.is_file() for p in srcs.values()):
        raise ModelRegistryError("no_legacy_model")
    target = root / "v1"
    if target.exists():
        raise ModelRegistryError("already_adopted")
    tmp = root / f"v1.tmp-{os.getpid()}"
    tmp.mkdir()
    try:
        artifacts = {}
        for name, src in srcs.items():
            dst = tmp / name
            shutil.copy2(src, dst)                       # copia, preserva mtime; src só lido
            artifacts[name] = {"sha256": sha256_file(dst), "size_bytes": dst.stat().st_size}
            if artifacts[name]["sha256"] != sha256_file(src):
                raise ModelRegistryError("hash_mismatch")
        mtime = srcs["isolation_forest.pkl"].stat().st_mtime
        meta = {... "origin": "adopted", "trained_at": iso(mtime), "trained_at_estimated": True, ...}
        (tmp / "metadata.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, target)
    except OSError as exc:
        raise ModelRegistryError("registry_unavailable") from exc
    finally:
        if tmp.exists():
            shutil.rmtree(tmp, ignore_errors=True)
    _write_active_atomic(root, "v1")                    # só se não existir ACTIVE
    return meta
```

### Esqueleto de teste (padrão do repo)
```python
import os, tempfile
os.environ.setdefault("SENTRYLENS_API_KEY", "chave-de-teste-nao-usar-em-producao")
import main, model_registry
from fastapi.testclient import TestClient
main.app.router.on_startup.clear()
tmp = tempfile.TemporaryDirectory()
main.ML_MODEL_DIR = tmp.name          # o handler lê o global em cada pedido (como test_incidents_api.py:59)
client = TestClient(main.app, headers={"X-API-Key": os.environ["SENTRYLENS_API_KEY"]})
```
`ml_anomalies._model = None; _scaler = None` (ou `reset_cache()`) no início de cada teste que exercite o caminho de disco, e restaurar `load_model` se for monkeypatched.

## State of the Art

| Old Approach | Current Approach | Impact |
|--------------|------------------|--------|
| `.pkl` soltos sem metadados | `models/vN/` + `metadata.json` + `ACTIVE` | rastreabilidade e verificação |
| `joblib.load(path)` direto | hash sobre bytes lidos uma vez + `joblib.load(BytesIO)` | sem TOCTOU |

**Deprecated/outdated:** `docs/README.md` (estrutura antiga) — não usar como fonte. `ml_training_report.json` avulso não se liga a versões (Fase 2 decide o seu destino).

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `skops` não é alternativa prática para estes artefactos | Alternatives | Baixo; só afeta ideias futuras |
| A2 | Depois de `adopt` o legado deve desaparecer da lista (em vez de aparecer como "já adotado") | Pattern 4 | UX; trivial de mudar |
| A3 | `adopt` não sobrescreve um `ACTIVE` já existente | Pattern 5 | Pode contrariar a expectativa "v1 fica ativa"; confirmar |
| A4 | `GET /api/ml/models` deve calcular `integrity`/`status` por hash em cada pedido (não só ler metadados) | Pattern 7 | Custo mínimo; alternativa é "not_checked" |
| A5 | Versões ordenadas da mais recente para a mais antiga | Pattern 7 | UX |
| A6 | Unicode `v٣` (dígitos Unicode) é rejeitado por `[0-9]` em `fullmatch` | Pitfall 1 | `[0-9]` em `str` patterns é ASCII-estrito; testado só parcialmente (a impressão do caso falhou por codepage da consola, não pela regex) — incluir caso no teste |

## Open Questions

1. **`adopt` com `ACTIVE` já existente?**
   - Sabemos: critério 3 diz que depois de `adopt` a v1 aparece ativa.
   - Por esclarecer: o que fazer se já existir `ACTIVE` apontando outra versão (só possível se `v1` não existir mas `v2` sim).
   - Recomendação: `adopt` escreve `ACTIVE` só se não existir; caso contrário avisa e deixa-o. Confirmar com o utilizador.
2. **Expor `loaded` (o que o processo tem em memória)?**
   - Recomendação: sim, campo opcional barato (`_loaded_from`), para a aba não afirmar uma ativa diferente da que serve deteções. Senão, só documentar o reinício.
3. **Legado oculto após adoção?** Recomendado ocultar (A2).
4. **HMAC em vez de SHA-256 simples?** Fora de âmbito (REQUIREMENTS fixa SHA-256); ponto a registar como dívida de segurança se o modelo de ameaça incluir escrita local.
5. **Aba Evaluation na Fase 1:** a mesma fonte (`/api/ml/models`) alimenta-a com "Sem avaliação"; a Fase 2 pode separar em `ml_evaluation.js` (exigiria nova entrada na whitelist).

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Python venv `scripts/.venv` | testes, CLI | ✓ | 3.12.7 | — |
| joblib / scikit-learn | `load_model`, testes | ✓ | 1.4.2 / 1.5.2 | — |
| Node | `node --check ml_models.js` | ✓ | v24.11.1 | revisão manual no browser |
| Laboratório Wazuh | — | não necessário (tudo mockado) | — | — |

**Missing dependencies with no fallback:** none.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | scripts standalone (`check()` + `sys.exit`), sem pytest |
| Config file | none — `run_all_tests.py` descobre `test_*.py` |
| Quick run command | `cd scripts && .venv/Scripts/python test_model_registry.py` e `test_ml_models_api.py` |
| Full suite command | `cd scripts && .venv/Scripts/python run_all_tests.py` (33 ficheiros hoje; tem de continuar verde) |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| REG-01 | lista `vN` + `ACTIVE`; vazio → lista vazia | unit | `python test_model_registry.py` | ❌ Wave 0 |
| REG-02 | só `.pkl` soltos → entrada `legacy`, `metadata: null`, `evaluation: null`; `load_model` carrega-os | unit + integração | idem + `test_ml_models_api.py` | ❌ Wave 0 |
| REG-03 | `adopt`: v1 criada, `ACTIVE=v1`, originais com mesmos SHA-256/size/mtime, `trained_at_estimated`, 2ª execução → `already_adopted` | unit (tmp dir; `.pkl` falsos de bytes arbitrários bastam, não há unpickle) | `python test_model_registry.py` | ❌ Wave 0 |
| SEC-01 | alterar 1 byte de um `.pkl` da v1 → `load_model` levanta `hash_mismatch` e **`joblib.load` não é chamado** (monkeypatch com contador) | unit | idem | ❌ Wave 0 |
| SEC-02 | ids `../x`, `..\x`(via variável), `v1\n`, `v12345`, `V1`, vazio, `C:/Windows`, junction/symlink (se o SO permitir; senão skip com `[OK]` explícito) → `invalid_version_id`/`active_not_found`; nada fora de `models/` resolvido | unit | idem | ❌ Wave 0 |
| API-01 | sem key → 401; vazio → 200 `{"active":null,"versions":[],"total":0}`; com versões → metadados + ativa + `evaluation: null` | integração (TestClient) | `python test_ml_models_api.py` | ❌ Wave 0 |
| API-02 | `metadata.json` corrompido/`ACTIVE` inválido/hash adulterado → resposta só com códigos; `str(resp.json())` não contém o caminho do tmp nem `Traceback`/`Error`; rotas `/api/ml-anomalies` com hash adulterado → 503 (não 500) | integração | idem | ❌ Wave 0 |
| UI-03 | `/ml_models.js` servido (200, `application/javascript`); `index.html` não contém `data-planned="R9"`, contém `data-tab="ml-models"`, `data-tab="ml-evaluation"`, `id="tab-ml-models"`, `id="tab-ml-evaluation"`, `<script src="ml_models.js">` | unit (leitura de ficheiro) | `python test_serve_frontend.py` + novo teste estático | ✅ existe / ❌ checks novos |
| UI-01 | renderização | manual (+ `node --check ml_models.js`) | `node --check ml_models.js` | ❌ Wave 0 |

Critério 2 do ROADMAP (sem regressão): `python run_all_tests.py` verde, com atenção a `test_ml_anomalies.py`, `test_redblue.py`, `test_detections_api.py`, `test_attack_registry.py`, `test_metrics_api.py`, `test_incident_ingest.py`, `test_incidents_api.py`, que monkeypatcham `ml_anomalies.load_model`/`_model`.

### Sampling Rate
- **Per task commit:** o ficheiro de teste novo + `python run_all_tests.py ml`
- **Per wave merge:** `python run_all_tests.py`
- **Phase gate:** suite completa verde antes de `/gsd-verify-work`; verificação manual da aba no browser (UI-01) com `start-backend.ps1`/`start-frontend.ps1`.

### Wave 0 Gaps
- [ ] `scripts/test_model_registry.py` — REG-01/02/03, SEC-01/02
- [ ] `scripts/test_ml_models_api.py` — API-01/02 (+ 503 em `/api/ml-anomalies`)
- [ ] check de `/ml_models.js` em `scripts/test_serve_frontend.py` e teste estático do `index.html`
- Fixtures: helper `make_version(tmp, vid, corrupt=False)` que escreve `.pkl` com bytes arbitrários + `metadata.json` coerente; para testar `load_model` real treinar um IsolationForest minúsculo (`train_anomaly_model.train_model`) e `joblib.dump` para o tmp.

## Security Domain

### Applicable ASVS Categories (nível 1, `security_enforcement: true`)

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | sim (rota REST) | `Depends(require_api_key)` por rota |
| V3 Session Management | não | — |
| V4 Access Control | sim | mesma API key; sem rotas de escrita |
| V5 Input Validation | sim | `fullmatch` no id; caps de tamanho em `ACTIVE` (≤64 B) e `metadata.json` (≤64 KB); nomes de ficheiros constantes |
| V6 Cryptography | sim | `hashlib.sha256`, `hmac.compare_digest`; nada de crypto própria |
| V12 Files | sim | resolução sob `models/`, cópia sem tocar nos originais, escrita atómica |
| V8 Data Protection / Error handling | sim | códigos estáveis, sem paths/exceções nas respostas |

### Known Threat Patterns
| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Path traversal via `ACTIVE`/id | Tampering | regex `fullmatch` + `parent == root` |
| `.pkl` trocado/corrompido → execução de código no `joblib.load` | Tampering/EoP | SHA-256 antes de carregar, sobre os mesmos bytes (limite: atacante com escrita também altera o metadata) |
| Fuga de caminhos/exceções em respostas | Information disclosure | `detail=<código>`, logs no servidor |
| Servir `models/` por HTTP | Information disclosure | `serve_frontend.py` whitelist (não alterar além de `ml_models.js`) |
| XSS via metadados (nome de dataset, etc.) | Tampering | `escapeHtml` em todo o texto dinâmico |
| Rota sem API key por esquecimento | Spoofing | `dependencies=_REQUIRE_API_KEY`; teste 401 |

## Sources

### Primary (HIGH confidence — leitura direta/execução nesta sessão)
- `scripts/ml_anomalies.py` (load_model, cache `_model/_scaler`), `scripts/train_anomaly_model.py` (`save_model`, `DEFAULT_MODEL_DIR`), `scripts/main.py` (linhas 117, 201, 754-775, 1198-1204, 1304-1318), `scripts/serve_frontend.py` (ALLOWED_FILES), `scripts/incident_ingest.py` (`ml_summary`), `attack_library.js`, `app.js` (`showTab`/`activateTab`/`applyHash`/`escapeHtml`/`renderPanelError`), `index.html`, `scripts/test_ml_anomalies.py`, `scripts/test_serve_frontend.py`, `.gitignore`, `.planning/*`, `CLAUDE.md`.
- Execuções no venv: comportamento de `re.match` vs `fullmatch`, `Path.resolve().is_relative_to`, `shutil.copy2` preservando mtime, `joblib.load(BytesIO)`, versões (Python 3.12.7, joblib 1.4.2, sklearn 1.5.2), SHA-256 e `get_params()` do modelo atual.

### Secondary / Tertiary
- Nenhuma fonte web usada; afirmações sobre pickle/OneDrive/PowerShell 5.1 são conhecimento geral de engenharia [ASSUMED] salvo onde indicado.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — stdlib + libs já instaladas, versões lidas do venv
- Architecture: HIGH — assente nos padrões existentes do repo
- Pitfalls: HIGH para os verificados por execução (`$`, `is_relative_to`, `BytesIO`); MEDIUM para os específicos de Windows/OneDrive (não reproduzidos)

**Research date:** 2026-10-09
**Valid until:** 2026-11-09 (repo estável; revalidar se `main.py`/`ml_anomalies.py` mudarem antes da execução)
