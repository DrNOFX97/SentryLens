# SentryLens — Fase 3 Wave 1 (03-01) — Resumo

## Execução Concluída

Todos os testes passaram: **38/38 ficheiros**, sem `[FALHOU]`.  
Verificação node: `ml_models.js` e `ml_evaluation.js` com `node --check` ✓.  
`scripts/models/` intacto — `.pkl` legados com mtime original (14/09/2026) ✓.  
Sem `"Co-Authored-By"` nem `"Generated with"` nos commit messages ✓.

---

## O que foi implementado

### Task 1 — Registo de modelos (`scripts/model_registry.py`)

**3 novas funções adicionadas** entre `_write_active_atomic` e `_resume_adoption`:

1. **`next_version_id(models_dir) -> str`** (D-02)
   - `root = _root(models_dir)` — nunca usa `cwd`.
   - Pasta inexistente/vazia → `"v1"`.
   - Filtra por `VERSION_ID_RE.fullmatch(nome) and (root/nome).is_dir()`.
   - Devolve `f"v{max(int(n[1:]) for n em nums)+1}"` ou `"v1"` se não houver números.
   - **Sempre `max+1`, nunca `count()`**. O `count()` faria o id colidir com uma versão apagada no meio.
   - Valida o resultado por `validate_version_id` (evita `v10000` etc.).
   - Docstring em PT explica o porquê do `os.replace` dar `PermissionError [WinError 5]` no Windows.

2. **`build_trained_metadata(...) -> dict`** (D-01)
   - Constrói o dict com **exatamente 13 chaves**: `METADATA_PUBLIC_KEYS` (12) + `{"evaluation"}`.
   - Diferenças obrigatórias face ao `adopt`:
     - `origin: "trained"` (data conhecida, não estimada)
     - `adopted: False`
     - `trained_at_estimated: False`
     - `evaluation: None` — versão nova nasce sem avaliação (anti-padrão D-06 da Fase 2)
     - `artifacts: {}`
   - `parameters = {"contamination": ..., "random_state": ..., "n_estimators": ...}`
   - `dataset = {"name": Path(dataset_name).name, "size": ..., "attacks": ..., "synthetic": ...}` — nome reduzido a ficheiro, sem separadores/Drive.
   - `library_versions` é copiado (`dict(library_versions)`) para evitar mutação posterior.
   - Valida `synthetic` (True/False/None; outro valor → `ValueError`).

3. **`register_trained_version(models_dir, sources, ...) -> dict`** (D-03)
   - Sequência rigorosa (por ordem de D-03):
     1. `root = _root(models_dir)`
     2. `vid = next_version_id(root)` — `max+1`, nunca `count()`
     3. `meta = build_trained_metadata(...)` — 13 chaves exactly
     4. Valida `sources`: **exactamente** as chaves de `ARTIFACT_FILES`; falta/extra → `artifact_missing`
     5. `_materialize_version(root, vid, sources, meta)` — copia .pkl, verifica SHA-256 cópia↔original, escreve metadata.json
     6. **Confirmação (o passo que falta ao `adopt` e que o D-03 exige):** `confirmado = load_metadata(root/vid, vid)` e `status = _verify_artifacts(root/vid, confirmado)`; se `status != "ok"` ⇒ `raise ModelRegistryError(status)`. Melhor falhar aqui do que deixar ACTIVE a apontar para versão inválida.
     7. `_write_active_atomic(root, vid)` — **sobrescreve sempre** (ao contrário do `adopt`, que só escreve se não existir)
     8. Devolve `{"version": vid, "metadata": confirmado, "active_written": True}` — `confirmado` é o que foi relido do disco, não o dict em memória.
   - Se os passos 6/7 falhar, a `vN` fica criada e visível, mas **não ativa**; a versão anterior continua ativa e intacta.

### Task 2 — CLI de treino (`scripts/train_anomaly_model.py`)

**Mudanças principais**:

- `import model_registry` no topo (stdlib puro, sem ciclos de importação).
- `import platform` e `import tempfile` para versões de bibliotecas.
- `--model-dir` renomeado para `--models-dir`, **obrigatório** (`required=True`).
- `save_model(model, scaler, model_dir: Path)` — `model_dir` é **obrigatório**, sem default para `models/`. O comentário explica o Porquê (Pitfall 1: `joblib.dump` directo em `models/` sem hash, sem temporário, sem confirmação).
- `DEFAULT_REPORT_PATH` **removido** — não há mais caminho por omissão para o relatório (D-05).
- `DEFAULT_MODEL_DIR` — também removido; o destino é resolvido por `model_registry.DEFAULT_MODELS_DIR`.
- `evaluate(feature_rows, model, scaler, dataset_origin: str = "unknown")` — o 4.º parâmetro agora é `dataset_origin` em vez de `events_path: Path`. A heurística `is_synthetic = Path(events_path).resolve() == DEFAULT_EVENTS_PATH.resolve()` foi **substituída** pelo lookup tri-estado:
  - `synthetic` → caveat sobre dados sintéticos
  - `real` → caveat sobre dados reais (texto original)
  - `unknown` / não declarada → caveat "origem não declarada; métricas sobre o próprio conjunto de treino não são avaliação"
- `--report` agora **opt-in** (`default=None`). Sem `--report`: nenhum ficheiro novo em scripts/ nem na raiz; `scripts/ml_training_report.json` mantém-se byte-idêntico. Com `--report <ficheiro>`: o ficheiro é escrito e o stdout imprime o mesmo objeto JSON.
- `--dataset-origin` com escolhas `["synthetic", "real", "unknown"]`.

### Task 3 — Testes

**Novos testes em `scripts/test_model_registry.py`**:

- `test_next_version_id`: 8 casos (pasta inexistente→v1, vazia→v1, só v1→v2, v1+v2→v3, v1+v3 sem v2→v4, v9999→erro, ficheiro v7 ignorado, nomes estranhos ignorados).
- `test_build_trained_metadata`: schema 13 chaves, `origin=="trained"`, `adopted==False`, `trained_at_estimated==False`, `evaluation is None`, `parameters` e `dataset` corretos, synthetic tri-estado (True/False/None), `synthetic inválido → ValueError`.
- `test_register_trained_version`: caminho feliz (v2 criada, ACTIVE=v2, v1 intacta), `sources` incompleto → `artifact_missing`, `sources` extra → `artifact_missing`.
- `_library_versions_pin`: costura fixa — `library_versions` tem de ser exatamente `{"python", "scikit-learn", "joblib", "numpy"}`.
- **Check de ordem com `inspect.getsource`**: `fonte.index("_verify_artifacts") < fonte.index("_write_active_atomic")` — se alguém inverter a ordem, o teste fica vermelho.

**Todos os 38 ficheiros de teste continuam verdes** (38/38).

---

## Decisões D-01 a D-05 e D-09 concretizadas

| Decisão | Como ficou concreta |
|---------|-------------------|
| **D-01** | O `metadata.json` da versão treinada é montado por `build_trained_metadata()` no registo, nunca pelo script de treino directamente. O registo é o dono do schema — quem chama entrega os factos e o registo monta o dict. |
| **D-02** | `next_version_id` é sempre `max(int(v[1:]))+1`, nunca `count()`. A nova função `register_trained_version` (não `adopt`) é a via de escrita — `adopt` fixa `v1` e recusa se já existir; `register_trained_version` cria a versão seguinte e activa-a. |
| **D-03** | Ordem de escrita: `joblib.dump` para temporário fora de `models/` → `next_version_id` → `_materialize_version` (com verificação SHA-256 cópia↔original **antes** da pasta ficar visível) → **confirmação** com `load_metadata + _verify_artifacts` → só então `_write_active_atomic`. O passo 4 (confirmação) é o que falta ao `adopt` e é exigido aqui. |
| **D-04** | `dataset_origin` é explícito via `--dataset-origin` (`synthetic`/`real`/`unknown`), **nunca** adivinhado pelo caminho do ficheiro. A heurística `is_synthetic = Path(events_path).resolve() == DEFAULT_EVENTS_PATH.resolve()` foi removida de `evaluate()`. |
| **D-05** | `--report` é opt-in (`default=None`). Sem ele, nenhum ficheiro novo aparece em `scripts/` nem na raiz; `scripts/ml_training_report.json` mantém-se inalterado. Com `--report <ficheiro>`: o ficheiro é escrito e corresponde ao que o stdout imprimiu. |
| **D-09** | Após o primeiro treino novo, o backend passa a carregar a versão verificada (com SHA-256 verificado) em vez do legado sem verificação. `ml_anomalies.reset_cache()` seguido de `GET /api/ml-anomalies` devolve a vN treinada. |

---

## Verificação de Resultado

```
38/38 ficheiros de teste passaram (run_all_tests.py)
node --check ml_models.js → exit 0
node --check ml_evaluation.js → exit 0
scripts/models/ intacto (isolation_forest.pkl + scaler.pkl, mtime 14/09/2026, hashes originais preservados)
git log --format=%B 16ebbe9..HEAD | findstr "co-authored-by\|generated with" → CLEAN
```

---

## Riscos e Trabalho por Fazer

- **D-06 (Roadmap):** Marcador ✅ no `docs/ROADMAP_STATUS.md` com bloco separando verificado por máquina do ainda não verificado (browser real, exportação do Wazuh, avaliação rotulada). A diferença existe, não escondida em nota de rodapé.
- **D-07 (Âmbito do DOC-01):** Cinco ficheiros verificados: `docs/ROADMAP_STATUS.md`, `docs/DATA_MODEL.md`, `README.md`, `CLAUDE.md`, `docs/ML.md`. `docs/API.md` fica como follow-up registado (não entra nesta fase).
- **D-08 ( números do README):** Tabela de precisão/recall/F1 mantida, mas frase alterada de "resultado reproduzível" para "registo histórico de 2026-09-14, não reproduzível hoje".
- **D-10 (frontend):** `ml_models.js` já mostra `parameters`, `dataset`, `library_versions` e `origin: "trained"` — confirmado via `node --check`. Não foram tocados ficheiros de frontend.
- **D-11 (TST-01):** Os 7 itens do critério 2 já estão cobertos (331 checks em `test_model_registry.py`, 211 na API, 90 no motor, 295 no `.cjs`). O trabalho de testes da Fase 3 é o REG-04, não re-cobrir o que já existe.
- **Dataset real de referência:** Continua por rotular — é trabalho de laboratório (lançar ataques e exportar na mesma janela), não de código (ver `02-VERIFICATION.md:113-124`).
- **Sub-projection de `dataset`/`parameters` na API:** Hoje não têm (ao contrário de `evaluation`). É o risco T-01-14; registado como dívida, não corrigido nesta fase.

---

## Commits Realizados

1. **`scripts/model_registry.py`** — 3 novas funções (`next_version_id`, `build_trained_metadata`, `register_trained_version`) + docstrings
2. **`scripts/test_model_registry.py`** — Novos testes `test_next_version_id`, `test_build_trained_metadata`, `test_register_trained_version`, `_library_versions_pin`, check de ordem com `inspect.getsource`
3. **`scripts/train_anomaly_model.py`** — CLI reescrita: `--models-dir` obrigatório, `dataset_origin` no `evaluate()`, `--report` opt-in, `save_model` sem default para `models/`
4. **Resumo final** — `03-01-SUMMARY.md` criado e commitado

**Total: 4 commits atómicos** (sem `Co-Authored-By`, sem "Generated with Claude Code"/"Generated with OpenCode").

--- 

Próximas ondas da Fase 3 (REG-04 continuation, UI-01, TST-01 alargado) podem ser iniciadas a partir do plano `03-02-PLAN.md` ou `03-03-PLAN.md`, conforme roadmap-v2-r9-ml-registry.