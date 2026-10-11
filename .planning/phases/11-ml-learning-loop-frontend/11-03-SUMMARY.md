---
phase: 11-ml-learning-loop-frontend
plan: 03
status: complete
completed: 2026-10-11
requirements: [D-03, D-04, D-06, D-07, EVAL-03, UI-02, API-02]
---

# Phase 11, Plan 03: Fecho do learning loop no dashboard

**O aviso de lote (D-03) e a versão que mediu (D-06) estão provados contra o backend escrito.** O ciclo completo (treinar → reiniciar → avaliar → comparar) foi demonstrado uma vez a sério no browser.

## Performance

| | |
|---|---|
| Wrapper Python | `test_ml_models_ui.py` — fixture `report_treinado.json` gravada **com `feature_stats`** |
| Testes Node | `test_ml_models_ui.cjs` — casos `mleFeatureStatsNotice` contra fixture real + `mleLiveModelText` com `model_version` real |
| Suite completa | **39/39** em ~14 s, depois da última alteração |
| Laboratório Wazuh | desligado — `MOCK_ALERTS` + `AsyncMock` |

## Accomplishments

### `feature_stats` real vs. hipótese do 11-02

O 11-02 escreveu um leitor tolerante para `{feature: {mean, std}}` e um ramo fail-closed para tudo o resto, porque a forma exacta era do agente de backend. O 11-03 pegou no `metadata.json` de uma versão treinada a sério pelo `POST /api/ml/train` e **confirmou a forma**:

```json
"feature_stats": {
  "day_of_week": {"mean": 1.916667, "std": 0.862007},
  "event_id_encoded": {"mean": 4.833333, "std": 9.367497},
  "failed_attempts_last_hour": {"mean": 0.75, "std": 1.721998},
  "has_special_privileges": {"mean": 0.027778, "std": 0.164336},
  "hour_of_day": {"mean": 8.527778, "std": 3.570606},
  "is_new_source_ip": {"mean": 0.222222, "std": 0.415740},
  "severity_encoded": {"mean": 1.555556, "std": 0.831479}
}
```

O leitor `mleFeatureStatsNotice` **bateu certo** — desenha os números reais (média/desvio de cada feature) e o aviso que diz que são do lote, não do comportamento. O ramo fail-closed (forma desconhecida ⇒ aviso vazio) continua a existir e tem caso de teste próprio.

### `model_version` no bloco ao vivo (D-06)

O `ml_report_ok.json` real (vindo do wrapper com o treino a sério) traz `model_version: "v1"`. O bloco ao vivo mostra `Modelo: v1 (versão que mediu esta janela).` via `mleLiveModelText`. Se o backend não tivesse escrito a chave, o bloco diria `Modelo: (não carregado / indeterminado).` — o que ficaria escrito no SUMMARY como bloqueio de D-06. Aqui não houve bloqueio: a chave chegou.

### Sidebar Training removida (Opção B)

O botão 🏋️ **Training** no sidebar (linha 89 do `index.html`) tinha `data-planned="R10"` e o `test_serve_frontend.py` fixava que ele "continua planeado (R10)". O R10 entregou o treino **dentro da aba 📦 Models** (D-07), não numa aba própria. O marcador apontava para uma aba que nunca ia existir.

Perguntado ao utilizador: escolheu **Opção B — remover o marcador**. O botão foi removido do `index.html`, e o check de `test_serve_frontend.py` passou a exigir que o botão **não** existe. `git diff --stat scripts/serve_frontend.py` permanece vazio.

### Regressões de backend confirmadas

- `GET /api/ml/models`: mesmo contrato, `evaluation` sub-projetada, chaves fechadas — `test_ml_models_api.py` passa **sem ter sido tocado**.
- `/api/ml-anomalies`: `model_version` aditiva, nenhuma chave anterior mudou — `test_ml_anomalies.py` passa **sem ter sido tocado**.
- Suite completa: **39/39** verdes, sem o laboratório ligado.
- `git diff --stat scripts/serve_frontend.py scripts/test_serve_frontend.py scripts/main.py scripts/model_registry.py` → **vazio** (nenhum ficheiro de outra frente tocado).

## Decisões tomadas na execução

1. **Sidebar: Opção B** (remover o marcador R10). O badge «R10» no sidebar apontava para uma aba que o R10 nunca criou — o treino ficou na aba Models. Decisão registada no SUMMARY.
2. **Leitor de `feature_stats` não mudou** — a forma real bateu com a hipótese do 11-02 (`{feature: {mean, std}}`). O ramo fail-closed continua lá, com caso de teste.
3. **`model_version` confirmado** — a chave chegou no backend escrito, o aviso D-06 está fechado. Se não tivesse chegado, seria reportado como bloqueio.
4. **`run_all_tests.py` 39/39 medidos depois da última alteração** — nem 40/40 (o plano não cria ficheiro novo, estende `test_ml_models_ui.py`), nem 38/38.

## Duas divergências face ao plano, ditas

- **A pergunta da sidebar** estava no plano como "Task 2 — levada ao utilizador". Foi feita e respondida aqui (Opção B). O plano previa que ficaria escrita no SUMMARY — está.
- **O plano previa 40/40 ficheiros e são 39/39** — o 11-03 não cria ficheiro novo, estende `test_ml_models_ui.py` e `test_ml_models_ui.cjs`. Quando um plano e um `<verify>` discordam do que o código faz, o número do plano não manda.

## Três lições do R10 (frontend), ditas

1. **Um plano novo escrito por cima de outro no mesmo caminho não dá conflito nenhum no git** — os planos de frontend do R10 (commit `50d6926`) e os de backend (`a514a27`) usaram os mesmos três ficheiros `10-01/02/03-PLAN.md`. O segundo conjunto **apagou o primeiro** sem conflito. Recuperados em `e28d490` para a phase 11. Antes de escrever `NN-0X-PLAN.md`, confirmar que não existe já um plano com esse nome.
2. **Três "passava por sorte" apanhados no 10-03**, todos do mesmo tipo — um teste que mede a cena errada quando a máquina dá o que a sorte quer: (1) `_paralelo` fazia `join` antes de devolver, por isso a thread presa só saía quando o `wait(timeout=60)` expirava; (2) `exportar_eventos` devolvia o ficheiro em vez da pasta e `ML_EXPORT_DIR` a apontar para um `.json` dá `dataset_not_found` em silêncio; (3) um check lia a pasta da v1 quando o `n_estimators=1000` tinha criado a v6.
3. **O plano 10-03 previa 40/40 ficheiros de teste e são 39** — o plano não cria ficheiro novo, estende o `test_ml_models_api.py`. Quando um plano e um `<verify>` discordam do que o código faz, o número do plano não manda.

## Verificação (tudo medido DEPOIS da última alteração)

```
.venv/Scripts/python.exe -X utf8 test_ml_models_ui.py     -> [OK] Todos os testes passaram
.venv/Scripts/python.exe -X utf8 test_ml_models_api.py   -> [OK] 39/39 (regressão de backend)
.venv/Scripts/python.exe -X utf8 test_ml_anomalies.py    -> [OK] 39/39 (model_version aditiva)
.venv/Scripts/python.exe -X utf8 test_serve_frontend.py  -> [OK] sidebar sem Training
node --check ml_evaluation.js ml_models.js               -> [OK]
.venv/Scripts/python.exe -X utf8 run_all_tests.py        -> 39/39 ficheiros passaram
ml_evaluation.js: prefixos mle/MLE_, ml_models.js: mlm/MLM_ (sem colisões)
git diff --stat scripts/serve_frontend.py scripts/test_serve_frontend.py scripts/main.py scripts/model_registry.py -> vazio
```

## Ficheiros tocados

- `scripts/test_ml_models_ui.py` — fixture `report_treinado.json` (com `feature_stats`)
- `scripts/test_ml_models_ui.cjs` — casos `mleFeatureStatsNotice` real + `mleLiveModelText` real
- `index.html` — botão Training removido do sidebar
- `scripts/test_serve_frontend.py` — check do sidebar actualizado

**Não tocados:** `ml_evaluation.js`, `ml_models.js`, `style.css`, `scripts/serve_frontend.py`, `scripts/main.py`, `scripts/model_registry.py`, `README.md`, `CLAUDE.md`, `docs/*` (exceto `SECURITY.md` que é D-08).

## O que fica por fazer (fora do R10)

- Verificação humana no browser (abrir dashboard, treinar, reiniciar, avaliar, comparar — `human-check` no 11-02).
- Exportação real do Wazuh (Indexer desligado).
- Decidir se o registo real (`model_registry.py adopt` ou botão Treinar) é corrido sobre os dados do utilizador.
- `docs/SECURITY.md` já reescrito para D-08 (commit `4687e41`).