# Phase 2: Avaliação ligada à versão - Research

**Researched:** 2026-10-10
**Domain:** gravação de avaliação ML (precisão/recall/F1 de ML vs regras) no `metadata.json` de uma versão de modelo, comando CLI `evaluate`, concordância ao vivo ML↔regras a partir de `/api/ml-anomalies`, e apresentação na aba Evaluation
**Confidence:** HIGH no que assenta em código lido nesta sessão; **MEDIUM** em duas QUESTÕES ABERTAS (o dataset real de 2026-09-14 desapareceu e não há forma de o reproduzir a partir do repo; o join entre rótulos e decisões do modelo não tem chave estável)

> Sem `02-CONTEXT.md` ainda (esta é a pesquisa que o alimenta). As decisões travadas D-01..D-08 de `01-CONTEXT.md` continuam válidas e são citadas por id; o `SKELETON.md` da Fase 1 é contrato e a Fase 2 tem de caber nele.

## Summary

A Fase 2 é, na maior parte, **montar o que já existe**. Não há dependências novas (`sklearn`, `joblib`, `numpy` já estão no venv), não há detector novo, não há métrica nova: `train_anomaly_model.evaluate()` [VERIFIED: `scripts/train_anomaly_model.py:51-90`] já calcula exactamente o que o ROADMAP pede (ML vs regras, precisão/recall/F1, contagens de comparação, aviso de dataset), e `ml_anomalies.build_ml_anomalies_report()` [VERIFIED: `scripts/ml_anomalies.py:87-137`] já devolve, por evento, `rule_flagged`, `ml_is_anomaly` e `agreement` — que é literalmente a "concordância ao vivo" do critério 4.

O que **não** existe e a Fase 2 tem de construir são quatro pontes:

1. **O dataset rotulado real desapareceu.** `ml_training_report.json` diz `real_events_2026-09-14.json` [VERIFIED: `scripts/ml_training_report.json:20`] e esse ficheiro **nunca existiu no git** (`git log --all --diff-filter=A -- "*real_events*"` → vazio) nem está no disco. O único dataset versionado é o sintético `sample_events_real.json` [VERIFIED: 17 664 B, 12/09/2026]. Consequência: **hoje não é possível reproduzir os números de 35 eventos/20 ataques**; o máximo reprodutível é o fixture sintético, cujos números reproduzi agora exactamente [VERIFIED: execução no venv → 36 eventos, 5 ataques, ML 0.4286/0.6/0.5, regras 0.625/1.0/0.7692 — igual à tabela de `docs/ML.md:40-49`].
2. **Não há como carregar os bytes de uma versão arbitrária.** `resolve_active_artifacts()` [VERIFIED: `scripts/model_registry.py:425-475`] só resolve o que está **ativo**. `evaluate vN` precisa de um `resolve_version_artifacts(root, "vN")` novo (compõe `resolve_version_dir` + `load_metadata` + `read_verified_bytes`, que já existem, linhas 170/234/355).
3. **`model_registry.py` não pode implementar a avaliação.** O SKELETON fixa-o como stdlib pura sem `joblib` [VERIFIED: `SKELETON.md:19`; docstring `scripts/model_registry.py:1-50`]. A avaliação precisa de `joblib`/`sklearn`. Reconciliação: um `ml_evaluation.py` novo, importado **dentro** de `_cmd_evaluate` (import tardio), mantendo `adopt` sem `joblib`.
4. **O join rótulo↔decisão é frágil.** `label_with_attack_log()` põe `is_attack` nas linhas de `extract_features()` [VERIFIED: `scripts/feature_extractor.py:177-195`], e `build_ml_anomalies_report()` devolve resultados **sem** `source_ip` [VERIFIED: `scripts/ml_anomalies.py:115-126`]; o único campo partilhado-fiável é `timestamp`. Dois eventos com o mesmo `@timestamp` colam. **QUESTÃO ABERTA.**

Achados não óbvios: (a) `evaluation` **não** passa por `METADATA_PUBLIC_KEYS` — é exposto em cru no nível da versão [VERIFIED: `scripts/model_registry.py:113-114`, `:517`, `:530`], e o único teto é `MAX_METADATA_BYTES = 65536` para o `metadata.json` inteiro [VERIFIED: linha 76] ⇒ qualquer texto que o `evaluate` grave vai cru para o browser e tem de ir por `escapeHtml`; (b) `build_ml_anomalies_report()` devolve `total: 0` e contagens a zero quando não há features [VERIFIED: linhas 92-96] — nunca `None`, logo "sem amostra" é uma decisão **do frontend** (`total == 0` ⇒ "Sem dados"), não um valor ausente; (c) já existe uma convenção de amostra pequena pronta a reusar: `soc_metrics.DEFAULT_MIN_SAMPLE = 5`, lida de `METRICS_MIN_SAMPLE` [VERIFIED: `scripts/soc_metrics.py:24`, `:36-41`] com `small_sample` e `reason: "no_data"`; (d) `evaluate` **não** pode escrever `metadata.json` com `os.replace` a meio sem readable rollback: um `metadata.json` truncado transforma a versão inteira em `metadata_invalid` (`load_metadata`, linha 247-258) e apaga-a da lista.

**Primary recommendation:** `python model_registry.py evaluate vN --events F --attack-log L` → importa tardiamente `ml_evaluation.build_evaluation_report(...)`, que (1) resolve e verifica os bytes da vN, (2) extrai features, (3) rotula com `feature_extractor.label_with_attack_log`, (4) **reusa `ml_anomalies.build_ml_anomalies_report`** para obter o veredicto por evento pelo mesmo caminho do dashboard, (5) calcula PRF com a mesma função `prf` de `train_anomaly_model`, e (6) devolve um dict `evaluation` que o CLI grava por escrita atómica com backup. Frontend: `mlmBuildEvalRows` passa a desenhar as métricas por versão + um bloco novo de concordância ao vivo alimentado por um segundo `fetch` a `/api/ml-anomalies`, com `total == 0` ⇒ "Sem dados".

## Project Constraints (from CLAUDE.md)

- API key **por rota** (`dependencies=_REQUIRE_API_KEY`), nunca a nível de app [VERIFIED: `scripts/main.py:755`, `:782`, `:813`].
- Erros HTTP com **códigos estáveis**; nunca `str(e)` nem caminhos. A lista de códigos é **fechada** (D-06, 9 códigos) [VERIFIED: `scripts/model_registry.py:101-111`].
- `main.py` é só a camada HTTP; a lógica vive em módulos puros `build_*_report`.
- Testes standalone `test_*.py` (sem pytest), `check()`/`sys.exit(1)`, `SENTRYLENS_API_KEY` **antes** de `import main`, `main.app.router.on_startup.clear()`, `run_all_tests.py` descobre `test_*.py` [VERIFIED: `scripts/run_all_tests.py:29`].
- Frontend: `serve_frontend.py` é whitelist fixa [VERIFIED: `scripts/serve_frontend.py:39-51`]; módulos de aba **não editam `app.js`**; todo o texto dinâmico por `escapeHtml`; identificadores de topo prefixados.
- Backend na porta 8001; sempre o venv de `scripts/`.
- **Sem `Co-Authored-By` do Claude** em commits/PRs (D-08).
- R9 é só leitura no backend: nada de escrever por HTTP. **A avaliação só entra por CLI.**
- `.gitignore` tem `scripts/models/` [VERIFIED: `.gitignore:19`] ⇒ nenhum `.pkl` nem `metadata.json` vai para o git; os testes nunca podem tocar em `scripts/models/` real.

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| EVAL-01 | A avaliação (ML vs regras, contagens, aviso do dataset) fica gravada no `metadata.json` **daquela** versão | Pattern 3 (`evaluation` no contrato, escrita atómica com rollback) |
| EVAL-02 | `python model_registry.py evaluate vN --events <ficheiro>` recalcula e grava | Pattern 2 (schema do objeto `evaluation`) + Pattern 4 (fluxo do CLI) |
| EVAL-03 | Versão sem avaliação ⇒ "Sem avaliação"; nunca números de outro modelo; aviso de amostra pequena sempre presente quando o nº de eventos é baixo | Pitfall 1 (números cruzados), Pitfall 4 (limiar de amostra), Pattern 6 (frontend) |
| UI-02 | Aba Evaluation: ML vs regras por versão + concordância ao vivo de `/api/ml-anomalies`, sem métricas/detectores novos, sempre com os avisos de dataset | Pattern 5 (o que já existe em `/api/ml-anomalies`), Pattern 6 (frontend) |

</phase_requirements>

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|---------------|----------------|-----------|
| Carregar os `.pkl` verificados de **uma versão arbitrária** | `model_registry.resolve_version_artifacts(root, vid)` (novo, stdlib) | `ml_evaluation` pede-lhe bytes | Reusa `resolve_version_dir`+`load_metadata`+`read_verified_bytes`; um só ponto com `joblib.load` mantém-se em `ml_anomalies` |
| Extrair features e rotular ataque/normal | `feature_extractor.extract_features/label_with_attack_log/load_attack_log` | — | Já é o módulo único partilhado treino/inferência |
| Decisão do modelo por evento | **`ml_anomalies.build_ml_anomalies_report(alerts, model, scaler)`** | — | É o caminho do dashboard; reusá-lo garante que os números não mentem |
| PRF + contagens + aviso | `ml_evaluation.build_evaluation_report` reusando o `prf` de `train_anomaly_model` | `train_anomaly_model.evaluate` (mantido, para retro-comparabilidade) | `sklearn.metrics` já é dependência |
| Gravar `evaluation` no `metadata.json` | CLI (`_cmd_evaluate` em `model_registry.py`) | — |Único ponto de escrita no registo (D-06/SKELETON:27) |
| Apresentação | `ml_models.js` (ou `ml_evaluation.js`, D-05) + `serve_frontend.py` whitelist | — | Padrão de `attack_library.js`/`metrics.js` |

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `joblib` | 1.4.2 [VERIFIED: venv] | carregar `.pkl` já verificados | Já usado em `ml_anomalies.py:16` |
| `scikit-learn` | 1.5.2 [VERIFIED: venv] | `IsolationForest` + `precision/recall/f1_score` | Já em `train_anomaly_model.py:24-26` |
| `numpy` / `scipy` | 2.5.3 / 1.18.1 [VERIFIED: venv] | dependências do sklearn | Já instaladas |
| stdlib (`json`, `os`, `tempfile`, `shutil`, `argparse`, `hashlib`) | Python 3.12.14 [VERIFIED: venv] | registo + CLI | Estilo do repo |
| Node | v24.14.1 [VERIFIED: `node --version`] | `node:vm` para os helpers puros de `ml_evaluation.js` | Já usado por `test_ml_models_ui.cjs` |

**Installation:** nenhuma. **Package Legitimacy Audit:** não aplicável — nenhuma dependência nova.

## Answers to the 8 questions

### 1. De onde vem o dataset rotulado hoje?

**O `ml_training_report.json` é um artefacto manual, não reproduzível a partir do repo.**

Cadeia rastreada:

| Ficheiro | Papel | Verificado |
|---|---|---|
| `scripts/ml_training_report.json` | Reporte com 35 eventos / 20 ataques, `caveat` a citar `real_events_2026-09-14.json` | `scripts/ml_training_report.json:2,3,20` |
| `scripts/train_anomaly_model.py:33` | `DEFAULT_REPORT_PATH` — o único código **vivo** que escreve este ficheiro | ✅ |
| `scripts/train_anomaly_model.py:114-116` | `main()` escreve o report com `--report` | ✅ |
| `scripts/feature_extractor.py:99,177,198` | `extract_features` → `label_with_attack_log` → `vectorize` | ✅ |
| `scripts/attack_scenarios.py:280` | `append_attack_log` grava `attack_log.jsonl` (12 entradas hoje, 06/10/2026) | ✅ |
| `scripts/export_snapshot.py:45,67` | Exporta `/api/alerts` + `/api/stats` + `attack_log.jsonl` para `snapshots/AAAA-MM-DD_HH-MM.json` | ✅ |
| `scripts/_generate_sample_ml_data.py:99-111` | Gerador **sintético** determinístico: escreve `sample_events_real.json` + `sample_attack_log.jsonl` | ✅ |

Achados:

- **`real_events_2026-09-14.json` não existe nem existiu**: `git log --all --diff-filter=A -- "*real_events*"` → vazio; `git log --all --name-only | Select-String real_events` → vazio; não está em `scripts/`. [VERIFIED]
- **`export_snapshot.py` não produz um ficheiro que o `evaluate` possa consumir.** O `docs/ML.md:71-75` diz-no explicitamente: o snapshot exporta o formato **já classificado** de `/api/alerts`, incompatível com o formato bruto que `feature_extractor` espera (`data.win.system.eventID`). Os 500 documentos brutos foram tirados **à mão** do Indexer. Ou seja: para voltar a ter um dataset rotulado real é preciso **exportar alerts brutos do Indexer por outra via** — não há hoje nenhum script vivo que o faça. [VERIFIED por leitura de `docs/ML.md:65-91` + ausência de qualquer gerador de eventos reais]
- **O caminho sintético é 100% reprodutível.** Executei agora, no venv, com saída para uma pasta temporária (nada escrito no repo):
  `train_anomaly_model.py --events sample_events_real.json --attack-log sample_attack_log.jsonl` → `total_events: 36`, `attacks_in_dataset: 5`, ML `0.4286/0.6/0.5`, regras `0.625/1.0/0.7692`, `comparison {both 3, ml_only 4, rules_only 5, neither 24}`. Idêntico à tabela de `docs/ML.md:40-49`. [VERIFIED]

**Isto decide a reprodutibilidade do `evaluate`:** o comando é reprodutível sobre qualquer dataset **que exista**; o dataset real de referência é irrecuperável. Ver Decisão D-2.

### 2. Como se rotula "ataque" vs "normal"?

O mecanismo **já existe e é puro**. É a única forma fiel e já implementada:

```python
# scripts/feature_extractor.py:177
def label_with_attack_log(features: list[dict], attack_log: list[dict],
                          window_seconds: int = 120) -> list[dict]
```
Devolve **uma nova lista** (nunca modifica `features` in-place), com `is_attack` ∈ {0,1} por evento, atribuído por **correspondência de janela temporal**: `start <= ts <= start + window_seconds` para qualquer entrada do log [VERIFIED: `scripts/feature_extractor.py:183-195`]. Entradas sem timestamp parseável são ignoradas (`_parse_timestamp` → `None`, linha 185-187).

Complementos:
- `load_attack_log(path: str) -> list[dict]` [VERIFIED: `scripts/feature_extractor.py:154-174`] — JSONL tolerante: ficheiro ausente ⇒ `[]`, linha truncada ⇒ ignorada.
- Default do log: `scripts/attack_log.jsonl`, sobreposto por `ATTACK_LOG_PATH` [VERIFIED: `scripts/main.py:122`].
- `attack_scenarios.append_attack_log(entry, log_path=DEFAULT_LOG_PATH)` grava `timestamp` de **lançamento** (não de conclusão) [VERIFIED: `scripts/attack_scenarios.py:280-282`, `:317-321`].

**Mecanismos alternativos e por que não servem como ground truth:**
- `redblue_correlator.build_redblue_report(attack_log, ml_results, scenarios, window_seconds=300, network_detections=None)` [VERIFIED: `scripts/redblue_correlator.py:115-121`] — exige `agent_ip == target` **e** `windows_event_id in scenario.event_ids`. É mais estrita (falso-negativo por IP errado, como o `docs/ML.md:159-163` avisa) e depende do `ml_results`, portanto **não pode avaliar um modelo sem antes o ter corrido**. Serve para "o ataque foi detetado?", não para "este evento é um ataque?".
- `attack_registry.build_attack_registry(...)` [VERIFIED: `scripts/attack_registry.py:107`] — deriva de `parse_launched_attacks` + `build_redblue_report` + incidentes; é uma **agregação por ataque**, não um rótulo por evento.
- `incident_engine` — agrupa evidência em incidentes; também por incidente, não por evento.

**Conclusão:** `label_with_attack_log` + `load_attack_log` é a forma correcta e já existente. O `evaluate` tem de a usar tal e qual, com `window_seconds=120` (o default histórico, o mesmo que produziu os 20 ataques de 2026-09-14).

### 3. O que conta como "regra" na comparação?

**Já está fixado no código e é exactamente `severity == "high"`.**

`README` diz "Regras (`event_catalog.py`)" e o que o pipeline usa é:

```python
# scripts/feature_extractor.py:122 e :141
classification = classify_alert(event_id)       # event_catalog.classify_alert
...
"rule_flagged": classification["severity"] == "high",
```
[VERIFIED: `scripts/feature_extractor.py:122`, `:141`]

- `classify_alert(win_event_id)` devolve `friendly_name`/`severity`/`category`/`recommendation`; Event ID desconhecido ⇒ `severity: "info"` [VERIFIED: `scripts/event_catalog.py:77-93`].
- O limiar é literal: só `high`. `medium` (4720, 4738, 4740, 4688, 4725, 4797, 4699, 4724, 4732, 4767) **não** conta como acerto.
- `has_special_privileges` (feature 5) usa `category == "atividade_privilegiada"`, **não** a severidade [VERIFIED: `scripts/feature_extractor.py:146`] — não confundir.

**Comparabilidade com `ml_training_report.json`: é possível, e o caminho de menor risco é NÃO reescrever.** O bloco `train_anomaly_model.evaluate()` [VERIFIED: linhas 51-90] já produz, byte a byte, o mesmo formato:

| Chave | `ml_training_report.json` | `train_anomaly_model.evaluate()` |
|---|---|---|
| `total_events` | 35 | `len(feature_rows)` |
| `attacks_in_dataset` | 20 | `sum(truth)` |
| `ml`/`rules` | precision/recall/f1 a 4 casas | idêntico, `round(..., 4)` |
| `comparison` | `both_flagged`/`ml_only`/`rules_only`/`neither` | idêntico |
| `caveat` | texto dinâmico conforme o `--events` | linhas 72-81 |

Para os números novos serem **comparáveis**, o `evaluate` tem de: (i) usar `classify_alert`→`severity=="high"` (grarante, se reutilizar `extract_features`); (ii) usar `sklearn.metrics.{precision,recall,f1}_score(..., zero_division=0)` com `round(4)`; (iii) usar `pred == -1` do `model.predict` — não `decision_function < 0` [VERIFIED: `scripts/ml_anomalies.py:111` e `scripts/train_anomaly_model.py:54` são iguais, portanto as duas implementações concordam hoje].

O que **não** é comparável: o `caveat` actual decide "sintético vs real" por comparação do path com `DEFAULT_EVENTS_PATH` [VERIFIED: `scripts/train_anomaly_model.py:72`] — uma heurística frágil que a Fase 2 deve substituir por um campo explícito (`dataset.synthetic`) no `metadata.json`, sem quebrar retro-compatibilidade.

### 4. Onde vive a lógica de anomalias que a avaliação tem de reutilizar?

Três funções públicas, todas reutilizáveis sem duplicar nada:

| Necessidade | Função a reutilizar | Assinatura / evidência |
|---|---|---|
| Carregar modelo+scaler **verificados** de uma versão | `ml_anomalies.load_model(model_dir=None)` — mas só serve a **ativa** | `scripts/ml_anomalies.py:32`; usa `model_registry.resolve_active_artifacts()` e faz `joblib.load(io.BytesIO(bytes))` [linhas 59-67] |
| Extrair features | `feature_extractor.extract_features(alerts)` | `scripts/feature_extractor.py:99` |
| Correr scaler + modelo | `ml_anomalies.build_ml_anomalies_report(alerts, model, scaler)` | `scripts/ml_anomalies.py:87` — faz `vectorize` → `scaler.transform` → `decision_function` + `predict` → `ml_is_anomaly` |
| Decisão por evento | o item de `results`: `ml_is_anomaly`, `rule_flagged`, `ml_score`, `agreement` | `scripts/ml_anomalies.py:111-126` |

**Não existe uma função pública "decide este evento"** — `build_ml_anomalies_report` é a única que chega ao `model.predict`. É *ela* que a avaliação tem de reutilizar, senão os números do `evaluate` e os do dashboard `/api/ml-anomalies` divergem (mesmo modelo, features diferentes) — o que o critério 4 proíbe implicitamente.

**Duas consequências arquitecturais:**

1. **Falta um carregador por versão.** `load_model` só vê a ativa e `resolve_active_artifacts()` [VERIFIED: `scripts/model_registry.py:425`] idem. `evaluate vN` sobre uma vN **não ativa** é impossível hoje. Falta `resolve_version_artifacts(models_dir, version_id) -> ArtifactSource`, que é literalmente o bloco `if active:` de `resolve_active_artifacts` (linhas 461-473) sem a lógica de `_active_state`. **A Fase 3 precisa dele também** (para treinar/avaliar a vN nova antes de a ativar).
2. **O `evaluate` tem de passar o modelo ao `build_ml_anomalies_report`, não carregá-lo.** O único ponto com `joblib.load` no projeto é `ml_anomalies.load_model` [VERIFIED: `scripts/ml_anomalies.py:63-64`, único `joblib.load` no repo]. Para não criar um segundo ponto de desserialização, o caminho certo é: `model_registry.resolve_version_artifacts()` devolve os bytes **verificados** → `ml_evaluation` faz `joblib.load(io.BytesIO(...))`… o que **viola** o ponto único. **Alternativa recomendada:** `ml_evaluation` delega em `ml_anomalies` — ganha-se uma função pública nova `ml_anomalies.load_version_artifacts(source) -> (model, scaler)` que faz o `joblib.load(io.BytesIO(...))` sobre bytes já verificados, mantendo `joblib.load` num único módulo. Isto é uma decisão de desenho para o planeador (ver Decisão D-3).

### 5. Contrato JSON — onde entra `evaluation`?

Confirmado no código:

- **`load_metadata` já valida `evaluation`**: `evaluation = meta.get("evaluation)`; se não for `None` nem `dict` ⇒ `metadata_invalid` [VERIFIED: `scripts/model_registry.py:284-286`]. A Fase 1 já valida o campo.
- **`evaluation` NÃO entra em `METADATA_PUBLIC_KEYS`** — comentário explícito na linha 113-114 ("é uma chave do nível da versão, não dos metadados"). A tupla tem 12 chaves e `evaluation` não está lá [VERIFIED: `scripts/model_registry.py:115-128`].
- **A projeção para a API é a metadata CRUA**: `evaluation = meta.get("evaluation")` e `"evaluation": evaluation` na entrada [VERIFIED: `scripts/model_registry.py:517`, `:530`]. Não há `evaluation_public_keys`, nem sub-projeção, nem saneamento. A entrada do legado tem `evaluation: None` hardcoded [VERIFIED: linha 547].
- **Em caso de erro da versão**, `metadata = evaluation = None` [VERIFIED: linha 520] — uma versão em `hash_mismatch` mostra `evaluation: null` mesmo que o `metadata.json` tenha avaliação. Isto é consistente com EVAL-03 ("sem avaliação ⇒ Sem avaliação") mas vale a pena está-lo no plano.
- **Único teto de tamanho**: `MAX_METADATA_BYTES = 65536` para o `metadata.json` inteiro [VERIFIED: linha 76]. Não há teto por campo.

Implicações para a Fase 2:

- O objeto `evaluation` gravado pelo CLI tem de ser **JSON-serializável, pequeno e redondo**. O `caveat` actual do `train_anomaly_model` é uma frase com o nome do ficheiro de eventos embutido [VERIFIED: `train_anomaly_model.py:77-81`] — se esse nome for um caminho, **vai cru para o browser** (só o `escapeHtml` o neutraliza como HTML, mas fica um caminho absoluto exposto na resposta da API). Recomendação: guardar só o **nome do ficheiro** (`Path(...).name`) ou nenhum, e a data.
- Todos os valores dinâmicos do novo objeto têm de entrar por `escapeHtml`/`mlmCell` no JS (risco residual **T-01-14**, já registado em `01-VERIFICATION.md:110-112`).

### 6. Concordância ao vivo

**Já vem calculada.** `build_ml_anomalies_report` devolve, no topo [VERIFIED: `scripts/ml_anomalies.py:130-137`]:

```json
{"total": N, "ml_anomalies_count": N, "rule_flagged_count": N,
 "agree_count": N, "diverge_count": N, "results": [...]}
```
e por evento, `agreement: "agree" | "diverge"` [linha 113]. A rota `GET /api/ml-anomalies?hours=24` devolve exatamente isto + `window_hours` [VERIFIED: `scripts/main.py:755-777`]. **Zero detectores novos, zero métricas novas** — o critério 4 é satisfeito só por ler `total`/`agree_count`/`diverge_count`.

**O que é reusável de `soc_metrics.py`** (a "cobertura" que o enunciado menciona):
- A convenção de honestidade: sem amostra ⇒ `None` (nunca 0) e `available: false` [VERIFIED: `scripts/soc_metrics.py:7-11`, `:66-73`, `:137`, `:171-177`].
- `DEFAULT_MIN_SAMPLE = 5` e `_min_sample_from_env()` lendo `METRICS_MIN_SAMPLE` [VERIFIED: linhas 24, 36-41].
- O padrão `{"available": bool, "reason": "no_data"|"source_unavailable"|None, "n": N, "small_sample": bool}` [VERIFIED: linhas 66-73, 153-161, 171-177].
- O texto no browser: `metrics.js:37-42` — `available === false` ⇒ "sem dados"/"fonte indisponível"; `small_sample` ⇒ "amostra pequena (n=…)".

**Mas attention — tensão real:** `build_ml_anomalies_report` com lista vazia devolve `total: 0, agree_count: 0, diverge_count: 0` [VERIFIED: linhas 92-96], **não** `None`. Logo o padrão `available` do R8 **não se aplica tal e qual**: ou o frontend mapeia `total === 0` ⇒ "Sem dados", ou a Fase 2 introduz uma projeção nova. Recomendo a **primeira** (zero backend novo), e é isso que a Decisão D-1 tem de fixar.

**Definição de "sem amostra" que a pesquisa recomenda:**
> "Sem dados" quando `total === 0` (nenhum evento com timestamp + Event ID válidos na janela) **ou** quando o pedido falhar com 503/502. Concretamente: 503 `hash_mismatch`/modelo ausente ⇒ o erro de D-06 traduzido por `MLM_ERROR_TEXT` (não "Sem dados"); 502 Indexer ⇒ erro; `total === 0` ⇒ "Sem dados — nenhum evento na janela".

Nota de escopo: `/api/ml-anomalies` está limitado a `hours` 1..168 [VERIFIED: `scripts/main.py:756`] e a 1000 alertas [linha 774]. A concordância ao vivo herda os mesmos limites — não precisa de `alerts_truncated` (ao contrário de `/api/metrics`), porque `build_ml_anomalies_report` não faz contagens de cobertura por ataque. Se a Fase 2 quiser mostrar isso, é **um campo novo** — ver Decisão D-4.

### 7. Testes — como estender sem duplicar

| Ficheiro | Papel | Helpers reutilizáveis (com linha) |
|---|---|---|
| `scripts/test_model_registry.py` (1108 linhas, 267 checks) | Domínio + CLI, sem `joblib`/`main` | `make_version(root, vid, model_bytes, scaler_bytes, model_sha, scaler_sha, **meta_overrides)` [linha 58] — **aceita `evaluation=` por override**, `make_legacy` [102], `write_active` [111], `flip_byte` [118], `versoes_por_id` [126], `entradas_legacy` [130], `espera_erro(func, *a, codigo=None)` [134], `fotografar` [598], `restos(root, prefixo)` [616], `replace_bloqueado(*nomes)` [622], `fixar_mtime` [590], `correr_cli(*args, timeout=60)` [947], `check` [40], `secao` [51] |
| `scripts/test_ml_models_api.py` (689 linhas, 142 checks) | Rotas via `TestClient` | `make_version(root, vid, ..., **meta_overrides)` [54] (também aceita `evaluation=`), `make_legacy` [91], `write_active(root, text, encoding=)` [100], `flip_byte` [104], `no_leaks`/`no_leaks_pasta` [112/120], **`alerta(event_id, ts, user, ip)`** [129], `MOCK_ALERTS` [140] (10 alertas mockados), **`real_model_bytes()`** [147] (treina um IsolationForest minúsculo via `train_anomaly_model.train_model` e devolve `(bytes_model, bytes_scaler)`), `ContadorJoblib` [161], `carregamento_verificado(client)` [366], `adocao_ponta_a_ponta(client)` [559] |
| `scripts/test_ml_models_ui.py` (142 linhas) | **Wrapper Python** → gera `report_v1.json`/`report_legacy.json`/`report_empty.json` a partir de `GET /api/ml/models` real com `TestClient` e chama `node test_ml_models_ui.cjs <pasta>` [linhas 99-130] | `make_version` [44], `make_legacy` [80], e o padrão: sem `node` no PATH ⇒ `check(..., False)` e sai (fail-closed, linha 92) |
| `scripts/test_ml_models_ui.cjs` (655 linhas, 185 checks) | Teste Node dos helpers puros em `node:vm` | Carrega o ficheiro real sem DOM [51-60]; extrai os helpers por nome numa **string literal** [62-69]; `versioned(over)` [149] e `legacy(over)` [178] como fixtures inline do contrato; `escapeHtml` reimplementado [27]; `D06_CODES` [37]; `fakeEvent(key, indice)` [504] |

**Como a Fase 2 os estende (não duplica):**
- `test_model_registry.py`: adicionar `test_eval_cli(...)` ao `run()` [linha 1079]. Precisa de `make_version(root, "v1", evaluation=...)` — **já funciona hoje** por causa do `**meta_overrides` [linha 95]. Reusar `correr_cli("evaluate", "v1", "--events", ...)`. ⚠️ `test_model_registry.py` **não importa joblib nem main** [linhas 4-6, 28] — os testes de CLI do `evaluate` que precisem de um `.pkl` real têm de usar bytes arbitrários + um módulo de avaliação injetado, ou ficar em `test_ml_models_api.py` (que já tem `real_model_bytes()`).
- `test_ml_models_api.py`: `real_model_bytes()` [147] + `MOCK_ALERTS`/`alerta()` [129/140] dão tudo o que é preciso para um teste ponta a ponta `evaluate → GET /api/ml/models → evaluation preenchido`. Reusar `no_leaks_pasta`.
- `test_ml_models_ui.py`: acrescentar um 4.º report **com avaliação** (ex. `report_evaluated.json`), gerado do mesmo registo depois de correr o `evaluate`. É o caminho idiomático já estabelecido.
- `test_ml_models_ui.cjs`: acrescentar uma **quarta** fixture de `/api/ml-anomalies` (o wrapper tem de a gerar com `main.indexer_client.get_recent_alerts = AsyncMock(return_value=MOCK_ALERTS)`, exactamente como `test_ml_models_api.py:381`). ⚠️ O `.cjs` tem hoje **185 checks** e nenhuma cobertura de `mlmBuildEvalRows` com números — a Fase 2 escreve essa cobertura.
- `run_all_tests.py` descobre `test_*.py` sozinho [linha 29] — um `test_ml_evaluation.py` novo é apanhado sem editar nada; mas o padrão dominante é **estender os três existentes**.

### 8. Ambiente

| Item | Estado | Versão |
|---|---|---|
| `scripts\.venv\Scripts\python.exe` | ✅ funciona | Python **3.12.14** [VERIFIED] |
| `scikit-learn` | ✅ presente | **1.5.2** [VERIFIED] |
| `joblib` | ✅ presente | **1.4.2** [VERIFIED] |
| `numpy` / `scipy` | ✅ presentes | **2.5.3** / **1.18.1** [VERIFIED] |
| Node | ✅ disponível | **v24.14.1** [VERIFIED] — `node --check` e `node:vm` OK |
| `pip` dentro do venv | ❌ **não instalado** (`No module named pip`) | — não é bloqueante: `requirements.txt` já está instalado; só impede `pip list`/`pip install` dentro do venv |
| Laboratório Wazuh | não necessário | tudo mockado |
| `scripts/models/` real | intacto — só os dois `.pkl` legados, sem `v1/` nem `ACTIVE` [VERIFIED `01-VERIFICATION.md:52-53`] | nunca tocar |

## Architecture Patterns

### Pattern 1 — `evaluation` no contrato: entra no `metadata.json` dessa versão e sai cru

`evaluation` é uma chave **do nível da versão**, fora de `METADATA_PUBLIC_KEYS` [VERIFIED: `model_registry.py:113-128`]. A API expõe-a verbatim [linha 517/530] e valida-a só como `dict | None` [linha 284-286]. Schema recomendado (dentro do teto de 64 KB do ficheiro inteiro):

```json
"evaluation": {
  "evaluated_at": "2026-10-10T12:00:00+00:00",
  "events_file": "real_events_2026-09-14.json",
  "attack_log": "attack_log.jsonl",
  "label_window_seconds": 120,
  "total_events": 35,
  "attacks_in_dataset": 20,
  "ml":      {"precision": 0.8571, "recall": 0.3,  "f1": 0.4444},
  "rules":   {"precision": 0.875,  "recall": 0.35, "f1": 0.5},
  "comparison": {"both_flagged": 5, "ml_only": 2, "rules_only": 3, "neither": 25},
  "min_sample": 50,
  "small_sample": true,
  "caveat": "Dataset pequeno (35 eventos, 20 ataques) — não é uma estimativa robusta de taxa de deteção."
}
```
Os 6 primeiros campos + `comparison` são **exatamente** o formato de `ml_training_report.json`, para que a comparação com o relatório histórico seja uma subtração mental e não um decipher. `min_sample`/`small_sample` são o que EVAL-03 exige que seja "sempre presente".

### Pattern 2 — `resolve_version_artifacts(models_dir, version_id) -> ArtifactSource`

O bloco `if active:` de `resolve_active_artifacts` [VERIFIED: `model_registry.py:461-473`] sem `_active_state`:

```python
def resolve_version_artifacts(models_dir, version_id) -> ArtifactSource:
    root = _root(models_dir)
    version_dir = resolve_version_dir(root, version_id)   # SEC-02: 2 camadas
    meta = load_metadata(version_dir, version_id)          # schema 1
    artifacts = meta["artifacts"]
    # os DOIS verificados ANTES de devolver qualquer coisa (SEC-01)
    model_bytes  = read_verified_bytes(version_dir, MODEL_FILE,  artifacts[MODEL_FILE]["sha256"])
    scaler_bytes = read_verified_bytes(version_dir, SCALER_FILE, artifacts[SCALER_FILE]["sha256"])
    return ArtifactSource(version=version_id, verified=True,
                          model_bytes=model_bytes, scaler_bytes=scaler_bytes)
```
`resolve_active_artifacts` passa a chamá-la, o que elimina a duplicação e garante que "avaliar a vN" e "carregar a vN ativa" usam **exatamente** as mesmas regras de integridade. É a função que a Fase 3 também vai precisar.

### Pattern 3 — Gravar `evaluation` sem poder partir a versão

Um `metadata.json` truncado ⇒ `metadata_invalid` ⇒ **a versão desaparece da lista** [VERIFIED: `model_registry.py:247-258` + `:518-520`]. Logo:

1. `load_metadata` primeiro (a versão tem de estar `ok` **antes** de escrever).
2. Escrever `metadata.json.tmp-<rand>` com `os.replace` (atómico, mesmo volume) — **nunca** escrever por cima.
3. **Verificação pós-escrita**: reler e confirmar que a avaliação gravada é a esperada; se algo estiver mal, o `.bak` anterior está intacto e o comando diz como repor.
4. Nunca tocar nos `.pkl` (o SHA-256 não muda, a versão continua íntegra).
5. `_verify_artifacts` continua a passar porque `metadata.json` não participa no hash dos artefactos [VERIFIED: `_verify_artifacts`, linhas 329-352].

**Isto altera só `evaluation`** — `created_at`, `trained_at`, `dataset` ficam intactos. É o que o critério 1 do ROADMAP exige ("as restantes versões não são alteradas").

### Pattern 4 — O fluxo do CLI

```
python model_registry.py evaluate v1 --events real_events.json [--attack-log attack_log.jsonl]
        │
        ├─ (tardio) import ml_evaluation          ← só aqui entra joblib/sklearn
        ├─ root = _root(models_dir or ML_MODEL_DIR or DEFAULT)
        ├─ source = model_registry.resolve_version_artifacts(root, "v1")   # SEC-01/SEC-02
        ├─ model, scaler = ml_anomalies.load_version_artifacts(source)      # joblib.load(BytesIO)
        ├─ alerts   = json.load(events)                 # lista de _source do Indexer
        ├─ rows     = feature_extractor.extract_features(alerts)            # regas já aplicadas
        ├─ rotulados= feature_extractor.label_with_attack_log(rows, log, 120)
        ├─ report   = ml_anomalies.build_ml_anomalies_report(alerts, model, scaler)   # MESMO caminho
        ├─ join     = rotulados <-> report["results"]        ← ver Pitfall 2
        └─ evaluation = { … }   → escrita atómica (Pattern 3)
```
⚠️ **Tensão com o SKELETON:** `SKELETON.md:19` fixa `model_registry.py` como stdlib pura sem `joblib`. O import tardio dentro de `_cmd_evaluate` mantém `adopt` limpo, mas `model_registry` deixa de ser "nunca importa joblib" — o que está literalmente escrito na docstring (`model_registry.py:7-10`). Alternativa: `ml_evaluation.py` com o seu próprio `main()`, e `model_registry.py evaluate` faz `os.execv`/import tardio só para delegar. **Ver Decisão D-3.**

### Pattern 5 — Reutilização do caminho do dashboard (sem duplicar)

`build_ml_anomalies_report(alerts, model, scaler)` é a **única** função que chega ao `model.predict` [VERIFIED: `ml_anomalies.py:105-106`]. Reusá-la garante que "o que o `evaluate` mediu" e "o que o dashboard mostra ao vivo" são a mesma conta. `ml_score` e `decision_function` ficam de fora do `evaluate` (são contínuos e não têm lugar numa métrica de classificação), mas `ml_is_anomaly` e `rule_flagged` são exactamente os dois lados da comparação.

Custo: `extract_features` corre duas vezes (dentro de `build_ml_anomalies_report` e para rotular). É aceitável (35 eventos, microssegundos) e **preferível** a duplicar a lógica — a alternativa (um helper novo `predict_rows(rows, model, scaler)`) é a opção "menos duplicação, mais superfície". Ver Decisão D-3.

### Pattern 6 — Frontend: `mlmBuildEvalRows` com métricas + bloco de concordância ao vivo

Estado atual [VERIFIED: `ml_models.js:370-386`]: 3 colunas (Versão / Ativa / Avaliação), e o texto do `evaluation` é literalmente *"Avaliação registada no metadata.json; a apresentação das métricas chega na Fase 2."*. Há um teste que **fixa** esse comportamento e que a Fase 2 tem de inverter [VERIFIED: `test_ml_models_ui.cjs:631-647`].

Extensão mínima, mantendo a arquitectura de duas camadas (puro/DOM):
- `mlmBuildEvalRows(report)` — uma linha por versão, agora com precision/recall/F1 de ML e de regras, `total_events`/`attacks_in_dataset`, e **sempre** a linha de aviso de amostra pequena (`small_sample === true` ⇒ texto, independente do resto).
- `mlmBuildLiveAgreement(mlReport)` — **novo** helper puro que recebe a resposta de `/api/ml-anomalies` e devolve `{html, state}` com três estados: `n === 0` ⇒ "Sem dados"; erro ⇒ nada (trata o erro com `MLM_ERROR_TEXT`, como as outras abas); caso contrário ⇒ concordância + contagens.
- `mlmEvalWasShown` já existe [VERIFIED: `ml_models.js:393`, `:526-528`] ⇒ o gancho para o segundo `fetch` já está lá.
- `index.html:619-649` tem de ganhar colunas (`precision/recall/F1` ×2 + dataset) e um painel novo para a concordância ao vivo. **Sem `ml_evaluation.js` novo** é mais simples; **com** é o que D-05 previa ("a Fase 2 cria o `ml_evaluation.js`") e o que o `serve_frontend.py:39-51` teria de whitelistar.

**D-05 é ambíguo hoje**: o texto de `01-CONTEXT.md:35` diz "a Fase 2 cria o `ml_evaluation.js`", mas o `SKELETON.md:107` diz o mesmo e a implementação da Fase 1 pôs a aba em `ml_models.js` com um único `fetch`. Splitting para um segundo ficheiro significa: segunda entrada na whitelist, segundo `MutationObserver`, e `test_ml_models_ui.cjs` passa a carregar dois ficheiros no mesmo `vm`. Não é caro, mas é trabalho a mais. **Ver Decisão D-5.**

### Anti-Patterns to Avoid
- Chamar `train_anomaly_model.train_model()` dentro do `evaluate` — isso **treina um modelo novo** e os números deixariam de ser sobre a versão avaliada. O `evaluate` tem de **carregar** os `.pkl` da vN.
- Chamar `train_anomaly_model.evaluate()` tal e qual e usar o seu `is_synthetic = Path(events_path) == DEFAULT_EVENTS_PATH` [VERIFIED linha 72] — a heurística quebra assim que o utilizador apontar a um dataset real com outro nome, e o `caveat` mentiria.
- `joblib.load(caminho)` no módulo de avaliação — quebra o ponto único de desserialização e o SEC-01 (verificar bytes e carregar o ficheiro são operações diferentes).
- Escrever `metadata.json` por cima (`write_text` directo) — um crash deixa a versão em `metadata_invalid` e some-a da lista.
- Usar `decision_function() < 0` em vez de `predict() == -1` — divergiria do dashboard.
- Derivar ground truth por `redblue_correlator` (exige `agent_ip == target` e `event_ids` do cenário) — subestima o ground truth e depende do próprio modelo.
- Mostrar `total: 0` como "0% de concordância" — é `0 == 0`, não um valor. Tem de ser "Sem dados".
- Reusar `soc_metrics.DEFAULT_MIN_SAMPLE` (5) para o aviso de amostra do `evaluate` sem dizer: 5 é o limiar **de SOC** (MTTD/rate), não de ML. 35 eventos com 20 ataques passaria num limiar de 5 e não merece um veredicto de robustez.
- Mexer em `app.js` ou nos testes existentes em vez de estendê-los.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Métricas PRF | contagens manuais | `sklearn.metrics.precision/recall/f1_score(zero_division=0)` + `round(4)` | Já é o que gera `ml_training_report.json`; comparar exige a mesma função |
| Carregar um `.pkl` verificado | `joblib.load(path)` | `model_registry.read_verified_bytes` + `ml_anomalies` a desserializar os mesmos bytes | SEC-01 / T-01-08 |
| Rotular ataque/normal | novo matching por `agent_ip` ou por severidade | `feature_extractor.label_with_attack_log(rows, log, 120)` | Já é o mecanismo que produziu os números históricos |
| Escrita atómica de JSON | `write_text` + rename manual | `tempfile` + `os.replace`, com backup | Windows/OneDrive bloqueiam ficheiros abertos (Pitfall 5 da Fase 1) |
| Contagem de concordância | recomputar ML↔regra no browser | `agree_count`/`diverge_count` de `/api/ml-anomalies` | Já vem pronto; critério 4 proíbe criar métricas novas |
| "Sem amostra" | `agree_count === 0 ? "0%" : ...` | `total === 0` ⇒ "Sem dados" | `total: 0` é o único sinal fiável (Pitfall 3) |

**Key insight:** a Fase 2 não tem um único número novo para inventar — tem **três pontes** a montar (carregar uma vN arbitrária, juntar rótulo a decisão, escrever o `metadata.json` sem o partir) e **um problema de dados** que não se resolve com código.

## Runtime State Inventory

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | `scripts/models/isolation_forest.pkl` (539 673 B) + `scaler.pkl` (767 B), sem `v1/`, sem `ACTIVE` [VERIFIED `01-VERIFICATION.md:52-53`]; `.gitignore:19` ignora `scripts/models/` | Nenhuma. `evaluate` escreve só em `models/vN/metadata.json`; testes em `TemporaryDirectory` |
| Stored data (avulsa) | `scripts/ml_training_report.json` (26/09/2026, 35 eventos), `scripts/sample_events_real.json` (sintético, 36 eventos), `scripts/sample_attack_log.jsonl` (2 entradas), `scripts/attack_log.jsonl` (12 entradas, 06/10/2026) | `ml_training_report.json` **não** é apagado nesta fase (critério 2 só proíbe mostrá-lo); o seu destino é do utilizador |
| Lost data | `real_events_2026-09-14.json` — nunca no git, não no disco | Nenhuma acção de código; **decisão do utilizador** sobre como substituir o dataset de referência |
| Live service config | `ML_MODEL_DIR`, `ATTACK_LOG_PATH` (`.env.example`), `METRICS_MIN_SAMPLE` | Reusar `ML_MODEL_DIR`; `ATTACK_LOG_PATH` para o `--attack-log`; `METRICS_MIN_SAMPLE` só como referência, não necessariamente como limiar |
| OS-registered state | `start-backend.ps1`; a cache do modelo é por processo (`loaded` != `active` depois de avaliar não muda nada, mas um `evaluate` **também não** recarrega) | Documentar "avaliar não muda o modelo em uso"; não pedir reinício |
| Secrets | `scripts/.env` | Nunca ler nem escrever |
| Build artifacts | `scripts/snapshots/` (não versionado; `export_snapshot.py` escreve lá) | Formato **incompatível** com `feature_extractor` (`docs/ML.md:71-75`) |

## Common Pitfalls

### Pitfall 1 — Números de outra versão (o critério 2 é o que a UI promete)
**What goes wrong:** a Evaluation mostra o `evaluation` da v1 na linha da v2, ou o `ml_training_report.json` quando a vN não tem avaliação. **Why:** o `evaluation` é **cru** (Pattern 1) e o browser recebe um dict arbitrário por versão. **How to avoid:** o helper puro tem de ler `entry.evaluation` **da própria entrada** e nunca um global; teste `.cjs` explícito com duas versões com avaliações diferentes. **Warning signs:** um `report.evaluation` no nível de topo em vez de `versions[i].evaluation`.

### Pitfall 2 — Join rótulo ↔ decisão por timestamp (QUESTÃO ABERTA)
**What goes wrong:** `extract_features` produz uma linha por evento **em ordem cronológica** [VERIFIED: `feature_extractor.py:113`, `:151`] e `build_ml_anomalies_report` itera `zip(features, scores, predictions)` [VERIFIED: `ml_anomalies.py:110`] ⇒ **as duas listas estão na mesma ordem e são paralelas 1:1**. O `timestamp` é, na prática, redundante. **Why funciona:** ambos chamam `extract_features(alerts)` com a **mesma** lista e a mesma função pura, logo os resultados são idênticos. **Why é frágil:** se alguém mudar `build_ml_anomalies_report` a meio (p.ex. a filtrar `full_log`), o `zip` deixa de estar alinhado e o `evaluate` passa a medir a coisa errada sem dar erro. **How to avoid:** preferir o índice posicional sobre o join por timestamp, e **fixar o comportamento num teste** (N eventos mockados ⇒ N linhas de rótulo alinhadas com N resultados). **Warning signs:** `len(rows) != len(report["results"])` numa comparação — se divergirem, falhar em vez de repartir.

### Pitfall 3 — "Sem amostra" é uma decisão defrontend, não um valor ausente
**What goes wrong:** mostrar `agree_count / total` com `total == 0` ⇒ "NaN%" ou "0%", que é mentira. **Why:** `build_ml_anomalies_report` devolve `total: 0, agree_count: 0` (inteiros) [VERIFIED: `ml_anomalies.py:92-96`], não `None`. **How to avoid:** `total === 0` ⇒ "Sem dados" no helper puro, com teste próprio. **Warning signs:** o texto "0,0 %" numa janela sem eventos.

### Pitfall 4 — Limiar de amostra pequena: 5 é o número errado
**What goes wrong:** reusar `soc_metrics.DEFAULT_MIN_SAMPLE = 5` [VERIFIED: `soc_metrics.py:24`] e mostrar 35 eventos sem qualquer aviso, ou mostrar aviso com 4 ataques. **Why:** o R8 usa 5 para "MTTD/rate de ataques lançados" — é um limiar de contagem de incidentes, não de um dataset ML. **How to avoid:** limiar próprio, com nome próprio (ex. `evaluation_min_events`, default 50) e um limiar **separado** para ataques (ex. 10), porque é o recall que explode com poucos positivos. **Warning signs:** um dataset de 35 eventos a passar o aviso.

### Pitfall 5 — O `caveat` com caminho absoluto
**What goes wrong:** `train_anomaly_model.evaluate()` embute `Path(events_path).name` [VERIFIED: linhas 77-81] — hoje só o nome, mas um `--events C:\Users\...\ficheiro.json` habitsua o padrão; e `evaluation` vai cru para a API. **Why:** API-02 proíbe caminhos nas respostas. **How to avoid:** guardar só o **nome do ficheiro** e, idealmente, um `synthetic: true|false` explícito em vez de inferir pelo path.

### Pitfall 6 — Reescrever `metadata.json` e partir a versão
**What goes wrong:** `write_text` directo e um crash/OneDrive deixa JSON truncado ⇒ `metadata_invalid` ⇒ a versão **desaparece da lista** e `/api/ml-anomalies` dá 503. **How to avoid:** Pattern 3 (temp + `os.replace` + `.bak` + verificação pós-escrita). **Warning signs:** o teste "evaluate duas vezes com o registo bloqueado a meio" (o padrão `replace_bloqueado` já existe em `test_model_registry.py:622`).

### Pitfall 7 — `joblib.load` num segundo sítio
**What goes wrong:** o módulo de avaliação faz `joblib.load(BytesIO(...))` por sua conta. **Why:** `ml_anomalies.load_model` é, por contrato do SKELETON (`SKELETON.md:20`), o **único** ponto de desserialização; um segundo `joblib.load` é uma superfície de RCE que o SEC-01 não cobre. **How to avoid:** Pattern 5 / Decisão D-3 — `ml_anomalies` expõe o carregamento a partir de bytes já verificados.

### Pitfall 8 — Regressão silenciosa nos testes que injetam `_model`/`_scaler`
**What goes wrong:** mexer em `ml_anomalies.load_model` ou na forma da cache parte `test_ml_anomalies.py`, `test_redblue.py`, `test_detections_api.py`, `test_attack_registry.py`, `test_metrics_api.py`, `test_incident_ingest.py` [todos com `ml_anomalies._model = fake_model` / `load_model = ...`]. **How to avoid:** preservar o curto-circuito `if _model is not None and _scaler is not None: return` como **primeira instrução** [VERIFIED: `ml_anomalies.py:56-57`]; `run_all_tests.py` verde (36/36 hoje) é o gate.

### Pitfall 9 — Colisões de globais JS
**What goes wrong:** um `const mlmX` repetido, ou um nome que já exista em `app.js`, rebenta o script inteiro [VERIFIED: comentário em `ml_models.js:6-8`]. **How to avoid:** prefixo `mlm`/`MLM_` em tudo; se entrar `ml_evaluation.js`, prefixo próprio (ex. `mle`) e `node --check`.

### Pitfall 10 — Amostra rotulada comAttack log do dia errado
**What goes wrong:** `--events` de 2026-09-14 com o `attack_log.jsonl` **de hoje** (06/10) ⇒ 0 ataques rotulados ⇒ recall 0,0 e um relatório que parece uma falha do modelo. **How goes wrong:** não há validação cruzada. **How to avoid:** o comando tem de **imprimir o nº de ataques rotulados** e, se `total_events > 0 and attacks_in_dataset == 0`, avisar explicitamente ("o log de ataques não cobre a janela dos eventos"). This is a `build_evaluation_report` invariant, cheap, and honest.

## Code Examples

### O único ponto de `joblib.load` a estender
```python
# scripts/ml_anomalies.py — hipótese de extensão (NÃO é produção, é o esboço)
def load_version_artifacts(source) -> tuple:
    """Bytes JÁ verificados (model_registry) -> (model, scaler) em memória.
    Único sítio com joblib.load, tal como load_model."""
    model  = joblib.load(io.BytesIO(source.model_bytes))
    scaler = joblib.load(io.BytesIO(source.scaler_bytes))
    return model, scaler
```

### O PRF partilhado (extraído de `train_anomaly_model.evaluate`, linhas 60-65)
```python
from sklearn.metrics import f1_score, precision_score, recall_score

def prf(truth: list[bool], flags: list[bool]) -> dict:
    return {
        "precision": round(precision_score(truth, flags, zero_division=0), 4),
        "recall":    round(recall_score(truth, flags, zero_division=0), 4),
        "f1":        round(f1_score(truth, flags, zero_division=0), 4),
    }
```
⚠️ `train_anomaly_model.py` tem `sklearn` no topo do ficheiro [VERIFIED: linhas 24-26]; se a Fase 2 mover isto para `ml_evaluation.py`, `train_anomaly_model.py` continua a ter o seu (ou passa a importar) — **não** deixar os dois em divergência.

### Reconciliação rótulo ↔ decisão sem duplicar (Pitfall 2)
```python
rows = feature_extractor.label_with_attack_log(
    feature_extractor.extract_features(alerts), log, window_seconds=120)
report = ml_anomalies.build_ml_anomalies_report(alerts, model, scaler)
if len(rows) != len(report["results"]):
    raise ...   # nunca repartir e medir a coisa errada em silêncio
truth   = [bool(r["is_attack"]) for r in rows]
ml      = [bool(r["ml_is_anomaly"]) for r in report["results"]]
regras  = [bool(r["rule_flagged"]) for r in report["results"]]
```

### Reprodução verificada nesta sessão (nada escrito no repo)
```powershell
cd scripts
.\.venv\Scripts\python.exe -X utf8 train_anomaly_model.py `
  --events sample_events_real.json --attack-log sample_attack_log.jsonl `
  --model-dir <TMP>\models --report <TMP>\report.json
```
→ `total_events: 36`, `attacks_in_dataset: 5`, ML `0.4286/0.6/0.5`, regras `0.625/1.0/0.7692`, `comparison {3, 4, 5, 24}`. Idêntico a `docs/ML.md:40-49`.

## State of the Art

| Old Approach | Current Approach | Impact |
|--------------|------------------|--------|
| `ml_training_report.json` avulso, sem ligação a nenhum modelo | `metadata.json` de cada `vN` com `evaluation` | rastreabilidade; critério 2 do ROADMAP |
| `train_anomaly_model.evaluate()` sobre os `.pkl` acabadinhos de treinar | `model_registry.py evaluate vN` sobre os `.pkl` **registados** | mede a versão que está no registo, não a que acabou de sair do treino |
| RecalcularFeatures e decisões em código novo | reusar `extract_features` + `build_ml_anomalies_report` | garante que o número do `evaluate` e o do dashboard são a mesma conta |

**Deprecated/outdated:** `docs/README.md` (estrutura antiga). `ml_training_report.json` fica como **evidência histórica** legível, mas nunca como fonte para a UI (critério 2). `docs/superpowers/plans/2026-09-12-fase6-ml-anomaly-detection.md:1674` descreve o pipeline como "demonstrado, não real" — superado pelo ciclo de 2026-09-14 descrito em `docs/ML.md:65-91`.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `extract_features` é puro e determinístico, portanto `build_ml_anomalies_report` e `extract_features` produzem listas paralelas na mesma ordem | Q4 / Pitfall 2 | Se não for, o `evaluate` mede o alinhamento errado. Mitigação: teste de igualdade de comprimento + comparação por índice |
| A2 | `sklearn` 1.5.2 no venv é a versão com que o modelo atual foi treinado (os `.pkl` de 14/09 carregam sem `InconsistentVersionWarning`) | Ambiente | Versão diferente ⇒ `joblib.load` falha no `evaluate`. `library_versions` está `null` em adotados (Fase 3 preenche) |
| A3 | O utilizador ainda tem acesso aos alertas brutos de 2026-09-14 (Indexer com 90 dias retention, ou cópias) | Q1 | Se não, o primeiro `evaluate` real tem de ser sobre o fixture sintético — ver Decisão D-2 |
| A4 | O `evaluate` não precisa de ser rápido o suficiente para cache | Q4 | Se o utilizador o correr sobre milhares de alertas, `build_ml_anomalies_report` corre `extract_features` duas vezes |
| A5 | Um único `--events` + `--attack-log` chega (não é preciso um modo "extrair do snapshot") | Pitfall 10 | `export_snapshot.py` produz um formato incompatível; se o utilizador quiser esse caminho, é um plano extra |

## Open Questions

1. **Dataset de referência.** O `real_events_2026-09-14.json` desapareceu. Não há script vivo que produza alertas brutos do Indexer num ficheiro que o `feature_extractor` consiga ler (`export_snapshot.py` exporta o formato já classificado, `docs/ML.md:71-75`). **O que seria preciso saber:** (a) o utilizador ainda tem os 500 documentos brutos algures (VM Wazuh, `/var/ossec/logs/...`, export manual)? (b) Ou aceitamos que o primeiro `evaluate` real corra sobre `sample_events_real.json`, o que torna os números **sintéticos** e obriga a dizer isso no painel? **Ver Decisão D-2.**
2. **Alinhamento rótulo↔decisão.** Assenta em `len(rows) == len(report["results"])` e na ordem cronológica idêntica. **O que seria preciso saber:** o planeador aceita o índice posicional com teste de guarda, ou prefere um `event_uid` novo em `extract_features` (que tocaria no contrato partilhado eしたがって na Fase 3 e nos testes existentes)? **Ver Decisão D-3.**
3. **Limiar de amostra pequena.** Não existe nenhum número no repo que diga quando 35 eventos são "poucos" para ML. `soc_metrics.DEFAULT_MIN_SAMPLE = 5` é de outro domínio. **O que seria preciso saber:** o utilizador quer um limiar único (ex. 50 eventos) ou dois (eventos **e** ataques, ex. 50 e 10)? **Ver Decisão D-1.**
4. **`evaluate` sobre alertas brutos ou sobre features já rotuladas.** O comando do ROADMAP é `--events <ficheiro>`, o que sugere alertas brutos do Indexer. Mas o `attack_log` correspondente também tem de ser indicado. **O que seria preciso saber:** é aceitável `--attack-log` opcional com default `$ATTACK_LOG_PATH` (o que torna o comando curto mas perigoso se o log não cobrir a janela), ou é obrigatório e explícito?
5. **Reprodutibilidade face ao `ml_training_report.json`.** O REQUIREMENTS não diz se os números novos têm de bater com os de 35/20. **O que seria preciso saber:** o utilizador quer (a) o mesmo formato e a mesma função PRF para comparação direta, ou (b) um formato novo, mais rico, em que a comparação com o relatório antigo passa a ser manual?

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Python venv `scripts/.venv` | CLI, testes | ✓ | 3.12.14 | — |
| `scikit-learn` | `IsolationForest`, métricas | ✓ | 1.5.2 | — |
| `joblib` / `numpy` / `scipy` | carregar `.pkl` | ✓ | 1.4.2 / 2.5.3 / 1.18.1 | — |
| Node | `node:vm` nos testes de UI | ✓ | v24.14.1 | revisão manual no browser |
| Laboratório Wazuh | — | não necessário (tudo mockado) | — | — |
| `pip` no venv | — | ✗ (não instalado) | — | irrelevante; nada novo a instalar |

**Missing dependencies with no fallback:** none.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | scripts standalone (`check()` + `sys.exit`), sem pytest |
| Config file | none — `run_all_tests.py` descobre `test_*.py` [VERIFIED: `run_all_tests.py:29`] |
| Quick run | `cd scripts && .venv\Scripts\python test_model_registry.py` / `test_ml_models_api.py` / `test_ml_models_ui.py` |
| Full suite | `cd scripts && .venv\Scripts\python run_all_tests.py` — **36/36 verdes hoje**, tem de continuar |
| Gate | `node --check ml_models.js` (+ `ml_evaluation.js` se existir) |

### Phase Requirements → Test Map
| Req | Behavior | Test Type | Ficheiro | Helpers a reusar |
|-----|----------|-----------|----------|-------------------|
| EVAL-01 | `evaluate` escreve `evaluation` no `metadata.json` da vN e **só** dessa; as outras versões ficam byte-idênticas | unit + integração | `test_model_registry.py`, `test_ml_models_api.py` | `make_version(**meta_overrides)`, `fotografar`, `correr_cli`, `real_model_bytes()` |
| EVAL-01 | `evaluation` escrito faz `load_metadata` continuar a passar e `build_models_report` a devolvê-lo | unit | `test_model_registry.py` | `build_models_report`, `versoes_por_id` |
| EVAL-02 | CLI: `evaluate v1 --events F --attack-log L` → código 0; id inválido → `invalid_version_id`; versão inexistente → `active_not_found`; `.pkl` adulterado → `hash_mismatch` **com 0 chamadas a `joblib.load`** | unit + integração | os dois | `espera_erro`, `flip_byte`, `ContadorJoblib`, `replace_bloqueado` |
| EVAL-02 | Eventos/ataques contados batem com o dataset | unit | `test_model_registry.py` (com `ml_evaluation` importado tardiamente) | `MOCK_ALERTS`, `alerta()` |
| EVAL-03 | `evaluation is None` ⇒ `evaluation: null` na API e "Sem avaliação" no browser; `evaluation` de outra versão **nunca** aparece na linha errada | integração + UI | `test_ml_models_api.py`, `test_ml_models_ui.cjs` | `versioned({evaluation: {...}})`, `mlmBuildEvalRows` |
| EVAL-03 | `small_sample: true` ⇒ o aviso está sempre presente, com n = total_events | UI | `test_ml_models_ui.cjs` | fixture com `evaluation` real |
| UI-02 | `mlmBuildLiveAgreement`: `total: 0` ⇒ "Sem dados" (nunca "0 %"); com amostra ⇒ percentagem + contagens; erro 503 ⇒ mensagem de `MLM_ERROR_TEXT` | UI (node:vm) | `test_ml_models_ui.cjs` + nova fixture do wrapper | `MLM_ERROR_TEXT`, `mlmCodeFromResponse` |
| UI-02 | `/api/ml-anomalies` continua intocada (a Fase 2 não muda a rota) | regressão | `test_ml_anomalies.py` | — |
| SEC-01/SEC-02 | `evaluate` não contorna a verificação: hash adulterado ⇒ sem `joblib.load` | integração | `test_ml_models_api.py` | `ContadorJoblib` (contador a 0) |
| Regressão | `run_all_tests.py` verde | suite | — | 36/36 hoje |

### Sampling Rate
- **Por commit de plano:** `python run_all_tests.py ml` (filtra por nome).
- **Por wave:** `python run_all_tests.py` completo.
- **Phase gate:** suite verde + `node --check` + **verificação humana no browser** (as abas Evaluation/Models nunca correram num browser real — `01-VERIFICATION.md:92-104`).

### Wave 0 Gaps (a fechar com o código, não depois — STATE.md:58)
- [ ] `test_model_registry.py` — `make_version` já aceita `evaluation=`; falta a secção CLI do `evaluate`.
- [ ] `test_ml_models_api.py` — avaliar a v1 real e ver `evaluation` na resposta de `/api/ml/models`.
- [ ] `test_ml_models_ui.py` — 4.ª fixture (registo com `evaluation`) + fixture de `/api/ml-anomalies` para o `.cjs`.
- [ ] `test_ml_models_ui.cjs` — **inverter** o teste `D-05` que hoje fixa "nenhum número é mostrado" (`test_ml_models_ui.cjs:646-647`).

## Security Domain

### Applicable ASVS Categories (nível 1)

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V5 Input Validation | sim | `--events`/`--attack-log` são caminhos fornecidos pelo utilizador; `--models-dir` + id pelo `resolve_version_dir`; nomes de `.pkl` sempre constantes |
| V6 Cryptography | sim | `sha256` + `hmac.compare_digest` **antes** de qualquer `joblib.load`, sem exceção |
| V8 Data Protection / Error handling | sim | `evaluation` cru no JSON ⇒ nada de caminhos absolutos nem de texto de exceção (API-02); erros só com códigos de D-06 |
| V12 Files | sim | escrita atómica de `metadata.json`; o `evaluate` **nunca** escreve nos `.pkl` nem no `ACTIVE` |
| V4 Access Control | sim | escrita só por CLI, nunca por HTTP (regra do marco) |

### Known Threat Patterns
| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| `.pkl` adulterado avaliado com `joblib.load` | Tampering/EoP | `resolve_version_artifacts` verifica os **dois** antes de devolver; nenhum byte não verificado chega ao desserializador |
| `metadata.json` truncado por um write directo | Tampering | temp + `os.replace` + `.bak` (Pattern 3) |
| Caminho de eventos absoluto a vazar para a API | Information disclosure | guardar só `Path(...).name`; `escapeHtml` em todo o valor |
| XSS via nome de dataset num `evaluation` futuro | Tampering | `escapeHtml`/`mlmCell` em todo o campo novo (T-01-14, já registado) |
| CLI a escrever fora de `models/` | Tampering | `resolve_version_dir` (regex + `parent == root`); nenhum nome vem do utilizador |
| `evaluate` a treinar um modelo novo por engano | Tampering | `evaluate` **carrega**, nunca `train_model`; teste que prova que `save_model` não é chamado |

## Sources

### Primary (HIGH — leitura directa/execução nesta sessão)
- `scripts/ml_anomalies.py`, `scripts/feature_extractor.py`, `scripts/train_anomaly_model.py`, `scripts/model_registry.py`, `scripts/event_catalog.py`, `scripts/soc_metrics.py`, `scripts/detection_event.py`, `scripts/redblue_correlator.py` (linhas 1-200), `scripts/attack_registry.py` (assinaturas), `scripts/incident_engine.py` (assinaturas), `scripts/incident_ingest.py:101-117`, `scripts/export_snapshot.py`, `scripts/_generate_sample_ml_data.py`, `scripts/attack_scenarios.py:265-324`, `scripts/serve_frontend.py:39-59`, `scripts/run_all_tests.py`, `scripts/main.py:108-137` + `:745-864`, `ml_models.js`, `index.html:617-649`, `metrics.js:37-126`, `scripts/test_model_registry.py`, `scripts/test_ml_models_api.py`, `scripts/test_ml_models_ui.py`, `scripts/test_ml_models_ui.cjs`, `scripts/ml_training_report.json`, `docs/ML.md`, `.gitignore`.
- `.planning/PROJECT.md`, `ROADMAP.md`, `STATE.md`, `REQUIREMENTS.md`, `phases/01-.../01-CONTEXT.md`, `SKELETON.md`, `01-RESEARCH.md`, `01-VERIFICATION.md`, `01-01..01-04-SUMMARY.md`, `01-01..01-04-PLAN.md` (consulta).
- Execuções nesta sessão: versões do venv (Python 3.12.14, sklearn 1.5.2, joblib 1.4.2, numpy 2.5.3, scipy 1.18.1); `node --version` (v24.14.1); reprodução completa do `train_anomaly_model.py` sobre o fixture sintético (saída para pasta temporária, **nada escrito no repo**); `git log --all --diff-filter=A -- "*real_events*"` (vazio); listagem de `scripts/*.json`, `*.jsonl`, `docs/`.

### Secondary / Tertiary
- Nenhuma fonte web usada. Afirmações sobre Windows/OneDrive (`os.replace` bloqueado) vêm do `01-RESEARCH.md` da Fase 1 e são [ASSUMED] como lá.

## Riscos e tensões com o contrato já implementado

1. **`model_registry.py` é stdlib pura por contrato** (`SKELETON.md:19` + docstring `model_registry.py:7-10`), mas `evaluate` precisa de `joblib`/`sklearn`. Reconciliação por import tardio — ou por um CLI separado. **Tensão real, precisa de decisão explícita.**
2. **Não existe carregador de uma versão arbitrária.** `resolve_active_artifacts()` só vê a ativa. Falta `resolve_version_artifacts()` — e a Fase 3 precisa dele tanto ou mais.
3. **`evaluation` é exposto cru** (fora de `METADATA_PUBLIC_KEYS`, sem sub-projeção, sem teto por campo). Qualquer string gravada vai para o browser; a UI tem de a tratar toda.
4. **O `.cjs` fixa hoje o comportamento oposto ao da Fase 2** (`test_ml_models_ui.cjs:646-647`: "nenhum número é mostrado (D-05)") — esse teste tem de ser invertido, não contornado.
5. **D-05 é ambíguo**: `01-CONTEXT.md:35` diz que a Fase 2 cria `ml_evaluation.js`; a implementação pôs a aba em `ml_models.js` com um `fetch` partilhado. Escolher `ml_evaluation.js` implica whitelist + segundo observer + o `.cjs` a carregar dois ficheiros.
6. **`soc_metrics.DEFAULT_MIN_SAMPLE = 5` não serve** para o aviso de dataset ML (Pitfall 4).
7. **O dataset de referência desapareceu** — o marco não consegue, só com código, reproduzir os números que `docs/ML.md` e o `ml_training_report.json` apresentam como evidência do projeto.
8. **`build_ml_anomalies_report` devolve zeros, não `None`** — a convenção `available/reason` do R8 não se aplica sem um mapeamento no frontend.

---

## Decisões que precisam do utilizador

### D-1 — Limiar (ou limiares) do aviso de "amostra pequena"
**Contexto:** EVAL-03 exige o aviso "sempre presente quando o nº de eventos é baixo". Hoje o dataset real tinha 35 eventos/20 ataques; o sintético 36/5. `soc_metrics.DEFAULT_MIN_SAMPLE = 5` é de outro domínio (MTTD/rate).
| Opção | Prós | Contras |
|---|---|---|
| **A. Um limiar só, `evaluation_min_events` (env), default 50** | simples, uma variável, aviso fácil de explicar | com 35/20 e 36/5 aparece aviso nos dois; um dataset com 49 eventos e 3 ataques passa como "grande" |
| **B. Dois limiares: eventos (50) e ataques (10), ambos em `evaluation`** | o recall com poucos positivos é o que explode; é o mais honesto | mais campos no contrato e no painel |
| **C. Reusar `METRICS_MIN_SAMPLE` (5) e o bloco de `soc_metrics`** | zero configuração nova | 35 eventos passariam sem aviso — viola o espírito do EVAL-03 |
**Recomendação: B.** Um limiar de eventos e um de ataques, em `evaluation`, com default 50/10, ambos override por variável de ambiente. Custa dois campos e resolve o caso que o projeto realmente tem.

### D-2 — Que dataset o primeiro `evaluate` real usa
**Contexto:** `real_events_2026-09-14.json` desapareceu e **não há script vivo** que produza alertas brutos compatíveis (`export_snapshot.py` exporta outro formato, `docs/ML.md:71-75`).
| Opção | Prós | Contras |
|---|---|---|
| **A. Aceitar o fixture sintético como primeiro dataset** | funciona hoje, zero dependências; os números ficam marcados como sintéticos em todo o lado | os números do dashboard passam a ser sintéticos — a "evidência real" do projeto fica sem reprodutibilidade |
| **B. Pedir ao utilizador os 500 documentos brutos (ou re-exportar do Indexer) e avaliar sobre esses** | é o que o PROJECT.md chama "dados reais" | depende de o utilizador os ter; bloqueia a demonstração |
| **C. Escrever agora um exportador de alertas brutos (`--raw` em `export_snapshot.py`)** | fecha o gap que `docs/ML.md` regista "para uma sessão futura" | é trabalho fora do âmbito da Fase 2 (um plano extra) |
**Recomendação: B com C como follow-up explícito.** Pedir os documentos agora; se o utilizador não os tiver, planear o exportador como tarefa da Fase 3 (é o `gap registado` de `docs/ML.md:74-75`). Nunca apresentar o sintético como real: o `evaluation` tem de levar `synthetic: true|false` explícito.

### D-3 — Onde vive o `evaluate` e como se liga ao `joblib.load` único
**Contexto:** `model_registry.py` é stdlib pura por contrato; `evaluate` precisa de `joblib`/`sklearn`; `ml_anomalies.load_model` é o único ponto de desserialização; e o alinhamento rótulo↔decisão assenta na ordem de `extract_features` (QUESTÃO ABERTA 2).
| Opção | Prós | Contras |
|---|---|---|
| **A. `ml_evaluation.py` novo (módulo de domínio com joblib) + import tardio em `_cmd_evaluate`** | um só ponto de entrada no CLI (SKELETON:27); `adopt` continua sem `joblib`; o módulo é testável isoladamente | `model_registry.py` deixa de ser "nunca importa joblib" (docstring a atualizar); o import tardio é um padrão que a CLAUDE.md não usa |
| **B. `ml_evaluation.py` com `main()` próprio; `model_registry.py` não ganha o subcomando** | a pureza do registo fica intacta | dois CLIs para o registo — contradiz o SKELETON:27 e D-06 |
| **C. `_cmd_evaluate` faz `os.execv` para o novo script** | pureza total | `os.execv` no Windows é frágil com paths do OneDrive |
| **D. (variante de A) adicionar `ml_anomalies.load_version_artifacts(source)` para manter um só `joblib.load`** | fecha o SEC-01 sem criar uma segunda superfície | mais uma função pública em `ml_anomalies` |
**Recomendação: A + D.** `ml_evaluation.py` com `resolve_version_artifacts` do registo + `ml_anomalies.load_version_artifacts` (único `joblib.load`) + `build_ml_anomalies_report` reusado tal e qual. O join rótulo↔decisão por **índice posicional**, com guarda `len(rows) == len(report["results"])` e um teste que o fixa — sem tocar no contrato de `extract_features`.

### D-4 — A concordância ao vivo mostra só o que `/api/ml-anomalies` já dá, ou ganha um campo?
**Contexto:** critério 4 — "obtida de `/api/ml-anomalies` (sem criar métricas ou detetores novos)". A rota devolve `total`, `agree_count`, `diverge_count` e `results` (com `agreement` por evento) [VERIFIED: `ml_anomalies.py:130-137`], e **limita-se a 1000 alertas e 168 h** [`main.py:756`, `:774`] sem qualquer sinal de truncagem.
| Opção | Prós | Contras |
|---|---|---|
| **A. Só `total`/`agree_count`/`diverge_count`; `total === 0` ⇒ "Sem dados"** | zero backend; cumpre o critério à letra | não avisa que a janela pode estar truncada — um acordo silencioso não é um acordo completo |
| **B. A + `alerts_truncated: bool` calculado na rota** | é o mesmo padrão de `/api/redblue/metrics` [`main.py:853-854`] e de `/api/metrics` (`soc_metrics.alerts_truncated`) | é um campo **novo** na resposta de uma rota existente — "métrica nova"? (é um sinal de integridade, não uma métrica) |
| **C. A + detalhamento por evento na UI (mini-tabela de divergências)** | é o que o analista quer de facto | traz N linhas ao DOM e um segundo desenho; `results` pode ter 1000 itens |
**Recomendação: A agora, B se o utilizador quiser.** A satisfaz o critério 4 sem ambiguidade; B é defensável mas é uma alteração a um contrato existente e o PROJECT.md põe "métricas ML novas" fora de âmbito. C fica para o R10.

### D-5 — `ml_evaluation.js` novo ou continuar em `ml_models.js`?
**Contexto:** D-05 diz "a Fase 2 cria o `ml_evaluation.js`"; a implementação da Fase 1 pôs as duas abas em `ml_models.js` com um `fetch` partilhado e um único `MutationObserver` por aba. A aba Evaluation agora precisa de **dois** pedidos (`/api/ml/models` + `/api/ml-anomalies`).
| Opção | Prós | Contras |
|---|---|---|
| **A. Continuar em `ml_models.js`** | zero whitelist nova, um só `mlmRefresh`, um só `.cjs` | o ficheiro cresce (~560 → ~800 linhas) e mistura duas fontes de dados |
| **B. `ml_evaluation.js` novo (como D-05 previa)** | separacao clara, o `.cjs` carrega os dois ficheiros no mesmo `vm`, prefixo próprio (`mle`) | nova entrada em `serve_frontend.py:39-51` + check em `test_serve_frontend.py` + segundo observer + segundo ciclo de vida |
**Recomendação: B.** D-05 foi escrito para isto, a aba tem um ciclo de dados diferente (dois endpoints, estados "Sem dados"/erro próprios), e um `MutationObserver` separado é o que `/api/ml-anomalies` precisa para não ser pedido ao abrir a aba Models. Custo: uma entrada na whitelist e um check de teste.

---

**Research date:** 2026-10-10
**Valid until:** 2026-11-10 (repo estável; revalidar se `ml_anomalies.py`/`model_registry.py` mudarem antes da execução)