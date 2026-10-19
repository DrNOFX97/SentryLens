# Phase 3: Treino gera versões, testes e documentação - Research

**Researched:** 2026-10-10
**Domain:** REG-04 (cada `train_anomaly_model.py` grava e ativa uma versão `vN` nova), TST-01 (cobertura de testes completa) e DOC-01 (documentação do registo de modelos + honestidade dos números ML)
**Confidence:** **HIGH** no que assenta em código lido e executado nesta sessão; **MEDIUM** na estimativa de tempo de treino (estimada por leitura, não medida — ver Q7) e em duas decisões de desenho que dependem do utilizador (D-1, D-3)

> Não há `03-CONTEXT.md` ainda (esta é a pesquisa que o alimenta). As decisões D-01..D-11 de `02-CONTEXT.md` e o `SKELETON.md` da Fase 1 continuam a ser contrato; este documento cita-os por id.

## Summary

A Fase 3 é **a mais barata das três em código e a mais pesada em honestidade**. As duas primeiras construíram o registo (`model_registry.py`), a avaliação (`ml_evaluation.py`) e os painéis (`ml_models.js` + `ml_evaluation.js`). O que falta é **fazer o treino participar do registo** e **parar de publicar números que o repo não consegue sustentar**.

Três achados que moldam o plano:

1. **O treino hoje escreve "por cima" e não participate em nada do registo.** `save_model()` [VERIFIED: `scripts/train_anomaly_model.py:93-96`] faz `joblib.dump(model, model_dir / "isolation_forest.pkl")` directamente nos dois `.pkl` **soltos** — o caminho que o `SKELETON.md:18` chama "o legado". Não há `import model_registry` no ficheiro [VERIFIED: `train_anomaly_model.py:19-28`], não há `--models-dir`, não há conceito de `vN`. O `--model-dir` existe [linha 103] mas aponta para a pasta, não para o registo, e o `--report` [linha 104] escreve `ml_training_report.json`, que é **versionado no git** [VERIFIED: `git ls-files` → `scripts/ml_training_report.json`].
2. **O caminho de escrita já existe e está testado — falta só o "qual `vN`" e o "com que metadados".** `_materialize_version(root, version_id, sources, meta)` [VERIFIED: `scripts/model_registry.py:711-758`] faz exatamente o que o REG-04 precisa: pasta temporária `vN.tmp-<rand>` (que não casa o regex, logo invisível à listagem — linha 644), `shutil.copy2` dos dois `.pkl`, SHA-256 conferido **entre a cópia e o original** antes de a pasta ficar visível (linhas 741-744), `metadata.json` escrito, `os.replace` atómico. O docstring diz literalmente *"Helper privado, mas reutilizável pela Fase 3 (treino a criar vN)"* [linha 729] e o `SKELETON.md:28` diz o mesmo. **O que não existe em lado nenhum**: uma função que calcule o "próximo id" (só há `sorted(version_ids, key=lambda v: int(v[1:]), reverse=True)` dentro de `build_models_report`, linha 647 — que produz uma lista, não um id), e o `meta` de uma versão treinada (`origin: "trained"`, `parameters`, `dataset`, `library_versions` preenchidos — hoje todos `None` em adotados [linhas 895-897]).
3. **O teste de disco do utilizador é real e já está em baixo.** Verifiquei que `os.replace` de uma pasta temporária **sobre uma pasta existente e não vazia** levanta `PermissionError [WinError 5]` no Windows [VERIFIED: medição nesta sessão, `C:\Users\fnuno\AppData\Local\Temp\opencode\probe_replace`]. Isto é uma boa notícia para o risco de integridade (não substitui uma `v1` por cima) e uma má notícia para o design: **`_materialize_version` nunca pode ser chamada com um `version_id` que já exista** — tem de calcular sempre o seguinte. E os testes **não** podem tocar em `scripts/models/`: `test_export_raw_events.py:733-735` compara o conteúdo de `scripts/models/` com `["isolation_forest.pkl", "scaler.pkl"]` antes e depois de correr — é um **guard explícito** que rebenta se um teste escrever lá.

O lado documentary é o mais substantivo: o README publica hoje uma tabela ML (0,86 / 0,30 / 0,44) calculada sobre um dataset de 2026-09-14 que **o `attack_log.jsonl` actual não rotula** (12 entradas, todas de 2026-10-06 [VERIFIED: leitura do ficheiro]). O `02-VERIFICATION.md:113-124` já Diagnosticou isto; a Fase 3 tem de o escrever sem apagar o histórico. A proposta na secção "Honestidade dos números" é: manter o número, marcá-lo como histórico e não reproduzível, e apontar para o comando que produz um número realmente rotulado.

**Primary recommendation:** o treino ganha **uma via nova** — `model_registry.register_trained_version(root, sources, meta)` (público, stdlib, dentro do `model_registry.py`, não um subcomando novo) — que (1) calcula `vN` seguinte a partir do que existe em disco, (2) monta/valida o `meta` treinado, (3) chama `_materialize_version`, (4) **re-lê com `load_metadata` + `_verify_artifacts`** (o mesmo `os.replace` da cópia é a prova de que o `.pkl` que vai ficar em disco é o que foi verificado), e (5) escreve o `ACTIVE`. `train_anomaly_model.py` chama-o e passa a ter `--models-dir`/`--dataset-origin`, mantendo `--model-dir` e `--report` para retro-compatibilidade (mas com aviso). Isto **não** passa pelo `adopt` (que copia do legado e recusa se já houver `ACTIVE` — linhas 918-926), porque o `adopt` tem duas travas que o treino não quer: `v1` fixa e "só escreve `ACTIVE` se não existir".

## Project Constraints (from CLAUDE.md)

- `model_registry.py` é **stdlib pura** por contrato [VERIFIED: `SKELETON.md:19`; docstring `scripts/model_registry.py:6-10`]. Existe um **gate por AST** que o projecto corre em cada plano [VERIFIED: `model_registry.py:1049-1053` descreve o mecanismo; o teste é `test_ml_models_api.py:747-762` com `_modulos_de`, mais o gate que o `02-VERIFICATION.md:80` dá como verde]. `register_trained_version` tem de respeitar isto: recebe `sources` (caminhos) e `meta` prontos e **não** importa `joblib` nem `sklearn`.
- **API key por rota**, nunca a nível de app; `GET /api/ml/models` já existe e não muda [VERIFIED: `scripts/main.py:790-820`].
- Erros HTTP com **códigos estáveis**; `ERROR_CODES` é uma lista **fechada** de 9 [VERIFIED: `model_registry.py:107-117`]. A Fase 3 **não pode acrescentar códigos** sem mexer na lista — e essa lista está duplicada em `ml_models.js:30-61` (`MLM_ERROR_TEXT`, 10 chaves = 9 + `unauthorized`) com teste [VERIFIED: `test_ml_models_ui.cjs:163-175`].
- `joblib.load` tem **um único ponto** em todo o projecto: `ml_anomalies` [VERIFIED: `ml_anomalies.py:63-64` e `:105-106`; teste negativo em `test_ml_models_api.py:761-762`].
- Testes standalone `test_*.py`, sem pytest, `check()`/`sys.exit(1)`, `SENTRYLENS_API_KEY` antes de `import main`, `main.app.router.on_startup.clear()`, disco em `tempfile.TemporaryDirectory()` [VERIFIED: `test_model_registry.py:7-15`; `test_ml_models_api.py:30-41`; `test_ml_models_ui.py:198-201`].
- `scripts/models/` está no `.gitignore` [VERIFIED: `.gitignore:19` (`scripts/models/`), testado em `test_export_raw_events.py:704-707`] ⇒ nenhum `.pkl` nem `metadata.json` vai para o git, e os testes **nunca** podem tocar na pasta real.
- Frontend: `serve_frontend.py` é whitelist fixa [VERIFIED: `scripts/serve_frontend.py:39-56`]; `ml_models.js` e `ml_evaluation.js` já lá estão [linhas 50-51]. **Um ficheiro novo na raiz tem de ser whitelisted + testado** — a Fase 3, pelo que tudo indica, **não precisa de nenhum** (ver Q2).
- `.ps1` novos com BOM UTF-8; nunca `Co-Authored-By` do Claude.

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| REG-04 | Cada execução de `train_anomaly_model.py` grava uma versão nova `vN` (a seguinte) com metadados completos e **ativa-a**; as anteriores ficam intactas | Pattern 1 (via de escrita nova, não o `adopt`), Pattern 2 (`vN` seguinte), Pitfall 1 (o `.pkl` novo nunca é verificado depois de escrito), Pitfall 2 (`os.replace` sobre pasta existente) |
| TST-01 | A suite standalone cobre registo, `adopt`, hash adulterado, id inválido, legado sem metadados, avaliação ausente e a rota; `run_all_tests.py` verde sem o laboratório | Q4 (inventário exacto: **os 7 itens já estão cobertos**; falta o que a Fase 3 introduz) + Pitfall 4 (nenhum teste toca em `scripts/models/`) |
| DOC-01 | `docs/ROADMAP_STATUS.md` com R9 ✅; `DATA_MODEL.md`, `README.md` e `CLAUDE.md` a descreverem o registo (versões, `ACTIVE`, `adopt`, SHA-256, `/api/ml/models`) | Q5 (secções exactas com linhas) + "Honestidade dos números" (texto PT-PT pronto) |

</phase_requirements>

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|---------------|----------------|-----------|
| Calcular a `vN` seguinte | `model_registry.next_version_id(root)` (novo, stdlib) | — | Não há nada hoje: `build_models_report:644-647` só ordena uma lista. Tem de ignorar pastas que não casem o regex (`.tmp-`) |
| Escrever a versão treinada | `model_registry.register_trained_version(root, sources, meta)` (novo, stdlib) | `_materialize_version` (privado, já pronto) | Mantém o registo como **único** ponto que escreve; `train_anomaly_model.py` fica sem `shutil`/`hashlib` |
| Produzir os `.pkl` | `train_anomaly_model.save_model()` | — | `joblib.dump` num diretório temporário **fora** de `models/`, passado como `sources` |
| Calcular SHA-256 | `_materialize_version` (linhas 741-745) | `sha256_file` | Já compara cópia↔original antes de a pasta ser visível |
| Decidir o que é a ativa | `_write_active_atomic` (linha 761) | — | Já é atómico e **sobrescreve** o `ACTIVE` (medido nesta sessão) — ao contrário do `adopt`, que só escreve se não existir |
| Verificar depois de escrever | `load_metadata` + `_verify_artifacts` (o `adopt` já faz isto, linhas 907-916) | — | É o que fecha a janela entre "gravei" e "está no disco" |
| Avaliar a versão nova | `model_registry.evaluate` (Fase 2, já pronto) | `ml_evaluation` | Não é responsabilidade do treino — o treino grava `evaluation: null` e o analista avalia à parte |

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| stdlib (`pathlib`, `tempfile`, `os`, `shutil`, `hashlib`, `json`, `datetime`) | Python **3.12.14** [VERIFIED: `scripts\.venv\Scripts\python.exe --version`] | registo + CLI | Estilo do repo; `model_registry.py` não pode ganhar mais nada (D-01) |
| `scikit-learn` | **1.5.2** [VERIFIED] | `IsolationForest` + métricas | Já em `train_anomaly_model.py:24-26` |
| `joblib` | **1.4.2** [VERIFIED] | `dump`/`load` dos `.pkl` | Já em `ml_anomalies.py:16` |
| `numpy` / `scipy` | **2.5.3** / **1.18.1** [VERIFIED] | dependências do sklearn | Já instaladas |
| Node | **v24.14.1** [VERIFIED: `node --version`] | `node:vm` nos testes de UI | Já usado por `test_ml_models_ui.cjs` |

**Installation:** nenhuma. **Package Legitimacy Audit:** não aplicável — nenhuma dependência nova.

## Answers to the 8 questions

### 1. `train_anomaly_model.py` hoje: o que escreve, onde, com que CLI, que dataset aceita

**O ficheiro tem 124 linhas e faz quatro coisas** [VERIFIED: leitura integral].

| Pergunta | Resposta | Evidência |
|---|---|---|
| **Que artefactos escreve** | Os **dois `.pkl` soltos** (`isolation_forest.pkl`, `scaler.pkl`) e **um JSON de relatório** (`ml_training_report.json`). Nada mais — nem `metadata.json`, nem `ACTIVE`, nem pastas `vN/`. | `save_model()` [`train_anomaly_model.py:93-96`]; escrita do report [`:115-116`] |
| **Em que caminho** | `model_dir` (default `scripts/models/`) para os `.pkl`; `DEFAULT_REPORT_PATH` = `scripts/ml_training_report.json` para o report. | [`:32-33`, `:103-104`] |
| **Que CLI tem** | `--events`, `--attack-log`, `--model-dir`, `--report`, `--contamination`. **Não tem** `--models-dir` (o registo), nem `--dataset-origin`, nem `--label-window-seconds`, nem nada que falte de versão. | [`:101-106`] |
| **Que dataset aceita** | **Qualquer JSON** que o `feature_extractor.extract_features` leia — isto é, uma lista de documentos **brutos** do Wazuh Indexer (`@timestamp` + `data.win.system.eventID`). O default é o **sintético** `sample_events_real.json` (36 eventos). O formato do `export_snapshot.py` **não serve** (já classificado). | [`:30-31`, `:36-40`]; `docs/ML.md:71-75`; `export_raw_events.py:6-12` |
| **Histórico JSONL?** | **Não.** O `--attack-log` é JSONL, mas é o log de **ataques lançados** (`attack_scenarios.append_attack_log`), não um histórico de alertas. O histórico JSONL do projecto (`history_store.py`) **não é lido pelo treino** — é uma fonte que existe e não é usada. | [`train_anomaly_model.py:39`]; `feature_extractor.load_attack_log:154-174` |
| **Sintético vs real** | **Adivinhado pelo caminho**: `is_synthetic = Path(events_path).resolve() == DEFAULT_EVENTS_PATH.resolve()` e o texto do `caveat` muda consoante [|`:72-81`]. É exactamente a heurística que a Fase 2 eliminou e substituiu por `--dataset-origin` declarado [VERIFIED: `ml_evaluation.py:34-37` e `:262-263`]. |

**Onde entra a `vN` e a escrita do `ACTIVE` sem quebrar o que existe:** hoje **não entra em lado nenhum** — e é esse o ponto. Três restrições que a escrita tem de respeitar:

1. **`joblib.dump` tem de ir para um diretório temporário fora de `models/`**, não para `models/`. Se.dumpar direto nos `.pkl` soltos, o `detect_legacy()` [linha 440-463] continua a vê-los e a entrada "legado" continua a aparecer **em cima da v2** [linha 676: o legado só desaparece quando `models/v1` existe] — o que é correto, mas significa que o utilizador fica com dois registos do mesmo modelo e a `vN` nova nunca é a ativa sem o `ACTIVE` trocar.
2. **A pasta `vN` tem de ser criada antes de o `ACTIVE` apontar para ela** (a ordem do `adopt`, documentada em [`model_registry.py:851-860`]). A ordem inversa deixaria o `ACTIVE` a apontar para uma versão inexistente — e `_active_state` é **fail-closed** nesse caso [linhas 283-287], o que daria 503 em vez de carregar a v1.
3. **`ml_training_report.json` é versionado** [VERIFIED: `git ls-files --error-unmatch`]. Continuar a escrevê-lo a cada treino significa que um `git status` fica sujo. Ver D-3.

**O que o ficheiro tem de ganhar, em linha:** `import model_registry` (tardio ou no topo — `model_registry` não importa sklearn, por isso **no topo é seguro** [linha 19-28 de `model_registry.py` só tem stdlib]); `--models-dir` com o mesmo semântica do resto (`$ML_MODEL_DIR` ou `DEFAULT_MODELS_DIR`, **nunca o cwd** [`model_registry.py:205-213`]); `--dataset-origin {real,synthetic,unknown}` com default `unknown` (coerente com `evaluate` [`model_registry.py:1297-1302`]); e a construção do `meta` treinado.

### 2. O que falta para o REG-04: assinaturas exactas e a decisão "adopt vs via nova"

**As três funções que a Fase 2 deixou prontas, com as assinaturas exactas** [VERIFIED por leitura de `scripts/model_registry.py`]:

```python
# scripts/model_registry.py:711
def _materialize_version(root: Path, version_id: str, sources: dict, meta: dict) -> dict
#   sources: {nome -> caminho} com nome em ARTIFACT_FILES ("isolation_forest.pkl", "scaler.pkl")
#   meta:    dict mutado in-place — ganha meta["artifacts"][nome] = {"sha256", "size_bytes"}
#   Devolve o mesmo meta. Levanta ModelRegistryError em qualquer OSError.

# scripts/model_registry.py:761
def _write_active_atomic(root: Path, version_id: str) -> None
#   Escreve root/ACTIVE com "<vid>\n" por mkstemp + os.replace. NÃO decide se deve escrever.

# scripts/model_registry.py:482
def resolve_version_artifacts(models_dir, version_id) -> ArtifactSource
#   Lê e VERIFICA os dois .pkl de UMA versão pedida. ArtifactSource(version, verified, model_bytes, scaler_bytes)
```

**O `_materialize_version` é exactamente o que o REG-04 precisa**, e o seu corpo já tem as três garantias que o critério exige: cópia temporária com nome que não casa `VERSION_ID_RE` [linhas 735, 644], SHA-256 conferido entre a cópia e o original **antes** de a pasta existir [linhas 741-744], `os.replace` atómico [linha 749], `finally` que apaga a temporária em qualquer caso [linhas 755-757]. O `adopt` só acrescenta a **confirmação pós-escrita** [`:907-916`] — e essa é a peça que responde à Q3.

**O que o treino precisa e ainda não existe** (tudo ausente, verificado por `Select-String` em `model_registry.py`):

| Falta | Onde deveria viver | Porquê |
|---|---|---|
| `next_version_id(root) -> str` | `model_registry.py` (público, stdlib) | Hoje só existe `sorted(version_ids, key=lambda v: int(v[1:]), reverse=True)` **dentro** de `build_models_report` [linha 647], que produz uma lista ordenada, não o id seguinte. `test_model_registry.py` já tem `v1` e `v2` em simultâneo [linha 268, `ids == ["v2", "v1"]`], por isso o teste do helper é trivial |
| `register_trained_version(root, sources, meta) -> dict` | `model_registry.py` (público, stdlib) | Sequência `next_version_id` → `_materialize_version` → confirmação (`load_metadata` + `_verify_artifacts`) → `_write_active_atomic`. Devolve `{"version", "metadata", "active_written"}` |
| O `meta` treinado | `train_anomaly_model.py` (ou um helper em `model_registry`, decisão D-1) | `origin: "trained"`, `adopted: false`, `trained_at_estimated: false`, `parameters: {contamination, random_state, n_estimators}`, `dataset: {name, size, attacks, synthetic}`, `library_versions: {python, scikit-learn, joblib, numpy}` |
| `--models-dir` e `--dataset-origin` no CLI do treino | `train_anomaly_model.py` | Ver Q1 |

**A decisão: `adopt` (cópia) ou via nova?** — **Via nova, e o código diz porquê.** [`model_registry.py:840-933`]

| Trava no `adopt` | Porquê quebra o treino |
|---|---|
| `v1_path.exists() → _resume_adoption` [linha 873-876] | O `adopt` só conhece `v1`. Na segunda vez que se treina, `v1` já existe ⇒ o comando entraria em `_resume_adoption`, que **recusa com `already_adopted`** [linha 815] |
| "`ACTIVE` só se não existir" (D-01) [linhas 918-926] | O REG-04 exige o contrário: o treino **tem de ativar** a `vN` nova. Este é o argumento decisivo |
| `origin: "adopted"`, `trained_at_estimated: true` [linhas 886, 893] | Mentira para um modelo acabado de treinar: a data é conhecida, não estimada a partir da mtime |
| Fontes: `sources = {nome: root / nome}` [linha 901] | O `adopt` copia **dos `.pkl` soltos**; o treino copia **do que acabou de escrever** noutro sítio |
| Pré-condição `detect_legacy(root) is not None` [linhas 869-870] | Se o utilizador já adotou (ou se os `.pkl` soltos já não existem), o `adopt` dá `no_legacy_model`. O treino não tem `.pkl` soltos para queimar |

Duas nuances que **não** são decisões, só factos: (a) `_write_active_atomic` **sobrescreve** o `ACTIVE` — confirmei nesta sessão que `os.replace` de ficheiro-sobre-ficheiro substitui o destino [VERIFIED] —, por isso o "só se não existir" é uma decisão **do chamador** [linha 769-770], não da função; (b) `_materialize_version` é_privada_ (underscore), mas o seu docstring **declara** que é reutilizável pela Fase 3 [linha 729] e o `SKELETON.md:28` repete. Chamá-la de dentro de `model_registry.py` (a nova `register_trained_version`) evita o problema de um módulo externo chamar uma função com underscore.

**Segurança:** a escrita nova não contorna nada. `_materialize_version` continua a ser o único que faz `shutil.copy2` para dentro de `models/`, `resolve_version_dir` continua a ser a única forma de chegar a uma pasta de versão, e `train_anomaly_model.py` nunca constrói um caminho dentro de `models/` a partir de dados do utilizador — só passa **nomes de pastas inteiramente controlados** ("v2") e **caminhos de origem** que são os do seu próprio temporário.

### 3. Contrapartida de segurança: um modelo acabado de treinar nunca é verificado ao ser escrito

**O facto, sem eufemismo:** hoje `save_model()` [`train_anomaly_model.py:93-96`] faz `joblib.dump` **directamente no destino final**, sem hash, sem temporário, sem confirmação. Um `Ctrl-C` a meio do `dump` de um `isolation_forest.pkl` de ~540 KB deixa um ficheiro truncado que o `joblib.load` vai explodir com um erro que não é código estável. **E `resolve_version_artifacts` — que existe desde a Fase 2 [linha 482] — nunca é chamado pelo treino**, porque o treino não conhece o registo [VERIFIED: `train_anomaly_model.py:19-28` não importa `model_registry`].

**A ordem correcta** (é a do `adopt`, que é a única ordem já provada neste código, [`model_registry.py:851-860` + `:904-926`]):

```
1. joblib.dump para um diretório temporário FORA de models/     ← fora do registo
2. next_version_id(root) -> "v2"                                ← o registo decide o nome
3. _materialize_version(root, "v2", sources, meta)
     3a. mkdtemp("v2.tmp-", dir=root)                           ← invisível à listagem
     3b. copy2 dos DOIS .pkl
     3c. sha256(cópia) == sha256(original)  -> se não bater: hash_mismatch, nada escrito
     3d. meta["artifacts"][nome] = {sha256 da CÓPIA, size}
     3e. escreve metadata.json
     3f. os.replace(tmp, root/"v2")                            ← atómico
4. CONFIRMAÇÃO: load_metadata(root/"v2", "v2") + _verify_artifacts(...) == "ok"
                                                             ← o `adopt` faz isto em :907-916
5. _write_active_atomic(root, "v2")
```

O passo 4 é o que responde a esta pergunta, e **o `adopt` já o faz** [linha 907-916, com o comentário *"melhor falhar aqui do que deixar um ACTIVE a apontar para uma versão que não verifica"*]. Sem ele, uma falha de I/O entre 3 e 5 deixa um `ACTIVE` a apontar para uma versão meio escrita — e como `_active_state` é fail-closed [linhas 283-287], isso **não** volta a cair para o legado: dá 503. Melhor 503 do que carregar bytes não verificados, mas evitável.

**Onde pode haver janela:**

| Janela | Risco | Quem fecha |
|---|---|---|
| Entre 3f e 5 | `ACTIVE` aponta para `v2` que pode não verificar. `resolve_active_artifacts` → `resolve_version_artifacts` [linha 550] **verifica na leitura**, portanto o pior caso é um `hash_mismatch` honesto, não bytes não verificados a carregar | `_verify_artifacts` no passo 4 fecha; e mesmo sem ele, a leitura re-verifica |
| Entre 5 e o backend recarregar | O processo continua com `v1` em memória. O dashboard **já diz isso**: `mlmModelsNoticeText` compara `loaded != active` [VERIFIED: `ml_models.js:211-213`] | É o cache por processo, por desenho (D-02). O CLI tem de repetir o aviso "reinicia o backend", como o `adopt` faz [`model_registry.py:1154`] |
| Entre o `dump` (1) e o `os.replace` (3f) | O `.pkl` a meio nunca é visível: a pasta temporária não casa `VERSION_ID_RE` [linha 644] | `_materialize_version` |
| **Entre o `joblib.dump` (1) e o `_materialize_version` (3)** | **O `.pkl` existe num sítio temporário do utilizador, sem hash.** Se esse temporário for `scripts/models/` em vez de fora, estamos a reintroduzir o problema | Dump para `tempfile.mkdtemp()` **do sistema** (fora de `models/` e fora do OneDrive — ver Q8) |
| `metadata.json` truncado | A versão desaparece da lista com `metadata_invalid` | Não se aplica: `_materialize_version` escreve o JSON **antes** do `os.replace`, e a pasta só passa a existir inteira [linhas 746-749] |
| `ACTIVE` truncado | `invalid_version_id` fail-closed | `_write_active_atomic` por `mkstemp`+`os.replace` [linhas 775-778] |

**O limite honesto que a documentação tem de manter (D-04, já registado):** o SHA-256 **detecta corrupção e troca acidental, não autentica**. Quem escreve em `models/` reescreve também o `metadata.json`. Isto **vale ainda mais** para uma versão treinada do que para uma adotada: o `metadata.json` de uma versão treinada é gerado pelo mesmo processo que escreveu o `.pkl`, ou seja, o hash é uma **auto-atestação** — o que o registo garante é "isto não mudou *desde o treino*", não "isto foi treinado por mim". Ver a formulação proposta em "Honestidade dos números".

### 4. Cobertura de testes actual (TST-01): inventário exacto

**Contagens medidas nesta sessão** (contagem de linhas `[OK   ]` no stdout de cada ficheiro, não de `check(` — porque `test_ml_models_ui.py` imprime também o stdout do Node):

| Ficheiro | Checks | Executado | Tem o que |
|---|---|---|---|
| `scripts/test_model_registry.py` | **331** | ✅ verde | 18 secções (`run()` linha 1358-1378) |
| `scripts/test_ml_models_api.py` | **211** | ✅ verde | 3 blocos: rota (a-x), SEC-01, REG-03, EVAL-01 |
| `scripts/test_ml_evaluation.py` | **90** | ✅ verde | 10 secções do motor |
| `scripts/test_export_raw_events.py` | **142** | ✅ verde | 11 secções do exportador |
| `scripts/test_ml_models_ui.py` | **23** (wrapper) | ✅ verde | 4 fixtures de `/api/ml/models` + 3 de `/api/ml-anomalies` + CLI `evaluate` real |
| `scripts/test_ml_models_ui.cjs` | **295** | ✅ verde | helpers puros de `ml_models.js` **e** `ml_evaluation.js` em `node:vm` |
| `scripts/test_serve_frontend.py` | (não contado) | ✅ verde | whitelist, ordem dos `<script>`, prefixos `mlm`/`mle`, ausência de colisões |
| **Total `run_all_tests.py`** | — | ✅ **38/38 PASS em ~86 s** [VERIFIED nesta sessão] | — |

**Os 7 itens do critério 2, um a um** — com o nome dos testes, porque é isso que permite ao planeador ver que **não há trabalho a inventar**:

| # | Item | Onde está coberto hoje | Estado |
|---|---|---|---|
| 1 | **registo** | `test_model_registry.py::test_reg01` (lista v1+v2, ativa marcada, `METADATA_PUBLIC_KEYS` projetadas, chave extra não vaza) + `test_reg02` (legado) + `test_root_e_inexistente` (pasta vazia/inexistente) | ✅ **coberto** |
| 2 | **`adopt`** | `test_model_registry.py`: `test_adopt_copia_o_legado` (cópia, originais intactos por `fotografar`), `test_adopt_d01` (ACTIVE não é reescrito), `test_adopt_pre_condicoes`, `test_adopt_falha_a_criar_a_v1`, `test_adopt_falha_so_no_active_e_retoma`, `test_adopt_retomas_recusadas`, `test_cli_adopt`, `test_cli_recuperacao`; `test_ml_models_api.py` bloco "(q) adoção ponta a ponta" e "(r) adopt interrompido" | ✅ **coberto** (é a secção mais grossa do suite) |
| 3 | **hash adulterado recusado** | `test_model_registry.py::test_sec01`; `test_ml_models_api.py` (l) modelo adulterado, (m) scaler adulterado, (t) `evaluate` com `.pkl` adulterado — **com `ContadorJoblib` a fixar `joblib.load` em 0** [linha 184-193] | ✅ **coberto** |
| 4 | **id inválido recusado** | `test_model_registry.py::test_sec02_ids` (`../x`, `v1\n`, `V1`, `v12345`, `""`, não-str), `test_sec02_junction` (symlink/junction para fora), `test_sec02_active` (ACTIVE `v9`, UTF-16, >64 bytes); `test_ml_models_api.py` (g), (n), (u) `evaluate ../x` | ✅ **coberto** |
| 5 | **legado sem metadados** | `test_reg02`; `test_ml_models_api.py` (k) `loaded == "legacy"` depois de um `joblib.load` real; `test_ml_models_ui.cjs` linhas 331-347, 663-665 (badge, ausência de badge de erro) | ✅ **coberto** |
| 6 | **avaliação ausente** | `test_ml_models_api.py` (d) `evaluation` presente e `None`, (q) `evaluation None`, (v) "a v2 sem avaliação continua null"; `test_ml_evaluation.py` (9 secções,incluindo `validate_evaluation`); `test_ml_models_ui.cjs` 730, 803-807 ("Sem avaliação", nunca números de outra versão) | ✅ **coberto** |
| 7 | **rota `GET /api/ml/models`** | `test_ml_models_api.py` **inteiro** (211 checks): (a) 401 sem key, (b)-(f) formas do relatório, (g)/(i) erros, (j)-(m) SEC-01, (o)-(p) cache, (q)-(x) adopt/evaluate; `test_ml_models_ui.py` gera 4 relatórios reais | ✅ **coberto** |

**Conclusão honesta: os 7 itens do critério 2 já estão todos cobertos.** O `STATE.md:59` já o dizia ("TST-01 fecha na Fase 3, mas os testes de cada fase escrevem-se com o respetivo código") — e foi cumprido. **O que falta para TST-01 não é re-cobrir isto: é cobrir o que a Fase 3 introduz.** Concretamente:

| Falta (a escrever com o código) | Ficheiro natural |
|---|---|
| `train_anomaly_model.py` grava `vN` **seguinte** e **ativa-a** | novo `test_train_registry.py`, ou secção nova em `test_model_registry.py` |
| Treino duas vezes ⇒ `v1` e `v2`, `v2` ativa, **`v1` byte-idêntica** | o mesmo |
| `origin: "trained"`, `adopted: false`, `trained_at_estimated: false`; `parameters`/`dataset`/`library_versions` preenchidos (hoje `None`) | o mesmo |
| O `metadata.json` treinado **passa** `load_metadata` e `_verify_artifacts` | o mesmo |
| Hash adulterado **na versão treinada** ⇒ `hash_mismatch` e 0 `joblib.load` | `test_ml_models_api.py` (reusar `real_model_bytes()` + `ContadorJoblib` [linhas 147, 161-193]) |
| `dataset.synthetic` reflecte o `--dataset-origin`, **nunca** o caminho | o mesmo |
| `_verify_artifacts` no passo 4 falha ⇒ **nenhum `ACTIVE` escrito** | o mesmo (o `adopt` já tem `replace_bloqueado` [linha 558] e `test_adopt_falha_so_no_active_e_retoma` [linha 825] — é o padrão a copiar) |
| `next_version_id` ignora `v1.tmp-*` e pastas com nome inválido | `test_model_registry.py` |
| Um teste que **prove que `scripts/models/` não foi tocado** pelo treino | já existe: `test_export_raw_events.py:733-735` — **reutilizar, não duplicar** |

**Gate de referência:** `run_all_tests.py` está em **38/38 verdes em ~86 s** com timeout de 300 s/ficheiro [`run_all_tests.py:22`, 4 workers linha 33] — folgado para mais um ficheiro.

### 5. DOC-01: o que exactamente tem de mudar, secção a secção

**Secções a acrescentar/alterar, com linhas:**

**`README.md`** (357 linhas)

| Linha(s) | O que está hoje | O que tem de acontecer |
|---|---|---|
| **152-174** (`## Machine Learning`) | Descreve só `IsolationForest` + o painel. **Linha 172** diz literalmente: *"Isto escreve `models/isolation_forest.pkl` e `models/scaler.pkl`, que **não são versionados**."* — **é exactamente o oposto do que a Fase 3 passa a ser verdade** | Reescrever o bloco "Para treinar o modelo" (165-172) para: o treino cria `models/vN/` com `metadata.json` + SHA-256 e ativa-a; os `.pkl` soltos são o **modelo legado**; `adopt` é o caminho para registar o que já existe |
| **156-163** (tabela ML) | Publica 0,86 / 0,30 / 0,44 e 0,88 / 0,35 / 0,50 como "Resultados do primeiro ciclo com dados reais" | **Ver "Honestidade dos números"** — o número fica, a afirmação muda |
| **262** | *"33 scripts standalone"* | **38** [VERIFIED nesta sessão] |
| **288-300** (tabela de API) | **Não tem `/api/ml/models`** | Acrescentar a linha `GET /api/ml/models` entre `/api/ml-anomalies` (288) e `/api/redblue/metrics` (289) |
| **328** (árvore) | `ml_anomalies.py / feature_extractor.py / train_anomaly_model.py` | Acrescentar `model_registry.py`, `ml_evaluation.py`, `export_raw_events.py` |
| **334** | *"33 testes standalone"* | 38 |
| **344** (*Limitações*) | *"**ML com pouca amostra:** o modelo foi treinado com 35 eventos reais"* | Reformular: o que está registado é a versão e a avaliação **por versão**; a limitação passa a ser "o dataset de referência não é rotulável com o `attack_log.jsonl` actual" |

**`CLAUDE.md`** (309 linhas)

| Linha(s) | O que está hoje | O que tem de acontecer |
|---|---|---|
| **83** | *"33 ficheiros standalone"* | 38 |
| **229-231** (`feature_extractor.py`) | Descreve features "conta de tentativas, intervalo médio, desvio padrão" — **nada disso existe** no ficheiro (as 7 features estão em [`feature_extractor.py:40-48`]) | Corrigir enquanto se toca; é a mesma passagem que vai descrever o registo |
| **241-244** (`train_anomaly_model.py`) | *"Lê histórico JSONL, extrai features via `feature_extractor.py`, treina Isolation Forest, guarda em `./models/anomaly_model.pkl`"* — **três erros**: não lê histórico JSONL (lê um JSON de eventos + um JSONL de ataques, [`:36-40`]); não guarda em `anomaly_model.pkl` (grava em `isolation_forest.pkl` + `scaler.pkl`, [`:95-96`]); e depois da Fase 3 grava em `models/vN/` | Reescrever: o que faz, o que escreve, `--models-dir`/`--dataset-origin`, que **é o único sítio que cria versões** |
| **(novo, depois de 244)** | — | Acrescentar **`model_registry.py`** e **`ml_evaluation.py`** ao mesmo bullets de arquitectura (hoje `model_registry.py` e `ml_evaluation.py` **não aparecem em lado nenhum do CLAUDE.md** [VERIFIED por `Select-String`]) |
| **253-299** (*Coisas não óbvias*) | Não tem nada de R9 | Acrescentar: (a) SHA-256 detecta, não autentica; (b) a cache do modelo é **por processo** — depois de `adopt`/treino é preciso reiniciar o backend; (c) o registo escreve-se **só por linha de comando**, nunca por HTTP; (d) `.pkl` executa código ao carregar |

**`docs/DATA_MODEL.md`** (230 linhas)

| Linha(s) | O que está hoje | O que tem de acontecer |
|---|---|---|
| **1-5** (cabeçalho) | *"Entidades do Roadmap v2 ainda por definir: Vaccine, Replay, **Model (fases R9-R14)**"* — o `Model` está agora **definido** | Actualizar a data e tirar `Model` da lista de "por definir" |
| **(nova secção, depois de 7 ou depois de 169)** | — | **`## Registo de modelo (R9)`**: o layout em disco (`ACTIVE`, `vN/{isolation_forest.pkl, scaler.pkl, metadata.json}`, os `.pkl` soltos = legado), o `metadata.json` schema 1 completo (as 12 chaves públicas + `artifacts` + `evaluation`), as regras de validade, o `ArtifactSource`, e a forma da resposta de `GET /api/ml/models`. Este é o ficheiro certo para o **contrato**, porque os outros três sãonarrativa |
| **210-230** (MTTD/métricas R8) | Fica como está | — |

**`docs/ROADMAP_STATUS.md`** (81 linhas)

| Linha | O que está hoje | O que tem de acontecer |
|---|---|---|
| **3** | *"Estado de execução do R9 em `.planning/`"* | Actualizar para "concluído" |
| **27** (linha do R9) | `🟡` + *"**nenhum código do R9 escrito ainda**, próximo passo `/gsd-plan-phase 1`"* — **desatualizado em três pontos**: o código existe, o GSD está na Fase 3, e a nota da tabela R24 (linha 42) diz *"17 ficheiros standalone"* | `✅` + resumo do que existe: `model_registry.py` (registo versionado + `adopt` + `evaluate`), SHA-256 antes do `joblib.load`, `GET /api/ml/models`, abas Models e Evaluation, `export_raw_events.py`, 38 ficheiros de teste |
| **42** (R24) | *"17 ficheiros standalone existentes"* | 38 |
| **80-81** (dívida conhecida) | Termina no R8 | Acrescentar uma entrada R9: o SHA-256 não autentica; o dataset de referência não é rotulável |

**Desatualizações confirmadas que já estavam na lista da encomenda** (todas verificadas):

1. `README.md:172` — "não são versionados" ❌ (depois da Fase 3 é falso).
2. `docs/ML.md:71-75` — *"gap registado para uma sessão futura"* sobre o formato de exportação ❌ **já resolvido** por `export_raw_events.py` [VERIFIED: o seu docstring `export_raw_events.py:10-12` diz precisamente que fecha esse gap]. ⚠️ **Este ficheiro não está na lista do critério 3**, mas `STATE.md:87` e `02-VERIFICATION.md:134` apontam-no explicitamente. Recomendo incluí-lo — ver D-4.
3. `CLAUDE.md:243` — `anomaly_model.pkl` ❌ não existe em lado nenhum [VERIFIED: `Get-ChildItem scripts/models` → só os dois `.pkl`].
4. `CLAUDE.md:229-231` — features que não existem ❌.
5. `CLAUDE.md:241` — "Lê histórico JSONL" ❌.
6. `README.md:344` / `CLAUDE.md:83` / `README.md:262,334` — contagens de testes erradas ❌ (33 vs 38).
7. **`docs/ML.md:35-38`** — *"não versionados (`.gitignore`)"* ❌, mesma razão que `README.md:172`.
8. **`docs/API.md`** — **não menciona `/api/ml/models` em lado nenhum** [VERIFIED: `Select-String` não devolve nenhuma ocorrência]. Não está na lista do critério 3, mas é a referência da API e a tabela do README remete para lá. Ver D-4.

### 6. Honestidade dos números

**O problema exacto, verificado:** `scripts/ml_training_report.json` [VERIFIED: versionado, `git log` mostra o commit `06b69fa` de 2026-09-12] diz `total_events: 35`, `attacks_in_dataset: 20`, ML `0.8571 / 0.3 / 0.4444`. O `caveat` cita `real_events_2026-09-14.json`. Esse ficheiro **existe** (`scripts/snapshots/real_events_2026-09-14.json`, 1,7 MB, 14/09/2026 — não versionado, `snapshots/` está no `.gitignore:18`). **O que não rotula é o `attack_log.jsonl`**: tem 12 entradas, **todas de 2026-10-06** [VERIFIED: leitura directa], e a janela do dataset é 2026-09-14 15:22–15:34. Rotulado contra o log de hoje dá **0 ataques** ⇒ recall 0 **por definição**, não por falha do modelo — exactamente o que o CLI avisa [`model_registry.py:1226-1228`].

**O que a documentação tem de fazer, sem apagar o histórico:**
1. **Não apagar** `ml_training_report.json` nem a tabela — são evidência datada e reprodutível no sentido de "correu sobre estes dados" (o `comparison` 5/2/3/25 é idêntico ao que o `evaluate` de hoje produz sobre o mesmo ficheiro [VERIFIED: `02-VERIFICATION.md:37-39`]).
2. **Reclassificar o número**: de "resultado" para "resultado histórico, não reproduzível hoje".
3. **Dar o comando que produz um número sustentado**, que já existe: `export_raw_events.py` → `model_registry.py evaluate vN --events ... --attack-log ... --dataset-origin real`, **com ataques lançados na mesma janela**.
4. Manter, visível, o limite D-04 (SHA-256 não autentica).

**Texto PT-PT pronto a usar** — para `README.md`, a substituir as linhas 156-163 actuais:

> ### Resultados medidos, e o que eles provam
>
> O primeiro ciclo com dados reais (14 de setembro de 2026) mediu, sobre **35 eventos processáveis** de 500 alertas capturados no laboratório:
>
> | | Precisão | Recall | F1 |
> |---|---|---|---|
> | ML (Isolation Forest) | 0,86 | 0,30 | 0,44 |
> | Regras (`event_catalog.py`) | 0,88 | 0,35 | 0,50 |
>
> **Isto é um registo histórico, não um resultado reproduzível hoje.** A medição foi feita com o `scripts/attack_log.jsonl` de 14 de setembro, que registava os 5 ataques lançados nessa sessão. O `attack_log.jsonl` que existe no repositório hoje é de **6 de outubro de 2026** e **não cobre** a janela do dataset: avaliá-lo contra estes eventos dá **0 ataques rotulados** e recall 0 **por definição** — não por falha do modelo. O comando de avaliação avisa-o quando isso acontece, em vez de publicar o número a zero.
>
> Para uma avaliação rotulada a sério: lança os ataques com `scripts/attack_scenarios.py`, exporta os alertas **na mesma janela** com `scripts/export_raw_events.py`, e avalia com `python model_registry.py evaluate vN --events ... --attack-log ... --dataset-origin real`. O resultado fica gravado no `metadata.json` **daquela versão** e é o que a aba 📐 Evaluation mostra. Nenhum número aparece no dashboard sem dizer que versão mediu e sobre que dataset.

E para `docs/ML.md`, a substituir o bloco "Primeiro ciclo real (2026-09-14)" (linhas 65-91), acrescentando antes da tabela:

> **Nota de reprodutibilidade (2026-10-10).** Os números abaixo foram medidos em 2026-09-14 com o `attack_log.jsonl` **dessa** sessão. O log de ataques que existe hoje no repositório é de 2026-10-06 e não rotula a janela do dataset (`real_events_2026-09-14.json`, 2026-09-14 15:22–15:34): avaliá-lo contra estes eventos dá 0 ataques e recall 0 por definição. O ficheiro de eventos ainda existe; o que não existe hoje é o log de ataques da mesma janela. Para repetir a medição com rótulo é preciso lançar os ataques e exportar na mesma janela.

E, para `CLAUDE.md` (*Coisas não óbvias*, dívida D-04):

> - **O SHA-256 dos `.pkl` detecta corrupção e troca acidental; não autentica.** Quem consegue escrever em `scripts/models/` reescreve também o `metadata.json`. Para uma versão treinada o hash é uma auto-atestação do próprio processo de treino: garante que o `.pkl` não mudou desde que foi gravado, não que foi gerado por quem diz ter gerado. HMAC/assinatura ficaram fora do âmbito do R9.

E, para `docs/ROADMAP_STATUS.md` (dívida conhecida):

> - ML (R9): o SHA-256 do registo **não autentica** quem escreve em `models/` — quem escreve reescreve o `metadata.json`. O dataset de referência do primeiro ciclo real (2026-09-14) **não é rotulável** com o `attack_log.jsonl` actual (12 entradas, todas de 2026-10-06): avaliá-lo dá 0 ataques e recall 0 por definição. Qualquer avaliação a sério exige ataques lançados e alertas exportados na mesma janela.

### 7. Ambiente e execução

| Item | Estado | Versão / valor |
|---|---|---|
| `scripts\.venv\Scripts\python.exe` | ✅ funciona | **3.12.14** [VERIFIED] |
| `scikit-learn` | ✅ | **1.5.2** [VERIFIED] |
| `joblib` | ✅ | **1.4.2** [VERIFIED] |
| `numpy` / `scipy` | ✅ | **2.5.3** / **1.18.1** [VERIFIED] |
| Node | ✅ | **v24.14.1** [VERIFIED: `node --version`] |
| `node_modules/` / `package.json` | ❌ não existe — não é preciso (`node:vm`, `node:fs`, `node:path` só) [VERIFIED] | — |
| Laboratório Wazuh | **não necessário** — tudo mockado | — |
| `scripts/models/` real | intacto: só `isolation_forest.pkl` (539 673 B) + `scaler.pkl` (767 B), ambos de 14/09/2026, **sem `v1/` nem `ACTIVE`** [VERIFIED] | nunca tocar |
| `TMPDIR` | `C:\Users\fnuno\AppData\Local\Temp` [VERIFIED] — **fora do OneDrive**, que é o que o Pitfall 5 da Fase 1 pediu | — |
| Suite completa | ✅ **38/38 PASS em ~86 s** [VERIFIED nesta sessão] | timeout 300 s/ficheiro |

**Tempo de um `train_anomaly_model.py` com o gerador sintético — ESTIMADO, NÃO MEDIDO.** Não corro o treino (escreve em `scripts/models/`, que é o disco do utilizador). O que medi, e é a parte dominante:

- **Import de `joblib` + `sklearn.ensemble` + `sklearn.preprocessing` + `sklearn.metrics`: 3,35 s** [VERIFIED, `Measure-Command` nesta sessão]. Este é o custo fixo, independente dos dados.
- O que fica: `extract_features` sobre 36 eventos (sub-milissegundo), `StandardScaler.fit_transform` sobre uma matriz 36×7 (sub-milissegundo), `IsolationForest(n_estimators=200).fit` sobre 36 amostras (alguns milissegundos), dois `joblib.dump` (~540 KB + 767 B), e por cima o **SHA-256 de ~540 KB** (sub-milissegundo) mais a cópia.
- **Estimativa: 4 s, com mais de 95 % do tempo a importar o scikit-learn.** Mesmo sobre o dataset real (500 docs → 35 processáveis) a parte variável não muda de ordem de grandeza.

**O que isto significa para os testes:** um teste que corra o treino de facto custa ~4 s por invocação **e paga o import outra vez** se o rodar como subprocesso. `run_all_tests.py` tem 4 workers e 300 s por ficheiro [`:22,:33`] e a suite inteira leva 86 s — folga confortável. **Se quiseres o número medido em vez de estimado, diz-me e corro o treino com `--model-dir` apontado para um temporário** (nada sai do `%TEMP%`), e digo-te quanto demora.

### 8. Riscos da Fase 3

**Risco 1 — escrever em `scripts/models/` é uma operação que toca no disco do utilizador. Como é que os testes a fazem sem tocar?**

**Resposta: hoje nenhum teste escreve lá, e há um guard que o garante.** [VERIFIED]

- `test_model_registry.py:7-11` (docstring): *"Nada toca no scripts/models real: todo o disco vive num `tempfile.TemporaryDirectory()`"*; `run()` [linha 1359] abre **um** `TemporaryDirectory` e passa a raiz a todas as 18 secções.
- `test_ml_models_api.py:200-203`: `TemporaryDirectory` + `main.ML_MODEL_DIR = str(pasta)` num `finally` que restaura [linhas 1010-1017]. Os `.pkl` das fixtures são **bytes arbitrários** (`b"fake-model"`), excepto onde é preciso um pickle real (`real_model_bytes()` [linha 147-157], que treina um `IsolationForest` minúsculo e faz `dump` para `BytesIO` — **nunca para disco**).
- `test_export_raw_events.py:710-735` é a **rede de segurança explícita**: fotografa `scripts/snapshots/` **e** `scripts/models/` antes, e no fim verifica que `sorted(p.name for p in (SCRIPT_DIR / "models").iterdir()) == modelos_antes == ["isolation_forest.pkl", "scaler.pkl"]`. **Qualquer teste novo que escreva em `scripts/models/` faz este teste falhar.** É o guard que a Fase 3 deve reutilizar e não duplicar.
- `test_ml_models_ui.py:201`: dois `TemporaryDirectory` (registo e fixtures), `main.ML_MODEL_DIR` restaurado no `finally` [linha 281].
- ⚠️ **`run_all_tests.py` corre 4 ficheiros em paralelo** [`:33`]. Dois ficheiros de teste que escrevam no mesmo sítio sem `TemporaryDirectory` *partilhado* colidem. A regra a dar aos planos: **o treino nos testes escreve sempre com `--model-dir`/`--models-dir` apontado para o `TemporaryDirectory` do próprio ficheiro**, nunca para o default.

**Risco 2 — o treino correr duas vezes seguidas (v1 → v2).**

Sequência real com o que existe hoje [VERIFIED por leitura do código + a medição do `os.replace`]:

1. `models/` tem os dois `.pkl` soltos, **sem** `v1/`, **sem** `ACTIVE`. `_active_state` [linhas 279-282] → `("legacy", None)`. O backend carrega o legado sem verificação (REG-02).
2. **1.ª execução.** `next_version_id` → `v1` (não há nenhuma). `_materialize_version(root, "v1", …)` → `mkdtemp("v1.tmp-")` → copia → `os.replace(tmp, root/"v1")` (destino **não existe** ⇒ OK, medi). Confirmação `load_metadata` + `_verify_artifacts` → `"ok"`. `_write_active_atomic(root, "v1")` — **sobrescreve** (não havia `ACTIVE`). Estado: `active = "v1"`, `total = 1`.
   - ⚠️ **A entrada "legado" desaparece da lista** [linha 676: `if not (root / "v1").exists() and active in (None, "legacy")`] — correcto por desenho (o `.pkl` solto agora é a mesma coisa que a `v1`), mas **é uma mudança visível que o teste e a doc têm de cobrir**. Os `.pkl` soltos **ficam em disco** (nunca são movidos nem apagados, [`SKELETON.md:95`]).
3. **2.ª execução.** `next_version_id` → `v2` (max+1). `_materialize_version(root, "v2", …)` → `root/"v2"` **não existe** ⇒ `os.replace` funciona. **A `v1` não é tocada em momento algum** — a função só escreve em `v2.tmp-*` e faz `replace` para `v2`. `_verify_artifacts(v1)` continua a dar `"ok"`. **Critério 1 satisfeito.**
4. ⚠️ **O que parte se o `next_version_id` devolver um id que já existe.** Medi nesta sessão: `os.replace` de uma pasta temporária **sobre uma pasta existente e não vazia** levanta **`PermissionError [WinError 5]`** [VERIFIED]. `_materialize_version` apanha `OSError` e converte em `registry_unavailable` [linhas 753-754], e o `finally` apaga a temporária [linhas 755-757] ⇒ **nada fica a meio**. O comportamento é seguro, mas a **mensagem ao utilizador é má** ("Não foi possível escrever em models/…") quando o problema real é um id repetido. `next_version_id` tem de ser à prova disto (max sobre `int(v[1:])`, nunca "count").
5. ⚠️ **`os.replace` de pasta é atómico no mesmo volume** [comentário em `model_registry.py:703-704`]. **Se o temporário do `joblib.dump` for para outro volume**, o `copy2` continua a funcionar (é uma cópia normal), mas **é mais lento e passa a ser um ponto de falha extra**. Dump para `tempfile.mkdtemp()` (sys tmp) e cópia pelo `copy2` é o padrão correcto — e é o que `_materialize_version` já faz.
6. ⚠️ **O backend continua com `v1` em memória** depois do treino. Já é o comportamento erradodo por desenho (D-02) e o dashboard avisa [`ml_models.js:211-213`]. O CLI **tem de** repetir o "reinicia o backend", como o `adopt` faz [`model_registry.py:1154`]. Sem isso, o utilizador treina, reinicia e vê a v2 — mas se **não** reiniciar vê "ativa: v2, loaded: v1" sem explicação no terminal.

**Risco 3 — regressões fora do âmbito do R9.** `ml_anomalies.load_model` [linha 32] é importado por **8 rotas/serviços** [`main.py:763, 833, 1014, 1087, 1124, 1248`] e injetado por **7 ficheiros de teste** (`_model`/`_scaler` em cache). A Fase 3 **não toca** em `ml_anomalies.load_model` — só em `train_anomaly_model.py` e no registo. Se alguém mexer no curto-circuito de cache, parte tudo (é o Pitfall 8 da pesquisa da Fase 2).

**Risco 4 — a costura das listas escritas à mão.** `EVALUATION_PUBLIC_KEYS` (14 chaves) existe em `model_registry.py:141-156` **e** em `ml_evaluation.EVALUATION_KEYS` [`ml_evaluation.py:58-73`], presa por comparação em `test_ml_models_api.py:749-756`. A Fase 3 **não precisa de mexer** — mas se o `meta` treinado ganhar uma chave nova no `dataset`/`parameters`, ela entra por `METADATA_PUBLIC_KEYS` e é projectada **crú** para o browser (o `dataset` não tem sub-projeção, ao contrário do `evaluation`). O `ml_models.js` escapa tudo [`mlmDatasetHtml:331-341`, `mlmParamsHtml:320-329`], e o `.cjs` tem testes de XSS para ambos [VERIFIED], mas **um campo novo no `dataset` ou no `parameters` tem de entrar por `mlmCell`/`escapeHtml`** — é o risco T-01-14, e nenhum teste o apanha automaticamente.

**Risco 5 — `docs/ROADMAP_STATUS.md` a marcar R9 ✅ com a verificação humana por fazer.** `01-VERIFICATION.md:93-104` e `02-VERIFICATION.md:101-111` deixam **duas listas de verificação humana em aberto** (abrir o browser, confirmar badges, reiniciar o backend). O `STATE.md:75` repete. Marcar ✅ **sem** essas verificações é exactamente o que o `PROJECT.md:9` ("nunca apresentar como real um valor inventado") proíbe. Ver D-2.

## Architecture Patterns

### Pattern 1 — Via de escrita nova (`register_trained_version`), não `adopt`

O `adopt` tem quatro travas que são **correctas para adotar** e **erradas para treinar** (Q2). A via nova vive dentro de `model_registry.py` (não é subcomando novo, não é função do treino) e é a **única** que escreve em `models/` além do `adopt`:

```
train_anomaly_model.py
  ├─ joblib.dump(model,  tmpdir/isolation_forest.pkl)     ← temporário do SISTEMA, fora de models/
  ├─ joblib.dump(scaler, tmpdir/scaler.pkl)
  ├─ meta = {"schema_version": 1, "origin": "trained", "adopted": False,
  │         "created_at": now, "trained_at": now, "trained_at_estimated": False,
  │         "model_type": "IsolationForest", "parameters": {...},
  │         "dataset": {"name": Path(events).name, "size": N, "attacks": A, "synthetic": bool},
  │         "library_versions": {...}, "evaluation": None}
  └─ model_registry.register_trained_version(models_dir, sources=tmpdir, meta=meta)
        ├─ root = _root(models_dir)                        # NUNCA o cwd
        ├─ vid  = next_version_id(root)                     # max(int(v[1:])) + 1
        ├─ meta = _materialize_version(root, vid, sources, meta)
        ├─ confirmado = load_metadata(root/vid, vid)       # passo 4 (Q3)
        │  if _verify_artifacts(root/vid, confirmado) != "ok": raise ModelRegistryError(status)
        └─ _write_active_atomic(root, vid)                 # SOBRESCREVE, ao contrário do adopt
```

**Porque não uma função nova no `train_anomaly_model.py`:** duplicaria `shutil.copy2` + SHA-256 + `os.replace`, e o registo passaria a ter **dois** pontos de escrita com garantias diferentes — que é a falha de desenho que `_materialize_version` foi criada para evitar.

### Pattern 2 — `next_version_id(root)`: max + 1, sobre o regex

```python
def next_version_id(models_dir) -> str:
    """O id da próxima versão: max(int(v[1:])) + 1 sobre as pastas que casam
    VERSION_ID_RE. Ignora 'v1.tmp-*' (não casa o regex), ficheiros soltos e
    nomes inválidos. Pasta vazia ou inexistente -> 'v1'."""
```

Regras que a implementação **tem** de respeitar, todas com base em código lido:
- Ignorar o que não casa `VERSION_ID_RE` [`:644`] — senão `v1.tmp-abc` contava como versão e o `int()` rebentava.
- **max, nunca count**: o teste `os.replace` de Q8 provou que a pasta de destino não pode existir. Com `count`, apagar a `v2` faria a próxima colidir com a `v3`. Com `max`, a `v3` é simply ignorada e a `v4` é a seguinte.
- Teto: `VERSION_ID_RE` é `v[0-9]{1,4}` [`:102`] ⇒ máximo `v9999`. Um `v10000` seria `invalid_version_id`. Uma fase que gere mais de 9999 versões não é um cenário real, mas o erro tem de ser accionável, não um `ValueError` cru.
- O `metadata.json` **não** é lido: o id é decided pelo nome da pasta. Uma pasta `v5` com `metadata.json` corrompido conta como `v5` (o que é o certo — o `build_models_report` mostra-a com `metadata_invalid` e ela não pode ser reutilizada).

### Pattern 3 — O `dataset.synthetic` tem de ser **declarado**, nunca adivinhado

O `train_anomaly_model.py:72` adivinha pelo caminho (`Path(events_path).resolve() == DEFAULT_EVENTS_PATH.resolve()`). A Fase 2 já matou essa heurística para o `evaluate` [`ml_evaluation.py:34-37`, `:262-263`], com `--dataset-origin {real,synthetic,unknown}` default `unknown` [`model_registry.py:1297-1302`]. **O treino tem de Adoptar exatamente a mesma convenção** — pela mesma razão: um dataset real chamado `real_events.json` seria rotulado "sintético" e vice-versa, e o `caveat` mentiria. `dataset.synthetic` é um **tri-estado**: `true` / `false` / `null` (não declarado), que é exactamente o que `mlmDatasetHtml` já desenha como "desconhecido" [`ml_models.js:333-334`].

### Pattern 4 — `parameters` e `library_versions` são o que torna a versão rastreável

`parameters` deve ser o que **realmente**affected o resultado: `contamination`, `random_state`, `n_estimators` [`train_anomaly_model.py:43-48`]. `library_versions`: `python`, `scikit-learn`, `joblib`, `numpy` — que fecham a lacuna A2 da pesquisa da Fase 2 (o `.pkl` treinado com 1.5.2 carrega hoje por acaso; com outra versão daria `InconsistentVersionWarning`). O `ml_models.js` **já sabe mostrar os dois** [`mlmParamsHtml:320-329`, `mlmLibraryVersionsText:278-285`] — **zero trabalho de frontend**.

### Anti-Patterns to Avoid

- **Chamar `adopt` depois de treinar.** Daria `already_adopted` [linha 815] e não activaria nada.
- **Reutilizar `v1`** quando a pasta já existe — `PermissionError` (medido).
- **Escrever `ACTIVE` antes da `vN`** — deixa o `ACTIVE` a apontar para uma versão que pode não verificar, e `_active_state` é fail-closed [linhas 283-287].
- **`joblib.dump` directo em `models/isolation_forest.pkl`** (o que o código faz hoje) — sem hash, sem temporário, sem confirmação; e faz o registo nunca saber que houve um treino novo.
- **Adivinhar `synthetic` pelo caminho** — a heurística de `train_anomaly_model.py:72`, morta na Fase 2.
- **Passar um caminho absoluto para `dataset.name`** — `evaluation` guarda só `Path(...).name` pelo motivo T-02-15 [`ml_evaluation.py:364-366`]; o mesmo se aplica ao `dataset`.
- **Meter `evaluation` no `meta` treinado** — a versão nova nasce **sem avaliação** (`evaluation: null`), que é o que o critério 2 da Fase 2 exige para não mostrar números de outro modelo. Avaliar é um acto separado e explícito.
- **Tocar em `ml_models.js` / `ml_evaluation.js`** — a UI já renderiza `parameters`, `dataset`, `library_versions` e `origin: "trained"` [`mlmOriginText:117-123`, que já tem a linha 121 para `"trained"`]. **Zero trabalho de frontend, salvo se um campo novo precisar de entrar por `escapeHtml`.**
- **Acrescentar um código novo a `ERROR_CODES`** — a lista é fechada (D-06), está replicada em `ml_models.js:30-61` e tem teste de contagem [`.cjs:163-175`].
- **Tocar em `ml_anomalies.load_model`** — 8 consumidores, 7 testes com `_model`/`_scaler` injetados.

## Runtime State Inventory

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | `scripts/models/isolation_forest.pkl` (539 673 B) + `scaler.pkl` (767 B), ambos 14/09/2026, **sem `v1/` nem `ACTIVE`** [VERIFIED]; `.gitignore:19` ignora `scripts/models/` | Nenhuma. A 1.ª execução do novo treino cria `v1` a partir do sintético e **passa a ser o que o backend carrega** — o utilizador tem de saber disto |
| Stored data | `scripts/ml_training_report.json` — **versionado** [VERIFIED], 35/20 de 2026-09-14 | Não apagar. Continuar a escrever? Ver D-3 |
| Stored data | `scripts/snapshots/real_events_2026-09-14.json` (1,7 MB, não versionado, `snapshots/` no `.gitignore:18`) e `2026-09-14_16-37.json` (147 KB) | Nenhuma. Continua a ser o dataset real de referência, **não rotulável** com o log actual |
| Stored data | `scripts/attack_log.jsonl` — 12 entradas, todas 2026-10-06 [VERIFIED] | Nenhuma acção de código. É trabalho de laboratório |
| Stored data | `scripts/sample_events_real.json` (17 664 B, sintético, versionado) + `sample_attack_log.jsonl` (433 B, 2 entradas) | Nenhum. É o default do treino e o dataset reprodutível |
| Live service config | `ML_MODEL_DIR` (`.env.example:18`, default `scripts/models`), `ATTACK_LOG_PATH` (`.env.example:22`) | O `--models-dir` do treino tem de seguir `ML_MODEL_DIR` como o resto do registo [`model_registry.py:1130`, `:1165`] |
| OS-registered state | `start-backend.ps1`; a cache do modelo é **por processo** | O CLI de treino tem de imprimir "reinicia o backend", como o `adopt` [`:1154`] |
| Secrets | `scripts/.env` | Nunca ler nem escrever |
| Build artifacts | `scripts/__pycache__/`, `scripts/*.log` | Nada |

## Common Pitfalls

### Pitfall 1 — O `.pkl` novo nunca é verificado depois de escrito
**What goes wrong:** `save_model()` faz `joblib.dump` directo no destino final [`train_anomaly_model.py:93-96`]; um `Ctrl-C` deixa um ficheiro truncado, e o primeiro `joblib.load` explode com um erro que não é código estável. **Why:** o treino não conhece o registo e `resolve_version_artifacts` [`:482`] nunca é chamado. **How to avoid:** Pattern 1 — dump para um temporário fora de `models/`, `_materialize_version` (que compara o SHA-256 da cópia com o do original **antes** de a pasta existir, [`:741-744`]), confirmação `load_metadata` + `_verify_artifacts` (o que o `adopt` faz em [`:907-916`]), só então o `ACTIVE`. **Warning signs:** um `metadata.json` gravado antes de os `.pkl` estarem no sítio; `joblib.dump` a apontar para dentro de `models/`.

### Pitfall 2 — `os.replace` sobre uma pasta que já existe
**What goes wrong:** `next_version_id` devolve um id repetido e o `os.replace` falha. **Why (medido nesta sessão):** `os.replace(tmp, target)` com `target` a ser uma directório **não vazia** levanta `PermissionError [WinError 5]` no Windows. **How to avoid:** `next_version_id` = **max + 1** (nunca `count`); e mesmo que falhe, `_materialize_version` converte em `registry_unavailable` e apaga a temporária no `finally` [`:753-757`] ⇒ **nada fica a meio**. **Warning signs:** um teste que apague a `v2` e espere que a próxima seja `v2`.

### Pitfall 3 — A entrada "legado" desaparece depois da primeira versão
**What goes wrong:** a UI deixa de mostrar o "legado, sem metadados" e alguém acha que o `.pkl` solto foi apagado. **Why:** [`model_registry.py:676`] — `if not (root / "v1").exists() and active in (None, "legacy")`. **How to avoid:** é o comportamento **correcto** por desenho ([`SKELETON.md:95`]: os `.pkl` soltos nunca são movidos nem apagados). Testá-lo explicitamente e dizer na doc que os `.pkl` soltos continuam lá, como cópias de segurança. **Warning signs:** um teste que conte `total` depois do treino sem saber que o legado desapareceu da lista.

### Pitfall 4 — Um teste novo que escreva em `scripts/models/`
**What goes wrong:** um teste passa localmente e, com os 4 workers do `run_all_tests.py` [`:33`], outro teste a ler a pasta real em paralelo vê um estado a meio — ou, pior, o `test_export_raw_events.py:733-735` falha e ninguém sabe porquê. **Why:** `scripts/models/` é o disco do utilizador e os `.pkl` são o modelo em produção. **How to avoid:** `--models-dir` sempre para o `TemporaryDirectory` do próprio ficheiro de teste; nunca confiar no default; o guard de `test_export_raw_events.py` fica verde como prova. **Warning signs:** um `test_*.py` novo sem `TemporaryDirectory` no `run()`.

### Pitfall 5 — `parameters`/`dataset` com caminho absoluto ou HTML
**What goes wrong:** o `dataset` e o `parameters` são projectados **crú** para o browser (ao contrário do `evaluation`, que tem sub-projeção tipada [`:581-615`]); um path absoluto vaza a árvore de pastas da máquina e um `<script>` num nome de ficheiro vai cru para a resposta. **Why:** `_public_metadata` [`:348-361`] projecta as 12 chaves sem sub-projeção. **How to avoid:** `dataset.name` = `Path(events).name` só; todo o valor novo entra por `mlmCell`/`escapeHtml`; teste de XSS no `.cjs` para o campo novo. **Warning signs:** um valor novo no `dataset` sem uma linha no `.cjs` que prove que `<img` não chega ao HTML.

### Pitfall 6 — Treinar e não reiniciar o backend
**What goes wrong:** o utilizador treina, vê "ativa: v2" e continua a receber detecções da `v1`. **Why:** `ml_anomalies._model` é cache de processo [`ml_anomalies.py:23-29`]. **How to avoid:** o CLI imprime o aviso, como o `adopt` [`model_registry.py:1154`]; o dashboard já avisa sozinho [`ml_models.js:211-213`]. **Warning signs:** um CLI de treino que não menciona o reinício.

### Pitfall 7 — Assumir que o Criterion 2 do TST-01 está por fazer
**What goes wrong:** a Fase 3 passar um plano inteiro a "re-cobrir" o que já tem 331 + 211 + 295 checks verdes. **Why:** foi exactamente o que a pesquisa da Fase 2 previu (`.planning/STATE.md:59`) e foi cumprido. **How to avoid:** Q4 tem o inventário exato; o trabalho de testes da Fase 3 é o **REG-04**, não a re-cobertura. **Warning signs:** um plano com uma tarefa "escrever testes de adopt/hash/id inválido".

### Pitfall 8 — Marcar o R9 ✅ com a verificação humana por fazer
**What goes wrong:** `docs/ROADMAP_STATUS.md` diz "feito" com `01-VERIFICATION.md:93-104` e `02-VERIFICATION.md:101-111` ainda por executar (browser, reinício de backend, exportação real). **Why:** o `PROJECT.md:9` é explícito: nunca apresentar como real o que não foi verificado. **How to avoid:** D-2. **Warning signs:** um ✅ sem uma linha a dizer o que continua por verificar.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Escolher o id da próxima versão | contar pastas | `max(int(v[1:]) for v in version_ids) + 1` sobre o regex | `count` rebenta depois de um `rm -rf v2` (Pitfall 2) |
| Gravar a versão | `shutil.copy2` + `os.replace` no treino | `_materialize_version` | Já tem temporário invisível, SHA-256 cópia↔original, `finally` de limpeza e a nota de reutilização [`:729`] |
| Escrever o `ACTIVE` | `write_text` | `_write_active_atomic` | `mkstemp` + `os.replace`; `ACTIVE` truncado é `invalid_version_id` fail-closed |
| Calcular os SHA-256 | `hashlib` no treino | `_materialize_version` (linhas 741-745) | Uma única implementação, testada |
| Confirmar depois de escrever | confiar no `os.replace` | `load_metadata` + `_verify_artifacts` (o `adopt` em [`:907-916`]) | É o passo 4 de Q3 |
| Decidir se um dataset é sintético | comparar caminhos | `--dataset-origin` declarado | A heurística de [`:72`] mente; a Fase 2 já a matou |
| Ver o que o treino gravou | `print(json.dumps(meta))` no CLI | `GET /api/ml/models` (já existe) e o detalhe da aba Models | Zero frontend novo |

## State of the Art

| Old Approach | Current Approach | Impact |
|--------------|------------------|--------|
| `joblib.dump` directo nos `.pkl` soltos, sem registo nem hash | `models/vN/` + `metadata.json` + SHA-256 + `ACTIVE`, escrita por `register_trained_version` | Rastreabilidade (critério 1 do REG-04); o `.pkl` deixa de poder mudar sem dar erro |
| Duas fontes de "que modelo está a ser usado": o `.pkl` solto e (a partir da Fase 1) o `ACTIVE` | Uma só: o registo. Os `.pkl` soltos passam a ser explicitamente o *legado* | `_active_state` [`:266-288`] é a função única que decide |
| `is_synthetic` adivinhado pelo caminho [`train_anomaly_model.py:72`] | `--dataset-origin` declarado, tri-estado | Um dataset real com outro nome deixa de ser rotulado "sintético" |
| Números ML publicados no README como resultado corrente | Número histórico datado + o comando que produz um número sustentado | `PROJECT.md:9` — honestidade sobre o que se mediu e quando |

**Deprecated/outdated (confirmado nesta sessão):** `docs/README.md` (estrutura antiga, já sinalizado na Fase 2); `docs/ML.md:71-75` (gap de exportação já resolvido); `README.md:172` e `docs/ML.md:35` ("não são versionados"); `CLAUDE.md:241-243` (`anomaly_model.pkl`, "histórico JSONL"); `CLAUDE.md:229-231` (features que não existem); contagens de testes (33 vs 38) em `README.md:262,334` e `CLAUDE.md:83`; `docs/ROADMAP_STATUS.md:27` ("nenhum código escrito ainda") e `:42` ("17 ficheiros"); `docs/API.md` (sem `/api/ml/models`).

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `os.replace` de pasta sobre pasta existente e não vazia falha com `PermissionError` neste Windows | Q8/Pitfall 2 | Se passasse a substituir, `_materialize_version` podia destruir uma `vN` — mas o teste `adopt` (nunca substitui) e o `next_version_id` por `max` tornam a situação inalcançável na prática |
| A2 | `TemporaryDirectory` do sistema (`C:\Users\fnuno\AppData\Local\Temp`) está fora do OneDrive e por isso não sofre o bloqueio de ficheiros abertos | Q7 | Se o OneDrive passar a sincronizar o temp, os testes ficam lentos ou intermitentes. Foi o motivo do Pitfall 5 da Fase 1 |
| A3 | O utilizador ainda tem `scripts/snapshots/real_events_2026-09-14.json` (1,7 MB) | Q6 | Se o tiver perdido, o único dataset real de referência desaparece — e aí só o sintético fica. **A exportação real via `export_raw_events.py` é a saída** |
| A4 | Treinar com o default sintético é aceitável como primeira `v1` | Q8 | Se não for, a 1.ª versão tem de ser o `adopt` do modelo de 14/09, e o treino passa a exigir um `--events` real. Ver D-3 |
| A5 | `library_versions` vale a pena (o `.pkl` treinado hoje carrega por acaso com sklearn 1.5.2) | Pattern 4 | Se não, um `.pkl` novo com outra versão do sklearn dá `InconsistentVersionWarning` em produção e ninguém sabe com que versão foi treinado |

## Open Questions

1. **O que fazer ao `ml_training_report.json`?** Hoje é **versionado** [VERIFIED] e o `--report` reescreve-o a cada treino. Manter (e o `git status` fica sujo sempre que se treina)? Deixar de escrever por omissão e exigir `--report` explícito? Ou passar a gravá-lo dentro da pasta da versão? Não resolvi porque é uma escolha de higiene de repo, não de arquitectura.
2. **Onde vive o `meta` treinado?** Montado em `train_anomaly_model.py` (perto dos dados, longe do registo) ou num helper de `model_registry.py` (perto das regras do schema)? Depende de se a Fase 3 quer um gate por AST que impeça o `meta` de crescer sem validação. Ver D-1.
3. **O que fazer quando o treino falha DEPOIS de gravar a `vN` e ANTES do `ACTIVE`?** O `adopt` tem `_resume_adoption` [`:790-837`] que recupera exatamente esse estado. O treino **não precisa** de retoma (basta reexecutar, que cria `vN+1`), mas fica uma `vN` órfã na lista. Aceitável, ou o treino deve reexecutar o `ACTIVE` se a `vN` imediatamente anterior for dele? **Assumi que aceitar é melhor** (uma versão órfã é visível e inofensiva; uma retoma automática pode ativar a versão errada). Se o utilizador preferir outra coisa, é uma linha a mais.
4. **O teste de UI precisa de uma 5.ª fixture?** O `.cjs` já tem 4 relatórios de `/api/ml/models` (`report_v1`, `report_legacy`, `report_empty`, `report_evaluated`) e 3 de `/api/ml-anomalies`. Uma versão `origin: "trained"` **já** está coberta: [`test_ml_models_ui.cjs:274`] tem o check *"mlmOriginHtml: origin 'trained' -> 'treinado'"*. **Assumi que não é preciso fixture nova** — a confirmar pelo planeador.
5. **`docs/API.md` e `docs/ML.md` entram no DOC-01?** O critério 3 nomeia `ROADMAP_STATUS.md`, `DATA_MODEL.md`, `README.md` e `CLAUDE.md`. Mas `API.md` não menciona `/api/ml/models` e `ML.md` diz "não são versionados" e que o gap de exportação "fica para uma sessão futura" — e o `STATE.md:87` aponta explicitamente para `ML.md:71-75`. Ver D-4.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Python venv `scripts/.venv` | treino, testes | ✓ | 3.12.14 | — |
| `scikit-learn` | `IsolationForest`, métricas | ✓ | 1.5.2 | — |
| `joblib` / `numpy` / `scipy` | `.pkl` | ✓ | 1.4.2 / 2.5.3 / 1.18.1 | — |
| Node | `node:vm` nos testes de UI | ✓ | v24.14.1 | revisão manual no browser |
| Laboratório Wazuh | — | não necessário (tudo mockado) | — | — |

**Missing dependencies with no fallback:** none.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | scripts standalone (`check()` + `sys.exit(1)`), sem pytest |
| Config file | none — `run_all_tests.py` descobre `test_*.py` [`run_all_tests.py:29`] |
| Quick run | `cd scripts && .venv\Scripts\python.exe -X utf8 test_model_registry.py` (ou `run_all_tests.py ml`) |
| Full suite | `cd scripts && .venv\Scripts\python.exe run_all_tests.py` — **38/38 verdes em ~86 s** [VERIFIED nesta sessão] |
| Gate | `node --check ml_models.js` + `node --check ml_evaluation.js`; gate AST de `model_registry.py` (stdlib puro) |

### Phase Requirements → Test Map
| Req | Behavior | Test Type | Ficheiro | Helpers a reusar |
|-----|----------|-----------|----------|-------------------|
| REG-04 | `train_anomaly_model.py` grava `vN` seguinte e ativa-a | integração (subprocess) | novo `test_train_registry.py`, ou secção nova em `test_model_registry.py` | `correr_cli` [`:947`], `make_version`, `fotografar`, `restos(root, "v2.tmp-")` [`:616`] |
| REG-04 | 2.º treino ⇒ `v2` ativa e `v1` **byte-idêntica** | integração | o mesmo | `fotografar` [`:598`] (já prova T-01-17 para o `adopt`) |
| REG-04 | `meta` treinado: `origin`/`adopted`/`trained_at_estimated`/`parameters`/`dataset`/`library_versions` | unit | o mesmo | `load_metadata`, `build_models_report`, `versoes_por_id` [`:126`] |
| REG-04/SEC-01 | `.pkl` adulterado na versão treinada ⇒ `hash_mismatch` + **0** `joblib.load` | integração | `test_ml_models_api.py` | `real_model_bytes()` [`:147`], `ContadorJoblib` [`:161`], `flip_byte` [`:118`] |
| REG-04 | `dataset.synthetic` segue `--dataset-origin`, **nunca** o caminho | integração | novo/secção nova | o mesmo |
| REG-04 | Falha na confirmação (passo 4) ⇒ **nenhum `ACTIVE` escrito** | integração | o mesmo | `replace_bloqueado` [`:558`], padrão de `test_adopt_falha_so_no_active_e_retoma` [`:825`] |
| REG-04 | `next_version_id`: ignora `vN.tmp-*`, inválidos; **max e não count** | unit | `test_model_registry.py` | `make_version`, `write_active` |
| REG-04 | Nada toca em `scripts/models/` | regressão | `test_export_raw_events.py:733-735` (**já existe**) | — |
| TST-01 | Os 7 itens do critério 2 | regressão | `test_model_registry.py`, `test_ml_models_api.py`, `test_ml_evaluation.py`, `test_ml_models_ui.cjs` (**já cobertos** — 331/211/90/295 checks) | — |
| DOC-01 | `run_all_tests.py` verde | suite | — | 38/38 hoje |
| UI-01/UI-03 | `origin: "trained"` desenha "treinado" | UI (node:vm) | `test_ml_models_ui.cjs:274` (**já coberto**) | — |

### Sampling Rate
- **Por commit de plano:** `.venv\Scripts\python.exe run_all_tests.py ml` (filtra por nome; apanha `test_model_registry`, `test_ml_models*`, `test_ml_evaluation`, `test_ml_anomalies`).
- **Por wave:** `run_all_tests.py` completo (~86 s).
- **Phase gate:** suite verde + `node --check` nos dois `.js` + gate AST de `model_registry.py` + **verificação humana** (D-2).

### Wave 0 Gaps (a fechar com o código, não depois — `STATE.md:58`)
- [ ] `test_model_registry.py` — `next_version_id` e `register_trained_version` (se ficarem no registo).
- [ ] `test_ml_models_api.py` — o caminho completo treinar → `vN` ativa → `GET /api/ml/models` → `/api/ml-anomalies` a carregar a nova (com `ContadorJoblib` para provar que **zero** bytes não verificados chegam ao `joblib.load`).
- [ ] `test_ml_models_ui.cjs` — provavelmente **nada** (o `origin: "trained"` já está coberto, linha 274); confirmar antes de mexer.
- [ ] `test_serve_frontend.py` — **nada** (nenhum ficheiro novo na raiz, se o treino não criar um).

## Security Domain

### Applicable ASVS Categories (nível 1)

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V5 Input Validation | sim | `--models-dir` + id gerado internamente por `next_version_id`; `--events`/`--attack-log` são caminhos do utilizador mas **nunca** são usados para construir um caminho dentro de `models/`; nomes de `.pkl` são sempre a constante `ARTIFACT_FILES` |
| V6 Cryptography | sim | SHA-256 gravado e conferido **antes** de qualquer `joblib.load`, sem excepção; `hmac.compare_digest` |
| V8 Data Protection / Error handling | sim | erros só com códigos de `ERROR_CODES`; `dataset.name` só o nome do ficheiro (nunca caminho); nada de HTML no `dataset`/`parameters` |
| V12 Files | sim | escrita atómica (temporário + `os.replace`); o `ACTIVE` escreve-se **depois** da versão e **só** depois de a confirmar; nenhum teste toca em `scripts/models/` |
| V4 Access Control | sim | escrita só por linha de comando, nunca por HTTP (regra do marco, mantida) |

### Known Threat Patterns
| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| `.pkl` truncado por um `Ctrl-C` no `dump` | Tampering / DoS | dump para um temporário **fora** de `models/`; a versão só existe depois do `os.replace` |
| `ACTIVE` a apontar para uma `vN` meio gravada | Tampering | ordem versão → confirmação → `ACTIVE` (a ordem do `adopt`, `model_registry.py:851-860`) |
| `metadata.json` com um campo do `dataset`/utilizador a vazar caminho ou HTML | Information disclosure / Tampering | `Path(...).name` só; `escapeHtml`/`mlmCell` no JS; teste de XSS no `.cjs` |
| `next_version_id` a devolver um id existente | DoS (nãoAvailability) | `max + 1`; e mesmo que falhe, `registry_unavailable` + `finally` limpa a temporária |
| Um teste escrever no `models/` do utilizador | Tampering | `TemporaryDirectory` por ficheiro + o guard de `test_export_raw_events.py:733-735` |
| Auto-atestação: quem treina escreve também o hash | Spoofing (**D-04, aceite**) | Documentado em `CLAUDE.md`, `README.md` e `ROADMAP_STATUS.md`: o SHA-256 detecta, **não autentica** |

## Sources

### Primary (HIGH — leitura directa/execução nesta sessão)
- `scripts/train_anomaly_model.py` (íntegro, 124 linhas), `scripts/model_registry.py` (íntegro, 1324 linhas), `scripts/ml_evaluation.py` (íntegro, 522 linhas), `scripts/feature_extractor.py` (íntegro, 201 linhas), `scripts/ml_anomalies.py` (íntegro, 161 linhas), `scripts/export_raw_events.py` (íntegro, 408 linhas), `scripts/_generate_sample_ml_data.py` (íntegro, 114 linhas), `scripts/run_all_tests.py`, `scripts/serve_frontend.py:30-70`, `scripts/main.py:113-127` + `:755-860`, `scripts/.env.example:18-22`.
- Testes lidos e **executados**: `test_model_registry.py` (331 checks), `test_ml_models_api.py` (211), `test_ml_evaluation.py` (90), `test_export_raw_events.py` (142), `test_ml_models_ui.py` (23 wrapper + 295 `.cjs`), `test_serve_frontend.py` (grep). **Suite completa: 38/38 PASS em ~86 s.**
- `ml_models.js` (518 linhas, lidas as funções de detalhe e de aviso), `ml_evaluation.js` (grep das funções `mle*`), `index.html:563-655`.
- `README.md` (357 linhas), `CLAUDE.md` (309 linhas), `docs/DATA_MODEL.md` (230 linhas), `docs/ML.md` (237 linhas), `docs/ROADMAP_STATUS.md` (81 linhas), `docs/API.md` (grep), `.gitignore`.
- `.planning/PROJECT.md`, `ROADMAP.md`, `STATE.md`, `REQUIREMENTS.md`, `SKELETON.md` (Fase 1), `01-VERIFICATION.md`, `02-VERIFICATION.md`, `02-RESEARCH.md` (estrutura e pitfalls).
- **Medições desta sessão:** versões do venv (Python 3.12.14, sklearn 1.5.2, joblib 1.4.2, numpy 2.5.3, scipy 1.18.1); `node --version` (v24.14.1); **import do sklearn = 3,35 s** (`Measure-Command`); **`os.replace` de pasta sobre pasta existente e não vazia ⇒ `PermissionError [WinError 5]`**; `os.replace` de ficheiro sobre ficheiro **substitui**; `TMPDIR = C:\Users\fnuno\AppData\Local\Temp`; conteúdo de `scripts/models/`, `attack_log.jsonl` (12 entradas, 2026-10-06), `snapshots/`; `git ls-files` sobre `ml_training_report.json` e `sample_events_real.json`.
- **NÃO executado, por instrução:** o treino de facto (`train_anomaly_model.py`) — nada foi escrito em `scripts/models/`.

### Secondary / Tertiary
- Nenhuma fonte web usada. Afirmações sobre OneDrive/`os.replace` bloqueado vêm de `01-RESEARCH.md` e foram confirmadas quanto a `PermissionError`.

## Riscos e tensões com o contrato já implementado

1. **O `adopt` e o treino são operações incompatíveis na mesma função** — D-01 ("só escreve `ACTIVE` se não existir") é o oposto do REG-04. Via nova obrigatória.
2. **`next_version_id` não existe** e o único código parecido está enterrado dentro de `build_models_report` [`:647`]. É a peça mais pequena e a que mais chamadas tem.
3. **`dataset`/`parameters` não têm sub-projeção** (ao contrário de `evaluation`) — qualquer campo novo entra cru no browser. Risco T-01-14.
4. **A primeira execução do novo treino muda o que o backend carrega** (de legado para `v1` sintética) e faz a entrada "legado" desaparecer da lista. Mudança de comportamento visível que tem de ser testada e documentada.
5. **`ml_training_report.json` é versionado** e o `--report` reescreve-o — cada treino suja o `git status`.
6. **A verificação humana das Fases 1 e 2 continua por fazer** (browser, reinício de backend, exportação real). Marcar o R9 como ✅ sem ela é publishing sem evidência.
7. **`docs/ML.md` e `docs/API.md` estão desatualizados e não estão no critério 3** — mas o `STATE.md:87` aponta para um deles.
8. **Nenhum trabalho de frontend parece necessário** — `ml_models.js` já sabe mostrar `parameters`, `dataset`, `library_versions` e `origin: "trained"` [`mlmOriginText:121`], e o `.cjs` já tem o check. **Mas isso só se confirmar se nenhum campo novo for acrescentado ao `dataset`.**

---

## Decisões que precisam do utilizador

### D-1 — Onde vive o `meta` da versão treinada?
**Contexto:** REG-04 exige metadados (data, parâmetros, dataset, sintético, SHA-256). O registo tem um validador (`load_metadata`, `model_registry.py:291-345`) que valida `schema_version`, `version`, `artifacts` e `evaluation` — mas **não** valida `origin`, `adopted`, `parameters`, `dataset` nem `library_versions` (esses entram na projection sem tipo, linha 348-361).
| Opção | Prós | Contras |
|---|---|---|
| **A. `train_anomaly_model.py` monta o `meta`** | Perto dos dados que ele tem; `model_registry.py` fica intocado e o gate AST continua a passar sem esforço | O `schema` das 12 chaves fica em dois sítios sem teste que os ate (o que existe hoje com as 14 chaves de `evaluation` é uma lição — `STATE.md:86`) |
| **B. Helper `build_trained_metadata(...)` em `model_registry.py`** (ou em `ml_evaluation.py`) | O registo é o dono do schema; um teste pode iteratear sobre os campos; a validação fica num sítio | `ml_evaluation` já é o módulo do sklearn fora do registo; `model_registry` (stdlib) teria de receber primitivas — o que é limpo, mas é mais superfície |
| **C. Montar no treino + um gate no `test_model_registry.py`** que confirma que o `meta` treinado tem exactamente as chaves do schema | O treino fica simples e o schema é preso por teste, sem mover código | É uma costura escrita à mão — a mesma que a Fase 2 já tem para o `evaluation` |
**Recomendação: B**, com `build_trained_metadata` em `model_registry.py` a receber apenas primitivas (dict de parâmetros, nome do ficheiro, contagens, flag sintético, dicionário de versões) — o registo continua stdlib e dono do schema, e o teste pode verificar que o que o treino produz passa o mesmo `load_metadata` que o `adopt` produz. Se preferires menos código, **A + C** é aceitável e fica igualmente honesto, desde que o teste exista.

### D-2 — O `docs/ROADMAP_STATUS.md` marca o R9 ✅ com a verificação humana ainda por fazer?
**Contexto:** o critério 3 pede ✅. Mas `01-VERIFICATION.md:93-104` e `02-VERIFICATION.md:101-111` deixam por executar: abrir o browser e confirmar badges/seleção por teclado, reiniciar o backend depois de um `adopt`, e a exportação real do Indexer. O `STATE.md:75` repete a lista.
| Opção | Prós | Contras |
|---|---|---|
| **A. ✅ com uma linha "verificação humana por fazer"** | Fecha o marco sem mentir; o utilizador sabe exactamente o que falta | Um ✅ com ressalva é um ✅ que precisa de ser lido |
| **B. ✅ apenas depois de o utilizador correr a verificação manual** (eu escrevo a documentação com 🟡 e ele troca) | Coerente com `PROJECT.md:9` ("nunca apresentar como real o que não foi verificado") | O marco fica aberto mais tempo; depende de ti ter as VMs ligadas |
| **C. ✅ e um bloco "Verificado / Por verificar" explícito no próprio `ROADMAP_STATUS.md`** | O estado fica num sítio só, visível, sem ser ambíguo | `ROADMAP_STATUS.md` é um quadro de fases, não um relatório de verificação |
**Recomendação: C.** ✅ na tabela (é o que o critério pede e o código está verificado por 38/38 testes automatizados), com uma linhaimmediately abaixo a dizer exactamente o que continua por verificar em humano e porquê. Se preferires não publicar nada como concluído antes de veres o browser, **B** é a escolha honesta — mas então o `STATE.md` tem de reflectir isso.

### D-3 — O que faz o `--report` / o `ml_training_report.json`?
**Contexto:** `ml_training_report.json` é **versionado no git** [VERIFIED] e `train_anomaly_model.py:115-116` reescreve-o a cada execução. Depois da Fase 3 o `evaluate` é a via canónica de avaliação (grava no `metadata.json` da versão), e o `PROJECT.md:32` põe "recolher métricas ML novas" fora de âmbito. Cada treino a seguir suja o `git status`.
| Opção | Prós | Contras |
|---|---|---|
| **A. Manter como está** | Zero mudanças; o relatório continua a ser o registo "do treino em si" | `git status` sujo a cada treino; e o número é justamente o que a Q6 diz que não se pode publicar |
| **B. `--report` passa a ser opt-in** (`--report` sem valor = não escreve) | O default fica limpo; quem quiser o artefacto pede-o | Quebra o `--report` implícito actual (que é o default) — é uma mudança de comportamento |
| **C. Deixar de escrever; o relatório de treino passa a ser o `metadata.json` da versão** (o `evaluation` fica para o `evaluate` a sério) | Uma única fonte; nada duplica o que o registo já tem | `train_anomaly_model.py` deixa de imprimir os números no stdout, o que é uma perda de ergonomia |
**Recomendação: B com um eco no stdout.** `--report` só escreve se for explicitamente passado; por omissão o treino imprime o mesmo JSON no stdout (que já faz hoje, linha 118) e grava-o na `vN/metadata.json`. Isto mantém a convenção "nada sai para o git sem o pedir", que é a mesma razão pela qual `scripts/models/` e `scripts/snapshots/` estão no `.gitignore`. **E, qualquer que seja a opção, o `ml_training_report.json` versionado não se apaga** — passa a ser evidência histórica datada, com a nota de reprodutibilidade da Q6.

### D-4 — O DOC-01 alarga-se a `docs/ML.md` e `docs/API.md`?
**Contexto:** o critério 3 nomeia 4 ficheiros. Mas `docs/ML.md:35` diz "não versionados" (passa a ser falso), `docs/ML.md:71-75` diz que o gap de exportação "fica para uma sessão futura" (já resolvido pelo `export_raw_events.py` — e o `STATE.md:87` aponta para lá), e `docs/API.md` **não menciona `/api/ml/models` em lado nenhum** [VERIFIED], sendo que a tabela do README remende para lá.
| Opção | Prós | Contras |
|---|---|---|
| **A. Só os 4 ficheiros do critério** | Cumpre o ROADMAP à letra; plano mais rápido | Deixa `docs/ML.md` a dizer o oposto do que o README passa a dizer, e `API.md` sem a rota nova |
| **B. Os 4 + `docs/ML.md`** (que o `STATE.md:87` já pede) | Fecha a incoerência mais visível e a dívida já registada | Mais um ficheiro a editar |
| **C. Os 4 + `ML.md` + `API.md`** | Documentação coerente em todo o lado | Mais trabalho; `API.md` tem 30 KB e a rota nova precisa de uma secção com o contrato |
**Recomendação: B.** `docs/ML.md` é o documento de metodologia do ML e diz hoje duas coisas que a Fase 3 torna falsas — publicá-lo assim seria pior do que não o publicar. `docs/API.md` fica como **follow-up explícito** (a rota `GET /api/ml/models` precisa de uma secção, mas é trabalho de referência, não de marco). Se quiseres os dois, **C** — é a opção mais completa e o custo é uma secção.

---

**Research date:** 2026-10-10
**Valid until:** 2026-11-10 (repo estável; revalidar se `model_registry.py`, `train_anomaly_model.py` ou `ml_evaluation.py` mudarem antes da execução)