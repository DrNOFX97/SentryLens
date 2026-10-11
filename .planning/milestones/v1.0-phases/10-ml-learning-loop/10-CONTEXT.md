---
phase: 10-ml-learning-loop
decided: 2026-10-11
source: discuss com o utilizador (D-01..D-04) + pesquisa R10 (segurança/concorrência, dados/frontend)
---

# Contexto do R10 — ML Learning Loop

Objectivo de `PROJECT.md:30`: **treinar modelos a partir do dashboard e comparar versões
automaticamente**. O R9 deu o registo e a avaliação; o R10 fecha o ciclo.

**Inverte deliberadamente uma decisão de desenho do R9:** `main.py:793-795` diz que
"activar, adotar ou treinar é operação de CLI, nunca por HTTP". O utilizador autorizou a
inversão **com as protecções de D-01**. `docs/SECURITY.md` tem de ser **reescrito** sobre
este ponto, não anotado.

## D-01 — Treinar por HTTP: sim, com quatro protecções obrigatórias

`POST /api/ml/train` existe. O que fecha o buraco, e é o mesmo que fecha no desenho da
pesquisa:

1. **Nenhum caminho no corpo do pedido.** Nem `--events`, nem `--attack-log`, nem
   `--models-dir`. O dataset vem de um conjunto **fechado no servidor**; o registo vem de
   `ML_MODEL_DIR`/`DEFAULT_MODELS_DIR`; o temporário de `joblib.dump` é `mkdtemp`.
   Isto não é Prudência: `register_trained_version` aceita `sources` de qualquer caminho
   (`model_registry.py:964-968`, `:738-740`) e o `evaluate` desserializa-os
   (`ml_anomalies.py:105-107`) — aceitar `.pkl` escolhidos pelo cliente é `pickle.load` de
   bytes do atacante com a API key, ou seja RCE.
2. **Single-flight com `threading.Lock`.** Um treino a correr de cada vez; o segundo devolve
   **409**. O limiter do anyio tem 40 tokens (`run_in_threadpool` → `anyio`), e
   `IsolationForest(n_estimators=200)` sem `n_jobs` usa **todos os cores** por treino: 40
   treinos simultâneos são thrash garantido, mais 80 `.pkl` em `%TEMP%`.
3. **Tetos nos parâmetros.** `contamination` 0.01–0.5, `random_state` 0–2³²−1,
   `n_estimators` 10–1000. Sem tecto, `n_estimators=10**9` é um DoS de uma linha.
4. **`dataset` e `dataset_origin` como `Literal`, nunca caminho.** É o padrão que o projecto
   já fixou: `/api/attacks*` não aceita path nenhum; `/api/network/evidence` valida a data
   por regex antes de tocar no filesystem.

`dependencies=_REQUIRE_API_KEY` em **cada** rota nova, nunca a nível de app — a armadilha
que rebentou `/ws/alerts` está em `main.py:174-190`. CORS continua loopback, nunca `*`.

## D-02 — Dataset: export do Indexer, com a proveniência registada

As três alternativas foram avaliadas e **duas estão medidas como mortas**:

- **Histórico JSONL** — `history_store` grava uma projecção de 7 escalares
  (`history_store.py:76-84`); `extract_features` sobre esse esquema devolve `[]`. Confirmado
  em 10 ficheiros de histórico reais.
- **Buffer em memória** — preenchido newest-first com tecto de 1000 (`main.py:774`); não há
  forma de distinguir "os 1000 mais recentes de 300" de "os 1000 todos".
- **Export do Indexer** — o único caminho que preserva o documento bruto.

Logo: `dataset` no `metadata.json` passa a guardar **documentos**, **processáveis**,
**truncated**, **`window_first`** e **`window_last`**, para que "35 eventos" seja
distinguível de "os 35 que couberam de 500". Hoje `dataset.size` são linhas processáveis e
nada mais — o `metadata.json` de um treino sobre uma janela truncada é indistinguível do
mesmo treino sobre a janela completa.

## D-03 — O skew não se corrige; mede-se e declara-se

`is_new_source_ip` e `failed_attempts_last_hour` acumulam **dentro do lote**
(`feature_extractor.py:124-131`). Medido: o mesmo evento muda de feature em 9,6% dos casos
conforme o lote, e **8,7% dos eventos mudam de veredicto anómalo/normal** só por isso.

**Não** se toca no `feature_extractor` — é uma mudança de contrato partilhado com a
inferência e invalida todos os `.pkl`. Em vez disso, o `dataset` regista
`feature_stats` (média e desvio por feature no lote de treino), e a aba Evaluation mostra
que estes números são do **lote**, não do comportamento. É a Honestidade como
funcionalidade: o learning loop passa a saber o que não sabe.

## D-04 — Hash do catálogo de features, gravado com a versão

`event_id_encoded` é o índice posicional no catálogo ordenado
(`feature_extractor.py:50-52`). Medido: adicionar um Event ID desloca **31 de 31** índices,
o bucket desconhecido muda, e **nenhum `.pkl` é invalidado** — o SHA-256 continua a bater e
o `metadata.json` continua válido. Falha em silêncio.

Logo: `metadata.json` passa a guardar um hash de `CRITICAL_EVENTS`, verificado no
`build_models_report`. Transforma "não sei" em "sei que é incompatível". **É uma mudança de
schema** (`schema_version` continua 1) e tem de ser uma decisão explícita, não de passagem —
por isso está aqui e não no meio do código.

## D-05 — `n_estimators`, `random_state` e `contamination` registados, com tecto

Já são registados (`build_trained_metadata`); o que falta é o **tecto** na fronteira HTTP
(D-01.3) e nenhum código de cliente poder escolher valor fora dele.

## D-06 — `model_version` no `/api/ml-anomalies`

Hoje o relatório **não diz que versão mediu** (`main.py:775-785`). Durante e depois de um
`reset_cache`, um relatório pode ser de uma versão que já não é a activa. Aditivo, uma
linha — o mesmo argumento que o `alerts_truncated` usou na Fase 2.

## D-07 — Sem ficheiro JS novo; sem polling; sem jobs assíncronos

- **UI**: `ml_models.js` ganha o botão e o estado "a treinar…"; `ml_evaluation.js` ganha a
  comparação. `serve_frontend.py` **não muda** — nenhum ficheiro novo na raiz, logo nada
  entra na whitelist.
- **Sem polling nem `202`/`job_id`.** Um treino são ~3 s medidos; é um `await` normal. Um
  `GET` de estado seria uma segunda superfície de API com autenticação e erros próprios para
  ganho zero.
- **Comparação vN vs vN−1 derivada no browser** a partir do que `GET /api/ml/models` já traz
  (cada versão já vem com a sua `evaluation`). O backend não tem nada a acrescentar que o
  browser não calcule das mesmas duas avaliações — **sem endpoint novo**.

## D-08 — A ressalva de segurança é reescrita, não anotada

Com treino por HTTP, quem tem a API key passa a ter escrita em `models/`, e o SHA-256 deixa
de ser auto-atestação de disco para ser auto-atestação do processo que atendeu o pedido
(`docs/SECURITY.md:113-117`). A redacção actual fica falsa. Reescrever: o hash **deixa de
ser uma defesa e passa a ser um detector de corrupção**, porque o `.pkl` que entra passa a
ser sempre produto de `train_model()` sobre dados escolhidos pelo servidor.

## Fora de âmbito

- **Upload de `.pkl` ou de dataset** — é a RCE de D-01. Fecha com "nenhum caminho no body".
- **HMAC / assinatura** — continua a dívida D-04 do R9. O que muda é a redacção do limite.
- **`POST adopt`** — operação única; a UI já diz como se faz.
- **Apagar versões** — reverter, não apagar.
- **Rate limiting fino por IP/token** — `docs/SECURITY.md:128` já assume uma só chave global
  sem papéis; o single-flight resolve o caso prático.
- **`activated_at` no `metadata.json`** — auditoria, não fecha nenhum buraco.
- **Corrigir o skew (D-03)** e **migrar o `history_store`** para documento bruto.