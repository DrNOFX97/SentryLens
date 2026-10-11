---
phase: 02-avaliacao-ligada-a-versao
decided: 2026-10-10
source: discuss com o utilizador (decisões D-1..D-5) + pesquisa 02-RESEARCH.md
---

# Contexto da Fase 2 — Avaliação ligada à versão

Decisões travadas para a fase. Vêm da pesquisa (`02-RESEARCH.md`) e da conversa com o
utilizador. As decisões D-01..D-08 da Fase 1 (`01-CONTEXT.md`) continuam válidas onde não
contradicam isto.

## D-01 — Onde vive a lógica de avaliação

`model_registry.py` continua **stdlib puro** (contrato da Fase 1, `SKELETON.md`). A lógica de
métricas vive num módulo de domínio novo, `scripts/ml_evaluation.py`, e o CLI importa-o
**dentro** de `_cmd_evaluate` (import tardio), nunca a nível de módulo. O registo não ganha
dependência de joblib nem de scikit-learn, e a verificação AST da Fase 1 continua a passar.

Porquê: `model_registry.py` é lido por testes que não podem ter sklearn carregado, e o
`evaluate` é a única operação do registo que precisa dele.

## D-02 — O `evaluate` avalia **essa** versão, não a ativa

`python model_registry.py evaluate v1 --events <ficheiro>` carrega os artefactos de `v1` por
`id`, não o que estiver em `ACTIVE`. Não existe hoje um carregador de versão arbitrária
(`resolve_active_artifacts` só vê a ativa) — a fase acrescenta `resolve_version_artifacts()`
em `model_registry.py`, que a Fase 3 vai reutilizar igual (avaliar a vN nova antes de a ativar).

## D-03 — Um evento, uma linha: ground truth e decisões emparelhadas por índice

O rótulo vem de `feature_extractor.label_with_attack_log(...)` (o mecanismo que já existe e é
puro) e a decisão do modelo vem de `ml_anomalies.build_ml_anomalies_report(...)` (o **único**
caminho de código que chega ao `model.predict`, o mesmo que o dashboard usa). Rótulo e decisão
são emparelhados por **índice posicional**, e o evaluate recusa-se a gravar se
`len(rows) != len(results)` — dois conjuntos de tamanhos diferentes é exactamente o modo
silencioso de um número falso.

Isto responde ao objectivo central do projecto: a avaliação nunca diz uma coisa diferente
da que o dashboard mostra.

## D-04 — "Regra" é `classify_alert(event_id)["severity"] == "high"`

Mantém-se o limiar literal que `feature_extractor.py:141` já usa e com que o
`ml_training_report.json` foi calculado. As métricas novas são comparáveis com as do README
(mesmos `sklearn.metrics.*(zero_division=0)`, mesmo `round(4)`, mesmo `predict() == -1`).
O `caveat` em texto do relatório antigo **não** é reusável — cada avaliação gera o seu.

## D-05 — Aviso de amostra pequena: dois limiares

O aviso está sempre presente quando **eventos < 50** *ou* **ataques < 10**. Com o dataset
histórico (35 eventos / 20 ataques) o aviso aparece, que é o que o README já promete.

Porquê dois eixos: a métrica degrada por amostra pequena e por cobertura de ataques. Um só
limiar deixaria passar 40 eventos com 3 ataques. `METRICS_MIN_SAMPLE=5` do `soc_metrics.py`
é de outro domínio e não é reusado.

Os dois limiares vão para constantes nomeadas (não números mágicos no meio da função), para
que a Fase 3 e a documentação tenham um sítio único onde os mudar.

## D-06 — Dataset real exportado do Wazuh, não sintético

O utilizador decidiu explicitamente: os números da primeira avaliação real saem de **dados
reais do laboratório**, não do gerador sintético. O `real_events_2026-09-14.json` do
`ml_training_report.json` nunca esteve no git e não é reproduzível por nenhum script vivo.

Consequência prática, e é a principal tensão desta fase: **no momento de planear, o Wazuh
Indexer está desligado** (portas 9200 e 55000 fechadas). O plano tem de incluir o exportador
dos documentos brutos do Indexer como parte do trabalho, e a execução da avaliação real fica
para o momento em que a VM estiver ligada. Não há atalho: correr a avaliação sobre o dataset
sintético e publicar o número no README seria exactamente o "valor inventado" que o
PROJECT.md proíbe.

## D-07 — `evaluation` entra no `metadata.json` da versão, e a API projecta-o

`load_metadata` já valida `evaluation` como `dict | None` (Fase 1), mas `evaluation` **não**
está em `METADATA_PUBLIC_KEYS` e a API expõe-o cru. Um `evaluation` gravado com
`METADATA_PUBLIC_KEYS` widened tornaria o `metadata.json` maior e a lista mais cara.

Escolha: `evaluation` **não** entra em `METADATA_PUBLIC_KEYS` (continua a ser um campo de
nível superior do metadata, como já está), e o `evaluate` grava o resultado em
`metadata["evaluation"]` reescrevendo o ficheiro de forma atómica, deixando os restantes
campos intactos. A Fase 2 valida o que grava contra o mesmo validador do CLI de adopting
(schema_version, ids de artefacto, etc.), para não escrever um metadata.json que o próprio
registo de seguida rejeite.

## D-08 — Sub-projeção de `evaluation` na API (fecha o risco T-01-14)

A Fase 1 registou como risco residual que a API expõe `evaluation` cru, sem teto por campo.
Com a Fase 2 esse campo passa a ter conteúdo real vindo de ficheiros do utilizador.

Escolha: `build_models_report` sub-projecta `evaluation` para as chaves conhecidas
(métricas ML, métricas de regras, contagens de comparação, metadados do dataset, avisos) e
**nunca** devolve texto arbitrário do `metadata.json`. `null` continua a ser `null`
(EVAL-03); uma versão com avaliação inválida não passa a ser "sem avaliação" silenciosamente
— tem de dar `metadata_invalid`, que a Fase 1 já tem.

## D-09 — A aba Evaluation vive em `ml_evaluation.js`

Ficheiro novo, como o D-05 original da Fase 1 previa; a implementação da Fase 1 pôs as duas
abas em `ml_models.js` com um `fetch` partilhado. O utilizador decidiu separar.

Consequência: `ml_evaluation.js` passa a precisar do que `ml_models.js` faz com os globais de
`app.js` (`API_BASE`, `API_KEY`, `escapeHtml`, `renderPanelError`) e de `activateTab`/hash —
sem redeclarar nada. Os helpers puros ficam testáveis em `node:vm` como os de
`ml_models.js`, com prefixo próprio para não colidir no escopo global partilhado
(os scripts clássicos partilham um só escopo — Pitfall 8 da pesquisa da Fase 1).

## D-10 — Concordância ao vivo: só o que `/api/ml-anomalies` já dá

Reusar `total`/`agree_count`/`diverge_count` que a rota já devolve, mais `alerts_truncated`
para o dashboard poder avisar. **Sem** criar métricas ou detetores novos. "Sem dados" é uma
decisão de frontend: a função devolve `total = 0` (nunca `None`), logo é `total === 0` que
desenha "Sem dados" em vez de um valor. Não se introduz a convenção `available/reason` do R8
aqui — é de outro domínio.

## D-11 — O teste Node que fixa o D-05 inverte-se

`test_ml_models_ui.cjs:646-647` fixa hoje que "nenhum número é mostrado (D-05)". A Fase 2
precisa exactamente do contrário. O teste **inverte-se**; não se contorna nem se salta.
Qualquer texto de métrica que apareça no DOM tem de continuar a passar por `escapeHtml`.

## Ambiguidade do D-05 registada

`01-CONTEXT.md` (Fase 1) previa `ml_evaluation.js`; a implementação pôs as duas abas em
`ml_models.js`. A decisão D-09 acima resolve a favor do ficheiro separado. O plano deve
 notar esta mudança em relação ao que a Fase 1 decidiu, para não parecer uma inversão
silenciosa.

## Fora de âmbito (Fase 2)

- Treinar a partir do dashboard, comparar versões automaticamente (R10).
- Métricas novas além de precisão/recall/F1 e das contagens de comparação.
- HMAC sobre o `metadata.json` (dívida D-04 da Fase 1, aceite).
- Mover ou apagar os `.pkl` do utilizador.
- Tornar o pipeline de exportação reproduzível de ponta a ponta para lá do exportador bruto
  (é a tensão D-06; resolver o "de onde veio o dataset" é follow-up da Fase 3).