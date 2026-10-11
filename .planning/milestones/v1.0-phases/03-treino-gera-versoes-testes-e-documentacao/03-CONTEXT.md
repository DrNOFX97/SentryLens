---
phase: 03-treino-gera-versoes-testes-e-documentacao
decided: 2026-10-10
source: discuss com o utilizador (decisoes D-01..D-05) + pesquisa 03-RESEARCH.md
---

# Contexto da Fase 3 — Treino gera versões, testes e documentação

Decisões travadas. Vêm da pesquisa (`03-RESEARCH.md`) e da conversa com o utilizador. As
decisões das Fases 1 e 2 continuam válidas onde não as contradizem.

## D-01 — O `metadata.json` da versão treinada é escrito pelo registo

O `meta` treinado é montado por um helper em `scripts/model_registry.py`
(`build_trained_metadata()`, nome a fixar), não pelo `train_anomaly_model.py`. O registo
continua a ser o dono do schema — é o que impede que o treino escreva um `metadata.json` que
o próprio registo de seguida rejeite.

`model_registry.py` continua **stdlib puro** (D-01 da Fase 2). O treino calcula o modelo com
joblib/scikit-learn fora do registo e entrega-lhe os factos.

## D-02 — O treino usa uma via nova, não o `adopt`

O `adopt` fixa `v1`, recusa se ela já existe, e — decisivamente — só escreve o `ACTIVE` **se
não existir**. O REG-04 pede o oposto: cada treino cria a versão **seguinte** e **activa-a**.
Reusar o `adopt` seria um conflito directo de semântica, não um detalhe de implementação.

Daí: `next_version_id()` e um caminho de registo novo para o treino. `_materialize_version()`,
`_write_active_atomic()` e `resolve_version_artifacts()` — já testados pelo `adopt` — são
reusados tal como estão.

**`next_version_id()` é sempre `max(n)+1`, nunca `count()`.** Medido: `os.replace` de pasta
sobre pasta existente dá `PermissionError [WinError 5]` no Windows. Com `count()` uma pasta
apagada no meio faria o `next` colidir com uma versão existente e o treino rebentaria.

## D-03 — Ordem de escrita, sem janela de modelo não verificado

1. `joblib.dump` dos dois `.pkl` para um temporário **fora** de `models/`.
2. `next_version_id(root)`.
3. `_materialize_version()` — que já compara o SHA-256 cópia↔original **antes** de a pasta existir.
4. **Confirmação** com `load_metadata()` + `_verify_artifacts()` sobre a versão recién criada.
   Este passo é o que falta hoje: `register_trained_version` não o faria.
5. Só então `_write_active_atomic()`.

Se qualquer passo falhar, não há `ACTIVE` novo e não há pasta a meio. A versão anterior
permanece activa e intacta.

## D-04 — `dataset_origin` é explícito, nunca adivinhado pelo caminho

O `train_anomaly_model.py:72` adivinha "sintético" pelo caminho do ficheiro — exactamente a
heurística que a Fase 2 matou para a avaliação (D-06 da Fase 2). A regra é a mesma: o utilizador
declara a origem (`--dataset-origin`), o código nunca a infere.

## D-05 — `--report` passa a ser opt-in

Por omissão, o treino **imprime** o resumo no stdout e grava-o na `evaluation`/`dataset` da
`vN/metadata.json` da versão treinada. `--report <ficheiro>` continua a existir para quem
quer o artefacto avulso, mas deixa de ser o caminho normal.

Isto mata a razão de ser do `scripts/ml_training_report.json` versionado no git: um relatório
que não pertence a nenhum modelo é exactamente o que esta fase veio resolver.

## D-06 — Rótulo ✅ no `docs/ROADMAP_STATUS.md`, com bloco "Verificado / Por verificar"

O critério 3 da fase pede marcar o R9 como concluído. Mas as verificações humanas das Fases 1
e 2 continuam por fazer, e o `PROJECT.md:9` manda nunca apresentar como real o que não foi
verificado.

Decisão: marcar ✅ **e** acrescentar no próprio ficheiro um bloco que separa o que está
verificado por máquina do que ainda não está (browser real, exportação do Wazuh, avaliação
rotulada). Fica escrito que a diferença existe, não escondida numa nota de rodapé.

## D-07 — Âmbito do DOC-01: cinco ficheiros

`docs/ROADMAP_STATUS.md`, `docs/DATA_MODEL.md`, `README.md`, `CLAUDE.md` (os quatro do
critério 3) **e `docs/ML.md`** — cuja dívida ("o gap do formato de exportação fica para uma
sessão futura") já foi resolvida pelo `export_raw_events.py` da Fase 2.

`docs/API.md`, que não menciona `/api/ml/models` em lado nenhum, fica como **follow-up
registado**, não entra nesta fase.

## D-08 — Os números do README ficam, a afirmação muda

A tabela de precisão/recall/F1 (35 eventos / 20 ataques, 14/09/2026) **fica** — apagar
histórico seria pior do que o qualificar. O que muda é a frase que a acompanha: deixa de
apresentar o número como resultado reproduzível e passa a dizer que é um **registo histórico
de 2026-09-14, não reproduzível hoje**, porque o `attack_log.jsonl` só cobre 2026-10-06 e não
rotula essa janela — com o comando que produz um número sustentado.

Mesmo texto, adapted, em `README.md`, `docs/ML.md` e `CLAUDE.md`.

## D-09 — O primeiro treino novo muda o que o backend carrega

Hoje o backend carrega o **legado**, que não tem verificação de integridade. Depois do primeiro
treino passa a carregar uma versão com SHA-256 verificado. É uma mudança visível e desejada,
mas precisa de teste e de nota na documentação — não pode passar como detalhe.

## D-10 — Provavelmente zero trabalho de frontend

`ml_models.js` já sabe mostrar `parameters`, `dataset`, `library_versions` e `origin: "trained"`,
e o `.cjs` já tem o check. **O plano tem de confirmar isto antes de assumir**; se houver
qualquer coisa em falta, digo-o em vez de refazer o que já está feito.

## D-11 — TST-01 não é re-trabalho

Os 7 itens do critério 2 (registo, `adopt`, hash adulterado recusado, id inválido recusado,
legado sem metadados, avaliação ausente, rota `GET /api/ml/models`) **já estão todos
cobertos** — 331 checks em `test_model_registry.py`, 211 na API, 90 no motor, 295 no `.cjs`.

O trabalho de testes da Fase 3 é cobrir o **REG-04** (treino gera e activa a versão seguinte,
duas execuções seguidas, originais intactos), **não** re-cobrir o que já existe.

## Fora de âmbito (Fase 3)

- Treinar a partir do dashboard (R10).
- HMAC sobre o `metadata.json` (dívida D-04 da Fase 1, aceite e documentada).
- Corrigir `docs/API.md` (follow-up registado por D-07).
- Tornar o dataset histórico rotulável — é trabalho de laboratório (lançar ataques e exportar
  na mesma janela), não de código.
- Sub-projection de `dataset`/`parameters` na API: hoje não têm (ao contrário de `evaluation`).
  É o risco T-01-14; registado como dívida, não corrigido nesta fase.