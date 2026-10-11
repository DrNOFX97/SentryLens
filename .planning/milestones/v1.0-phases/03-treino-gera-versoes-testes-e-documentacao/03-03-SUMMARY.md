# Wave 3 — Fase 3, Plano 03-03: Honestidade dos números e documentação do registo de modelos

**Data:** 2026-10-10

## Objetivo

Fechar o DOC-01: os cinco ficheiros de documentação (`README.md`, `CLAUDE.md`, `docs/DATA_MODEL.md`, `docs/ROADMAP_STATUS.md`, `docs/ML.md`) passaram a descrever a verdade sobre o registo de modelos — e, onde não conseguem dizer a verdade, dizem isso mesmo.

## O que mudou

### `README.md`
- A tabela ML de 14 de setembro de 2026 manteve os números (0,86 / 0,30 / 0,44 e 0,88 / 0,35 / 0,50) mas a afirmação mudou: passou a ser qualificada como **registo histórico, não reproduzível hoje** (o `attack_log.jsonl` do repositório é de 6 de outubro e não rotula a janela de 14 de setembro).
- O bloco "Para treinar o modelo" foi atualizado para descrever `--models-dir`, `--dataset-origin`, `--report` opt-in, e que o treino cria `models/vN/` + `metadata.json` + `ACTIVE`; os `.pkl` soltos são o modelo legado.
- Foi acrescentada a subsecção **"Registo de modelos"** com: versões, `ACTIVE`, `adopt`, SHA-256, `/api/ml/models`, e a mudança de garantia (antes da primeira versão: legado sem verificação; a partir da primeira: com SHA-256 verificado).
- Contagens de testes atualizadas de **33** para **38** em todos os sítios.
- Rota `GET /api/ml/models` acrescentada à tabela da API (entre `/api/ml-anomalies` e `/api/redblue/metrics`).
- Árvore do repositório completada com `model_registry.py`, `ml_evaluation.py` e `export_raw_events.py`.
- Limitação "ML com pouca amostra" reformulada: a questão passa a ser o dataset não ser rotulável com o `attack_log.jsonl` atual.

### `CLAUDE.md`
- Contagem de testes atualizada de **33** para **38**.
- Descrição do `feature_extractor.py` corrigida: as 7 features reais (em vez de "conta de tentativas, intervalo médio, desvio padrão").
- Descrição do `train_anomaly_model.py` atualizada: escreve em `models/vN/`, usa `--models-dir`/`--dataset-origin`/`--report`, é o único sítio que cria versões.
- Acrescentados `model_registry.py` e `ml_evaluation.py` ao bloco de arquitectura.
- Acrescentadas **5 regras** em "Coisas não óbvias" (D-04 a D-08).
- Texto da honestidade dos números com data **2026-10-06** acrescentado.

### `docs/DATA_MODEL.md`
- Entidade `Model` removida da lista "ainda por definir" do Roadmap v2 (já está definido na R9).
- Acrescentada secção **"Registo de modelo (R9)"** com: layout em disco (`ACTIVE`, `vN/`, `.pkl` soltos = legado), schema completo do `metadata.json` (13 chaves, diferença `origin: trained` vs `origin: adopted`), regras de validade, `ArtifactSource`, e a resposta de `GET /api/ml/models`.

### `docs/ROADMAP_STATUS.md`
- Linha do R9 mudada de **🟡** para **✅** na tabela das fases.
- Contagem R24 alterada de **17** para **38** ficheiros standalone.
- Acrescentada entrada do R9 em **"Dívida conhecida"**: SHA-256 não autentica; dataset de referência não rotulável.
- Acrescentada secção **"R9 — verificado por máquina / por verificar em humano"** (D-06): separa o que foi verificado automaticamente (suite de testes, SHA-256, IDs inválidos, evaluate) do que ainda depende de verificação humana (abrir dashboard, reiniciar backend, exportar eventos, lançar ataques).

### `docs/ML.md`
- O "O que o treino escreve" foi atualizado para descrever `models/vN/` + `metadata.json` + `ACTIVE`, `--models-dir`, `--dataset-origin`, `--report` opt-in; `.pkl` soltos são legado.
- O gap do formato de exportação que antes se dizia "para uma sessão futura" passou a dizer que foi resolvido por `scripts/export_raw_events.py`.
- Acrescentada **nota de reprodutibilidade (2026-10-10)** antes da tabela do primeiro ciclo real: mesma verdade, data do `attack_log.jsonl` atual (2026-10-06), e o comando para reproduzir a medição rotulada.
- A descrição do "Resultado" passou a referir `origin --dataset-origin` declarado em vez de `caveat` adivinhado pelo caminho.

## Verificação

- `run_all_tests.py` — 38/38 verdes (documentação não afetou testes).
- Gates de presença/ausência em todos os 5 ficheiros: aprovados.
- Nenhuma das 10 frases antigas proibidas sobreviveu nos ficheiros.
- A data **2026-10-06** está presente em `README.md`, `CLAUDE.md` e `docs/ML.md`.
- O SHA-256 non-authentication remark está em `README.md`, `CLAUDE.md` e `docs/ROADMAP_STATUS.md`.
- A tabela de 2026-09-14 mantém os mesmos algarismos em `README.md` e `docs/ML.md`.
- `docs/ROADMAP_STATUS.md` tem `| R9 | ML Intelligence | ✅` **e** a secção "Por verificar".

## Artifacts this phase produces

| Artefacto | Tipo | Estado |
|-----------|------|--------|
| `README.md` | documentação do utilizador | alterado (DOC-01) |
| `CLAUDE.md` | guia de trabalho | alterado (DOC-01) |
| `docs/DATA_MODEL.md` | contrato | alterado (DOC-01) |
| `docs/ROADMAP_STATUS.md` | estado do roadmap | alterado (DOC-01) |
| `docs/ML.md` | metodologia | alterado (DOC-01) |
| `03-03-SUMMARY.md` | resumo da wave | criado |

## Success criteria (DOC-01)

- ✅ Critério 3 do ROADMAP: R9 marcado como concluído e o ficheiro diz o que isso significa e o que ainda não está verificado (D-06).
- ✅ Critério 3 do ROADMAP, parte DATA_MODEL/README/CLAUDE: os três descrevem o registo de modelos — versões em `vN/`, `ACTIVE`, `adopt`, SHA-256 antes de carregar o `.pkl` e `GET /api/ml/models` — cada um no registo que lhe compete.
- ✅ D-07 fechado: os cinco ficheiros estão actualizados e a dívida do STATE.md:87 está resolvida; `docs/API.md` fica registado como follow-up, não corrigido.
- ✅ D-08 fechado: a tabela de 2026-09-14 fica com os mesmos algarismos em `README.md` e `docs/ML.md`, e o mesmo texto (adaptado) diz nos três ficheiros que é um registo histórico não reproduzível hoje e aponta para o comando que produz um número sustentado.
- ✅ Erros factuais do `CLAUDE.md` corrigidos: `anomaly_model.pkl` (que não existe), "lê histórico JSONL" (que não lê), as features descritas (que não são as 7 reais) e as três contagens de testes.
- ✅ D-09 fechado na documentação: o README diz, em duas frases, que até à primeira versão registada o backend carrega o legado sem verificação de integridade e que a partir daí carrega uma versão com SHA-256 verificado — a mudança de garantia fica escrita, não implícita.
- ✅ DOC-01 servido por um critério verificável: o gate de presença/ausência é mecânico e sai com 0; a leitura da qualidade do texto é humana, mas o que o ficheiro tem de dizer é fixado por máquina.