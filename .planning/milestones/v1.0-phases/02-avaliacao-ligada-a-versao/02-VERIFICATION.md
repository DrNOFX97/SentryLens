---
phase: 02-avaliacao-ligada-a-versao
verified: 2026-10-10
status: complete-with-open-human-checks
plans: 4/4
---

# Verificação — Fase 2: Avaliação ligada à versão

Verificação feita pelo orquestrador depois da execução dos 4 planos (3 waves), por confronto
com os 4 Success Criteria do ROADMAP e com as decisões D-01..D-11 de `02-CONTEXT.md`.

## Estado dos planos

| Plano | Wave | Commits | Estado |
|-------|------|---------|--------|
| 02-01 | 1 | `efb416d`, `29140fe`, `23f0171`, `88f4d8e` | Completo |
| 02-02 | 2 | `c130c52`, `9a0d33b`, `e890d8a` | Completo |
| 02-03 | 2 | `0ccdeaf`, `b647697`, `283c6b0` | Completo |
| 02-04 | 3 | `c01a434`, `86d962f`, `7cdb8fc`, `4f39003` | Completo |

## Success Criteria do ROADMAP

### 1. `evaluate vN --events F` grava na **dessa** versão — PASS (verificado a sério)

Corrido pelo orquestrador num registo temporário, sem tocar em `scripts/models/`:

```
model_registry.py adopt   -> v1 criada por CÓPIA, originais intactos, ACTIVE=v1
model_registry.py evaluate v1 --events snapshots/real_events_2026-09-14.json --dataset-origin real
  -> 35 eventos processados, 0 rotulados como ataque
  -> comparison: ambos 5, só ML 2, só regras 3, nenhum 25
  -> limiares: min_events=50, min_attacks=10 — amostra pequena: SIM
  -> "Avaliação gravada em models/v1/metadata.json — as restantes versões não foram alteradas."
```

O `comparison` **5/2/3/25 é idêntico** ao do `ml_training_report.json` histórico (14/09/2026),
o que confirma D-04: as métricas novas são comparáveis com as do README, porque correm o mesmo
código sobre os mesmos dados.

`resolve_version_artifacts()` (D-02) garante que mede a versão pedida, não a ativa; a guarda
`labels_misaligned` (D-03) recusa gravar quando os conjuntos não batem certo, e o teste
provoca-a trocando `build_ml_anomalies_report` por uma função que devolve menos resultados.

### 2. Sem avaliação → "Sem avaliação", nunca números de outra versão — PASS

`evaluation` continua fora de `METADATA_PUBLIC_KEYS` e é exposto por sub-projection às chaves
fechadas (D-07/D-08). `test_ml_models_api.py` fixa que uma versão sem avaliação devolve `null`,
e `test_ml_models_ui.cjs` (D-11) fixa que a Evaluation mostra as métricas **daquela** versão e
nunca de outra. O teste que na Fase 1 fixava "nenhum número é mostrado" foi **invertido**, com
o `<verify>` a falhar se a frase antiga reaparecer.

### 3. ML vs regras + tamanho do dataset + aviso sempre presente — PASS (automatizado)

`mleSmallSampleNotice` devolve `""` sem `small_sample === true`; com o aviso, mostra
`total_events`, `attacks_in_dataset` e **os dois limiares do payload** (`min_events`,
`min_attacks`) — nunca recalculados no frontend. Os limiares são nomeados
(`MIN_EVENTS = 50`, `MIN_ATTACKS = 10`, D-05) e testados eixo a eixo: 49/12 → aviso,
60/9 → aviso, 60/12 → sem aviso.

### 4. Concordância ao vivo sem métricas novas — PASS

`ml_evaluation.js` consome apenas `total`/`agree_count`/`ml_anomalies_count`/
`rule_flagged_count`/`diverge_count`/`alerts_truncated` de `/api/ml-anomalies` (D-10).
`total === 0` desenha "Sem dados", nunca "0,0 %". Um erro tem caminho de render
próprio (`mleLiveErrorHtml`) e **nunca** se apresenta como "Sem dados"; a convenção
`available/reason` do R8 não foi introduzida.

`/api/ml-anomalies` ganhou `alerts_fetched` e `alerts_truncated` — alteração **aditiva**, a
chave `report["alerts_truncated"]` aparece em exactamente 2 rotas, a API key continua intacta
e nenhuma rota nova foi criada.

## Verificações automatizadas (executadas pelo orquestrador)

| Comando | Resultado |
|---------|-----------|
| `scripts\.venv\Scripts\python run_all_tests.py` | **38/38 verdes** (36 no fim da Fase 1, +2 ficheiros novos) |
| `node --check ml_evaluation.js` | exit 0 |
| `node --check ml_models.js` | exit 0 |
| gate AST: `model_registry.py` stdlib puro | sem violações (D-01) |
| `git log --format=%B 0939528..HEAD \| grep -i "co-authored-by\|generated with"` | vazio |

## Decisões do utilizador — como ficaram

| Decisão | Estado |
|---------|--------|
| D-01 registo stdlib puro, import tardio | ✅ `importlib.import_module` dentro da função; gate AST verde |
| D-02 medir a versão pedida | ✅ `resolve_version_artifacts()`; `resolve_active_artifacts` passou a chamá-la |
| D-03 emparelhamento por índice + guarda | ✅ `labels_misaligned`, nada gravado |
| D-04 comparável com o histórico | ✅ confirmado: 5/2/3/25 idéntico |
| D-05 dois limiares nomeados | ✅ `MIN_EVENTS=50`, `MIN_ATTACKS=10`, OR dos dois eixos |
| D-06 dataset real exportado | ⚠️ exportador escrito e testado; **a exportação real está por executar** (Wazuh desligado) |
| D-07 escrita atómica, fora de METADATA_PUBLIC_KEYS | ✅ `mkstemp` + `os.replace`, validado antes e depois de escrever |
| D-08 sub-projection na API | ✅ `EVALUATION_PUBLIC_KEYS`, texto truncado |
| D-09 `ml_evaluation.js` separado | ✅ prefixo `mle`, sem colisão (testado contra todos os identificadores de `ml_models.js`) |
| D-10 só o que a rota já dá | ✅ sem métricas nem detetores novos |
| D-11 inverter o teste do D-05 | ✅ invertido, com gate que falha se a frase antiga voltar |

## Em aberto

### 1. Verificação humana (nenhum serviço arrancou nesta sessão)

Com as VMs ligadas:

1. `scripts\export_raw_events.py --hours 168 --size 1000 --output scripts\snapshots\raw_events_2026-10-10.json`
2. `scripts\model_registry.py adopt` (se ainda não foi feito)
3. `scripts\model_registry.py evaluate v1 --events <o ficheiro> --attack-log scripts\attack_log.jsonl --dataset-origin real`
4. Arrancar backend + frontend e abrir **📐 Evaluation**: dataset, origem, aviso de amostra e a
   concordância ao vivo a mudar de 24 h para 168 h sem reload; parar o Wazuh e confirmar que
   o erro do Indexer aparece sem estragar a tabela.
5. O mesmo na aba **📦 Models** (verificação herdada da Fase 1, ainda por fazer).

### 2. O dataset real está encontrado, mas **não pode ser rotulado** — esta é a tensão real

`scripts/snapshots/real_events_2026-09-14.json` **existe** (1,7 MB, 14/09/2026) — não está
versionado, mas não está perdido. Dá 35 eventos processáveis de 500.

O problema é o `attack_log.jsonl`: tem **12 entradas, todas de 2026-10-06**, fora da janela do
dataset (2026-09-14 15:22–15:34). Rotulado contra esse log dá **0 ataques**, logo recall 0 por
definição. O CLI Detecta e avisa ("o recall sai 0 por definição e não por falha do modelo"),
mas **esse número não pode ser publicado**.

Para uma avaliação rotulada a sério é preciso: lançar os ataques com `attack_scenarios.py` e
exportar na **mesma janela**. É trabalho de laboratório, não de código.

### 3. Dívidas e riscos registados

- **D-04 (Fase 1) continua aberta:** o SHA-256 deteta corrupção, não autentica.
- **Costura das 14 chaves:** escritas à mão em dois ficheiros (motor e registo), presas por
  comparação em `test_ml_models_api.py`. Mudar a lista obriga a migrar os `metadata.json` já
  gravados e `schema_version` continua 1.
- **Contrato partilhado novo:** `CAVEAT_TEXT_LIMIT` (motor) tem de andar com
  `EVALUATION_TEXT_LIMIT` (API).
- **`docs/ML.md:71-75` desatualizado:** diz que o gap do formato de exportação "fica para uma
  sessão futura" — já foi resolvido pelo exportador.
- **Escopo global do browser** ganhou ~13 identificadores; preso por 3 testes, mas nenhum teste
  apanha uma colisão escrita depois da revisão.
- **DOC-01 (Fase 3)** tem de documentar `evaluate`, `export_raw_events.py` e o facto de o
  dataset histórico não ser rotulável com o `attack_log.jsonl` actual.