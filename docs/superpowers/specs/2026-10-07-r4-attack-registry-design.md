# R4 — Attack Registry (design)

Data: 2026-10-07 · Branch: `roadmap-v2-r4-attack-registry` · Base: R2/R3.

## Objetivo

Tornar o ataque uma entidade consultável: o que foi lançado (id, quando, cenário,
técnica MITRE e ferramenta reais, origem, alvo, operador), o que **esperávamos**
que fosse detetado e o que **realmente** foi (regra/ML/rede), com referências
(não cópias) aos alertas e incidentes ligados. Substitui os itens planeados
"Attack Registry" e "Attack Timeline" da sidebar por painéis reais.

## Rulings (decididos, não em aberto)

1. **Só leitura no backend.** Duas rotas `GET`; **nenhuma rota `POST`** que escreva
   no log. O log continua a ser escrito apenas por `attack_scenarios.py` (na Kali).
   Razão: uma rota de escrita aberta permitiria forjar ataques e assim falsear
   cobertura/MTTD e a ligação a incidentes; o registo de operador/esperado faz-se
   à nascença, no cenário (`--operator`, `--source`, `--expect`).
2. **`attack_log.jsonl` continua no `.gitignore`.** Pode conter IPs/alvos do
   laboratório e o ficheiro é estado de runtime. Quem quiser versionar exemplos usa
   ficheiros sanitizados (`192.0.2.x`/`203.0.113.x`), como nos testes.
3. **Universo = ataques `launched` com cenário conhecido e timestamp válido**, o
   mesmo de `redblue_correlator.parse_launched_attacks` (reutilizado, não
   reimplementado). As restantes entradas (`failed`/`skipped`, cenário
   desconhecido, inválidas) aparecem só como contagens em `skipped`.
4. **Ids.** O `id` do log é o id do registo (inteiro positivo). Entradas sem `id`
   aparecem na lista com `id: null` e não têm detalhe; ids duplicados são
   assinalados (`duplicate_id: true`) e o detalhe devolve o primeiro por tempo.
   `{id}` no URL só aceita `^[0-9]{1,9}$` (outro formato → 422).
5. **Campos novos, todos opcionais** (ficheiros antigos lêem-se sem alteração):
   `operator` (≤64 car., default `"unknown"`), `source` (origem, ≤64 car., default
   `null`: nunca inventada), `expected` (lista ⊂ `rule|ml|network`). Strings são
   limpas de caracteres de controlo e truncadas na leitura. `details` do log
   (comando, returncode) **não** é exposto.
6. **Esperado.** Sem `expected` no log, o esperado é o por omissão do cenário:
   `["rule","ml"]` (é o que o correlator consegue casar pelos `event_ids` do
   cenário); `expected_source` diz `log` ou `scenario_default`. A rede só é
   esperada se o log o disser.
7. **Real (veredito).** Calculado por `build_redblue_report` (mesma janela, mesmo
   IP alvo, mesmos event_ids): `detected` (todas as fontes esperadas viram),
   `partial` (alguma), `not_detected` (nenhuma — explícito), `unknown`
   (correlação indisponível: Indexer/modelo ML em baixo). **Nunca** se afirma
   "não detetado" sem correlação feita. Se os alertas foram truncados (teto 1000),
   a resposta traz `alerts_truncated` e o painel avisa.
8. **Evidência = referências**: `matched_event_ids`, `matched_alert_count`,
   `network_detection_types`, MTTD por fonte e `incidents[]` (`id`, `severity`,
   `status`, `evidence_count`) ligados via `attack_id` nos eventos `attack_linked`
   do R3. Ataques sem `id` não têm ligação a incidentes (a lista de `attack_ids`
   do store só tem ids numéricos).
9. **Falhas parciais não derrubam a lista.** Indexer/ML em baixo →
   `200` com `correlation.available=false` e `error_code` estável
   (`indexer_unavailable`, `ml_model_unavailable`); base de incidentes em baixo →
   `incidents_available=false`. Detalhes só no log do servidor. Leitura do log
   ilegível → `500` genérico. Id inexistente → `404`.
10. **Janela.** `hours` (1–720, default 168) filtra por timestamp do ataque e define
    a janela de alertas pedida ao Indexer. No detalhe a janela é derivada da idade
    do ataque (+1 h); se exceder 720 h o veredito é `unknown`.

## API

| Rota | Parâmetros | Resposta |
|---|---|---|
| `GET /api/attacks` | `hours`, `technique` (`^T\d{4}(\.\d{3})?$`), `status` (`detected\|partial\|not_detected\|unknown`), `limit` (1–500, 200), `offset` | `{window_hours, attacks[], summary, skipped, correlation, incidents_available, total}` |
| `GET /api/attacks/{id}` | — | um ataque (mesmos campos) + `correlation` + `incidents_available` |

Ambas com `dependencies=_REQUIRE_API_KEY`. `/api/redblue/*` não muda (só ganha
`matched_alert_count` aditivo em `attempts[]`).

## Módulo

`scripts/attack_registry.py` (puro, sem I/O): `build_attack_registry(attack_log,
scenarios, ml_results, network_detections, incidents, window_seconds)` chama
`build_redblue_report` e junta cada tentativa à sua entrada (mesma ordenação de
`parse_launched_attacks`). `main.py` só obtém os dados (log, Indexer, buffer de
rede, store) e traduz erros.

## Frontend

`attack_registry.js` (padrão `incidents.js`/`live_soc.js`), dois itens da sidebar
que partilham o mesmo script e a mesma chamada: `data-tab="attack-registry"`
(tabela + detalhe) e `data-tab="attack-timeline"` (lista cronológica com o
veredito). `escapeHtml` em todo o texto dinâmico, "Sem dados" quando vazio, sem
mocks, sem `setInterval` ativo com a aba escondida (padrão `lsIsActive`), sem 2.º
WebSocket, sem scroll horizontal a 390 px. `app.js` não é editado (a navegação é
genérica); `serve_frontend.py` ganha o ficheiro na whitelist.

## Escrita no cenário (`attack_scenarios.py`)

`format_log_entry(..., operator=None, source=None, expected=None)` acrescenta os
campos só se fornecidos; CLI `--operator`, `--source`, `--expect rule,ml,network`
validados por allowlist/tamanho (sem paths).

## Testes

`test_attack_registry.py` (módulo puro e rotas): ficheiro antigo sem campos
novos, linhas corrompidas, id inexistente (404), id malformado (422), sem API key
(401), ataque não detetado, ataque com incidente ligado, correlação indisponível,
sem fuga de excepções. Regressão: todos os `scripts/test_*.py`.

## Fora de âmbito / dívida

Allowlist de targets (R5), cleanup/risco/replay (R5, R13), rotação do log,
editar `operator`/`expected` a posteriori, ligação de ataques sem `id` a incidentes.
