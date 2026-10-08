# R7 — Detection Engine (`DetectionEvent`) (design)

Data: 2026-10-07 · Branch: `roadmap-v2-r7-detection-engine` (a partir de
`roadmap-v2-r6-network-soc`, HEAD `4023328`).

## Objetivo

`docs/ROADMAP_STATUS.md` marca R7 como ⬜: hoje há 3 detetores
independentes (regra/Wazuh via `event_catalog.classify_alert`, ML via
`ml_anomalies.py`/`feature_extractor.py`/Isolation Forest, rede via
`network_detections.py`) que só são unidos ad-hoc, em dois sítios
diferentes, cada um com a sua própria normalização:

- `incident_engine.py` normaliza evidência de incidente como
  `{kind: wazuh_alert|network_detection, key, ts, asset, severity, payload}`
  (ML nunca entra como evidência — só como `ml_summary` por incidente, via
  `incident_ingest.ml_summary`).
- `redblue_correlator.py` classifica cada tentativa de ataque por
  `detected_by` (`rule|ml|both|none`) + `detected_by_network` em separado,
  com a sua própria lógica de janela/correspondência.

Não há hoje um tipo de dados comum. Esta fase cria essa base
(`detection_event.py`) e usa-a **dentro** dos dois sítios acima, sem lhes
mudar o contrato observável — é um refactor de risco mais alto que R2–R6
porque toca código já em produção (R3, Fase 11/R4/R6).

## Rulings (decididos, não em aberto)

1. **`scripts/detection_event.py`, módulo puro, novo.** Tipo comum
   `DetectionEvent` (dict tipado via `TypedDict`, não dataclass — mantém o
   estilo do resto do projeto, que usa dicts simples em todo o lado, nunca
   dataclasses) com os campos pedidos: `source` (`rule|ml|network`),
   `severity`, `asset` (pode ser `None`, ex.: nenhum detetor de rede tem
   sempre os dois IPs), `ts` (ISO-8601 com fuso), `technique` (opcional,
   `None` por agora nos 3 construtores — nenhuma das 3 fontes atuais liga
   uma técnica MITRE a uma deteção individual; isso só existe ao nível da
   tentativa de ataque no `redblue_correlator`, não da deteção em si),
   `confidence` (opcional, **`None` nos 3 construtores por agora** — ver
   ruling 2), `ref` (apontador para o dado original, nunca cópia — o
   próprio dict já recebido), `label` e `description`. Três construtoras
   puras: `from_rule_alert(raw)`, `from_ml_anomaly(result)`,
   `from_network_detection(det)`. Nunca lançam exceção; entrada inválida →
   `None`. Reaproveita `_parse_timestamp` de `redblue_correlator` (mesmo
   padrão de import que `incident_engine.py` já usa) e `classify_alert` de
   `event_catalog.py` — não reimplementa nada.
2. **`confidence` fica `None` nos 3 construtores nesta fase.** `ml_score`
   (saída de `IsolationForest.decision_function`) não é uma probabilidade
   calibrada — é só um grau relativo ("quanto mais negativo, mais
   anómalo"), sem significado absoluto 0–1. Inventar uma normalização
   linear/sigmoide só para preencher o campo seria um número com aparência
   de rigor que não tem — pior do que deixá-lo vazio. O campo existe no
   tipo (é a "base" que a R7 pede) porque uma fase futura pode calibrar um
   score real; por agora nenhuma das 3 fontes o alimenta. Documentado
   aqui para não ser lido como uma omissão acidental.
3. **`incident_engine.py` — refactor real, não cosmético.**
   `evidence_from_raw_alert`/`evidence_from_network_detection` passam a
   construir-se sobre `detection_event.from_rule_alert`/
   `from_network_detection` internamente: chamam o construtor, e se vier
   `None` devolvem `None` (mesmo critério de validade que já tinham — `ts`
   e `asset` têm de existir); se vier um evento válido, montam
   `{kind, key, ts: event["ts"], asset: event["asset"],
   severity: event["severity"], payload: event["ref"]}` — `kind`/`key`
   continuam a ser decididos aqui (são conceitos de deduplicação de
   incidente, não do tipo de deteção em si) e `payload` é sempre
   `event["ref"]`, isto é, o mesmo dict de entrada, nunca uma cópia.
   Equivalência campo-a-campo confirmada por leitura de código antes de
   editar e por `test_incident_engine.py` a passar **sem alterações**
   antes e depois (prova de que o contrato de evidência de incidente não
   mudou). `NETWORK_SEVERITY` deixa de estar duplicado: `incident_engine.py`
   passa a importá-lo de `detection_event.py` (fonte única).
4. **`redblue_correlator.py` — refactor aditivo e deliberadamente estreito.**
   O algoritmo de janelas/correspondência (`parse_launched_attacks`,
   `attack_windows`, os filtros de `matches`/`network_matches` dentro de
   `build_redblue_report`) **não é tocado** — é o código mais sensível
   desta fase (alimenta `attack_registry.py`, que por sua vez alimenta
   `GET /api/attacks`, e o painel Red vs Blue via `GET /api/redblue/metrics`;
   uma regressão silenciosa ali corromperia MTTD/cobertura já reportados).
   A única integração feita é no campo `network_detection_types` de cada
   `attempt`: em vez de ler `det.get("type")` diretamente, cada deteção de
   rede já selecionada pelo filtro de match (inalterado) passa por
   `detection_event.from_network_detection(det)`; se o construtor devolver
   um evento válido usa-se `event["label"]` (que é sempre == `det.get("type")`
   quando o construtor aceita a entrada — ver `detection_event.py`), senão
   (deteção malformada que o construtor rejeita mas que o filtro de match,
   mais permissivo, deixou passar) cai-se de volta para `det.get("type")`,
   exatamente o comportamento anterior. É uma substituição estritamente
   equivalente para todas as entradas que já passavam no filtro existente,
   com fallback para as que não passam no construtor — nunca uma nova
   forma de perder um match. Nenhum campo novo é exposto; nenhum teste
   existente assume diretamente o conteúdo de `network_detection_types`
   (confirmado por grep a `test_redblue.py`), mas acrescenta-se um caso
   novo dedicado a esta integração (ver Testes).
5. **Nenhuma mudança de contrato observável.** `/api/incidents/*`,
   `/api/redblue/*` e `/api/attacks` mantêm exatamente o mesmo shape. Prova:
   `test_incident_engine.py`, `test_incident_ingest.py`,
   `test_incident_store.py`, `test_incidents_api.py`, `test_redblue.py`,
   `test_redblue_attack_log.py` e `test_attack_registry.py` correm **sem
   nenhuma edição** antes e depois do refactor e continuam todos a passar
   (ver Testes/Critérios de aceitação). Se algum precisasse de mudar, seria
   sinal de uma mudança de contrato não planeada — não foi o caso.
6. **Rota nova `GET /api/detections` — implementada, mas sem painel
   frontend nesta fase.** A sidebar já tem "🎯 Detections" como
   `data-planned="R7"` em `index.html` (confirmado por grep). Decisão:
   expor o backend (API) agora, porque é o consumidor natural e seguro de
   `detection_event.py` — uma vista unificada recente dos 3 detetores, só
   leitura, reaproveitando dados já expostos individualmente por
   `/api/alerts`, `/api/ml-anomalies` e `/api/network/detections` (não é
   uma fuga de dados nova). Ficar sem painel: construir a aba nova implica
   tocar `serve_frontend.py` (whitelist), criar um `detection_engine.js`
   novo, ligar `data-tab`/`data-planned` em `index.html`, e verificação
   Playwright — trabalho real, independente do refactor de risco mais alto
   que é o foco desta fase, e sem urgência (R8/MTTD-MTTR e fases
   seguintes vão consumir `DetectionEvent` de formas ainda não decididas;
   desenhar a UI antes disso arrisca desenhá-la para a forma errada). O
   item da sidebar fica `data-planned="R7"` como está — a API já existe,
   mas sem um consumidor na UI ainda; isto é dívida documentada, não uma
   lacuna acidental (ver Dívida).
7. **Forma da rota nova.** `GET /api/detections` (`dependencies=
   _REQUIRE_API_KEY`), parâmetros `hours` (`Query(24, ge=1, le=168)`,
   mesmo teto dos outros endpoints temporais) e `limit` (`Query(50, ge=1,
   le=200)`, nunca sem teto). Cada fonte é isolada: uma falha no Indexer
   (regra) ou a ausência do modelo ML (`FileNotFoundError`) nunca derruba
   a rota — essa fonte fica `available: false` e `count: 0`, as outras
   continuam a responder (mais estrito que `/api/ml-anomalies`/
   `/api/redblue/metrics`, que devolvem 502/503 se a sua única fonte
   falhar; aqui há 3 fontes independentes, por isso "uma fonte em baixo"
   não é motivo para apagar as outras duas — é exatamente o "Sem dados"
   pedido no âmbito). Rede usa `network_detection_buffer` (mesma fonte que
   `/api/redblue/metrics`, não `packet_buffer` recomputado — mantém a
   mesma convenção já estabelecida). `ref` (o dado bruto de origem) é
   **excluído** da resposta HTTP — expor o alerta Wazuh/linha de ML/
   deteção de rede completa duplicaria o que `/api/alerts`,
   `/api/ml-anomalies` e `/api/network/detections` já servem, sem
   necessidade; a vista unificada expõe `source/severity/asset/ts/
   technique/confidence/label/description`, ordenada por `ts` descendente,
   capada a `limit`, com `truncated: true` se havia mais eventos do que
   `limit` entre as 3 fontes.

## Módulo novo — `scripts/detection_event.py`

```python
class DetectionEvent(TypedDict):
    source: str            # "rule" | "ml" | "network"
    severity: str
    asset: str | None
    ts: str                # ISO-8601 com fuso
    technique: str | None  # sempre None nos 3 construtores por agora (ruling 2)
    confidence: float | None  # sempre None nos 3 construtores por agora (ruling 2)
    ref: object            # apontador para o dado original, nunca cópia
    label: str
    description: str | None
```

- `from_rule_alert(raw: dict) -> DetectionEvent | None` — alerta bruto do
  Indexer (`_source`), mesmo critério de validade que
  `incident_engine.evidence_from_raw_alert` tinha (`@timestamp` válido +
  `agent.ip`); `severity`/`label`/`description` vêm de
  `event_catalog.classify_alert(windows_event_id)`.
- `from_ml_anomaly(result: dict) -> DetectionEvent | None` — um item de
  `ml_anomalies.build_ml_anomalies_report()["results"]`. Só
  `ml_is_anomaly=True` vira evento (uma linha "normal" não é uma deteção);
  `asset = result["agent_ip"]`, `label` fixo ("Anomalia ML (Isolation
  Forest)"), `description` menciona o `ml_score` em bruto (não uma
  confiança — ver ruling 2).
- `from_network_detection(det: dict) -> DetectionEvent | None` — mesmo
  critério de validade que `incident_engine.evidence_from_network_detection`
  (`timestamp`/`type` válidos, `dst_ip` ou `src_ip` como `asset`);
  `severity` vem de `NETWORK_SEVERITY` (movido para aqui, `incident_engine.py`
  passa a importá-lo em vez de duplicar), `label = det["type"]`.

## Integração com código existente

Ver rulings 3 e 4. Resumo: `incident_engine.py` passa a usar os
construtores desta fase como a implementação interna das suas duas
funções de normalização (equivalência total, provada por testes
inalterados); `redblue_correlator.py` só usa `from_network_detection` para
rotular `network_detection_types` de forma partilhada, com fallback
seguro — tudo o resto (janelas, correspondência, MTTD, cobertura) fica
exatamente como estava.

## API nova (`main.py`)

| Rota | Parâmetros | Resposta |
|---|---|---|
| `GET /api/detections` | `hours` (1–168, default 24), `limit` (1–200, default 50) | `{window_hours, sources: {rule: {available, count}, ml: {available, count}, network: {available, count}}, total, truncated, events: [{source, severity, asset, ts, technique, confidence, label, description}]}` |

`dependencies=_REQUIRE_API_KEY`, `GET`, nunca 500 por uma fonte em baixo
(ver ruling 7).

## Testes

- `scripts/test_detection_event.py` (novo, puro, sem I/O): os 3
  construtores, casos válidos/invalidos (espelha os fixtures já usados em
  `test_incident_engine.py` para `evidence_from_raw_alert`/
  `evidence_from_network_detection`, para confirmar a equivalência que o
  refactor assume), e que `confidence`/`technique` são sempre `None`
  (ruling 2, para não regredir silenciosamente se uma fase futura os
  preencher sem atualizar este teste).
- `test_incident_engine.py` — **zero edições**; continua a passar, prova
  de que a evidência de incidente não mudou.
- `test_redblue.py` — **zero edições** nos casos existentes; acrescenta-se
  1 caso novo para a integração do ruling 4 (uma deteção de rede com
  `type` ausente, que o filtro de match aceita mas `from_network_detection`
  rejeita, confirma o fallback para `det.get("type")`, aqui `None`).
- `test_attack_registry.py`, `test_redblue_attack_log.py`,
  `test_incident_ingest.py`, `test_incident_store.py`,
  `test_incidents_api.py` — regressão, sem edições esperadas.
- `scripts/test_detections_api.py` (novo): `GET /api/detections` com as 3
  fontes mockadas (indexer via `AsyncMock`, modelo ML treinado em memória
  como em `test_ml_anomalies.py`, `network_detection_buffer` populado
  manualmente como em `test_network_soc.py`); 401 sem `X-API-Key`; cada
  fonte em baixo isoladamente (indexer a lançar, sem modelo, sem
  `vm_ssh_client`) devolve `available: false` nessa fonte e 200 no total;
  `limit`/`hours` fora do intervalo → 422; `truncated` reflete haver mais
  eventos que `limit`.
- Regressão completa: todos os `scripts/test_*.py` (27 ficheiros à data
  desta fase) correm antes e depois do refactor — `any_fail=0` nas duas
  vezes.

## Fora de âmbito, riscos, dívida

**Fora de âmbito**: painel frontend de "Detections" (ruling 6 — fica como
dívida documentada, não lacuna acidental); migrar `incident_engine.py`/
`redblue_correlator.py` para `DetectionEvent` como o seu *contrato
externo* (continuam com os seus próprios shapes — `evidência de incidente`
e `attempt de correlação` — por design, ver rulings 3/4); calibrar
`confidence` com um score real (ruling 2); MITRE por deteção individual
(`technique` fica `None` — só existe ao nível da tentativa de ataque,
fora desta fase); paginação por cursor em `/api/detections` (só
`limit`/`hours`, suficiente para "vista recente", não para consultar
histórico — mesmo nível de ambição que `/api/network/evidence` em R6).

**Riscos geridos**: o maior risco desta fase é uma regressão silenciosa em
`incident_engine.py`/`redblue_correlator.py` — mitigado por (a) não tocar
no algoritmo de correspondência/janelas do correlator, (b) exigir que os
testes existentes passem **sem edição** como critério de aceitação, não
só "os testes passam" (que permitiria editar um teste para encobrir uma
mudança de contrato).

**Dívida**: painel "Detections" ainda não existe (sidebar continua
`data-planned="R7"`); `/api/detections` não tem índice/paginação por
cursor (mesma situação que `/api/network/evidence`); `confidence` existe
no tipo mas nenhuma fonte o preenche ainda.

**Critérios de aceitação**:
- [ ] `detection_event.py` tem as 3 construtoras, puras, nunca lançam.
- [ ] `test_incident_engine.py` e `test_redblue.py` passam **sem edição**
      no essencial (só 1 caso novo acrescentado em `test_redblue.py` para
      a integração do ruling 4, nenhum caso existente alterado).
- [ ] `/api/incidents/*`, `/api/redblue/*`, `/api/attacks` com o mesmo
      shape de antes (confirmado pelos testes de API inalterados).
- [ ] `GET /api/detections` nunca devolve 500 por uma fonte em baixo;
      `limit`/`hours` sempre capados pelo FastAPI (422 fora do intervalo).
- [ ] Todos os `scripts/test_*.py` passam (27 ficheiros à data).
- [ ] Docs atualizadas (`API.md`, `DATA_MODEL.md`, `ARCHITECTURE.md`,
      `SECURITY.md`, `ROADMAP_STATUS.md`, `README.md`, `CLAUDE.md` local).
