# Phase 12: Motor de vaccines - Research

**Researched:** 2026-10-11
**Domain:** módulo Python puro (stdlib) que transforma o relatório do Attack Registry em candidatos a regra de deteção ("vaccines"); sem I/O, sem HTTP, sem store.
**Confidence:** HIGH (tudo assenta em código do próprio repo lido nesta sessão; zero dependências novas)

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
**Ataque partial**
- **D-01:** Um ataque `partial` gera uma vaccine só para o(s) sensor(es) em falta: `missing_sensors = expected − achieved`. A vaccine guarda também `achieved` para contexto. Um `not_detected` tem `missing_sensors` = todos os esperados.

**Identidade e id**
- **D-02:** Um candidato por ataque (`not_detected`/`partial`); `detected` e `unknown` (incluindo `unknown` por `alerts_truncated`) nunca geram.
- **D-03:** O id é um hash determinístico de `attack_id` + conjunto ordenado de `missing_sensors`. Reprocessar os mesmos ataques dá os mesmos ids. Se o veredito evoluir (partial → not_detected) o id muda de propósito, porque o conjunto em falta mudou. — **Reversibility:** costly — o id é a chave do store (Phase 13) e da rota `/api/vaccines/{id}`; mudar a fórmula depois exige migração.
- **D-04:** Ataques sem `attack_id` válido ou com `duplicate_id` são saltados (sem origem rastreável, VAC-03) e contados; o motor devolve `skipped` com contadores (ex.: `no_attack_id`, `duplicate_id`) em vez de os esconder.

**Regra proposta**
- **D-05:** A janela vem de `redblue_correlator.DEFAULT_WINDOW_SECONDS` (300 s), a mesma usada na correlação que mediu o gap. Sem campo novo no `attack_library.yaml`.
- **D-06:** A condição é estruturada e de chaves fechadas: `{event_ids, min_count, window_seconds}`, com `min_count = 1` por omissão (a evidência só tem `matched_alert_count`, sem base para limiares inventados). `event_ids` vêm de `attack_scenarios.SCENARIOS` (ligados a `event_catalog`). Nenhum campo contém comando executável.
- **D-07:** Cada vaccine tem `sensor` ∈ {rule, ml, network}. Para `ml`/`network` a regra de `event_ids` não se aplica: `rule: null` e uma `recommendation` em texto (português, sem comandos). Nada é inventado nem perdido.

### Claude's Discretion
- Algoritmo do hash (ex.: sha256 truncado) e nomes exatos dos campos fora dos acima.
- Forma exata do "Sem dados" / código estável (seguir o padrão `source_unavailable` de `soc_metrics.py`).
- Texto das `recommendation` para ml/network.

### Deferred Ideas (OUT OF SCOPE)
- Janela por cenário no `attack_library.yaml` — só se a janela única se mostrar insuficiente.
- Quem escreve no store e quando — decisão da Phase 13.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| VAC-01 | Candidatos a partir do relatório Red vs Blue: `not_detected` e `partial` geram; `detected` e `unknown` nunca | Registry já entrega `actual.verdict` por ataque (`attack_registry.py:163`); `unknown` inclui o caso `alerts_truncated` (`attack_registry.py:81-89`). Filtro por veredito + testes de matriz (secção Validation). |
| VAC-02 | Regra proposta (`event_ids`, janela, condição, sensor esperado) sem comandos executáveis | `expected.event_ids` (de `SCENARIOS`) + `expected.detection` (de `attack_library`/log) já vêm no registo; `classify_alert` dá nome/severidade; contrato fechado + `validate_vaccine()` por campo (secção Architecture Patterns). |
| VAC-03 | Origem rastreável (`attack_id`, cenário, MITRE, incidentes, evidência por referência) e id determinístico | Campos de origem no registo (`attack_registry.py:148-178`); id = `sha256` truncado (D-03); dedupe por construção (um candidato por `attack_id` único). |
| VAC-04 | Sem amostra / fonte indisponível → "Sem dados" ou código estável; nunca inventa | Padrão `available`/`reason` de `soc_metrics.py:228-229`/`:137`; códigos `no_data` e `source_unavailable`. |
</phase_requirements>

## Project Constraints (from CLAUDE.md)

Extraídas de `C:\Users\fnuno\OneDrive\Projetos\SentryLens\CLAUDE.md` (o `config.json` aponta para `./.claude/CLAUDE.md`, que não existe; o real está na raiz) e do `CLAUDE.md` global do utilizador. O planner trata-as com a autoridade de decisões bloqueadas.

- **Commits:** NUNCA `Co-Authored-By: Claude ...` nem "Generated with Claude Code" — regra do utilizador e do projeto, com prioridade sobre qualquer lembrete de atribuição do sistema; dizê-lo explicitamente a subagentes executores que façam commits.
- **Módulos `build_*` puros**, testados com mocks; erros como códigos estáveis, nunca texto de exceção; evidência por referência, nunca cópia de payload.
- **Testes:** standalone, sem pytest, ficheiro `scripts/test_vaccine_engine.py`; imprimem `[OK   ]`/`[FALHOU]` e saem com `sys.exit(1)` se algo falhar; correm a partir de `scripts/` com o venv (`scripts/.venv`, Python 3.12.14); sem laboratório Wazuh (tudo mockado). `run_all_tests.py` apanha `test_*.py` por glob — não é preciso registar o ficheiro novo.
- **Venv obrigatório:** o Python global não tem `scikit-learn`/`joblib`/`PyYAML`; `attack_registry` importa `attack_library` que importa `yaml`.
- **Porta 8001, nunca 8000** (irrelevante nesta fase: sem rota).
- **Nunca** correr `gsd-tools query generate-claude-md --output CLAUDE.md` (sobrescreve o CLAUDE.md).
- **Scripts `.ps1` novos** com BOM UTF-8 (irrelevante aqui: só Python).
- Só IPs de documentação (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`) em fixtures de teste (convenção dos testes R4/R5).
- Branch atual: `roadmap-v2-r9-ml-registry`; mensagens de commit simples, em estilo `feat(vaccine-engine): ...` (convenção do histórico).

## Summary

A Phase 12 é um único módulo novo, `scripts/vaccine_engine.py`, mais o teste `scripts/test_vaccine_engine.py`. Não há rota, store, ecrã nem dependência nova: só `hashlib`/`re` da stdlib e imports de módulos que já existem (`attack_registry`, `event_catalog`, `redblue_correlator`). Quase tudo o que a vaccine precisa já está calculado por `build_attack_registry` por ataque: veredito, esperado (`expected.detection`, `expected.event_ids`, `expected.source`), atingido (`actual.achieved`), técnica MITRE, evidência por referência e incidentes ligados. O motor é, essencialmente, um filtro + uma projeção para um contrato fechado + um hash.

O trabalho de risco não é algorítmico, é de contrato: (1) o id (D-03) é "costly" a mudar porque é a chave do store, por isso tem de ficar fixado por um teste com valores literais ("golden ids"); (2) "nenhum campo contém comando executável" deve ser garantido por construção — chaves fechadas + validador por campo (allowlist), não só uma lista de padrões proibidos; (3) "nunca inventa" exige que "sem dados", "fonte indisponível" e "ataque unknown" sejam três resultados distintos e testados.

Duas descobertas que o planner tem de conhecer: a regra D-07 fala num `sensor` singular, mas D-01/D-02 dizem um candidato por ataque com `missing_sensors` que pode ter vários elementos (ver Open Question 1 — recomendação: lista `proposals`, uma por sensor em falta); e o escritor atual do `attack_log` (`format_log_entry`) **não grava `id`**, por isso ataques lançados pelo CLI hoje ficam `id: null` e, por D-04, nunca gerariam vaccine (ver Pitfall 1 / Open Question 2). Nenhuma das duas bloqueia a Phase 12 (os testes usam fixtures), mas a segunda faz o motor ficar inerte em dados reais até alguém atribuir ids.

**Primary recommendation:** Criar `scripts/vaccine_engine.py` com `build_vaccine_candidates(registry, correlation=None, *, window_seconds=DEFAULT_WINDOW_SECONDS)` puro; cada vaccine = chaves fechadas (`id`, `verdict`, `expected`, `expected_source`, `achieved`, `missing_sensors`, `proposals[]`, `origin{}`), id = `"vac-" + sha256(f"{attack_id}:{','.join(missing)}")[:12]`, `VACCINE_KEYS`/`validate_vaccine()` exportados (mesmo precedente de `ml_evaluation.EVALUATION_KEYS`/`validate_evaluation`), e `test_vaccine_engine.py` com ids literais fixados.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Decidir que ataques geram vaccine, montar a regra proposta e o id | API / Backend (módulo de domínio puro em `scripts/`) | — | Mesmo padrão dos `build_*_report`: lógica de negócio num módulo puro que `main.py` só chama. |
| Obter o registo de ataques (veredito, esperado, atingido) | API / Backend (`attack_registry.build_attack_registry`, já existe) | — | O motor não recalcula correlação nem vereditos: consome a saída. |
| Persistir vaccines e dar-lhes ciclo de vida | Database / Storage (Phase 13) | — | Fora desta fase (CONTEXT: "Store e API são a Phase 13"). |
| Expor por HTTP / mostrar no dashboard | API (Phase 13) / Browser (Phase 14) | — | Fora desta fase; sem rota nem ecrã. |
| Aplicar regra no Wazuh | — (nunca) | — | Out of Scope do milestone (REQUIREMENTS.md): R11 só propõe. |

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Python stdlib `hashlib` | Python 3.12.14 (`scripts/.venv`) | sha256 do id determinístico | Determinístico entre processos, ao contrário de `hash()` embutido (salgado por processo). [VERIFIED: `scripts/.venv/Scripts/python.exe --version` -> 3.12.14] |
| Python stdlib `re` | idem | Validação dos formatos (id da vaccine, MITRE, id de incidente) | Mesma abordagem de `attack_library.ID_RE`/`MITRE_RE`. |
| `attack_registry` (repo) | — | Fonte dos vereditos/origem: `build_attack_registry`, `EXPECTED_SOURCES`, `VERDICTS`, `normalize_attack_id`, `clean_text` | Fonte única de verdade (CONTEXT canonical refs). |
| `event_catalog` (repo) | — | `classify_alert()` -> nome amigável e severidade por Event ID | Único ponto Event ID -> nome/severidade (CLAUDE.md). |
| `redblue_correlator` (repo) | — | `DEFAULT_WINDOW_SECONDS` | D-05. |

### Supporting
Nenhuma. Não se usa `yaml`, `scikit-learn`, `fastapi` nem `pytest` no motor nem no teste. (`attack_registry` arrasta `yaml` por `attack_library`; o venv já o tem.)

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `sha256` truncado | `uuid5(NAMESPACE, canonical)` | Também determinístico, mas o id é opaco e mais longo; D-03 pede "hash" e o sha256 truncado é legível/curto numa rota. Qualquer das duas serve; escolher uma e fixá-la por teste. |
| Motor a receber `registry` já calculado | Motor a receber `attack_log`+`ml_results`+... e chamar `build_attack_registry` por dentro | Duplica a assinatura do registry e acopla; CONTEXT diz "o motor consome a saída de `build_attack_registry`". |

**Installation:** nada a instalar.

**Version verification:** não aplicável (sem pacotes externos). Python do venv confirmado acima; `yaml` e `sklearn` importam (`python -c "import yaml,sklearn"` -> `ok` no venv).

## Package Legitimacy Audit

Esta fase não instala pacotes externos (só stdlib e módulos do repo), por isso o gate `package-legitimacy check` não se aplica.

| Package | Registry | Age | Downloads | Source Repo | Verdict | Disposition |
|---------|----------|-----|-----------|-------------|---------|-------------|
| — | — | — | — | — | — | Nenhum pacote novo |

**Packages removed due to [SLOP] verdict:** none
**Packages flagged as suspicious [SUS]:** none

## Architecture Patterns

### System Architecture Diagram

```
   (Phase 13 / testes chamam; esta fase NÃO tem chamador em produção)
                     |
   build_attack_registry(...) --> registry {attacks[], skipped}     correlation {available, alerts_truncated, error_code}
                     |                         |                                |
                     +-----------+-------------+--------------------------------+
                                 v
                     build_vaccine_candidates(registry, correlation)
                                 |
        registry is None  OR  correlation.available is False ------> {available:false, reason:"source_unavailable", vaccines:[]}
                                 |
                       attacks == []  -------------------------------> {available:true,  reason:"no_data",           vaccines:[]}
                                 |
                       para cada ataque:
                         verdict in (detected, unknown, outro) ---> só conta em `considered`, nunca gera
                         verdict in (not_detected, partial):
                           id inválido/None ----------------------> skipped.no_attack_id
                           duplicate_id --------------------------> skipped.duplicate_id
                           missing = expected − achieved (ordem EXPECTED_SOURCES)
                           missing vazio -------------------------> skipped.no_missing_sensors   (defensivo)
                           "rule" em missing e sem event_ids ------> skipped.no_event_ids          (defensivo)
                           senão: monta proposals[] (1 por sensor em falta)
                                  id = vac-sha256(attack_id:missing)[:12]
                                 |
                                 v
        {available:true, reason:None, vaccines:[...ordenadas...], total, considered{...}, skipped{...}, alerts_truncated}
```

### Recommended Project Structure
```
scripts/
├── vaccine_engine.py        # NOVO (esta fase): build_vaccine_candidates, vaccine_id, validate_vaccine, VACCINE_KEYS...
└── test_vaccine_engine.py   # NOVO (esta fase): standalone, sem Wazuh, sem importar main
```
Nada mais é tocado nesta fase (não editar `main.py`, `app.js`, `DATA_MODEL.md`; docs são da Phase 14/VAC-08).

### Contrato de entrada (lido do código nesta sessão)

`build_attack_registry` devolve `{"attacks": [...], "skipped": {"not_executed", "unknown_scenario", "invalid"}}` e cada ataque tem (verbatim de `scripts/attack_registry.py:148-178`):

```python
attacks.append((ts, {
    "id": attack_id,
    "duplicate_id": attack_id is not None and id_counts[attack_id] > 1,
    "timestamp": attempt["timestamp"],
    "scenario": entry["scenario"],
    "mitre_tactic": scenario.mitre_tactic,
    "mitre_technique": technique or scenario.mitre_technique,
    ...
    "expected": {"detection": expected, "source": expected_source, "event_ids": list(scenario.event_ids)},
    "actual": {
        "verdict": verdict(expected, achieved, ok, alerts_truncated),
        "correlation_reason": "alerts_truncated" if ok and alerts_truncated and not achieved else None,
        "achieved": achieved,
        ...
    },
    "evidence": {
        "matched_event_ids": attempt["matched_event_ids"] if ok else [],
        "matched_alert_count": attempt["matched_alert_count"] if ok else None,
        "network_detection_types": attempt["network_detection_types"] if ok else [],
        "incident_count": len(linked),
    },
    "incidents": linked,
}))
```
[VERIFIED: scripts/attack_registry.py:148-178]

Constantes e regra de veredito (verbatim):
```python
EXPECTED_SOURCES = ("rule", "ml", "network")
VERDICTS = ("detected", "partial", "not_detected", "unknown")
...
    if not correlation_available:
        return "unknown"
    if not achieved:
        return "unknown" if alerts_truncated else "not_detected"
    return "detected" if all(s in achieved for s in expected) else "partial"
```
[VERIFIED: scripts/attack_registry.py:25,27,81-89]

Janela e Event IDs:
```python
DEFAULT_WINDOW_SECONDS = 300
```
[VERIFIED: scripts/redblue_correlator.py:35]

```python
5140: {"name": "Network Share Accessed", "severity": "low", "category": "acesso_rede"},
...
def classify_alert(win_event_id: int | None) -> dict[str, str]:
    ...
        return {"friendly_name": "Evento não catalogado", "severity": "info", ...}
    return {"friendly_name": info["name"], "severity": info["severity"], ...}
```
[VERIFIED: scripts/event_catalog.py:33,77-93]

Event IDs dos 5 cenários (todos presentes em `CRITICAL_EVENTS`): `brute_force_rdp` [4625, 4740]; `smb_enum` [5140, 5145]; `blank_password_check` [4797]; `lateral_movement_schtasks` [4672, 4698]; `account_lockout_spray` [4625, 4740]. [VERIFIED: scripts/attack_scenarios.py:185,194,203,212,221 + scripts/event_catalog.py:12,14,30,33,34,38,13]

Padrão de "Sem dados" (verbatim, `scripts/soc_metrics.py`):
```python
return {"available": False, "reason": "no_data", ...}            # duration_block, linha 66
"available": bool(attempts), "reason": None if attempts else "no_data",   # linha 137
down = {"available": False, "reason": "source_unavailable"}      # linha 229 (redblue_report is None)
```
[VERIFIED: scripts/soc_metrics.py:66,137,229]

### Contrato de saída recomendado (chaves fechadas)

Os nomes de D-01/D-03/D-06/D-07 são fixos; o resto é discrição.

```
resultado = {
  "available": bool,
  "reason": None | "no_data" | "source_unavailable",
  "vaccines": [vaccine, ...],            # [] quando reason != None
  "total": int,
  "considered": {"attacks","detected","partial","not_detected","unknown"} | None,   # None só em source_unavailable (nunca 0 inventado)
  "skipped": {"no_attack_id","duplicate_id","no_missing_sensors","no_event_ids"},   # inteiros >= 0
  "alerts_truncated": bool,              # True se algum ataque tem actual.correlation_reason == "alerts_truncated"
}

vaccine = {
  "id": "vac-<12 hex>",
  "verdict": "not_detected" | "partial",
  "expected": [sensores],                # copia de expected.detection
  "expected_source": "log" | "scenario_default",   # proveniência: log do ataque vs Attack Library (VAC-02)
  "achieved": [sensores],                # D-01 (contexto)
  "missing_sensors": [sensores],         # D-01, ordem de EXPECTED_SOURCES
  "proposals": [proposal, ...],          # 1 por sensor em falta (ver Open Question 1)
  "origin": {
    "attack_id": int, "scenario": str, "mitre_tactic": str, "mitre_technique": str,
    "incident_ids": [str],               # só ids (referência); severidade/estado mudam, não se copiam
    "evidence": {"matched_event_ids": [int], "matched_alert_count": int | None, "network_detection_types": [str]},
  },
}

proposal = {
  "sensor": "rule" | "ml" | "network",                       # D-07
  "rule": {"event_ids": [int], "min_count": 1, "window_seconds": 300} | None,   # D-06; None para ml/network
  "events": [{"event_id": int, "name": str, "severity": str}] | None,           # só para rule (event_catalog)
  "recommendation": None | str,                              # D-07: só ml/network, PT, sem comandos
}
```

Deliberadamente **fora** da vaccine: `target`, `source`, `operator`, `tool`, `timestamp`, `details`, os dicts completos de `incidents`. Razão: VAC-03 não os pede, `tool` (hydra/netexec) e `details.command` são o vetor de "comando executável", e o alvo é um IP do laboratório. Sem relógio no motor: nenhum `generated_at` (o determinismo da saída inteira fica testável por igualdade; timestamps são do store, Phase 13). Sem campo `status`/`state` no motor (o `proposed` fixo é do store, VAC-05).

### Pattern 1: Contrato fechado + validador por campo (allowlist, não deny-list)
**What:** exportar `VACCINE_KEYS`, `ORIGIN_KEYS`, `PROPOSAL_KEYS`, `RULE_KEYS` e `validate_vaccine(v) -> list[str]` que verifica: conjunto de chaves **igual** (não subconjunto) a cada nível; `id` casa `VACCINE_ID_RE`; sensores ∈ `EXPECTED_SOURCES`; `mitre_technique` casa `^T\d{4}(\.\d{3})?$`; `scenario` casa `^[a-z_]{1,64}$`; `incident_ids` casam `^INC-\d{8}-\d+$`; `recommendation` ∈ conjunto constante do módulo. Mesmo precedente do projeto: `ml_evaluation.EVALUATION_KEYS`/`validate_evaluation` (CLAUDE.md).
**When to use:** sempre — o teste da fase chama-o sobre todas as vaccines; a Phase 13 pode chamá-lo antes de persistir.
**Porquê allowlist:** o critério 2 diz "verificado varrendo todos os valores". Uma deny-list de padrões (`;`, `&&`, `$(`) deixa passar o que não previu; uma allowlist por campo só admite formatos conhecidos, por isso um valor "comando" falha por não casar com nenhum. Complementar com um varrimento de deny-list sobre todas as strings (defesa em profundidade) e um teste negativo: injetar um comando num campo e confirmar que `validate_vaccine` o rejeita.
**Example:**
```python
# Source: padrão do repo (ml_evaluation.EVALUATION_KEYS / attack_library.validate_entry); valores de D-06
RULE_KEYS = frozenset({"event_ids", "min_count", "window_seconds"})
def _walk_strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for k, v in node.items():
            yield from _walk_strings(k); yield from _walk_strings(v)
    elif isinstance(node, (list, tuple)):
        for item in node:
            yield from _walk_strings(item)
```

### Pattern 2: Resultado de três estados, "nunca 0 sem amostra"
**What:** `registry is None` ou `correlation.get("available") is False` -> `reason="source_unavailable"`, `considered=None`; `attacks == []` -> `reason="no_data"`, `considered` com zeros (aí 0 é verdadeiro: sabemos que são zero); com ataques -> `reason=None`, mesmo que `vaccines == []` (ex.: todos `detected`, ou todos `unknown` por truncagem — isso é um resultado legítimo, não "sem dados"). Regista o código; **não** copiar `correlation["error_code"]` em bruto (só se passar por allowlist dos três códigos estáveis do `main.py`: `attack_outside_alert_window`, `ml_model_unavailable`, `indexer_unavailable`; opcional, discrição).
**Texto "Sem dados":** a UI (Phase 14) é que traduz `no_data` -> "Sem dados"; o motor devolve o código (mesmo critério de `soc_metrics`, que só devolve `reason`). Se o planner preferir, uma constante `NO_DATA_LABEL = "Sem dados"` é inócua.

### Pattern 3: Id determinístico
**What:** uma função única e testada por valores literais.
```python
# Source: D-03; ordem canónica = EXPECTED_SOURCES (atribuída pelo motor, nunca por set/sorted-de-set não ordenado)
def vaccine_id(attack_id: int, missing: list[str]) -> str:
    canonical = f"{attack_id}:{','.join(missing)}"          # missing já na ordem de EXPECTED_SOURCES
    return "vac-" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]
```
Valores de referência calculados nesta sessão (`hashlib.sha256(...).hexdigest()[:12]`, venv Python 3.12.14) para fixar no teste: `"2:rule,ml"` -> `vac-5fe3861aa2a3`; `"3:ml"` -> `vac-bd617cce8054`; `"4:rule,ml"` -> `vac-ca13ec0fa618`. [VERIFIED: execução local `python -c` nesta sessão]
O teste "golden" tem de comparar com **literais**, não com o resultado de chamar `vaccine_id` outra vez (senão mudar a fórmula passaria despercebido — exatamente o risco "costly" de D-03). Truncar a 12 hex (48 bits) chega para o volume do laboratório; a colisão de dois ataques tem de ser impossível por construção porque o `attack_id` entra no hash e `duplicate_id` está excluído.

### Pattern 4: Ordem e cópia defensiva
Ordenar `vaccines` por `origin.attack_id` descendente (independente da ordem de entrada; o registry ordena por tempo e há timestamps com `Z`/`+00:00` misturados). Copiar listas (`list(...)`) em vez de partilhar referências com o registry (a Phase 13 pode mutar). Nunca lançar exceção sobre input malformado (convenção do projeto): ataque que não é dict, `actual`/`expected` ausentes, veredito fora de `VERDICTS` -> conta-se em `considered` só se for veredito válido; entradas inutilizáveis ignoram-se sem lançar.

### Anti-Patterns to Avoid
- **Chamar `load_attack_library()`/`SCENARIOS` dentro do motor:** o registo já traz `expected.detection` (library ou log) e `expected.event_ids` (SCENARIOS). Reler duplicaria a fonte e traria I/O para um módulo puro. A proveniência fica visível em `expected_source`.
- **Usar `hash()`, `set` ou `dict` não ordenado no id:** `hash()` é salgado por processo (ids diferentes a cada arranque); ordem de `set` varia. Usar `hashlib` e a ordem de `EXPECTED_SOURCES`.
- **Copiar `tool`, `target`, `operator`, `details`, ou o dict `incidents` completo:** vazam comandos/IPs e congelam estado mutável.
- **Inventar limiares** (`min_count > 1`, janelas por cenário): D-06 e Deferred Ideas proíbem.
- **Tratar `unknown` como "não detetado"** ou gerar vaccine "para encher a lista" (VAC-04).
- **Converter `None` em `0`** em `considered`/`matched_alert_count` quando a fonte está indisponível.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Veredito detected/partial/not_detected/unknown | Recalcular a partir de `detected_by` | `attack["actual"]["verdict"]` do registry | A regra já trata `alerts_truncated` e `correlation_available`; reimplementar diverge (e é o código mais sensível da R4). |
| Esperado por cenário | Mapa cenário->sensores no motor | `attack["expected"]["detection"]` (vem de `attack_library.get_expected_sensors` ou do log) | Fonte única (R5). |
| Event IDs do cenário | Copiar listas de `SCENARIOS` | `attack["expected"]["event_ids"]` | Já resolvido pelo registry; um cenário novo propaga-se sem tocar no motor. |
| Nome/severidade de Event ID | Dicionário próprio | `event_catalog.classify_alert()` | Fonte única Event ID -> nome/severidade (CLAUDE.md). |
| Validação de id de ataque | `int(x) > 0` à mão | `attack_registry.normalize_attack_id` | Já exclui `bool` e limita a 999_999_999. |
| Janela | Constante 300 própria | `redblue_correlator.DEFAULT_WINDOW_SECONDS` | D-05: a mesma que mediu o gap. |
| Texto seguro de campos livres | Regex própria | `attack_registry.clean_text` (se algum texto livre for usado; o contrato recomendado não usa nenhum) | Remove controlo/NEL/LS/PS. |
| Hash | Algoritmo próprio | `hashlib.sha256` | Estável entre processos e versões. |

**Key insight:** o motor é uma projeção. Cada vez que o planner for tentado a recalcular algo (veredito, esperado, event_ids), a resposta é: já está no registo; ler de lá.

## Common Pitfalls

### Pitfall 1: O escritor do attack_log não grava `id` (motor inerte em dados reais)
**What goes wrong:** `format_log_entry` constrói `{"timestamp","scenario","target","tool","status","details"}` e só acrescenta `operator`/`source`/`expected` — nenhum `id`. [VERIFIED: scripts/attack_scenarios.py:263-276]. O `scripts/attack_log.jsonl` atual tem 12 linhas, todas com `"id"` (1..12), semeadas à mão (formato `{"scenario":...,"id":1,"technique":"T1046","tool":"nmap"}`). [VERIFIED: leitura do ficheiro + `grep -c '"id"'` = 12 de 12 linhas]. Um ataque novo lançado por `attack_scenarios.py` fica `id: null` no registry (`normalize_attack_id(None)` -> `None`), e por D-04 conta-se em `skipped.no_attack_id` e **nunca gera vaccine**.
**Why it happens:** o R4 definiu o `id` como "o id do registo" mas nunca implementou a atribuição no escritor; `docs/superpowers/specs/2026-10-07-r4-attack-registry-design.md` aceita `id: null` para o formato antigo.
**How to avoid:** não é desta fase (D-04 é decisão bloqueada). O motor tem de contar e devolver `skipped.no_attack_id` e o teste tem de o cobrir. Registar como dívida/risco para o utilizador decidir (Open Question 2).
**Warning signs:** `considered.not_detected > 0` mas `total == 0` e `skipped.no_attack_id > 0` em dados reais.

### Pitfall 2: `duplicate_id` marca TODAS as entradas com o mesmo id
**What goes wrong:** `"duplicate_id": attack_id is not None and id_counts[attack_id] > 1` é verdadeiro para cada entrada que partilha o id. [VERIFIED: scripts/attack_registry.py:150]. D-04 manda saltar "ataques com `duplicate_id`" — logo saltam-se todos, não "todos menos um", e `skipped.duplicate_id` conta entradas (ataques), não ids distintos. Definir e testar isto explicitamente (ex.: id 8 duplicado -> 2 saltados).

### Pitfall 3: `achieved` pode conter sensores que não eram esperados
**What goes wrong:** `verdict` é `partial` quando `achieved` não está vazio e algum esperado falta. `achieved` pode incluir um sensor fora de `expected` (ex.: esperado `["network"]`, atingido `["rule"]` -> `partial`). `missing_sensors` tem de ser `expected − achieved` (nunca `EXPECTED_SOURCES − achieved`), senão propõe-se vaccine para um sensor que ninguém esperava. [VERIFIED: attack_registry.py:88-89 + 56-67 (expected vem do log ou da library)].
**How to avoid:** `missing = [s for s in EXPECTED_SOURCES if s in expected and s not in achieved]`; testar o caso esperado=network/atingido=rule.

### Pitfall 4: `not_detected` com alertas que chegaram mas não foram sinalizados
**What goes wrong:** o correlator conta `matched_alert_count` para qualquer alerta com `windows_event_id` do cenário no mesmo `agent_ip` dentro da janela, mas `detected_by` só olha `rule_flagged`/`ml_is_anomaly`. [VERIFIED: scripts/redblue_correlator.py:190-209]. Um ataque pode ser `not_detected` com `matched_alert_count > 0`: os eventos chegaram ao Indexer e nenhuma regra/ML os sinalizou. A vaccine propõe a regra na mesma (correto), mas a referência `origin.evidence.matched_alert_count` é o que permite ao analista distinguir "eventos nunca chegaram" de "chegaram e não foram sinalizados". Não omitir esse campo; não "interpretar" no motor.

### Pitfall 5: `unknown` por truncagem ou correlação indisponível
**What goes wrong:** com `alerts_truncated` e sem correspondência o veredito é `unknown`; com `correlation_available=False` todos são `unknown` e `matched_alert_count` é `None`. Gerar vaccine aí seria fabricar um gap (VAC-04). **How to avoid:** só `not_detected`/`partial` geram (comparação exata de strings); `unknown` apenas conta em `considered`; `alerts_truncated` sobe para o nível do resultado para a UI avisar (derivado de `actual.correlation_reason == "alerts_truncated"`; não é preciso o dict `correlation`). Para distinguir "fonte em baixo" de "tudo unknown" o motor precisa do dict `correlation` (parâmetro opcional), porque o registry não marca o caso `correlation_available=False` em `correlation_reason` (fica `None`).

### Pitfall 6: Id que evolui deixa vaccines "velhas" por ataque (aviso para a Phase 13)
**What goes wrong:** D-03 faz o id mudar quando `partial` -> `not_detected`. Num store, o mesmo `attack_id` pode ter 2 vaccines (a antiga e a nova). O critério "nenhum duplicado" desta fase cobre só reprocessar a **mesma** entrada, e é garantido por construção. A política para a antiga (substituir? manter?) é decisão da Phase 13 — registar no handoff, não resolver aqui.

### Pitfall 7: Bool é `int`
`isinstance(True, int)` é `True`. Para `event_ids`, `attack_id`, `matched_event_ids` filtrar `bool` explicitamente (como `normalize_attack_id`). Um `min_count`/`window_seconds` vêm de constantes do motor, nunca do input.

### Pitfall 8: Consola Windows e acentos
Os testes imprimem acentos; `run_all_tests.py` corre-os com `-X utf8`. Ao correr o teste isolado em PowerShell/Git Bash usar `python -X utf8 test_vaccine_engine.py` se aparecer `UnicodeEncodeError`. As `recommendation` em PT têm acentos: o ficheiro `.py` é UTF-8 (default do Python 3).

### Pitfall 9: Janela efetiva ≤ 300 s
`attack_windows` corta a janela no início do ataque seguinte (`redblue_correlator.py:99-112`), por isso a janela com que o gap foi medido pode ser mais curta que 300 s. D-05 fixa 300 s na regra proposta; é uma simplificação consciente, não um bug. Não tentar "corrigir".

## Code Examples

### Esqueleto do motor (todos os valores vêm das citações verbatim acima ou das decisões D-0x)
```python
# scripts/vaccine_engine.py  -- puro: sem I/O, sem rede, sem relógio, nunca lança sobre dados malformados
import hashlib
import re

from attack_registry import EXPECTED_SOURCES, VERDICTS, normalize_attack_id
from event_catalog import classify_alert
from redblue_correlator import DEFAULT_WINDOW_SECONDS

GENERATING_VERDICTS = ("not_detected", "partial")          # D-02
MIN_COUNT = 1                                              # D-06
VACCINE_ID_RE = re.compile(r"^vac-[0-9a-f]{12}$")

RECOMMENDATIONS = {                                        # D-07: texto PT, sem comandos (discrição do texto)
    "ml": "Rever o treino do modelo de anomalias: incluir este ataque e eventos semelhantes no conjunto de treino e reavaliar a versão antes de a ativar.",
    "network": "Rever a captura e as deteções de rede: confirmar que o tráfego deste ataque é capturado e considerar uma deteção por padrão de rede para este cenário.",
}

def vaccine_id(attack_id: int, missing: list[str]) -> str:
    canonical = f"{attack_id}:{','.join(missing)}"
    return "vac-" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]

def _int_list(values) -> list[int]:
    return [v for v in (values or []) if isinstance(v, int) and not isinstance(v, bool)]

def _proposal(sensor: str, event_ids: list[int], window_seconds: int) -> dict:
    if sensor == "rule":
        events = []
        for event_id in event_ids:
            info = classify_alert(event_id)
            events.append({"event_id": event_id, "name": info["friendly_name"], "severity": info["severity"]})
        return {"sensor": "rule",
                "rule": {"event_ids": list(event_ids), "min_count": MIN_COUNT, "window_seconds": window_seconds},
                "events": events, "recommendation": None}
    return {"sensor": sensor, "rule": None, "events": None, "recommendation": RECOMMENDATIONS[sensor]}

def build_vaccine_candidates(registry, correlation=None, *, window_seconds: int = DEFAULT_WINDOW_SECONDS) -> dict:
    ...  # registry None / correlation.available False -> source_unavailable; attacks vazio -> no_data;
         # filtro por veredito; skip no_attack_id/duplicate_id/no_missing_sensors/no_event_ids; ordenar por attack_id desc
```
[ASSUMED] o nome `build_vaccine_candidates` e os nomes de campos fora de D-01/D-03/D-06/D-07 (discrição do CONTEXT); os textos das `recommendation` são rascunho para o planner confirmar.

### Teste: matriz de vereditos a partir do registry real (critério 1)
```python
# Fixtures: o mesmo padrão de test_attack_registry.py (ATTACKS/ML_RESULTS com timestamps relativos a NOW).
# Com os ATTACKS e ML_RESULTS desse ficheiro o registry dá {1: detected, 2: not_detected, 3: partial, 4: not_detected};
# com alerts_truncated=True dá {1: detected, 2: unknown, 3: partial, 4: unknown}
# [VERIFIED: scripts/test_attack_registry.py:99,101,109,165-167].
reg = attack_registry.build_attack_registry(ATTACKS, SCENARIOS, ML_RESULTS)
out = vaccine_engine.build_vaccine_candidates(reg)
check("um candidato por not_detected/partial", sorted(v["origin"]["attack_id"] for v in out["vaccines"]) == [2, 3, 4])
check("detected não gera", 1 not in {v["origin"]["attack_id"] for v in out["vaccines"]})
reg_tr = attack_registry.build_attack_registry(ATTACKS, SCENARIOS, ML_RESULTS, alerts_truncated=True)
out_tr = vaccine_engine.build_vaccine_candidates(reg_tr)
check("unknown por truncagem não gera", sorted(v["origin"]["attack_id"] for v in out_tr["vaccines"]) == [3])
```
Nota: no registry de `ATTACKS`, o ataque 4 tem `expected: ["network", "bogus"]` -> `["network"]` (log), logo a sua vaccine tem `missing_sensors == ["network"]` e proposta só `network`; o ataque 3 (`partial`, atingido `["rule"]`, esperado `["rule","ml"]`) dá `missing_sensors == ["ml"]` (id `vac-bd617cce8054` se o id do ataque for 3); o ataque 2 dá `["rule","ml"]` (id `vac-5fe3861aa2a3` se for 2). Os ids literais acima só valem com esses `attack_id`/`missing`. [VERIFIED: attack_registry.py:56-67 + test_attack_registry.py:62-77,103-106]

### Teste: varrimento "nenhum comando" (critério 2)
```python
def check_no_commands(vaccines):
    for v in vaccines:
        problems = vaccine_engine.validate_vaccine(v)            # chaves fechadas + formato por campo
        check(f"vaccine {v['id']}: contrato fechado válido", problems == [])
        for s in _walk_strings(v):
            check("sem metacaracteres de shell/ferramentas", not DENY_RE.search(s))   # defesa em profundidade
# Negativo: um valor com comando tem de ser rejeitado
bad = copy.deepcopy(vaccines[0]); bad["proposals"][0]["recommendation"] = "netexec smb 192.0.2.10 --shares"
check("validate_vaccine rejeita comando", vaccine_engine.validate_vaccine(bad) != [])
```
`DENY_RE` (no teste): `[;&|`$<>\\]|netexec|hydra|schtasks|powershell|cmd\.exe|sudo|\brm\b|--\w` — escolher com cuidado para não apanhar prosa legítima (`recommendation` PT contém "deteção", "treino"; o Event name `Special Privileges Assigned` etc. não casam). Os nomes de `classify_alert` são texto do catálogo (ex.: `"Process Created"`).

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `DEFAULT_EXPECTED` fixo no registry | Sensores esperados por cenário vêm da Attack Library (`get_expected_sensors`) | R5 | A proveniência vive em `expected.source` (`log`/`scenario_default`); o motor propaga-a como `expected_source`. [VERIFIED: attack_registry.py:56-67] |
| Veredito binário detetado/não | 4 vereditos com `unknown` honesto | R4 | O motor só gera em `not_detected`/`partial`. |

**Deprecated/outdated:** `docs/README.md` descreve estrutura `backend/`/`frontend/` antiga (CLAUDE.md) — não usar. A contagem "38 ficheiros de teste" do CLAUDE.md está desatualizada (há 39 `scripts/test_*.py` hoje; passam a 40 com este); a correção de docs é da Phase 14 (VAC-08).

## Runtime State Inventory

Não aplicável: fase greenfield (módulo novo), sem rename/refactor/migração. Nenhum dado armazenado, serviço, registo do SO, variável de ambiente ou artefacto de build é afetado.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | A vaccine tem lista `proposals[]` (um `sensor` por proposta) em vez de um único `sensor` de topo, porque `missing_sensors` pode ter vários elementos (D-01) e há um candidato por ataque (D-02). | Contrato de saída / Open Question 1 | D-07 diz literalmente "Cada vaccine tem `sensor`". Se o utilizador quiser `sensor` singular na vaccine, a Phase 13 (store/rota) e a 14 (UI) herdam o formato; mudar depois é caro. **Confirmar com o utilizador antes de planear.** |
| A2 | O id usa `f"{attack_id}:{','.join(missing)}"` com `missing` na ordem de `EXPECTED_SOURCES`, prefixo `vac-`, 12 hex. | Pattern 3 | D-03 deixa o algoritmo à discrição, mas é "costly"; formato fixado pelo teste com literais. Risco só se o utilizador quiser outro formato (ex.: sem prefixo). |
| A3 | O motor não emite `status`/`state` nem timestamps; `proposed` e `created_at` são do store (Phase 13). | Contrato de saída | Se a Phase 13 esperar o campo vindo do motor, é um acrescento trivial (aditivo). |
| A4 | A vaccine omite `target`, `source`, `operator`, `tool` e o dict completo de `incidents` (só `incident_ids`). | Contrato de saída | VAC-03 não os lista; se a UI da Phase 14 os quiser, vêm do `GET /api/attacks/{id}` via `origin.attack_id`. |
| A5 | `reason` usa os códigos `no_data` e `source_unavailable` (padrão de `soc_metrics`); "Sem dados" é o rótulo da UI. | Pattern 2 | Critério 4 aceita "Sem dados" ou código estável; baixo risco. |
| A6 | Ordenação por `origin.attack_id` descendente. | Pattern 4 | Cosmético; a UI pode reordenar. |
| A7 | `skipped.no_missing_sensors` e `skipped.no_event_ids` são ramos defensivos que o registry real nunca produz (esperado nunca vazio; `event_ids` de `SCENARIOS` nunca vazio). | Diagrama | Se existirem cenários sem `event_ids`, o motor salta-os em vez de propor uma regra vazia — comportamento honesto. |
| A8 | Rascunho PT das `recommendation` de `ml`/`network`. | Code Examples | Texto é discrição do CONTEXT; confirmar redação. |

## Open Questions

1. **`sensor` singular (D-07) vs vários sensores em falta (D-01/D-02)?**
   - What we know: um ataque `not_detected` tem `missing_sensors` = todos os esperados (hoje `["rule","ml"]` para 4 dos 5 cenários, por `attack_library.yaml`); D-02 exige um candidato por ataque; D-07 diz "Cada vaccine tem `sensor` ∈ {rule, ml, network}" com `rule: null` para ml/network.
   - What's unclear: como uma vaccine com `missing_sensors == ["rule","ml"]` tem um único `sensor`.
   - Recommendation: `proposals[]` (uma por sensor em falta), cada uma com `sensor`/`rule`/`recommendation` exatamente como D-07. Alternativas: (b) `sensor` de topo = sensor primário (rule > ml > network) perdendo as outras propostas, ou (c) um candidato por (ataque, sensor), que contradiz D-02. Pedir confirmação rápida ao utilizador; é a única decisão com custo a jusante.

2. **Ataques lançados pelo CLI não têm `id` (Pitfall 1).**
   - What we know: `format_log_entry` não grava `id`; só o log semeado tem; D-04 salta `id` inválido.
   - What's unclear: quem atribuirá ids no escritor (R4 deixou "id do registo" por implementar) para o motor gerar vaccines com dados reais.
   - Recommendation: manter D-04 e a fase como está (fixtures); registar como dívida visível ao utilizador antes da Phase 13/14 (a UI mostraria "0 vaccines" com `skipped.no_attack_id > 0`). Não alterar `attack_scenarios.py` nesta fase (fora do âmbito).

3. **Política para vaccines antigas do mesmo `attack_id` quando o id evolui (Pitfall 6).**
   - Recommendation: deixar explícito no handoff para a Phase 13; nada a fazer no motor.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Python venv `scripts/.venv` | Correr o teste e importar `attack_registry`/`attack_library` (`yaml`) | ✓ | 3.12.14 | — |
| `PyYAML` / `scikit-learn` no venv | `attack_library` (yaml); sklearn não é usado pelo motor | ✓ | `import yaml, sklearn` -> `ok` | — |
| Laboratório Wazuh / Indexer | — | não necessário | — | Tudo mockado/puro (fixtures) |
| `pytest` | — | não usado | — | Teste standalone com `check()` |

**Missing dependencies with no fallback:** nenhuma.
**Missing dependencies with fallback:** nenhuma.

## Validation Architecture

(`workflow.nyquist_validation` é `true` em `.planning/config.json`.)

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Scripts standalone sem pytest (`check(label, cond)` + `sys.exit(1)`), convenção do projeto |
| Config file | none |
| Quick run command | `cd scripts && source .venv/Scripts/activate && python -X utf8 test_vaccine_engine.py` |
| Full suite command | `cd scripts && python run_all_tests.py` (~13 s; 39 ficheiros hoje) |

### Phase Requirements -> Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| VAC-01 | Exatamente 1 candidato por `not_detected`/`partial`; 0 por `detected`/`unknown`; `unknown` por `alerts_truncated` nunca gera; matriz sobre registry real (fixtures `ATTACKS`/`ML_RESULTS`) e dicts à mão | unit | `python -X utf8 test_vaccine_engine.py` | ❌ Wave 0 |
| VAC-01 | D-01: `partial` -> `missing_sensors = expected − achieved` (incl. esperado=network/atingido=rule); `not_detected` -> todos os esperados; `achieved` guardado | unit | idem | ❌ Wave 0 |
| VAC-02 | `proposals`: `rule` com `{event_ids, min_count=1, window_seconds=300}` e `events` do catálogo; `ml`/`network` com `rule: None` e recomendação; `window_seconds == DEFAULT_WINDOW_SECONDS`; fechado por `validate_vaccine`; varrimento de todas as strings (allowlist + deny-list); teste negativo (comando injetado é rejeitado); `RECOMMENDATIONS` e Event names sem padrões de comando | unit | idem | ❌ Wave 0 |
| VAC-03 | Origem completa (`attack_id`, `scenario`, `mitre_tactic`, `mitre_technique` do log quando existir, `incident_ids`, evidência por referência); `tool`/`target`/`operator`/`details` ausentes; id golden com literais; duas corridas -> mesma saída (igualdade total) e ids únicos; partial->not_detected muda o id; `id None`/bool/0 -> `skipped.no_attack_id`; `duplicate_id` -> `skipped.duplicate_id` (todas as entradas) | unit | idem | ❌ Wave 0 |
| VAC-04 | `registry=None` -> `source_unavailable`, `considered=None`; `correlation.available=False` -> `source_unavailable`; `attacks=[]` -> `no_data`; todos `unknown` -> `reason=None`, 0 vaccines, `alerts_truncated` visível; entrada não-dict / chaves em falta / `None` não lançam; nunca "inventa" uma vaccine | unit | idem | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `python -X utf8 test_vaccine_engine.py` (< 1 s, sem `main`/TestClient).
- **Per wave merge:** `python run_all_tests.py vaccine` e depois a suite completa.
- **Phase gate:** `python run_all_tests.py` verde (39 -> 40 ficheiros) antes de `/gsd-verify-work`.

### Wave 0 Gaps
- [ ] `scripts/test_vaccine_engine.py` — cobre VAC-01..04 (único ficheiro novo de teste; não precisa `SENTRYLENS_API_KEY` porque não importa `main`).
- [ ] `scripts/vaccine_engine.py` — módulo sob teste (a escrever primeiro com o contrato; o teste golden de ids escreve-se **antes** de fixar a fórmula final).
- Nenhuma instalação de framework.

## Security Domain

(`security_enforcement` ativo, ASVS nível 1, `security_block_on: high`.)

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | Sem rota nesta fase (a API key por rota é da Phase 13) |
| V3 Session Management | no | — |
| V4 Access Control | no | Sem superfície HTTP |
| V5 Input Validation | yes | Tratar a saída do registry como input: filtrar tipos (`int` sem `bool`), allowlist de sensores/veredito, formato de `scenario`/MITRE/`incident_id`, `validate_vaccine()` fechado; nunca lançar |
| V6 Cryptography | partial | `hashlib.sha256` só como identificador determinístico, **não** autenticação; não vender o id como assinatura (o mesmo aviso que o CLAUDE.md faz do SHA-256 dos `.pkl`) |
| V7/V8 Error handling / data protection | yes | Códigos estáveis em vez de texto de exceção; sem caminhos; sem cópia de payload/comando/IP de alvo para a vaccine |

### Known Threat Patterns for esta stack (módulo puro sobre dados de log)

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Comando executável embutido numa vaccine (via `tool`/`details.command` do log antigo ou campo livre) | Tampering / Elevation | Contrato fechado + allowlist por campo; excluir `tool`/`details`/`target`; o único texto livre é uma constante do módulo (`RECOMMENDATIONS`) |
| Entradas hostis no `attack_log` (id booleano, id gigante, strings de controlo, entradas duplicadas) | Tampering | Já higienizadas pelo registry (`clean_text`, `normalize_attack_id`); o motor revalida tipos e não confia no formato |
| Fabricar um gap por falha de fonte (falso "não detetado") | Repudiation / Info integrity | `unknown` e `source_unavailable` nunca geram; teste explícito |
| Vazamento de caminhos/exceções | Information disclosure | Motor não faz I/O nem formata exceções; devolve só códigos |
| Colisão/forja de id | Spoofing | Id inclui `attack_id`; duplicados excluídos; documentar que não é autenticação |

## Sources

### Primary (HIGH confidence)
- `C:\Users\fnuno\OneDrive\Projetos\SentryLens\scripts\attack_registry.py` (lido integralmente) — contrato do registo, `verdict`, `expected_detection`, `normalize_attack_id`, `duplicate_id`.
- `...\scripts\redblue_correlator.py` (linhas 1-280) — `DEFAULT_WINDOW_SECONDS`, regra de correspondência de alertas, `attack_windows`.
- `...\scripts\attack_library.py` + `attack_library.yaml` (lidos integralmente) — `get_expected_sensors`, sensores esperados por cenário, catálogo sem comandos.
- `...\scripts\attack_scenarios.py` (linhas 135-310) — `Scenario`, `SCENARIOS`, `format_log_entry` (sem `id`).
- `...\scripts\event_catalog.py` — `CRITICAL_EVENTS`, `classify_alert`.
- `...\scripts\soc_metrics.py` — padrão `available`/`reason`/`source_unavailable`/`no_data`.
- `...\scripts\main.py:1465-1590` — como o registry é montado e o que é `correlation` (`available`, `alerts_truncated`, `error_code`).
- `...\scripts\test_attack_registry.py`, `test_attack_library.py`, `run_all_tests.py` — convenções de teste e fixtures reutilizáveis.
- `...\scripts\attack_log.jsonl` — 12 linhas com `id` (semeadas à mão).
- `.planning/phases/12-motor-de-vaccines/12-CONTEXT.md`, `.planning/REQUIREMENTS.md`, `.planning/STATE.md`, `.planning/config.json`, `CLAUDE.md`.

### Secondary (MEDIUM confidence)
- `docs/DATA_MODEL.md`, `docs/ROADMAP_STATUS.md` (menções a Vaccine/R11; a entidade Vaccine ainda não está definida em `DATA_MODEL.md` — entra na Phase 14).

### Tertiary (LOW confidence)
- Nenhuma. Não foi usada pesquisa web nem Context7: a fase não depende de bibliotecas externas (só stdlib e código do repo); `research-plan`/`research-store` dispensados por não haver perguntas de documentação externa.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — só stdlib + módulos do repo lidos nesta sessão.
- Architecture: HIGH nos pontos bloqueados (D-01..D-07); MEDIUM no formato exato `proposals[]` (A1, aguarda confirmação do utilizador).
- Pitfalls: HIGH — todos derivados de linhas de código lidas (Pitfall 1 confirmado também no ficheiro de log real).

**Research date:** 2026-10-11
**Valid until:** 2026-11-10 (estável; só invalida se `attack_registry.py`/`redblue_correlator.py` mudarem de contrato)
